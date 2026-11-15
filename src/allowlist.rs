//! Cryptographic SHA-256 finding suppression allowlist (`--allowlist`, TUI `[w]`).
//!
//! Suppression rules are anchored to a mandatory 64-character hex SHA-256 digest of the executable
//! on disk (plus optional `rule_id` prefix and `local_port`). If a binary is modified, trojanized,
//! or replaced at the same path, its SHA-256 changes and suppression automatically invalidates.

use crate::models::{ format_endpoint, ScanSnapshot, SecurityFinding, Severity };
use crate::report::write_report_atomic;
use crate::scanner::fs_safe::{ is_local_safe_path, read_bounded_string };
use serde::{ Deserialize, Serialize };
use std::collections::{ HashMap, HashSet };
use std::fs;
use std::path::Path;

const MAX_ALLOWLIST_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistRule {
    /// Mandatory 64-hex-char SHA-256 digest of the trusted executable.
    pub sha256: String,
    /// Optional rule ID or prefix (e.g. `"H05"` or `"H05-BACKDOOR-PORT"`). `None` matches all rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Optional local port constraint. `None` matches any port owned by the binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
    /// Analyst note explaining why this binary/port is expected.
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Allowlist {
    #[serde(default)]
    pub rules: Vec<AllowlistRule>,
}

#[must_use]
pub fn is_valid_sha256(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Allowlist {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = read_bounded_string(path, MAX_ALLOWLIST_BYTES)?;
        let mut list: Self = serde_json::from_str(raw.trim_start_matches('\u{feff}'))
            .map_err(|e| format!("{}: invalid allowlist JSON ({e})", path.display()))?;
        for (idx, rule) in list.rules.iter_mut().enumerate() {
            if !is_valid_sha256(&rule.sha256) {
                return Err(format!(
                    "{}: rule #{} has invalid SHA-256 '{}' (expected 64 hex chars)",
                    path.display(),
                    idx + 1,
                    rule.sha256
                ));
            }
            rule.sha256.make_ascii_lowercase();
            if let Some(rid) = &mut rule.rule_id {
                *rid = rid.trim().to_string();
                if rid.is_empty() {
                    rule.rule_id = None;
                }
            }
        }
        Ok(list)
    }

    pub fn load_if_exists(path: &Path) -> Result<Self, String> {
        if !is_local_safe_path(path) {
            return Err(format!("{}: rejected non-local path", path.display()));
        }
        match fs::symlink_metadata(path) {
            Ok(_) => Self::load(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_report_atomic(path, json.as_bytes())
    }

    /// Inserts `rule` if no identical `(sha256, rule_id, local_port)` rule exists.
    /// Returns `Ok(true)` if inserted, `Ok(false)` if already present.
    pub fn upsert_rule(&mut self, mut rule: AllowlistRule) -> Result<bool, String> {
        if !is_valid_sha256(&rule.sha256) {
            return Err(format!(
                "Cannot allowlist without a valid 64-hex SHA-256 digest (got '{}')",
                rule.sha256
            ));
        }
        rule.sha256.make_ascii_lowercase();
        if let Some(rid) = &mut rule.rule_id {
            *rid = rid.trim().to_string();
            if rid.is_empty() {
                rule.rule_id = None;
            }
        }

        let exists = self.rules.iter().any(|r| {
            r.sha256 == rule.sha256
                && r.rule_id.as_deref().map(str::to_ascii_uppercase)
                    == rule.rule_id.as_deref().map(str::to_ascii_uppercase)
                && r.local_port == rule.local_port
        });
        if exists {
            return Ok(false);
        }
        self.rules.push(rule);
        Ok(true)
    }

    /// Suppresses findings whose owning process SHA-256 matches an allowlist rule, recomputing
    /// connection/process severities and snapshot summary metrics. Returns suppressed count.
    pub fn apply(&self, snapshot: &mut ScanSnapshot) -> usize {
        if self.rules.is_empty() {
            return 0;
        }

        let mut pid_hashes: HashMap<u32, String> = HashMap::new();
        for p in &snapshot.processes {
            if let Some(sha) = &p.sha256 {
                if is_valid_sha256(sha) {
                    pid_hashes.insert(p.pid, sha.to_ascii_lowercase());
                }
            }
        }
        let mut pid_ports: HashMap<u32, HashSet<u16>> = HashMap::new();
        for c in &snapshot.connections {
            if let Some(pid) = c.pid {
                pid_ports.entry(pid).or_default().insert(c.local_port);
                if !pid_hashes.contains_key(&pid) {
                    if let Some(sha) = &c.sha256 {
                        if is_valid_sha256(sha) {
                            pid_hashes.insert(pid, sha.to_ascii_lowercase());
                        }
                    }
                }
            }
        }

        let before = snapshot.findings.len();
        let mut suppressed_pids = HashSet::new();
        snapshot.findings.retain(|f| {
            let Some(pid) = f.pid else {
                return true;
            };
            let Some(sha) = pid_hashes.get(&pid) else {
                return true;
            };
            let ports = pid_ports.get(&pid);
            let matched = self
                .rules
                .iter()
                .any(|r| rule_matches_finding(r, sha, f, ports));
            if matched {
                suppressed_pids.insert(pid);
            }
            !matched
        });

        let removed = before - snapshot.findings.len();
        if removed == 0 {
            return 0;
        }

        snapshot.suppressed_count += removed;

        // Reconcile socket and process severities for PIDs that had findings suppressed.
        let mut remaining_pid_sev: HashMap<u32, Severity> = HashMap::new();
        let mut remaining_ep_sev: HashMap<(u32, String), Severity> = HashMap::new();
        for f in &snapshot.findings {
            if let Some(pid) = f.pid {
                let entry = remaining_pid_sev.entry(pid).or_insert(Severity::Safe);
                if f.severity > *entry {
                    *entry = f.severity;
                }
                if let Some(ep) = &f.endpoint {
                    let ep_entry = remaining_ep_sev
                        .entry((pid, ep.clone()))
                        .or_insert(Severity::Safe);
                    if f.severity > *ep_entry {
                        *ep_entry = f.severity;
                    }
                }
            }
        }

        for conn in &mut snapshot.connections {
            let Some(pid) = conn.pid else { continue };
            if !suppressed_pids.contains(&pid) {
                continue;
            }
            let Some(sha) = pid_hashes.get(&pid) else { continue };
            let socket_covered = self.rules.iter().any(|r| {
                r.sha256 == *sha && r.local_port.is_none_or(|lp| lp == conn.local_port)
            });
            if !socket_covered {
                continue;
            }

            let local_ep = format_endpoint(conn.local_ip, conn.local_port);
            let pair_ep = format!("{} -> {}", local_ep, conn.remote_endpoint());
            let rem_ep = conn.remote_endpoint();
            let active_sev = [local_ep.as_str(), pair_ep.as_str(), rem_ep.as_str()]
                .into_iter()
                .filter_map(|ep| remaining_ep_sev.get(&(pid, ep.to_string())).copied())
                .max()
                .unwrap_or(Severity::Safe);

            if active_sev < conn.severity {
                conn.severity = active_sev;
                if active_sev == Severity::Safe {
                    conn.risk_reasons.clear();
                    conn.risk_reasons
                        .push("Suppressed via SHA-256 allowlist".to_string());
                }
            }
        }

        let mut max_conn_sev: HashMap<u32, Severity> = HashMap::new();
        for conn in &snapshot.connections {
            if let Some(pid) = conn.pid {
                let entry = max_conn_sev.entry(pid).or_insert(Severity::Safe);
                if conn.severity > *entry {
                    *entry = conn.severity;
                }
            }
        }

        for proc_rec in &mut snapshot.processes {
            if suppressed_pids.contains(&proc_rec.pid) {
                let f_sev = remaining_pid_sev
                    .get(&proc_rec.pid)
                    .copied()
                    .unwrap_or(Severity::Safe);
                let c_sev = max_conn_sev
                    .get(&proc_rec.pid)
                    .copied()
                    .unwrap_or(Severity::Safe);
                proc_rec.max_severity = f_sev.max(c_sev);
            }
        }

        snapshot.recompute_summary();
        removed
    }
}

fn rule_matches_finding(
    rule: &AllowlistRule,
    proc_sha_lower: &str,
    finding: &SecurityFinding,
    pid_ports: Option<&HashSet<u16>>,
) -> bool {
    if rule.sha256 != proc_sha_lower {
        return false;
    }
    if let Some(rid) = &rule.rule_id {
        let f_upper = finding.rule_id.to_ascii_uppercase();
        let r_upper = rid.to_ascii_uppercase();
        if f_upper != r_upper && !f_upper.starts_with(&r_upper) {
            return false;
        }
    }
    if let Some(port) = rule.local_port {
        match finding.endpoint.as_deref() {
            Some(ep) => {
                let local_side = ep.split(" -> ").next().unwrap_or(ep);
                if parse_endpoint_port(local_side) != Some(port) {
                    return false;
                }
            }
            None => {
                if !pid_ports.is_some_and(|ps| ps.contains(&port)) {
                    return false;
                }
            }
        }
    }
    true
}

fn parse_endpoint_port(endpoint: &str) -> Option<u16> {
    let (_, port_str) = endpoint.rsplit_once(':')?;
    port_str.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        ConnectionEntry, ExposureScope, IpCategory, ProcessRecord, Protocol,
    };
    use chrono::Local;
    use std::net::{IpAddr, Ipv4Addr};

    const VALID_SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const OTHER_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn sample_snapshot(sha: &str) -> ScanSnapshot {
        let conn = ConnectionEntry {
            id: 1,
            protocol: Protocol::Tcp,
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 4444,
            remote_ip: None,
            remote_port: None,
            remote_hostname: None,
            state: "LISTEN".to_string(),
            pid: Some(4242),
            process_name: "dev_server".to_string(),
            exe_path: "/opt/dev_server".to_string(),
            cmdline: "/opt/dev_server --port 4444".to_string(),
            sha256: Some(sha.to_string()),
            lineage: vec!["systemd(1)".to_string(), "dev_server(4242)".to_string()],
            service_name: "Metasploit/C2".to_string(),
            exposure: ExposureScope::WildcardAllInterfaces,
            remote_category: IpCategory::Unspecified,
            severity: Severity::Critical,
            risk_reasons: vec!["Backdoor port 4444".to_string()],
        };
        let proc_rec = ProcessRecord {
            pid: 4242,
            ppid: Some(1),
            name: "dev_server".to_string(),
            exe_path: "/opt/dev_server".to_string(),
            cmdline: "/opt/dev_server --port 4444".to_string(),
            user: "dev".to_string(),
            sha256: Some(sha.to_string()),
            original_filename: None,
            lineage: vec!["systemd(1)".to_string(), "dev_server(4242)".to_string()],
            cpu_usage: 0.0,
            memory_bytes: 1024,
            run_time_secs: 10,
            exe_exists_on_disk: true,
            is_deleted_binary: false,
            open_sockets_count: 1,
            max_severity: Severity::Critical,
        };
        let finding = SecurityFinding {
            rule_id: "H05-BACKDOOR-PORT".to_string(),
            category: "Suspicious Port".to_string(),
            mitre_id: "T1571".to_string(),
            severity: Severity::Critical,
            title: "Port 4444".to_string(),
            description: "Test".to_string(),
            pid: Some(4242),
            process_name: Some("dev_server".to_string()),
            endpoint: Some("0.0.0.0:4444".to_string()),
            evidence: "0.0.0.0:4444".to_string(),
            remediation: "None".to_string(),
        };
        let mut snap = ScanSnapshot {
            timestamp: Local::now(),
            scan_duration_ms: 1,
            hostname: "host".to_string(),
            os_name: "TestOS".to_string(),
            os_version: "1".to_string(),
            kernel_version: "1".to_string(),
            is_elevated: true,
            security_score: 70,
            security_grade: "C".to_string(),
            scan_warnings: Vec::new(),
            sockets_without_exe: 0,
            suppressed_count: 0,
            total_connections: 1,
            listening_ports: 1,
            established_connections: 0,
            external_connections: 0,
            suspicious_connections: 1,
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            connections: vec![conn],
            findings: vec![finding],
            audit_items: Vec::new(),
            processes: vec![proc_rec],
            timeline_events: Vec::new(),
            wifi_shield: None,
        };
        snap.recompute_summary();
        snap
    }

    #[test]
    fn suppresses_matching_sha256_and_invalidates_when_binary_changes() {
        let mut allow = Allowlist::default();
        assert!(allow
            .upsert_rule(AllowlistRule {
                sha256: VALID_SHA.to_uppercase(),
                rule_id: Some("H05".to_string()),
                local_port: Some(4444),
                reason: "Local dev harness".to_string(),
            })
            .unwrap());

        let mut snap = sample_snapshot(VALID_SHA);
        assert_eq!(snap.security_score, 70);
        assert_eq!(allow.apply(&mut snap), 1);
        assert!(snap.findings.is_empty());
        assert_eq!(snap.suppressed_count, 1);
        assert_eq!(snap.security_score, 100);
        assert_eq!(snap.connections[0].severity, Severity::Safe);
        assert_eq!(snap.processes[0].max_severity, Severity::Safe);

        // Same path/port/name, but modified binary digest -> suppression MUST NOT apply.
        let mut tampered = sample_snapshot(OTHER_SHA);
        assert_eq!(allow.apply(&mut tampered), 0);
        assert_eq!(tampered.findings.len(), 1);
        assert_eq!(tampered.security_score, 70);
    }

    #[test]
    fn rejects_invalid_sha256_and_enforces_port_scope() {
        let mut allow = Allowlist::default();
        assert!(allow
            .upsert_rule(AllowlistRule {
                sha256: "not-a-sha256".to_string(),
                rule_id: None,
                local_port: None,
                reason: String::new(),
            })
            .is_err());

        allow
            .upsert_rule(AllowlistRule {
                sha256: VALID_SHA.to_string(),
                rule_id: Some("H05".to_string()),
                local_port: Some(8080),
                reason: "Only port 8080 allowed".to_string(),
            })
            .unwrap();
        let mut snap = sample_snapshot(VALID_SHA);
        assert_eq!(allow.apply(&mut snap), 0, "port 4444 must not match port 8080 rule");
    }
}
