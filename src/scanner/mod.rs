pub mod audit;
pub mod heuristics;
pub mod network;
pub mod ports_db;
pub mod process;

use crate::models::{IpCategory, ProcessRecord, ScanSnapshot, Severity};
use chrono::Local;
use network::{collect_network_connections, DnsCache};
use process::{check_is_elevated, collect_processes, enrich_sha256_hashes, CachedHash};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use sysinfo::{System, Users};

/// Windows folder read from HKLM, which only admins can write. `%SystemRoot%` is not used:
/// a normal user can override environment variables, and this tool runs elevated.
#[cfg(windows)]
pub(crate) fn system_root() -> std::path::PathBuf {
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .and_then(|k| k.get_value::<String, _>("SystemRoot"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\Windows"))
}

/// 100 minus each finding's penalty, floored at 0, plus a letter grade.
/// The score counts findings. It does not measure how secure the host is.
fn score_and_grade(findings: &[crate::models::SecurityFinding], incomplete: bool) -> (u8, String) {
    let penalty: u32 = findings.iter().map(|f| f.severity.penalty_points()).sum();
    let score = 100u32.saturating_sub(penalty) as u8;
    let grade = if incomplete {
        "INCOMPLETE"
    } else {
        match score {
            95..=100 => "A+",
            85..=94 => "A",
            75..=84 => "B",
            60..=74 => "C",
            40..=59 => "D",
            _ => "F",
        }
    };
    (score, grade.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SecurityFinding;

    fn finding(severity: Severity) -> SecurityFinding {
        SecurityFinding {
            rule_id: "T".to_string(),
            category: String::new(),
            mitre_id: String::new(),
            severity,
            title: String::new(),
            description: String::new(),
            pid: None,
            process_name: None,
            endpoint: None,
            evidence: String::new(),
            remediation: String::new(),
        }
    }

    #[test]
    fn score_subtracts_penalties_and_floors_at_zero() {
        use Severity::*;
        let grade = |sevs: &[Severity], incomplete| {
            let fs: Vec<_> = sevs.iter().map(|&s| finding(s)).collect();
            score_and_grade(&fs, incomplete)
        };
        assert_eq!(grade(&[], false), (100, "A+".to_string()));
        assert_eq!(grade(&[Critical], false), (70, "C".to_string()));
        // The stock Windows host in this session: one High (SMB) and one Medium (RPC).
        assert_eq!(grade(&[High, Medium], false), (79, "B".to_string()));
        assert_eq!(grade(&[Low, Safe], false), (98, "A+".to_string()));
        assert_eq!(grade(&[Critical; 4], false), (0, "F".to_string()));
        assert_eq!(grade(&[], true), (100, "INCOMPLETE".to_string()));
    }
}

pub struct ScannerEngine {
    sys: System,
    users: Users,
    hash_cache: HashMap<String, CachedHash>,
    dns_cache: DnsCache,
    hostname: String,
    os_name: String,
    os_version: String,
    kernel_version: String,
    is_elevated: bool,
}

impl ScannerEngine {
    pub fn new() -> Self {
        Self {
            sys: System::new(),
            users: Users::new_with_refreshed_list(),
            hash_cache: HashMap::new(),
            dns_cache: DnsCache::new(),
            hostname: System::host_name().unwrap_or_else(|| "localhost".to_string()),
            os_name: System::name().unwrap_or_else(|| std::env::consts::OS.to_string()),
            os_version: System::os_version().unwrap_or_else(|| "Unknown".to_string()),
            kernel_version: System::kernel_version().unwrap_or_else(|| "Unknown".to_string()),
            is_elevated: check_is_elevated(),
        }
    }

    /// One-shot modes exit before the DNS workers answer, so wait briefly and fill in the names.
    pub fn refresh_hostnames(&self, snapshot: &mut ScanSnapshot, wait: Duration) {
        self.dns_cache.wait_idle(wait);
        for conn in &mut snapshot.connections {
            if let (None, Some(ip)) = (&conn.remote_hostname, conn.remote_ip) {
                conn.remote_hostname = self.dns_cache.lookup_or_queue(ip);
            }
        }
    }

    pub fn perform_scan(&mut self) -> ScanSnapshot {
        let start = Instant::now();

        let mut proc_map = collect_processes(&mut self.sys, &self.users);
        let (mut connections, net_warning) =
            collect_network_connections(&mut proc_map, &self.dns_cache);
        let scan_warnings: Vec<String> = net_warning.into_iter().collect();
        let mut findings =
            heuristics::evaluate_security_heuristics(&mut connections, &mut proc_map);

        enrich_sha256_hashes(&mut proc_map, &mut self.hash_cache);
        for conn in &mut connections {
            if let Some(pid) = conn.pid {
                if let Some(p) = proc_map.get(&pid) {
                    conn.sha256 = p.sha256.clone();
                }
            }
        }

        let audit_items = audit::run_host_security_audit(self.is_elevated, &mut findings);

        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        connections.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.is_listening().cmp(&a.is_listening()))
                .then_with(|| a.local_port.cmp(&b.local_port))
        });

        let mut processes: Vec<ProcessRecord> = proc_map.into_values().collect();
        processes.sort_by(|a, b| {
            b.max_severity
                .cmp(&a.max_severity)
                .then_with(|| b.open_sockets_count.cmp(&a.open_sockets_count))
                .then_with(|| a.name.cmp(&b.name))
        });

        let sockets_without_exe = connections.iter().filter(|c| c.exe_path.is_empty()).count();
        let total_connections = connections.len();
        let listening_ports = connections.iter().filter(|c| c.is_listening()).count();
        let established_connections = connections.iter().filter(|c| c.is_established()).count();
        let external_connections = connections
            .iter()
            .filter(|c| c.remote_category == IpCategory::PublicInternet)
            .count();
        let suspicious_connections = connections
            .iter()
            .filter(|c| c.severity >= Severity::Medium)
            .count();

        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();

        let (security_score, security_grade) =
            score_and_grade(&findings, !scan_warnings.is_empty());

        let mut snapshot = ScanSnapshot {
            timestamp: Local::now(),
            scan_duration_ms: start.elapsed().as_millis(),
            hostname: self.hostname.clone(),
            os_name: self.os_name.clone(),
            os_version: self.os_version.clone(),
            kernel_version: self.kernel_version.clone(),
            is_elevated: self.is_elevated,
            security_score,
            security_grade,
            scan_warnings,
            sockets_without_exe,
            total_connections,
            listening_ports,
            established_connections,
            external_connections,
            suspicious_connections,
            critical_count,
            high_count,
            medium_count,
            low_count,
            connections,
            findings,
            audit_items,
            processes,
        };
        // After detection, which needs the raw text; before any output sees it.
        snapshot.neutralize_text();
        snapshot
    }
}
