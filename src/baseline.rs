//! Compare a scan with an earlier one saved by `--export-json`.
//! A known-good baseline cuts false positives: only what changed is reported.

use crate::models::{ConnectionEntry, ScanSnapshot};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

/// Audit checks that list autostart entries. Firewall and privilege rows are not persistence.
const PERSISTENCE_CHECKS: &[&str] = &[
    "AUD-REG-RUN",
    "AUD-STARTUP-DIR",
    "AUD-LIN-SCHED",
    "AUD-SYSTEMD",
    "AUD-WINLOGON-01",
];

/// Identity of a socket that survives PID changes and ephemeral source ports.
pub fn socket_key(c: &ConnectionEntry) -> String {
    let owner = if c.exe_path.is_empty() {
        &c.process_name
    } else {
        &c.exe_path
    };
    if c.is_listening() {
        // OS-chosen ports (32768 and up) change on every run. A known program on a new random port
        // is not news, so key on the program alone. A new program on a high port still shows up.
        let port = if c.local_port >= 32768 {
            "ephemeral".to_string()
        } else {
            c.local_port.to_string()
        };
        format!("L|{}|{}|{}", c.protocol.as_str(), port, owner)
    } else {
        format!("C|{}|{}|{}", c.protocol.as_str(), owner, c.remote_endpoint())
    }
}

fn owner_key(exe_path: &str, name: &str) -> String {
    if exe_path.is_empty() { name } else { exe_path }.to_string()
}

pub fn load(path: &Path) -> Result<ScanSnapshot, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // Windows PowerShell redirects and `Out-File -Encoding utf8` write a BOM that serde_json rejects.
    serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("{}: not a scan JSON ({e})", path.display()))
}

#[derive(Debug, Default)]
pub struct SnapshotDiff {
    pub new_listeners: BTreeSet<String>,
    pub new_owners: BTreeSet<String>,
    pub new_autostart: BTreeSet<String>,
    pub changed_hashes: BTreeSet<String>,
    pub notes: Vec<String>,
}

pub fn diff_snapshots(old: &ScanSnapshot, new: &ScanSnapshot) -> SnapshotDiff {
    let mut d = SnapshotDiff::default();

    if old.is_elevated != new.is_elevated {
        d.notes.push(format!(
            "Baseline ran {} and this scan runs {}. Hidden processes make the diff unreliable.",
            if old.is_elevated { "elevated" } else { "unelevated" },
            if new.is_elevated { "elevated" } else { "unelevated" },
        ));
    }
    if !old.scan_warnings.is_empty() || !new.scan_warnings.is_empty() {
        d.notes
            .push("A scan had collector warnings, so the diff may miss changes.".to_string());
    }

    let old_sockets: HashSet<String> = old.connections.iter().map(socket_key).collect();
    for c in new.connections.iter().filter(|c| c.is_listening()) {
        if !old_sockets.contains(&socket_key(c)) {
            d.new_listeners.insert(format!(
                "{} {} {} ({})",
                c.protocol.as_str(),
                c.local_endpoint(),
                c.process_name,
                if c.exe_path.is_empty() { "path unknown" } else { &c.exe_path }
            ));
        }
    }

    let owners = |s: &ScanSnapshot| -> HashSet<String> {
        s.processes
            .iter()
            .filter(|p| p.open_sockets_count > 0)
            .map(|p| owner_key(&p.exe_path, &p.name))
            .collect()
    };
    let old_owners = owners(old);
    for p in new.processes.iter().filter(|p| p.open_sockets_count > 0) {
        let key = owner_key(&p.exe_path, &p.name);
        if !old_owners.contains(&key) {
            d.new_owners.insert(key);
        }
    }

    let persistence_key = |check_id: &str, location: &str, value: &str| {
        format!("{check_id}|{location}|{value}")
    };
    let old_autostart: HashSet<String> = old
        .audit_items
        .iter()
        .filter(|a| PERSISTENCE_CHECKS.contains(&a.check_id.as_str()))
        .map(|a| persistence_key(&a.check_id, &a.location, &a.value))
        .collect();
    for a in new
        .audit_items
        .iter()
        .filter(|a| PERSISTENCE_CHECKS.contains(&a.check_id.as_str()))
    {
        if !old_autostart.contains(&persistence_key(&a.check_id, &a.location, &a.value)) {
            d.new_autostart.insert(format!(
                "[{}] {}: {} -> {}",
                a.status.label(),
                a.subsystem,
                a.name,
                a.value
            ));
        }
    }

    // Same path, different bytes: a replaced binary. Only compares paths hashed in both scans.
    let old_hashes: HashMap<&str, &str> = old
        .processes
        .iter()
        .filter_map(|p| Some((p.exe_path.as_str(), p.sha256.as_deref()?)))
        .collect();
    for p in &new.processes {
        if let (Some(new_hash), Some(old_hash)) = (&p.sha256, old_hashes.get(p.exe_path.as_str())) {
            if new_hash != old_hash {
                d.changed_hashes.insert(format!(
                    "{}: {} -> {}",
                    p.exe_path,
                    &old_hash[..old_hash.len().min(12)],
                    &new_hash[..new_hash.len().min(12)]
                ));
            }
        }
    }

    d
}

impl SnapshotDiff {
    pub fn render(&self) -> String {
        let mut out = String::from("Changes since baseline\n");
        let sections: [(&str, &BTreeSet<String>); 4] = [
            ("New listeners", &self.new_listeners),
            ("New socket-owning programs", &self.new_owners),
            ("New autostart entries", &self.new_autostart),
            ("Changed binaries (same path, new SHA-256)", &self.changed_hashes),
        ];
        let mut any = false;
        for (title, items) in sections {
            if items.is_empty() {
                continue;
            }
            any = true;
            out.push_str(&format!("  {title} ({})\n", items.len()));
            for item in items {
                out.push_str(&format!("    + {item}\n"));
            }
        }
        if !any {
            out.push_str("  No changes.\n");
        }
        for note in &self.notes {
            out.push_str(&format!("  Note: {note}\n"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AuditItem, AuditStatus, ExposureScope, IpCategory, ProcessRecord, Protocol, Severity,
    };
    use chrono::Local;
    use std::net::{IpAddr, Ipv4Addr};

    fn listener(pid: u32, port: u16, exe: &str) -> ConnectionEntry {
        ConnectionEntry {
            id: 1,
            protocol: Protocol::Tcp,
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: port,
            remote_ip: None,
            remote_port: None,
            remote_hostname: None,
            state: "LISTEN".to_string(),
            pid: Some(pid),
            process_name: "svc".to_string(),
            exe_path: exe.to_string(),
            cmdline: String::new(),
            sha256: None,
            lineage: Vec::new(),
            service_name: "Custom".to_string(),
            exposure: ExposureScope::WildcardAllInterfaces,
            remote_category: IpCategory::Unspecified,
            severity: Severity::Safe,
            risk_reasons: Vec::new(),
        }
    }

    fn process(pid: u32, exe: &str, sha: &str) -> ProcessRecord {
        ProcessRecord {
            pid,
            ppid: None,
            name: "svc".to_string(),
            exe_path: exe.to_string(),
            cmdline: String::new(),
            user: "u".to_string(),
            sha256: Some(sha.to_string()),
            lineage: Vec::new(),
            cpu_usage: 0.0,
            memory_bytes: 0,
            run_time_secs: 0,
            exe_exists_on_disk: true,
            is_deleted_binary: false,
            open_sockets_count: 1,
            max_severity: Severity::Safe,
        }
    }

    fn autostart(value: &str) -> AuditItem {
        AuditItem {
            check_id: "AUD-REG-RUN".to_string(),
            subsystem: "Registry Persistence".to_string(),
            name: "x".to_string(),
            location: "HKCU\\Run".to_string(),
            value: value.to_string(),
            status: AuditStatus::Pass,
            details: String::new(),
        }
    }

    fn snapshot(
        connections: Vec<ConnectionEntry>,
        processes: Vec<ProcessRecord>,
        audit_items: Vec<AuditItem>,
    ) -> ScanSnapshot {
        ScanSnapshot {
            timestamp: Local::now(),
            scan_duration_ms: 0,
            hostname: "h".to_string(),
            os_name: "os".to_string(),
            os_version: "1".to_string(),
            kernel_version: "1".to_string(),
            is_elevated: false,
            security_score: 100,
            security_grade: "A+".to_string(),
            scan_warnings: Vec::new(),
            total_connections: connections.len(),
            listening_ports: 0,
            established_connections: 0,
            external_connections: 0,
            suspicious_connections: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            connections,
            findings: Vec::new(),
            audit_items,
            processes,
        }
    }

    #[test]
    fn diff_reports_changes_and_ignores_pid_churn() {
        let old = snapshot(
            vec![listener(10, 8080, "/bin/app"), listener(10, 50000, "/bin/app")],
            vec![process(10, "/bin/app", "aaaaaaaaaaaaaaaa")],
            vec![autostart("/bin/app")],
        );
        let new = snapshot(
            vec![
                listener(99, 8080, "/bin/app"),
                listener(99, 50001, "/bin/app"),
                listener(100, 9999, "/tmp/evil"),
            ],
            vec![
                process(99, "/bin/app", "bbbbbbbbbbbbbbbb"),
                process(100, "/tmp/evil", "cccccccccccccccc"),
            ],
            vec![autostart("/bin/app"), autostart("/tmp/evil")],
        );
        let d = diff_snapshots(&old, &new);
        assert_eq!(
            d.new_listeners.len(),
            1,
            "a new PID or a new random high port for a known program is not new"
        );
        assert!(d.new_listeners.iter().next().unwrap().contains("9999"));
        assert_eq!(d.new_owners.len(), 1);
        assert_eq!(d.new_autostart.len(), 1);
        assert_eq!(d.changed_hashes.len(), 1);
        assert!(diff_snapshots(&old, &old).render().contains("No changes."));
    }
}
