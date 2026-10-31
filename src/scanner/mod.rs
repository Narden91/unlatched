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

        let total_penalty: u32 = findings.iter().map(|f| f.severity.penalty_points()).sum();
        let security_score = 100u32.saturating_sub(total_penalty) as u8;
        // The score only counts findings. It does not measure how secure the host is.
        let security_grade = if scan_warnings.is_empty() {
            match security_score {
                95..=100 => "A+",
                85..=94 => "A",
                75..=84 => "B",
                60..=74 => "C",
                40..=59 => "D",
                _ => "F",
            }
        } else {
            "INCOMPLETE"
        }
        .to_string();

        ScanSnapshot {
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
        }
    }
}
