//! Live Socket Flight Recorder & Statistical C2 Beacon Detector (`--watch`, TUI `[6] Events`, `H09-C2-BEACON`).
//!
//! Inspired by multi-view provenance stream fusion (Yang et al., *PROVFUSION*, arXiv:2604.14685v1)
//! and temporal edge anomaly detection (Shibbir & Tosh, *ProvICS*, arXiv:2607.05989v1):
//! 1. Maintains a bounded 256-event ring buffer of socket/listener births & deaths and on-disk
//!    executable SHA-256 mutations across consecutive scans.
//! 2. Tracks inter-arrival times $\Delta t$ of newly opened outbound external connections per
//!    `(executable, remote_ip, remote_port)` flow using Welford's $O(1)$-space online variance
//!    algorithm, emitting `H09-C2-BEACON` (`MITRE T1071`) when periodic low-jitter callbacks
//!    ($n \ge 4$ intervals, $\mu \ge 1.0\text{s}$, $CV = s/\mu \le 0.20$) are observed.

use crate::baseline::socket_key;
use crate::models::{
    format_endpoint, IpCategory, Protocol, ScanSnapshot, SecurityFinding, Severity, TimelineEvent,
    TimelineKind,
};
use chrono::Local;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

const MAX_TIMELINE_EVENTS: usize = 256;
const MAX_BEACON_FLOWS: usize = 1024;
const MIN_BEACON_INTERVALS: u64 = 4;
const MIN_BEACON_MEAN_SECS: f64 = 1.0;
const MAX_BEACON_CV: f64 = 0.20;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TupleKey {
    proto: Protocol,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Debug, Clone)]
struct SocketMeta {
    process_name: String,
    pid: Option<u32>,
    endpoint: String,
    report_close: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BeaconKey {
    owner: String,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Debug, Clone)]
struct WelfordStats {
    last_seen_secs: f64,
    intervals: u64,
    mean: f64,
    m2: f64,
    alerted: bool,
    last_pid: Option<u32>,
    last_process_name: String,
}

impl WelfordStats {
    fn new(now_secs: f64, pid: Option<u32>, process_name: String) -> Self {
        Self {
            last_seen_secs: now_secs,
            intervals: 0,
            mean: 0.0,
            m2: 0.0,
            alerted: false,
            last_pid: pid,
            last_process_name: process_name,
        }
    }

    fn record_arrival(&mut self, now_secs: f64, pid: Option<u32>, process_name: &str) {
        let dt = now_secs - self.last_seen_secs;
        self.last_seen_secs = now_secs;
        self.last_pid = pid;
        self.last_process_name = process_name.to_string();
        if dt < 0.25 {
            return;
        }
        self.intervals += 1;
        let delta = dt - self.mean;
        self.mean += delta / (self.intervals as f64);
        let delta2 = dt - self.mean;
        self.m2 += delta * delta2;
    }

    fn std_dev(&self) -> f64 {
        if self.intervals < 2 {
            0.0
        } else {
            (self.m2 / ((self.intervals - 1) as f64)).sqrt()
        }
    }

    fn coeff_of_variation(&self) -> Option<f64> {
        if self.intervals < MIN_BEACON_INTERVALS || self.mean < MIN_BEACON_MEAN_SECS {
            return None;
        }
        Some(self.std_dev() / self.mean)
    }

    fn is_periodic_beacon(&self) -> bool {
        self.coeff_of_variation()
            .is_some_and(|cv| cv <= MAX_BEACON_CV)
    }
}

pub struct FlightRecorder {
    epoch: Instant,
    initialized: bool,
    events: VecDeque<TimelineEvent>,
    prev_listeners: HashMap<String, SocketMeta>,
    prev_connections: HashMap<TupleKey, SocketMeta>,
    prev_hashes: HashMap<String, String>,
    beacons: HashMap<BeaconKey, WelfordStats>,
}

impl Default for FlightRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl FlightRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            initialized: false,
            events: VecDeque::with_capacity(MAX_TIMELINE_EVENTS),
            prev_listeners: HashMap::new(),
            prev_connections: HashMap::new(),
            prev_hashes: HashMap::new(),
            beacons: HashMap::new(),
        }
    }

    /// Observes `snapshot` using monotonic elapsed wall time.
    pub fn observe(&mut self, snapshot: &mut ScanSnapshot) -> Vec<TimelineEvent> {
        let now_secs = self.epoch.elapsed().as_secs_f64();
        self.observe_at(snapshot, now_secs)
    }

    /// Observes `snapshot` at explicit monotonic timestamp `now_secs` (deterministic in tests).
    pub fn observe_at(&mut self, snapshot: &mut ScanSnapshot, now_secs: f64) -> Vec<TimelineEvent> {
        let listen_ports: HashSet<(bool, u16)> = snapshot
            .connections
            .iter()
            .filter(|c| c.is_listening())
            .map(|c| (c.protocol.is_tcp(), c.local_port))
            .collect();

        let mut curr_listeners: HashMap<String, SocketMeta> = HashMap::new();
        let mut curr_connections: HashMap<TupleKey, SocketMeta> = HashMap::new();
        let mut delta_events: Vec<TimelineEvent> = Vec::new();
        let ts = snapshot.timestamp;

        let self_pid = std::process::id();
        let scanner_dns_children: HashSet<u32> = snapshot
            .processes
            .iter()
            .filter(|p| {
                p.ppid == Some(self_pid)
                    && matches!(
                        p.name.to_ascii_lowercase().as_str(),
                        "nslookup.exe" | "nslookup" | "getent"
                    )
            })
            .map(|p| p.pid)
            .collect();

        for c in &snapshot.connections {
            if c.pid.is_some_and(|pid| pid == self_pid || scanner_dns_children.contains(&pid)) {
                continue;
            }
            if c.is_listening() {
                let key = socket_key(c);
                let meta = SocketMeta {
                    process_name: c.process_name.clone(),
                    pid: c.pid,
                    endpoint: format!("{} {}", c.protocol.as_str(), c.local_endpoint()),
                    report_close: true,
                };
                if self.initialized && !self.prev_listeners.contains_key(&key) {
                    delta_events.push(TimelineEvent {
                        timestamp: ts,
                        kind: TimelineKind::ListenerOpened,
                        severity: c.severity.max(Severity::Medium),
                        process_name: c.process_name.clone(),
                        pid: c.pid,
                        endpoint: meta.endpoint.clone(),
                        summary: format!(
                            "New listener opened by '{}' on {} ({})",
                            c.process_name,
                            c.local_endpoint(),
                            c.exposure.short_label()
                        ),
                    });
                }
                curr_listeners.insert(key, meta);
            } else if let (Some(rip), Some(rport)) = (c.remote_ip, c.remote_port) {
                let tkey = TupleKey {
                    proto: c.protocol,
                    local_ip: c.local_ip,
                    local_port: c.local_port,
                    remote_ip: rip,
                    remote_port: rport,
                };
                let is_external_or_flagged =
                    c.remote_category == IpCategory::PublicInternet || c.severity >= Severity::Low;
                let ep_str = format!("{} -> {}", c.local_endpoint(), c.remote_display());
                let meta = SocketMeta {
                    process_name: c.process_name.clone(),
                    pid: c.pid,
                    endpoint: ep_str.clone(),
                    report_close: is_external_or_flagged,
                };

                let is_new_tuple = !self.prev_connections.contains_key(&tkey);
                if self.initialized && is_new_tuple && is_external_or_flagged {
                    delta_events.push(TimelineEvent {
                        timestamp: ts,
                        kind: TimelineKind::ConnectionOpened,
                        severity: c.severity.max(Severity::Low),
                        process_name: c.process_name.clone(),
                        pid: c.pid,
                        endpoint: ep_str,
                        summary: format!(
                            "Outbound/active {} socket from '{}' to {}",
                            c.protocol.as_str(),
                            c.process_name,
                            c.remote_display()
                        ),
                    });
                }

                // Feed outbound public connection arrivals (excluding inbound peers to local listeners)
                // into the per-flow Welford beacon tracker.
                let is_inbound = listen_ports.contains(&(c.protocol.is_tcp(), c.local_port));
                if is_new_tuple && !is_inbound && c.remote_category == IpCategory::PublicInternet {
                    let owner = if c.exe_path.is_empty() {
                        c.process_name.clone()
                    } else {
                        c.exe_path.clone()
                    };
                    let bkey = BeaconKey {
                        owner,
                        remote_ip: rip,
                        remote_port: rport,
                    };
                    if let Some(stats) = self.beacons.get_mut(&bkey) {
                        stats.record_arrival(now_secs, c.pid, &c.process_name);
                    } else {
                        if self.beacons.len() >= MAX_BEACON_FLOWS {
                            self.beacons.retain(|_, v| v.intervals > 0 || v.alerted);
                            if self.beacons.len() >= MAX_BEACON_FLOWS {
                                self.beacons.clear();
                            }
                        }
                        self.beacons.insert(
                            bkey,
                            WelfordStats::new(now_secs, c.pid, c.process_name.clone()),
                        );
                    }
                }

                curr_connections.insert(tkey, meta);
            }
        }

        if self.initialized {
            for (key, old) in &self.prev_listeners {
                if !curr_listeners.contains_key(key) {
                    delta_events.push(TimelineEvent {
                        timestamp: ts,
                        kind: TimelineKind::ListenerClosed,
                        severity: Severity::Low,
                        process_name: old.process_name.clone(),
                        pid: old.pid,
                        endpoint: old.endpoint.clone(),
                        summary: format!(
                            "Listener closed by '{}' ({})",
                            old.process_name, old.endpoint
                        ),
                    });
                }
            }
            for (tkey, old) in &self.prev_connections {
                if old.report_close && !curr_connections.contains_key(tkey) {
                    delta_events.push(TimelineEvent {
                        timestamp: ts,
                        kind: TimelineKind::ConnectionClosed,
                        severity: Severity::Safe,
                        process_name: old.process_name.clone(),
                        pid: old.pid,
                        endpoint: old.endpoint.clone(),
                        summary: format!(
                            "Socket closed by '{}' ({})",
                            old.process_name, old.endpoint
                        ),
                    });
                }
            }
        }

        // Track binary SHA-256 changes at identical executable paths.
        for p in &snapshot.processes {
            let Some(sha) = &p.sha256 else { continue };
            if p.exe_path.is_empty() {
                continue;
            }
            if let Some(prev_sha) = self.prev_hashes.get(&p.exe_path) {
                if prev_sha != sha {
                    delta_events.push(TimelineEvent {
                        timestamp: ts,
                        kind: TimelineKind::BinaryModified,
                        severity: Severity::High,
                        process_name: p.name.clone(),
                        pid: Some(p.pid),
                        endpoint: p.exe_path.clone(),
                        summary: format!(
                            "Binary SHA-256 changed on disk: {} -> {}",
                            &prev_sha[..prev_sha.len().min(12)],
                            &sha[..sha.len().min(12)]
                        ),
                    });
                }
            }
            self.prev_hashes.insert(p.exe_path.clone(), sha.clone());
        }

        // Check Welford beacon flows and emit H09-C2-BEACON findings + timeline alerts.
        let mut findings_added = false;
        for (bkey, stats) in &mut self.beacons {
            if !stats.is_periodic_beacon() {
                continue;
            }
            let cv = stats.coeff_of_variation().unwrap_or(0.0);
            let std_s = stats.std_dev();
            let remote_ep = format_endpoint(bkey.remote_ip, bkey.remote_port);

            if !stats.alerted {
                stats.alerted = true;
                delta_events.push(TimelineEvent {
                    timestamp: Local::now(),
                    kind: TimelineKind::BeaconSuspected,
                    severity: Severity::High,
                    process_name: stats.last_process_name.clone(),
                    pid: stats.last_pid,
                    endpoint: remote_ep.clone(),
                    summary: format!(
                        "Periodic C2 beacon suspected: {} -> {} (mean {:.1}s, CV {:.2}, n={})",
                        stats.last_process_name, remote_ep, stats.mean, cv, stats.intervals
                    ),
                });
            }

            // Attach H09-C2-BEACON to any snapshot where the flow was recently active (within 3 periods).
            if now_secs - stats.last_seen_secs <= (stats.mean * 3.0).max(15.0) {
                let already_present = snapshot.findings.iter().any(|f| {
                    f.rule_id == "H09-C2-BEACON" && f.endpoint.as_deref() == Some(remote_ep.as_str())
                });
                if !already_present {
                    snapshot.findings.push(SecurityFinding {
                        rule_id: "H09-C2-BEACON".to_string(),
                        category: "Periodic C2 Beaconing".to_string(),
                        mitre_id: "T1071".to_string(),
                        severity: Severity::High,
                        title: format!(
                            "Periodic Outbound C2 Beacon Pattern ({} -> {})",
                            stats.last_process_name, remote_ep
                        ),
                        description: format!(
                            "Process '{}' established {} consecutive outbound connections to {} with periodic inter-arrival mean {:.2}s (stddev {:.2}s, CV {:.3} <= {:.2}).",
                            stats.last_process_name,
                            stats.intervals + 1,
                            remote_ep,
                            stats.mean,
                            std_s,
                            cv,
                            MAX_BEACON_CV
                        ),
                        pid: stats.last_pid,
                        process_name: Some(stats.last_process_name.clone()),
                        endpoint: Some(remote_ep.clone()),
                        evidence: format!(
                            "Owner: {} | Remote: {} | Intervals: {} | Mean: {:.2}s | StdDev: {:.2}s | CV: {:.3}",
                            bkey.owner, remote_ep, stats.intervals, stats.mean, std_s, cv
                        ),
                        remediation: "Inspect the process for scheduled C2 callback loops, check outbound firewall logs, and capture packet metadata.".to_string(),
                    });
                    findings_added = true;
                }

                for conn in &mut snapshot.connections {
                    if conn.remote_ip == Some(bkey.remote_ip)
                        && conn.remote_port == Some(bkey.remote_port)
                    {
                        conn.elevate_severity(
                            Severity::High,
                            format!(
                                "Periodic outbound beacon cadence (mean {:.1}s, CV {:.2})",
                                stats.mean, cv
                            ),
                        );
                    }
                }
                if let Some(pid) = stats.last_pid {
                    for p in &mut snapshot.processes {
                        if p.pid == pid && p.max_severity < Severity::High {
                            p.max_severity = Severity::High;
                        }
                    }
                }
            }
        }

        self.prev_listeners = curr_listeners;
        self.prev_connections = curr_connections;
        self.initialized = true;

        for ev in &delta_events {
            self.events.push_front(ev.clone());
        }
        while self.events.len() > MAX_TIMELINE_EVENTS {
            self.events.pop_back();
        }
        snapshot.timeline_events = self.events.iter().cloned().collect();

        if findings_added {
            snapshot.findings.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then_with(|| a.rule_id.cmp(&b.rule_id))
            });
            snapshot.recompute_summary();
            snapshot.neutralize_text();
        }

        delta_events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ConnectionEntry, ExposureScope, ProcessRecord};
    use std::net::Ipv4Addr;

    fn outbound_conn(local_port: u16, remote_port: u16) -> ConnectionEntry {
        ConnectionEntry {
            id: 1,
            protocol: Protocol::Tcp,
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            local_port,
            remote_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))),
            remote_port: Some(remote_port),
            remote_hostname: None,
            state: "ESTABLISHED".to_string(),
            pid: Some(777),
            process_name: "agent".to_string(),
            exe_path: "/opt/agent".to_string(),
            cmdline: "/opt/agent".to_string(),
            sha256: Some(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
            ),
            lineage: Vec::new(),
            service_name: "HTTPS".to_string(),
            exposure: ExposureScope::LocalLan,
            remote_category: IpCategory::PublicInternet,
            severity: Severity::Safe,
            risk_reasons: Vec::new(),
        }
    }

    fn snap_with(conns: Vec<ConnectionEntry>, sha: &str) -> ScanSnapshot {
        let proc_rec = ProcessRecord {
            pid: 777,
            ppid: Some(1),
            name: "agent".to_string(),
            exe_path: "/opt/agent".to_string(),
            cmdline: "/opt/agent".to_string(),
            user: "u".to_string(),
            sha256: Some(sha.to_string()),
            original_filename: None,
            lineage: Vec::new(),
            cpu_usage: 0.0,
            memory_bytes: 0,
            run_time_secs: 1,
            exe_exists_on_disk: true,
            is_deleted_binary: false,
            open_sockets_count: conns.len(),
            max_severity: Severity::Safe,
        };
        let mut s = ScanSnapshot {
            timestamp: Local::now(),
            scan_duration_ms: 1,
            hostname: "h".to_string(),
            os_name: "os".to_string(),
            os_version: "1".to_string(),
            kernel_version: "1".to_string(),
            is_elevated: true,
            security_score: 100,
            security_grade: "A+".to_string(),
            scan_warnings: Vec::new(),
            sockets_without_exe: 0,
            suppressed_count: 0,
            total_connections: conns.len(),
            listening_ports: 0,
            established_connections: conns.len(),
            external_connections: conns.len(),
            suspicious_connections: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            connections: conns,
            findings: Vec::new(),
            audit_items: Vec::new(),
            processes: vec![proc_rec],
            timeline_events: Vec::new(),
            wifi_shield: None,
        };
        s.recompute_summary();
        s
    }

    #[test]
    fn detects_periodic_c2_beacon_and_ignores_persistent_or_irregular_traffic() {
        let mut rec = FlightRecorder::new();

        // 5 periodic callbacks on fresh ephemeral source ports (~10s +/- 0.5s -> CV ~ 0.05 <= 0.20).
        let times = [0.0, 10.0, 20.4, 30.1, 40.2];
        let mut last_snap = None;
        for (i, &t) in times.iter().enumerate() {
            let mut s = snap_with(vec![outbound_conn(50000 + i as u16, 443)], "aaaa");
            rec.observe_at(&mut s, t);
            last_snap = Some(s);
        }
        let final_snap = last_snap.unwrap();
        assert!(
            final_snap
                .findings
                .iter()
                .any(|f| f.rule_id == "H09-C2-BEACON"),
            "periodic low-jitter callbacks should trigger H09-C2-BEACON"
        );
        assert!(final_snap
            .timeline_events
            .iter()
            .any(|e| e.kind == TimelineKind::BeaconSuspected));

        // Irregular human browsing intervals must NOT trigger H09-C2-BEACON.
        let mut rec_irregular = FlightRecorder::new();
        for (i, &t) in [0.0, 2.0, 25.0, 27.0, 95.0].iter().enumerate() {
            let mut s = snap_with(vec![outbound_conn(51000 + i as u16, 443)], "aaaa");
            rec_irregular.observe_at(&mut s, t);
            assert!(!s.findings.iter().any(|f| f.rule_id == "H09-C2-BEACON"));
        }

        // Single long-lived persistent connection on the same source port must NOT trigger H09.
        let mut rec_persistent = FlightRecorder::new();
        for &t in &[0.0, 5.0, 10.0, 15.0, 20.0, 25.0] {
            let mut s = snap_with(vec![outbound_conn(52000, 443)], "aaaa");
            rec_persistent.observe_at(&mut s, t);
            assert!(!s.findings.iter().any(|f| f.rule_id == "H09-C2-BEACON"));
        }
    }

    #[test]
    fn records_socket_close_and_binary_hash_mutation() {
        let mut rec = FlightRecorder::new();
        let mut s1 = snap_with(vec![outbound_conn(53000, 8443)], "1111111111111111");
        assert!(rec.observe_at(&mut s1, 0.0).is_empty(), "seed scan stays quiet");

        let mut s2 = snap_with(Vec::new(), "2222222222222222");
        let delta = rec.observe_at(&mut s2, 3.0);
        assert!(delta.iter().any(|e| e.kind == TimelineKind::ConnectionClosed));
        assert!(delta.iter().any(|e| e.kind == TimelineKind::BinaryModified));
    }
}
