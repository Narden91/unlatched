use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Safe => "SAFE",
        }
    }

    #[must_use]
    pub fn penalty_points(&self) -> u32 {
        match self {
            Severity::Critical => 30,
            Severity::High => 15,
            Severity::Medium => 6,
            Severity::Low => 2,
            Severity::Safe => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Protocol {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Tcp6 => "TCP6",
            Protocol::Udp => "UDP",
            Protocol::Udp6 => "UDP6",
        }
    }

    #[must_use]
    pub fn is_tcp(&self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Tcp6)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExposureScope {
    Loopback,
    LoopbackProxy,
    LocalLan,
    WildcardAllInterfaces,
    PublicInternet,
}

impl ExposureScope {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            ExposureScope::Loopback => "Loopback (Local Only)",
            ExposureScope::LoopbackProxy => "Loopback via Exposed Proxy",
            ExposureScope::LocalLan => "LAN Interface",
            ExposureScope::WildcardAllInterfaces => "0.0.0.0 / :: (All Ifaces)",
            ExposureScope::PublicInternet => "Public Interface",
        }
    }

    #[must_use]
    pub fn short_label(&self) -> &'static str {
        match self {
            ExposureScope::Loopback => "LOCAL",
            ExposureScope::LoopbackProxy => "PROXY-EXP",
            ExposureScope::LocalLan => "LAN",
            ExposureScope::WildcardAllInterfaces => "WILDCARD",
            ExposureScope::PublicInternet => "PUBLIC",
        }
    }

    #[must_use]
    pub fn is_network_reachable(&self) -> bool {
        matches!(
            self,
            ExposureScope::LocalLan
                | ExposureScope::WildcardAllInterfaces
                | ExposureScope::PublicInternet
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpCategory {
    Unspecified,
    Loopback,
    PrivateLan,
    LinkLocal,
    PublicInternet,
}

impl IpCategory {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            IpCategory::Unspecified => "Any (*)",
            IpCategory::Loopback => "Loopback",
            IpCategory::PrivateLan => "Private LAN",
            IpCategory::LinkLocal => "Link-Local",
            IpCategory::PublicInternet => "Public Internet",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub user: String,
    pub sha256: Option<String>,
    #[serde(default)]
    pub original_filename: Option<String>,
    pub lineage: Vec<String>,
    pub cpu_usage: f32,
    pub memory_bytes: u64,
    pub run_time_secs: u64,
    pub exe_exists_on_disk: bool,
    pub is_deleted_binary: bool,
    pub open_sockets_count: usize,
    pub max_severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub id: usize,
    pub protocol: Protocol,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub remote_hostname: Option<String>,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub sha256: Option<String>,
    pub lineage: Vec<String>,
    pub service_name: String,
    pub exposure: ExposureScope,
    pub remote_category: IpCategory,
    pub severity: Severity,
    pub risk_reasons: Vec<String>,
}

impl ConnectionEntry {
    #[must_use]
    pub fn local_endpoint(&self) -> String {
        format_endpoint(self.local_ip, self.local_port)
    }

    #[must_use]
    pub fn has_remote_peer(&self) -> bool {
        match (self.remote_ip, self.remote_port) {
            (Some(ip), Some(port)) => !ip.is_unspecified() || port != 0,
            _ => false,
        }
    }

    #[must_use]
    pub fn remote_endpoint(&self) -> String {
        match (self.remote_ip, self.remote_port) {
            (Some(ip), Some(port)) if !ip.is_unspecified() || port != 0 => {
                format_endpoint(ip, port)
            }
            _ => "*:*".to_string(),
        }
    }

    #[must_use]
    pub fn remote_display(&self) -> String {
        if !self.has_remote_peer() {
            return "*:*".to_string();
        }
        let ep = self.remote_endpoint();
        if let Some(host) = &self.remote_hostname {
            if !host.is_empty() {
                return format!("{} ({})", ep, host);
            }
        }
        ep
    }

    /// Zero-allocation listener predicate safe for hot sort comparators.
    #[must_use]
    pub fn is_listening(&self) -> bool {
        self.state == "LISTEN" || (self.state == "OPEN" && !self.has_remote_peer())
    }

    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == "ESTABLISHED"
    }
}

#[must_use]
pub fn format_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{}:{}", v4, port),
        IpAddr::V6(v6) => format!("[{}]:{}", v6, port),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub rule_id: String,
    pub category: String,
    pub mitre_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub endpoint: Option<String>,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditStatus {
    Pass,
    Info,
    Warning,
    Critical,
}

impl AuditStatus {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            AuditStatus::Pass => "PASS",
            AuditStatus::Info => "INFO",
            AuditStatus::Warning => "WARN",
            AuditStatus::Critical => "ALERT",
        }
    }

    #[must_use]
    pub fn to_severity(&self) -> Severity {
        match self {
            AuditStatus::Critical => Severity::Critical,
            AuditStatus::Warning => Severity::High,
            AuditStatus::Info => Severity::Low,
            AuditStatus::Pass => Severity::Safe,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditItem {
    pub check_id: String,
    pub subsystem: String,
    pub name: String,
    pub location: String,
    pub value: String,
    pub status: AuditStatus,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineKind {
    ListenerOpened,
    ListenerClosed,
    ConnectionOpened,
    ConnectionClosed,
    BinaryModified,
    BeaconSuspected,
}

impl TimelineKind {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            TimelineKind::ListenerOpened => "+LISTEN",
            TimelineKind::ListenerClosed => "-LISTEN",
            TimelineKind::ConnectionOpened => "+SOCKET",
            TimelineKind::ConnectionClosed => "-SOCKET",
            TimelineKind::BinaryModified => "!HASH",
            TimelineKind::BeaconSuspected => "!BEACON",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Local>,
    pub kind: TimelineKind,
    pub severity: Severity,
    pub process_name: String,
    pub pid: Option<u32>,
    pub endpoint: String,
    pub summary: String,
}

/// Characters a terminal or text viewer acts on instead of showing: C0/C1 controls (ESC starts
/// cursor, erase and title sequences) and bidi controls (U+202E makes a name read backwards).
fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// `None` when `s` is safe to print. Otherwise a copy with each unsafe char written as `\u{..}`,
/// so the evidence stays readable but cannot drive the terminal.
#[must_use]
pub fn neutralized(s: &str) -> Option<String> {
    if !s.chars().any(is_unsafe_char) {
        return None;
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if is_unsafe_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// Zero-allocation case-insensitive substring match when `needle_lower` is ASCII.
#[must_use]
pub fn contains_ci(haystack: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if needle_lower.is_ascii() {
        let nb = needle_lower.as_bytes();
        let hb = haystack.as_bytes();
        if hb.len() < nb.len() {
            return false;
        }
        hb.windows(nb.len())
            .any(|w| w.eq_ignore_ascii_case(nb))
    } else {
        haystack.to_lowercase().contains(needle_lower)
    }
}

/// Zero-allocation ASCII case-insensitive comparator for hot sort routines.
#[must_use]
pub fn cmp_ci(a: &str, b: &str) -> Ordering {
    a.bytes()
        .map(|c| c.to_ascii_lowercase())
        .cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
}

/// 100 minus each finding's penalty, floored at 0, plus a letter grade.
/// The score counts findings. It does not measure how secure the host is.
#[must_use]
pub fn score_and_grade(findings: &[SecurityFinding], incomplete: bool) -> (u8, String) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiProfileCategory {
    Public,
    Private,
    Domain,
    Unknown,
}

impl WifiProfileCategory {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            WifiProfileCategory::Public => "PUBLIC (Zero-Trust)",
            WifiProfileCategory::Private => "PRIVATE (Trusted LAN)",
            WifiProfileCategory::Domain => "DOMAIN (Enterprise)",
            WifiProfileCategory::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiRiskCheck {
    pub check_id: String,
    pub vector: String,
    pub status: AuditStatus,
    pub severity: Severity,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiShieldReport {
    pub connected: bool,
    pub interface_name: String,
    pub interface_guid: Option<String>,
    pub interface_index: Option<u32>,
    pub ssid: String,
    pub bssid: String,
    pub auth_suite: String,
    pub cipher_suite: String,
    pub radio_info: String,
    pub signal_percent: Option<u8>,
    pub rssi_dbm: Option<i32>,
    pub profile_category: WifiProfileCategory,
    pub local_ip: Option<IpAddr>,
    pub subnet_prefix: Option<u8>,
    pub gateway_ip: Option<IpAddr>,
    pub gateway_mac: Option<String>,
    pub dhcp_server: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub vpn_active: bool,
    pub vpn_interfaces: Vec<String>,
    pub tunnelvision_bypass: bool,
    pub is_public_or_guest_ssid: bool,
    pub wifi_safety_score: u8,
    pub wifi_grade: String,
    pub risk_level: Severity,
    pub exposed_lan_listeners: usize,
    pub exposed_shadow_ai_ports: Vec<u16>,
    pub cleartext_sockets: usize,
    pub checks: Vec<WifiRiskCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub timestamp: DateTime<Local>,
    pub scan_duration_ms: u128,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub is_elevated: bool,
    pub security_score: u8,
    pub security_grade: String,
    /// Collector failures. A non-empty list means the counts below may be too low.
    #[serde(default)]
    pub scan_warnings: Vec<String>,
    /// Sockets whose program path is unknown, usually because the scan is not elevated.
    #[serde(default)]
    pub sockets_without_exe: usize,
    /// Findings suppressed via cryptographic SHA-256 allowlist.
    #[serde(default)]
    pub suppressed_count: usize,
    pub total_connections: usize,
    pub listening_ports: usize,
    pub established_connections: usize,
    pub external_connections: usize,
    pub suspicious_connections: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub connections: Vec<ConnectionEntry>,
    pub findings: Vec<SecurityFinding>,
    pub audit_items: Vec<AuditItem>,
    pub processes: Vec<ProcessRecord>,
    #[serde(default)]
    pub timeline_events: Vec<TimelineEvent>,
    #[serde(default)]
    pub wifi_shield: Option<WifiShieldReport>,
}

impl ScanSnapshot {
    /// Single-pass aggregation of socket and finding counters plus score/grade recalculation.
    pub fn recompute_summary(&mut self) {
        let mut sockets_without_exe = 0usize;
        let mut listening_ports = 0usize;
        let mut established_connections = 0usize;
        let mut external_connections = 0usize;
        let mut suspicious_connections = 0usize;

        for c in &self.connections {
            if c.exe_path.is_empty() {
                sockets_without_exe += 1;
            }
            if c.is_listening() {
                listening_ports += 1;
            }
            if c.is_established() {
                established_connections += 1;
            }
            if c.remote_category == IpCategory::PublicInternet {
                external_connections += 1;
            }
            if c.severity >= Severity::Medium {
                suspicious_connections += 1;
            }
        }

        let mut critical_count = 0usize;
        let mut high_count = 0usize;
        let mut medium_count = 0usize;
        let mut low_count = 0usize;

        for f in &self.findings {
            match f.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
                Severity::Safe => {}
            }
        }

        self.total_connections = self.connections.len();
        self.sockets_without_exe = sockets_without_exe;
        self.listening_ports = listening_ports;
        self.established_connections = established_connections;
        self.external_connections = external_connections;
        self.suspicious_connections = suspicious_connections;
        self.critical_count = critical_count;
        self.high_count = high_count;
        self.medium_count = medium_count;
        self.low_count = low_count;

        let (score, grade) = score_and_grade(&self.findings, !self.scan_warnings.is_empty());
        self.security_score = score;
        self.security_grade = grade;
    }

    /// Make every text field safe to print. Run it after detection: the rules must see the
    /// raw text, while the CLI, TUI and Markdown must not pass attacker bytes to a terminal.
    pub fn neutralize_text(&mut self) {
        fn fix(s: &mut String) {
            if let Some(clean) = neutralized(s) {
                *s = clean;
            }
        }
        fn fix_opt(s: &mut Option<String>) {
            if let Some(s) = s {
                fix(s);
            }
        }
        fn fix_all(v: &mut [String]) {
            v.iter_mut().for_each(fix);
        }

        for s in [
            &mut self.hostname,
            &mut self.os_name,
            &mut self.os_version,
            &mut self.kernel_version,
            &mut self.security_grade,
        ] {
            fix(s);
        }
        fix_all(&mut self.scan_warnings);
        for c in &mut self.connections {
            for s in [
                &mut c.process_name,
                &mut c.exe_path,
                &mut c.cmdline,
                &mut c.state,
                &mut c.service_name,
            ] {
                fix(s);
            }
            fix_opt(&mut c.sha256);
            fix_opt(&mut c.remote_hostname);
            fix_all(&mut c.lineage);
            fix_all(&mut c.risk_reasons);
        }
        for f in &mut self.findings {
            for s in [
                &mut f.rule_id,
                &mut f.category,
                &mut f.mitre_id,
                &mut f.title,
                &mut f.description,
                &mut f.evidence,
                &mut f.remediation,
            ] {
                fix(s);
            }
            fix_opt(&mut f.process_name);
            fix_opt(&mut f.endpoint);
        }
        for a in &mut self.audit_items {
            for s in [
                &mut a.check_id,
                &mut a.subsystem,
                &mut a.name,
                &mut a.location,
                &mut a.value,
                &mut a.details,
            ] {
                fix(s);
            }
        }
        for p in &mut self.processes {
            for s in [&mut p.name, &mut p.exe_path, &mut p.cmdline, &mut p.user] {
                fix(s);
            }
            fix_opt(&mut p.sha256);
            fix_opt(&mut p.original_filename);
            fix_all(&mut p.lineage);
        }
        for ev in &mut self.timeline_events {
            for s in [&mut ev.process_name, &mut ev.endpoint, &mut ev.summary] {
                fix(s);
            }
        }
        if let Some(ws) = &mut self.wifi_shield {
            for s in [
                &mut ws.interface_name,
                &mut ws.ssid,
                &mut ws.bssid,
                &mut ws.auth_suite,
                &mut ws.cipher_suite,
                &mut ws.radio_info,
                &mut ws.wifi_grade,
            ] {
                fix(s);
            }
            fix_opt(&mut ws.interface_guid);
            fix_opt(&mut ws.gateway_mac);
            fix_all(&mut ws.vpn_interfaces);
            for chk in &mut ws.checks {
                for s in [
                    &mut chk.check_id,
                    &mut chk.vector,
                    &mut chk.detail,
                    &mut chk.recommendation,
                ] {
                    fix(s);
                }
            }
        }
    }
}
