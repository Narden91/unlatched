use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
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
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Safe => "SAFE",
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Tcp6 => "TCP6",
            Protocol::Udp => "UDP",
            Protocol::Udp6 => "UDP6",
        }
    }

    pub fn is_tcp(&self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Tcp6)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExposureScope {
    Loopback,
    LocalLan,
    WildcardAllInterfaces,
    PublicInternet,
}

impl ExposureScope {
    pub fn label(&self) -> &'static str {
        match self {
            ExposureScope::Loopback => "Loopback (Local Only)",
            ExposureScope::LocalLan => "LAN Interface",
            ExposureScope::WildcardAllInterfaces => "0.0.0.0 / :: (All Ifaces)",
            ExposureScope::PublicInternet => "Public Interface",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            ExposureScope::Loopback => "LOCAL",
            ExposureScope::LocalLan => "LAN",
            ExposureScope::WildcardAllInterfaces => "WILDCARD",
            ExposureScope::PublicInternet => "PUBLIC",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpCategory {
    Unspecified,
    Loopback,
    PrivateLan,
    LinkLocal,
    PublicInternet,
}

impl IpCategory {
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
    pub fn local_endpoint(&self) -> String {
        format_endpoint(self.local_ip, self.local_port)
    }

    pub fn remote_endpoint(&self) -> String {
        match (self.remote_ip, self.remote_port) {
            (Some(ip), Some(port)) if !ip.is_unspecified() || port != 0 => {
                format_endpoint(ip, port)
            }
            _ => "*:*".to_string(),
        }
    }

    pub fn remote_display(&self) -> String {
        let ep = self.remote_endpoint();
        if let Some(host) = &self.remote_hostname {
            if !host.is_empty() && ep != "*:*" {
                return format!("{} ({})", ep, host);
            }
        }
        ep
    }

    pub fn is_listening(&self) -> bool {
        self.state == "LISTEN" || (self.state == "OPEN" && self.remote_endpoint() == "*:*")
    }

    pub fn is_established(&self) -> bool {
        self.state == "ESTABLISHED"
    }
}

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
    pub fn label(&self) -> &'static str {
        match self {
            AuditStatus::Pass => "PASS",
            AuditStatus::Info => "INFO",
            AuditStatus::Warning => "WARN",
            AuditStatus::Critical => "ALERT",
        }
    }

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

/// Characters a terminal or text viewer acts on instead of showing: C0/C1 controls (ESC starts
/// cursor, erase and title sequences) and bidi controls (U+202E makes a name read backwards).
fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `None` when `s` is safe to print. Otherwise a copy with each unsafe char written as `\u{..}`,
/// so the evidence stays readable but cannot drive the terminal.
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
}

impl ScanSnapshot {
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
            fix_all(&mut p.lineage);
        }
    }
}

