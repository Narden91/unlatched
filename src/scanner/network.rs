use crate::models::{
    ConnectionEntry, ExposureScope, IpCategory, ProcessRecord, Protocol, Severity,
};
use crate::scanner::indicators::{
    check_suspicious_exec_path, is_relay_name, is_shell_name, SENSITIVE_ORIGINAL_BINARIES,
};
use crate::scanner::ports_db::lookup_service_name;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// A lookup that fails to resolve blocks for about 1 s, so one worker would stall the queue.
const DNS_WORKERS: usize = 8;
const DNS_QUEUE_CAPACITY: usize = 256;
const DNS_CACHE_MAX_ENTRIES: usize = 2048;
const NEGATIVE_DNS_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct DnsEntry {
    host: Option<String>,
    retry_after: Option<Instant>,
}

#[derive(Clone)]
pub struct DnsCache {
    resolved: Arc<Mutex<HashMap<IpAddr, DnsEntry>>>,
    in_flight: Arc<Mutex<HashSet<IpAddr>>>,
    tx: mpsc::SyncSender<IpAddr>,
}

impl DnsCache {
    pub fn new() -> Self {
        let resolved = Arc::new(Mutex::new(HashMap::new()));
        let in_flight = Arc::new(Mutex::new(HashSet::new()));
        let (tx, rx) = mpsc::sync_channel::<IpAddr>(DNS_QUEUE_CAPACITY);
        let rx = Arc::new(Mutex::new(rx));

        for _ in 0..DNS_WORKERS {
            let rx = Arc::clone(&rx);
            let resolved_worker = Arc::clone(&resolved);
            let flight_worker = Arc::clone(&in_flight);
            thread::spawn(move || loop {
                // The guard drops at the end of this statement, so lookups run in parallel.
                let next = match rx.lock() {
                    Ok(guard) => guard.recv(),
                    Err(_) => return,
                };
                let Ok(ip) = next else { return };
                // Whoever controls the remote IP writes its PTR record, so validate & neutralize on entry.
                let host = reverse_dns_lookup(ip)
                    .filter(|h| is_valid_ptr_hostname(h))
                    .map(|h| crate::models::neutralized(&h).unwrap_or(h));

                let retry_after = if host.is_none() {
                    Some(Instant::now() + NEGATIVE_DNS_TTL)
                } else {
                    None
                };

                if let Ok(mut guard) = resolved_worker.lock() {
                    if guard.len() >= DNS_CACHE_MAX_ENTRIES {
                        guard.clear();
                    }
                    guard.insert(ip, DnsEntry { host, retry_after });
                }
                if let Ok(mut f) = flight_worker.lock() {
                    f.remove(&ip);
                }
            });
        }

        Self {
            resolved,
            in_flight,
            tx,
        }
    }

    /// Block until every in-flight lookup finished or `timeout` passed.
    pub fn wait_idle(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let empty = self.in_flight.lock().map(|q| q.is_empty()).unwrap_or(true);
            if empty {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    pub fn lookup_or_queue(&self, ip: IpAddr) -> Option<String> {
        if ip.is_unspecified() || ip.is_loopback() {
            return Some("localhost".to_string());
        }

        if let Ok(guard) = self.resolved.lock() {
            if let Some(entry) = guard.get(&ip) {
                match (&entry.host, entry.retry_after) {
                    (Some(h), _) => return Some(h.clone()),
                    (None, Some(until)) if Instant::now() < until => return None,
                    _ => {}
                }
            }
        }

        if let Ok(mut f) = self.in_flight.lock() {
            if f.len() < DNS_QUEUE_CAPACITY && f.insert(ip) && self.tx.try_send(ip).is_err() {
                f.remove(&ip);
            }
        }

        None
    }
}

#[must_use]
fn is_valid_ptr_hostname(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[cfg_attr(not(any(windows, target_os = "linux")), allow(unused_variables))]
fn reverse_dns_lookup(ip: IpAddr) -> Option<String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let sys_root = crate::scanner::system_root();
        let output = Command::new(nslookup_exe())
            .env_clear()
            .env("SystemRoot", &sys_root)
            .arg(ip.to_string())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        parse_nslookup_name(&String::from_utf8_lossy(&output.stdout))
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        // Absolute path + cleared env: user-controlled PATH or LD_PRELOAD must not run as root.
        let getent = ["/usr/bin/getent", "/bin/getent"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())?;
        let output = Command::new(getent)
            .env_clear()
            .args(["hosts", &ip.to_string()])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .split_whitespace()
            .nth(1)
            .map(|h| h.trim_end_matches('.').to_string())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

/// Absolute path, because a bare "nslookup" is searched in the scanner's own folder before
/// System32. A user-writable build folder would then let a planted nslookup.exe run as admin.
#[cfg(windows)]
fn nslookup_exe() -> std::path::PathBuf {
    crate::scanner::system_root()
        .join("System32")
        .join("nslookup.exe")
}

/// Read the answer line of `nslookup <ip>` without matching a localized "Name:" label.
/// The answer is the first line after the blank line that ends the Server/Address header.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_nslookup_name(stdout: &str) -> Option<String> {
    let mut lines = stdout.lines().map(str::trim).skip_while(|l| l.is_empty());
    lines.by_ref().find(|l| l.is_empty())?;
    let answer = lines.find(|l| !l.is_empty())?;
    if answer.starts_with('*') {
        return None;
    }
    let host = answer.split_once(':')?.1.trim().trim_end_matches('.');
    is_valid_ptr_hostname(host).then(|| host.to_string())
}

pub fn classify_ip(ip: IpAddr) -> IpCategory {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                IpCategory::Unspecified
            } else if v6.is_loopback() {
                IpCategory::Loopback
            } else if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                classify_ipv4(mapped_v4)
            } else {
                let seg0 = v6.segments()[0];
                if (seg0 & 0xfe00) == 0xfc00 {
                    IpCategory::PrivateLan
                } else if (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xff00) == 0xff00 {
                    IpCategory::LinkLocal
                } else {
                    IpCategory::PublicInternet
                }
            }
        }
    }
}

fn classify_ipv4(v4: Ipv4Addr) -> IpCategory {
    let octets = v4.octets();
    if v4.is_unspecified() {
        IpCategory::Unspecified
    } else if v4.is_loopback() {
        IpCategory::Loopback
    } else if v4.is_private() || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64) {
        IpCategory::PrivateLan
    } else if v4.is_link_local() || v4.is_multicast() || v4.is_broadcast() {
        IpCategory::LinkLocal
    } else {
        IpCategory::PublicInternet
    }
}

pub fn determine_exposure(local_ip: IpAddr) -> ExposureScope {
    match classify_ip(local_ip) {
        IpCategory::Unspecified => ExposureScope::WildcardAllInterfaces,
        IpCategory::Loopback => ExposureScope::Loopback,
        IpCategory::PrivateLan | IpCategory::LinkLocal => ExposureScope::LocalLan,
        IpCategory::PublicInternet => ExposureScope::PublicInternet,
    }
}

fn format_tcp_state(state: TcpState) -> &'static str {
    match state {
        TcpState::Listen => "LISTEN",
        TcpState::Established => "ESTABLISHED",
        TcpState::SynSent => "SYN_SENT",
        TcpState::SynReceived => "SYN_RECV",
        TcpState::FinWait1 => "FIN_WAIT1",
        TcpState::FinWait2 => "FIN_WAIT2",
        TcpState::CloseWait => "CLOSE_WAIT",
        TcpState::Closing => "CLOSING",
        TcpState::LastAck => "LAST_ACK",
        TcpState::TimeWait => "TIME_WAIT",
        TcpState::DeleteTcb => "DELETE_TCB",
        TcpState::Closed => "CLOSED",
        TcpState::Unknown => "UNKNOWN",
    }
}

pub fn is_windows_rpc_system_process(proc_name: &str) -> bool {
    proc_name.eq_ignore_ascii_case("svchost.exe")
        || proc_name.eq_ignore_ascii_case("lsass.exe")
        || proc_name.eq_ignore_ascii_case("wininit.exe")
        || proc_name.eq_ignore_ascii_case("services.exe")
        || proc_name.eq_ignore_ascii_case("spoolsv.exe")
        || proc_name.eq_ignore_ascii_case("system")
}

pub fn collect_network_connections(
    processes: &mut HashMap<u32, ProcessRecord>,
    dns_cache: &DnsCache,
) -> (Vec<ConnectionEntry>, Option<String>) {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    // An empty list on error would look like a clean host, so report the error to the caller.
    let (sockets, warning) = match get_sockets_info(af_flags, proto_flags) {
        Ok(s) => (s, None),
        Err(e) => (
            Vec::new(),
            Some(format!(
                "Socket enumeration failed: {e}. No sockets were checked."
            )),
        ),
    };

    let mut entries = Vec::with_capacity(sockets.len());

    for (idx, sock) in sockets.into_iter().enumerate() {
        let pid = attribute_socket_pids(&sock.associated_pids, processes);

        let (protocol, local_ip, local_port, remote_ip, remote_port, state) =
            match sock.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    let proto = match tcp.local_addr {
                        IpAddr::V4(_) => Protocol::Tcp,
                        IpAddr::V6(_) => Protocol::Tcp6,
                    };
                    let has_remote = !tcp.remote_addr.is_unspecified() || tcp.remote_port != 0;
                    (
                        proto,
                        tcp.local_addr,
                        tcp.local_port,
                        has_remote.then_some(tcp.remote_addr),
                        has_remote.then_some(tcp.remote_port),
                        format_tcp_state(tcp.state).to_string(),
                    )
                }
                ProtocolSocketInfo::Udp(udp) => {
                    let proto = match udp.local_addr {
                        IpAddr::V4(_) => Protocol::Udp,
                        IpAddr::V6(_) => Protocol::Udp6,
                    };
                    (
                        proto,
                        udp.local_addr,
                        udp.local_port,
                        None,
                        None,
                        "OPEN".to_string(),
                    )
                }
            };

        let (process_name, exe_path, cmdline, sha256, lineage) =
            resolve_socket_owner(pid, processes);

        let primary_port = if state == "LISTEN" || state == "OPEN" || remote_port.is_none() {
            local_port
        } else if lookup_service_name(local_port) != "Custom" {
            local_port
        } else {
            remote_port.unwrap_or(local_port)
        };

        let mut service_name = lookup_service_name(primary_port).to_string();
        if service_name == "Custom"
            && state == "LISTEN"
            && local_port >= 49152
            && is_windows_rpc_system_process(&process_name)
        {
            service_name = "Win-RPC-Dyn".to_string();
        }

        let exposure = determine_exposure(local_ip);
        let remote_category = remote_ip
            .map(classify_ip)
            .unwrap_or(IpCategory::Unspecified);
        let remote_hostname = remote_ip.and_then(|rip| dns_cache.lookup_or_queue(rip));

        entries.push(ConnectionEntry {
            id: idx + 1,
            protocol,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            remote_hostname,
            state,
            pid,
            process_name,
            exe_path,
            cmdline,
            sha256,
            lineage,
            service_name,
            exposure,
            remote_category,
            severity: Severity::Safe,
            risk_reasons: Vec::new(),
        });
    }

    (entries, warning)
}

/// Increments `open_sockets_count` on every PID sharing the socket descriptor and selects the
/// highest-risk owner PID (preventing FD-inheritance via `dup2` from hiding a child shell behind
/// its parent daemon's lower PID).
fn attribute_socket_pids(
    associated_pids: &[u32],
    processes: &mut HashMap<u32, ProcessRecord>,
) -> Option<u32> {
    if associated_pids.is_empty() {
        return None;
    }

    let mut seen_buf = [0u32; 8];
    let mut seen_len = 0usize;
    for &id in associated_pids {
        if seen_len < seen_buf.len() {
            if seen_buf[..seen_len].contains(&id) {
                continue;
            }
            seen_buf[seen_len] = id;
            seen_len += 1;
        }
        if let Some(p) = processes.get_mut(&id) {
            p.open_sockets_count += 1;
        }
    }

    if associated_pids.len() == 1 {
        return Some(associated_pids[0]);
    }

    associated_pids
        .iter()
        .copied()
        .max_by_key(|&id| (pid_risk_weight(processes.get(&id)), id))
}

fn pid_risk_weight(proc_opt: Option<&ProcessRecord>) -> u8 {
    let Some(p) = proc_opt else { return 0 };
    let name_lower = p.name.to_ascii_lowercase();
    let orig_lower = p
        .original_filename
        .as_deref()
        .map(str::to_ascii_lowercase);
    if is_shell_name(&name_lower)
        || is_relay_name(&name_lower)
        || orig_lower
            .as_deref()
            .is_some_and(|o| SENSITIVE_ORIGINAL_BINARIES.contains(&o))
    {
        return 4;
    }
    let exe_norm = p.exe_path.to_ascii_lowercase().replace('/', "\\");
    if p.is_deleted_binary || check_suspicious_exec_path(&p.exe_path, &exe_norm).is_some() {
        return 3;
    }
    1
}

fn resolve_socket_owner(
    pid: Option<u32>,
    processes: &HashMap<u32, ProcessRecord>,
) -> (String, String, String, Option<String>, Vec<String>) {
    if let Some(p) = pid.and_then(|id| processes.get(&id)) {
        return (
            p.name.clone(),
            p.exe_path.clone(),
            p.cmdline.clone(),
            p.sha256.clone(),
            p.lineage.clone(),
        );
    }

    match pid {
        Some(0) => (
            "Kernel".to_string(),
            String::new(),
            String::new(),
            None,
            vec!["Kernel(0)".to_string()],
        ),
        Some(4) => (
            "System".to_string(),
            "ntoskrnl.exe".to_string(),
            "System".to_string(),
            None,
            vec!["System(4)".to_string()],
        ),
        Some(id) => (
            format!("PID {}", id),
            String::new(),
            String::new(),
            None,
            Vec::new(),
        ),
        None => (
            "Unowned".to_string(),
            String::new(),
            String::new(),
            None,
            Vec::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nslookup_answer_is_found_in_any_language() {
        let en = "Server:  router.lan\r\nAddress:  192.168.1.1\r\n\r\nName:    dns.google\r\nAddress:  8.8.8.8\r\n\r\n";
        let it = "Server:  router.lan\nAddress:  192.168.1.1\n\nNome:    dns.google\nAddress:  8.8.8.8\n";
        let fr = "Serveur :  router.lan\nAddress:  192.168.1.1\n\nNom :    dns.google\nAddress:  8.8.8.8\n";
        for out in [en, it, fr] {
            assert_eq!(parse_nslookup_name(out).as_deref(), Some("dns.google"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn nslookup_is_spawned_from_system32_by_absolute_path() {
        let exe = nslookup_exe();
        assert!(exe.is_absolute(), "{}", exe.display());
        assert!(exe.ends_with(r"System32\nslookup.exe"));
        assert!(exe.exists(), "{}", exe.display());
    }

    #[test]
    fn nslookup_failure_and_malicious_ptr_give_none() {
        let missing = "Server:  router.lan\nAddress:  192.168.1.1\n\n*** router.lan can't find 203.0.113.7: Non-existent domain\n";
        assert_eq!(parse_nslookup_name(missing), None);
        assert_eq!(parse_nslookup_name(""), None);
        let starred = "Server:  r\nAddress:  1.1.1.1\n\n*** timeout:expired\n";
        assert_eq!(parse_nslookup_name(starred), None);
        let spaced = "Server:  r\nAddress:  1.1.1.1\n\nDNS request timed out: timeout was 2 seconds.\n";
        assert_eq!(parse_nslookup_name(spaced), None);
        let injected = "Server:  r\nAddress:  1.1.1.1\n\nName:    evil`pwn`|cell\n";
        assert_eq!(parse_nslookup_name(injected), None);
    }

    #[test]
    fn multi_pid_socket_prefers_inherited_shell_and_counts_all_owners() {
        let mut procs = HashMap::new();
        for (pid, name, exe) in [(400u32, "nginx", "/usr/sbin/nginx"), (9001u32, "bash", "/bin/bash")] {
            procs.insert(
                pid,
                ProcessRecord {
                    pid,
                    ppid: None,
                    name: name.to_string(),
                    exe_path: exe.to_string(),
                    cmdline: name.to_string(),
                    user: "www-data".to_string(),
                    sha256: None,
                    original_filename: None,
                    lineage: Vec::new(),
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    run_time_secs: 0,
                    exe_exists_on_disk: true,
                    is_deleted_binary: false,
                    open_sockets_count: 0,
                    max_severity: Severity::Safe,
                },
            );
        }

        let chosen = attribute_socket_pids(&[400, 9001], &mut procs);
        assert_eq!(chosen, Some(9001));
        assert_eq!(procs[&400].open_sockets_count, 1);
        assert_eq!(procs[&9001].open_sockets_count, 1);
    }
}
