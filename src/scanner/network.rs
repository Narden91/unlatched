use crate::models::{
    ConnectionEntry, ExposureScope, IpCategory, ProcessRecord, Protocol, Severity,
};
use crate::scanner::ports_db::lookup_service_name;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

#[derive(Clone)]
pub struct DnsCache {
    resolved: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    queued: Arc<Mutex<HashSet<IpAddr>>>,
    tx: mpsc::Sender<IpAddr>,
}

impl DnsCache {
    pub fn new() -> Self {
        let resolved = Arc::new(Mutex::new(HashMap::new()));
        let queued = Arc::new(Mutex::new(HashSet::new()));
        let (tx, rx) = mpsc::channel::<IpAddr>();

        let resolved_worker = Arc::clone(&resolved);
        thread::spawn(move || {
            while let Ok(ip) = rx.recv() {
                let host = reverse_dns_lookup(ip);
                if let Ok(mut guard) = resolved_worker.lock() {
                    guard.insert(ip, host);
                }
            }
        });

        Self {
            resolved,
            queued,
            tx,
        }
    }

    pub fn lookup_or_queue(&self, ip: IpAddr) -> Option<String> {
        if ip.is_unspecified() || ip.is_loopback() {
            return Some("localhost".to_string());
        }

        if let Ok(guard) = self.resolved.lock() {
            if let Some(res) = guard.get(&ip) {
                return res.clone();
            }
        }

        if let Ok(mut q) = self.queued.lock() {
            if q.insert(ip) {
                let _ = self.tx.send(ip);
            }
        }

        None
    }
}

#[cfg_attr(not(any(windows, target_os = "linux")), allow(unused_variables))]
fn reverse_dns_lookup(ip: IpAddr) -> Option<String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let output = Command::new("nslookup")
            .arg(ip.to_string())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed
                .strip_prefix("Name:")
                .or_else(|| trimmed.strip_prefix("Nome:"))
            {
                let host = rest.trim().trim_end_matches('.');
                if !host.is_empty() {
                    return Some(host.to_string());
                }
            }
        }
        None
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let output = Command::new("getent")
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
    matches!(
        proc_name.to_lowercase().as_str(),
        "svchost.exe" | "lsass.exe" | "wininit.exe" | "services.exe" | "spoolsv.exe" | "system"
    )
}

pub fn collect_network_connections(
    processes: &mut HashMap<u32, ProcessRecord>,
    dns_cache: &DnsCache,
) -> Vec<ConnectionEntry> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = get_sockets_info(af_flags, proto_flags).unwrap_or_default();

    let mut entries = Vec::with_capacity(sockets.len());

    for (idx, sock) in sockets.into_iter().enumerate() {
        let pid = sock.associated_pids.first().copied();

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

    entries
}

fn resolve_socket_owner(
    pid: Option<u32>,
    processes: &mut HashMap<u32, ProcessRecord>,
) -> (String, String, String, Option<String>, Vec<String>) {
    if let Some(p) = pid.and_then(|id| processes.get_mut(&id)) {
        p.open_sockets_count += 1;
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
