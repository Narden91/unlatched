use super::network::DnsCache;
use super::wifi_shield::{RawLinkSnapshot, WifiRadarState};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const MAX_HOSTS: u32 = 254;

#[derive(Clone, Debug, Serialize)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub role: &'static str,
    pub kind: &'static str,
    pub evidence: String,
    pub observation: &'static str,
    pub distance_m: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkMap {
    pub ssid: String,
    pub bssid: String,
    pub interface: String,
    pub local_ip: Option<Ipv4Addr>,
    pub prefix: Option<u8>,
    pub signal_percent: Option<u8>,
    pub scanned_at: String,
    pub elapsed_ms: u64,
    pub active: bool,
    pub can_scan: bool,
    pub devices: Vec<Device>,
    pub warnings: Vec<String>,
}

pub struct Discovery {
    radar: WifiRadarState,
    dns: DnsCache,
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            radar: WifiRadarState::new(),
            dns: DnsCache::new(),
        }
    }

    pub fn scan(&mut self, active: bool) -> Result<NetworkMap, String> {
        if !cfg!(windows) {
            return Err("Wi-Fi device mapping currently supports Windows only.".into());
        }
        let start = Instant::now();
        let mut raw = self.telemetry()?;
        let mut warnings = vec![
            "3D placement is schematic. Physical distances are unavailable without measured coordinates or compatible ranging hardware.".into(),
            "LAN neighbors may be wired or wireless. Sleeping devices and client isolation can hide peers; this is not a router client list.".into(),
        ];
        if !raw.wifi.connected {
            warnings.push("No active Wi-Fi connection was detected. Check the connection and Windows Location permission if telemetry is unavailable.".into());
        }
        let local = local_ipv4(&raw);
        let targets = local
            .zip(raw.subnet_prefix)
            .ok_or_else(|| {
                "The Wi-Fi interface IPv4 address or subnet mask is unavailable.".to_string()
            })
            .and_then(|(ip, prefix)| subnet_hosts(ip, prefix));
        if let Err(reason) = &targets {
            warnings.push(reason.clone());
        }
        let can_scan = raw.wifi.connected && targets.is_ok();
        let mut replies = HashSet::new();
        if active {
            if !can_scan {
                return Err(warnings
                    .last()
                    .cloned()
                    .unwrap_or_else(|| "No active Wi-Fi connection.".into()));
            }
            let before = raw.clone();
            replies = probe_hosts(local.unwrap(), &targets?)?;
            raw = self.telemetry()?;
            if !same_network(&before, &raw) {
                return Err("Wi-Fi connection changed during discovery. Refresh and scan again.".into());
            }
        }

        let mut devices = build_devices(&raw, &replies);
        if active {
            // Resolution is optional; the map must finish even if DNS is slow or absent.
            for device in &devices {
                if device.role != "local" {
                    self.dns.lookup_or_queue(IpAddr::V4(device.ip));
                }
            }
            self.dns.wait_idle(Duration::from_secs(2));
        }
        for device in &mut devices {
            if device.role == "local" {
                device.hostname = sysinfo::System::host_name();
            } else if active {
                device.hostname = self.dns.lookup_or_queue(IpAddr::V4(device.ip));
                if device.role == "peer" {
                    let (kind, evidence) = classify_hostname(device.hostname.as_deref());
                    device.kind = kind;
                    device.evidence = evidence;
                }
            }
        }
        if active && replies.is_empty() {
            warnings.push("No ICMP echo replies were received. Firewalls, routing, or isolation may block replies; cached neighbors are not proof of current reachability.".into());
        }
        if devices.len() <= 1 && raw.wifi.connected {
            warnings.push("No peer addresses are available in the Wi-Fi interface neighbor cache. Try Scan network.".into());
        }
        Ok(NetworkMap {
            ssid: raw.wifi.ssid,
            bssid: raw.wifi.bssid,
            interface: raw.wifi.interface_name,
            local_ip: local,
            prefix: raw.subnet_prefix,
            signal_percent: raw.wifi.signal_percent,
            scanned_at: chrono::Utc::now().to_rfc3339(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            active,
            can_scan,
            devices,
            warnings,
        })
    }

    fn telemetry(&mut self) -> Result<RawLinkSnapshot, String> {
        self.radar.collect_platform_telemetry(false).ok_or_else(|| {
            "Wi-Fi telemetry could not be read. Check that WLAN AutoConfig is running and Windows allows Location access for desktop apps.".into()
        })
    }
}

fn local_ipv4(raw: &RawLinkSnapshot) -> Option<Ipv4Addr> {
    match raw.local_ip {
        Some(IpAddr::V4(ip)) => Some(ip),
        _ => None,
    }
}

fn same_network(a: &RawLinkSnapshot, b: &RawLinkSnapshot) -> bool {
    b.wifi.connected
        && a.wifi.guid == b.wifi.guid
        && a.wifi.bssid == b.wifi.bssid
        && a.wifi.ssid == b.wifi.ssid
        && a.local_ip == b.local_ip
        && a.subnet_prefix == b.subnet_prefix
}

fn subnet_bounds(local: Ipv4Addr, prefix: u8) -> Result<(u32, u32), String> {
    if !(1..=30).contains(&prefix)
        || local.is_unspecified()
        || local.is_loopback()
        || local.is_multicast()
        || local.is_broadcast()
    {
        return Err("A unicast IPv4 interface with a /1 through /30 subnet is required.".into());
    }
    let mask = u32::MAX << (32 - prefix);
    let network = u32::from(local) & mask;
    let broadcast = network | !mask;
    if u32::from(local) == network || u32::from(local) == broadcast {
        return Err("The local IPv4 address is a subnet network or broadcast address.".into());
    }
    Ok((network, broadcast))
}

fn subnet_hosts(local: Ipv4Addr, prefix: u8) -> Result<Vec<Ipv4Addr>, String> {
    let (network, broadcast) = subnet_bounds(local, prefix)?;
    if broadcast - network - 1 > MAX_HOSTS {
        return Err("Active discovery is limited to subnets of at most 254 hosts (/24 through /30). Cached neighbors remain available on larger subnets.".into());
    }
    Ok((network + 1..broadcast)
        .filter(|ip| *ip != u32::from(local))
        .map(Ipv4Addr::from)
        .collect())
}

fn build_devices(raw: &RawLinkSnapshot, replies: &HashSet<Ipv4Addr>) -> Vec<Device> {
    let mut devices = BTreeMap::new();
    let Some(local) = local_ipv4(raw) else {
        return Vec::new();
    };
    let Some((network, broadcast)) = raw
        .subnet_prefix
        .and_then(|p| subnet_bounds(local, p).ok())
    else {
        return vec![local_device(local)];
    };
    for (ip, mac) in &raw.arp_neighbors {
        let n = u32::from(*ip);
        if n > network && n < broadcast && *ip != local {
            devices.insert(
                *ip,
                Device {
                    ip: *ip,
                    mac: Some(mac.clone()),
                    hostname: None,
                    role: "peer",
                    kind: "Unknown",
                    evidence: "No device type evidence. A MAC address alone does not establish device type.".into(),
                    observation: "Cached neighbor; may be stale",
                    distance_m: None,
                },
            );
        }
    }
    for ip in replies {
        let n = u32::from(*ip);
        if n <= network || n >= broadcast || *ip == local {
            continue;
        }
        devices
            .entry(*ip)
            .or_insert_with(|| Device {
                ip: *ip,
                mac: None,
                hostname: None,
                role: "peer",
                kind: "Unknown",
                evidence: "No device type evidence.".into(),
                observation: "ICMP reply this scan",
                distance_m: None,
            })
            .observation = "ICMP reply this scan";
    }
    if let Some(gateway) = raw.route.default_gateway {
        if let Some(device) = devices.get_mut(&gateway) {
            device.role = "gateway";
            device.kind = "Gateway";
            device.evidence = "Default gateway from the routing table; hardware type is not verified.".into();
        }
    }
    devices.insert(local, local_device(local));
    devices.into_values().collect()
}

fn local_device(ip: Ipv4Addr) -> Device {
    Device {
        ip,
        mac: None,
        hostname: None,
        role: "local",
        kind: "Computer",
        evidence: "This computer's Wi-Fi interface.".into(),
        observation: "Local interface",
        distance_m: None,
    }
}

fn classify_hostname(hostname: Option<&str>) -> (&'static str, String) {
    let Some(hostname) = hostname else {
        return (
            "Unknown",
            "No hostname or advertised device type is available.".into(),
        );
    };
    let label = hostname.split('.').next().unwrap_or("").to_ascii_lowercase();
    let tokens: Vec<_> = label.split(['-', '_']).collect();
    let groups: &[(&str, &[&str])] = &[
        (
            "Phone / tablet",
            &["iphone", "ipad", "android", "pixel", "galaxy"],
        ),
        ("Printer", &["printer", "laserjet", "officejet", "deskjet"]),
        (
            "TV / media",
            &["chromecast", "appletv", "roku", "firetv", "smarttv", "sonos"],
        ),
        (
            "Computer",
            &["desktop", "laptop", "macbook", "imac", "workstation"],
        ),
        ("Storage", &["nas", "diskstation", "synology", "qnap"]),
    ];
    for (kind, names) in groups {
        if names.iter().any(|name| tokens.contains(name)) {
            return (kind, format!("Low confidence: hostname '{hostname}' suggests {kind}. Hostnames are user-controlled; this is not verified."));
        }
    }
    (
        "Unknown",
        format!("Hostname '{hostname}' does not establish device type."),
    )
}

#[cfg(not(windows))]
fn probe_hosts(_: Ipv4Addr, _: &[Ipv4Addr]) -> Result<HashSet<Ipv4Addr>, String> {
    Err("Active discovery currently supports Windows only.".into())
}

#[cfg(windows)]
fn probe_hosts(source: Ipv4Addr, targets: &[Ipv4Addr]) -> Result<HashSet<Ipv4Addr>, String> {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    // Refuse a stale registry address that is no longer assigned to this host.
    let _source_check = std::net::UdpSocket::bind((source, 0))
        .map_err(|error| format!("Wi-Fi source address is no longer available: {error}"))?;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> *mut c_void;
        fn IcmpCloseHandle(handle: *mut c_void) -> i32;
        fn IcmpSendEcho2Ex(
            handle: *mut c_void,
            event: *mut c_void,
            routine: Option<unsafe extern "system" fn(*mut c_void, *mut c_void, u32)>,
            context: *mut c_void,
            source: u32,
            destination: u32,
            data: *const c_void,
            data_size: u16,
            options: *const c_void,
            reply: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }
    struct Handle(*mut c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }
    let next = AtomicUsize::new(0);
    let results = Mutex::new(HashSet::new());
    let failures = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..16.min(targets.len()) {
            scope.spawn(|| {
                // Every worker owns its handle and aligned buffer. Null event/callback
                // makes this synchronous, keeping all pointers valid until return.
                let handle = unsafe { IcmpCreateFile() };
                if handle as isize == -1 || handle.is_null() {
                    failures
                        .lock()
                        .unwrap()
                        .push(std::io::Error::last_os_error().to_string());
                    return;
                }
                let handle = Handle(handle);
                while let Some(target) = targets.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let mut reply = [0u64; 128];
                    let data = *b"Unlatched";
                    let count = unsafe {
                        IcmpSendEcho2Ex(
                            handle.0,
                            std::ptr::null_mut(),
                            None,
                            std::ptr::null_mut(),
                            u32::from_ne_bytes(source.octets()),
                            u32::from_ne_bytes(target.octets()),
                            data.as_ptr().cast(),
                            data.len() as u16,
                            std::ptr::null(),
                            reply.as_mut_ptr().cast(),
                            std::mem::size_of_val(&reply) as u32,
                            300,
                        )
                    };
                    // ICMP_ECHO_REPLY starts with Address and Status (two DWORDs).
                    // Only a successful reply from the requested target is a live peer.
                    let header = reply[0].to_ne_bytes();
                    if count > 0 && header[..4] == target.octets() && header[4..8] == [0; 4] {
                        results.lock().unwrap().insert(*target);
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    if !failures.is_empty() {
        return Err(format!(
            "Could not open an ICMP discovery handle: {}",
            failures[0]
        ));
    }
    Ok(results.into_inner().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn subnet_scan_excludes_local_network_broadcast_and_large_ranges() {
        let local = ip("192.0.2.17");
        let hosts = subnet_hosts(local, 24).unwrap();
        assert_eq!(hosts.len(), 253);
        assert!(![local, ip("192.0.2.0"), ip("192.0.2.255")]
            .iter()
            .any(|a| hosts.contains(a)));
        assert_eq!(
            subnet_hosts(ip("192.0.2.1"), 30).unwrap(),
            vec![ip("192.0.2.2")]
        );
        for prefix in [0, 16, 23, 31, 32, 33, 255] {
            assert!(subnet_hosts(local, prefix).is_err());
        }
        for local in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "192.0.2.0", "192.0.2.255"] {
            assert!(subnet_hosts(ip(local), 24).is_err());
        }
    }

    #[test]
    fn neighbors_are_filtered_deduplicated_and_not_claimed_live_or_located() {
        let raw = RawLinkSnapshot {
            local_ip: Some(IpAddr::V4(ip("192.0.2.17"))),
            subnet_prefix: Some(24),
            arp_neighbors: ["192.0.2.1", "192.0.2.1", "192.0.3.9", "192.0.2.255", "192.0.2.0"]
                .iter()
                .map(|a| (ip(a), "02:00:00:00:00:01".into()))
                .collect(),
            ..Default::default()
        };
        let devices = build_devices(&raw, &HashSet::from([ip("192.0.2.5"), ip("192.0.3.8")]));
        assert_eq!(devices.len(), 3);
        assert!(devices.iter().all(|d| d.distance_m.is_none()));
        assert_eq!(
            devices.iter().find(|d| d.ip == ip("192.0.2.1")).unwrap().observation,
            "Cached neighbor; may be stale"
        );
        assert_eq!(
            devices.iter().find(|d| d.ip == ip("192.0.2.5")).unwrap().observation,
            "ICMP reply this scan"
        );
        let json = serde_json::to_value(&devices).unwrap();
        assert!(json.as_array().unwrap().iter().all(|d| d["distance_m"].is_null()));
    }

    #[test]
    fn types_need_evidence_and_hostname_guesses_remain_uncertain() {
        for name in [
            None,
            Some("192.0.2.8"),
            Some("myprinterbox"),
            Some("router.example"),
            Some("host.iphone.example"),
        ] {
            assert_eq!(classify_hostname(name).0, "Unknown");
        }
        let (kind, evidence) = classify_hostname(Some("Alice-iPhone.local"));
        assert_eq!(kind, "Phone / tablet");
        assert!(evidence.contains("Low confidence"));
    }

    #[test]
    fn connection_changes_invalidate_scan() {
        let mut before = RawLinkSnapshot::default();
        before.wifi.connected = true;
        before.wifi.ssid = "demo".into();
        let mut after = before.clone();
        assert!(same_network(&before, &after));
        after.wifi.ssid = "other".into();
        assert!(!same_network(&before, &after));
        after = before.clone();
        after.wifi.connected = false;
        assert!(!same_network(&before, &after));
    }

    #[test]
    #[cfg(windows)]
    fn native_icmp_recognizes_successful_loopback_reply() {
        let replies = probe_hosts(Ipv4Addr::LOCALHOST, &[Ipv4Addr::LOCALHOST]).unwrap();
        assert!(replies.contains(&Ipv4Addr::LOCALHOST));
    }
}
