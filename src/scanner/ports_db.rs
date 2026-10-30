use crate::models::Severity;

#[derive(Debug, Clone)]
pub struct BackdoorPortIntel {
    pub threat_name: &'static str,
    pub severity: Severity,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct SensitivePortRule {
    pub port: u16,
    pub service: &'static str,
    pub severity: Severity,
    pub risk_summary: &'static str,
    pub remediation: &'static str,
}

pub fn lookup_service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        111 => "RPCbind",
        123 => "NTP",
        135 => "MS-RPC",
        137..=139 => "NetBIOS",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 | 587 => "SMTPS",
        514 => "Syslog",
        631 => "IPP/CUPS",
        636 => "LDAPS",
        873 => "Rsync",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS-Proxy",
        1337 => "Suspicious-1337",
        1433 => "MS-SQL",
        1521 => "Oracle-DB",
        1883 => "MQTT",
        1900 => "SSDP/UPnP",
        2049 => "NFS",
        2375 | 2376 => "Docker-API",
        3000 => "Dev-HTTP",
        3306 => "MySQL",
        3333 => "Stratum-Miner",
        3389 => "RDP",
        3702 => "WS-Discovery",
        4200 => "Angular-Dev",
        4444 => "Metasploit/C2",
        5000 => "Flask/UPnP",
        5040 => "Win-CDPSvc",
        5173 => "Vite-Dev",
        5353 => "mDNS",
        5355 => "LLMNR",
        5357 => "WS-Discovery",
        5432 => "PostgreSQL",
        5555 => "ADB-Shell",
        5672 => "AMQP/RabbitMQ",
        5900..=5905 => "VNC",
        5985 | 5986 => "WinRM",
        6379 => "Redis",
        6443 => "K8s-API",
        6666..=6669 => "IRC-C2",
        7680 => "Win-DeliveryOpt",
        8000 | 8080 | 8888 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        9000 => "PHP-FPM/Sonar",
        9001 | 9050 => "Tor-Node",
        9090 => "Prometheus/Admin",
        9200 | 9300 => "Elasticsearch",
        11211 => "Memcached",
        14444 => "Crypto-Miner",
        27017 => "MongoDB",
        27036 => "Steam-Transfer",
        31337 => "BackOrifice/C2",
        57621 => "Spotify-P2P",
        _ => "Custom",
    }
}

pub fn check_backdoor_port(port: u16) -> Option<BackdoorPortIntel> {
    let intel = match port {
        4444 => BackdoorPortIntel {
            threat_name: "Metasploit / Meterpreter Default Handler",
            severity: Severity::Critical,
            reason: "Default reverse/bind shell port for Metasploit payload handlers.",
        },
        31337 => BackdoorPortIntel {
            threat_name: "Back Orifice / Elite Backdoor Port",
            severity: Severity::Critical,
            reason: "Historically used by Back Orifice trojans, bind shells, and unauthorized listeners.",
        },
        1337 => BackdoorPortIntel {
            threat_name: "Custom Backdoor / C2 Port (1337)",
            severity: Severity::High,
            reason: "Frequently used by ad-hoc reverse shells, custom RATs, and tunnel listeners.",
        },
        12345 | 27374 => BackdoorPortIntel {
            threat_name: "Legacy RAT Port (NetBus / SubSeven)",
            severity: Severity::Critical,
            reason: "Associated with Remote Access Trojans (NetBus / SubSeven) and commodity backdoors.",
        },
        6666..=6669 => BackdoorPortIntel {
            threat_name: "IRC Command & Control (C2) Channel",
            severity: Severity::High,
            reason: "IRC ports are commonly used by botnets for command-and-control communication.",
        },
        3333 | 14444 | 45560 => BackdoorPortIntel {
            threat_name: "Stratum Crypto-Mining Pool Port",
            severity: Severity::High,
            reason: "Standard port used by XMRig and Stratum mining pools.",
        },
        2375 => BackdoorPortIntel {
            threat_name: "Unencrypted Docker Daemon Socket (TCP 2375)",
            severity: Severity::Critical,
            reason: "Exposing Docker daemon on TCP 2375 without TLS grants unauthenticated root access.",
        },
        5554 => BackdoorPortIntel {
            threat_name: "Worm / FTP Backdoor Port (5554)",
            severity: Severity::High,
            reason: "Associated with worm backdoors and unauthorized payload transfer listeners.",
        },
        5555 => BackdoorPortIntel {
            threat_name: "Android Debug Bridge (ADB) / Remote Shell",
            severity: Severity::High,
            reason: "Used by ADB over TCP; if exposed, allows unauthenticated shell execution.",
        },
        9001 | 9050 | 9150 => BackdoorPortIntel {
            threat_name: "Tor SOCKS Proxy / Onion Router Relay",
            severity: Severity::Medium,
            reason: "Tor proxy or relay port active. Verify this is intentional.",
        },
        _ => return None,
    };
    Some(intel)
}

pub fn check_sensitive_wildcard_port(port: u16) -> Option<SensitivePortRule> {
    let rule = match port {
        23 => SensitivePortRule {
            port,
            service: "Telnet",
            severity: Severity::Critical,
            risk_summary: "Unencrypted Telnet service listening on all network interfaces.",
            remediation: "Disable Telnet and migrate to SSH (port 22).",
        },
        2375 => SensitivePortRule {
            port,
            service: "Docker Remote API",
            severity: Severity::Critical,
            risk_summary: "Unencrypted Docker API listening on all interfaces allows host takeover.",
            remediation: "Bind Docker daemon to unix:///var/run/docker.sock or 127.0.0.1, or enforce TLS on 2376.",
        },
        6379 => SensitivePortRule {
            port,
            service: "Redis Database",
            severity: Severity::Critical,
            risk_summary: "Redis exposed on all interfaces (0.0.0.0/::).",
            remediation: "Set 'bind 127.0.0.1 ::1' and 'protected-mode yes' in redis.conf.",
        },
        445 => SensitivePortRule {
            port,
            service: "SMB / CIFS File Sharing",
            severity: Severity::High,
            risk_summary: "SMB port 445 listening on all interfaces increases lateral movement exposure.",
            remediation: "Restrict SMB port 445 via host firewall to trusted LAN subnets or disable Server service.",
        },
        3389 => SensitivePortRule {
            port,
            service: "Remote Desktop (RDP)",
            severity: Severity::High,
            risk_summary: "RDP port 3389 exposed on all interfaces.",
            remediation: "Enforce Network Level Authentication (NLA) and restrict RDP via firewall or VPN.",
        },
        5900..=5905 => SensitivePortRule {
            port,
            service: "VNC Remote Desktop",
            severity: Severity::High,
            risk_summary: "VNC server listening on all interfaces.",
            remediation: "Bind VNC to localhost (127.0.0.1) and tunnel over SSH or VPN.",
        },
        3306 => SensitivePortRule {
            port,
            service: "MySQL / MariaDB",
            severity: Severity::High,
            risk_summary: "MySQL database listening on all network interfaces.",
            remediation: "Configure 'bind-address = 127.0.0.1' in my.cnf.",
        },
        5432 => SensitivePortRule {
            port,
            service: "PostgreSQL",
            severity: Severity::High,
            risk_summary: "PostgreSQL database listening on all network interfaces.",
            remediation: "Set listen_addresses = 'localhost' in postgresql.conf.",
        },
        27017 => SensitivePortRule {
            port,
            service: "MongoDB",
            severity: Severity::Critical,
            risk_summary: "MongoDB exposed on all interfaces.",
            remediation: "Set net.bindIp to 127.0.0.1 in mongod.conf and enable authentication.",
        },
        9200 | 9300 => SensitivePortRule {
            port,
            service: "Elasticsearch",
            severity: Severity::High,
            risk_summary: "Elasticsearch cluster port exposed on all interfaces.",
            remediation: "Set network.host to 127.0.0.1 in elasticsearch.yml.",
        },
        11211 => SensitivePortRule {
            port,
            service: "Memcached",
            severity: Severity::High,
            risk_summary: "Memcached exposed on all interfaces.",
            remediation: "Bind Memcached to 127.0.0.1 (-l 127.0.0.1).",
        },
        5985 | 5986 => SensitivePortRule {
            port,
            service: "WinRM",
            severity: Severity::Medium,
            risk_summary: "WinRM remote management listener active on all interfaces.",
            remediation: "Restrict WinRM firewall rules to administrative hosts.",
        },
        135 | 139 => SensitivePortRule {
            port,
            service: "Windows RPC / NetBIOS",
            severity: Severity::Medium,
            risk_summary: "Windows RPC/NetBIOS endpoint mapper listening on all interfaces.",
            remediation: "Ensure host firewall blocks inbound 135/139 on untrusted networks.",
        },
        _ => return None,
    };
    Some(rule)
}
