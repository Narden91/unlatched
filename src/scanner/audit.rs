use crate::models::{AuditItem, AuditStatus, SecurityFinding, Severity};
use std::fs;
use std::path::Path;

pub fn run_host_security_audit(
    is_elevated: bool,
    findings: &mut Vec<SecurityFinding>,
) -> Vec<AuditItem> {
    let mut items = vec![AuditItem {
        check_id: "AUD-PRIV-01".to_string(),
        subsystem: "Scanner Telemetry".to_string(),
        name: "Execution Privilege Level".to_string(),
        location: "Process Token / UID".to_string(),
        value: if is_elevated {
            "Elevated (Administrator / root)".to_string()
        } else {
            "Standard User (Unprivileged)".to_string()
        },
        status: if is_elevated {
            AuditStatus::Pass
        } else {
            AuditStatus::Info
        },
        details: if is_elevated {
            "Full kernel socket-to-PID mapping and system binary inspection active.".to_string()
        } else {
            "Running as standard user; some system daemon paths require Admin/root.".to_string()
        },
    }];

    #[cfg(windows)]
    {
        audit_windows_firewall(&mut items, findings);
        audit_windows_registry_persistence(&mut items, findings);
        audit_windows_startup_folders(&mut items, findings);
    }

    #[cfg(target_os = "linux")]
    {
        audit_linux_firewall(&mut items, findings);
        audit_linux_ld_preload(&mut items, findings);
        audit_linux_cron_and_rc(&mut items, findings);
        audit_linux_sshd_config(&mut items, findings);
        audit_linux_systemd_units(&mut items, findings);
    }

    audit_hosts_file(&mut items, findings);

    items.sort_by(|a, b| {
        b.status
            .cmp(&a.status)
            .then_with(|| a.subsystem.cmp(&b.subsystem))
            .then_with(|| a.name.cmp(&b.name))
    });

    items
}

fn evaluate_persistence_command(cmd: &str) -> (AuditStatus, String) {
    let lower = cmd.to_lowercase();
    let norm_path = lower.replace('/', "\\");

    // A chained command (`del x & powershell -enc ...`) must reach the critical patterns below.
    let is_chained = lower.contains(['&', '|', ';', '>', '<']);
    if (lower.contains("cmd.exe") || lower.starts_with("cmd "))
        && lower.contains(" /c ")
        && lower.contains(" del ")
        && !is_chained
    {
        return (
            AuditStatus::Info,
            "Temporary file cleanup command (cmd.exe /c del)".to_string(),
        );
    }

    let critical_cmd_patterns = [
        ("powershell", "Startup item launches PowerShell interpreter"),
        ("pwsh", "Startup item launches PowerShell Core interpreter"),
        ("mshta", "Startup item uses mshta.exe LOLBin"),
        ("regsvr32", "Startup item uses regsvr32.exe LOLBin"),
        ("wscript", "Startup item launches Windows Script Host (wscript)"),
        ("cscript", "Startup item launches Windows Script Host (cscript)"),
        ("/tmp/", "Persistence entry executes from /tmp"),
        ("/var/tmp/", "Persistence entry executes from /var/tmp"),
        ("/dev/shm/", "Persistence entry executes from /dev/shm"),
        ("base64", "Persistence entry uses base64 decoding"),
        ("/dev/tcp/", "Persistence entry opens raw /dev/tcp socket"),
    ];

    for (pat, reason) in critical_cmd_patterns {
        if lower.contains(pat) {
            return (AuditStatus::Critical, reason.to_string());
        }
    }

    let critical_win_paths = [
        ("\\appdata\\local\\temp\\", "Startup binary executes from Temp folder"),
        ("\\windows\\temp\\", "Startup binary executes from Windows Temp folder"),
        ("\\users\\public\\", "Startup binary executes from Users\\Public"),
    ];

    for (pat, reason) in critical_win_paths {
        if norm_path.contains(pat) {
            return (AuditStatus::Critical, reason.to_string());
        }
    }

    if (lower.contains("cmd.exe") || lower.starts_with("cmd ")) && lower.contains(" /c ") {
        return (
            AuditStatus::Warning,
            "Startup item executes inline cmd.exe /c shell command".to_string(),
        );
    }

    let warning_patterns = [
        (".vbs", "Startup item executes a VBScript (.vbs)"),
        (".js", "Startup item executes a JScript (.js) file"),
        (".hta", "Startup item executes an HTML Application (.hta)"),
        (".bat", "Startup item executes a Batch script (.bat)"),
        (".ps1", "Startup item executes a PowerShell script (.ps1)"),
        ("rundll32", "Startup item invokes rundll32.exe DLL loader"),
    ];

    for (pat, reason) in warning_patterns {
        if lower.contains(pat) {
            return (AuditStatus::Warning, reason.to_string());
        }
    }

    (
        AuditStatus::Pass,
        "Registered autostart binary path.".to_string(),
    )
}

#[cfg(windows)]
fn audit_windows_firewall(items: &mut Vec<AuditItem>, findings: &mut Vec<SecurityFinding>) {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let profiles = [
        (
            "DomainProfile",
            "Windows Firewall (Domain Profile)",
            AuditStatus::Warning,
        ),
        (
            "StandardProfile",
            "Windows Firewall (Private Network)",
            AuditStatus::Warning,
        ),
        (
            "PublicProfile",
            "Windows Firewall (Public Network)",
            AuditStatus::Critical,
        ),
    ];

    for (subkey_name, label, disabled_status) in profiles {
        let path = format!(
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\{}",
            subkey_name
        );
        if let Ok(key) = hklm.open_subkey(&path) {
            let local: u32 = key.get_value("EnableFirewall").unwrap_or(1);
            // Group Policy overrides the local setting, so it decides the effective state.
            let policy: Option<u32> = hklm
                .open_subkey(format!(
                    "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\{}",
                    subkey_name
                ))
                .ok()
                .and_then(|k| k.get_value("EnableFirewall").ok());
            let enabled = policy.unwrap_or(local);
            if enabled == 1 {
                items.push(AuditItem {
                    check_id: format!("AUD-FW-{}", subkey_name.to_uppercase()),
                    subsystem: "Host Firewall".to_string(),
                    name: label.to_string(),
                    location: format!("HKLM\\{}", path),
                    value: "ENABLED (Active)".to_string(),
                    status: AuditStatus::Pass,
                    details: "Inbound unsolicited traffic is filtered on this profile.".to_string(),
                });
            } else {
                items.push(AuditItem {
                    check_id: format!("AUD-FW-{}", subkey_name.to_uppercase()),
                    subsystem: "Host Firewall".to_string(),
                    name: label.to_string(),
                    location: format!("HKLM\\{}", path),
                    value: "DISABLED".to_string(),
                    status: disabled_status,
                    details: "Windows Defender Firewall is turned OFF for this profile.".to_string(),
                });

                findings.push(SecurityFinding {
                    rule_id: "AUD-FW-DISABLED".to_string(),
                    category: "Host Defense Disabled".to_string(),
                    mitre_id: "T1562.004".to_string(),
                    severity: disabled_status.to_severity(),
                    title: format!("{} is DISABLED", label),
                    description: format!(
                        "{} has EnableFirewall=0. Local listening services are reachable from the network.",
                        label
                    ),
                    pid: None,
                    process_name: None,
                    endpoint: None,
                    evidence: format!("HKLM\\{}\\EnableFirewall = 0", path),
                    remediation: "Enable Windows Defender Firewall via 'netsh advfirewall set allprofiles state on'.".to_string(),
                });
            }
        }
    }
}

#[cfg(windows)]
fn audit_windows_registry_persistence(
    items: &mut Vec<AuditItem>,
    findings: &mut Vec<SecurityFinding>,
) {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let run_keys = [
        (
            HKEY_CURRENT_USER,
            "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ),
        (
            HKEY_CURRENT_USER,
            "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ),
        (
            HKEY_LOCAL_MACHINE,
            "HKLM",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ),
        (
            HKEY_LOCAL_MACHINE,
            "HKLM",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ),
        (
            HKEY_LOCAL_MACHINE,
            "HKLM",
            "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        ),
    ];

    for (hive, hive_name, subkey_path) in run_keys {
        let root = RegKey::predef(hive);
        if let Ok(key) = root.open_subkey(subkey_path) {
            for (name, val) in key.enum_values().flatten() {
                let cmd = val.to_string();
                if cmd.trim().is_empty() {
                    continue;
                }
                let (status, details) = evaluate_persistence_command(&cmd);
                let location = format!("{}\\{}", hive_name, subkey_path);

                if matches!(status, AuditStatus::Critical | AuditStatus::Warning) {
                    findings.push(SecurityFinding {
                        rule_id: "AUD-PERSIST-REG".to_string(),
                        category: "Suspicious Persistence".to_string(),
                        mitre_id: "T1547.001".to_string(),
                        severity: status.to_severity(),
                        title: format!("Suspicious Registry Autostart Entry: '{}'", name),
                        description: format!("{} ({})", details, location),
                        pid: None,
                        process_name: Some(name.clone()),
                        endpoint: None,
                        evidence: format!("{}\\{} -> {}", location, name, cmd),
                        remediation: "Inspect the referenced script/binary and remove unauthorized Run entries.".to_string(),
                    });
                }

                items.push(AuditItem {
                    check_id: "AUD-REG-RUN".to_string(),
                    subsystem: "Registry Persistence".to_string(),
                    name,
                    location,
                    value: cmd,
                    status,
                    details,
                });
            }
        }
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let winlogon_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    if let Ok(wl_key) = hklm.open_subkey(winlogon_path) {
        if let Ok(shell) = wl_key.get_value::<String, _>("Shell") {
            let status = if shell.trim().eq_ignore_ascii_case("explorer.exe") {
                AuditStatus::Pass
            } else {
                AuditStatus::Critical
            };
            if status == AuditStatus::Critical {
                findings.push(SecurityFinding {
                    rule_id: "AUD-WINLOGON-SHELL".to_string(),
                    category: "Winlogon Persistence".to_string(),
                    mitre_id: "T1547.004".to_string(),
                    severity: Severity::Critical,
                    title: "Modified Winlogon Shell Registry Value".to_string(),
                    description: format!(
                        "HKLM\\{}\\Shell is set to '{}' instead of 'explorer.exe'.",
                        winlogon_path, shell
                    ),
                    pid: None,
                    process_name: None,
                    endpoint: None,
                    evidence: format!("Shell = {}", shell),
                    remediation: "Restore Winlogon Shell value to 'explorer.exe'.".to_string(),
                });
            }
            items.push(AuditItem {
                check_id: "AUD-WINLOGON-01".to_string(),
                subsystem: "Winlogon Helper".to_string(),
                name: "Winlogon Shell".to_string(),
                location: format!("HKLM\\{}", winlogon_path),
                value: shell,
                status,
                details: "Primary desktop shell launched at user logon.".to_string(),
            });
        }
    }
}

#[cfg(windows)]
fn audit_windows_startup_folders(
    items: &mut Vec<AuditItem>,
    findings: &mut Vec<SecurityFinding>,
) {
    let mut folders = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        folders.push((
            "User Startup Folder",
            format!("{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", appdata),
        ));
    }
    if let Ok(progdata) = std::env::var("PROGRAMDATA") {
        folders.push((
            "Common Startup Folder",
            format!(
                "{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                progdata
            ),
        ));
    }

    for (label, folder_path) in folders {
        if let Ok(entries) = fs::read_dir(&folder_path) {
            for entry in entries.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                if file_name.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                let full_path = entry.path().to_string_lossy().into_owned();
                let (status, details) = evaluate_persistence_command(&full_path);

                if matches!(status, AuditStatus::Critical | AuditStatus::Warning) {
                    findings.push(SecurityFinding {
                        rule_id: "AUD-STARTUP-FILE".to_string(),
                        category: "Startup Folder Persistence".to_string(),
                        mitre_id: "T1547.001".to_string(),
                        severity: status.to_severity(),
                        title: format!("Suspicious Startup Folder Item: {}", file_name),
                        description: details.clone(),
                        pid: None,
                        process_name: Some(file_name.clone()),
                        endpoint: None,
                        evidence: full_path.clone(),
                        remediation: "Remove unauthorized scripts or executables from the Startup folder.".to_string(),
                    });
                }

                items.push(AuditItem {
                    check_id: "AUD-STARTUP-DIR".to_string(),
                    subsystem: label.to_string(),
                    name: file_name,
                    location: folder_path.clone(),
                    value: full_path,
                    status,
                    details,
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn audit_linux_firewall(items: &mut Vec<AuditItem>, findings: &mut Vec<SecurityFinding>) {
    let ufw_conf = fs::read_to_string("/etc/ufw/ufw.conf").unwrap_or_default();
    let nft_loaded = Path::new("/sys/module/nf_tables").exists();
    let ipt_loaded = Path::new("/proc/net/ip_tables_names").exists();

    let (status, value, details) = if ufw_conf.contains("ENABLED=yes") {
        (
            AuditStatus::Pass,
            "UFW Enabled".to_string(),
            "UFW is configured as enabled.".to_string(),
        )
    } else if nft_loaded || ipt_loaded {
        (
            AuditStatus::Pass,
            "Kernel Netfilter Active (nftables/iptables)".to_string(),
            "Linux netfilter packet filtering modules are loaded.".to_string(),
        )
    } else {
        (
            AuditStatus::Warning,
            "No Active Firewall Detected".to_string(),
            "Neither UFW nor nftables/iptables kernel modules appear active.".to_string(),
        )
    };

    if status == AuditStatus::Warning {
        findings.push(SecurityFinding {
            rule_id: "AUD-LIN-FW".to_string(),
            category: "Host Defense Disabled".to_string(),
            mitre_id: "T1562.004".to_string(),
            severity: status.to_severity(),
            title: "No Active Linux Firewall Detected".to_string(),
            description: details.clone(),
            pid: None,
            process_name: None,
            endpoint: None,
            evidence: "/etc/ufw/ufw.conf, /sys/module/nf_tables, /proc/net/ip_tables_names"
                .to_string(),
            remediation: "Enable ufw or load an nftables ruleset.".to_string(),
        });
    }

    items.push(AuditItem {
        check_id: "AUD-LIN-FW".to_string(),
        subsystem: "Host Firewall".to_string(),
        name: "Linux Netfilter / UFW State".to_string(),
        location: "/etc/ufw/ufw.conf | /sys/module/nf_tables".to_string(),
        value,
        status,
        details,
    });
}

#[cfg(target_os = "linux")]
fn audit_linux_ld_preload(items: &mut Vec<AuditItem>, findings: &mut Vec<SecurityFinding>) {
    let preload_path = "/etc/ld.so.preload";
    if let Ok(content) = fs::read_to_string(preload_path) {
        let active_lines: Vec<&str> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        if !active_lines.is_empty() {
            let joined = active_lines.join(", ");
            items.push(AuditItem {
                check_id: "AUD-LIN-PRELOAD".to_string(),
                subsystem: "Dynamic Linker Integrity".to_string(),
                name: "/etc/ld.so.preload Hook".to_string(),
                location: preload_path.to_string(),
                value: joined.clone(),
                status: AuditStatus::Critical,
                details: "Global shared library preload active.".to_string(),
            });
            findings.push(SecurityFinding {
                rule_id: "AUD-LD-PRELOAD".to_string(),
                category: "Dynamic Linker Hijack".to_string(),
                mitre_id: "T1574.006".to_string(),
                severity: Severity::Critical,
                title: "Active Shared Library in /etc/ld.so.preload".to_string(),
                description: format!(
                    "/etc/ld.so.preload forces dynamically linked binaries to load: {}.",
                    joined
                ),
                pid: None,
                process_name: None,
                endpoint: None,
                evidence: format!("/etc/ld.so.preload: {}", joined),
                remediation: "Inspect the preloaded .so library and clear /etc/ld.so.preload if unauthorized.".to_string(),
            });
            return;
        }
    }

    items.push(AuditItem {
        check_id: "AUD-LIN-PRELOAD".to_string(),
        subsystem: "Dynamic Linker Integrity".to_string(),
        name: "/etc/ld.so.preload Check".to_string(),
        location: preload_path.to_string(),
        value: "Clean".to_string(),
        status: AuditStatus::Pass,
        details: "No global LD_PRELOAD entries found.".to_string(),
    });
}

#[cfg(target_os = "linux")]
fn audit_linux_cron_and_rc(items: &mut Vec<AuditItem>, findings: &mut Vec<SecurityFinding>) {
    let files_to_check = ["/etc/crontab", "/etc/rc.local"];
    for file_path in files_to_check {
        if let Ok(content) = fs::read_to_string(file_path) {
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty()
                    || trimmed.starts_with('#')
                    || trimmed.starts_with("SHELL=")
                    || trimmed.starts_with("PATH=")
                    || trimmed.starts_with("exit 0")
                {
                    continue;
                }
                let (status, details) = evaluate_persistence_command(trimmed);
                if matches!(status, AuditStatus::Critical | AuditStatus::Warning) {
                    findings.push(SecurityFinding {
                        rule_id: "AUD-LIN-CRON".to_string(),
                        category: "Cron / Boot Persistence".to_string(),
                        mitre_id: "T1053.003".to_string(),
                        severity: status.to_severity(),
                        title: format!("Suspicious Entry in {}", file_path),
                        description: details.clone(),
                        pid: None,
                        process_name: None,
                        endpoint: None,
                        evidence: format!("{}:{} -> {}", file_path, idx + 1, trimmed),
                        remediation: "Remove unauthorized scheduled commands from crontab/rc.local.".to_string(),
                    });
                }
                items.push(AuditItem {
                    check_id: "AUD-LIN-SCHED".to_string(),
                    subsystem: "Cron / Boot Script".to_string(),
                    name: format!("Line {}", idx + 1),
                    location: file_path.to_string(),
                    value: trimmed.to_string(),
                    status,
                    details,
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn audit_linux_sshd_config(items: &mut Vec<AuditItem>, findings: &mut Vec<SecurityFinding>) {
    let sshd_path = "/etc/ssh/sshd_config";
    if let Ok(content) = fs::read_to_string(sshd_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((item, finding)) = check_sshd_directive(sshd_path, trimmed) {
                items.push(item);
                findings.extend(finding);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn audit_linux_systemd_units(items: &mut Vec<AuditItem>, findings: &mut Vec<SecurityFinding>) {
    let dir = "/etc/systemd/system";
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("service") {
                continue;
            }
            if let Ok(content) = fs::read_to_string(&path) {
                for line in content.lines() {
                    if let Some(exec) = line.trim().strip_prefix("ExecStart=") {
                        let (status, details) = evaluate_persistence_command(exec);
                        if matches!(status, AuditStatus::Critical | AuditStatus::Warning) {
                            let unit_name = entry.file_name().to_string_lossy().into_owned();
                            findings.push(SecurityFinding {
                                rule_id: "AUD-SYSTEMD-UNIT".to_string(),
                                category: "Systemd Persistence".to_string(),
                                mitre_id: "T1543.002".to_string(),
                                severity: status.to_severity(),
                                title: format!("Suspicious Systemd Unit: {}", unit_name),
                                description: details.clone(),
                                pid: None,
                                process_name: Some(unit_name.clone()),
                                endpoint: None,
                                evidence: format!("{} -> ExecStart={}", path.display(), exec),
                                remediation: "Disable and inspect the systemd service file.".to_string(),
                            });
                            items.push(AuditItem {
                                check_id: "AUD-SYSTEMD".to_string(),
                                subsystem: "Systemd Persistence".to_string(),
                                name: unit_name,
                                location: path.display().to_string(),
                                value: exec.to_string(),
                                status,
                                details,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Not Linux-only, so the tests run on every host.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn check_sshd_directive(
    path: &str,
    trimmed: &str,
) -> Option<(AuditItem, Option<SecurityFinding>)> {
    let lower = trimmed.to_lowercase();
    if lower.starts_with("permitrootlogin") && lower.contains("yes") {
        let item = AuditItem {
            check_id: "AUD-SSH-ROOT".to_string(),
            subsystem: "SSH Hardening".to_string(),
            name: "PermitRootLogin".to_string(),
            location: path.to_string(),
            value: trimmed.to_string(),
            status: AuditStatus::Warning,
            details: "Direct SSH root login is enabled.".to_string(),
        };
        let finding = SecurityFinding {
            rule_id: "AUD-SSH-ROOT".to_string(),
            category: "SSH Configuration".to_string(),
            mitre_id: "T1078.003".to_string(),
            severity: Severity::Medium,
            title: "SSH PermitRootLogin Enabled".to_string(),
            description: format!("{} permits direct root login over SSH.", path),
            pid: None,
            process_name: Some("sshd".to_string()),
            endpoint: None,
            evidence: trimmed.to_string(),
            remediation: format!(
                "Set 'PermitRootLogin prohibit-password' or 'no' in {}.",
                path
            ),
        };
        return Some((item, Some(finding)));
    }
    if lower.starts_with("permitemptypasswords") && lower.contains("yes") {
        let item = AuditItem {
            check_id: "AUD-SSH-EMPTY".to_string(),
            subsystem: "SSH Hardening".to_string(),
            name: "PermitEmptyPasswords".to_string(),
            location: path.to_string(),
            value: trimmed.to_string(),
            status: AuditStatus::Critical,
            details: "SSH allows login for accounts with empty passwords.".to_string(),
        };
        // The audit row alone did not change the score or the exit code, so add a finding.
        let finding = SecurityFinding {
            rule_id: "AUD-SSH-EMPTY".to_string(),
            category: "SSH Configuration".to_string(),
            mitre_id: "T1078".to_string(),
            severity: Severity::Critical,
            title: "SSH PermitEmptyPasswords Enabled".to_string(),
            description: format!("{} allows SSH login with an empty password.", path),
            pid: None,
            process_name: Some("sshd".to_string()),
            endpoint: None,
            evidence: trimmed.to_string(),
            remediation: format!("Set 'PermitEmptyPasswords no' in {}.", path),
        };
        return Some((item, Some(finding)));
    }
    None
}

/// 0.0.0.0 and loopback targets are what blocklists use. Any other address is a redirect.
fn hosts_override_level(ip: &str) -> (AuditStatus, Severity, &'static str) {
    if matches!(ip, "0.0.0.0" | "127.0.0.1" | "::1") {
        (
            AuditStatus::Warning,
            Severity::Medium,
            "Hosts file blocks a security or OS update domain (blocklist or tampering).",
        )
    } else {
        (
            AuditStatus::Critical,
            Severity::Critical,
            "Hosts file redirects a security or OS update domain to another address.",
        )
    }
}

fn audit_hosts_file(items: &mut Vec<AuditItem>, findings: &mut Vec<SecurityFinding>) {
    #[cfg(windows)]
    let hosts_path = crate::scanner::system_root()
        .join(r"System32\drivers\etc\hosts")
        .to_string_lossy()
        .into_owned();
    #[cfg(not(windows))]
    let hosts_path = "/etc/hosts".to_string();

    if !Path::new(&hosts_path).exists() {
        return;
    }

    let Ok(content) = fs::read_to_string(&hosts_path) else {
        return;
    };

    let sensitive_domains = [
        "windowsupdate.com",
        "microsoft.com",
        "defender",
        "virustotal.com",
        "kaspersky",
        "malwarebytes",
        "bitdefender",
        "crowdstrike",
        "sophos",
        "symantec",
    ];

    let mut custom_mappings = 0usize;
    for line in content.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let ip = parts[0];
        let domains = &parts[1..];

        let is_standard_local = matches!(ip, "127.0.0.1" | "::1" | "0.0.0.0")
            && domains.iter().all(|d| {
                let dl = d.to_lowercase();
                dl == "localhost"
                    || dl.ends_with(".local")
                    || dl.ends_with(".internal")
                    || dl.starts_with("ip6-")
            });

        if is_standard_local {
            continue;
        }

        custom_mappings += 1;
        let domain_list = domains.join(", ");
        let domain_lower = domain_list.to_lowercase();

        if sensitive_domains.iter().any(|&sd| domain_lower.contains(sd)) {
            let (status, severity, details) = hosts_override_level(ip);
            items.push(AuditItem {
                check_id: "AUD-HOSTS-HIJACK".to_string(),
                subsystem: "DNS / Hosts File".to_string(),
                name: format!("Hijacked Domain ({})", domain_list),
                location: hosts_path.to_string(),
                value: format!("{} -> {}", domain_list, ip),
                status,
                details: details.to_string(),
            });
            findings.push(SecurityFinding {
                rule_id: "AUD-HOSTS-TAMPER".to_string(),
                category: "Hosts File Tampering".to_string(),
                mitre_id: "T1565.001".to_string(),
                severity,
                title: format!("Hosts File Redirects Security/Update Domain: {}", domain_list),
                description: format!(
                    "{} maps '{}' to '{}'.",
                    hosts_path, domain_list, ip
                ),
                pid: None,
                process_name: None,
                endpoint: None,
                evidence: trimmed.to_string(),
                remediation: format!("Remove the redirection entry from {}.", hosts_path),
            });
        }
    }

    items.push(AuditItem {
        check_id: "AUD-HOSTS-SUMMARY".to_string(),
        subsystem: "DNS / Hosts File".to_string(),
        name: "Hosts File Custom Mappings".to_string(),
        location: hosts_path.to_string(),
        value: format!("{} custom entry/entries", custom_mappings),
        status: AuditStatus::Pass,
        details: "Inspected local hosts file for domain overrides.".to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_command_heuristics() {
        let (st1, _) = evaluate_persistence_command(
            r#"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -Enc ZQBjAGgAbwA="#,
        );
        assert_eq!(st1, AuditStatus::Critical);

        let (st2, _) = evaluate_persistence_command("/tmp/.x11-unix/backdoor --daemon");
        assert_eq!(st2, AuditStatus::Critical);

        let (st3, _) = evaluate_persistence_command(
            r#"C:\Windows\system32\cmd.exe /q /c del /q "C:\Users\user\AppData\Local\Temp\test.exe""#,
        );
        assert_eq!(st3, AuditStatus::Info);

        let (st3b, _) = evaluate_persistence_command(
            r#"C:\Users\user\AppData\Local\Temp\dropper.exe --silent"#,
        );
        assert_eq!(st3b, AuditStatus::Critical);

        let (st4, _) = evaluate_persistence_command(r#"C:\Windows\system32\cmd.exe /q /c echo hello"#);
        assert_eq!(st4, AuditStatus::Warning);

        let (st5, _) = evaluate_persistence_command(
            r#""C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background"#,
        );
        assert_eq!(st5, AuditStatus::Pass);

        // Chaining after `del` must not hide the second command behind the Info rule.
        let (st6, _) = evaluate_persistence_command(
            r#"cmd.exe /c del x.tmp & powershell -w hidden -enc ZQBjAGgAbwA="#,
        );
        assert_eq!(st6, AuditStatus::Critical);
    }

    #[test]
    fn test_sshd_empty_passwords_creates_finding() {
        let (item, finding) =
            check_sshd_directive("/etc/ssh/sshd_config", "PermitEmptyPasswords yes").unwrap();
        assert_eq!(item.status, AuditStatus::Critical);
        assert_eq!(finding.unwrap().severity, Severity::Critical);
        assert!(check_sshd_directive("/etc/ssh/sshd_config", "PermitEmptyPasswords no").is_none());
        assert!(check_sshd_directive("/etc/ssh/sshd_config", "PermitRootLogin yes").is_some());
    }

    #[test]
    fn test_hosts_blocklist_is_not_critical() {
        assert_eq!(hosts_override_level("0.0.0.0").0, AuditStatus::Warning);
        assert_eq!(hosts_override_level("127.0.0.1").1, Severity::Medium);
        assert_eq!(hosts_override_level("203.0.113.5").0, AuditStatus::Critical);
    }
}
