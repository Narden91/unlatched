use crate::models::{AuditItem, AuditStatus, SecurityFinding, Severity};
use crate::scanner::fs_safe::{is_local_safe_path, read_bounded_string};
use crate::scanner::indicators::{check_suspicious_exec_path, has_script_token};
use std::path::Path;

const MAX_AUDIT_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_HOSTS_BLOCKLIST_ITEMS: usize = 5;

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

fn has_command_word(lower: &str, word: &str) -> bool {
    lower.split_whitespace().any(|tok| {
        let clean = tok.trim_matches(|c| c == '"' || c == '\'');
        let bin = clean.rsplit(['/', '\\']).next().unwrap_or(clean);
        bin == word || bin.strip_suffix(".exe") == Some(word)
    })
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

    // Benign Linux /tmp cleanup cron commands (`find /tmp ... -delete`, `rm -f /tmp/...`).
    if !is_chained
        && (has_command_word(&lower, "find") || has_command_word(&lower, "tmpwatch"))
        && (lower.contains("-delete") || lower.contains("/tmp"))
    {
        let first_word = lower.split_whitespace().next().unwrap_or("");
        if first_word.ends_with("find") || first_word.ends_with("tmpwatch") {
            return (
                AuditStatus::Info,
                "Scheduled temporary directory cleanup task".to_string(),
            );
        }
    }

    let critical_cmd_patterns = [
        ("powershell", "Startup item launches PowerShell interpreter"),
        ("pwsh", "Startup item launches PowerShell Core interpreter"),
        ("mshta", "Startup item uses mshta.exe LOLBin"),
        ("regsvr32", "Startup item uses regsvr32.exe LOLBin"),
        ("wscript", "Startup item launches Windows Script Host (wscript)"),
        ("cscript", "Startup item launches Windows Script Host (cscript)"),
        ("certutil", "Startup item invokes certutil.exe LOLBin"),
        ("bitsadmin", "Startup item invokes bitsadmin.exe downloader"),
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

    if has_command_word(&lower, "curl")
        || has_command_word(&lower, "wget")
        || has_command_word(&lower, "nc")
        || has_command_word(&lower, "ncat")
        || has_command_word(&lower, "socat")
    {
        return (
            AuditStatus::Critical,
            "Persistence entry invokes network transfer or socket relay utility".to_string(),
        );
    }

    if let Some(reason) = check_suspicious_exec_path(cmd, &norm_path) {
        return (
            AuditStatus::Critical,
            format!("Startup binary executes from suspicious path: {}", reason),
        );
    }

    if (lower.contains("cmd.exe") || lower.starts_with("cmd ")) && lower.contains(" /c ") {
        return (
            AuditStatus::Warning,
            "Startup item executes inline cmd.exe /c shell command".to_string(),
        );
    }

    if (has_command_word(&lower, "bash") || has_command_word(&lower, "sh"))
        && lower.contains(" -c ")
    {
        return (
            AuditStatus::Warning,
            "Persistence entry executes inline sh/bash -c command".to_string(),
        );
    }

    let warning_scripts = [
        (".vbs", "Startup item executes a VBScript (.vbs)"),
        (".js", "Startup item executes a JScript (.js) file"),
        (".hta", "Startup item executes an HTML Application (.hta)"),
        (".bat", "Startup item executes a Batch script (.bat)"),
        (".cmd", "Startup item executes a Command script (.cmd)"),
        (".ps1", "Startup item executes a PowerShell script (.ps1)"),
        (".scr", "Startup item executes a Screensaver PE (.scr)"),
    ];

    for (ext, reason) in warning_scripts {
        if has_script_token(&lower, ext) {
            return (AuditStatus::Warning, reason.to_string());
        }
    }

    if lower.contains("rundll32") {
        return (
            AuditStatus::Warning,
            "Startup item invokes rundll32.exe DLL loader".to_string(),
        );
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
                    details: "Windows Defender Firewall is turned OFF for this profile."
                        .to_string(),
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

        if let Ok(userinit) = wl_key.get_value::<String, _>("Userinit") {
            let status = if is_default_winlogon_userinit(&userinit) {
                AuditStatus::Pass
            } else {
                AuditStatus::Critical
            };
            if status == AuditStatus::Critical {
                findings.push(SecurityFinding {
                    rule_id: "AUD-WINLOGON-USERINIT".to_string(),
                    category: "Winlogon Persistence".to_string(),
                    mitre_id: "T1547.004".to_string(),
                    severity: Severity::Critical,
                    title: "Modified Winlogon Userinit Registry Value".to_string(),
                    description: format!(
                        "HKLM\\{}\\Userinit contains additional or modified logon command: '{}'.",
                        winlogon_path, userinit
                    ),
                    pid: None,
                    process_name: None,
                    endpoint: None,
                    evidence: format!("Userinit = {}", userinit),
                    remediation:
                        "Restore Winlogon Userinit to C:\\Windows\\system32\\userinit.exe,."
                            .to_string(),
                });
            }
            items.push(AuditItem {
                check_id: "AUD-WINLOGON-02".to_string(),
                subsystem: "Winlogon Helper".to_string(),
                name: "Winlogon Userinit".to_string(),
                location: format!("HKLM\\{}", winlogon_path),
                value: userinit,
                status,
                details: "Logon initialization helper invoked by winlogon.exe.".to_string(),
            });
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn is_default_winlogon_userinit(raw: &str) -> bool {
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.len() != 1 {
        return false;
    }
    let single = entries[0].trim_matches('"').to_lowercase().replace('/', "\\");
    single == "userinit.exe" || single.ends_with(r"\windows\system32\userinit.exe")
}

#[cfg(windows)]
fn audit_windows_startup_folders(
    items: &mut Vec<AuditItem>,
    findings: &mut Vec<SecurityFinding>,
) {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    // Read Startup paths from Registry Shell Folders rather than trusting user-mutable %APPDATA%
    // environment variables (preventing UNC path injection during elevated runs).
    let mut folders = Vec::new();
    if let Ok(hkcu_sf) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders")
    {
        if let Ok(user_startup) = hkcu_sf.get_value::<String, _>("Startup") {
            folders.push(("User Startup Folder", user_startup));
        }
    }
    if let Ok(hklm_sf) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders")
    {
        if let Ok(common_startup) = hklm_sf.get_value::<String, _>("Common Startup") {
            folders.push(("Common Startup Folder", common_startup));
        }
    }

    for (label, folder_path) in folders {
        let dir_path = Path::new(&folder_path);
        if !is_local_safe_path(dir_path) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(dir_path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                if file_name.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                let full_path = entry.path().to_string_lossy().into_owned();
                let (mut status, mut details) = evaluate_persistence_command(&full_path);
                let name_lower = file_name.to_lowercase();
                if status == AuditStatus::Pass
                    && (name_lower.ends_with(".exe") || name_lower.ends_with(".lnk"))
                {
                    status = AuditStatus::Info;
                    details = "Executable or shortcut placed in Startup folder.".to_string();
                }

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
                        remediation:
                            "Remove unauthorized scripts or executables from the Startup folder."
                                .to_string(),
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
    let ufw_conf =
        read_bounded_string(Path::new("/etc/ufw/ufw.conf"), MAX_AUDIT_FILE_BYTES).unwrap_or_default();
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
    if let Ok(content) = read_bounded_string(Path::new(preload_path), MAX_AUDIT_FILE_BYTES) {
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
                remediation:
                    "Inspect the preloaded .so library and clear /etc/ld.so.preload if unauthorized."
                        .to_string(),
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
    let mut files_to_check = vec!["/etc/crontab".to_string(), "/etc/rc.local".to_string()];
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            files_to_check.push(entry.path().to_string_lossy().into_owned());
        }
    }

    for file_path in files_to_check {
        if let Ok(content) = read_bounded_string(Path::new(&file_path), MAX_AUDIT_FILE_BYTES) {
            parse_cron_or_rc_content(&file_path, &content, items, findings);
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_cron_or_rc_content(
    file_path: &str,
    content: &str,
    items: &mut Vec<AuditItem>,
    findings: &mut Vec<SecurityFinding>,
) {
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("SHELL=")
            || trimmed.starts_with("PATH=")
            || trimmed.starts_with("MAILTO=")
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
                remediation: "Remove unauthorized scheduled commands from crontab/rc.local."
                    .to_string(),
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

#[cfg(target_os = "linux")]
fn audit_linux_sshd_config(items: &mut Vec<AuditItem>, findings: &mut Vec<SecurityFinding>) {
    let sshd_path = "/etc/ssh/sshd_config";
    if let Ok(content) = read_bounded_string(Path::new(sshd_path), MAX_AUDIT_FILE_BYTES) {
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
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("service") {
                continue;
            }
            if let Ok(content) = read_bounded_string(&path, MAX_AUDIT_FILE_BYTES) {
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
                                remediation: "Disable and inspect the systemd service file."
                                    .to_string(),
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
    let uncommented = trimmed.split('#').next().unwrap_or("").trim();
    let mut parts = uncommented.split_whitespace();
    let directive = parts.next()?;
    let value = parts.next()?;

    if directive.eq_ignore_ascii_case("permitrootlogin") && value.eq_ignore_ascii_case("yes") {
        let item = AuditItem {
            check_id: "AUD-SSH-ROOT".to_string(),
            subsystem: "SSH Hardening".to_string(),
            name: "PermitRootLogin".to_string(),
            location: path.to_string(),
            value: uncommented.to_string(),
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
            evidence: uncommented.to_string(),
            remediation: format!(
                "Set 'PermitRootLogin prohibit-password' or 'no' in {}.",
                path
            ),
        };
        return Some((item, Some(finding)));
    }
    if directive.eq_ignore_ascii_case("permitemptypasswords") && value.eq_ignore_ascii_case("yes")
    {
        let item = AuditItem {
            check_id: "AUD-SSH-EMPTY".to_string(),
            subsystem: "SSH Hardening".to_string(),
            name: "PermitEmptyPasswords".to_string(),
            location: path.to_string(),
            value: uncommented.to_string(),
            status: AuditStatus::Critical,
            details: "SSH allows login for accounts with empty passwords.".to_string(),
        };
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
            evidence: uncommented.to_string(),
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

    let Ok(content) = read_bounded_string(Path::new(&hosts_path), MAX_AUDIT_FILE_BYTES) else {
        return;
    };

    parse_hosts_content(&hosts_path, &content, items, findings);
}

fn parse_hosts_content(
    hosts_path: &str,
    content: &str,
    items: &mut Vec<AuditItem>,
    findings: &mut Vec<SecurityFinding>,
) {
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
    let mut sinkholed_domains: Vec<String> = Vec::new();
    let mut sinkhole_sample_line = String::new();

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
            if severity == Severity::Critical {
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
                    description: format!("{} maps '{}' to '{}'.", hosts_path, domain_list, ip),
                    pid: None,
                    process_name: None,
                    endpoint: None,
                    evidence: trimmed.to_string(),
                    remediation: format!("Remove the redirection entry from {}.", hosts_path),
                });
            } else {
                if sinkholed_domains.len() < MAX_HOSTS_BLOCKLIST_ITEMS {
                    items.push(AuditItem {
                        check_id: "AUD-HOSTS-HIJACK".to_string(),
                        subsystem: "DNS / Hosts File".to_string(),
                        name: format!("Blocked Domain ({})", domain_list),
                        location: hosts_path.to_string(),
                        value: format!("{} -> {}", domain_list, ip),
                        status,
                        details: details.to_string(),
                    });
                }
                if sinkhole_sample_line.is_empty() {
                    sinkhole_sample_line = trimmed.to_string();
                }
                sinkholed_domains.push(domain_list);
            }
        }
    }

    // Aggregate sinkhole/blocklist matches into a single Medium finding so ad-blockers with dozens
    // of telemetry entries do not multiply score penalties while still surfacing tampering.
    if !sinkholed_domains.is_empty() {
        let (_, severity, _) = hosts_override_level("0.0.0.0");
        let preview: Vec<&str> = sinkholed_domains
            .iter()
            .take(3)
            .map(String::as_str)
            .collect();
        let summary_domains = if sinkholed_domains.len() > 3 {
            format!(
                "{} (+{} more)",
                preview.join(", "),
                sinkholed_domains.len() - 3
            )
        } else {
            preview.join(", ")
        };
        findings.push(SecurityFinding {
            rule_id: "AUD-HOSTS-TAMPER".to_string(),
            category: "Hosts File Tampering".to_string(),
            mitre_id: "T1565.001".to_string(),
            severity,
            title: format!(
                "Hosts File Blocks Security/Update Domain(s): {}",
                summary_domains
            ),
            description: format!(
                "{} maps {} security/OS domain entry(ies) to loopback/0.0.0.0 (blocklist or AV tampering).",
                hosts_path,
                sinkholed_domains.len()
            ),
            pid: None,
            process_name: None,
            endpoint: None,
            evidence: sinkhole_sample_line,
            remediation: format!(
                "Verify whether these sinkhole rules in {} come from an intentional blocklist.",
                hosts_path
            ),
        });
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

        let (st4, _) =
            evaluate_persistence_command(r#"C:\Windows\system32\cmd.exe /q /c echo hello"#);
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

        // `.json` argument must NOT false-positive on the `.js` JScript rule.
        let (st7, _) = evaluate_persistence_command(
            r#""C:\Program Files\Daemon\service.exe" --config "C:\ProgramData\Daemon\config.json""#,
        );
        assert_eq!(st7, AuditStatus::Pass);

        // Benign Linux `/tmp` cleanup job must NOT trigger Critical `/tmp/` execution alert.
        let (st8, _) =
            evaluate_persistence_command("/usr/bin/find /tmp/ -type f -mtime +7 -delete");
        assert_eq!(st8, AuditStatus::Info);
    }

    #[test]
    fn test_sshd_empty_passwords_and_inline_comments() {
        let (item, finding) =
            check_sshd_directive("/etc/ssh/sshd_config", "PermitEmptyPasswords yes").unwrap();
        assert_eq!(item.status, AuditStatus::Critical);
        assert_eq!(finding.unwrap().severity, Severity::Critical);
        assert!(check_sshd_directive("/etc/ssh/sshd_config", "PermitEmptyPasswords no").is_none());
        assert!(
            check_sshd_directive("/etc/ssh/sshd_config", "PermitRootLogin no # never set yes")
                .is_none(),
            "inline comment containing 'yes' must not trigger PermitRootLogin"
        );
        assert!(check_sshd_directive("/etc/ssh/sshd_config", "PermitRootLogin yes # admin").is_some());
    }

    #[test]
    fn test_hosts_blocklist_aggregates_while_redirect_stays_critical() {
        assert_eq!(hosts_override_level("0.0.0.0").0, AuditStatus::Warning);
        assert_eq!(hosts_override_level("127.0.0.1").1, Severity::Medium);
        assert_eq!(hosts_override_level("203.0.113.5").0, AuditStatus::Critical);

        let sample = "\
            0.0.0.0 telemetry.microsoft.com\n\
            0.0.0.0 watson.microsoft.com\n\
            0.0.0.0 vortex.data.microsoft.com\n\
            198.51.100.77 www.virustotal.com\n";
        let mut items = Vec::new();
        let mut findings = Vec::new();
        parse_hosts_content("/etc/hosts", sample, &mut items, &mut findings);
        let crit = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let med = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        assert_eq!(crit, 1, "redirect to external IP is Critical");
        assert_eq!(med, 1, "multiple 0.0.0.0 blocklist lines aggregate to 1 Medium finding");
    }

    #[test]
    fn test_winlogon_userinit_validation() {
        assert!(is_default_winlogon_userinit(
            r"C:\Windows\system32\userinit.exe,"
        ));
        assert!(is_default_winlogon_userinit("userinit.exe"));
        assert!(!is_default_winlogon_userinit(
            r"C:\Windows\system32\userinit.exe,C:\Temp\evil.exe"
        ));
    }
}
