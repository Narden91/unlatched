use crate::models::{AuditStatus, ScanSnapshot, Severity};
use std::fs;
use std::path::Path;

pub fn export_json_report(snapshot: &ScanSnapshot, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(snapshot).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}

pub fn export_markdown_report(snapshot: &ScanSnapshot, path: &Path) -> Result<(), String> {
    let mut md = String::with_capacity(8192);
    md.push_str("# Unlatched - Security Report\n\n");
    md.push_str(&format!(
        "- **Timestamp:** `{}`\n",
        snapshot.timestamp.format("%Y-%m-%d %H:%M:%S %z")
    ));
    md.push_str(&format!(
        "- **Host:** `{}` (`{} {}` | Kernel `{}`)\n",
        snapshot.hostname, snapshot.os_name, snapshot.os_version, snapshot.kernel_version
    ));
    md.push_str(&format!(
        "- **Privilege Mode:** `{}`\n",
        if snapshot.is_elevated {
            "Elevated (Admin / root)"
        } else {
            "Standard User"
        }
    ));
    md.push_str(&format!(
        "- **Security Score:** **{}/100** (`{}`)\n",
        snapshot.security_score, snapshot.security_grade
    ));
    md.push_str(&format!(
        "- **Scan Duration:** `{} ms`\n\n",
        snapshot.scan_duration_ms
    ));

    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Count |\n| :--- | :---: |\n");
    md.push_str(&format!(
        "| Active Sockets | **{}** |\n",
        snapshot.total_connections
    ));
    md.push_str(&format!(
        "| Listening Ports | **{}** |\n",
        snapshot.listening_ports
    ));
    md.push_str(&format!(
        "| Established Connections | **{}** |\n",
        snapshot.established_connections
    ));
    md.push_str(&format!(
        "| Public IP Connections | **{}** |\n",
        snapshot.external_connections
    ));
    md.push_str(&format!(
        "| Critical / High / Medium / Low | **{} / {} / {} / {}** |\n\n",
        snapshot.critical_count, snapshot.high_count, snapshot.medium_count, snapshot.low_count
    ));

    md.push_str("## Findings\n\n");
    if snapshot.findings.is_empty() {
        md.push_str("No security findings detected.\n\n");
    } else {
        for (idx, f) in snapshot.findings.iter().enumerate() {
            md.push_str(&format!(
                "### {}. [{}] {} (`{}`)\n",
                idx + 1,
                f.severity.label(),
                f.title,
                f.rule_id
            ));
            md.push_str(&format!(
                "- **Category:** {} | **MITRE:** `{}`\n",
                f.category, f.mitre_id
            ));
            if let Some(proc_name) = &f.process_name {
                md.push_str(&format!(
                    "- **Process:** `{}` (PID `{}`)\n",
                    proc_name,
                    f.pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "N/A".to_string())
                ));
            }
            if let Some(ep) = &f.endpoint {
                md.push_str(&format!("- **Endpoint:** `{}`\n", ep));
            }
            md.push_str(&format!("- **Description:** {}\n", f.description));
            md.push_str(&format!("- **Evidence:** `{}`\n", f.evidence));
            md.push_str(&format!("- **Remediation:** {}\n\n", f.remediation));
        }
    }

    md.push_str("## Connections & Listening Ports (Top 60)\n\n");
    md.push_str("| Risk | Proto | Local Endpoint | Remote Endpoint | State | PID | Process | Service | Scope |\n");
    md.push_str("| :---: | :---: | :--- | :--- | :---: | :---: | :--- | :--- | :---: |\n");
    for conn in snapshot.connections.iter().take(60) {
        md.push_str(&format!(
            "| **{}** | {} | `{}` | `{}` | `{}` | {} | `{}` | {} | {} |\n",
            conn.severity.label(),
            conn.protocol.as_str(),
            conn.local_endpoint(),
            conn.remote_display(),
            conn.state,
            conn.pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            conn.process_name,
            conn.service_name,
            conn.exposure.short_label()
        ));
    }
    md.push('\n');

    md.push_str("## Persistence & Host Audit\n\n");
    md.push_str("| Status | Subsystem | Item | Location | Value / Details |\n");
    md.push_str("| :---: | :--- | :--- | :--- | :--- |\n");
    for item in &snapshot.audit_items {
        md.push_str(&format!(
            "| **{}** | {} | `{}` | `{}` | `{}` - {} |\n",
            item.status.label(),
            item.subsystem,
            item.name,
            item.location,
            item.value.replace('|', "\\|"),
            item.details
        ));
    }

    fs::write(path, md).map_err(|e| e.to_string())
}

pub fn print_cli_summary(snapshot: &ScanSnapshot, only_flagged: bool) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let red = "\x1b[31m";
    let magenta = "\x1b[35m";
    let dim = "\x1b[2m";

    let score_color = match snapshot.security_score {
        85..=100 => green,
        65..=84 => yellow,
        _ => red,
    };

    println!(
        "\n{bold}{cyan}========================================================================================{reset}"
    );
    println!(
        "{bold}{cyan}  SAFE DOOR SCANNER v0.1.0{reset}  |  Host: {bold}{}{reset} ({} {})  |  Scan Time: {bold}{} ms{reset}",
        snapshot.hostname, snapshot.os_name, snapshot.os_version, snapshot.scan_duration_ms
    );
    println!(
        "{bold}{cyan}========================================================================================{reset}"
    );
    println!(
        "  Security Score : {bold}{score_color}{}/100 [{}]{reset}   |   Privilege: {bold}{}{reset}",
        snapshot.security_score,
        snapshot.security_grade,
        if snapshot.is_elevated {
            "ADMIN / ROOT"
        } else {
            "USER MODE"
        }
    );
    println!(
        "  Sockets Total  : {bold}{}{reset} (Listening: {bold}{}{reset}, Established: {bold}{}{reset}, External IP: {bold}{}{reset})",
        snapshot.total_connections,
        snapshot.listening_ports,
        snapshot.established_connections,
        snapshot.external_connections
    );
    println!(
        "  Findings       : {bold}{red}CRITICAL: {}{reset}  |  {bold}{magenta}HIGH: {}{reset}  |  {bold}{yellow}MEDIUM: {}{reset}  |  {dim}LOW: {}{reset}\n",
        snapshot.critical_count, snapshot.high_count, snapshot.medium_count, snapshot.low_count
    );

    println!("{bold}{cyan}FINDINGS ({}){reset}", snapshot.findings.len());
    println!("{dim}----------------------------------------------------------------------------------------{reset}");
    if snapshot.findings.is_empty() {
        println!("  {green}[OK] No security findings detected.{reset}\n");
    } else {
        for f in &snapshot.findings {
            let sev_col = match f.severity {
                Severity::Critical => red,
                Severity::High => magenta,
                Severity::Medium => yellow,
                Severity::Low => cyan,
                Severity::Safe => green,
            };
            println!(
                "  {bold}{sev_col}[{:^8}]{reset} {bold}{}{reset} {dim}({} | {}){reset}",
                f.severity.label(),
                f.title,
                f.rule_id,
                f.mitre_id
            );
            println!("             {}", f.description);
            println!("             {dim}Evidence   : {}{reset}", f.evidence);
            println!("             {cyan}Remediation: {}{reset}\n", f.remediation);
        }
    }

    let filtered_conns: Vec<_> = snapshot
        .connections
        .iter()
        .filter(|c| !only_flagged || c.severity >= Severity::Low)
        .collect();

    println!(
        "{bold}{cyan}CONNECTIONS & PORTS (Showing {} of {}){reset}",
        filtered_conns.len().min(45),
        filtered_conns.len()
    );
    println!("{dim}----------------------------------------------------------------------------------------{reset}");
    println!(
        "  {bold}{:<8} {:<5} {:<24} {:<26} {:<11} {:<7} {:<18} {:<10}{reset}",
        "RISK", "PROTO", "LOCAL ENDPOINT", "REMOTE ENDPOINT", "STATE", "PID", "PROCESS", "SERVICE"
    );
    for conn in filtered_conns.iter().take(45) {
        let sev_col = match conn.severity {
            Severity::Critical => red,
            Severity::High => magenta,
            Severity::Medium => yellow,
            Severity::Low => cyan,
            Severity::Safe => green,
        };
        let local_ep = truncate_str(&conn.local_endpoint(), 23);
        let remote_ep = truncate_str(&conn.remote_endpoint(), 25);
        let proc_str = truncate_str(&conn.process_name, 17);
        let pid_str = conn
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());

        println!(
            "  {bold}{sev_col}{:<8}{reset} {:<5} {:<24} {:<26} {:<11} {:<7} {:<18} {:<10}",
            conn.severity.label(),
            conn.protocol.as_str(),
            local_ep,
            remote_ep,
            conn.state,
            pid_str,
            proc_str,
            conn.service_name
        );
    }
    println!();

    println!(
        "{bold}{cyan}PERSISTENCE & HOST AUDIT ({} checks){reset}",
        snapshot.audit_items.len()
    );
    println!("{dim}----------------------------------------------------------------------------------------{reset}");
    for item in snapshot.audit_items.iter().take(20) {
        let st_col = match item.status {
            AuditStatus::Critical => red,
            AuditStatus::Warning => yellow,
            AuditStatus::Info => cyan,
            AuditStatus::Pass => green,
        };
        println!(
            "  {bold}{st_col}[{:^5}]{reset} {:<22} {:<26} -> {}",
            item.status.label(),
            truncate_str(&item.subsystem, 21),
            truncate_str(&item.name, 25),
            truncate_str(&item.value, 45)
        );
    }
    println!();
}

pub fn truncate_str(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else if max_chars > 3 {
        let prefix: String = s.chars().take(max_chars - 3).collect();
        format!("{}...", prefix)
    } else {
        s.chars().take(max_chars).collect()
    }
}
