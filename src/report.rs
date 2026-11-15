use crate::models::{AuditStatus, ScanSnapshot, Severity};
use crate::scanner::fs_safe::is_local_safe_path;
use serde_json::json;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically writes `contents` to `path` via an owner-restricted temporary file and `rename`.
///
/// Security controls:
/// 1. Rejects Windows UNC / device paths (`is_local_safe_path`).
/// 2. Rejects symlink or NTFS junction parent directories (`symlink_metadata`) so an elevated
///    export cannot be redirected to `/etc` or `C:\Windows\System32`.
/// 3. Uses unpredictable `.tmp` names with `create_new(true)` and `0600` permissions on Unix.
pub(crate) fn write_report_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    if !is_local_safe_path(path) {
        return Err(format!("{}: rejected non-local or UNC export path", path.display()));
    }

    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !is_local_safe_path(dir) {
        return Err(format!("{}: rejected non-local parent directory", dir.display()));
    }

    let dir_meta =
        fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
        return Err(format!(
            "{}: parent directory must not be a symlink",
            dir.display()
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if (dir_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(format!(
                "{}: parent directory must not be a junction or reparse point",
                dir.display()
            ));
        }
    }

    let name = path
        .file_name()
        .ok_or_else(|| format!("{}: not a file path", path.display()))?;

    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(
        ".{}.{}.{:x}.{}.tmp",
        name.to_string_lossy(),
        pid,
        nanos,
        seq
    ));

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let written = opts
        .open(&tmp)
        .and_then(|mut f| f.write_all(contents).and_then(|_| f.sync_all()));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(format!("{}: {e}", tmp.display()));
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!(
            "{}: {e} (is the file open in another program?)",
            path.display()
        )
    })
}

pub fn export_json_report(snapshot: &ScanSnapshot, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(snapshot).map_err(|e| e.to_string())?;
    write_report_atomic(path, json.as_bytes())
}

/// Sanitizes untrusted text placed inside inline Markdown code spans (`` `...` ``) and tables.
fn md_code(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '`' => '\'',
            '|' => '/',
            '\r' | '\n' => ' ',
            _ => c,
        })
        .collect()
}

/// Sanitizes untrusted prose placed in Markdown list items or table cells so HTML tags, pipes,
/// and links cannot break formatting or inject active markup in Markdown viewers.
fn md_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '`' => out.push('\''),
            '\r' | '\n' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
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
        md_code(&snapshot.hostname),
        md_code(&snapshot.os_name),
        md_code(&snapshot.os_version),
        md_code(&snapshot.kernel_version)
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
        snapshot.security_score,
        md_code(&snapshot.security_grade)
    ));
    md.push_str(&format!(
        "- **Scan Duration:** `{} ms`\n",
        snapshot.scan_duration_ms
    ));
    if snapshot.suppressed_count > 0 {
        md.push_str(&format!(
            "- **Allowlist Suppressed Findings:** `{}`\n",
            snapshot.suppressed_count
        ));
    }
    for w in &snapshot.scan_warnings {
        md.push_str(&format!("- **Warning:** {}\n", md_text(w)));
    }
    if snapshot.sockets_without_exe > 0 {
        md.push_str(&format!(
            "- **Coverage:** program path unknown for {} of {} sockets\n",
            snapshot.sockets_without_exe, snapshot.total_connections
        ));
    }
    md.push('\n');

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
                md_text(&f.title),
                md_code(&f.rule_id)
            ));
            md.push_str(&format!(
                "- **Category:** {} | **MITRE:** `{}`\n",
                md_text(&f.category),
                md_code(&f.mitre_id)
            ));
            if let Some(proc_name) = &f.process_name {
                md.push_str(&format!(
                    "- **Process:** `{}` (PID `{}`)\n",
                    md_code(proc_name),
                    f.pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "N/A".to_string())
                ));
            }
            if let Some(ep) = &f.endpoint {
                md.push_str(&format!("- **Endpoint:** `{}`\n", md_code(ep)));
            }
            md.push_str(&format!("- **Description:** {}\n", md_text(&f.description)));
            md.push_str(&format!("- **Evidence:** `{}`\n", md_code(&f.evidence)));
            md.push_str(&format!(
                "- **Remediation:** {}\n\n",
                md_text(&f.remediation)
            ));
        }
    }

    md.push_str("## Connections & Listening Ports (Top 60)\n\n");
    md.push_str(
        "| Risk | Proto | Local Endpoint | Remote Endpoint | State | PID | Process | Service | Scope |\n",
    );
    md.push_str("| :---: | :---: | :--- | :--- | :---: | :---: | :--- | :--- | :---: |\n");
    for conn in snapshot.connections.iter().take(60) {
        md.push_str(&format!(
            "| **{}** | {} | `{}` | `{}` | `{}` | {} | `{}` | {} | {} |\n",
            conn.severity.label(),
            conn.protocol.as_str(),
            md_code(&conn.local_endpoint()),
            md_code(&conn.remote_display()),
            md_code(&conn.state),
            conn.pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            md_code(&conn.process_name),
            md_text(&conn.service_name),
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
            md_text(&item.subsystem),
            md_code(&item.name),
            md_code(&item.location),
            md_code(&item.value),
            md_text(&item.details)
        ));
    }

    write_report_atomic(path, md.as_bytes())
}

fn sarif_level_and_score(sev: Severity) -> (&'static str, &'static str) {
    match sev {
        Severity::Critical => ("error", "9.5"),
        Severity::High => ("error", "7.8"),
        Severity::Medium => ("warning", "5.5"),
        Severity::Low => ("note", "3.0"),
        Severity::Safe => ("none", "0.0"),
    }
}

/// Builds an OASIS SARIF v2.1.0 JSON document compatible with GitHub Code Scanning, SIEMs, and CI gates.
#[must_use]
pub fn build_sarif_value(snapshot: &ScanSnapshot) -> serde_json::Value {
    let mut rule_indices: HashMap<String, usize> = HashMap::new();
    let mut rules_json: Vec<serde_json::Value> = Vec::new();
    let mut results_json: Vec<serde_json::Value> = Vec::with_capacity(snapshot.findings.len());

    let mut pid_exe: HashMap<u32, &str> = HashMap::new();
    for p in &snapshot.processes {
        if !p.exe_path.is_empty() {
            pid_exe.insert(p.pid, p.exe_path.as_str());
        }
    }

    for f in &snapshot.findings {
        let (level, sec_score) = sarif_level_and_score(f.severity);
        let rule_index = match rule_indices.get(&f.rule_id) {
            Some(&idx) => idx,
            None => {
                let idx = rules_json.len();
                rule_indices.insert(f.rule_id.clone(), idx);
                let mut tags = vec!["security".to_string(), "endpoint".to_string()];
                if !f.mitre_id.is_empty() {
                    tags.push(format!("external/mitre/{}", f.mitre_id));
                }
                rules_json.push(json!({
                    "id": f.rule_id,
                    "name": f.category,
                    "shortDescription": { "text": f.category },
                    "fullDescription": { "text": f.description },
                    "help": { "text": f.remediation },
                    "defaultConfiguration": { "level": level },
                    "properties": {
                        "tags": tags,
                        "security-severity": sec_score
                    }
                }));
                idx
            }
        };

        let artifact_uri = f
            .pid
            .and_then(|pid| pid_exe.get(&pid).copied())
            .or(f.endpoint.as_deref())
            .unwrap_or(snapshot.hostname.as_str());

        let mut logical_locations = Vec::new();
        if let Some(proc_name) = &f.process_name {
            logical_locations.push(json!({
                "name": proc_name,
                "kind": "process"
            }));
        }
        if let Some(ep) = &f.endpoint {
            logical_locations.push(json!({
                "name": ep,
                "kind": "endpoint"
            }));
        }

        results_json.push(json!({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": {
                "text": format!("{} — {} (Evidence: {})", f.title, f.description, f.evidence)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri
                    }
                },
                "logicalLocations": logical_locations
            }],
            "properties": {
                "severity": f.severity.label(),
                "mitreAttackId": f.mitre_id,
                "pid": f.pid,
                "processName": f.process_name,
                "endpoint": f.endpoint,
                "evidence": f.evidence,
                "remediation": f.remediation
            }
        }));
    }

    let notifications: Vec<serde_json::Value> = snapshot
        .scan_warnings
        .iter()
        .map(|w| {
            json!({
                "level": "warning",
                "message": { "text": w }
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Unlatched",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/Narden91/unlatched",
                    "rules": rules_json
                }
            },
            "invocations": [{
                "executionSuccessful": snapshot.scan_warnings.is_empty(),
                "toolExecutionNotifications": notifications,
                "properties": {
                    "hostname": snapshot.hostname,
                    "os": format!("{} {}", snapshot.os_name, snapshot.os_version),
                    "isElevated": snapshot.is_elevated,
                    "securityScore": snapshot.security_score,
                    "securityGrade": snapshot.security_grade,
                    "suppressedFindings": snapshot.suppressed_count
                }
            }],
            "results": results_json
        }]
    })
}

pub fn export_sarif_report(snapshot: &ScanSnapshot, path: &Path) -> Result<(), String> {
    let sarif = build_sarif_value(snapshot);
    let serialized = serde_json::to_string_pretty(&sarif).map_err(|e| e.to_string())?;
    write_report_atomic(path, serialized.as_bytes())
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

    let severity_color = |s: Severity| match s {
        Severity::Critical => red,
        Severity::High => magenta,
        Severity::Medium => yellow,
        Severity::Low => cyan,
        Severity::Safe => green,
    };

    let score_color = match snapshot.security_score {
        85..=100 => green,
        65..=84 => yellow,
        _ => red,
    };

    println!(
        "\n{bold}{cyan}Unlatched{reset}  {} ({} {})  {}ms",
        snapshot.hostname, snapshot.os_name, snapshot.os_version, snapshot.scan_duration_ms
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
    let suppressed_note = if snapshot.suppressed_count > 0 {
        format!("  |  {green}ALLOWLISTED: {}{reset}", snapshot.suppressed_count)
    } else {
        String::new()
    };
    println!(
        "  Findings       : {bold}{red}CRITICAL: {}{reset}  |  {bold}{magenta}HIGH: {}{reset}  |  {bold}{yellow}MEDIUM: {}{reset}  |  {dim}LOW: {}{reset}{suppressed_note}\n",
        snapshot.critical_count, snapshot.high_count, snapshot.medium_count, snapshot.low_count
    );

    if snapshot.sockets_without_exe > 0 {
        println!(
            "  {yellow}Program path unknown for {} of {} sockets{}{reset}",
            snapshot.sockets_without_exe,
            snapshot.total_connections,
            if snapshot.is_elevated {
                "."
            } else {
                ". Run as Administrator/root for full coverage."
            }
        );
    }
    for w in &snapshot.scan_warnings {
        println!("  {bold}{red}WARNING: {w}{reset}");
    }
    if snapshot.sockets_without_exe > 0 || !snapshot.scan_warnings.is_empty() {
        println!();
    }

    println!("{bold}{cyan}Findings ({}){reset}", snapshot.findings.len());
    println!("{dim}----------------------------------------------------------------------------------------{reset}");
    if snapshot.findings.is_empty() {
        println!("  {green}Nothing flagged.{reset}\n");
    } else {
        for f in &snapshot.findings {
            let sev_col = severity_color(f.severity);
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
        "{bold}{cyan}Connections ({} of {}){reset}",
        filtered_conns.len().min(45),
        filtered_conns.len()
    );
    println!("{dim}----------------------------------------------------------------------------------------{reset}");
    println!(
        "  {bold}{:<8} {:<5} {:<24} {:<26} {:<11} {:<7} {:<18} {:<10}{reset}",
        "RISK", "PROTO", "LOCAL ENDPOINT", "REMOTE ENDPOINT", "STATE", "PID", "PROCESS", "SERVICE"
    );
    for conn in filtered_conns.iter().take(45) {
        let sev_col = severity_color(conn.severity);
        let local_raw = conn.local_endpoint();
        let remote_raw = conn.remote_endpoint();
        let local_ep = truncate_str(&local_raw, 23);
        let remote_ep = truncate_str(&remote_raw, 25);
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

/// Single-pass UTF-8 truncation that returns `Cow::Borrowed` with zero allocation whenever `s` fits.
#[must_use]
pub fn truncate_str(s: &str, max_chars: usize) -> Cow<'_, str> {
    if s.len() <= max_chars {
        return Cow::Borrowed(s);
    }
    if s.char_indices().nth(max_chars).is_none() {
        return Cow::Borrowed(s);
    }
    if max_chars > 3 {
        let end = s
            .char_indices()
            .nth(max_chars - 3)
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        let mut out = String::with_capacity(end + 3);
        out.push_str(&s[..end]);
        out.push_str("...");
        Cow::Owned(out)
    } else {
        let end = s
            .char_indices()
            .nth(max_chars)
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        Cow::Borrowed(&s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SecurityFinding;
    use chrono::Local;

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("unlatched_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn report_write_replaces_file_and_leaves_no_temp() {
        let dir = scratch_dir("write");
        let path = dir.join("report.md");
        fs::write(&path, "old").unwrap();
        write_report_atomic(&path, b"new").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "temp file left behind"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// An elevated export must not write through a link planted at the report name.
    #[test]
    fn report_write_does_not_follow_planted_symlink() {
        let dir = scratch_dir("link");
        let victim = dir.join("victim.conf");
        let link = dir.join("report.md");
        fs::write(&victim, "precious").unwrap();
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&victim, &link);
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&victim, &link);
        if let Err(e) = made {
            eprintln!("skipped: cannot create symlinks here ({e})");
            fs::remove_dir_all(&dir).unwrap();
            return;
        }
        write_report_atomic(&link, b"report text").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(fs::read_to_string(&link).unwrap(), "report text");
        assert!(!fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sarif_export_produces_valid_v2_1_0_schema_and_markdown_escapes_injection() {
        let snap = ScanSnapshot {
            timestamp: Local::now(),
            scan_duration_ms: 12,
            hostname: "workstation".to_string(),
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            kernel_version: "26100".to_string(),
            is_elevated: true,
            security_score: 70,
            security_grade: "C".to_string(),
            scan_warnings: Vec::new(),
            sockets_without_exe: 0,
            suppressed_count: 2,
            total_connections: 0,
            listening_ports: 0,
            established_connections: 0,
            external_connections: 0,
            suspicious_connections: 0,
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            connections: Vec::new(),
            findings: vec![
                SecurityFinding {
                    rule_id: "H01-REV-SHELL".to_string(),
                    category: "Reverse / Bind Shell".to_string(),
                    mitre_id: "T1059".to_string(),
                    severity: Severity::Critical,
                    title: "Shell <script>alert(1)</script>".to_string(),
                    description: "Pipe | and `backtick` injection".to_string(),
                    pid: Some(9001),
                    process_name: Some("ba`sh|x".to_string()),
                    endpoint: Some("0.0.0.0:4444".to_string()),
                    evidence: "cmd `| evil".to_string(),
                    remediation: "Terminate".to_string(),
                },
                SecurityFinding {
                    rule_id: "H01-REV-SHELL".to_string(),
                    category: "Reverse / Bind Shell".to_string(),
                    mitre_id: "T1059".to_string(),
                    severity: Severity::Critical,
                    title: "Second shell".to_string(),
                    description: "Duplicate rule id deduplicates driver.rules".to_string(),
                    pid: Some(9002),
                    process_name: Some("sh".to_string()),
                    endpoint: Some("0.0.0.0:4445".to_string()),
                    evidence: "sh -i".to_string(),
                    remediation: "Terminate".to_string(),
                },
            ],
            audit_items: Vec::new(),
            processes: Vec::new(),
            timeline_events: Vec::new(),
        };

        let sarif = build_sarif_value(&snap);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "Unlatched");
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "driver.rules must deduplicate identical rule_ids"
        );
        assert_eq!(
            sarif["runs"][0]["results"].as_array().unwrap().len(),
            2
        );
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");

        let dir = scratch_dir("sarif_md");
        let md_path = dir.join("out.md");
        export_markdown_report(&snap, &md_path).unwrap();
        let md_content = fs::read_to_string(&md_path).unwrap();
        assert!(!md_content.contains("<script>"));
        assert!(md_content.contains("&lt;script&gt;"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
