use crate::models::Severity;
use crate::scanner::fs_safe::read_bounded_slice;
use std::path::Path;

pub const SHELL_NAMES: &[&str] = &[
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

pub const NETCAT_TOOLS: &[&str] = &[
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

pub const SERVER_PARENTS: &[&str] = &[
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

/// High-risk Windows utilities whose embedded PE `OriginalFilename` reveals identity even if the
/// file on disk was copied and renamed (MITRE T1036.003).
pub const SENSITIVE_ORIGINAL_BINARIES: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "nc.exe",
    "ncat.exe",
];

#[must_use]
pub fn is_shell_name(name_lower: &str) -> bool {
    SHELL_NAMES.contains(&name_lower)
}

#[must_use]
pub fn is_relay_name(name_lower: &str) -> bool {
    NETCAT_TOOLS.contains(&name_lower)
}

/// Shared suspicious execution directory detector used across socket, process, and persistence rules.
#[must_use]
pub fn check_suspicious_exec_path(raw_path: &str, norm_lower: &str) -> Option<String> {
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
        ("%temp%\\", "Unexpanded %TEMP% folder"),
        ("%tmp%\\", "Unexpanded %TMP% folder"),
        ("%public%\\", "Unexpanded %PUBLIC% folder"),
    ];

    for (pattern, desc) in win_suspicious {
        if norm_lower.contains(pattern) {
            return Some(format!("{} ({})", desc, raw_path));
        }
    }

    None
}

/// Matches PowerShell's native `-EncodedCommand` prefix abbreviations (`-e`, `-ec`, `-en`, `-enc`,
/// `-enco`, ..., `-encodedcommand`, plus `/` and `:` forms) without false-positiving on flags
/// like `-ExecutionPolicy` or `-ErrorAction`.
#[must_use]
pub fn has_powershell_encoded_flag(cmd_lower: &str) -> bool {
    if cmd_lower.contains("frombase64string") {
        return true;
    }
    for raw_tok in cmd_lower.split_whitespace() {
        let tok = raw_tok.trim_matches(|c| c == '"' || c == '\'');
        let Some(rest) = tok.strip_prefix('-').or_else(|| tok.strip_prefix('/')) else {
            continue;
        };
        let flag = rest.split(':').next().unwrap_or(rest);
        if !flag.is_empty() && (flag == "ec" || "encodedcommand".starts_with(flag)) {
            return true;
        }
    }
    false
}

#[must_use]
pub fn is_powershell_identity(name_lower: &str, orig_lower: Option<&str>) -> bool {
    let check = |s: &str| s.starts_with("powershell") || s.starts_with("pwsh");
    check(name_lower) || orig_lower.is_some_and(check)
}

#[must_use]
pub fn is_lolbin_identity(name_lower: &str, orig_lower: Option<&str>) -> bool {
    let check =
        |s: &str| s.starts_with("mshta") || s.starts_with("regsvr32") || s.starts_with("rundll32");
    check(name_lower) || orig_lower.is_some_and(check)
}

/// Evaluates suspicious command-line patterns, accounting for both the active process name and
/// any PE `OriginalFilename` uncovered on disk.
#[must_use]
pub fn check_suspicious_cmdline(
    name_lower: &str,
    orig_lower: Option<&str>,
    cmd_lower: &str,
) -> Option<(Severity, &'static str)> {
    if is_powershell_identity(name_lower, orig_lower) {
        if has_powershell_encoded_flag(cmd_lower) {
            return Some((
                Severity::High,
                "Base64-encoded PowerShell command (-EncodedCommand / FromBase64String)",
            ));
        }
        let has_cradle_fn = cmd_lower.contains("downloadstring(")
            || cmd_lower.contains("downloaddata(")
            || cmd_lower.contains("downloadfile(");
        let has_iex_http = (cmd_lower.contains("iex")
            || cmd_lower.contains("invoke-expression"))
            && (cmd_lower.contains("http")
                || cmd_lower.contains("iwr ")
                || cmd_lower.contains("irm ")
                || cmd_lower.contains("invoke-webrequest")
                || cmd_lower.contains("invoke-restmethod"));
        if has_cradle_fn || has_iex_http {
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

    if is_lolbin_identity(name_lower, orig_lower)
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

    if (name_lower.starts_with("certutil")
        || orig_lower.is_some_and(|o| o.starts_with("certutil")))
        && cmd_lower.contains("-urlcache")
        && cmd_lower.contains("http")
    {
        return Some((
            Severity::High,
            "certutil.exe -urlcache remote payload download",
        ));
    }

    None
}

/// Checks whether `cmd_lower` invokes a script with `ext` (e.g. `.js`, `.vbs`) bounded at token end
/// so `.js` never false-positives on `.json` or `.jsp`.
#[must_use]
pub fn has_script_token(cmd_lower: &str, ext: &str) -> bool {
    let bytes = cmd_lower.as_bytes();
    let ext_b = ext.as_bytes();
    if ext_b.is_empty() || bytes.len() < ext_b.len() {
        return false;
    }
    let mut pos = 0;
    while let Some(rel) = cmd_lower[pos..].find(ext) {
        let idx = pos + rel;
        let after = idx + ext_b.len();
        let boundary = after == bytes.len()
            || matches!(
                bytes[after],
                b' ' | b'\t' | b'"' | b'\'' | b',' | b';' | b')'
            );
        if boundary {
            return true;
        }
        pos = idx + 1;
    }
    false
}

/// Inspects a local PE executable's `.rsrc` section in $O(1)$ bounded I/O (`<= 260 KB` read) to
/// extract its embedded UTF-16LE `OriginalFilename` from `VS_VERSION_INFO`. Returns `None` for
/// non-PE files or binaries without version metadata.
pub fn inspect_pe_original_filename(path: &Path) -> Option<String> {
    let header = read_bounded_slice(path, 0, 4096)?;
    if let Some((rsrc_off, rsrc_len)) = locate_pe_rsrc_section(&header) {
        let rsrc = read_bounded_slice(path, rsrc_off, rsrc_len.min(256 * 1024))?;
        return extract_pe_original_filename_from_bytes(&rsrc);
    }
    extract_pe_original_filename_from_bytes(&header)
}

fn locate_pe_rsrc_section(hdr: &[u8]) -> Option<(u64, usize)> {
    if hdr.len() < 0x40 || &hdr[0..2] != b"MZ" {
        return None;
    }
    let pe_off = u32::from_le_bytes(hdr[0x3c..0x40].try_into().ok()?) as usize;
    if pe_off.checked_add(24)? > hdr.len() || &hdr[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }
    let coff = &hdr[pe_off + 4..pe_off + 24];
    let num_sections = (u16::from_le_bytes([coff[2], coff[3]]) as usize).min(96);
    let opt_hdr_size = u16::from_le_bytes([coff[16], coff[17]]) as usize;
    let sec_base = pe_off.checked_add(24)?.checked_add(opt_hdr_size)?;

    for i in 0..num_sections {
        let off = sec_base.checked_add(i * 40)?;
        if off.checked_add(40)? > hdr.len() {
            break;
        }
        let sec = &hdr[off..off + 40];
        if sec[0..5].eq_ignore_ascii_case(b".rsrc") {
            let raw_size = u32::from_le_bytes(sec[16..20].try_into().ok()?) as usize;
            let raw_ptr = u32::from_le_bytes(sec[20..24].try_into().ok()?) as u64;
            if raw_size > 0 && raw_ptr > 0 {
                return Some((raw_ptr, raw_size));
            }
        }
    }
    None
}

/// Scans a byte slice (such as a PE `.rsrc` section) for UTF-16LE `"OriginalFilename\0"` and
/// decodes the adjacent UTF-16LE value string.
#[must_use]
pub fn extract_pe_original_filename_from_bytes(bytes: &[u8]) -> Option<String> {
    // UTF-16LE encoding of "OriginalFilename\0" (17 WCHARs = 34 bytes).
    const KEY_UTF16: [u8; 34] = [
        b'O', 0, b'r', 0, b'i', 0, b'g', 0, b'i', 0, b'n', 0, b'a', 0, b'l', 0, b'F', 0, b'i', 0,
        b'l', 0, b'e', 0, b'n', 0, b'a', 0, b'm', 0, b'e', 0, 0, 0,
    ];

    if bytes.len() < KEY_UTF16.len() + 4 {
        return None;
    }

    let limit = bytes.len() - KEY_UTF16.len();
    let mut i = 0;
    while i <= limit {
        if bytes[i..i + KEY_UTF16.len()] == KEY_UTF16 {
            let mut val_off = i + KEY_UTF16.len();
            // Skip up to 2 optional alignment NUL WCHARs before the value starts.
            for _ in 0..2 {
                if val_off + 2 <= bytes.len() && bytes[val_off] == 0 && bytes[val_off + 1] == 0 {
                    val_off += 2;
                } else {
                    break;
                }
            }

            let mut out = String::with_capacity(24);
            let mut cursor = val_off;
            while cursor + 2 <= bytes.len() && out.len() < 64 {
                let unit = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
                if unit == 0 {
                    break;
                }
                let ch = char::from_u32(u32::from(unit))?;
                if ch.is_control() || matches!(ch, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                    out.clear();
                    break;
                }
                out.push(ch);
                cursor += 2;
            }

            let trimmed = out.trim();
            if !trimmed.is_empty() && trimmed.is_ascii() {
                return Some(trimmed.to_string());
            }
        }
        i += 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_encoded_flag_matches_abbreviations_not_executionpolicy() {
        assert!(has_powershell_encoded_flag("powershell.exe -e ZQBjAGgAbwA="));
        assert!(has_powershell_encoded_flag("pwsh -enc ZQBjAGgAbwA="));
        assert!(has_powershell_encoded_flag("powershell /encodedcommand ZQBjAGgAbwA="));
        assert!(has_powershell_encoded_flag("powershell -ec:ZQBjAGgAbwA="));
        assert!(!has_powershell_encoded_flag(
            "powershell.exe -executionpolicy bypass -erroraction stop -file a.ps1"
        ));
    }

    #[test]
    fn script_token_boundary_distinguishes_js_from_json() {
        assert!(!has_script_token(
            r#""c:\program files\app\app.exe" --config settings.json"#,
            ".js"
        ));
        assert!(has_script_token(r#"wscript.exe "c:\temp\dropper.js" --run"#, ".js"));
        assert!(has_script_token("cscript payload.js", ".js"));
    }

    #[test]
    fn extracts_pe_original_filename_from_synthetic_and_real_pe() {
        let mut blob = vec![0u8; 16];
        for ch in "OriginalFilename\0".encode_utf16() {
            blob.extend_from_slice(&ch.to_le_bytes());
        }
        // 1 padding WCHAR + "PowerShell.EXE\0"
        blob.extend_from_slice(&[0, 0]);
        for ch in "PowerShell.EXE\0".encode_utf16() {
            blob.extend_from_slice(&ch.to_le_bytes());
        }
        assert_eq!(
            extract_pe_original_filename_from_bytes(&blob).as_deref(),
            Some("PowerShell.EXE")
        );

        #[cfg(windows)]
        {
            let cmd = crate::scanner::system_root().join(r"System32\cmd.exe");
            if cmd.exists() {
                let orig = inspect_pe_original_filename(&cmd)
                    .expect("System32\\cmd.exe should carry VS_VERSION_INFO OriginalFilename");
                assert!(
                    orig.to_lowercase().starts_with("cmd.exe"),
                    "unexpected OriginalFilename: {orig}"
                );
            }
        }
    }
}
