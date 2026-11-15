use crate::models::{ProcessRecord, Severity};
use crate::scanner::fs_safe::{is_local_safe_path, open_regular_nofollow};
use crate::scanner::indicators::inspect_pe_original_filename;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

const MAX_HASH_FILE_SIZE: u64 = 20 * 1024 * 1024;
const MAX_LINEAGE_DEPTH: usize = 6;
const MAX_HASH_CACHE_ENTRIES: usize = 2048;

#[derive(Clone, Default)]
pub struct CachedHash {
    pub file_len: u64,
    pub modified: Option<SystemTime>,
    pub sha256: Option<String>,
    pub original_filename: Option<String>,
    pub pe_checked: bool,
}

pub fn check_is_elevated() -> bool {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_USERS;
        use winreg::RegKey;
        RegKey::predef(HKEY_USERS).open_subkey("S-1-5-19").is_ok()
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    let mut parts = rest.split_whitespace();
                    let ruid = parts.next();
                    let euid = parts.next();
                    if euid == Some("0") || ruid == Some("0") {
                        return true;
                    }
                }
            }
        }
        false
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

pub fn collect_processes(sys: &mut System, users: &Users) -> HashMap<u32, ProcessRecord> {
    let refresh_kind = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::Always)
        .with_user(UpdateKind::OnlyIfNotSet)
        .with_memory()
        .with_cpu();

    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind);

    let raw_procs = sys.processes();
    let mut records = HashMap::with_capacity(raw_procs.len());

    for (pid, proc_info) in raw_procs {
        let pid_u32 = pid.as_u32();
        let ppid_u32 = proc_info.parent().map(|p| p.as_u32());
        let name = proc_info.name().to_string_lossy().into_owned();

        let exe_path = proc_info
            .exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        let cmdline = if proc_info.cmd().is_empty() {
            name.clone()
        } else {
            let mut joined = String::new();
            for (idx, arg) in proc_info.cmd().iter().enumerate() {
                if idx > 0 {
                    joined.push(' ');
                }
                joined.push_str(&arg.to_string_lossy());
            }
            joined
        };

        let user = proc_info
            .user_id()
            .and_then(|uid| users.get_user_by_id(uid))
            .map(|u| u.name().to_string())
            .unwrap_or_else(|| "SYSTEM".to_string());

        let is_deleted_binary = is_unlinked_binary(pid_u32, &exe_path);
        let clean_exe = exe_path.trim_end_matches(" (deleted)");
        let exe_exists_on_disk = !clean_exe.is_empty()
            && is_local_safe_path(Path::new(clean_exe))
            && Path::new(clean_exe).is_file();

        records.insert(
            pid_u32,
            ProcessRecord {
                pid: pid_u32,
                ppid: ppid_u32,
                name,
                exe_path,
                cmdline,
                user,
                sha256: None,
                original_filename: None,
                lineage: Vec::new(),
                cpu_usage: proc_info.cpu_usage(),
                memory_bytes: proc_info.memory(),
                run_time_secs: proc_info.run_time(),
                exe_exists_on_disk,
                is_deleted_binary,
                open_sockets_count: 0,
                max_severity: Severity::Safe,
            },
        );
    }

    let lineages: Vec<(u32, Vec<String>)> = {
        let parent_index: HashMap<u32, (Option<u32>, &str)> = records
            .iter()
            .map(|(&pid, rec)| (pid, (rec.ppid, rec.name.as_str())))
            .collect();
        records
            .values()
            .map(|rec| {
                (
                    rec.pid,
                    build_lineage(rec.pid, rec.ppid, &rec.name, &parent_index),
                )
            })
            .collect()
    };

    for (pid, lineage) in lineages {
        if let Some(rec) = records.get_mut(&pid) {
            rec.lineage = lineage;
        }
    }

    records
}

fn build_lineage(
    pid: u32,
    mut curr_ppid: Option<u32>,
    name: &str,
    parent_index: &HashMap<u32, (Option<u32>, &str)>,
) -> Vec<String> {
    let mut chain = Vec::with_capacity(MAX_LINEAGE_DEPTH + 1);
    let mut visited = [0u32; MAX_LINEAGE_DEPTH + 1];
    visited[0] = pid;
    let mut visited_len = 1usize;
    chain.push(format!("{}({})", name, pid));

    let mut depth = 0usize;
    while let Some(p) = curr_ppid {
        if p == 0 || depth >= MAX_LINEAGE_DEPTH || visited[..visited_len].contains(&p) {
            break;
        }
        visited[visited_len] = p;
        visited_len += 1;

        match parent_index.get(&p) {
            Some((next_ppid, pname)) => {
                chain.push(format!("{}({})", pname, p));
                curr_ppid = *next_ppid;
            }
            None => {
                chain.push(format!("PID({})", p));
                break;
            }
        }
        depth += 1;
    }

    chain.reverse();
    chain
}

/// Populates cached PE `OriginalFilename` metadata before heuristic evaluation so renamed
/// system utilities and LOLBins (`powershell.exe` -> `updater.exe`) are exposed to all rules.
pub fn enrich_pe_identities(
    processes: &mut HashMap<u32, ProcessRecord>,
    hash_cache: &mut HashMap<String, CachedHash>,
) {
    trim_cache_if_needed(hash_cache);
    for rec in processes.values_mut() {
        if rec.exe_exists_on_disk && !rec.exe_path.is_empty() {
            rec.original_filename = compute_cached_pe_name(&rec.exe_path, hash_cache);
        }
    }
}

pub fn enrich_sha256_hashes(
    processes: &mut HashMap<u32, ProcessRecord>,
    hash_cache: &mut HashMap<String, CachedHash>,
) {
    trim_cache_if_needed(hash_cache);
    for rec in processes.values_mut() {
        if rec.exe_exists_on_disk
            && !rec.exe_path.is_empty()
            && (rec.open_sockets_count > 0 || rec.max_severity > Severity::Safe)
        {
            rec.sha256 = compute_cached_sha256(&rec.exe_path, hash_cache);
        }
    }
}

fn trim_cache_if_needed(cache: &mut HashMap<String, CachedHash>) {
    if cache.len() > MAX_HASH_CACHE_ENTRIES {
        cache.clear();
    }
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn is_unlinked_binary(pid: u32, exe_path: &str) -> bool {
    if exe_path.ends_with(" (deleted)")
        || exe_path.starts_with("/memfd:")
        || exe_path.starts_with("memfd:")
    {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        if exe_path.is_empty() {
            if let Ok(link) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                let target = link.to_string_lossy();
                if target.ends_with(" (deleted)") || target.contains("memfd:") {
                    return true;
                }
            }
        }
    }
    false
}

pub fn compute_cached_pe_name(
    exe_path: &str,
    cache: &mut HashMap<String, CachedHash>,
) -> Option<String> {
    let path = Path::new(exe_path);
    if !is_local_safe_path(path) {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    let file_len = meta.len();
    let modified = meta.modified().ok();

    if let Some(entry) = cache.get(exe_path) {
        if entry.file_len == file_len && entry.modified == modified && entry.pe_checked {
            return entry.original_filename.clone();
        }
    }

    let orig = inspect_pe_original_filename(path);
    let existing_sha = cache
        .get(exe_path)
        .filter(|e| e.file_len == file_len && e.modified == modified)
        .and_then(|e| e.sha256.clone());

    cache.insert(
        exe_path.to_string(),
        CachedHash {
            file_len,
            modified,
            sha256: existing_sha,
            original_filename: orig.clone(),
            pe_checked: true,
        },
    );
    orig
}

pub fn compute_cached_sha256(
    exe_path: &str,
    cache: &mut HashMap<String, CachedHash>,
) -> Option<String> {
    let path = Path::new(exe_path);
    let (file, meta) = open_regular_nofollow(path)?;

    let file_len = meta.len();
    if file_len == 0 || file_len > MAX_HASH_FILE_SIZE {
        return None;
    }
    let modified = meta.modified().ok();

    if let Some(entry) = cache.get(exe_path) {
        if entry.file_len == file_len && entry.modified == modified {
            if let Some(sha) = &entry.sha256 {
                return Some(sha.clone());
            }
        }
    }

    let mut reader = file.take(MAX_HASH_FILE_SIZE + 1);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total_read = 0u64;
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        total_read += n as u64;
        if total_read > MAX_HASH_FILE_SIZE {
            return None;
        }
        hasher.update(&buf[..n]);
    }

    // Format digest in one pre-sized 64-byte string without per-byte heap allocations.
    let raw_digest = hasher.finalize();
    let mut digest = String::with_capacity(64);
    for b in raw_digest.iter() {
        let _ = write!(&mut digest, "{b:02x}");
    }

    let (orig, pe_checked) = cache
        .get(exe_path)
        .filter(|e| e.file_len == file_len && e.modified == modified)
        .map(|e| (e.original_filename.clone(), e.pe_checked))
        .unwrap_or((None, false));

    cache.insert(
        exe_path.to_string(),
        CachedHash {
            file_len,
            modified,
            sha256: Some(digest.clone()),
            original_filename: orig,
            pe_checked,
        },
    );

    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector_and_uses_cache() {
        let path = std::env::temp_dir().join(format!("unlatched_sha_test_{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        let exe = path.to_string_lossy().into_owned();
        let mut cache = HashMap::new();

        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(
            compute_cached_sha256(&exe, &mut cache).as_deref(),
            Some(expected)
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(
            compute_cached_sha256(&exe, &mut cache).as_deref(),
            Some(expected)
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn lineage_handles_cycles_without_infinite_loop() {
        let mut index = HashMap::new();
        index.insert(10, (Some(20), "child"));
        index.insert(20, (Some(10), "parent"));
        let chain = build_lineage(10, Some(20), "child", &index);
        assert_eq!(chain, vec!["parent(20)", "child(10)"]);
    }
}
