use crate::models::{ProcessRecord, Severity};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

const MAX_HASH_FILE_SIZE: u64 = 20 * 1024 * 1024;
const MAX_LINEAGE_DEPTH: usize = 6;

#[derive(Clone)]
pub struct CachedHash {
    pub file_len: u64,
    pub modified: Option<SystemTime>,
    pub sha256: Option<String>,
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
        .with_cmd(UpdateKind::OnlyIfNotSet)
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
            proc_info
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        };

        let user = proc_info
            .user_id()
            .and_then(|uid| users.get_user_by_id(uid))
            .map(|u| u.name().to_string())
            .unwrap_or_else(|| "SYSTEM".to_string());

        let is_deleted_binary = is_unlinked_binary(pid_u32, &exe_path);
        let exe_exists_on_disk = !exe_path.is_empty()
            && Path::new(exe_path.trim_end_matches(" (deleted)")).exists();

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

    let parent_index: HashMap<u32, (Option<u32>, String)> = records
        .iter()
        .map(|(&pid, rec)| (pid, (rec.ppid, rec.name.clone())))
        .collect();

    for rec in records.values_mut() {
        rec.lineage = build_lineage(rec.pid, rec.ppid, &rec.name, &parent_index);
    }

    records
}

fn build_lineage(
    pid: u32,
    mut curr_ppid: Option<u32>,
    name: &str,
    parent_index: &HashMap<u32, (Option<u32>, String)>,
) -> Vec<String> {
    let mut chain = Vec::with_capacity(MAX_LINEAGE_DEPTH + 1);
    let mut visited = HashSet::new();
    visited.insert(pid);
    chain.push(format!("{}({})", name, pid));

    let mut depth = 0;
    while let Some(p) = curr_ppid {
        if p == 0 || !visited.insert(p) || depth >= MAX_LINEAGE_DEPTH {
            break;
        }
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

pub fn enrich_sha256_hashes(
    processes: &mut HashMap<u32, ProcessRecord>,
    hash_cache: &mut HashMap<String, CachedHash>,
) {
    for rec in processes.values_mut() {
        if rec.exe_exists_on_disk
            && !rec.exe_path.is_empty()
            && (rec.open_sockets_count > 0 || rec.max_severity > Severity::Safe)
        {
            rec.sha256 = compute_cached_sha256(&rec.exe_path, hash_cache);
        }
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
        if let Ok(link) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
            let target = link.to_string_lossy();
            if target.ends_with(" (deleted)") || target.contains("memfd:") {
                return true;
            }
        }
    }
    false
}

pub fn compute_cached_sha256(
    exe_path: &str,
    cache: &mut HashMap<String, CachedHash>,
) -> Option<String> {
    let path = Path::new(exe_path);
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }

    let file_len = meta.len();
    if file_len == 0 || file_len > MAX_HASH_FILE_SIZE {
        return None;
    }
    let modified = meta.modified().ok();

    if let Some(entry) = cache.get(exe_path) {
        if entry.file_len == file_len && entry.modified == modified {
            return entry.sha256.clone();
        }
    }

    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    // sha2 0.11 digests no longer implement LowerHex.
    let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();

    cache.insert(
        exe_path.to_string(),
        CachedHash {
            file_len,
            modified,
            sha256: Some(digest.clone()),
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
        assert_eq!(compute_cached_sha256(&exe, &mut cache).as_deref(), Some(expected));
        assert_eq!(cache.len(), 1);
        assert_eq!(compute_cached_sha256(&exe, &mut cache).as_deref(), Some(expected));
        std::fs::remove_file(&path).unwrap();
    }
}
