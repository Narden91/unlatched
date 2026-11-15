use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Rejects empty, Windows UNC (`\\server\share`, `\\?\UNC\`), and device (`\\.\`) paths so an
/// elevated scan never initiates outbound SMB authentication (leaking Admin Net-NTLMv2 hashes)
/// or blocks on named pipes / device nodes.
#[must_use]
pub fn is_local_safe_path(path: &Path) -> bool {
    let raw = path.as_os_str().to_string_lossy();
    if raw.is_empty() {
        return false;
    }

    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        // Allow verbatim local drive paths like `\\?\C:\Windows\...`, reject `\\?\UNC\...` and others.
        let bytes = rest.as_bytes();
        return bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/');
    }

    if raw.starts_with(r"\\") || raw.starts_with("//") {
        return false;
    }

    true
}

/// Opens a regular local file without following symlinks, NTFS junctions, FIFOs, or device nodes,
/// verifying metadata directly on the opened handle (`fstat`) to eliminate TOCTOU races.
pub fn open_regular_nofollow(path: &Path) -> Option<(File, Metadata)> {
    if !is_local_safe_path(path) {
        return None;
    }

    let link_meta = fs::symlink_metadata(path).ok()?;
    if link_meta.file_type().is_symlink() || !link_meta.file_type().is_file() {
        return None;
    }

    let mut opts = OpenOptions::new();
    opts.read(true);

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = opts.open(path).ok()?;
    let handle_meta = file.metadata().ok()?;
    if handle_meta.file_type().is_symlink() || !handle_meta.file_type().is_file() {
        return None;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if (handle_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return None;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (link_meta.dev(), link_meta.ino()) != (handle_meta.dev(), handle_meta.ino()) {
            return None;
        }
    }

    Some((file, handle_meta))
}

/// Reads at most `max_bytes` from a verified local regular file. Returns `None` if the file
/// exceeds `max_bytes` (including files that grow during the read).
pub fn read_bounded_bytes(path: &Path, max_bytes: u64) -> Option<(Vec<u8>, Metadata)> {
    let (file, meta) = open_regular_nofollow(path)?;
    let len = meta.len();
    if len > max_bytes {
        return None;
    }

    let cap = usize::try_from(len.min(max_bytes)).ok()?;
    let mut buf = Vec::with_capacity(cap);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() as u64 > max_bytes {
        return None;
    }
    Some((buf, meta))
}

/// Reads a UTF-8 string up to `max_bytes` from a verified regular local file.
pub fn read_bounded_string(path: &Path, max_bytes: u64) -> Result<String, String> {
    if !is_local_safe_path(path) {
        return Err(format!("{}: rejected non-local or UNC path", path.display()));
    }
    let link_meta =
        fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if link_meta.file_type().is_symlink() || !link_meta.file_type().is_file() {
        return Err(format!(
            "{}: refused symlink or non-regular file",
            path.display()
        ));
    }
    if link_meta.len() > max_bytes {
        return Err(format!(
            "{}: file exceeds safety limit ({} > {} bytes)",
            path.display(),
            link_meta.len(),
            max_bytes
        ));
    }

    let (bytes, _) = read_bounded_bytes(path, max_bytes)
        .ok_or_else(|| format!("{}: failed safe bounded read", path.display()))?;
    String::from_utf8(bytes).map_err(|e| format!("{}: invalid UTF-8 ({e})", path.display()))
}

/// Reads a bounded slice at `[offset .. offset + max_len]` from an already-verified local file.
pub fn read_bounded_slice(path: &Path, offset: u64, max_len: usize) -> Option<Vec<u8>> {
    let (mut file, meta) = open_regular_nofollow(path)?;
    if offset >= meta.len() {
        return None;
    }
    file.seek(SeekFrom::Start(offset)).ok()?;
    let to_read = ((meta.len() - offset) as usize).min(max_len);
    let mut buf = Vec::with_capacity(to_read);
    file.take(to_read as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unc_and_device_paths_allows_local() {
        assert!(!is_local_safe_path(Path::new("")));
        assert!(!is_local_safe_path(Path::new(r"\\192.168.1.9\share\evil.exe")));
        assert!(!is_local_safe_path(Path::new(r"\\?\UNC\evil\share\a.exe")));
        assert!(!is_local_safe_path(Path::new(r"\\.\pipe\named")));
        assert!(!is_local_safe_path(Path::new("//evil/share/payload")));

        assert!(is_local_safe_path(Path::new(r"C:\Windows\System32\cmd.exe")));
        assert!(is_local_safe_path(Path::new(r"\\?\C:\Windows\System32\cmd.exe")));
        assert!(is_local_safe_path(Path::new("/usr/bin/bash")));
    }

    #[test]
    fn bounded_read_enforces_limit_and_rejects_symlinks() {
        let dir = std::env::temp_dir().join(format!("unlatched_fssafe_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let file_path = dir.join("sample.txt");
        fs::write(&file_path, b"hello world").unwrap();
        assert_eq!(
            read_bounded_string(&file_path, 64).unwrap(),
            "hello world"
        );
        assert!(read_bounded_string(&file_path, 5).is_err());

        let link_path = dir.join("sample_link.txt");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&file_path, &link_path);
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&file_path, &link_path);
        if linked.is_ok() {
            assert!(open_regular_nofollow(&link_path).is_none());
            assert!(read_bounded_string(&link_path, 64).is_err());
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
