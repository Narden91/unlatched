# Unlatched

[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Windows 11](https://img.shields.io/badge/Windows%2011-tested-0078D6?logo=windows&logoColor=white)](#install)
[![Linux](https://img.shields.io/badge/Linux%20(WSL)-tested-FCC624?logo=linux&logoColor=black)](#install)

Unlatched inspects which process owns every TCP and UDP socket on the local host. It correlates sockets with process ancestry, on-disk SHA-256 digests, PE `VS_VERSION_INFO` version metadata, transitive reverse-proxy exposure paths, temporal C2 beaconing intervals, and host persistence surfaces.

It runs locally on the endpoint being inspected. It never scans remote hosts.

![Unlatched overview](docs/assets/tui-overview.svg)

## Status

- **Windows 11:** tested.
- **Linux:** tested on WSL (Windows Subsystem for Linux). Reports from other distributions are welcome.
- **macOS:** not supported.

## What it checks

Each connection maps to its owning process ID (PID), parent lineage chain, command line, executable SHA-256 digest, PE `OriginalFilename` (on Windows), exposure scope, and validated reverse-DNS hostname.

| ID | What it flags |
| :--- | :--- |
| `H01` | Interactive shells (`cmd`, PowerShell, `bash`, `sh`) or raw relays (`nc`, `ncat`, `socat`) holding sockets, including inline interpreter reverse shells and renamed shell binaries. |
| `H02` | Processes executing from temporary, shared-memory, or world-writable paths (`/tmp`, `/dev/shm`, `%TEMP%`, `Users\Public`, Recycle Bin). |
| `H03` | Processes executing from unlinked/deleted binaries or `memfd:` memory descriptors. |
| `H04` | System process masquerading: path spoofing (including `System32` subdirectories), typosquats, fake Linux kernel threads, and **copied/renamed PE utilities & LOLBins** (`H04-RENAMED-BINARY`, e.g. `powershell.exe` renamed to `updater.exe`). |
| `H05` | Listeners or outbound connections on ports commonly associated with RATs, C2 frameworks, or mining pools (`4444`, `31337`, `1337`, `5555`, `2375`, etc.). |
| `H06` | Sensitive services bound to `0.0.0.0`/`::` and shells spawned anywhere under a web or database server ancestor chain. |
| `H07` | Encoded PowerShell flags (`-e`/`-enc`/`-encodedcommand`), download cradles, `/dev/tcp`, `curl \| sh`, and Windows LOLBin scriptlet execution. |
| `H08` | **Transitive Loopback-Proxy Exposure** (`PROXY-EXP`): services bound to `127.0.0.1`/`[::1]` that are actively bridged by a local process listening on `0.0.0.0`/`::`, LAN, or a public IP. |
| `H09` | **Statistical C2 Beaconing**: periodic low-jitter outbound callback flows detected across live/watch scans using Welford's online variance ($n \ge 4$ intervals, $CV = s/\mu \le 0.20$). |

**Windows host audit:** Defender Firewall profile states (including Group Policy overrides), Registry `Run`/`RunOnce` keys, Registry-resolved `Startup` folders, and Winlogon `Shell` + `Userinit` helpers.

**Linux host audit:** `ufw`/netfilter state, `/etc/ld.so.preload`, `/etc/crontab`, `/etc/cron.d/*`, `/etc/rc.local`, `sshd_config` (`PermitRootLogin`, `PermitEmptyPasswords`), and systemd `ExecStart` units.

**Hosts file audit:** Redirects of OS update or antivirus domains to external IPs are flagged as `Critical`; `0.0.0.0`/loopback blocklist sinkholes are aggregated into a single `Warning`/`Medium` item.

## Install

### Windows

Install Rust (`>= 1.94`) via [rustup](https://rustup.rs/) with the MSVC toolchain:

```powershell
git clone https://github.com/Narden91/unlatched.git
cd unlatched
cargo build --release
```

The binary is built at `target\release\safe_door_scanner.exe`.

### Linux

```bash
git clone https://github.com/Narden91/unlatched.git
cd unlatched
cargo build --release
```

## Command-line mode

| Option | Effect |
| :--- | :--- |
| `--cli` | Print a terminal report and exit |
| `--flagged` | Show only flagged sockets in `--cli` output |
| `--json` | Print the full `ScanSnapshot` as JSON to stdout |
| `--export-md FILE` | Write a sanitized Markdown security report |
| `--export-json FILE` | Write a JSON snapshot report |
| `--export-sarif FILE` | Write an **OASIS SARIF v2.1.0** report for GitHub Security / SIEM ingestion |
| `--diff FILE` | Compare against an earlier `--export-json` baseline (including exposure escalations) |
| `--allowlist FILE` | Suppress findings matching cryptographic 64-hex SHA-256 rules in `FILE` |
| `--watch SECS` | Continuous headless flight-recorder & C2 beacon monitor polling every `SECS` seconds |
| `--watch-cycles N` | Exit `--watch` mode after `N` scan cycles |

```powershell
# One-shot flagged triage + SARIF v2.1.0 export
.\target\release\safe_door_scanner.exe --cli --flagged --export-sarif results.sarif.json

# Headless 5-second watch mode with SHA-256 allowlist
.\target\release\safe_door_scanner.exe --watch 5 --allowlist safe_door_allowlist.json
```

Exit code is `2` whenever at least one un-suppressed `Critical` finding is present, and `0` otherwise.

## Keys in the TUI

| Key | Action |
| :--- | :--- |
| `1` to `6`, `Tab`, `Shift+Tab` | Switch views: Overview, Connections, Findings, Audit, Processes, **Events** |
| `Up` / `Down`, `j` / `k`, `PgUp` / `PgDn` | Navigate table rows |
| `f` | Cycle connection filter (`All`, `Listening`, `Established`, `Public IP`, `Flagged`) |
| `s` | Cycle connection sort (`Risk`, `Port`, `Process`, `State`, `PID`) |
| `/` | Live substring filter across the active tab |
| `w` | Add the selected binary's **SHA-256** digest to `safe_door_allowlist.json` |
| `r` | Trigger an immediate background scan |
| `a` | Cycle auto-refresh (`3s`, `10s`, `Paused`) |
| `e` | Export `safe_door_report.json`, `safe_door_report.md`, and `safe_door_report.sarif.json` |
| `Enter`, `d` | Open full row inspector modal |
| `?`, `h` | Open keyboard and heuristic reference modal |
| `q`, `Esc` | Close modal, clear search, or quit |

## Running with admin rights safely

Copy the release binary into an administrator-owned directory (`C:\Program Files\Unlatched\` on Windows, `/usr/local/bin/` on Linux) before running elevated. Self-protection controls built into the scanner:

- **No outbound SMB / symlink traversal:** All file reads reject Windows UNC/device paths (`\\server\share`, `\\.\`), open files with `FILE_FLAG_OPEN_REPARSE_POINT` / inode verification (`lstat == fstat`), and enforce strict byte caps.
- **Hardened child execution & DLL loading:** Windows `build.rs` sets `/DEPENDENTLOADFLAG:0x800` (`LOAD_LIBRARY_SEARCH_SYSTEM32`); reverse-DNS helpers execute by absolute system path with cleared environments and strict hostname character validation.
- **Terminal & Markdown neutralization:** Control characters, ANSI escapes, and Unicode bidi overrides are escaped before TUI, CLI, JSON, SARIF, or Markdown output.
- **Atomic owner-only exports:** Reports verify parent directories are not symlinks or NTFS junctions, write through unpredictable `.tmp` files (`0600` on Unix), and atomically rename into place.
- **Tamper-evident allowlisting:** Allowlist entries require a full 64-hex SHA-256 binary digest; modifying or replacing an allowlisted binary on disk automatically invalidates suppression.

## License

[MIT](LICENSE)
