# safe_door_scanner

Cross-platform (Linux and Windows) network socket monitor, port scanner, and local host security auditor written in Rust.

It inspects active TCP/UDP sockets, maps them to processes and parent process chains, hashes network-facing binaries, and checks for common backdoor indicators and persistence mechanisms.

## Features

- **Socket & Port Inspection**: Lists TCP/UDP (IPv4 and IPv6) sockets, connection states, exposure scope (`127.0.0.1`, LAN, `0.0.0.0`/`::`), owning PID, command line, parent process chain, SHA-256 binary digest, and background reverse DNS lookups.
- **Process & Socket Heuristics**:
  - `H01`: Interactive shells (`sh`, `bash`, `cmd.exe`, `powershell`) or socket relays (`nc`, `ncat`, `socat`) directly bound to network sockets, plus inline scripting reverse shells.
  - `H02`: Binaries executing from temporary or world-writable directories (`/tmp`, `/var/tmp`, `/dev/shm`, `%TEMP%`, `Users\Public`, `$Recycle.Bin`).
  - `H03`: Processes running from unlinked/deleted binaries on disk or `memfd` descriptors.
  - `H04`: System process path spoofing (`svchost.exe`, `lsass.exe`, `csrss.exe` outside `System32`/`SysWOW64`), process name typosquats, and userland binaries spoofing Linux kernel thread names (`[kworker/...]`).
  - `H05`: Connections or listeners on common backdoor, RAT, C2, or mining ports (`4444`, `31337`, `1337`, `5555`, `2375`, `6666-6669`, `3333`, `14444`).
  - `H06`: Sensitive services (SMB, RDP, Telnet, Redis, MySQL, PostgreSQL, MongoDB, Docker API, VNC) bound to `0.0.0.0`/`::`, and web/database servers spawning command shells.
  - `H07`: Encoded PowerShell commands (`-EncodedCommand`), download cradles (`IEX`/`DownloadString`), `/dev/tcp` redirections, and LOLBin remote script execution (`mshta`, `regsvr32`, `rundll32`).
- **Host & Persistence Audit**:
  - **Windows**: Windows Defender Firewall profile status (Domain, Private, Public), Registry `Run`/`RunOnce` keys, `Winlogon\Shell`, and Startup folders.
  - **Linux**: `ufw`/`nftables`/`iptables` status, `/etc/ld.so.preload`, `/etc/crontab`, `/etc/rc.local`, `/etc/systemd/system/*.service`, and `/etc/ssh/sshd_config`.
  - **Cross-platform**: `hosts` file inspection for security or update domain overrides.

## Build

Requires a standard Rust toolchain (`cargo`):

```bash
cargo build --release
```

The compiled binary is placed at `target/release/safe_door_scanner` (or `target\release\safe_door_scanner.exe` on Windows).

Run with elevated privileges (`sudo` on Linux or Administrator terminal on Windows) for full kernel socket-to-PID mapping and system binary inspection.

## Usage

Launch the interactive TUI (default):

```bash
safe_door_scanner
```

Run a one-shot CLI scan:

```bash
# Summary output in terminal
safe_door_scanner --cli

# Show only flagged connections
safe_door_scanner --cli --flagged

# Export Markdown and JSON reports
safe_door_scanner --cli --export-md report.md --export-json report.json

# Print raw JSON to stdout
safe_door_scanner --json
```

In CLI mode, the process exits with code `2` if any `CRITICAL` findings are detected.

## TUI Keybindings

| Key | Action |
| :--- | :--- |
| `1` - `5`, `Tab`, `Shift+Tab` | Switch tabs (Overview, Connections, Findings, OS Audit, Processes) |
| `Up` / `Down`, `j` / `k` | Move selection |
| `PgUp` / `PgDn` | Move selection by 10 rows |
| `f` | Cycle connection filter (All, Listening, Established, Public IP, Flagged) |
| `s` | Cycle connection sort order (Risk, Port, Process, State, PID) |
| `/` | Filter current table by search string |
| `r` | Trigger immediate scan |
| `a` | Cycle auto-refresh interval (`3s`, `10s`, `Paused`) |
| `e` | Export `safe_door_report.json` and `safe_door_report.md` |
| `Enter`, `d` | Toggle detail modal for selected row |
| `?`, `h` | Toggle help modal |
| `q`, `Esc` | Close modal, clear search, or quit |

## License

MIT
