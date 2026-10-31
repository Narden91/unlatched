# Unlatched

[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Windows](https://img.shields.io/badge/Windows-ok-0078D6?logo=windows&logoColor=white)](#windows)
[![Linux](https://img.shields.io/badge/Linux-ok-FCC624?logo=linux&logoColor=black)](#linux)

Local socket inspector for Linux and Windows. It maps every TCP/UDP socket on this machine to the process that owns it, then flags shells on sockets, binaries in temp dirs, wildcard binds, and a short list of persistence tricks.

The crate/binary is still `safe_door_scanner`.

![Unlatched overview](docs/assets/tui-overview.svg)

You run it on the host you want to look at. It does not scan other machines. The score in the header is a heuristic; it is not an audit report.

## Rules

Each socket row has state, exposure (`127.0.0.1`, LAN, `0.0.0.0`/`::`), PID, command line, parent chain, SHA-256 of the on-disk binary, and a reverse DNS lookup in the background.

| ID | Trips when |
| :--- | :--- |
| `H01` | Interactive shells (`sh`, `bash`, `cmd.exe`, `powershell`) or relays (`nc`, `ncat`, `socat`) own a socket; also inline scripting reverse shells |
| `H02` | Binary runs from `/tmp`, `/var/tmp`, `/dev/shm`, `%TEMP%`, `Users\Public`, or `$Recycle.Bin` |
| `H03` | Process image is unlinked, or backed by `memfd` |
| `H04` | `svchost.exe` / `lsass.exe` / `csrss.exe` outside `System32`/`SysWOW64`; typosquats; userland binaries posing as `[kworker/...]` |
| `H05` | Traffic on common C2/RAT/miner ports (`4444`, `31337`, `1337`, `5555`, `2375`, `6666-6669`, `3333`, `14444`) |
| `H06` | SMB, RDP, Telnet, Redis, MySQL, PostgreSQL, MongoDB, Docker API, or VNC bound to `0.0.0.0`/`::`; web/database servers spawning shells |
| `H07` | Encoded PowerShell, `IEX`/`DownloadString` cradles, `/dev/tcp`, `mshta` / `regsvr32` / `rundll32` |

`H05` keys off the port number. Something legitimate on `4444` will still light up, so read the process path before you kill it.

Both OSes also read the `hosts` file for redirects of update or AV domains.

## Windows

Install Rust via [rustup](https://rustup.rs/) with the MSVC toolchain (Visual Studio C++ build tools). Then:

```powershell
git clone https://github.com/Narden91/unlatched.git
cd unlatched
cargo build --release
```

Binary: `target\release\safe_door_scanner.exe`

Use an Administrator terminal for kernel socket-to-PID mapping, hashes of system binaries, HKLM Run keys, and Defender Firewall profiles. A normal user session still runs; some PIDs come back empty and some audit rows are skipped.

```powershell
.\target\release\safe_door_scanner.exe
.\target\release\safe_door_scanner.exe --cli
.\target\release\safe_door_scanner.exe --cli --flagged
.\target\release\safe_door_scanner.exe --cli --export-md unlatched.md --export-json unlatched.json
.\target\release\safe_door_scanner.exe --json
```

What Windows audit actually opens: Domain/Private/Public firewall `EnableFirewall` values, `Run`/`RunOnce` (HKCU, HKLM, WOW6432Node), `Winlogon\Shell` (anything other than `explorer.exe` is critical), user + common Startup folders, and `C:\Windows\System32\drivers\etc\hosts`.

## Linux

`rustc`/`cargo` from rustup or the distro. No extra C libs.

```bash
git clone https://github.com/Narden91/unlatched.git
cd unlatched
cargo build --release
sudo ./target/release/safe_door_scanner
```

Root is required for `/proc` owners, `/etc/ld.so.preload`, crontab, sshd, and systemd units. Same flags as Windows (`--cli`, `--flagged`, `--export-md`, `--export-json`, `--json`).

Linux audit reads UFW/`nf_tables`, `/etc/ld.so.preload`, `/etc/crontab`, `/etc/rc.local`, `PermitRootLogin`/`PermitEmptyPasswords` in `sshd_config`, `ExecStart=` on `/etc/systemd/system/*.service`, and `/etc/hosts`.

macOS is out.

## TUI

No flags. Tabs are Overview, Connections, Findings, Audit, Processes.

| Key | Action |
| :--- | :--- |
| `1`–`5`, `Tab`, `Shift+Tab` | Switch tabs |
| `Up` / `Down`, `j` / `k` | Move selection |
| `PgUp` / `PgDn` | Jump 10 rows |
| `f` | Filter connections (All, Listening, Established, Public IP, Flagged) |
| `s` | Sort (Risk, Port, Process, State, PID) |
| `/` | Search the current table |
| `r` | Scan now |
| `a` | Auto-refresh `3s` / `10s` / Paused |
| `e` | Write `safe_door_report.json` and `safe_door_report.md` |
| `Enter`, `d` | Detail |
| `?`, `h` | Help |
| `q`, `Esc` | Close modal, clear search, or quit |

## CLI

`--cli` prints a summary and exits. Add `--flagged` to hide clean sockets. `--json` dumps the snapshot.

Exit `2` if anything `CRITICAL` showed up. Exit `0` only means no critical hits; high/medium/low can still be in the report.

## Limits

These are heuristics, not malware signatures. Rename the binary and skip `H01`–`H07` and the scan will look quiet on a box that is already owned. Firewall checks read registry or `/etc`; they don't prove packets are being dropped.

## License

[MIT](LICENSE)
