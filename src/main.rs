mod allowlist;
mod app;
mod baseline;
mod flight;
mod models;
mod report;
mod scanner;
mod ui;

use allowlist::Allowlist;
use app::{ActiveTab, App};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use flight::FlightRecorder;
use ratatui::{backend::CrosstermBackend, Terminal};
use report::{
    export_json_report, export_markdown_report, export_sarif_report, print_cli_summary,
    print_wifi_shield_cli,
};
use scanner::wifi_shield::export_wifi_lockdown_script;
use scanner::ScannerEngine;
use std::io;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "safe_door_scanner",
    version,
    about = "Unlatched: local socket, process provenance, and host persistence inspector"
)]
struct CliArgs {
    /// Run a one-shot scan in the terminal instead of launching the TUI
    #[arg(short, long)]
    cli: bool,

    /// Print scan results as JSON to stdout
    #[arg(short, long)]
    json: bool,

    /// Show only flagged network connections in CLI mode
    #[arg(short, long)]
    flagged: bool,

    /// Write a Markdown security report to the given path
    #[arg(long, value_name = "FILE")]
    export_md: Option<PathBuf>,

    /// Write a JSON security report to the given path
    #[arg(long, value_name = "FILE")]
    export_json: Option<PathBuf>,

    /// Write an OASIS SARIF v2.1.0 security report to the given path
    #[arg(long, value_name = "FILE")]
    export_sarif: Option<PathBuf>,

    /// Compare this scan with a JSON file from an earlier --export-json and list what changed
    #[arg(long, value_name = "FILE")]
    diff: Option<PathBuf>,

    /// Load cryptographic SHA-256 finding suppression rules from JSON file
    #[arg(long, value_name = "FILE")]
    allowlist: Option<PathBuf>,

    /// Run continuous headless socket flight-recorder & C2 beacon watch every SECS seconds
    #[arg(long, value_name = "SECS")]
    watch: Option<u64>,

    /// Stop headless --watch mode after N scan cycles (default: run until interrupted)
    #[arg(long, value_name = "N")]
    watch_cycles: Option<usize>,

    /// Run a focused Zero-Trust Public Wi-Fi & MitM Link Radar terminal check
    #[arg(long)]
    wifi_shield: bool,

    /// Export a rollback-capable, 7-bit ASCII Zero-Trust Public Wi-Fi Lockdown Script (.ps1 / .sh)
    #[arg(long, value_name = "FILE")]
    export_lockdown: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    // Fail on a bad baseline or allowlist before running the scan.
    let old_snapshot = args.diff.as_deref().map(baseline::load).transpose()?;
    let allowlist_path = args
        .allowlist
        .clone()
        .unwrap_or_else(|| PathBuf::from("safe_door_allowlist.json"));
    let allowlist = match &args.allowlist {
        Some(path) => Allowlist::load(path)?,
        None => Allowlist::load_if_exists(&allowlist_path)?,
    };

    if let Some(interval_secs) = args.watch {
        return run_watch_mode(&args, &allowlist, interval_secs.max(1));
    }

    let one_shot = args.cli
        || args.wifi_shield
        || args.json
        || args.export_md.is_some()
        || args.export_json.is_some()
        || args.export_sarif.is_some()
        || args.export_lockdown.is_some()
        || args.diff.is_some();

    let mut engine = ScannerEngine::new();
    let mut snapshot = engine.perform_scan();
    if one_shot {
        engine.refresh_hostnames(&mut snapshot, Duration::from_secs(2));
    }
    allowlist.apply(&mut snapshot);

    let diff = old_snapshot
        .as_ref()
        .map(|old| baseline::diff_snapshots(old, &snapshot));

    write_requested_exports(&args, &snapshot)?;

    if !one_shot {
        return run_tui(engine, snapshot, allowlist, allowlist_path);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        // stdout carries the JSON, so the diff goes to stderr.
        if let Some(d) = &diff {
            eprintln!("{}", d.render());
        }
    } else {
        if args.cli {
            print_cli_summary(&snapshot, args.flagged);
        }
        if args.wifi_shield {
            print_wifi_shield_cli(&snapshot);
        }
        if let Some(d) = &diff {
            println!("{}", d.render());
        }
    }

    if snapshot.critical_count > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn write_requested_exports(
    args: &CliArgs,
    snapshot: &models::ScanSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(md_path) = &args.export_md {
        export_markdown_report(snapshot, md_path)?;
        if !args.json {
            eprintln!("Saved Markdown report: {}", md_path.display());
        }
    }
    if let Some(json_path) = &args.export_json {
        export_json_report(snapshot, json_path)?;
        if !args.json {
            eprintln!("Saved JSON report: {}", json_path.display());
        }
    }
    if let Some(sarif_path) = &args.export_sarif {
        export_sarif_report(snapshot, sarif_path)?;
        if !args.json {
            eprintln!("Saved SARIF v2.1.0 report: {}", sarif_path.display());
        }
    }
    if let Some(lockdown_path) = &args.export_lockdown {
        export_wifi_lockdown_script(
            &snapshot.connections,
            snapshot.wifi_shield.as_ref(),
            lockdown_path,
        )?;
        if !args.json {
            eprintln!(
                "Saved Zero-Trust Wi-Fi Lockdown Script: {}",
                lockdown_path.display()
            );
        }
    }
    Ok(())
}

fn run_watch_mode(
    args: &CliArgs,
    allowlist: &Allowlist,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = ScannerEngine::new();
    let mut recorder = FlightRecorder::new();
    let mut cycle = 0usize;
    let mut saw_critical = false;

    loop {
        cycle += 1;
        let mut snapshot = engine.perform_scan();
        let delta = recorder.observe(&mut snapshot);
        allowlist.apply(&mut snapshot);
        saw_critical |= snapshot.critical_count > 0;

        if args.json {
            println!("{}", serde_json::to_string(&snapshot)?);
        } else {
            println!(
                "[{}] cycle #{} | score {}/100 ({}) | sockets {} | findings {} (crit {}) | delta events {}",
                snapshot.timestamp.format("%H:%M:%S"),
                cycle,
                snapshot.security_score,
                snapshot.security_grade,
                snapshot.total_connections,
                snapshot.findings.len(),
                snapshot.critical_count,
                delta.len()
            );
            for ev in &delta {
                let pid_label = ev.pid.map_or_else(|| "-".to_string(), |p| p.to_string());
                println!(
                    "  {} {:<8} {:<8} {} (PID {}) -> {}",
                    ev.timestamp.format("%H:%M:%S"),
                    ev.severity.label(),
                    ev.kind.label(),
                    ev.process_name,
                    pid_label,
                    ev.summary
                );
            }
        }

        if args.watch_cycles.is_some_and(|max_c| cycle >= max_c) {
            write_requested_exports(args, &snapshot)?;
            break;
        }

        thread::sleep(Duration::from_secs(interval_secs));
    }

    if saw_critical {
        std::process::exit(2);
    }
    Ok(())
}

fn run_tui(
    engine: ScannerEngine,
    initial_snapshot: models::ScanSnapshot,
    allowlist: Allowlist,
    allowlist_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // try_init installs a panic hook that restores the terminal, so a panic does not leave raw mode on.
    let mut terminal = ratatui::try_init()?;
    let mut app = App::with_options(engine, initial_snapshot, allowlist, allowlist_path);
    let res = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    res
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        if app.take_redraw() {
            terminal.draw(|f| ui::render(f, app))?;
        }

        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Resize(_, _) => {
                    app.mark_redraw();
                }
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        return Ok(());
                    }
                    if handle_key_press(app, key.code) {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }

        app.on_tick();
    }
}

/// Returns `true` when the user requested application exit.
fn handle_key_press(app: &mut App, code: KeyCode) -> bool {
    if app.is_searching {
        match code {
            KeyCode::Enter => {
                app.is_searching = false;
                app.rebuild_views();
            }
            KeyCode::Esc => {
                app.search_query.clear();
                app.is_searching = false;
                app.rebuild_views();
            }
            KeyCode::Backspace => {
                app.search_query.pop();
                app.rebuild_views();
            }
            KeyCode::Char(c) => {
                app.search_query.push(c);
                app.rebuild_views();
            }
            _ => {}
        }
        return false;
    }

    if app.show_help_modal {
        if matches!(
            code,
            KeyCode::Esc
                | KeyCode::Enter
                | KeyCode::Char('?')
                | KeyCode::Char('h')
                | KeyCode::Char('q')
        ) {
            app.show_help_modal = false;
            app.mark_redraw();
        }
        return false;
    }

    if app.show_detail_modal {
        if matches!(
            code,
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('d') | KeyCode::Char('q')
        ) {
            app.show_detail_modal = false;
            app.mark_redraw();
        }
        return false;
    }

    match code {
        KeyCode::Char('q') => return true,
        KeyCode::Esc => {
            if !app.search_query.is_empty() {
                app.search_query.clear();
                app.rebuild_views();
            } else {
                return true;
            }
        }
        KeyCode::Char('1') => {
            app.active_tab = ActiveTab::Overview;
            app.mark_redraw();
        }
        KeyCode::Char('2') => {
            app.active_tab = ActiveTab::Connections;
            app.mark_redraw();
        }
        KeyCode::Char('3') => {
            app.active_tab = ActiveTab::Findings;
            app.mark_redraw();
        }
        KeyCode::Char('4') => {
            app.active_tab = ActiveTab::Audit;
            app.mark_redraw();
        }
        KeyCode::Char('5') => {
            app.active_tab = ActiveTab::Processes;
            app.mark_redraw();
        }
        KeyCode::Char('6') => {
            app.active_tab = ActiveTab::Events;
            app.mark_redraw();
        }
        KeyCode::Char('7') => {
            app.active_tab = ActiveTab::WifiShield;
            app.mark_redraw();
        }
        KeyCode::Tab | KeyCode::Right => {
            app.active_tab = app.active_tab.next();
            app.mark_redraw();
        }
        KeyCode::BackTab | KeyCode::Left => {
            app.active_tab = app.active_tab.prev();
            app.mark_redraw();
        }
        KeyCode::Down | KeyCode::Char('j') => app.move_selection_down(1),
        KeyCode::Up | KeyCode::Char('k') => app.move_selection_up(1),
        KeyCode::PageDown => app.move_selection_down(10),
        KeyCode::PageUp => app.move_selection_up(10),
        KeyCode::Char('/') => {
            app.is_searching = true;
            app.mark_redraw();
        }
        KeyCode::Char('f') => {
            app.conn_filter = app.conn_filter.next();
            app.active_tab = ActiveTab::Connections;
            app.rebuild_views();
            app.set_status(format!("Filter: {}", app.conn_filter.label()));
        }
        KeyCode::Char('s') => {
            app.conn_sort = app.conn_sort.next();
            app.active_tab = ActiveTab::Connections;
            app.rebuild_views();
            app.set_status(format!("Sort: {}", app.conn_sort.label()));
        }
        KeyCode::Char('r') => {
            if app.is_scanning() {
                app.set_status("Scan already running");
            } else {
                app.trigger_scan();
                app.set_status("Scanning...");
            }
        }
        KeyCode::Char('a') => {
            app.refresh_mode = app.refresh_mode.next();
            app.set_status(format!("Refresh: {}", app.refresh_mode.label()));
        }
        KeyCode::Char('e') => {
            app.export_reports_now();
        }
        KeyCode::Char('w') => {
            app.allowlist_selected();
        }
        KeyCode::Char('l') | KeyCode::Char('L') => {
            app.export_wifi_lockdown();
        }
        KeyCode::Enter | KeyCode::Char('d') => {
            if app.active_tab == ActiveTab::Overview {
                app.active_tab = ActiveTab::Connections;
            } else {
                app.show_detail_modal = true;
            }
            app.mark_redraw();
        }
        KeyCode::Char('?') | KeyCode::Char('h') => {
            app.show_help_modal = true;
            app.mark_redraw();
        }
        _ => {}
    }
    false
}
