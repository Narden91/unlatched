mod app;
mod baseline;
mod models;
mod report;
mod scanner;
mod ui;

use app::{ActiveTab, App};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{backend::CrosstermBackend, Terminal};
use report::{export_json_report, export_markdown_report, print_cli_summary};
use scanner::ScannerEngine;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "safe_door_scanner",
    version,
    about = "Unlatched: local socket inspector"
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

    /// Compare this scan with a JSON file from an earlier --export-json and list what changed
    #[arg(long, value_name = "FILE")]
    diff: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    let one_shot = args.cli
        || args.json
        || args.export_md.is_some()
        || args.export_json.is_some()
        || args.diff.is_some();

    // Fail on a bad baseline before the scan, not after.
    let old_snapshot = args.diff.as_deref().map(baseline::load).transpose()?;

    let mut engine = ScannerEngine::new();
    let mut snapshot = engine.perform_scan();
    if one_shot {
        engine.refresh_hostnames(&mut snapshot, Duration::from_secs(2));
    }
    let diff = old_snapshot
        .as_ref()
        .map(|old| baseline::diff_snapshots(old, &snapshot));

    if let Some(md_path) = &args.export_md {
        export_markdown_report(&snapshot, md_path)?;
        if !args.json {
            eprintln!("Saved Markdown report: {}", md_path.display());
        }
    }

    if let Some(json_path) = &args.export_json {
        export_json_report(&snapshot, json_path)?;
        if !args.json {
            eprintln!("Saved JSON report: {}", json_path.display());
        }
    }

    if !one_shot {
        return run_tui(engine, snapshot);
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
        if let Some(d) = &diff {
            println!("{}", d.render());
        }
    }

    if snapshot.critical_count > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn run_tui(
    engine: ScannerEngine,
    initial_snapshot: models::ScanSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    // try_init installs a panic hook that restores the terminal, so a panic does not leave raw mode on.
    let mut terminal = ratatui::try_init()?;
    let mut app = App::new(engine, initial_snapshot);
    let res = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    res
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|f| ui::render(f, app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
                {
                    return Ok(());
                }

                if app.is_searching {
                    match key.code {
                        KeyCode::Enter => {
                            app.is_searching = false;
                            app.clamp_selections();
                        }
                        KeyCode::Esc => {
                            app.search_query.clear();
                            app.is_searching = false;
                            app.clamp_selections();
                        }
                        KeyCode::Backspace => {
                            app.search_query.pop();
                            app.clamp_selections();
                        }
                        KeyCode::Char(c) => {
                            app.search_query.push(c);
                            app.clamp_selections();
                        }
                        _ => {}
                    }
                    continue;
                }

                if app.show_help_modal {
                    if matches!(
                        key.code,
                        KeyCode::Esc
                            | KeyCode::Enter
                            | KeyCode::Char('?')
                            | KeyCode::Char('h')
                            | KeyCode::Char('q')
                    ) {
                        app.show_help_modal = false;
                    }
                    continue;
                }

                if app.show_detail_modal {
                    if matches!(
                        key.code,
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('d') | KeyCode::Char('q')
                    ) {
                        app.show_detail_modal = false;
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Esc => {
                        if !app.search_query.is_empty() {
                            app.search_query.clear();
                            app.clamp_selections();
                        } else {
                            return Ok(());
                        }
                    }
                    KeyCode::Char('1') => app.active_tab = ActiveTab::Overview,
                    KeyCode::Char('2') => app.active_tab = ActiveTab::Connections,
                    KeyCode::Char('3') => app.active_tab = ActiveTab::Findings,
                    KeyCode::Char('4') => app.active_tab = ActiveTab::Audit,
                    KeyCode::Char('5') => app.active_tab = ActiveTab::Processes,
                    KeyCode::Tab | KeyCode::Right => app.active_tab = app.active_tab.next(),
                    KeyCode::BackTab | KeyCode::Left => app.active_tab = app.active_tab.prev(),
                    KeyCode::Down | KeyCode::Char('j') => app.move_selection_down(1),
                    KeyCode::Up | KeyCode::Char('k') => app.move_selection_up(1),
                    KeyCode::PageDown => app.move_selection_down(10),
                    KeyCode::PageUp => app.move_selection_up(10),
                    KeyCode::Char('/') => {
                        app.is_searching = true;
                    }
                    KeyCode::Char('f') => {
                        app.conn_filter = app.conn_filter.next();
                        app.active_tab = ActiveTab::Connections;
                        app.clamp_selections();
                        app.set_status(format!("Filter: {}", app.conn_filter.label()));
                    }
                    KeyCode::Char('s') => {
                        app.conn_sort = app.conn_sort.next();
                        app.active_tab = ActiveTab::Connections;
                        app.clamp_selections();
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
                    KeyCode::Enter | KeyCode::Char('d') => {
                        if app.active_tab == ActiveTab::Overview {
                            app.active_tab = ActiveTab::Connections;
                        } else {
                            app.show_detail_modal = true;
                        }
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') => {
                        app.show_help_modal = true;
                    }
                    _ => {}
                }
            }
        }

        app.on_tick();
    }
}
