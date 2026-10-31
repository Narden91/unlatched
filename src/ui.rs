use crate::app::{ActiveTab, App};
use crate::models::{AuditStatus, Severity};
use crate::report::truncate_str;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Tabs, Wrap},
    Frame,
};

const COL_CRIT: Color = Color::Rgb(248, 81, 73);
const COL_HIGH: Color = Color::Rgb(245, 158, 11);
const COL_MED: Color = Color::Rgb(210, 153, 34);
const COL_LOW: Color = Color::Rgb(88, 166, 255);
const COL_SAFE: Color = Color::Rgb(16, 185, 129);
const COL_ACCENT: Color = Color::Rgb(16, 185, 129);
const COL_MUTED: Color = Color::Rgb(139, 148, 158);
const COL_HIGHLIGHT_BG: Color = Color::Rgb(26, 29, 32);

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Critical => COL_CRIT,
        Severity::High => COL_HIGH,
        Severity::Medium => COL_MED,
        Severity::Low => COL_LOW,
        Severity::Safe => COL_SAFE,
    }
}

fn audit_status_color(status: AuditStatus) -> Color {
    match status {
        AuditStatus::Critical => COL_CRIT,
        AuditStatus::Warning => COL_HIGH,
        AuditStatus::Info => COL_LOW,
        AuditStatus::Pass => COL_SAFE,
    }
}

pub fn render(frame: &mut Frame, app: &mut App) {
    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(frame.area());

    render_header(frame, app, root_chunks[0]);
    render_tabs(frame, app, root_chunks[1]);

    match app.active_tab {
        ActiveTab::Overview => render_overview_tab(frame, app, root_chunks[2]),
        ActiveTab::Connections => render_connections_tab(frame, app, root_chunks[2]),
        ActiveTab::Findings => render_findings_tab(frame, app, root_chunks[2]),
        ActiveTab::Audit => render_audit_tab(frame, app, root_chunks[2]),
        ActiveTab::Processes => render_processes_tab(frame, app, root_chunks[2]),
    }

    render_footer(frame, app, root_chunks[3]);

    if app.show_detail_modal {
        render_detail_modal(frame, app);
    }
    if app.show_help_modal {
        render_help_modal(frame);
    }
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let snap = &app.snapshot;
    let score_col = match snap.security_score {
        85..=100 => COL_SAFE,
        65..=84 => COL_MED,
        _ => COL_CRIT,
    };

    let priv_badge = if snap.is_elevated {
        Span::styled(
            " [ADMIN/ROOT] ",
            Style::default()
                .fg(Color::Black)
                .bg(COL_SAFE)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " [USER MODE] ",
            Style::default()
                .fg(Color::Black)
                .bg(COL_MED)
                .add_modifier(Modifier::BOLD),
        )
    };

    let line = Line::from(vec![
        Span::styled(
            " UNLATCHED ",
            Style::default()
                .fg(Color::Black)
                .bg(COL_ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        priv_badge,
        Span::styled(
            format!(" Host: {} ({}) ", snap.hostname, snap.os_name),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled("| ", Style::default().fg(COL_MUTED)),
        Span::styled("Score: ", Style::default().fg(COL_MUTED)),
        Span::styled(
            format!("{}/100 [{}] ", snap.security_score, snap.security_grade),
            Style::default().fg(score_col).add_modifier(Modifier::BOLD),
        ),
        Span::styled("| ", Style::default().fg(COL_MUTED)),
        Span::styled(
            format!(
                "Scan: {}ms ({}) @ {}",
                snap.scan_duration_ms,
                app.refresh_mode.label(),
                snap.timestamp.format("%H:%M:%S")
            ),
            Style::default().fg(COL_MUTED),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COL_ACCENT));
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn render_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let snap = &app.snapshot;
    let titles = vec![
        Line::from(Span::styled(
            " [1] Overview ",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::raw(" [2] Connections "),
            Span::styled(
                format!("({}) ", snap.total_connections),
                Style::default().fg(COL_ACCENT),
            ),
        ]),
        Line::from(vec![
            Span::raw(" [3] Findings "),
            Span::styled(
                format!("({}) ", snap.findings.len()),
                Style::default().fg(if snap.findings.is_empty() {
                    COL_SAFE
                } else {
                    COL_CRIT
                }),
            ),
        ]),
        Line::from(vec![
            Span::raw(" [4] Audit "),
            Span::styled(
                format!("({}) ", snap.audit_items.len()),
                Style::default().fg(COL_MED),
            ),
        ]),
        Line::from(vec![
            Span::raw(" [5] Processes "),
            Span::styled(
                format!("({}) ", snap.processes.len()),
                Style::default().fg(COL_MUTED),
            ),
        ]),
    ];

    let right_status = if !app.search_query.is_empty() {
        format!(" Filter: '{}' (Esc to clear) ", app.search_query)
    } else {
        format!(
            " View: {} | Sort: {} ",
            app.conn_filter.label(),
            app.conn_sort.label()
        )
    };

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title_bottom(Line::from(right_status).alignment(Alignment::Right)),
        )
        .select(app.active_tab.index())
        .style(Style::default().fg(COL_MUTED))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(COL_ACCENT)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_widget(tabs, area);
}

fn render_overview_tab(frame: &mut Frame, app: &App, area: Rect) {
    let snap = &app.snapshot;
    let v_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10)])
        .split(area);

    let flagged_col = if snap.suspicious_connections > 0 {
        COL_HIGH
    } else {
        COL_SAFE
    };
    let crit_col = if snap.critical_count > 0 {
        COL_CRIT
    } else {
        COL_MUTED
    };
    let status = Line::from(vec![
        Span::styled(" listen ", Style::default().fg(COL_MUTED)),
        Span::styled(
            snap.listening_ports.to_string(),
            Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  est ", Style::default().fg(COL_MUTED)),
        Span::styled(
            snap.established_connections.to_string(),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  public ", Style::default().fg(COL_MUTED)),
        Span::styled(
            snap.external_connections.to_string(),
            Style::default().fg(COL_MED).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  flagged ", Style::default().fg(COL_MUTED)),
        Span::styled(
            snap.suspicious_connections.to_string(),
            Style::default().fg(flagged_col).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  crit ", Style::default().fg(COL_MUTED)),
        Span::styled(
            snap.critical_count.to_string(),
            Style::default().fg(crit_col).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  high ", Style::default().fg(COL_MUTED)),
        Span::styled(
            snap.high_count.to_string(),
            Style::default().fg(if snap.high_count > 0 {
                COL_HIGH
            } else {
                COL_MUTED
            }),
        ),
        Span::styled("  med ", Style::default().fg(COL_MUTED)),
        Span::styled(snap.medium_count.to_string(), Style::default().fg(COL_MUTED)),
        Span::styled("  low ", Style::default().fg(COL_MUTED)),
        Span::styled(snap.low_count.to_string(), Style::default().fg(COL_MUTED)),
    ]);
    frame.render_widget(
        Paragraph::new(status).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        v_chunks[0],
    );

    let bottom_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(v_chunks[1]);

    let finding_rows: Vec<Row> = if snap.findings.is_empty() {
        vec![Row::new(vec![
            Cell::from(Span::styled(
                "SAFE",
                Style::default().fg(COL_SAFE).add_modifier(Modifier::BOLD),
            )),
            Cell::from("-"),
            Cell::from(Span::styled(
                "Nothing flagged.",
                Style::default().fg(COL_SAFE),
            )),
        ])]
    } else {
        snap.findings
            .iter()
            .take(18)
            .map(|f| {
                let col = severity_color(f.severity);
                Row::new(vec![
                    Cell::from(Span::styled(
                        f.severity.label(),
                        Style::default().fg(col).add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(Span::styled(
                        f.rule_id.clone(),
                        Style::default().fg(COL_MUTED),
                    )),
                    Cell::from(Span::styled(
                        truncate_str(&f.title, 58),
                        Style::default().fg(Color::White),
                    )),
                ])
            })
            .collect()
    };

    let findings_preview = Table::new(
        finding_rows,
        [
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Min(25),
        ],
    )
    .header(
        Row::new(vec!["SEVERITY", "RULE ID", "SUMMARY"])
            .style(Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" Findings ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(findings_preview, bottom_cols[0]);

    let listener_rows: Vec<Row> = snap
        .connections
        .iter()
        .filter(|c| c.is_listening())
        .take(18)
        .map(|c| {
            let col = severity_color(c.severity);
            Row::new(vec![
                Cell::from(Span::styled(
                    c.severity.label(),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                )),
                Cell::from(c.protocol.as_str()),
                Cell::from(Span::styled(
                    truncate_str(&c.local_endpoint(), 21),
                    Style::default().fg(Color::White),
                )),
                Cell::from(Span::styled(
                    truncate_str(&c.process_name, 16),
                    Style::default().fg(COL_ACCENT),
                )),
                Cell::from(c.service_name.clone()),
                Cell::from(Span::styled(
                    c.exposure.short_label(),
                    Style::default().fg(if c.exposure.short_label() == "WILDCARD" {
                        COL_MED
                    } else {
                        COL_SAFE
                    }),
                )),
            ])
        })
        .collect();

    let listeners_preview = Table::new(
        listener_rows,
        [
            Constraint::Length(9),
            Constraint::Length(6),
            Constraint::Length(22),
            Constraint::Length(17),
            Constraint::Length(13),
            Constraint::Min(9),
        ],
    )
    .header(
        Row::new(vec!["RISK", "PROTO", "LOCAL PORT", "PROCESS", "SERVICE", "SCOPE"])
            .style(Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" Listening ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(listeners_preview, bottom_cols[1]);
}

fn render_connections_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(8)])
        .split(area);

    let filtered = app.filtered_connections();
    let total_shown = filtered.len();
    let selected_conn = app
        .conn_table_state
        .selected()
        .and_then(|i| filtered.get(i).copied())
        .cloned();

    let rows: Vec<Row> = filtered
        .iter()
        .map(|c| {
            let col = severity_color(c.severity);
            let pid_str = c
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            Row::new(vec![
                Cell::from(Span::styled(
                    c.severity.label(),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                )),
                Cell::from(c.protocol.as_str()),
                Cell::from(truncate_str(&c.local_endpoint(), 23)),
                Cell::from(truncate_str(&c.remote_display(), 28)),
                Cell::from(c.state.clone()),
                Cell::from(pid_str),
                Cell::from(Span::styled(
                    truncate_str(&c.process_name, 18),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                )),
                Cell::from(c.service_name.clone()),
                Cell::from(c.exposure.short_label()),
            ])
        })
        .collect();

    let title = format!(
        " Connections ({})  f:{}  s:{} ",
        total_shown,
        app.conn_filter.label(),
        app.conn_sort.label()
    );

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(6),
            Constraint::Length(24),
            Constraint::Length(29),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(19),
            Constraint::Length(14),
            Constraint::Min(9),
        ],
    )
    .header(
        Row::new(vec![
            "RISK",
            "PROTO",
            "LOCAL ENDPOINT",
            "REMOTE ENDPOINT / HOST",
            "STATE",
            "PID",
            "PROCESS",
            "SERVICE",
            "SCOPE",
        ])
        .style(Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(COL_ACCENT)),
    )
    .row_highlight_style(
        Style::default()
            .bg(COL_HIGHLIGHT_BG)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("> ");

    frame.render_stateful_widget(table, chunks[0], &mut app.conn_table_state);

    let inspector_lines = if let Some(c) = selected_conn {
        let sev_col = severity_color(c.severity);
        let lineage_str = if c.lineage.is_empty() {
            "N/A".to_string()
        } else {
            c.lineage.join(" -> ")
        };
        let reasons_str = if c.risk_reasons.is_empty() {
            "None".to_string()
        } else {
            c.risk_reasons.join(" | ")
        };
        vec![
            Line::from(vec![
                Span::styled(" Process : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    format!("{} (PID: {:?}) ", c.process_name, c.pid.unwrap_or(0)),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" | Lineage : ", Style::default().fg(COL_MUTED)),
                Span::styled(lineage_str, Style::default().fg(COL_ACCENT)),
            ]),
            Line::from(vec![
                Span::styled(" Binary  : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    if c.exe_path.is_empty() {
                        "<Protected / Kernel Process>".to_string()
                    } else {
                        c.exe_path.clone()
                    },
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled(" SHA-256 : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    c.sha256
                        .clone()
                        .unwrap_or_else(|| "N/A".to_string()),
                    Style::default().fg(COL_MED),
                ),
                Span::styled(" | Scope: ", Style::default().fg(COL_MUTED)),
                Span::styled(c.exposure.label(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled(" Cmdline : ", Style::default().fg(COL_MUTED)),
                Span::styled(truncate_str(&c.cmdline, 115), Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled(" Notes   : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    format!("[{}] ", c.severity.label()),
                    Style::default().fg(sev_col).add_modifier(Modifier::BOLD),
                ),
                Span::styled(reasons_str, Style::default().fg(sev_col)),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            " No socket selected.",
            Style::default().fg(COL_MUTED),
        ))]
    };

    let inspector = Paragraph::new(inspector_lines).block(
        Block::default()
            .title(" Socket ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(inspector, chunks[1]);
}

fn render_findings_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(8)])
        .split(area);

    let filtered = app.filtered_findings();
    let selected_finding = app
        .finding_table_state
        .selected()
        .and_then(|i| filtered.get(i).copied())
        .cloned();

    let rows: Vec<Row> = if filtered.is_empty() {
        vec![Row::new(vec![
            Cell::from(Span::styled(
                "SAFE",
                Style::default().fg(COL_SAFE).add_modifier(Modifier::BOLD),
            )),
            Cell::from("-"),
            Cell::from("Clean"),
            Cell::from("-"),
            Cell::from("No security findings detected."),
        ])]
    } else {
        filtered
            .iter()
            .map(|f| {
                let col = severity_color(f.severity);
                Row::new(vec![
                    Cell::from(Span::styled(
                        f.severity.label(),
                        Style::default().fg(col).add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(f.rule_id.clone()),
                    Cell::from(truncate_str(&f.category, 24)),
                    Cell::from(truncate_str(&f.mitre_id, 28)),
                    Cell::from(Span::styled(
                        truncate_str(&f.title, 55),
                        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                    )),
                ])
            })
            .collect()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Length(25),
            Constraint::Length(29),
            Constraint::Min(30),
        ],
    )
    .header(
        Row::new(vec![
            "SEVERITY",
            "RULE ID",
            "CATEGORY",
            "MITRE ID",
            "TITLE",
        ])
        .style(Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(format!(" Findings ({}) ", filtered.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(COL_ACCENT)),
    )
    .row_highlight_style(
        Style::default()
            .bg(COL_HIGHLIGHT_BG)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("> ");

    frame.render_stateful_widget(table, chunks[0], &mut app.finding_table_state);

    let detail_lines = if let Some(f) = selected_finding {
        let col = severity_color(f.severity);
        vec![
            Line::from(vec![
                Span::styled(" Finding     : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    format!("[{}] {} ", f.severity.label(), f.title),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("({})", f.mitre_id), Style::default().fg(COL_ACCENT)),
            ]),
            Line::from(vec![
                Span::styled(" Description : ", Style::default().fg(COL_MUTED)),
                Span::styled(f.description.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled(" Evidence    : ", Style::default().fg(COL_MUTED)),
                Span::styled(truncate_str(&f.evidence, 115), Style::default().fg(COL_MED)),
            ]),
            Line::from(vec![
                Span::styled(" Remediation : ", Style::default().fg(COL_MUTED)),
                Span::styled(f.remediation.clone(), Style::default().fg(COL_SAFE)),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            " No findings detected.",
            Style::default().fg(COL_SAFE),
        ))]
    };

    let detail_box = Paragraph::new(detail_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" Finding Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(detail_box, chunks[1]);
}

fn render_audit_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(7)])
        .split(area);

    let filtered = app.filtered_audit_items();
    let selected_item = app
        .audit_table_state
        .selected()
        .and_then(|i| filtered.get(i).copied())
        .cloned();

    let rows: Vec<Row> = filtered
        .iter()
        .map(|item| {
            let col = audit_status_color(item.status);
            Row::new(vec![
                Cell::from(Span::styled(
                    item.status.label(),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                )),
                Cell::from(truncate_str(&item.subsystem, 22)),
                Cell::from(Span::styled(
                    truncate_str(&item.name, 26),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                )),
                Cell::from(truncate_str(&item.location, 34)),
                Cell::from(truncate_str(&item.value, 45)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(23),
            Constraint::Length(27),
            Constraint::Length(35),
            Constraint::Min(25),
        ],
    )
    .header(
        Row::new(vec![
            "STATUS",
            "SUBSYSTEM",
            "ITEM",
            "LOCATION",
            "VALUE / COMMAND",
        ])
        .style(Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(format!(" Audit ({}) ", filtered.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(COL_ACCENT)),
    )
    .row_highlight_style(
        Style::default()
            .bg(COL_HIGHLIGHT_BG)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("> ");

    frame.render_stateful_widget(table, chunks[0], &mut app.audit_table_state);

    let inspector_lines = if let Some(item) = selected_item {
        let col = audit_status_color(item.status);
        vec![
            Line::from(vec![
                Span::styled(" Check    : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    format!("[{}] {} - {} ", item.status.label(), item.subsystem, item.name),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Location : ", Style::default().fg(COL_MUTED)),
                Span::styled(item.location.clone(), Style::default().fg(COL_ACCENT)),
            ]),
            Line::from(vec![
                Span::styled(" Value    : ", Style::default().fg(COL_MUTED)),
                Span::styled(item.value.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled(" Details  : ", Style::default().fg(COL_MUTED)),
                Span::styled(item.details.clone(), Style::default().fg(COL_MED)),
            ]),
        ]
    } else {
        vec![Line::from(" No audit item selected.")]
    };

    let inspector = Paragraph::new(inspector_lines).block(
        Block::default()
            .title(" Audit Item Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(inspector, chunks[1]);
}

fn render_processes_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(7)])
        .split(area);

    let filtered = app.filtered_processes();
    let selected_proc = app
        .proc_table_state
        .selected()
        .and_then(|i| filtered.get(i).copied())
        .cloned();

    let rows: Vec<Row> = filtered
        .iter()
        .map(|p| {
            let col = severity_color(p.max_severity);
            let mem_mb = p.memory_bytes as f64 / (1024.0 * 1024.0);
            let hash_short = p
                .sha256
                .as_deref()
                .map(|h| &h[..12.min(h.len())])
                .unwrap_or("-");
            Row::new(vec![
                Cell::from(Span::styled(
                    p.max_severity.label(),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                )),
                Cell::from(p.pid.to_string()),
                Cell::from(
                    p.ppid
                        .map(|pp| pp.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(Span::styled(
                    truncate_str(&p.name, 20),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    p.open_sockets_count.to_string(),
                    Style::default().fg(if p.open_sockets_count > 0 {
                        COL_ACCENT
                    } else {
                        COL_MUTED
                    }),
                )),
                Cell::from(format!("{:.1} MB", mem_mb)),
                Cell::from(Span::styled(
                    hash_short.to_string(),
                    Style::default().fg(COL_MED),
                )),
                Cell::from(truncate_str(&p.exe_path, 46)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(21),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(25),
        ],
    )
    .header(
        Row::new(vec![
            "RISK",
            "PID",
            "PPID",
            "PROCESS NAME",
            "SOCKETS",
            "MEMORY",
            "SHA-256 (12)",
            "EXECUTABLE PATH",
        ])
        .style(Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(format!(" Processes ({}) ", filtered.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(COL_ACCENT)),
    )
    .row_highlight_style(
        Style::default()
            .bg(COL_HIGHLIGHT_BG)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("> ");

    frame.render_stateful_widget(table, chunks[0], &mut app.proc_table_state);

    let inspector_lines = if let Some(p) = selected_proc {
        vec![
            Line::from(vec![
                Span::styled(" Lineage  : ", Style::default().fg(COL_MUTED)),
                Span::styled(p.lineage.join(" -> "), Style::default().fg(COL_ACCENT)),
                Span::styled(format!("  | User: {}", p.user), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled(" Binary   : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    if p.exe_path.is_empty() {
                        "<Protected / Kernel Process>".to_string()
                    } else {
                        p.exe_path.clone()
                    },
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled(" SHA-256  : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    p.sha256
                        .clone()
                        .unwrap_or_else(|| "N/A".to_string()),
                    Style::default().fg(COL_MED),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Cmdline  : ", Style::default().fg(COL_MUTED)),
                Span::styled(truncate_str(&p.cmdline, 115), Style::default().fg(Color::Gray)),
            ]),
        ]
    } else {
        vec![Line::from(" No process selected.")]
    };

    let inspector = Paragraph::new(inspector_lines).block(
        Block::default()
            .title(" Process Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(inspector, chunks[1]);
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let top_line = if app.is_searching {
        Line::from(vec![
            Span::styled(
                " SEARCH: ",
                Style::default()
                    .fg(Color::Black)
                    .bg(COL_ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {}_ ", app.search_query),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " (Enter to apply, Esc to clear)",
                Style::default().fg(COL_MUTED),
            ),
        ])
    } else if let Some((msg, _)) = &app.status_message {
        Line::from(vec![
            Span::styled(
                " INFO ",
                Style::default()
                    .fg(Color::Black)
                    .bg(COL_SAFE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {}", msg), Style::default().fg(Color::White)),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                " [1-5/Tab]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" View  "),
            Span::styled(
                "[Up/Down]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Select  "),
            Span::styled(
                "[f]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Filter  "),
            Span::styled(
                "[s]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Sort  "),
            Span::styled(
                "[/]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Search  "),
            Span::styled(
                "[r]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Rescan  "),
            Span::styled(
                "[a]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Refresh  "),
            Span::styled(
                "[e]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Export  "),
            Span::styled(
                "[Enter]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Details  "),
            Span::styled(
                "[?]",
                Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Help  "),
            Span::styled(
                "[q]",
                Style::default().fg(COL_CRIT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Quit"),
        ])
    };

    frame.render_widget(Paragraph::new(top_line), area);
}

fn render_detail_modal(frame: &mut Frame, app: &App) {
    let area = centered_rect(78, 72, frame.area());
    frame.render_widget(Clear, area);

    let mut lines: Vec<Line> = Vec::new();
    match app.active_tab {
        ActiveTab::Connections | ActiveTab::Overview => {
            let filtered = app.filtered_connections();
            if let Some(c) = app.conn_table_state.selected().and_then(|i| filtered.get(i)) {
                lines.push(Line::from(Span::styled(
                    format!("Socket #{} - {} ({})", c.id, c.process_name, c.protocol.as_str()),
                    Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Risk Severity   : {}", c.severity.label())));
                lines.push(Line::from(format!("Local Endpoint  : {}", c.local_endpoint())));
                lines.push(Line::from(format!("Remote Endpoint : {}", c.remote_display())));
                lines.push(Line::from(format!("Socket State    : {}", c.state)));
                lines.push(Line::from(format!("Exposure Scope  : {}", c.exposure.label())));
                lines.push(Line::from(format!("Remote Category : {}", c.remote_category.label())));
                lines.push(Line::from(format!("Service Name    : {}", c.service_name)));
                lines.push(Line::from(format!("Process ID      : {:?}", c.pid)));
                lines.push(Line::from(format!("Process Lineage : {}", c.lineage.join(" -> "))));
                lines.push(Line::from(format!("Executable Path : {}", c.exe_path)));
                lines.push(Line::from(format!(
                    "SHA-256 Digest  : {}",
                    c.sha256.as_deref().unwrap_or("N/A")
                )));
                lines.push(Line::from(format!("Command Line    : {}", c.cmdline)));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Risk Notes:",
                    Style::default().fg(COL_MED).add_modifier(Modifier::BOLD),
                )));
                if c.risk_reasons.is_empty() {
                    lines.push(Line::from("  - None"));
                } else {
                    for r in &c.risk_reasons {
                        lines.push(Line::from(format!("  - {}", r)));
                    }
                }
            }
        }
        ActiveTab::Findings => {
            let filtered = app.filtered_findings();
            if let Some(f) = app.finding_table_state.selected().and_then(|i| filtered.get(i)) {
                lines.push(Line::from(Span::styled(
                    format!("[{}] {} ({})", f.severity.label(), f.title, f.rule_id),
                    Style::default()
                        .fg(severity_color(f.severity))
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Category      : {}", f.category)));
                lines.push(Line::from(format!("MITRE ID      : {}", f.mitre_id)));
                lines.push(Line::from(format!("Process / PID : {:?} (PID {:?})", f.process_name, f.pid)));
                lines.push(Line::from(format!("Endpoint      : {:?}", f.endpoint)));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Description   : {}", f.description)));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Evidence      : {}", f.evidence)));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Remediation   : {}", f.remediation)));
            }
        }
        ActiveTab::Audit => {
            let filtered = app.filtered_audit_items();
            if let Some(a) = app.audit_table_state.selected().and_then(|i| filtered.get(i)) {
                lines.push(Line::from(Span::styled(
                    format!("[{}] {} - {}", a.status.label(), a.subsystem, a.name),
                    Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Check ID : {}", a.check_id)));
                lines.push(Line::from(format!("Location : {}", a.location)));
                lines.push(Line::from(format!("Value    : {}", a.value)));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Details  : {}", a.details)));
            }
        }
        ActiveTab::Processes => {
            let filtered = app.filtered_processes();
            if let Some(p) = app.proc_table_state.selected().and_then(|i| filtered.get(i)) {
                lines.push(Line::from(Span::styled(
                    format!("Process: {} (PID {})", p.name, p.pid),
                    Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Parent PID     : {:?}", p.ppid)));
                lines.push(Line::from(format!("User           : {}", p.user)));
                lines.push(Line::from(format!("Lineage Chain  : {}", p.lineage.join(" -> "))));
                lines.push(Line::from(format!("Open Sockets   : {}", p.open_sockets_count)));
                lines.push(Line::from(format!("Executable     : {}", p.exe_path)));
                lines.push(Line::from(format!("Deleted Binary : {}", p.is_deleted_binary)));
                lines.push(Line::from(format!(
                    "SHA-256 Digest : {}",
                    p.sha256.as_deref().unwrap_or("N/A")
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Command Line   : {}", p.cmdline)));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press Enter, d, or Esc to close.",
        Style::default().fg(COL_MUTED),
    )));

    let modal = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" Item Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(COL_ACCENT)),
        );
    frame.render_widget(modal, area);
}

fn render_help_modal(frame: &mut Frame) {
    let area = centered_rect(74, 74, frame.area());
    frame.render_widget(Clear, area);

    let lines = vec![
        Line::from(Span::styled(
            "Keys",
            Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  [1] - [5] / [Tab]   Switch views (Overview, Connections, Findings, Audit, Processes)"),
        Line::from("  [Up/Down] / [j/k]   Move selection up or down"),
        Line::from("  [PgUp / PgDn]       Move selection 10 rows"),
        Line::from("  [f]                 Cycle connection filter"),
        Line::from("  [s]                 Cycle connection sort order"),
        Line::from("  [/]                 Filter current table by text"),
        Line::from("  [r]                 Run immediate scan"),
        Line::from("  [a]                 Cycle auto-refresh interval (3s / 10s / Paused)"),
        Line::from("  [e]                 Export safe_door_report.json and safe_door_report.md"),
        Line::from("  [Enter] or [d]      Open detail view for selected row"),
        Line::from("  [q] or [Esc]        Close modal / Clear search / Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Rules",
            Style::default().fg(COL_MED).add_modifier(Modifier::BOLD),
        )),
        Line::from("  - H01: Shells (sh, bash, cmd, powershell) or relays (nc, socat) bound to sockets"),
        Line::from("  - H02: Binaries executing from /tmp, /dev/shm, %TEMP%, or Users\\Public"),
        Line::from("  - H03: Processes executing from deleted binaries or memfd descriptors"),
        Line::from("  - H04: System process path spoofing, typosquats, or fake kernel threads"),
        Line::from("  - H05: Known backdoor, C2, RAT, or mining ports (4444, 31337, 1337, 5555, 2375)"),
        Line::from("  - H06: Sensitive services bound to 0.0.0.0/:: and server-spawned shells"),
        Line::from("  - H07: Encoded PowerShell commands, download cradles, /dev/tcp, and LOLBins"),
        Line::from("  - AUD: Host firewall state, Registry Run/Winlogon, Cron, LD_PRELOAD, and hosts file"),
        Line::from(""),
        Line::from(Span::styled(
            "Press ?, h, or Esc to close.",
            Style::default().fg(COL_MUTED),
        )),
    ];

    let modal = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(COL_ACCENT)),
        );
    frame.render_widget(modal, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
