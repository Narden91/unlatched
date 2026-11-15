use crate::app::{ActiveTab, App};
use crate::baseline::socket_key;
use crate::models::{AuditStatus, ExposureScope, Severity, TimelineKind};
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

fn exposure_color(scope: ExposureScope) -> Color {
    match scope {
        ExposureScope::Loopback => COL_SAFE,
        ExposureScope::LoopbackProxy => COL_HIGH,
        ExposureScope::LocalLan => COL_LOW,
        ExposureScope::WildcardAllInterfaces | ExposureScope::PublicInternet => COL_MED,
    }
}

fn timeline_kind_color(kind: TimelineKind) -> Color {
    match kind {
        TimelineKind::BeaconSuspected | TimelineKind::BinaryModified => COL_CRIT,
        TimelineKind::ListenerOpened => COL_HIGH,
        TimelineKind::ConnectionOpened => COL_LOW,
        TimelineKind::ListenerClosed | TimelineKind::ConnectionClosed => COL_MUTED,
    }
}

fn styled_table<'a, I>(
    rows: Vec<Row<'a>>,
    widths: I,
    headers: &[&'a str],
    title: String,
) -> Table<'a>
where
    I: IntoIterator,
    I::Item: Into<Constraint>,
{
    Table::new(rows, widths)
        .header(
            Row::new(headers.iter().copied())
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
        .highlight_symbol("> ")
}

fn inspector_panel<'a>(title: &'a str, lines: Vec<Line<'a>>, wrap: bool) -> Paragraph<'a> {
    let p = Paragraph::new(lines).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    if wrap {
        p.wrap(Wrap { trim: false })
    } else {
        p
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
        ActiveTab::Events => render_events_tab(frame, app, root_chunks[2]),
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

    let warn_badge = match snap.scan_warnings.first() {
        Some(w) => Span::styled(
            format!(" [INCOMPLETE: {}] ", truncate_str(w, 60)),
            Style::default()
                .fg(Color::Black)
                .bg(COL_CRIT)
                .add_modifier(Modifier::BOLD),
        ),
        None => Span::raw(""),
    };

    let mut spans = vec![
        Span::styled(
            " UNLATCHED ",
            Style::default()
                .fg(Color::Black)
                .bg(COL_ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        priv_badge,
        warn_badge,
        Span::styled(
            format!(" Host: {} ({}) ", snap.hostname, snap.os_name),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled("| Score: ", Style::default().fg(COL_MUTED)),
        Span::styled(
            format!("{}/100 [{}] ", snap.security_score, snap.security_grade),
            Style::default().fg(score_col).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "| Scan: {}ms ({}) @ {}{}",
                snap.scan_duration_ms,
                app.refresh_mode.label(),
                snap.timestamp.format("%H:%M:%S"),
                if app.is_scanning() { "  scanning..." } else { "" }
            ),
            Style::default().fg(COL_MUTED),
        ),
    ];

    if snap.suppressed_count > 0 {
        spans.push(Span::styled(
            format!(" | Allowlisted: {}", snap.suppressed_count),
            Style::default().fg(COL_SAFE),
        ));
    }
    if snap.sockets_without_exe > 0 {
        spans.push(Span::styled(
            format!(
                " | No exe path: {}/{}",
                snap.sockets_without_exe, snap.total_connections
            ),
            Style::default().fg(COL_MED),
        ));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COL_ACCENT));
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
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
        Line::from(vec![
            Span::raw(" [6] Events "),
            Span::styled(
                format!("({}) ", snap.timeline_events.len()),
                Style::default().fg(COL_LOW),
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
        Span::styled("  events ", Style::default().fg(COL_MUTED)),
        Span::styled(
            snap.timeline_events.len().to_string(),
            Style::default().fg(COL_LOW),
        ),
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
                        f.rule_id.as_str(),
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
            let local_ep = truncate_str(&c.local_endpoint(), 21).into_owned();
            Row::new(vec![
                Cell::from(Span::styled(
                    c.severity.label(),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                )),
                Cell::from(c.protocol.as_str()),
                Cell::from(Span::styled(local_ep, Style::default().fg(Color::White))),
                Cell::from(Span::styled(
                    truncate_str(&c.process_name, 16),
                    Style::default().fg(COL_ACCENT),
                )),
                Cell::from(c.service_name.as_str()),
                Cell::from(Span::styled(
                    c.exposure.short_label(),
                    Style::default().fg(exposure_color(c.exposure)),
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

    let snap = &app.snapshot;
    let indices = &app.conn_indices;
    let new_listeners = &app.new_listeners;
    let filter_lbl = app.conn_filter.label();
    let sort_lbl = app.conn_sort.label();
    let state = &mut app.conn_table_state;

    let selected_conn = state
        .selected()
        .and_then(|i| indices.get(i))
        .and_then(|&idx| snap.connections.get(idx));

    let rows: Vec<Row> = indices
        .iter()
        .filter_map(|&idx| snap.connections.get(idx))
        .map(|c| {
            let col = severity_color(c.severity);
            let pid_str = c
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            let local_ep = truncate_str(&c.local_endpoint(), 23).into_owned();
            let rem_ep = truncate_str(&c.remote_display(), 28).into_owned();
            let is_new = c.is_listening() && new_listeners.contains(&socket_key(c));
            Row::new(vec![
                Cell::from(Span::styled(
                    c.severity.label(),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                )),
                Cell::from(c.protocol.as_str()),
                Cell::from(local_ep),
                Cell::from(rem_ep),
                Cell::from(c.state.as_str()),
                Cell::from(pid_str),
                Cell::from(Line::from(vec![
                    Span::styled(
                        if is_new { "+ " } else { "" },
                        Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        truncate_str(&c.process_name, 16),
                        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                    ),
                ])),
                Cell::from(c.service_name.as_str()),
                Cell::from(Span::styled(
                    c.exposure.short_label(),
                    Style::default().fg(exposure_color(c.exposure)),
                )),
            ])
        })
        .collect();

    let title = format!(
        " Connections ({})  f:{}  s:{}  (+ = new listener since start) ",
        indices.len(),
        filter_lbl,
        sort_lbl
    );

    let table = styled_table(
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
            Constraint::Min(10),
        ],
        &[
            "RISK",
            "PROTO",
            "LOCAL ENDPOINT",
            "REMOTE ENDPOINT / HOST",
            "STATE",
            "PID",
            "PROCESS",
            "SERVICE",
            "SCOPE",
        ],
        title,
    );

    frame.render_stateful_widget(table, chunks[0], state);

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
                        "<Protected / Kernel Process>"
                    } else {
                        c.exe_path.as_str()
                    },
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled(" SHA-256 : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    c.sha256.as_deref().unwrap_or("N/A"),
                    Style::default().fg(COL_MED),
                ),
                Span::styled(" | Scope: ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    c.exposure.label(),
                    Style::default().fg(exposure_color(c.exposure)),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Cmdline : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    truncate_str(&c.cmdline, 115),
                    Style::default().fg(Color::Gray),
                ),
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

    frame.render_widget(inspector_panel(" Socket ", inspector_lines, false), chunks[1]);
}

fn render_findings_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(8)])
        .split(area);

    let snap = &app.snapshot;
    let indices = &app.finding_indices;
    let state = &mut app.finding_table_state;

    let selected_finding = state
        .selected()
        .and_then(|i| indices.get(i))
        .and_then(|&idx| snap.findings.get(idx));

    let rows: Vec<Row> = if indices.is_empty() {
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
        indices
            .iter()
            .filter_map(|&idx| snap.findings.get(idx))
            .map(|f| {
                let col = severity_color(f.severity);
                Row::new(vec![
                    Cell::from(Span::styled(
                        f.severity.label(),
                        Style::default().fg(col).add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(f.rule_id.as_str()),
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

    let table = styled_table(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Length(25),
            Constraint::Length(29),
            Constraint::Min(30),
        ],
        &["SEVERITY", "RULE ID", "CATEGORY", "MITRE ID", "TITLE"],
        format!(" Findings ({}) ", indices.len()),
    );

    frame.render_stateful_widget(table, chunks[0], state);

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
                Span::styled(f.description.as_str(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled(" Evidence    : ", Style::default().fg(COL_MUTED)),
                Span::styled(truncate_str(&f.evidence, 115), Style::default().fg(COL_MED)),
            ]),
            Line::from(vec![
                Span::styled(" Remediation : ", Style::default().fg(COL_MUTED)),
                Span::styled(f.remediation.as_str(), Style::default().fg(COL_SAFE)),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            " No findings detected.",
            Style::default().fg(COL_SAFE),
        ))]
    };

    frame.render_widget(
        inspector_panel(" Finding Details ", detail_lines, true),
        chunks[1],
    );
}

fn render_audit_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(7)])
        .split(area);

    let snap = &app.snapshot;
    let indices = &app.audit_indices;
    let state = &mut app.audit_table_state;

    let selected_item = state
        .selected()
        .and_then(|i| indices.get(i))
        .and_then(|&idx| snap.audit_items.get(idx));

    let rows: Vec<Row> = indices
        .iter()
        .filter_map(|&idx| snap.audit_items.get(idx))
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

    let table = styled_table(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(23),
            Constraint::Length(27),
            Constraint::Length(35),
            Constraint::Min(25),
        ],
        &["STATUS", "SUBSYSTEM", "ITEM", "LOCATION", "VALUE / COMMAND"],
        format!(" Audit ({}) ", indices.len()),
    );

    frame.render_stateful_widget(table, chunks[0], state);

    let inspector_lines = if let Some(item) = selected_item {
        let col = audit_status_color(item.status);
        vec![
            Line::from(vec![
                Span::styled(" Check    : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    format!(
                        "[{}] {} - {} ",
                        item.status.label(),
                        item.subsystem,
                        item.name
                    ),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Location : ", Style::default().fg(COL_MUTED)),
                Span::styled(item.location.as_str(), Style::default().fg(COL_ACCENT)),
            ]),
            Line::from(vec![
                Span::styled(" Value    : ", Style::default().fg(COL_MUTED)),
                Span::styled(item.value.as_str(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled(" Details  : ", Style::default().fg(COL_MUTED)),
                Span::styled(item.details.as_str(), Style::default().fg(COL_MED)),
            ]),
        ]
    } else {
        vec![Line::from(" No audit item selected.")]
    };

    frame.render_widget(
        inspector_panel(" Audit Item Details ", inspector_lines, false),
        chunks[1],
    );
}

fn render_processes_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(7)])
        .split(area);

    let snap = &app.snapshot;
    let indices = &app.proc_indices;
    let state = &mut app.proc_table_state;

    let selected_proc = state
        .selected()
        .and_then(|i| indices.get(i))
        .and_then(|&idx| snap.processes.get(idx));

    let rows: Vec<Row> = indices
        .iter()
        .filter_map(|&idx| snap.processes.get(idx))
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
                Cell::from(Span::styled(hash_short, Style::default().fg(COL_MED))),
                Cell::from(truncate_str(&p.exe_path, 46)),
            ])
        })
        .collect();

    let table = styled_table(
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
        &[
            "RISK",
            "PID",
            "PPID",
            "PROCESS NAME",
            "SOCKETS",
            "MEMORY",
            "SHA-256 (12)",
            "EXECUTABLE PATH",
        ],
        format!(" Processes ({}) ", indices.len()),
    );

    frame.render_stateful_widget(table, chunks[0], state);

    let inspector_lines = if let Some(p) = selected_proc {
        let mut sha_spans = vec![
            Span::styled(" SHA-256  : ", Style::default().fg(COL_MUTED)),
            Span::styled(
                p.sha256.as_deref().unwrap_or("N/A"),
                Style::default().fg(COL_MED),
            ),
        ];
        if let Some(orig) = &p.original_filename {
            sha_spans.push(Span::styled(
                "  | PE OriginalFilename: ",
                Style::default().fg(COL_MUTED),
            ));
            sha_spans.push(Span::styled(
                orig.as_str(),
                Style::default().fg(COL_LOW).add_modifier(Modifier::BOLD),
            ));
        }
        vec![
            Line::from(vec![
                Span::styled(" Lineage  : ", Style::default().fg(COL_MUTED)),
                Span::styled(p.lineage.join(" -> "), Style::default().fg(COL_ACCENT)),
                Span::styled(
                    format!("  | User: {}", p.user),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Binary   : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    if p.exe_path.is_empty() {
                        "<Protected / Kernel Process>"
                    } else {
                        p.exe_path.as_str()
                    },
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(sha_spans),
            Line::from(vec![
                Span::styled(" Cmdline  : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    truncate_str(&p.cmdline, 115),
                    Style::default().fg(Color::Gray),
                ),
            ]),
        ]
    } else {
        vec![Line::from(" No process selected.")]
    };

    frame.render_widget(
        inspector_panel(" Process Details ", inspector_lines, false),
        chunks[1],
    );
}

fn render_events_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(6)])
        .split(area);

    let snap = &app.snapshot;
    let indices = &app.event_indices;
    let state = &mut app.event_table_state;

    let selected_ev = state
        .selected()
        .and_then(|i| indices.get(i))
        .and_then(|&idx| snap.timeline_events.get(idx));

    let rows: Vec<Row> = if indices.is_empty() {
        vec![Row::new(vec![
            Cell::from("-"),
            Cell::from(Span::styled("IDLE", Style::default().fg(COL_SAFE))),
            Cell::from("-"),
            Cell::from("-"),
            Cell::from("-"),
            Cell::from("Flight recorder seeded. New/closed sockets, SHA-256 changes, and C2 beacons appear on next scan."),
        ])]
    } else {
        indices
            .iter()
            .filter_map(|&idx| snap.timeline_events.get(idx))
            .map(|ev| {
                let sev_col = severity_color(ev.severity);
                let kind_col = timeline_kind_color(ev.kind);
                Row::new(vec![
                    Cell::from(ev.timestamp.format("%H:%M:%S").to_string()),
                    Cell::from(Span::styled(
                        ev.kind.label(),
                        Style::default().fg(kind_col).add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(Span::styled(
                        ev.severity.label(),
                        Style::default().fg(sev_col).add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(
                        ev.pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(Span::styled(
                        truncate_str(&ev.process_name, 18),
                        Style::default().fg(Color::White),
                    )),
                    Cell::from(truncate_str(&ev.summary, 68)),
                ])
            })
            .collect()
    };

    let table = styled_table(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(20),
            Constraint::Min(30),
        ],
        &["TIME", "EVENT", "SEVERITY", "PID", "PROCESS", "SUMMARY"],
        format!(" Live Flight Recorder ({}) ", indices.len()),
    );

    frame.render_stateful_widget(table, chunks[0], state);

    let inspector_lines = if let Some(ev) = selected_ev {
        vec![
            Line::from(vec![
                Span::styled(" Event    : ", Style::default().fg(COL_MUTED)),
                Span::styled(
                    format!("{} [{}] ", ev.kind.label(), ev.severity.label()),
                    Style::default()
                        .fg(timeline_kind_color(ev.kind))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("@ {}", ev.timestamp.format("%Y-%m-%d %H:%M:%S")),
                    Style::default().fg(COL_MUTED),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Endpoint : ", Style::default().fg(COL_MUTED)),
                Span::styled(ev.endpoint.as_str(), Style::default().fg(COL_ACCENT)),
                Span::styled(
                    format!("  | Process: {} (PID {:?})", ev.process_name, ev.pid),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Summary  : ", Style::default().fg(COL_MUTED)),
                Span::styled(ev.summary.as_str(), Style::default().fg(Color::White)),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            " Waiting for socket or binary state transitions across scan intervals.",
            Style::default().fg(COL_MUTED),
        ))]
    };

    frame.render_widget(
        inspector_panel(" Event Details ", inspector_lines, false),
        chunks[1],
    );
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let key_style = Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD);
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
            Span::styled(" [1-6/Tab]", key_style),
            Span::raw(" View  "),
            Span::styled("[j/k]", key_style),
            Span::raw(" Select  "),
            Span::styled("[f]", key_style),
            Span::raw(" Filter  "),
            Span::styled("[s]", key_style),
            Span::raw(" Sort  "),
            Span::styled("[/]", key_style),
            Span::raw(" Search  "),
            Span::styled("[w]", key_style),
            Span::raw(" Allowlist  "),
            Span::styled("[r]", key_style),
            Span::raw(" Rescan  "),
            Span::styled("[a]", key_style),
            Span::raw(" Refresh  "),
            Span::styled("[e]", key_style),
            Span::raw(" Export  "),
            Span::styled("[Enter]", key_style),
            Span::raw(" Details  "),
            Span::styled("[?]", key_style),
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
    let area = centered_rect(78, 74, frame.area());
    frame.render_widget(Clear, area);

    let snap = &app.snapshot;
    let mut lines: Vec<Line> = Vec::new();
    match app.active_tab {
        ActiveTab::Connections | ActiveTab::Overview => {
            if let Some(c) = app
                .conn_table_state
                .selected()
                .and_then(|i| app.conn_indices.get(i))
                .and_then(|&idx| snap.connections.get(idx))
            {
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
                lines.push(Line::from(format!(
                    "Remote Category : {}",
                    c.remote_category.label()
                )));
                lines.push(Line::from(format!("Service Name    : {}", c.service_name)));
                lines.push(Line::from(format!("Process ID      : {:?}", c.pid)));
                lines.push(Line::from(format!(
                    "Process Lineage : {}",
                    c.lineage.join(" -> ")
                )));
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
            if let Some(f) = app
                .finding_table_state
                .selected()
                .and_then(|i| app.finding_indices.get(i))
                .and_then(|&idx| snap.findings.get(idx))
            {
                lines.push(Line::from(Span::styled(
                    format!("[{}] {} ({})", f.severity.label(), f.title, f.rule_id),
                    Style::default()
                        .fg(severity_color(f.severity))
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Category      : {}", f.category)));
                lines.push(Line::from(format!("MITRE ID      : {}", f.mitre_id)));
                lines.push(Line::from(format!(
                    "Process / PID : {:?} (PID {:?})",
                    f.process_name, f.pid
                )));
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
            if let Some(a) = app
                .audit_table_state
                .selected()
                .and_then(|i| app.audit_indices.get(i))
                .and_then(|&idx| snap.audit_items.get(idx))
            {
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
            if let Some(p) = app
                .proc_table_state
                .selected()
                .and_then(|i| app.proc_indices.get(i))
                .and_then(|&idx| snap.processes.get(idx))
            {
                lines.push(Line::from(Span::styled(
                    format!("Process: {} (PID {})", p.name, p.pid),
                    Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Parent PID          : {:?}", p.ppid)));
                lines.push(Line::from(format!("User                : {}", p.user)));
                lines.push(Line::from(format!(
                    "Lineage Chain       : {}",
                    p.lineage.join(" -> ")
                )));
                lines.push(Line::from(format!(
                    "Open Sockets        : {}",
                    p.open_sockets_count
                )));
                lines.push(Line::from(format!("Executable          : {}", p.exe_path)));
                lines.push(Line::from(format!(
                    "PE OriginalFilename : {}",
                    p.original_filename.as_deref().unwrap_or("N/A")
                )));
                lines.push(Line::from(format!(
                    "Deleted Binary      : {}",
                    p.is_deleted_binary
                )));
                lines.push(Line::from(format!(
                    "SHA-256 Digest      : {}",
                    p.sha256.as_deref().unwrap_or("N/A")
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Command Line        : {}", p.cmdline)));
            }
        }
        ActiveTab::Events => {
            if let Some(ev) = app
                .event_table_state
                .selected()
                .and_then(|i| app.event_indices.get(i))
                .and_then(|&idx| snap.timeline_events.get(idx))
            {
                lines.push(Line::from(Span::styled(
                    format!("{} [{}]", ev.kind.label(), ev.severity.label()),
                    Style::default()
                        .fg(timeline_kind_color(ev.kind))
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!(
                    "Timestamp : {}",
                    ev.timestamp.format("%Y-%m-%d %H:%M:%S %z")
                )));
                lines.push(Line::from(format!(
                    "Process   : {} (PID {:?})",
                    ev.process_name, ev.pid
                )));
                lines.push(Line::from(format!("Endpoint  : {}", ev.endpoint)));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Summary   : {}", ev.summary)));
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
    let area = centered_rect(76, 78, frame.area());
    frame.render_widget(Clear, area);

    let lines = vec![
        Line::from(Span::styled(
            "Keys",
            Style::default().fg(COL_ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  [1] - [6] / [Tab]   Switch views (Overview, Connections, Findings, Audit, Processes, Events)"),
        Line::from("  [Up/Down] / [j/k]   Move selection up or down"),
        Line::from("  [PgUp / PgDn]       Move selection 10 rows"),
        Line::from("  [f]                 Cycle connection filter"),
        Line::from("  [s]                 Cycle connection sort order"),
        Line::from("  [/]                 Filter current table by text"),
        Line::from("  [w]                 Allowlist selected binary by cryptographic SHA-256 digest"),
        Line::from("  [r]                 Run immediate scan"),
        Line::from("  [a]                 Cycle auto-refresh interval (3s / 10s / Paused)"),
        Line::from("  [e]                 Export safe_door_report.{json, md, sarif.json}"),
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
        Line::from("  - H04: System process path spoofing, typosquats, fake kthreads, or renamed PE LOLBins"),
        Line::from("  - H05: Known backdoor, C2, RAT, or mining ports (4444, 31337, 1337, 5555, 2375)"),
        Line::from("  - H06: Sensitive services bound to 0.0.0.0/:: and server-spawned shells"),
        Line::from("  - H07: Encoded PowerShell commands, download cradles, /dev/tcp, and LOLBins"),
        Line::from("  - H08: Loopback (127.0.0.1) services transitively exposed via a network-reachable proxy"),
        Line::from("  - H09: Periodic low-jitter outbound C2 beacon flows (Welford online CV <= 0.20)"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScannerEngine;
    use ratatui::{backend::TestBackend, Terminal};

    const TABS: [ActiveTab; 6] = [
        ActiveTab::Overview,
        ActiveTab::Connections,
        ActiveTab::Findings,
        ActiveTab::Audit,
        ActiveTab::Processes,
        ActiveTab::Events,
    ];

    /// Draws every tab and both modals on real scan data, at a normal and two tiny sizes.
    /// Tiny terminals are where layout arithmetic panics.
    #[test]
    fn every_tab_and_modal_renders_without_panic() {
        let mut engine = ScannerEngine::new();
        let snapshot = engine.perform_scan();
        let mut app = App::new(engine, snapshot);

        for (w, h) in [(140, 40), (60, 15), (20, 5)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            for tab in TABS {
                app.active_tab = tab;
                terminal.draw(|f| render(f, &mut app)).unwrap();
                app.show_help_modal = true;
                terminal.draw(|f| render(f, &mut app)).unwrap();
                app.show_help_modal = false;
                app.show_detail_modal = true;
                terminal.draw(|f| render(f, &mut app)).unwrap();
                app.show_detail_modal = false;
            }
        }
    }

    #[test]
    fn header_shows_brand_warning_and_allowlisted_badges() {
        let mut engine = ScannerEngine::new();
        let mut snapshot = engine.perform_scan();
        snapshot.scan_warnings = vec!["Socket enumeration failed: test".to_string()];
        snapshot.suppressed_count = 3;
        let mut app = App::new(engine, snapshot);

        let mut terminal = Terminal::new(TestBackend::new(220, 40)).unwrap();
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let screen = terminal.backend().to_string();
        assert!(screen.contains("UNLATCHED"));
        assert!(screen.contains("INCOMPLETE: Socket enumeration failed"));
        assert!(screen.contains("Allowlisted: 3"));
        assert!(screen.contains("[6] Events"));
    }
}
