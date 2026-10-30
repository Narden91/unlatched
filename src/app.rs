use crate::models::{
    AuditItem, ConnectionEntry, IpCategory, ProcessRecord, ScanSnapshot, SecurityFinding, Severity,
};
use crate::report::{export_json_report, export_markdown_report};
use crate::scanner::ScannerEngine;
use ratatui::widgets::TableState;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Overview,
    Connections,
    Findings,
    Audit,
    Processes,
}

impl ActiveTab {
    pub fn index(&self) -> usize {
        match self {
            ActiveTab::Overview => 0,
            ActiveTab::Connections => 1,
            ActiveTab::Findings => 2,
            ActiveTab::Audit => 3,
            ActiveTab::Processes => 4,
        }
    }

    pub fn next(&self) -> Self {
        match self {
            ActiveTab::Overview => ActiveTab::Connections,
            ActiveTab::Connections => ActiveTab::Findings,
            ActiveTab::Findings => ActiveTab::Audit,
            ActiveTab::Audit => ActiveTab::Processes,
            ActiveTab::Processes => ActiveTab::Overview,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            ActiveTab::Overview => ActiveTab::Processes,
            ActiveTab::Connections => ActiveTab::Overview,
            ActiveTab::Findings => ActiveTab::Connections,
            ActiveTab::Audit => ActiveTab::Findings,
            ActiveTab::Processes => ActiveTab::Audit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnFilter {
    All,
    Listening,
    Established,
    ExternalIp,
    FlaggedOnly,
}

impl ConnFilter {
    pub fn next(&self) -> Self {
        match self {
            ConnFilter::All => ConnFilter::Listening,
            ConnFilter::Listening => ConnFilter::Established,
            ConnFilter::Established => ConnFilter::ExternalIp,
            ConnFilter::ExternalIp => ConnFilter::FlaggedOnly,
            ConnFilter::FlaggedOnly => ConnFilter::All,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ConnFilter::All => "ALL SOCKETS",
            ConnFilter::Listening => "LISTENING ONLY",
            ConnFilter::Established => "ESTABLISHED ONLY",
            ConnFilter::ExternalIp => "PUBLIC IP ONLY",
            ConnFilter::FlaggedOnly => "FLAGGED / RISK ONLY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnSort {
    RiskDesc,
    LocalPortAsc,
    ProcessAsc,
    StateAsc,
    PidAsc,
}

impl ConnSort {
    pub fn next(&self) -> Self {
        match self {
            ConnSort::RiskDesc => ConnSort::LocalPortAsc,
            ConnSort::LocalPortAsc => ConnSort::ProcessAsc,
            ConnSort::ProcessAsc => ConnSort::StateAsc,
            ConnSort::StateAsc => ConnSort::PidAsc,
            ConnSort::PidAsc => ConnSort::RiskDesc,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ConnSort::RiskDesc => "Risk (High->Low)",
            ConnSort::LocalPortAsc => "Local Port (Asc)",
            ConnSort::ProcessAsc => "Process Name (A->Z)",
            ConnSort::StateAsc => "State",
            ConnSort::PidAsc => "PID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshMode {
    Fast3s,
    Slow10s,
    Paused,
}

impl RefreshMode {
    pub fn next(&self) -> Self {
        match self {
            RefreshMode::Fast3s => RefreshMode::Slow10s,
            RefreshMode::Slow10s => RefreshMode::Paused,
            RefreshMode::Paused => RefreshMode::Fast3s,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            RefreshMode::Fast3s => "Auto: 3s",
            RefreshMode::Slow10s => "Auto: 10s",
            RefreshMode::Paused => "Paused",
        }
    }

    pub fn duration(&self) -> Option<Duration> {
        match self {
            RefreshMode::Fast3s => Some(Duration::from_secs(3)),
            RefreshMode::Slow10s => Some(Duration::from_secs(10)),
            RefreshMode::Paused => None,
        }
    }
}

pub struct App {
    pub engine: ScannerEngine,
    pub snapshot: ScanSnapshot,
    pub active_tab: ActiveTab,
    pub conn_filter: ConnFilter,
    pub conn_sort: ConnSort,
    pub refresh_mode: RefreshMode,
    pub last_scan_instant: Instant,
    pub search_query: String,
    pub is_searching: bool,
    pub show_help_modal: bool,
    pub show_detail_modal: bool,
    pub status_message: Option<(String, Instant)>,

    pub conn_table_state: TableState,
    pub finding_table_state: TableState,
    pub audit_table_state: TableState,
    pub proc_table_state: TableState,
}

impl App {
    pub fn new(engine: ScannerEngine, initial_snapshot: ScanSnapshot) -> Self {
        let conn_table_state = init_table_state(initial_snapshot.connections.len());
        let finding_table_state = init_table_state(initial_snapshot.findings.len());
        let audit_table_state = init_table_state(initial_snapshot.audit_items.len());
        let proc_table_state = init_table_state(initial_snapshot.processes.len());

        Self {
            engine,
            snapshot: initial_snapshot,
            active_tab: ActiveTab::Overview,
            conn_filter: ConnFilter::All,
            conn_sort: ConnSort::RiskDesc,
            refresh_mode: RefreshMode::Fast3s,
            last_scan_instant: Instant::now(),
            search_query: String::new(),
            is_searching: false,
            show_help_modal: false,
            show_detail_modal: false,
            status_message: None,
            conn_table_state,
            finding_table_state,
            audit_table_state,
            proc_table_state,
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now()));
    }

    pub fn trigger_scan(&mut self) {
        self.snapshot = self.engine.perform_scan();
        self.last_scan_instant = Instant::now();
        self.clamp_selections();
    }

    pub fn on_tick(&mut self) {
        if let Some((_, ts)) = &self.status_message {
            if ts.elapsed() > Duration::from_secs(5) {
                self.status_message = None;
            }
        }

        if !self.is_searching && !self.show_detail_modal && !self.show_help_modal {
            if let Some(interval) = self.refresh_mode.duration() {
                if self.last_scan_instant.elapsed() >= interval {
                    self.trigger_scan();
                }
            }
        }
    }

    pub fn export_reports_now(&mut self) {
        let json_path = Path::new("safe_door_report.json");
        let md_path = Path::new("safe_door_report.md");
        match (
            export_json_report(&self.snapshot, json_path),
            export_markdown_report(&self.snapshot, md_path),
        ) {
            (Ok(_), Ok(_)) => {
                self.set_status("Saved safe_door_report.json and safe_door_report.md");
            }
            (Err(e), _) | (_, Err(e)) => {
                self.set_status(format!("Export error: {}", e));
            }
        }
    }

    pub fn filtered_connections(&self) -> Vec<&ConnectionEntry> {
        let q = self.search_query.trim().to_lowercase();
        let mut list: Vec<&ConnectionEntry> = self
            .snapshot
            .connections
            .iter()
            .filter(|c| match self.conn_filter {
                ConnFilter::All => true,
                ConnFilter::Listening => c.is_listening(),
                ConnFilter::Established => c.is_established(),
                ConnFilter::ExternalIp => c.remote_category == IpCategory::PublicInternet,
                ConnFilter::FlaggedOnly => c.severity >= Severity::Low,
            })
            .filter(|c| {
                if q.is_empty() {
                    return true;
                }
                c.process_name.to_lowercase().contains(&q)
                    || c.local_port.to_string().contains(&q)
                    || c.local_endpoint().to_lowercase().contains(&q)
                    || c.remote_display().to_lowercase().contains(&q)
                    || c.service_name.to_lowercase().contains(&q)
                    || c.state.to_lowercase().contains(&q)
                    || c.exe_path.to_lowercase().contains(&q)
                    || c.pid.map(|p| p.to_string()).unwrap_or_default().contains(&q)
            })
            .collect();

        match self.conn_sort {
            ConnSort::RiskDesc => {
                list.sort_by(|a, b| {
                    b.severity
                        .cmp(&a.severity)
                        .then_with(|| b.is_listening().cmp(&a.is_listening()))
                        .then_with(|| a.local_port.cmp(&b.local_port))
                });
            }
            ConnSort::LocalPortAsc => {
                list.sort_by(|a, b| a.local_port.cmp(&b.local_port));
            }
            ConnSort::ProcessAsc => {
                list.sort_by(|a, b| {
                    a.process_name
                        .to_lowercase()
                        .cmp(&b.process_name.to_lowercase())
                        .then_with(|| a.local_port.cmp(&b.local_port))
                });
            }
            ConnSort::StateAsc => {
                list.sort_by(|a, b| {
                    a.state
                        .cmp(&b.state)
                        .then_with(|| a.local_port.cmp(&b.local_port))
                });
            }
            ConnSort::PidAsc => {
                list.sort_by(|a, b| a.pid.unwrap_or(u32::MAX).cmp(&b.pid.unwrap_or(u32::MAX)));
            }
        }

        list
    }

    pub fn filtered_findings(&self) -> Vec<&SecurityFinding> {
        let q = self.search_query.trim().to_lowercase();
        self.snapshot
            .findings
            .iter()
            .filter(|f| {
                if q.is_empty() {
                    return true;
                }
                f.title.to_lowercase().contains(&q)
                    || f.category.to_lowercase().contains(&q)
                    || f.rule_id.to_lowercase().contains(&q)
                    || f.description.to_lowercase().contains(&q)
                    || f.evidence.to_lowercase().contains(&q)
            })
            .collect()
    }

    pub fn filtered_audit_items(&self) -> Vec<&AuditItem> {
        let q = self.search_query.trim().to_lowercase();
        self.snapshot
            .audit_items
            .iter()
            .filter(|a| {
                if q.is_empty() {
                    return true;
                }
                a.name.to_lowercase().contains(&q)
                    || a.subsystem.to_lowercase().contains(&q)
                    || a.location.to_lowercase().contains(&q)
                    || a.value.to_lowercase().contains(&q)
                    || a.details.to_lowercase().contains(&q)
            })
            .collect()
    }

    pub fn filtered_processes(&self) -> Vec<&ProcessRecord> {
        let q = self.search_query.trim().to_lowercase();
        self.snapshot
            .processes
            .iter()
            .filter(|p| {
                if q.is_empty() {
                    return true;
                }
                p.name.to_lowercase().contains(&q)
                    || p.pid.to_string().contains(&q)
                    || p.exe_path.to_lowercase().contains(&q)
                    || p.cmdline.to_lowercase().contains(&q)
                    || p.sha256
                        .as_deref()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&q)
            })
            .collect()
    }

    pub fn move_selection_down(&mut self, step: usize) {
        match self.active_tab {
            ActiveTab::Overview => {
                self.active_tab = ActiveTab::Connections;
            }
            ActiveTab::Connections => {
                let len = self.filtered_connections().len();
                advance_table(&mut self.conn_table_state, len, step, true);
            }
            ActiveTab::Findings => {
                let len = self.filtered_findings().len();
                advance_table(&mut self.finding_table_state, len, step, true);
            }
            ActiveTab::Audit => {
                let len = self.filtered_audit_items().len();
                advance_table(&mut self.audit_table_state, len, step, true);
            }
            ActiveTab::Processes => {
                let len = self.filtered_processes().len();
                advance_table(&mut self.proc_table_state, len, step, true);
            }
        }
    }

    pub fn move_selection_up(&mut self, step: usize) {
        match self.active_tab {
            ActiveTab::Overview => {}
            ActiveTab::Connections => {
                let len = self.filtered_connections().len();
                advance_table(&mut self.conn_table_state, len, step, false);
            }
            ActiveTab::Findings => {
                let len = self.filtered_findings().len();
                advance_table(&mut self.finding_table_state, len, step, false);
            }
            ActiveTab::Audit => {
                let len = self.filtered_audit_items().len();
                advance_table(&mut self.audit_table_state, len, step, false);
            }
            ActiveTab::Processes => {
                let len = self.filtered_processes().len();
                advance_table(&mut self.proc_table_state, len, step, false);
            }
        }
    }

    pub fn clamp_selections(&mut self) {
        let conn_len = self.filtered_connections().len();
        let finding_len = self.filtered_findings().len();
        let audit_len = self.filtered_audit_items().len();
        let proc_len = self.filtered_processes().len();
        clamp_table(&mut self.conn_table_state, conn_len);
        clamp_table(&mut self.finding_table_state, finding_len);
        clamp_table(&mut self.audit_table_state, audit_len);
        clamp_table(&mut self.proc_table_state, proc_len);
    }
}

fn init_table_state(len: usize) -> TableState {
    let mut state = TableState::default();
    if len > 0 {
        state.select(Some(0));
    }
    state
}

fn advance_table(state: &mut TableState, len: usize, step: usize, down: bool) {
    if len == 0 {
        state.select(None);
        return;
    }
    let current = state.selected().unwrap_or(0);
    let next = if down {
        (current + step).min(len - 1)
    } else {
        current.saturating_sub(step)
    };
    state.select(Some(next));
}

fn clamp_table(state: &mut TableState, len: usize) {
    if len == 0 {
        state.select(None);
    } else if let Some(sel) = state.selected() {
        if sel >= len {
            state.select(Some(len - 1));
        }
    } else {
        state.select(Some(0));
    }
}
