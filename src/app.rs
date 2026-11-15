use crate::allowlist::{Allowlist, AllowlistRule};
use crate::baseline::socket_key;
use crate::flight::FlightRecorder;
use crate::models::{cmp_ci, contains_ci, IpCategory, ScanSnapshot, Severity};
use crate::report::{export_json_report, export_markdown_report, export_sarif_report};
use crate::scanner::ScannerEngine;
use ratatui::widgets::TableState;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Overview,
    Connections,
    Findings,
    Audit,
    Processes,
    Events,
}

impl ActiveTab {
    #[must_use]
    pub fn index(&self) -> usize {
        match self {
            ActiveTab::Overview => 0,
            ActiveTab::Connections => 1,
            ActiveTab::Findings => 2,
            ActiveTab::Audit => 3,
            ActiveTab::Processes => 4,
            ActiveTab::Events => 5,
        }
    }

    #[must_use]
    pub fn next(&self) -> Self {
        match self {
            ActiveTab::Overview => ActiveTab::Connections,
            ActiveTab::Connections => ActiveTab::Findings,
            ActiveTab::Findings => ActiveTab::Audit,
            ActiveTab::Audit => ActiveTab::Processes,
            ActiveTab::Processes => ActiveTab::Events,
            ActiveTab::Events => ActiveTab::Overview,
        }
    }

    #[must_use]
    pub fn prev(&self) -> Self {
        match self {
            ActiveTab::Overview => ActiveTab::Events,
            ActiveTab::Connections => ActiveTab::Overview,
            ActiveTab::Findings => ActiveTab::Connections,
            ActiveTab::Audit => ActiveTab::Findings,
            ActiveTab::Processes => ActiveTab::Audit,
            ActiveTab::Events => ActiveTab::Processes,
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
    #[must_use]
    pub fn next(&self) -> Self {
        match self {
            ConnFilter::All => ConnFilter::Listening,
            ConnFilter::Listening => ConnFilter::Established,
            ConnFilter::Established => ConnFilter::ExternalIp,
            ConnFilter::ExternalIp => ConnFilter::FlaggedOnly,
            ConnFilter::FlaggedOnly => ConnFilter::All,
        }
    }

    #[must_use]
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
    #[must_use]
    pub fn next(&self) -> Self {
        match self {
            ConnSort::RiskDesc => ConnSort::LocalPortAsc,
            ConnSort::LocalPortAsc => ConnSort::ProcessAsc,
            ConnSort::ProcessAsc => ConnSort::StateAsc,
            ConnSort::StateAsc => ConnSort::PidAsc,
            ConnSort::PidAsc => ConnSort::RiskDesc,
        }
    }

    #[must_use]
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
    #[must_use]
    pub fn next(&self) -> Self {
        match self {
            RefreshMode::Fast3s => RefreshMode::Slow10s,
            RefreshMode::Slow10s => RefreshMode::Paused,
            RefreshMode::Paused => RefreshMode::Fast3s,
        }
    }

    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            RefreshMode::Fast3s => "Auto: 3s",
            RefreshMode::Slow10s => "Auto: 10s",
            RefreshMode::Paused => "Paused",
        }
    }

    #[must_use]
    pub fn duration(&self) -> Option<Duration> {
        match self {
            RefreshMode::Fast3s => Some(Duration::from_secs(3)),
            RefreshMode::Slow10s => Some(Duration::from_secs(10)),
            RefreshMode::Paused => None,
        }
    }
}

pub struct App {
    /// `None` while a scan runs on its own thread.
    engine: Option<ScannerEngine>,
    scan_rx: Option<mpsc::Receiver<(ScannerEngine, ScanSnapshot)>>,
    flight_recorder: FlightRecorder,
    allowlist: Allowlist,
    allowlist_path: PathBuf,
    /// Listener keys seen when the TUI started. A listener outside this set is new.
    baseline_listeners: HashSet<String>,
    pub new_listeners: HashSet<String>,
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
    pub event_table_state: TableState,

    pub(crate) conn_indices: Vec<usize>,
    pub(crate) finding_indices: Vec<usize>,
    pub(crate) audit_indices: Vec<usize>,
    pub(crate) proc_indices: Vec<usize>,
    pub(crate) event_indices: Vec<usize>,
    needs_redraw: bool,
}

impl App {
    #[cfg(test)]
    pub fn new(engine: ScannerEngine, initial_snapshot: ScanSnapshot) -> Self {
        Self::with_options(
            engine,
            initial_snapshot,
            Allowlist::default(),
            PathBuf::from("safe_door_allowlist.json"),
        )
    }

    pub fn with_options(
        engine: ScannerEngine,
        mut initial_snapshot: ScanSnapshot,
        allowlist: Allowlist,
        allowlist_path: PathBuf,
    ) -> Self {
        let mut flight_recorder = FlightRecorder::new();
        flight_recorder.observe(&mut initial_snapshot);
        allowlist.apply(&mut initial_snapshot);

        let mut app = Self {
            engine: Some(engine),
            scan_rx: None,
            flight_recorder,
            allowlist,
            allowlist_path,
            baseline_listeners: listener_keys(&initial_snapshot),
            new_listeners: HashSet::new(),
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
            conn_table_state: TableState::default(),
            finding_table_state: TableState::default(),
            audit_table_state: TableState::default(),
            proc_table_state: TableState::default(),
            event_table_state: TableState::default(),
            conn_indices: Vec::new(),
            finding_indices: Vec::new(),
            audit_indices: Vec::new(),
            proc_indices: Vec::new(),
            event_indices: Vec::new(),
            needs_redraw: true,
        };
        app.rebuild_views();
        app
    }

    pub fn mark_redraw(&mut self) {
        self.needs_redraw = true;
    }

    pub fn take_redraw(&mut self) -> bool {
        let flag = self.needs_redraw;
        self.needs_redraw = false;
        flag
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now()));
        self.needs_redraw = true;
    }

    #[must_use]
    pub fn is_scanning(&self) -> bool {
        self.engine.is_none()
    }

    /// Start a scan on its own thread so the UI keeps answering keys. No-op if one is running.
    pub fn trigger_scan(&mut self) {
        let Some(mut engine) = self.engine.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.scan_rx = Some(rx);
        self.needs_redraw = true;
        thread::spawn(move || {
            let snapshot = engine.perform_scan();
            let _ = tx.send((engine, snapshot));
        });
    }

    fn poll_scan(&mut self) {
        let Some(rx) = &self.scan_rx else { return };
        match rx.try_recv() {
            Ok((engine, mut snapshot)) => {
                self.engine = Some(engine);
                self.scan_rx = None;
                let events = self.flight_recorder.observe(&mut snapshot);
                self.allowlist.apply(&mut snapshot);
                self.new_listeners = listener_keys(&snapshot)
                    .difference(&self.baseline_listeners)
                    .cloned()
                    .collect();
                self.set_status(format!(
                    "Scan completed in {} ms | {} new listener(s) | +{} event(s)",
                    snapshot.scan_duration_ms,
                    self.new_listeners.len(),
                    events.len()
                ));
                self.snapshot = snapshot;
                self.last_scan_instant = Instant::now();
                self.rebuild_views();
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.engine = Some(ScannerEngine::new());
                self.scan_rx = None;
                self.last_scan_instant = Instant::now();
                self.set_status("Scan thread failed; engine restarted");
            }
        }
    }

    pub fn on_tick(&mut self) {
        self.poll_scan();
        if let Some((_, ts)) = &self.status_message {
            if ts.elapsed() > Duration::from_secs(5) {
                self.status_message = None;
                self.needs_redraw = true;
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
        let sarif_path = Path::new("safe_door_report.sarif.json");
        match (
            export_json_report(&self.snapshot, json_path),
            export_markdown_report(&self.snapshot, md_path),
            export_sarif_report(&self.snapshot, sarif_path),
        ) {
            (Ok(()), Ok(()), Ok(())) => {
                self.set_status(
                    "Saved safe_door_report.{json,md,sarif.json}",
                );
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                self.set_status(format!("Export error: {}", e));
            }
        }
    }

    /// Adds a cryptographic SHA-256 suppression rule for the currently selected item (`[w]` key)
    /// and persists it to `self.allowlist_path`.
    pub fn allowlist_selected(&mut self) {
        let candidate: Option<(String, Option<String>, Option<u16>, String)> = match self.active_tab
        {
            ActiveTab::Connections => self
                .conn_table_state
                .selected()
                .and_then(|i| self.conn_indices.get(i))
                .and_then(|&idx| self.snapshot.connections.get(idx))
                .and_then(|c| {
                    let sha = c.sha256.clone()?;
                    let port = c.is_listening().then_some(c.local_port);
                    Some((
                        sha,
                        None,
                        port,
                        format!("TUI allowlist: {}", c.process_name),
                    ))
                }),
            ActiveTab::Findings => self
                .finding_table_state
                .selected()
                .and_then(|i| self.finding_indices.get(i))
                .and_then(|&idx| self.snapshot.findings.get(idx))
                .and_then(|f| {
                    let pid = f.pid?;
                    let sha = self
                        .snapshot
                        .processes
                        .iter()
                        .find(|p| p.pid == pid)
                        .and_then(|p| p.sha256.clone())?;
                    Some((
                        sha,
                        Some(f.rule_id.clone()),
                        None,
                        format!("TUI allowlist: {} ({})", f.rule_id, f.title),
                    ))
                }),
            ActiveTab::Processes => self
                .proc_table_state
                .selected()
                .and_then(|i| self.proc_indices.get(i))
                .and_then(|&idx| self.snapshot.processes.get(idx))
                .and_then(|p| {
                    let sha = p.sha256.clone()?;
                    Some((sha, None, None, format!("TUI allowlist: {}", p.name)))
                }),
            _ => {
                self.set_status("Select a row in Connections, Findings, or Processes to allowlist");
                return;
            }
        };

        let Some((sha256, rule_id, local_port, reason)) = candidate else {
            self.set_status(
                "Cannot allowlist: selected item has no on-disk binary SHA-256 digest",
            );
            return;
        };

        let short_sha = sha256[..12.min(sha256.len())].to_string();
        match self.allowlist.upsert_rule(AllowlistRule {
            sha256,
            rule_id,
            local_port,
            reason,
        }) {
            Ok(inserted) => {
                if let Err(e) = self.allowlist.save(&self.allowlist_path) {
                    self.set_status(format!("Allowlist save failed: {e}"));
                    return;
                }
                let suppressed = self.allowlist.apply(&mut self.snapshot);
                self.rebuild_views();
                if inserted {
                    self.set_status(format!(
                        "Allowlisted SHA-256 {short_sha}... ({suppressed} finding(s) suppressed) -> {}",
                        self.allowlist_path.display()
                    ));
                } else {
                    self.set_status(format!("SHA-256 {short_sha}... is already allowlisted"));
                }
            }
            Err(e) => self.set_status(e),
        }
    }

    /// Recomputes cached filtered/sorted index vectors once on state changes so render frames
    /// perform zero sorting and zero lowercase heap allocations.
    pub fn rebuild_views(&mut self) {
        let q = self.search_query.trim().to_lowercase();
        let mut num_buf = String::with_capacity(12);

        self.conn_indices.clear();
        for (idx, c) in self.snapshot.connections.iter().enumerate() {
            let filter_ok = match self.conn_filter {
                ConnFilter::All => true,
                ConnFilter::Listening => c.is_listening(),
                ConnFilter::Established => c.is_established(),
                ConnFilter::ExternalIp => c.remote_category == IpCategory::PublicInternet,
                ConnFilter::FlaggedOnly => c.severity >= Severity::Low,
            };
            if !filter_ok {
                continue;
            }
            if !q.is_empty() {
                num_buf.clear();
                use std::fmt::Write as _;
                let _ = write!(&mut num_buf, "{}", c.local_port);
                let pid_match = c.pid.is_some_and(|p| {
                    let mut pbuf = String::with_capacity(10);
                    let _ = write!(&mut pbuf, "{p}");
                    pbuf.contains(&q)
                });
                let matches = contains_ci(&c.process_name, &q)
                    || num_buf.contains(&q)
                    || contains_ci(&c.service_name, &q)
                    || contains_ci(&c.state, &q)
                    || contains_ci(&c.exe_path, &q)
                    || contains_ci(c.exposure.short_label(), &q)
                    || pid_match
                    || contains_ci(&c.local_endpoint(), &q)
                    || contains_ci(&c.remote_display(), &q);
                if !matches {
                    continue;
                }
            }
            self.conn_indices.push(idx);
        }

        let conns = &self.snapshot.connections;
        match self.conn_sort {
            ConnSort::RiskDesc => {
                self.conn_indices.sort_by(|&ia, &ib| {
                    let (a, b) = (&conns[ia], &conns[ib]);
                    b.severity
                        .cmp(&a.severity)
                        .then_with(|| b.is_listening().cmp(&a.is_listening()))
                        .then_with(|| a.local_port.cmp(&b.local_port))
                });
            }
            ConnSort::LocalPortAsc => {
                self.conn_indices
                    .sort_by(|&ia, &ib| conns[ia].local_port.cmp(&conns[ib].local_port));
            }
            ConnSort::ProcessAsc => {
                self.conn_indices.sort_by(|&ia, &ib| {
                    let (a, b) = (&conns[ia], &conns[ib]);
                    cmp_ci(&a.process_name, &b.process_name)
                        .then_with(|| a.local_port.cmp(&b.local_port))
                });
            }
            ConnSort::StateAsc => {
                self.conn_indices.sort_by(|&ia, &ib| {
                    let (a, b) = (&conns[ia], &conns[ib]);
                    a.state
                        .cmp(&b.state)
                        .then_with(|| a.local_port.cmp(&b.local_port))
                });
            }
            ConnSort::PidAsc => {
                self.conn_indices.sort_by(|&ia, &ib| {
                    conns[ia]
                        .pid
                        .unwrap_or(u32::MAX)
                        .cmp(&conns[ib].pid.unwrap_or(u32::MAX))
                });
            }
        }

        self.finding_indices.clear();
        for (idx, f) in self.snapshot.findings.iter().enumerate() {
            if q.is_empty()
                || contains_ci(&f.title, &q)
                || contains_ci(&f.category, &q)
                || contains_ci(&f.rule_id, &q)
                || contains_ci(&f.description, &q)
                || contains_ci(&f.evidence, &q)
            {
                self.finding_indices.push(idx);
            }
        }

        self.audit_indices.clear();
        for (idx, a) in self.snapshot.audit_items.iter().enumerate() {
            if q.is_empty()
                || contains_ci(&a.name, &q)
                || contains_ci(&a.subsystem, &q)
                || contains_ci(&a.location, &q)
                || contains_ci(&a.value, &q)
                || contains_ci(&a.details, &q)
            {
                self.audit_indices.push(idx);
            }
        }

        self.proc_indices.clear();
        for (idx, p) in self.snapshot.processes.iter().enumerate() {
            if q.is_empty() {
                self.proc_indices.push(idx);
                continue;
            }
            num_buf.clear();
            use std::fmt::Write as _;
            let _ = write!(&mut num_buf, "{}", p.pid);
            if contains_ci(&p.name, &q)
                || num_buf.contains(&q)
                || contains_ci(&p.exe_path, &q)
                || contains_ci(&p.cmdline, &q)
                || p.sha256.as_deref().is_some_and(|h| contains_ci(h, &q))
                || p.original_filename
                    .as_deref()
                    .is_some_and(|o| contains_ci(o, &q))
            {
                self.proc_indices.push(idx);
            }
        }

        self.event_indices.clear();
        for (idx, ev) in self.snapshot.timeline_events.iter().enumerate() {
            if q.is_empty()
                || contains_ci(ev.kind.label(), &q)
                || contains_ci(&ev.process_name, &q)
                || contains_ci(&ev.endpoint, &q)
                || contains_ci(&ev.summary, &q)
            {
                self.event_indices.push(idx);
            }
        }

        self.clamp_selections();
        self.needs_redraw = true;
    }

    pub fn move_selection_down(&mut self, step: usize) {
        match self.active_tab {
            ActiveTab::Overview => {
                self.active_tab = ActiveTab::Connections;
            }
            ActiveTab::Connections => {
                advance_table(&mut self.conn_table_state, self.conn_indices.len(), step, true);
            }
            ActiveTab::Findings => {
                advance_table(
                    &mut self.finding_table_state,
                    self.finding_indices.len(),
                    step,
                    true,
                );
            }
            ActiveTab::Audit => {
                advance_table(&mut self.audit_table_state, self.audit_indices.len(), step, true);
            }
            ActiveTab::Processes => {
                advance_table(&mut self.proc_table_state, self.proc_indices.len(), step, true);
            }
            ActiveTab::Events => {
                advance_table(&mut self.event_table_state, self.event_indices.len(), step, true);
            }
        }
        self.needs_redraw = true;
    }

    pub fn move_selection_up(&mut self, step: usize) {
        match self.active_tab {
            ActiveTab::Overview => {}
            ActiveTab::Connections => {
                advance_table(&mut self.conn_table_state, self.conn_indices.len(), step, false);
            }
            ActiveTab::Findings => {
                advance_table(
                    &mut self.finding_table_state,
                    self.finding_indices.len(),
                    step,
                    false,
                );
            }
            ActiveTab::Audit => {
                advance_table(&mut self.audit_table_state, self.audit_indices.len(), step, false);
            }
            ActiveTab::Processes => {
                advance_table(&mut self.proc_table_state, self.proc_indices.len(), step, false);
            }
            ActiveTab::Events => {
                advance_table(&mut self.event_table_state, self.event_indices.len(), step, false);
            }
        }
        self.needs_redraw = true;
    }

    pub fn clamp_selections(&mut self) {
        clamp_table(&mut self.conn_table_state, self.conn_indices.len());
        clamp_table(&mut self.finding_table_state, self.finding_indices.len());
        clamp_table(&mut self.audit_table_state, self.audit_indices.len());
        clamp_table(&mut self.proc_table_state, self.proc_indices.len());
        clamp_table(&mut self.event_table_state, self.event_indices.len());
    }
}

fn listener_keys(snapshot: &ScanSnapshot) -> HashSet<String> {
    snapshot
        .connections
        .iter()
        .filter(|c| c.is_listening())
        .map(socket_key)
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ConnectionEntry, ExposureScope, ProcessRecord, Protocol, SecurityFinding};
    use chrono::Local;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn allowlist_selected_persists_rule_and_updates_cached_views() {
        let dir = std::env::temp_dir().join(format!("unlatched_app_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let allow_path = dir.join("allow.json");

        let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let conn = ConnectionEntry {
            id: 1,
            protocol: Protocol::Tcp,
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 4444,
            remote_ip: None,
            remote_port: None,
            remote_hostname: None,
            state: "LISTEN".to_string(),
            pid: Some(55),
            process_name: "lab_tool".to_string(),
            exe_path: "/opt/lab_tool".to_string(),
            cmdline: "/opt/lab_tool".to_string(),
            sha256: Some(sha.to_string()),
            lineage: Vec::new(),
            service_name: "Metasploit/C2".to_string(),
            exposure: ExposureScope::WildcardAllInterfaces,
            remote_category: IpCategory::Unspecified,
            severity: Severity::Critical,
            risk_reasons: vec!["Port 4444".to_string()],
        };
        let proc_rec = ProcessRecord {
            pid: 55,
            ppid: None,
            name: "lab_tool".to_string(),
            exe_path: "/opt/lab_tool".to_string(),
            cmdline: "/opt/lab_tool".to_string(),
            user: "u".to_string(),
            sha256: Some(sha.to_string()),
            original_filename: None,
            lineage: Vec::new(),
            cpu_usage: 0.0,
            memory_bytes: 0,
            run_time_secs: 0,
            exe_exists_on_disk: true,
            is_deleted_binary: false,
            open_sockets_count: 1,
            max_severity: Severity::Critical,
        };
        let finding = SecurityFinding {
            rule_id: "H05-BACKDOOR-PORT".to_string(),
            category: "Suspicious Port".to_string(),
            mitre_id: "T1571".to_string(),
            severity: Severity::Critical,
            title: "Port 4444".to_string(),
            description: "Test".to_string(),
            pid: Some(55),
            process_name: Some("lab_tool".to_string()),
            endpoint: Some("0.0.0.0:4444".to_string()),
            evidence: "0.0.0.0:4444".to_string(),
            remediation: "None".to_string(),
        };
        let mut snap = ScanSnapshot {
            timestamp: Local::now(),
            scan_duration_ms: 1,
            hostname: "h".to_string(),
            os_name: "os".to_string(),
            os_version: "1".to_string(),
            kernel_version: "1".to_string(),
            is_elevated: true,
            security_score: 70,
            security_grade: "C".to_string(),
            scan_warnings: Vec::new(),
            sockets_without_exe: 0,
            suppressed_count: 0,
            total_connections: 1,
            listening_ports: 1,
            established_connections: 0,
            external_connections: 0,
            suspicious_connections: 1,
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            connections: vec![conn],
            findings: vec![finding],
            audit_items: Vec::new(),
            processes: vec![proc_rec],
            timeline_events: Vec::new(),
        };
        snap.recompute_summary();

        let mut app = App::with_options(
            ScannerEngine::new(),
            snap,
            Allowlist::default(),
            allow_path.clone(),
        );
        app.active_tab = ActiveTab::Findings;
        assert_eq!(app.finding_indices.len(), 1);
        app.allowlist_selected();
        assert!(app.finding_indices.is_empty());
        assert_eq!(app.snapshot.suppressed_count, 1);
        assert!(allow_path.is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
