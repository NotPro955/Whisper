#![allow(dead_code)]

mod constants;
mod crypto;
mod protocol;
mod scanner;
mod client;
mod google_api;
mod hci;

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bluer::{Adapter, Address, Session};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use tokio::sync::{mpsc, Mutex};

use scanner::{FastPairDevice, find_fast_pair_devices};
use client::{FastPairClient, VerificationResult};
use constants::get_device_name;

const C_BG: Color        = Color::Rgb(10,  14,  26);
const C_BG2: Color       = Color::Rgb(16,  22,  38);
const C_BORDER: Color    = Color::Rgb(40,  60, 100);
const C_FOCUS: Color     = Color::Rgb(80, 140, 220);
const C_TEXT: Color      = Color::Rgb(190, 210, 240);
const C_DIM: Color       = Color::Rgb(80, 100, 130);
const C_CYAN: Color      = Color::Rgb(80, 200, 220);
const C_RED: Color       = Color::Rgb(220,  60,  60);
const C_GREEN: Color     = Color::Rgb(60,  200, 100);
const C_YELLOW: Color    = Color::Rgb(220, 180,  40);
const C_ORANGE: Color    = Color::Rgb(220, 120,  40);
const C_PURPLE: Color    = Color::Rgb(160, 100, 220);

#[derive(Debug, Clone, PartialEq)]
enum ScanState { Idle, Scanning, Done }

#[derive(Debug, Clone, PartialEq)]
enum VerifyState { Idle, Running, Done }

#[derive(Debug, Clone)]
struct DeviceEntry {
    device: FastPairDevice,
    verify_state: VerifyState,
    result: Option<VerificationResult>,
}

#[derive(Debug, Clone, PartialEq)]
enum Focus { List, Detail }

#[derive(Debug)]
enum AppEvent {
    ScanComplete(Vec<FastPairDevice>),
    VerifyComplete(Address, VerificationResult),
    Tick,
}

struct App {
    devices: Vec<DeviceEntry>,
    list_state: ListState,
    scan_state: ScanState,
    log: Vec<(String, Color)>,
    focus: Focus,
    detail_scroll: u16,
    scan_start: Option<Instant>,
    spinner: usize,
    status: String,
    show_help: bool,
}

impl App {
    fn new() -> Self {
        Self {
            devices: vec![],
            list_state: ListState::default(),
            scan_state: ScanState::Idle,
            log: vec![
                ("WhisperPair TUI  ·  CVE-2025-36911".into(), C_CYAN),
                ("──────────────────────────────────".into(), C_BORDER),
                ("S  scan        V  verify selected".into(), C_DIM),
                ("A  verify all  ?  help  Q  quit".into(), C_DIM),
            ],
            focus: Focus::List,
            detail_scroll: 0,
            scan_start: None,
            spinner: 0,
            status: "Ready".into(),
            show_help: false,
        }
    }

    fn selected(&self) -> Option<&DeviceEntry> {
        self.list_state.selected().and_then(|i| self.devices.get(i))
    }

    fn log(&mut self, msg: impl Into<String>, color: Color) {
        self.log.push((msg.into(), color));
    }

    fn next(&mut self) {
        if self.devices.is_empty() { return; }
        let i = self.list_state.selected().map(|i| (i + 1) % self.devices.len()).unwrap_or(0);
        self.list_state.select(Some(i));
        self.detail_scroll = 0;
    }

    fn prev(&mut self) {
        if self.devices.is_empty() { return; }
        let i = self.list_state.selected().map(|i| {
            if i == 0 { self.devices.len() - 1 } else { i - 1 }
        }).unwrap_or(0);
        self.list_state.select(Some(i));
        self.detail_scroll = 0;
    }

    fn tick(&mut self) {
        self.spinner = (self.spinner + 1) % 8;
    }

    fn scan_elapsed(&self) -> f32 {
        self.scan_start.map(|s| s.elapsed().as_secs_f32()).unwrap_or(0.0)
    }
}

const SPIN: [&str; 8] = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧"];

fn sp(app: &App) -> &'static str { SPIN[app.spinner] }

fn s(fg: Color) -> Style { Style::default().fg(fg) }
fn sb(fg: Color) -> Style { Style::default().fg(fg).add_modifier(Modifier::BOLD) }
fn sbg(fg: Color, bg: Color) -> Style { Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD) }

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() }
    else { format!("{}…", s.chars().take(max - 1).collect::<String>()) }
}

fn kv(label: &str, val: impl Into<String>, col: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {:14}", label), s(C_DIM)),
        Span::styled(val.into(), s(col)),
    ])
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.size();
    f.render_widget(Block::default().style(Style::default().bg(C_BG)), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    draw_header(f, rows[0], app);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(rows[1]);

    draw_list(f, cols[0], app);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(cols[1]);

    draw_detail(f, right[0], app);
    draw_log(f, right[1], app);
    draw_bar(f, rows[2], app);

    if app.show_help { draw_help(f, area); }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let left_spans = Line::from(vec![
        Span::styled("  WHISPERPAIR ", sb(C_CYAN)),
        Span::styled("TUI", s(C_DIM)),
        Span::styled("  ·  ", s(C_BORDER)),
        Span::styled("CVE-2025-36911", sb(C_ORANGE)),
        Span::styled("  ·  Fast Pair Security Research", s(C_DIM)),
    ]);

    let right_spans = match &app.scan_state {
        ScanState::Idle     => Line::from(Span::styled("idle  ", s(C_DIM))),
        ScanState::Scanning => Line::from(vec![
            Span::styled(sp(app), s(C_YELLOW)),
            Span::styled(format!(" scanning  {:.1}s  ", app.scan_elapsed()), s(C_YELLOW)),
        ]),
        ScanState::Done     => Line::from(vec![
            Span::styled("✓ ", s(C_GREEN)),
            Span::styled(format!("{} device(s)  ", app.devices.len()), s(C_GREEN)),
        ]),
    };

    let hcols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(28)])
        .split(area);

    let blk = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(s(C_BORDER))
        .style(Style::default().bg(C_BG));

    f.render_widget(Paragraph::new(left_spans).block(blk.clone()).style(Style::default().bg(C_BG)), hcols[0]);
    f.render_widget(Paragraph::new(right_spans).block(blk).alignment(Alignment::Right).style(Style::default().bg(C_BG)), hcols[1]);
}

fn draw_list(f: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::List;
    let bc = if focused { C_FOCUS } else { C_BORDER };

    let blk = Block::default()
        .title(Line::from(vec![
            Span::styled(" DEVICES ", sb(C_CYAN)),
            Span::styled(format!("[{}] ", app.devices.len()), s(C_DIM)),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(s(bc))
        .style(Style::default().bg(C_BG2));

    if app.devices.is_empty() {
        let hint = match app.scan_state {
            ScanState::Idle     => "Press S to scan",
            ScanState::Scanning => "Scanning…",
            ScanState::Done     => "No devices found",
        };
        f.render_widget(
            Paragraph::new(hint).block(blk).alignment(Alignment::Center).style(s(C_DIM).bg(C_BG2)),
            area,
        );
        return;
    }

    let items: Vec<ListItem> = app.devices.iter().map(|e| {
        let d = &e.device;
        let dot = match &e.result {
            Some(r) if  r.success => Span::styled("● ", s(C_RED)),
            Some(r) if !r.success => Span::styled("● ", s(C_GREEN)),
            _ => match e.verify_state {
                VerifyState::Running => Span::styled("◌ ", s(C_YELLOW)),
                _                   => Span::styled("○ ", s(C_DIM)),
            },
        };
        let badge = if d.is_in_pairing_mode {
            Span::styled("[PAIR] ", s(C_PURPLE))
        } else {
            Span::styled("[IDLE] ", s(C_ORANGE))
        };
        let name  = Span::styled(trunc(&d.display_name(), 18), sb(C_TEXT));
        let addr  = Span::styled(format!("  {}", d.address_str()), s(C_DIM));
        let rssi  = d.rssi.map(|r| format!(" {}dBm", r)).unwrap_or_default();
        let rssi  = Span::styled(rssi, s(C_DIM));

        ListItem::new(vec![
            Line::from(vec![dot, badge, name]),
            Line::from(vec![addr, rssi]),
        ])
    }).collect();

    let list = List::new(items)
        .block(blk)
        .highlight_style(Style::default().bg(Color::Rgb(25, 40, 70)).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_detail(f: &mut Frame, area: Rect, app: &App) {
    let bc = if app.focus == Focus::Detail { C_FOCUS } else { C_BORDER };
    let blk = Block::default()
        .title(Span::styled(" DETAIL ", sb(C_CYAN)))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(s(bc))
        .style(Style::default().bg(C_BG2));

    let Some(e) = app.selected() else {
        f.render_widget(
            Paragraph::new("Select a device").block(blk).alignment(Alignment::Center).style(s(C_DIM).bg(C_BG2)),
            area,
        );
        return;
    };

    let d = &e.device;
    let mut lines: Vec<Line> = vec![];

    let vuln_line = match &e.result {
        Some(r) if  r.success => Line::from(vec![
            Span::styled("  VULNERABLE  ", sbg(Color::White, C_RED)),
            Span::styled("  Responded to KBP outside pairing mode", sb(C_RED)),
        ]),
        Some(r) if !r.success => Line::from(vec![
            Span::styled("  NOT VULNERABLE  ", sbg(Color::Black, C_GREEN)),
            Span::styled("  No KBP response received", sb(C_GREEN)),
        ]),
        _ => match e.verify_state {
            VerifyState::Running => Line::from(vec![
                Span::styled(sp(app), s(C_YELLOW)),
                Span::styled("  Verifying CVE-2025-36911…", s(C_YELLOW)),
            ]),
            _ => Line::from(Span::styled("  Not yet verified — press V", s(C_DIM))),
        },
    };

    lines.push(vuln_line);
    lines.push(Line::from(""));

    lines.push(kv("Name",    &d.display_name(),  C_TEXT));
    lines.push(kv("BLE Addr", &d.address_str(),   C_CYAN));

    let model = d.model_id
        .map(|id| format!("0x{:06X}  {}", id, get_device_name(id)))
        .unwrap_or_else(|| "Unknown".into());
    lines.push(kv("Model", &model, C_TEXT));

    let rssi = d.rssi.map(|r| format!("{} dBm", r)).unwrap_or_else(|| "N/A".into());
    lines.push(kv("RSSI", &rssi, C_TEXT));

    let (mode_str, mode_col) = if d.is_in_pairing_mode {
        ("PAIRING MODE", C_PURPLE)
    } else {
        ("Idle / Paired", C_ORANGE)
    };
    lines.push(kv("Mode", mode_str, mode_col));

    let (tgt_str, tgt_col) = if !d.is_in_pairing_mode {
        ("Yes — candidate for CVE-2025-36911", C_ORANGE)
    } else {
        ("No — device is in pairing mode", C_DIM)
    };
    lines.push(kv("CVE Target", tgt_str, tgt_col));

    if let Some(r) = &e.result {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "── Verification Result ────────────────────",
            s(C_BORDER),
        )));

        lines.push(kv("Method", r.method_used.to_string(), C_CYAN));
        lines.push(kv("Attempts", r.attempts.to_string(), C_DIM));

        if let Some(ref info) = r.anti_spoofing_info {
            if let Some(ref name) = info.device_name {
                lines.push(kv("Google Name", name.clone(), C_TEXT));
            }
        }

        if let Some(ref strategy) = r.strategy_used {
            lines.push(kv("Strategy", strategy.clone(), C_DIM));
        }

        let (resp_str, resp_col) = if r.response_received {
            ("Yes — device replied to KBP request", C_RED)
        } else {
            ("No — device was silent", C_GREEN)
        };
        lines.push(kv("KBP Response", resp_str, resp_col));

        if let Some(ref diag) = r.hci_diagnostic {
            if let Some((code, ref name)) = diag.att_error {
                lines.push(kv("HCI ATT Error", format!("0x{:02X} — {}", code, name), C_YELLOW));
            }
            if diag.disconnected {
                lines.push(kv("HCI Disconnect", "device dropped connection", C_ORANGE));
            }
            for (i, n) in diag.raw_notifications.iter().enumerate() {
                lines.push(kv(
                    format!("HCI Notify[{}]", i).as_str(),
                    hex::encode(n),
                    C_DIM,
                ));
            }
        }

        if let Some(addr) = &r.provider_address {
            let addr_owned = addr.clone();
            let oui_full = addr_owned.replace(":", "");
            let oui = oui_full[..6.min(oui_full.len())].to_string();
            let oui_line = format!("{} → macvendors.com/{}", oui, oui);
            lines.push(kv("BR/EDR Addr", addr_owned, C_RED));
            lines.push(kv("OUI", oui_line, C_DIM));
        }

        if let Some(raw) = &r.raw_response {
            lines.push(kv("Raw (hex)", hex::encode(raw), C_DIM));
        }

        if let Some(err) = &r.error {
            lines.push(kv("Note", err.clone(), C_YELLOW));
        }
    }

    f.render_widget(
        Paragraph::new(lines)
            .block(blk)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0)),
        area,
    );
}

fn draw_log(f: &mut Frame, area: Rect, app: &App) {
    let bc = if app.focus == Focus::Detail { C_FOCUS } else { C_BORDER };
    let blk = Block::default()
        .title(Span::styled(" LOG ", sb(C_CYAN)))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(s(bc))
        .style(Style::default().bg(C_BG2));

    let inner_h = area.height.saturating_sub(2) as usize;
    let start = app.log.len().saturating_sub(inner_h);
    let lines: Vec<Line> = app.log[start..]
        .iter()
        .map(|(msg, col)| Line::from(Span::styled(format!("  {}", msg), s(*col))))
        .collect();

    f.render_widget(Paragraph::new(lines).block(blk).style(Style::default().bg(C_BG2)), area);
}

fn draw_bar(f: &mut Frame, area: Rect, app: &App) {
    let keys: &[(&str, &str)] = &[
        (" S ", "Scan"),
        (" V ", "Verify"),
        (" A ", "All"),
        (" Tab ", "Pane"),
        (" ↑↓ ", "Nav"),
        (" PgUp/Dn ", "Scroll"),
        (" ? ", "Help"),
        (" Q ", "Quit"),
    ];

    let mut spans: Vec<Span> = vec![];
    for (key, label) in keys {
        spans.push(Span::styled(*key, sbg(Color::White, C_FOCUS)));
        spans.push(Span::styled(format!(" {} ", label), s(C_DIM)));
        spans.push(Span::styled("  ", Style::default()));
    }

    let stat = Span::styled(format!("  {}", app.status), s(C_DIM));

    let bcols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(32)])
        .split(area);

    f.render_widget(Paragraph::new(Line::from(spans)).style(Style::default().bg(C_BG)), bcols[0]);
    f.render_widget(Paragraph::new(Line::from(stat)).alignment(Alignment::Right).style(Style::default().bg(C_BG)), bcols[1]);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let w = 52u16;
    let h = 22u16;
    let x = area.width.saturating_sub(w) / 2;
    let y = area.height.saturating_sub(h) / 2;
    let popup = Rect::new(x, y, w.min(area.width), h.min(area.height));

    let row = |key: &'static str, desc: &'static str| -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("  {:12}", key), sb(C_CYAN)),
            Span::styled(desc, s(C_TEXT)),
        ])
    };

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled("  KEYBINDINGS", sb(C_CYAN))),
        Line::from(Span::styled("  ────────────────────────────────────", s(C_BORDER))),
        row("S",          "Scan for nearby Fast Pair devices"),
        row("V",          "Verify selected device"),
        row("A",          "Verify all scanned devices"),
        row("Tab",        "Switch focus between panes"),
        row("↑ / K",      "Move selection up"),
        row("↓ / J",      "Move selection down"),
        row("PgUp",       "Scroll detail panel up"),
        row("PgDn",       "Scroll detail panel down"),
        row("?",          "Toggle this help overlay"),
        row("Q / Ctrl+C", "Quit"),
        Line::from(""),
        Line::from(Span::styled("  LEGEND", sb(C_CYAN))),
        Line::from(Span::styled("  ────────────────────────────────────", s(C_BORDER))),
        Line::from(vec![
            Span::styled("  ● ", s(C_RED)),   Span::styled("Vulnerable    ", s(C_TEXT)),
            Span::styled("● ",  s(C_GREEN)),  Span::styled("Not vulnerable", s(C_TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  ◌ ", s(C_YELLOW)), Span::styled("Verifying     ", s(C_TEXT)),
            Span::styled("○ ",  s(C_DIM)),     Span::styled("Not tested",     s(C_TEXT)),
        ]),
        Line::from(""),
    ];

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default()
                .title(Span::styled(" HELP ", sb(C_CYAN)))
                .borders(Borders::ALL)
                .border_style(s(C_FOCUS))
                .style(Style::default().bg(Color::Rgb(12, 18, 32))))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

async fn do_scan(adapter: Arc<Mutex<Adapter>>, tx: mpsc::UnboundedSender<AppEvent>) {
    let adapter = adapter.lock().await;
    match find_fast_pair_devices(&adapter, 8.0).await {
        Ok(d) => { let _ = tx.send(AppEvent::ScanComplete(d)); }
        Err(_) => { let _ = tx.send(AppEvent::ScanComplete(vec![])); }
    }
}

async fn do_verify(adapter: Arc<Mutex<Adapter>>, address: Address, tx: mpsc::UnboundedSender<AppEvent>) {
    let guard = adapter.lock().await;
    let client = FastPairClient::new(
        guard.clone(), address,
        Some(Duration::from_secs(10)),
        Some(Duration::from_secs(5)),
    );
    drop(guard);
    let result = client.verify_pairing_behavior(None, None).await;
    let _ = tx.send(AppEvent::VerifyComplete(address, result));
}

#[tokio::main]
async fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let session = Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;
    let adapter = Arc::new(Mutex::new(adapter));

    let mut app = App::new();
    let (tx, mut rx) = mpsc::unbounded_channel::<AppEvent>();

    let tick_tx = tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if tick_tx.send(AppEvent::Tick).is_err() { break; }
        }
    });

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if event::poll(Duration::ZERO)? {
            match event::read()? {
                Event::Key(k) => match k.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('?') => { app.show_help = !app.show_help; }
                    KeyCode::Tab => {
                        app.focus = if app.focus == Focus::List { Focus::Detail } else { Focus::List };
                    }
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => app.next(),
                    KeyCode::Up   | KeyCode::Char('k') | KeyCode::Char('K') => app.prev(),
                    KeyCode::PageDown => { app.detail_scroll = app.detail_scroll.saturating_add(3); }
                    KeyCode::PageUp   => { app.detail_scroll = app.detail_scroll.saturating_sub(3); }

                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        if app.scan_state != ScanState::Scanning {
                            app.scan_state = ScanState::Scanning;
                            app.scan_start = Some(Instant::now());
                            app.devices.clear();
                            app.list_state = ListState::default();
                            app.status = "Scanning…".into();
                            app.log("Scan started (8s)", C_YELLOW);
                            tokio::spawn(do_scan(Arc::clone(&adapter), tx.clone()));
                        }
                    }

                    KeyCode::Char('v') | KeyCode::Char('V') => {
                        if let Some(i) = app.list_state.selected() {
                            if let Some(e) = app.devices.get_mut(i) {
                                if e.verify_state != VerifyState::Running {
                                    let addr = e.device.address;
                                    e.verify_state = VerifyState::Running;
                                    e.result = None;
                                    app.log(format!("Verifying {}…", addr), C_YELLOW);
                                    app.status = format!("Verifying {}…", addr);
                                    tokio::spawn(do_verify(Arc::clone(&adapter), addr, tx.clone()));
                                }
                            }
                        } else {
                            app.status = "Select a device first".into();
                        }
                    }

                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        let addrs: Vec<Address> = app.devices.iter()
                            .filter(|e| e.verify_state != VerifyState::Running)
                            .map(|e| e.device.address)
                            .collect();
                        if addrs.is_empty() {
                            app.status = "No devices to verify".into();
                        } else {
                            app.log(format!("Verifying {} device(s)…", addrs.len()), C_YELLOW);
                            app.status = format!("Verifying {} device(s)…", addrs.len());
                            for e in app.devices.iter_mut() {
                                if e.verify_state != VerifyState::Running {
                                    e.verify_state = VerifyState::Running;
                                    e.result = None;
                                }
                            }
                            for addr in addrs {
                                tokio::spawn(do_verify(Arc::clone(&adapter), addr, tx.clone()));
                            }
                        }
                    }

                    _ => {}
                },
                _ => {}
            }
        }

        while let Ok(evt) = rx.try_recv() {
            match evt {
                AppEvent::Tick => app.tick(),

                AppEvent::ScanComplete(devices) => {
                    app.scan_state = ScanState::Done;
                    app.scan_start = None;
                    app.log(format!("Scan complete — {} device(s)", devices.len()), C_GREEN);
                    app.status = format!("{} device(s) found", devices.len());
                    app.devices = devices.into_iter().map(|d| DeviceEntry {
                        device: d, verify_state: VerifyState::Idle, result: None,
                    }).collect();
                    if !app.devices.is_empty() { app.list_state.select(Some(0)); }
                }

                AppEvent::VerifyComplete(addr, result) => {
                    let vuln = result.success;
                    let msg = if vuln {
                        format!("VULNERABLE  {} — responded to KBP", addr)
                    } else {
                        format!("Safe  {} — no KBP response", addr)
                    };
                    app.log(msg, if vuln { C_RED } else { C_GREEN });
                    app.status = if vuln {
                        format!("{} — VULNERABLE", addr)
                    } else {
                        format!("{} — not vulnerable", addr)
                    };
                    if let Some(e) = app.devices.iter_mut().find(|e| e.device.address == addr) {
                        e.verify_state = VerifyState::Done;
                        e.result = Some(result);
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}
