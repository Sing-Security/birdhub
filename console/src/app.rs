//! The shell — Splicer's layout, Noxgraph's palette: a left icon nav, the
//! page it selects, and a bottom status bar. The pages live in `ui/`; the
//! shell owns the navigation, the poll cadence, and the one action queue
//! every button feeds.

use crate::backend::{Action, Backend};
use crate::data::ConsoleData;
use crate::theme;
use egui::{Align, Layout, RichText};
use std::collections::VecDeque;
use std::time::Duration;

// region:    --- Sections

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Section {
    // Hub pages.
    Fleet,
    Roster,
    // Node pages.
    Status,
    Transports,
    Services,
    Peers,
    // Both.
    Events,
    Config,
    About,
}

impl Section {
    /// The pages a hub shows, in order.
    pub const HUB_NAV: &'static [(Section, &'static str)] = &[
        (Section::Fleet, "Fleet"),
        (Section::Roster, "Roster"),
        (Section::Events, "Events"),
        (Section::Config, "Config"),
        (Section::About, "About"),
    ];

    /// The pages a node shows, in order.
    pub const NODE_NAV: &'static [(Section, &'static str)] = &[
        (Section::Status, "Status"),
        (Section::Transports, "Transports"),
        (Section::Services, "Services"),
        (Section::Peers, "Peers"),
        (Section::Events, "Events"),
        (Section::About, "About"),
    ];

    fn nav(is_hub: bool) -> &'static [(Section, &'static str)] {
        if is_hub {
            Self::HUB_NAV
        } else {
            Self::NODE_NAV
        }
    }
}

// endregion: --- Sections

// region:    --- App

/// One roster row in the editor: free text, so an operator types targets the
/// way they write them in the file; Save parses and validates them through
/// the same path the API's PUT does.
pub struct DraftRow {
    pub client: String,
    pub targets: String,
}

/// The events page's quick filter, Splicer's chips.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventFilter {
    All,
    Sessions,
    Pairing,
    Refusals,
    Listeners,
    Other,
}

impl EventFilter {
    pub const ALL: [EventFilter; 6] = [
        EventFilter::All,
        EventFilter::Sessions,
        EventFilter::Pairing,
        EventFilter::Refusals,
        EventFilter::Listeners,
        EventFilter::Other,
    ];

    pub fn label(self) -> &'static str {
        match self {
            EventFilter::All => "all",
            EventFilter::Sessions => "sessions",
            EventFilter::Pairing => "pairing",
            EventFilter::Refusals => "refusals",
            EventFilter::Listeners => "listeners",
            EventFilter::Other => "other",
        }
    }

    pub fn matches(self, kind: &str) -> bool {
        self == EventFilter::All || self.label() == kind
    }
}

pub struct ConsoleApp {
    backend: Backend,
    /// The pages render this; only the shell writes it. Crate-visible
    /// because the pages live in `ui/`, siblings of this module.
    pub(crate) data: ConsoleData,
    pub(crate) section: Section,
    /// Actions built by buttons, run each frame in order — everything that
    /// mutates the core goes through here, so the screenshots' action test
    /// drives the same path a click does.
    actions: VecDeque<Action>,
    /// Events page state.
    pub(crate) events_search: String,
    pub(crate) events_filter: EventFilter,
    /// Fleet page: the inspected session.
    pub(crate) selected_session: Option<u64>,
    /// Roster page: the editor's rows.
    pub(crate) draft: Vec<DraftRow>,
    /// Time of the last state refresh, in egui time.
    last_refresh: f64,
}

impl ConsoleApp {
    pub fn new(backend: Backend) -> Self {
        let mut app = Self {
            backend,
            data: ConsoleData::empty(),
            section: Section::Fleet,
            actions: VecDeque::new(),
            events_search: String::new(),
            events_filter: EventFilter::All,
            selected_session: None,
            draft: Vec::new(),
            last_refresh: 0.0,
        };
        app.refresh();
        // The first section must exist in the mode's nav; a node opens on
        // Status, a hub on Fleet (the default above).
        if !app.is_hub() {
            app.section = Section::Status;
        }
        app
    }

    fn is_hub(&self) -> bool {
        self.data.mode == "hub"
    }

    /// Pull the core's state now — at startup and after every action batch.
    fn refresh(&mut self) {
        self.backend.refresh(&mut self.data);
    }

    /// Queue an action; it runs on the next frame, before the draw.
    /// Crate-visible: the pages' buttons are the callers.
    pub(crate) fn act(&mut self, action: Action) {
        self.actions.push_back(action);
    }

    // region: --- Fixture controls
    //
    // The screenshot tests build the views from hand-made data and drive the
    // action layer the way a click would. Hidden from the docs; they are the
    // test harness's door, not the operator's.

    /// Replace the view data outright (the fixture backend has no core to
    /// refresh from) and seed the roster editor from it.
    #[doc(hidden)]
    pub fn set_fixture(&mut self, data: ConsoleData) {
        self.draft = data
            .roster
            .iter()
            .map(|row| DraftRow {
                client: row.client.clone(),
                targets: row.targets.join(", "),
            })
            .collect();
        self.data = data;
    }

    /// Jump to a page, the way a nav click would.
    #[doc(hidden)]
    pub fn open_fixture_section(&mut self, section: Section) {
        self.section = section;
    }

    /// Select a fleet row and open the Fleet page.
    #[doc(hidden)]
    pub fn select_fixture_session(&mut self, session_id: u64) {
        self.section = Section::Fleet;
        self.selected_session = Some(session_id);
    }

    /// Edit one editor row's targets.
    #[doc(hidden)]
    pub fn edit_fixture_draft(&mut self, index: usize, targets: &str) {
        self.draft[index].targets = targets.to_string();
    }

    /// Queue a kick for the selected session.
    #[doc(hidden)]
    pub fn kick_fixture_selected(&mut self) {
        if let Some(session_id) = self.selected_session {
            self.act(Action::Kick(session_id));
        }
    }

    /// Queue a roster save from the editor's draft, the way the Save button
    /// does.
    #[doc(hidden)]
    pub fn act_fixture_save(&mut self) {
        let rows: Vec<crate::data::GrantRow> = self
            .draft
            .iter()
            .map(|row| crate::data::GrantRow {
                client: row.client.clone(),
                targets: crate::ui::roster::split_targets_for(&row.targets),
            })
            .collect();
        self.act(Action::SaveRoster(rows));
    }

    /// Run the queued actions now (a frame would).
    #[doc(hidden)]
    pub fn run_fixture_actions(&mut self) {
        self.drain_actions();
    }

    // endregion: --- Fixture controls

    /// Run the queued actions. One refresh after the batch, not per action,
    /// and only when something ran — the poll cadence covers idle frames and
    /// the snapshots allocate, so refreshing per frame would spend every
    /// frame copying state nobody changed.
    fn drain_actions(&mut self) {
        let mut ran = false;
        while let Some(action) = self.actions.pop_front() {
            ran = true;
            match self.backend.apply(&action) {
                Ok(()) => {}
                Err(message) => self.data.last_error = Some(message),
            }
        }
        if ran {
            self.refresh();
        }
    }
}

impl eframe::App for ConsoleApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // The pages paint cards over this; whatever they leave bare must
        // already be the panel colour, not the renderer's clear black.
        ui.painter().rect_filled(ui.max_rect(), 0.0, theme::PANEL);
        // Live state arrives from the core on another thread, not from
        // input — poll, the way Splicer's traffic log does.
        ui.ctx().request_repaint_after(Duration::from_millis(300));
        let now = ui.input(|i| i.time);
        if now - self.last_refresh > 0.3 {
            self.last_refresh = now;
            self.refresh();
        }
        self.drain_actions();

        let nav_width = 150.0;
        let bar_height = 22.0;
        // The status bar's own row costs a spacing gap and a separator on
        // top of its height; reserve all three or the bar lands half below
        // the window edge and the text clips to slivers (the shots showed it).
        let chrome = bar_height + ui.spacing().item_spacing.y + 2.0;
        let height = ui.available_height() - chrome;
        let top_down = Layout::top_down(Align::LEFT);
        ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), height), top_down, |ui| {
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(egui::vec2(nav_width, height), top_down, |ui| {
                    self.show_nav(ui)
                });
                ui.separator();
                let content_width = ui.available_width();
                ui.allocate_ui_with_layout(egui::vec2(content_width, height), top_down, |ui| {
                    match self.section {
                        Section::Fleet => self.show_fleet(ui),
                        Section::Roster => self.show_roster(ui),
                        Section::Status => self.show_status(ui),
                        Section::Transports => self.show_transports(ui),
                        Section::Services => self.show_services(ui),
                        Section::Peers => self.show_peers(ui),
                        Section::Events => self.show_events(ui),
                        Section::Config => self.show_config(ui),
                        Section::About => self.show_about(ui),
                    }
                });
            });
        });
        ui.separator();
        ui.horizontal(|ui| self.show_status_bar(ui));
    }
}

// region:    --- Shell pieces

impl ConsoleApp {
    fn show_nav(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(14, 12))
            .fill(theme::PANEL)
            .show(ui, |ui| {
                ui.set_min_height(ui.available_height());
                ui.spacing_mut().item_spacing.y = 6.0;

                ui.heading(RichText::new("BIRDHUB").color(theme::TEXT));
                ui.small(RichText::new("fleet console").color(theme::DIM));
                ui.small(
                    RichText::new(if self.is_hub() {
                        "the relay — sessions, roster, pairing"
                    } else {
                        "the node — link, tunnels, services"
                    })
                    .color(theme::DIM),
                );
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);
                for (section, label) in Section::nav(self.is_hub()) {
                    if ui
                        .selectable_label(self.section == *section, *label)
                        .clicked()
                    {
                        self.section = *section;
                    }
                }
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);

                // The one place the shell says "yes, still here" at a
                // glance — Splicer's slow pulse, over the live count.
                let t = ui.input(|i| i.time);
                let pulse = ((t * 1.6).sin() * 0.5 + 0.5) as f32;
                let glow = theme::LIVE.linear_multiply(0.5 + 0.5 * pulse);
                ui.horizontal(|ui| {
                    ui.colored_label(glow, "●");
                    if self.is_hub() {
                        ui.small(
                            RichText::new(format!("{} session(s)", self.data.sessions.len()))
                                .color(theme::DIM),
                        );
                    } else {
                        ui.small(
                            RichText::new(format!("hub {}", self.data.link.state))
                                .color(theme::DIM),
                        );
                    }
                });
                ui.small(
                    RichText::new(format!("{} events", self.data.events.len())).color(theme::DIM),
                );
                match &self.data.api {
                    Some(addr) => {
                        ui.small(RichText::new(format!("api: {addr}")).color(theme::DIM));
                    }
                    None => {
                        ui.small(RichText::new("api: off").color(theme::DIM));
                    }
                }
            });
    }

    fn show_status_bar(&mut self, ui: &mut egui::Ui) {
        ui.small(
            RichText::new(format!("{} · {}", self.data.mode, self.data.subject)).color(theme::DIM),
        );
        if let Some(error) = &self.data.last_error {
            ui.separator();
            ui.small(RichText::new(error).color(theme::WARN));
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.small(
                RichText::new(format!(
                    "events {}",
                    self.data.events.back().map(|e| e.seq).unwrap_or(0)
                ))
                .color(theme::DIM),
            );
        });
    }
}

// endregion: --- Shell pieces
