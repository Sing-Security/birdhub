//! The Fleet page — who is connected to the hub right now, with a right-hand
//! inspector for the selected session: the certificate that proved it, and
//! the operator's off switch.

use crate::app::ConsoleApp;
use crate::data::SessionRow;
use crate::theme;
use egui::RichText;
use egui_extras::{Column, TableBuilder};

impl ConsoleApp {
    pub fn show_fleet(&mut self, ui: &mut egui::Ui) {
        // The inspector is a panel inside the page, not a frame beside
        // one: an egui table sizes its remainder column from the ui it is
        // handed, and two frames sharing a horizontal row gave the header
        // and the body different answers (the shots caught the body drawn
        // clear across the inspector). A panel is one answer, everywhere.
        egui::Panel::right("fleet_inspector")
            .resizable(false)
            .exact_size(300.0)
            .frame(
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(14, 10))
                    .fill(theme::PANEL),
            )
            .show(ui, |ui| {
                // Copied out first: the inspector mutates `self` (its
                // button queues an action), so it cannot hold a borrow
                // into `self.data` at the same time.
                let selected = self.selected_session.and_then(|id| {
                    self.data
                        .sessions
                        .iter()
                        .find(|session| session.session_id == id)
                        .cloned()
                });
                match selected {
                    Some(session) => self.show_inspector(ui, &session),
                    None => {
                        ui.heading(RichText::new("Inspector").color(theme::TEXT));
                        ui.small(
                            RichText::new(
                                "select a session to inspect its certificate, or to end it",
                            )
                            .color(theme::DIM),
                        );
                    }
                }
            });

        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(14, 10))
            .fill(theme::VOID)
            .show(ui, |ui| {
                ui.heading(RichText::new("Fleet").color(theme::TEXT));
                ui.small(
                    RichText::new(
                        "who is connected right now — presence is a live session, nothing else",
                    )
                    .color(theme::DIM),
                );
                ui.add_space(6.0);
                ui.separator();

                let selected = self.selected_session;
                TableBuilder::new(ui)
                    .striped(true)
                    .column(Column::exact(210.0)) // subject
                    .column(Column::exact(120.0)) // session id
                    .column(Column::exact(70.0)) // streams
                    .column(Column::remainder()) // since
                    .header(20.0, |mut header| {
                        for label in ["subject", "session", "streams", "since"] {
                            header.col(|ui| {
                                ui.strong(RichText::new(label).color(theme::DIM));
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(20.0, self.data.sessions.len(), |mut row| {
                            let session = &self.data.sessions[row.index()];
                            let is_selected = selected == Some(session.session_id);
                            row.set_selected(is_selected);
                            row.col(|ui| {
                                ui.small(RichText::new(&session.subject).color(theme::TEXT));
                            });
                            row.col(|ui| {
                                ui.small(
                                    RichText::new(short_id(session.session_id)).color(theme::DIM),
                                );
                            });
                            row.col(|ui| {
                                ui.small(RichText::new(session.streams_open.to_string()).color(
                                    if session.streams_open > 0 {
                                        theme::LIVE
                                    } else {
                                        theme::DIM
                                    },
                                ));
                            });
                            row.col(|ui| {
                                ui.small(
                                    RichText::new(clock(session.since_unix)).color(theme::DIM),
                                );
                            });
                            if row.response().clicked() {
                                self.selected_session = Some(session.session_id);
                            }
                        });
                    });
            });
    }

    fn show_inspector(&mut self, ui: &mut egui::Ui, session: &SessionRow) {
        ui.heading(RichText::new(&session.subject).color(theme::TEXT));
        ui.small(RichText::new(format!("session {}", session.session_id)).color(theme::DIM));
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);

        ui.small(RichText::new("signing key").color(theme::DIM));
        ui.monospace(&session.key_id);
        ui.add_space(4.0);
        ui.small(RichText::new("certificate").color(theme::DIM));
        ui.monospace(&session.cert_id);
        ui.add_space(4.0);
        ui.small(RichText::new("validity").color(theme::DIM));
        ui.monospace(format!(
            "{} .. {}",
            crate::data::date_time(session.not_before),
            crate::data::date_time(session.not_after)
        ));
        ui.add_space(4.0);
        ui.small(RichText::new("connected").color(theme::DIM));
        ui.monospace(crate::data::date_time(session.since_unix));
        ui.add_space(4.0);
        ui.small(RichText::new("conversations open").color(theme::DIM));
        ui.monospace(session.streams_open.to_string());

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(4.0);
        let kick = session.session_id;
        let button = egui::Button::new(RichText::new("Disconnect session").color(theme::WARN));
        if ui.add(button).clicked() {
            self.act(crate::backend::Action::Kick(kick));
            self.selected_session = None;
        }
        ui.small(
            RichText::new(
                "the client reconnects and is then subject to whatever the roster says now",
            )
            .color(theme::DIM),
        );
    }
}

/// The session id, shortened the way the logs shorten certificate ids — the
/// table needs a hint, not the whole 64 bits.
fn short_id(id: u64) -> String {
    format!("…{}", id % 1_000_000_000_000)
}

/// HH:MM:SS (UTC) from a unix timestamp, as on the Events page.
fn clock(unix: u64) -> String {
    let secs = unix % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}
