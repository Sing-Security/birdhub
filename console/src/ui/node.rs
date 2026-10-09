//! The node's pages: Status (identity + hub link), Transports, Services,
//! and Peers. Tables over the core's snapshots; the one action is the
//! reconnect button, which runs `NodeLink::reconnect` — the same call the
//! control API's route makes.

use crate::app::ConsoleApp;
use crate::theme;
use egui::RichText;
use egui_extras::{Column, TableBuilder};

impl ConsoleApp {
    pub fn show_status(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(14, 10))
            .fill(theme::VOID)
            .show(ui, |ui| {
                ui.heading(RichText::new("Status").color(theme::TEXT));
                ui.small(
                    RichText::new("this node's identity and its link to the hub").color(theme::DIM),
                );
                ui.add_space(6.0);
                ui.separator();

                card(ui, "identity", &self.data.subject);
                ui.monospace(format!("key {}", self.data.key_id));
                ui.monospace(format!("cert {}", self.data.cert_id));
                ui.monospace(format!(
                    "valid {} .. {}",
                    crate::data::date_time(self.data.not_before),
                    crate::data::date_time(self.data.not_after)
                ));

                ui.add_space(10.0);
                card(ui, "hub", self.data.hub_subject.as_deref().unwrap_or("-"));
                ui.monospace(self.data.hub_address.as_deref().unwrap_or("-"));

                ui.add_space(6.0);
                let state_color = match self.data.link.state.as_str() {
                    "connected" => theme::LIVE,
                    "backoff" => theme::WARN,
                    _ => theme::ACCENT,
                };
                ui.horizontal(|ui| {
                    ui.small(RichText::new("link").color(theme::DIM));
                    ui.small(RichText::new(&self.data.link.state).color(state_color));
                    if let Some(session_id) = self.data.link.session_id {
                        ui.small(
                            RichText::new(format!("session {}", session_id)).color(theme::DIM),
                        );
                    }
                });
                if let Some(error) = &self.data.link.last_error {
                    ui.small(RichText::new(error).color(theme::WARN));
                }
                if let Some(retry_in) = self.data.link.retry_in_secs {
                    ui.small(
                        RichText::new(format!("retrying in {} s", retry_in)).color(theme::DIM),
                    );
                }

                ui.add_space(10.0);
                if ui.button("Reconnect").clicked() {
                    self.act(crate::backend::Action::Reconnect);
                }
                ui.small(
                    RichText::new(
                        "drops the live session; the supervisor reconnects on its own backoff",
                    )
                    .color(theme::DIM),
                );
            });
    }

    pub fn show_transports(&mut self, ui: &mut egui::Ui) {
        page_head(
            ui,
            "Transports",
            "local listeners — every connection is one stream on the hub session",
        );
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::exact(120.0)) // name
            .column(Column::exact(180.0)) // local
            .column(Column::exact(200.0)) // forward
            .column(Column::exact(80.0)) // accepted
            .column(Column::remainder()) // last error
            .header(20.0, |mut header| {
                for label in [
                    "name",
                    "listening on",
                    "forwards to",
                    "accepted",
                    "listener error",
                ] {
                    header.col(|ui| {
                        ui.strong(RichText::new(label).color(theme::DIM));
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, self.data.transports.len(), |mut row| {
                    let transport = &self.data.transports[row.index()];
                    row.col(|ui| {
                        ui.small(RichText::new(&transport.name).color(theme::TEXT));
                    });
                    row.col(|ui| {
                        ui.small(RichText::new(&transport.local_address).color(theme::DIM));
                    });
                    row.col(|ui| {
                        ui.small(RichText::new(&transport.forward_to).color(theme::ACCENT));
                    });
                    row.col(|ui| {
                        ui.small(RichText::new(transport.accepted.to_string()).color(theme::LIVE));
                    });
                    row.col(|ui| {
                        ui.small(
                            RichText::new(transport.last_error.as_deref().unwrap_or(""))
                                .color(theme::WARN),
                        );
                    });
                });
            });
    }

    pub fn show_services(&mut self, ui: &mut egui::Ui) {
        page_head(
            ui,
            "Services",
            "what this node serves to peers — each one names who may use it",
        );
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::exact(140.0)) // name
            .column(Column::exact(220.0)) // target
            .column(Column::remainder()) // clients
            .header(20.0, |mut header| {
                for label in [
                    "service",
                    "dials",
                    "permitted clients (certificate subjects)",
                ] {
                    header.col(|ui| {
                        ui.strong(RichText::new(label).color(theme::DIM));
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, self.data.services.len(), |mut row| {
                    let service = &self.data.services[row.index()];
                    row.col(|ui| {
                        ui.small(RichText::new(&service.name).color(theme::TEXT));
                    });
                    row.col(|ui| {
                        ui.small(RichText::new(&service.target).color(theme::ACCENT));
                    });
                    row.col(|ui| {
                        ui.small(RichText::new(service.clients.join(", ")).color(theme::DIM));
                    });
                });
            });
    }

    pub fn show_peers(&mut self, ui: &mut egui::Ui) {
        page_head(
            ui,
            "Peers",
            "cached node-to-node sessions, established on first use",
        );
        if self.data.peers.locked {
            ui.small(
                RichText::new(
                    "a handshake holds the map right now — peers will show once it completes",
                )
                .color(theme::DIM),
            );
        }
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::exact(220.0)) // subject
            .column(Column::exact(150.0)) // session
            .column(Column::exact(100.0)) // live
            .column(Column::remainder()) // since
            .header(20.0, |mut header| {
                for label in ["peer", "session", "live", "since"] {
                    header.col(|ui| {
                        ui.strong(RichText::new(label).color(theme::DIM));
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, self.data.peers.peers.len(), |mut row| {
                    let peer = &self.data.peers.peers[row.index()];
                    row.col(|ui| {
                        ui.small(RichText::new(&peer.subject).color(theme::TEXT));
                    });
                    row.col(|ui| {
                        ui.small(RichText::new(peer.session_id.to_string()).color(theme::DIM));
                    });
                    row.col(|ui| {
                        let (color, word) = if peer.live {
                            (theme::LIVE, "yes")
                        } else {
                            (theme::WARN, "no")
                        };
                        ui.small(RichText::new(word).color(color));
                    });
                    row.col(|ui| {
                        ui.small(RichText::new(clock(peer.since_unix)).color(theme::DIM));
                    });
                });
            });
    }
}

fn page_head(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(14, 10))
        .fill(theme::VOID)
        .show(ui, |ui| {
            ui.heading(RichText::new(title).color(theme::TEXT));
            ui.small(RichText::new(subtitle).color(theme::DIM));
            ui.add_space(6.0);
            ui.separator();
        });
}

fn card(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.small(RichText::new(label).color(theme::DIM));
    ui.monospace(value);
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
