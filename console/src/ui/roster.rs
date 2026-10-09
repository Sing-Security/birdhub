//! The Roster page — the grant table, editable. The editor is free text in
//! rows; Save runs the same path `PUT /grants` does (load, swap, validate,
//! rewrite, apply), so a typo comes back as a validation error in the status
//! bar and changes nothing.

use crate::app::{ConsoleApp, DraftRow};
use crate::data::GrantRow;
use crate::theme;
use egui::RichText;
use egui_extras::{Column, TableBuilder};

impl ConsoleApp {
    pub fn show_roster(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(14, 10))
            .fill(theme::VOID)
            .show(ui, |ui| {
                ui.heading(RichText::new("Roster").color(theme::TEXT));
                ui.small(
                    RichText::new("the grant table — who may connect, and exactly what they may ask for")
                        .color(theme::DIM),
                );
                ui.add_space(6.0);

                // The editor starts as the applied table; every row is
                // editable and the buttons act on the whole draft.
                if self.draft.is_empty() && !self.data.roster.is_empty() {
                    self.draft = self
                        .data
                        .roster
                        .iter()
                        .map(|row| DraftRow {
                            client: row.client.clone(),
                            targets: row.targets.join(", "),
                        })
                        .collect();
                }

                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Save").color(theme::LIVE)).clicked() {
                        let rows: Vec<GrantRow> = self
                            .draft
                            .iter()
                            .map(|row| GrantRow {
                                client: row.client.clone(),
                                targets: split_targets_for(&row.targets),
                            })
                            .collect();
                        self.act(crate::backend::Action::SaveRoster(rows));
                    }
                    if ui.button("Reload").clicked() {
                        self.act(crate::backend::Action::ReloadRoster);
                    }
                    if ui.button("Add row").clicked() {
                        self.draft.push(DraftRow {
                            client: String::new(),
                            targets: String::new(),
                        });
                    }
                    ui.small(
                        RichText::new("save rewrites the config file (comments are lost); reload re-reads a hand-edited file")
                            .color(theme::DIM),
                    );
                });
                ui.add_space(6.0);
                ui.separator();

                TableBuilder::new(ui)
                    .striped(true)
                    .column(Column::exact(220.0)) // client
                    .column(Column::remainder()) // targets
                    .column(Column::exact(60.0)) // remove
                    .header(20.0, |mut header| {
                        header.col(|ui| {
                            ui.strong(RichText::new("client").color(theme::DIM));
                        });
                        header.col(|ui| {
                            ui.strong(
                                RichText::new("targets (comma-separated; empty = serves only)")
                                    .color(theme::DIM),
                            );
                        });
                        header.col(|_ui| {});
                    })
                    .body(|body| {
                        body.rows(24.0, self.draft.len(), |mut row| {
                            let index = row.index();
                            row.col(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.draft[index].client)
                                        .hint_text("certificate subject"),
                                );
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.draft[index].targets)
                                        .hint_text("host:port, or @peer/subject"),
                                );
                            });
                            row.col(|ui| {
                                if ui.button("✕").clicked() {
                                    self.draft.remove(index);
                                }
                            });
                        });
                    });

                ui.add_space(8.0);
                ui.small(
                    RichText::new("admission applies to the next session — a client already up keeps its list; disconnect it (Fleet) to make the edit reach it now")
                        .color(theme::DIM),
                );
            });
    }
}

/// "host:80, @peer/node" → ["host:80", "@peer/node"], skipping blanks; the
/// real validation happens in `edit_roster`, which names the offender.
/// Shared with the action-layer test, which saves the way a click does.
pub fn split_targets_for(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .map(str::to_string)
        .collect()
}
