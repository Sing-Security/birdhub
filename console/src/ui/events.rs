//! The Events page — Splicer's History pattern applied to the core's log:
//! quick-filter chips, a search box, and the lines themselves as a table,
//! newest first. The ring lives in the core; this page renders the tail of
//! it and the chips narrow it.

use crate::app::{ConsoleApp, EventFilter};
use crate::theme;
use egui::{Color32, RichText};
use egui_extras::{Column, TableBuilder};

impl ConsoleApp {
    pub fn show_events(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(14, 10))
            .fill(theme::VOID)
            .show(ui, |ui| {
                ui.heading(RichText::new("Events").color(theme::TEXT));
                ui.small(
                    RichText::new(
                        "the hub's log, as data — the same lines the headless binary prints",
                    )
                    .color(theme::DIM),
                );
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    for filter in EventFilter::ALL {
                        if ui
                            .selectable_label(self.events_filter == filter, filter.label())
                            .clicked()
                        {
                            self.events_filter = filter;
                        }
                    }
                    ui.add_space(8.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.events_search)
                            .hint_text("search the log")
                            .desired_width(220.0),
                    );
                });
                ui.add_space(6.0);
                ui.separator();

                let needle = self.events_search.to_lowercase();
                let rows: Vec<&crate::data::EventRow> = self
                    .data
                    .recent_events_capped()
                    .into_iter()
                    .filter(|row| self.events_filter.matches(row.kind))
                    .filter(|row| needle.is_empty() || row.text.to_lowercase().contains(&needle))
                    .collect();

                let row_height = 18.0;
                TableBuilder::new(ui)
                    .striped(true)
                    .column(Column::exact(52.0)) // time
                    .column(Column::exact(110.0)) // kind
                    .column(Column::exact(70.0)) // level
                    .column(Column::remainder()) // the line
                    .header(20.0, |mut header| {
                        header.col(|ui| {
                            ui.strong(RichText::new("time").color(theme::DIM));
                        });
                        header.col(|ui| {
                            ui.strong(RichText::new("kind").color(theme::DIM));
                        });
                        header.col(|ui| {
                            ui.strong(RichText::new("level").color(theme::DIM));
                        });
                        header.col(|ui| {
                            ui.strong(RichText::new("line").color(theme::DIM));
                        });
                    })
                    .body(|body| {
                        body.rows(row_height, rows.len(), |mut row| {
                            let event = rows[row.index()];
                            row.col(|ui| {
                                ui.small(RichText::new(clock(event.at_unix)).color(theme::DIM));
                            });
                            row.col(|ui| {
                                ui.small(RichText::new(event.kind).color(theme::ACCENT));
                            });
                            row.col(|ui| {
                                if event.warn {
                                    ui.small(RichText::new("refused").color(theme::WARN));
                                } else {
                                    ui.small(RichText::new("info").color(theme::LIVE));
                                }
                            });
                            row.col(|ui| {
                                let color = if event.warn { theme::WARN } else { theme::TEXT };
                                ui.add(
                                    egui::Label::new(RichText::new(&event.text).color(color))
                                        .truncate(),
                                );
                            });
                        });
                    });
            });
    }
}

/// HH:MM:SS (UTC) from a unix timestamp — the log's times are unix seconds;
/// std has no timezone database, so the page shows UTC rather than guessing.
fn clock(unix: u64) -> String {
    let secs = unix % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// The event's kind as a colour chip the chips row can reuse.
pub fn kind_color(kind: &str) -> Color32 {
    match kind {
        "refusals" => theme::WARN,
        "pairing" => theme::ACCENT,
        "sessions" => theme::LIVE,
        _ => theme::DIM,
    }
}
