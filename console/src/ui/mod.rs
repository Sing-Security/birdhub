//! The pages. One file per page, all `impl ConsoleApp` blocks; the small
//! ones (Config, About) live here.

pub mod events;
pub mod fleet;
pub mod node;
pub mod roster;

use crate::app::ConsoleApp;
use crate::theme;
use egui::RichText;

impl ConsoleApp {
    /// The config file, raw — what the roster's Save rewrites and Reload
    /// re-reads, shown so the operator sees the file they own.
    pub fn show_config(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(14, 10))
            .fill(theme::VOID)
            .show(ui, |ui| {
                ui.heading(RichText::new("Config").color(theme::TEXT));
                match &self.data.config_path {
                    Some(path) => {
                        ui.small(RichText::new(path.clone()).color(theme::DIM));
                    }
                    None => {
                        ui.small(
                            RichText::new("this node's config is not shown here").color(theme::DIM),
                        );
                    }
                }
                ui.add_space(6.0);
                ui.separator();
                match &self.data.config_text {
                    Some(text) => {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            ui.monospace(text);
                        });
                    }
                    None => {
                        ui.small(RichText::new("no config text").color(theme::DIM));
                    }
                }
            });
    }

    /// Who this process is — the identity card both modes share.
    pub fn show_about(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(14, 10))
            .fill(theme::VOID)
            .show(ui, |ui| {
                ui.heading(RichText::new("About").color(theme::TEXT));
                ui.small(
                    RichText::new(
                        "identity is a certificate, not an address — the fleet's whole trust model",
                    )
                    .color(theme::DIM),
                );
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                row(ui, "mode", &self.data.mode);
                row(ui, "subject", &self.data.subject);
                ui.add_space(4.0);
                ui.small(RichText::new("signing key").color(theme::DIM));
                ui.monospace(&self.data.key_id);
                ui.add_space(4.0);
                ui.small(RichText::new("certificate").color(theme::DIM));
                ui.monospace(&self.data.cert_id);
                ui.add_space(4.0);
                ui.small(RichText::new("validity").color(theme::DIM));
                ui.monospace(format!(
                    "{} .. {}",
                    crate::data::date_time(self.data.not_before),
                    crate::data::date_time(self.data.not_after)
                ));
                ui.add_space(4.0);
                match (&self.data.hub_address, &self.data.hub_subject) {
                    (Some(address), Some(subject)) => {
                        row(ui, "hub", subject);
                        row(ui, "hub address", address);
                    }
                    _ => {
                        row(
                            ui,
                            "role",
                            "the hub — peers reach each other through this node",
                        );
                    }
                }
                ui.add_space(6.0);
                match &self.data.api {
                    Some(addr) => row(ui, "control api", &format!("http://{addr}")),
                    None => row(ui, "control api", "off — set [control] address to enable"),
                }
            });
    }
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.small(RichText::new(label).color(theme::DIM));
    ui.monospace(value);
}
