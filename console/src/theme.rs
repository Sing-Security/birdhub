//! The console's palette — Noxgraph's dark constants, so the three
//! applications (splicer, noxgraph, this) read as one family. Painted
//! directly, like the references do; eframe's default dark visuals stay as
//! the base.

use egui::Color32;

pub const PANEL: Color32 = Color32::from_rgb(0x0f, 0x15, 0x1d);
pub const VOID: Color32 = Color32::from_rgb(0x0d, 0x11, 0x17);
pub const TEXT: Color32 = Color32::from_rgb(0xD4, 0xDE, 0xEA);
pub const DIM: Color32 = Color32::from_rgb(0x7E, 0x8D, 0xA0);
pub const LINE: Color32 = Color32::from_rgb(0x30, 0x36, 0x3d);
pub const ACCENT: Color32 = Color32::from_rgb(0x58, 0xa6, 0xff);

/// The live/connected green Splicer pulses with.
pub const LIVE: Color32 = Color32::from_rgb(60, 200, 130);
/// Refusals and warnings — the log's red.
pub const WARN: Color32 = Color32::from_rgb(0xf8, 0x51, 0x49);

/// Put the palette under every surface the shell does not paint itself —
/// the panel behind the page cards and the wells inside them. Without it
/// the default dark visuals show through and the gaps read as black bands.
/// Both entry points call this: the window (main.rs) and the screenshot
/// harness, so the shots picture the real application.
pub fn apply(cc: &eframe::CreationContext) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = PANEL;
    visuals.extreme_bg_color = VOID;
    visuals.faint_bg_color = PANEL;
    visuals.widgets.noninteractive.bg_fill = PANEL;
    visuals.widgets.noninteractive.weak_bg_fill = PANEL;
    cc.egui_ctx.set_visuals(visuals);
}
