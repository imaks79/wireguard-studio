//! Visual theme: reminiscent of OpenWrt's LuCI web admin panel -- a dark
//! navy header bar, a light grey-blue page background, white bordered
//! "card" panels with bold blue-accented section headers, and blue
//! primary / red destructive buttons. Rust port of `setup_luci_theme()`.

use eframe::egui::{self, Color32, Stroke};

pub const BG_PAGE: Color32 = Color32::from_rgb(0xee, 0xf1, 0xf5);
pub const BG_PANEL: Color32 = Color32::from_rgb(0xff, 0xff, 0xff);
pub const BG_HEADER: Color32 = Color32::from_rgb(0x1b, 0x28, 0x36);
pub const FG_HEADER: Color32 = Color32::from_rgb(0xe7, 0xed, 0xf3);
pub const BORDER: Color32 = Color32::from_rgb(0xd3, 0xdb, 0xe3);
pub const TEXT: Color32 = Color32::from_rgb(0x25, 0x31, 0x3d);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x6c, 0x7a, 0x89);
pub const ACCENT: Color32 = Color32::from_rgb(0x2d, 0x7d, 0xd2);
pub const ACCENT_DARK: Color32 = Color32::from_rgb(0x1f, 0x5c, 0x9e);
pub const DANGER: Color32 = Color32::from_rgb(0xc0, 0x39, 0x2b);
pub const DANGER_DARK: Color32 = Color32::from_rgb(0x99, 0x2d, 0x22);
/// Outline color for a tab whose configuration has been successfully
/// applied to a device (see `gui/src/deploy.rs`).
pub const SUCCESS: Color32 = Color32::from_rgb(0x2e, 0xa0, 0x4a);

pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::light();
    visuals.override_text_color = Some(TEXT);
    visuals.panel_fill = BG_PAGE;
    visuals.window_fill = BG_PANEL;
    visuals.extreme_bg_color = Color32::WHITE;
    visuals.faint_bg_color = BG_PAGE;
    visuals.selection.bg_fill = ACCENT;
    // Doubles as a *focused* `TextEdit`'s border color (egui draws that
    // border from `selection.stroke`, not from the `widgets.*` states
    // used for everything else) -- white was invisible against our white
    // page/window background exactly while a field was focused and being
    // typed into, which is the one moment its border matters most.
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT_DARK);
    visuals.widgets.noninteractive.bg_fill = BG_PANEL;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.widgets.inactive.bg_fill = ACCENT;
    // `TextEdit`'s own box fill always comes from `extreme_bg_color`
    // (white, same as every panel/window here), never from this
    // `bg_fill` -- its *border* is what comes from `widgets.inactive`
    // while unfocused, though, and stock egui leaves that stroke empty
    // (relying on a fill/background contrast that our theme doesn't
    // have, since `extreme_bg_color` and `window_fill` are both plain
    // white). Without an explicit stroke here, every text field in the
    // app -- not just this dialog's -- has no visible edge at all: a
    // filled-in field reads as bare floating text and an empty one is
    // completely invisible. Setting it (and `hovered`'s, for the
    // pre-focus rollover state) gives every text field a real edge.
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    visuals.widgets.hovered.bg_fill = ACCENT_DARK;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT_DARK);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    visuals.widgets.active.bg_fill = ACCENT_DARK;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT_DARK);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(6.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    ctx.set_style(style);
}

/// Button-ish style used for destructive actions ("Remove Client", "Close
/// Host Tab", "Reset Project"). egui doesn't have per-widget named styles
/// the way ttk does, so this is applied by temporarily overriding the
/// widget visuals right before drawing the button.
pub fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let mut btn_visuals = ui.visuals().clone();
    btn_visuals.widgets.inactive.bg_fill = DANGER;
    btn_visuals.widgets.hovered.bg_fill = DANGER_DARK;
    btn_visuals.widgets.active.bg_fill = DANGER_DARK;
    let old = ui.ctx().style().visuals.clone();
    ui.ctx().set_visuals(btn_visuals);
    let resp = ui.button(text);
    ui.ctx().set_visuals(old);
    resp
}

/// One labeled group of stacked buttons in a button row -- e.g. "File",
/// "Preview", "Apply" -- so a long flat row of a dozen buttons reads as a
/// few clearly-purposed clusters instead of one wrapped wall of buttons.
/// Callers place `button_column`s next to each other inside their own
/// `ui.horizontal(|ui| { ... })`, with a `ui.separator()` between them.
pub fn button_column(ui: &mut egui::Ui, heading: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    ui.vertical(|ui| {
        if !heading.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.style_mut().visuals.override_text_color = Some(TEXT_MUTED);
                ui.small(heading);
            });
        }
        add_contents(ui);
    });
}

pub fn hint(ui: &mut egui::Ui, text: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.style_mut().visuals.override_text_color = Some(TEXT_MUTED);
        ui.small(text);
    });
}

pub fn mono(text_edit: egui::TextEdit<'_>) -> egui::TextEdit<'_> {
    text_edit.font(egui::TextStyle::Monospace)
}

/// A small "Copy" button for placing next to a read-only or hard-to-select
/// field (private/public keys, pre-shared keys) -- copies `value` to the
/// system clipboard when clicked.
pub fn copy_button(ui: &mut egui::Ui, value: &str) {
    if ui.button("Copy").on_hover_text("Copy to clipboard").clicked() {
        let value = value.to_string();
        ui.output_mut(|o| o.copied_text = value);
    }
}
