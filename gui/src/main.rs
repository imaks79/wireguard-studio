//! wireguard-studio-gui
//!
//! Desktop GUI for building WireGuard configurations, built on top of the
//! `wgcore` library. Rust/egui port of `wireguard_gui.py`.
//!
//! Layout mirrors a browser, same as the original:
//!   - A top-level tab strip holds one tab per WireGuard HOST (an office
//!     router, a hub server, ...). A trailing "+" tab opens a new one.
//!   - Inside each host tab is a second tab strip holding "Host Settings"
//!     plus one tab per CLIENT of that host (a laptop, phone, branch
//!     machine, ...). Its own trailing "+" adds a new client.
//!
//! Keyboard shortcuts (browser-style, scoped to the currently visible
//! host/client -- see the note above `WgStudioApp::handle_shortcuts`):
//!   Ctrl/Cmd+W        Remove the current client tab, or close the host
//!                     tab if "Host Settings" is the one showing.
//!   Ctrl/Cmd+T        Add a new client tab to the current host.
//!   Ctrl/Cmd+1..8     Jump to the 1st..8th sub-tab of the current host.
//!   Ctrl/Cmd+9        Jump to the last sub-tab.
//!
//! Saving:
//!   "Save Configuration" (inside a host tab) writes ONE .conf file for
//!   that host, including all of its clients as [Peer] blocks.
//!   "Save Entire Project" (top toolbar) writes the whole workspace --
//!   every host, every client, every field -- into a single .json file
//!   that "Open Project" can load back exactly as it was.

mod app;
mod client_tab;
mod client_ui;
mod host_tab;
mod host_ui;
mod modal;
mod project;
mod theme;
mod util;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1050.0, 760.0])
            .with_title("WireGuard Config Studio"),
        ..Default::default()
    };
    eframe::run_native(
        "WireGuard Config Studio",
        native_options,
        Box::new(|_cc| Ok(Box::new(app::WgStudioApp::default()))),
    )
}
