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
//!
//! "Mesh peers together" (in a host's own Host Settings tab): normally a
//! host's clients only ever talk to each other through the host (a star).
//! Turning this on also peers every client of THAT host directly with
//! every other client of the same host, so its peers form one fully
//! connected mesh among themselves, in addition to each one's own link
//! back to the host -- inspired by netbird's full mesh between nodes, just
//! applied to a host's own peers rather than between separate hosts. A
//! peer only becomes dialable by its mesh siblings if it sets its own
//! Public IP (and, for a stable Endpoint, a fixed Listen Port) in its
//! client tab; otherwise it can still reach them, it just can't be
//! reached itself. Applies the next time a peer's configuration is
//! generated (Save/Preview/RouterOS).
//!
//! "+ EoIP (L2)" (next to it, needs mesh on): each mesh link above is
//! routed (IP only). This adds a real MikroTik EoIP tunnel for each
//! meshed peer pair in their RouterOS export, bridging raw Ethernet
//! between them -- one L2 broadcast domain -- on top of that routed link.
//! RouterOS export only; the plain .conf export has no such concept.
//!
//! "Apply to Device..." (in a host's or client's own tab, next to the
//! Preview buttons): goes one step further than generating text -- for a
//! MikroTik, OpenWrt, or pfSense device it opens an SSH connection to an IP
//! address you enter (password or private-key auth) and runs the matching
//! script there directly, with a live "View Log" window; for a plain
//! WireGuard client it just exports the `.conf` (no SSH round-trip). A tab
//! whose config was successfully applied is filled solid green with a
//! hover tooltip naming the device type it was applied to (and, if "Check
//! Availability" was run, the model/serial number found). See `deploy.rs`
//! for the implementation and its documented simplifications (no host-key
//! verification, no config-drift tracking).

mod app;
mod client_tab;
mod client_ui;
mod deploy;
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
        // eframe defaults this to `true` on macOS/Windows, which makes it
        // silently re-apply a plain system light/dark `Visuals` (via
        // `egui::Context::set_visuals`) on top of ours -- at startup, and
        // again on every OS dark/light toggle while the app is running.
        // Since our own theme (`theme::apply_theme`) sets very specific
        // colors (e.g. `override_text_color` for a light background), a
        // stray system re-apply could leave some widgets' text unreadable
        // against our backgrounds. We render our own consistent theme
        // regardless of the OS setting, so system-following is unwanted.
        follow_system_theme: false,
        default_theme: eframe::Theme::Light,
        ..Default::default()
    };
    eframe::run_native(
        "WireGuard Config Studio",
        native_options,
        Box::new(|_cc| Ok(Box::new(app::WgStudioApp::default()))),
    )
}
