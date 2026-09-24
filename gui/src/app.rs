use eframe::egui;

use crate::host_tab::HostTabState;
use crate::modal::Modal;
use crate::project::{HostProjectDict, ProjectFile, PROJECT_FORMAT_VERSION};
use crate::theme;

#[derive(Clone)]
enum PendingConfirm {
    CloseHost { host_idx: usize },
    CloseClient { host_idx: usize, client_idx: usize },
    ResetProject,
}

pub struct WgStudioApp {
    hosts: Vec<HostTabState>,
    selected_host: usize,
    host_counter: u64,
    confirm_close: bool,
    /// "Create mesh between nodes": when on, every host also gets a
    /// `[Peer]` block for every *other* host, in addition to its own
    /// clients -- so instead of N separate stars (one per host), the
    /// hosts themselves are fully meshed together into one network.
    /// Inspired by netbird's full-mesh peer topology.
    mesh_hosts: bool,
    /// "+ EoIP (L2) between them": on top of `mesh_hosts`'s routed
    /// WireGuard link, also give each meshed host pair a MikroTik EoIP
    /// tunnel in the RouterOS export, so raw Ethernet (not just IP) can be
    /// bridged between them. Only meaningful -- and only shown enabled --
    /// while `mesh_hosts` is on; RouterOS export only, the plain .conf
    /// export has no such concept.
    mesh_eoip: bool,
    modal: Option<Modal>,
    confirm: Option<(String, String, PendingConfirm)>,
    theme_applied: bool,
}

impl Default for WgStudioApp {
    fn default() -> Self {
        let mut app = WgStudioApp {
            hosts: Vec::new(),
            selected_host: 0,
            host_counter: 0,
            confirm_close: true,
            mesh_hosts: false,
            mesh_eoip: false,
            modal: None,
            confirm: None,
            theme_applied: false,
        };
        app.new_host_tab();
        app
    }
}

impl WgStudioApp {
    fn new_host_tab(&mut self) -> usize {
        self.host_counter += 1;
        let name = format!("host-{}", self.host_counter);
        let host = HostTabState::new(self.host_counter, &name);
        self.hosts.push(host);
        self.selected_host = self.hosts.len() - 1;
        self.selected_host
    }

    fn info(&mut self, title: impl Into<String>, body: impl Into<String>) {
        self.modal = Some(Modal::Info {
            title: title.into(),
            body: body.into(),
        });
    }

    fn error(&mut self, title: impl Into<String>, body: impl Into<String>) {
        self.modal = Some(Modal::Error {
            title: title.into(),
            body: body.into(),
        });
    }

    // -- Header -----------------------------------------------------------

    fn ui_header(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            // Scoped to this `ui` (and everything drawn from it below) via
            // `visuals_mut`, *not* `ui.ctx().set_visuals()`: a `Ui` snapshots
            // its style when created, so a mid-closure `ctx().set_visuals()`
            // call here would never reach widgets drawn through this same
            // `ui` -- it only affects `Ui`s created fresh from the context
            // afterwards. That previously left every header label (button
            // text included) on the light-mode dark text color, invisible
            // wherever a widget has no light background box behind it (e.g.
            // a checkbox's label, unlike a button's own filled rect).
            //
            // Buttons paint their own background from `weak_bg_fill` (not
            // `bg_fill`, which is only for things like a checkbox's box) --
            // it defaults to light grey from the base light theme and is
            // never touched elsewhere, so once the text above turns light
            // it needs a background dark enough to read against, too.
            {
                let visuals = ui.visuals_mut();
                visuals.override_text_color = Some(theme::FG_HEADER);
                visuals.widgets.inactive.weak_bg_fill = theme::ACCENT_DARK;
                visuals.widgets.hovered.weak_bg_fill = theme::ACCENT;
                visuals.widgets.active.weak_bg_fill = theme::ACCENT;
            }

            egui::Frame::default().fill(theme::BG_HEADER).inner_margin(egui::Margin::symmetric(12.0, 10.0)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(theme::FG_HEADER, egui::RichText::new("WireGuard Config Studio").size(16.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::danger_button(ui, "Reset Project").clicked() {
                            if !self.hosts.is_empty() {
                                self.confirm = Some((
                                    "Reset project".into(),
                                    "This will remove every host and client tab and can't be undone. Reset the project?".into(),
                                    PendingConfirm::ResetProject,
                                ));
                            }
                        }
                        if ui.button("Save Entire Project...").clicked() {
                            self.save_project();
                        }
                        if ui.button("Open Project...").clicked() {
                            self.open_project();
                        }
                        ui.add_enabled(self.mesh_hosts, egui::Checkbox::new(&mut self.mesh_eoip, "+ EoIP (L2)"))
                            .on_hover_text(
                                "Also give each meshed host pair a MikroTik EoIP tunnel in the RouterOS \
                                 export, bridging raw Ethernet between them (one L2 broadcast domain) on \
                                 top of the routed WireGuard link. RouterOS export only -- needs \"Mesh \
                                 hosts together\" on.",
                            );
                        ui.checkbox(&mut self.mesh_hosts, "Mesh hosts together")
                            .on_hover_text(
                                "Link every host to every other host directly, in addition to each \
                                 host's own clients -- a full mesh between hosts instead of separate \
                                 stars. Applies next time you Save/Preview a host's configuration.",
                            );
                        // ui.checkbox(&mut self.confirm_close, "Confirm before closing tabs");
                        ui.checkbox(&mut self.confirm_close, "");
                    });
                });
            });
        });
    }

    // -- Host tab strip -----------------------------------------------------

    fn ui_host_tabs(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                for i in 0..self.hosts.len() {
                    let name = self.hosts[i].name.clone();
                    if ui.selectable_label(i == self.selected_host, name).clicked() {
                        self.selected_host = i;
                    }
                }
                if ui.button("+").clicked() {
                    self.new_host_tab();
                }
            });
            ui.separator();

            if self.hosts.is_empty() {
                self.new_host_tab();
                return;
            }
            let idx = self.selected_host.min(self.hosts.len() - 1);
            self.selected_host = idx;

            let confirm_close = self.confirm_close;
            let mesh_peers = if self.mesh_hosts {
                crate::host_tab::collect_mesh_peers(&self.hosts, idx)
            } else {
                Vec::new()
            };
            let out = self.hosts[idx].ui(ui, &mesh_peers, self.mesh_eoip);

            if let Some(m) = out.modal {
                self.modal = Some(m);
            }
            if let Some(client_idx) = out.close_client_requested {
                if confirm_close {
                    self.confirm = Some((
                        "Remove client".into(),
                        format!(
                            "Remove client '{}'?",
                            self.hosts[idx].clients[client_idx].name
                        ),
                        PendingConfirm::CloseClient {
                            host_idx: idx,
                            client_idx,
                        },
                    ));
                } else {
                    self.hosts[idx].close_client_tab(client_idx);
                }
            }
            if out.close_requested {
                if confirm_close {
                    self.confirm = Some((
                        "Close host tab".into(),
                        format!(
                            "Close host '{}' and all its client tabs?",
                            self.hosts[idx].name
                        ),
                        PendingConfirm::CloseHost { host_idx: idx },
                    ));
                } else {
                    self.close_host_tab(idx);
                }
            }
        });
    }

    fn close_host_tab(&mut self, idx: usize) {
        if idx < self.hosts.len() {
            self.hosts.remove(idx);
        }
        if self.selected_host >= self.hosts.len() && !self.hosts.is_empty() {
            self.selected_host = self.hosts.len() - 1;
        }
        if self.hosts.is_empty() {
            self.new_host_tab();
        }
    }

    // -- Modals -------------------------------------------------------------

    fn ui_modal(&mut self, ctx: &egui::Context) {
        if let Some(modal) = self.modal.clone() {
            let mut open = true;
            match &modal {
                Modal::Info { title, body } => {
                    egui::Window::new(title.clone())
                        .open(&mut open)
                        .collapsible(false)
                        .resizable(false)
                        .show(ctx, |ui| {
                            ui.label(body);
                            ui.horizontal(|ui| {
                                if ui.button("OK").clicked() {
                                    self.modal = None;
                                }
                            });
                        });
                }
                Modal::Error { title, body } => {
                    egui::Window::new(format!("⚠ {title}"))
                        .open(&mut open)
                        .collapsible(false)
                        .resizable(false)
                        .show(ctx, |ui| {
                            ui.colored_label(theme::DANGER, body);
                            ui.horizontal(|ui| {
                                if ui.button("OK").clicked() {
                                    self.modal = None;
                                }
                            });
                        });
                }
                Modal::Preview { title, body } => {
                    egui::Window::new(title.clone())
                        .open(&mut open)
                        .collapsible(false)
                        .default_size([640.0, 480.0])
                        .show(ctx, |ui| {
                            egui::ScrollArea::both().max_height(400.0).show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(body).monospace())
                                        .selectable(true),
                                );
                            });
                            ui.horizontal(|ui| {
                                if ui.button("Copy Configuration").clicked() {
                                    ui.output_mut(|o| o.copied_text = body.clone());
                                }
                                if ui.button("Close").clicked() {
                                    self.modal = None;
                                }
                            });
                        });
                }
            }
            if !open {
                self.modal = None;
            }
        }

        if let Some((title, body, _)) = self.confirm.clone() {
            let mut open = true;
            let mut decision: Option<bool> = None;
            egui::Window::new(title)
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(body);
                    ui.horizontal(|ui| {
                        if ui.button("Yes").clicked() {
                            decision = Some(true);
                        }
                        if ui.button("No").clicked() {
                            decision = Some(false);
                        }
                    });
                });
            if !open {
                decision = Some(false);
            }
            if let Some(yes) = decision {
                let (_, _, action) = self.confirm.take().unwrap();
                if yes {
                    match action {
                        PendingConfirm::CloseHost { host_idx } => self.close_host_tab(host_idx),
                        PendingConfirm::CloseClient {
                            host_idx,
                            client_idx,
                        } => {
                            if let Some(h) = self.hosts.get_mut(host_idx) {
                                h.close_client_tab(client_idx);
                            }
                        }
                        PendingConfirm::ResetProject => self.reset_project(),
                    }
                }
            }
        }
    }

    // -- Keyboard shortcuts -------------------------------------------------
    //
    // Browser-style shortcuts, same idea as the Tkinter original: Ctrl+W
    // closes the "current" tab, Ctrl+T opens a new one, Ctrl+1..9 jumps to
    // a tab by position. The Python version scoped these by which widget
    // had keyboard focus (host notebook vs. a client's inner notebook);
    // egui doesn't expose an equivalent focus tree, so here they're scoped
    // by the *currently selected* host's sub-tab instead, which covers the
    // overwhelmingly common case (acting on whichever client/host tab is
    // on screen).
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if self.modal.is_some() || self.confirm.is_some() || self.hosts.is_empty() {
            return;
        }
        let (want_close, want_new, want_number) = ctx.input_mut(|i| {
            let close = i.consume_key(egui::Modifiers::COMMAND, egui::Key::W);
            let new_tab = i.consume_key(egui::Modifiers::COMMAND, egui::Key::T);
            let mut number: Option<usize> = None;
            const KEYS: [egui::Key; 9] = [
                egui::Key::Num1,
                egui::Key::Num2,
                egui::Key::Num3,
                egui::Key::Num4,
                egui::Key::Num5,
                egui::Key::Num6,
                egui::Key::Num7,
                egui::Key::Num8,
                egui::Key::Num9,
            ];
            for (n, key) in KEYS.into_iter().enumerate() {
                if i.consume_key(egui::Modifiers::COMMAND, key) {
                    number = Some(n);
                }
            }
            (close, new_tab, number)
        });

        let idx = self.selected_host.min(self.hosts.len() - 1);

        if want_new {
            self.hosts[idx].new_client_tab(None);
        }
        if let Some(n) = want_number {
            self.hosts[idx].select_subtab_by_shortcut_index(n);
        }
        if want_close {
            use crate::host_tab::HostSubTab;
            match self.hosts[idx].selected {
                HostSubTab::Client(client_idx) => {
                    if self.confirm_close {
                        self.confirm = Some((
                            "Remove client".into(),
                            format!(
                                "Remove client '{}'?",
                                self.hosts[idx].clients[client_idx].name
                            ),
                            PendingConfirm::CloseClient {
                                host_idx: idx,
                                client_idx,
                            },
                        ));
                    } else {
                        self.hosts[idx].close_client_tab(client_idx);
                    }
                }
                HostSubTab::Settings => {
                    if self.confirm_close {
                        self.confirm = Some((
                            "Close host tab".into(),
                            format!(
                                "Close host '{}' and all its client tabs?",
                                self.hosts[idx].name
                            ),
                            PendingConfirm::CloseHost { host_idx: idx },
                        ));
                    } else {
                        self.close_host_tab(idx);
                    }
                }
            }
        }
    }

    // -- Project I/O ----------------------------------------------------

    fn open_project(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("WireGuard Studio project", &["json"])
            .pick_file()
        else {
            return;
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                return self.error(
                    "Failed to open project",
                    format!("Could not read this file:\n{e}"),
                )
            }
        };
        let data: ProjectFile = match serde_json::from_str(&text) {
            Ok(d) => d,
            Err(e) => {
                return self.error(
                    "Failed to open project",
                    format!("Could not parse this file:\n{e}"),
                )
            }
        };
        self.load_project(data);
        self.info(
            "Project loaded",
            format!(
                "Loaded {} host(s) from:\n{}",
                self.hosts.len(),
                path.display()
            ),
        );
    }

    fn load_project(&mut self, data: ProjectFile) {
        self.hosts.clear();
        self.mesh_hosts = data.mesh_hosts;
        self.mesh_eoip = data.mesh_eoip;
        for host_dict in &data.hosts {
            self.host_counter += 1;
            let host = HostTabState::from_project_dict(self.host_counter, host_dict);
            self.hosts.push(host);
        }
        self.selected_host = 0;
        if self.hosts.is_empty() {
            self.new_host_tab();
        }
    }

    fn save_project(&mut self) {
        let mut hosts_dicts: Vec<HostProjectDict> = Vec::with_capacity(self.hosts.len());
        for host in &mut self.hosts {
            // Sync every client, then the host, so the saved project
            // reflects the latest form values (mirrors `sync_all`).
            if let Err(e) = host.build_full_model(&[]) {
                return self.error("Save failed", e);
            }
            hosts_dicts.push(host.to_project_dict());
        }

        let Some(path) = rfd::FileDialog::new()
            .set_file_name("wireguard-project.json")
            .add_filter("WireGuard Studio project", &["json"])
            .save_file()
        else {
            return;
        };

        let project = ProjectFile {
            version: PROJECT_FORMAT_VERSION,
            mesh_hosts: self.mesh_hosts,
            mesh_eoip: self.mesh_eoip,
            hosts: hosts_dicts,
        };
        let json = match serde_json::to_string_pretty(&project) {
            Ok(j) => j,
            Err(e) => return self.error("Save failed", e.to_string()),
        };
        // The project file contains every host/client's private key in
        // plaintext, so it needs the same owner-only permissions as an
        // exported .conf, not just the WireGuardHost::save() path.
        if let Err(e) = std::fs::write(&path, json).and_then(|_| wgcore::set_owner_only_permissions(&path).map_err(std::io::Error::other)) {
            return self.error("Save failed", e.to_string());
        }
        self.info("Saved", format!("Project saved to:\n{}", path.display()));
    }

    fn reset_project(&mut self) {
        self.hosts.clear();
        self.host_counter = 0;
        self.mesh_hosts = false;
        self.mesh_eoip = false;
        self.new_host_tab();
    }
}

impl eframe::App for WgStudioApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            theme::apply_theme(ctx);
            self.theme_applied = true;
        }

        self.handle_shortcuts(ctx);
        self.ui_header(ctx);
        self.ui_host_tabs(ctx);
        self.ui_modal(ctx);
    }
}
