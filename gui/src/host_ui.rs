use eframe::egui;

use crate::client_ui::ClientCtx;
use crate::deploy::{self, DeviceType};
use crate::deploy::DeployState;
use crate::host_tab::{collect_client_mesh_peers, find_mesh_address_conflict, ExtraPeer, HostSubTab, HostTabState};
use crate::modal::Modal;
use crate::theme;
use crate::util::split_csv;
use wgcore::RouterOsOptions;

#[derive(Default)]
pub struct HostUiOutcome {
    pub modal: Option<Modal>,
    pub close_requested: bool,
    /// Set when a client's "Remove Client" button was clicked, so the
    /// app-level loop can gate it behind the confirm-close setting.
    pub close_client_requested: Option<usize>,
    /// Set to the new tab's name when the "+" (add client) button was
    /// clicked, so the app-level loop can record it in the action log.
    pub client_added: Option<String>,
    /// Interfaces copied from a device that should each open as a new host
    /// tab, with the SSH settings they were read through.
    pub imported_hosts: Vec<(wgcore::ImportedInterface, DeployState)>,
}

/// What was clicked in the "Copy Interface from Device" picker this frame.
enum ImportChoice {
    LoadHere(usize),
    NewTab(usize),
    AllNewTabs,
    Close,
}

impl HostTabState {
    pub fn ui(&mut self, ui: &mut egui::Ui) -> HostUiOutcome {
        let mut out = HostUiOutcome::default();

        // Deploy progress for this host and its clients is drained once
        // per frame for *every* host in `app.rs::ui_host_tabs`, not here --
        // see `HostTabState::poll_deploys`'s doc comment for why it must
        // run regardless of which host/sub-tab is currently selected.

        // -- sub-tab strip: "Host Settings", one per client, "+" --------
        ui.horizontal_wrapped(|ui| {
            let settings_selected = matches!(self.selected, HostSubTab::Settings);
            if deploy::labeled_tab_button(ui, settings_selected, "Host Settings", &self.deploy).clicked() {
                self.selected = HostSubTab::Settings;
            }
            for i in 0..self.clients.len() {
                let selected = matches!(self.selected, HostSubTab::Client(idx) if idx == i);
                let name = self.clients[i].name.clone();
                if deploy::labeled_tab_button(ui, selected, &name, &self.clients[i].deploy).clicked() {
                    self.selected = HostSubTab::Client(i);
                }
            }
            if ui.button("+").clicked() {
                let idx = self.new_client_tab(None);
                out.client_added = Some(self.clients[idx].name.clone());
            }
        });
        ui.separator();

        match self.selected {
            HostSubTab::Settings => self.ui_settings(ui, &mut out),
            HostSubTab::Client(i) if i < self.clients.len() => self.ui_client(ui, i, &mut out),
            _ => self.selected = HostSubTab::Settings,
        }

        out
    }

    fn ui_settings(&mut self, ui: &mut egui::Ui, out: &mut HostUiOutcome) {
        egui::ScrollArea::vertical().id_salt(("host-scroll", self.id)).show(ui, |ui| {
            ui.group(|ui| {
                ui.colored_label(theme::ACCENT_DARK, egui::RichText::new("Host — [Interface]").strong());
                ui.checkbox(&mut self.advanced, "Advanced settings (DNS, MTU, Table, FwMark, hooks, SaveConfig) — most hosts don't need these");

                egui::Grid::new(("host-grid", self.id)).num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
                    ui.label("Name:");
                    ui.add(egui::TextEdit::singleline(&mut self.name).desired_width(theme::FIELD_WIDTH));
                    ui.end_row();

                    ui.label("Private Key:");
                    ui.horizontal(|ui| {
                        ui.add_enabled(self.manual_key, theme::mono(egui::TextEdit::singleline(&mut self.private_key)).desired_width(theme::FIELD_WIDTH));
                        theme::copy_button(ui, &self.private_key);
                        if ui.checkbox(&mut self.manual_key, "Manual entry").changed() && !self.manual_key {
                            self.refresh_public_key();
                        }
                        if ui.button("Generate").clicked() {
                            self.regenerate_key();
                        }
                    });
                    ui.end_row();

                    ui.label("Public Key:");
                    ui.horizontal(|ui| {
                        ui.add_enabled(false, theme::mono(egui::TextEdit::singleline(&mut self.public_key)).desired_width(theme::FIELD_WIDTH));
                        theme::copy_button(ui, &self.public_key);
                    });
                    ui.end_row();

                    ui.label("Address(es):");
                    ui.add(egui::TextEdit::singleline(&mut self.address).desired_width(theme::FIELD_WIDTH));
                    ui.end_row();

                    ui.label("Listen Port:");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.listen_port).desired_width(theme::FIELD_WIDTH));
                        if ui.button("Random").clicked() {
                            self.randomize_listen_port();
                        }
                    });
                    ui.end_row();

                    if self.advanced {
                        ui.label("DNS:");
                        ui.add(egui::TextEdit::singleline(&mut self.dns).desired_width(theme::FIELD_WIDTH));
                        ui.end_row();
                        ui.label("MTU:");
                        ui.add(egui::TextEdit::singleline(&mut self.mtu).desired_width(theme::FIELD_WIDTH));
                        ui.end_row();
                        ui.label("Table:");
                        ui.add(egui::TextEdit::singleline(&mut self.table).desired_width(theme::FIELD_WIDTH));
                        ui.end_row();
                        ui.label("FwMark:");
                        ui.add(egui::TextEdit::singleline(&mut self.fwmark).desired_width(theme::FIELD_WIDTH));
                        ui.end_row();
                        ui.label("SaveConfig:");
                        ui.checkbox(&mut self.save_config, "");
                        ui.end_row();
                    }

                    ui.label("Public IP Address:");
                    ui.add(egui::TextEdit::singleline(&mut self.public_ip).desired_width(theme::FIELD_WIDTH));
                    ui.end_row();

                    ui.label("Interface on device:");
                    ui.add(egui::TextEdit::singleline(&mut self.device_interface).desired_width(theme::FIELD_WIDTH).hint_text("same as Name"))
                        .on_hover_text(
                            "The WireGuard interface this host is applied to on a MikroTik/OpenWrt device. \
                             If one with this name already exists there it is updated in place and its \
                             peer list is replaced with this host's; otherwise it is created. Leave blank \
                             to use Name.",
                        );
                    ui.end_row();

                    ui.label("Manage firewall:");
                    ui.checkbox(&mut self.manage_firewall, "")
                        .on_hover_text(
                            "Also set up firewall rules for the tunnel when applying to MikroTik/OpenWrt \
                             (accept the listen port, zone/forward rules). Turn off for an interface whose \
                             firewall is already configured on the device -- it is off after \
                             \"Copy Interface from Device\".",
                        );
                    ui.end_row();

                    ui.label("EoIP to peers:");
                    ui.checkbox(&mut self.host_eoip, "")
                        .on_hover_text(
                            "Build an EoIP tunnel (L2, bridging raw Ethernet) between this host and \
                             each of its peers, on top of the routed WireGuard link. Off by default; \
                             a MikroTik built-in in the RouterOS export, the third-party \
                             'eoip'/'luci-app-eoip' packages in the OpenWrt export.",
                        );
                    ui.end_row();

                    ui.label("Mesh peers together:");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.mesh_peers_enabled, "")
                            .on_hover_text(
                                "Link every peer (client) of this host directly to every other peer, \
                                 in addition to each peer's own link back to this host -- a full mesh \
                                 among all of them instead of just a star. Applies next time you \
                                 Save/Preview a peer's configuration.",
                            );
                        ui.add_enabled(self.mesh_peers_enabled, egui::Checkbox::new(&mut self.mesh_eoip, "+ EoIP (L2)"))
                            .on_hover_text(
                                "Also give each meshed peer pair an EoIP tunnel, bridging raw Ethernet \
                                 between them on top of the routed WireGuard link -- a MikroTik built-in \
                                 in the RouterOS export, or the third-party 'eoip'/'luci-app-eoip' \
                                 packages in the OpenWrt export. Router/RouterOS exports only.",
                            );
                    });
                    ui.end_row();
                });
                theme::hint(ui, "Address e.g. 10.10.0.1/24 -- clients get addresses from inside this range. \
                                 Public IP is how clients reach this host from outside; it auto-fills new clients' Endpoint field.");

                if self.advanced {
                    ui.add_space(4.0);
                    ui.label("Startup / shutdown hooks (one command per line):");
                    egui::Grid::new(("hooks-grid", self.id)).num_columns(4).show(ui, |ui| {
                        ui.vertical(|ui| { ui.label("PreUp"); ui.add(egui::TextEdit::multiline(&mut self.pre_up).desired_rows(3).desired_width(160.0)); });
                        ui.vertical(|ui| { ui.label("PostUp"); ui.add(egui::TextEdit::multiline(&mut self.post_up).desired_rows(3).desired_width(160.0)); });
                        ui.vertical(|ui| { ui.label("PreDown"); ui.add(egui::TextEdit::multiline(&mut self.pre_down).desired_rows(3).desired_width(160.0)); });
                        ui.vertical(|ui| { ui.label("PostDown"); ui.add(egui::TextEdit::multiline(&mut self.post_down).desired_rows(3).desired_width(160.0)); });
                        ui.end_row();
                    });
                }
            });

            ui.add_space(6.0);
            self.ui_extra_peers(ui);

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                theme::button_column(ui, "File", |ui| {
                    if theme::sized_button(ui, theme::FILE_BUTTON_WIDTH, "Load Configuration...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("WireGuard config", &["conf"]).pick_file() {
                            match std::fs::read_to_string(&path) {
                                Ok(text) => {
                                    let name = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| self.name.clone());
                                    match self.load_from_config(&text, &name) {
                                        Ok(n) => out.modal = Some(Modal::Info { title: "Loaded".into(), body: format!("Loaded '{}' ({n} peer(s) found).", path.display()) }),
                                        Err(e) => out.modal = Some(Modal::Error { title: "Failed to load config".into(), body: e }),
                                    }
                                }
                                Err(e) => out.modal = Some(Modal::Error { title: "Failed to load config".into(), body: e.to_string() }),
                            }
                        }
                    }

                    if theme::sized_button(ui, theme::FILE_BUTTON_WIDTH, "Save Configuration...").clicked() {
                        match self.build_full_model() {
                            Ok(host) => {
                                if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{}.conf", host.name)).add_filter("WireGuard config", &["conf"]).save_file() {
                                    match std::fs::write(&path, host.full_config()).and_then(|_| wgcore::set_owner_only_permissions(&path).map_err(std::io::Error::other)) {
                                        Ok(_) => out.modal = Some(Modal::Info { title: "Saved".into(), body: format!("Saved '{}' with {} peer(s) to:\n{}", host.name, host.peers.len(), path.display()) }),
                                        Err(e) => out.modal = Some(Modal::Error { title: "Save failed".into(), body: e.to_string() }),
                                    }
                                }
                            }
                            Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                        }
                    }
                });

                ui.separator();
                theme::button_column(ui, "Preview", |ui| {
                    if theme::sized_button(ui, theme::PREVIEW_BUTTON_WIDTH, "Preview Configuration").clicked() {
                        match self.build_full_model() {
                            Ok(host) => out.modal = Some(Modal::Preview { title: format!("Preview — {}.conf", host.name), body: host.full_config() }),
                            Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                        }
                    }

                    if theme::sized_button(ui, theme::PREVIEW_BUTTON_WIDTH, "Preview RouterOS Script").clicked() {
                        match self.build_routeros_script() {
                            Ok(script) => out.modal = Some(Modal::Preview { title: format!("RouterOS Script — {}", self.name), body: script }),
                            Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                        }
                    }

                    if theme::sized_button(ui, theme::PREVIEW_BUTTON_WIDTH, "Preview OpenWrt Configuration").clicked() {
                        match self.build_openwrt_script() {
                            Ok(script) => out.modal = Some(Modal::Preview { title: format!("OpenWrt Script — {}", self.name), body: script }),
                            Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                        }
                    }

                    if theme::sized_button(ui, theme::PREVIEW_BUTTON_WIDTH, "Preview pfSense Configuration").clicked() {
                        match self.build_pfsense_script() {
                            Ok(script) => out.modal = Some(Modal::Preview { title: format!("pfSense Script — {}", self.name), body: script }),
                            Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                        }
                    }
                });

                ui.separator();
                theme::button_column(ui, "Apply", |ui| {
                    if theme::sized_button(ui, theme::APPLY_BUTTON_WIDTH, "Apply Changes").clicked() {
                        match self.build_interface_model() {
                            Ok(_) => out.modal = Some(Modal::Info { title: "Applied".into(), body: format!("Changes applied for '{}'.", self.name) }),
                            Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                        }
                    }

                    if theme::sized_button(ui, theme::APPLY_BUTTON_WIDTH, "Apply to Device...").clicked() {
                        self.deploy.show_dialog = true;
                    }
                    if theme::sized_button(ui, theme::APPLY_BUTTON_WIDTH, "Copy from Device...")
                        .on_hover_text(
                            "Connect to a MikroTik/OpenWrt device over SSH and copy a WireGuard interface \
                             that already exists there -- with all its peers -- into the app for editing.",
                        )
                        .clicked()
                    {
                        self.deploy.show_dialog = true;
                    }
                    if !self.deploy.log.is_empty() && theme::sized_button(ui, theme::APPLY_BUTTON_WIDTH, "View Log").clicked() {
                        self.deploy.show_log = true;
                    }
                });

                ui.separator();
                theme::button_column(ui, "", |ui| {
                    if theme::danger_button(ui, "Close Host Tab").clicked() {
                        out.close_requested = true;
                    }
                });
            });

            let host_name = self.name.clone();
            match deploy::render_apply_dialog(ui.ctx(), &mut self.deploy, &host_name, true) {
                deploy::DialogAction::None => {}
                deploy::DialogAction::PlainExport { label } => match self.build_full_model() {
                    Ok(host) => {
                        let file_stem = crate::util::sanitize_filename_component(&label).unwrap_or_else(|| host.name.clone());
                        if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{file_stem}.conf")).add_filter("WireGuard config", &["conf"]).save_file() {
                            match std::fs::write(&path, host.full_config()).and_then(|_| wgcore::set_owner_only_permissions(&path).map_err(std::io::Error::other)) {
                                Ok(_) => {
                                    self.deploy.mark_applied_plain();
                                    out.modal = Some(Modal::Info { title: "Saved".into(), body: format!("Saved '{}' to:\n{}\n\nMarked this tab as applied.", host.name, path.display()) });
                                }
                                Err(e) => out.modal = Some(Modal::Error { title: "Save failed".into(), body: e.to_string() }),
                            }
                        }
                    }
                    Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                },
                deploy::DialogAction::Connect { device_type, target } => {
                    let script = match device_type {
                        DeviceType::MikroTik => self.build_routeros_script(),
                        DeviceType::OpenWrt => self.build_openwrt_script(),
                        DeviceType::PfSense => self.build_pfsense_script(),
                        DeviceType::PlainWg => unreachable!("plain WG never reaches the Connect action"),
                    };
                    match script {
                        Ok(script) => self.deploy.start(target, device_type, script),
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                    }
                }
            }
            deploy::render_log_window(ui.ctx(), &mut self.deploy, &host_name);
            self.ui_import_picker(ui.ctx(), out);

            if self.mesh_peers_enabled && !self.clients.is_empty() {
                let names = self.clients.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ");
                let eoip_note = if self.mesh_eoip { " Their RouterOS/OpenWrt exports will also bridge each of those links over EoIP (L2)." } else { "" };
                theme::hint(ui, &format!("Mesh peers together is on: {names} will all peer directly with each other, in addition to this host.{eoip_note}"));

                let conflict = (0..self.clients.len()).find_map(|i| {
                    let siblings = collect_client_mesh_peers(&self.clients, i);
                    find_mesh_address_conflict(&split_csv(&self.clients[i].address), &siblings)
                });
                if let Some(conflict) = conflict {
                    ui.colored_label(theme::DANGER, format!("⚠ Address conflict: {conflict} -- give each peer a distinct, non-overlapping Address or Save/Preview will refuse to build this config."));
                }
            }
        });
    }

    /// The "Other peers" table: peers with no client tab, one editable row
    /// each. This is where an interface copied from a device gets its peers
    /// added, removed and changed before being applied back.
    fn ui_extra_peers(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.colored_label(theme::ACCENT_DARK, egui::RichText::new("Other peers — known by public key only").strong());
            let mut remove = None;
            if !self.extra_peers.is_empty() {
                egui::ScrollArea::horizontal().id_salt(("extra-peers-scroll", self.id)).show(ui, |ui| {
                    egui::Grid::new(("extra-peers-grid", self.id)).num_columns(8).spacing([6.0, 4.0]).show(ui, |ui| {
                        for heading in ["Name", "Public Key", "Allowed IPs", "Endpoint", "Keepalive", "Pre-shared key", "Route", ""] {
                            ui.label(egui::RichText::new(heading).color(theme::TEXT_MUTED));
                        }
                        ui.end_row();
                        for (i, peer) in self.extra_peers.iter_mut().enumerate() {
                            ui.add(egui::TextEdit::singleline(&mut peer.name).desired_width(110.0));
                            ui.add(theme::mono(egui::TextEdit::singleline(&mut peer.public_key)).desired_width(200.0));
                            ui.add(egui::TextEdit::singleline(&mut peer.allowed_ips).desired_width(160.0));
                            ui.add(egui::TextEdit::singleline(&mut peer.endpoint).desired_width(150.0).hint_text("host:port"));
                            ui.add(egui::TextEdit::singleline(&mut peer.keepalive).desired_width(50.0));
                            ui.add(theme::mono(egui::TextEdit::singleline(&mut peer.psk)).password(true).desired_width(120.0));
                            ui.checkbox(&mut peer.route, "").on_hover_text(
                                "Have the device route this peer's Allowed IPs through the tunnel \
                                 (OpenWrt route_allowed_ips, a RouterOS /ip/route entry). Leave off for a \
                                 peer whose routing is already set up on the device.",
                            );
                            if ui.button("✕").on_hover_text("Remove this peer").clicked() {
                                remove = Some(i);
                            }
                            ui.end_row();
                        }
                    });
                });
            }
            if let Some(i) = remove {
                self.extra_peers.remove(i);
            }
            if ui.button("+ Add peer").clicked() {
                self.extra_peers.push(ExtraPeer { route: true, ..Default::default() });
            }
            theme::hint(
                ui,
                "Peers without a client tab: copied from a device, loaded from a .conf, or added here by \
                 public key. Applying to a MikroTik/OpenWrt device makes its peer list match these rows \
                 plus this host's client tabs -- a peer removed here is removed there.",
            );
        });
    }

    /// Shown once "Copy Interface from Device" has come back with what the
    /// device has: pick which interface goes where. A device with several
    /// WireGuard interfaces lists them all; each can replace this tab's
    /// settings or open as a host tab of its own.
    fn ui_import_picker(&mut self, ctx: &egui::Context, out: &mut HostUiOutcome) {
        let Some(found) = &self.deploy.imported else { return };
        let mut choice = None;

        egui::Window::new("Copy Interface from Device")
            .id(egui::Id::new(("import-picker", self.id)))
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!("{} has {} WireGuard interface(s):", self.deploy.target_description(), found.len()));
                ui.add_space(4.0);
                egui::Grid::new(("import-picker-grid", self.id)).num_columns(6).spacing([12.0, 6.0]).striped(true).show(ui, |ui| {
                    for heading in ["Interface", "Address", "Port", "Peers", "", ""] {
                        ui.label(egui::RichText::new(heading).color(theme::TEXT_MUTED));
                    }
                    ui.end_row();
                    for (i, iface) in found.iter().enumerate() {
                        ui.label(egui::RichText::new(&iface.name).strong());
                        ui.label(if iface.address.is_empty() { "—".to_string() } else { iface.address.join(", ") });
                        ui.label(iface.listen_port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string()));
                        ui.label(iface.peers.len().to_string());
                        if ui.button("Load into this tab").clicked() {
                            choice = Some(ImportChoice::LoadHere(i));
                        }
                        if ui.button("Open in new tab").clicked() {
                            choice = Some(ImportChoice::NewTab(i));
                        }
                        ui.end_row();
                    }
                });
                theme::hint(
                    ui,
                    "\"Load into this tab\" replaces this host's own settings (name, keys, address, port) \
                     and its \"Other peers\" rows; client tabs are kept. Nothing changes on the device \
                     until you apply.",
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if found.len() > 1 && ui.button("Open all in new tabs").clicked() {
                        choice = Some(ImportChoice::AllNewTabs);
                    }
                    if ui.button("Close").clicked() {
                        choice = Some(ImportChoice::Close);
                    }
                });
            });

        match choice {
            None => {}
            Some(ImportChoice::Close) => self.deploy.imported = None,
            Some(ImportChoice::NewTab(i)) => out.imported_hosts.push((found[i].clone(), self.deploy.for_another_tab())),
            Some(ImportChoice::AllNewTabs) => {
                out.imported_hosts.extend(found.iter().map(|iface| (iface.clone(), self.deploy.for_another_tab())));
                self.deploy.imported = None;
            }
            Some(ImportChoice::LoadHere(i)) => {
                let iface = found[i].clone();
                self.deploy.imported = None;
                out.modal = Some(match self.load_from_device(&iface) {
                    Ok((added, matched)) => {
                        let matched_note = if matched > 0 {
                            format!(" {matched} more already have a client tab here and stay as they are.")
                        } else {
                            String::new()
                        };
                        Modal::Info {
                            title: "Interface copied".into(),
                            body: format!(
                                "Loaded '{}' with {added} peer(s) into \"Other peers\".{matched_note}\n\n\
                                 Edit it, then use Apply to Device to write the changes back to that interface.",
                                iface.name
                            ),
                        }
                    }
                    Err(e) => Modal::Error { title: "Copy from device failed".into(), body: e },
                });
            }
        }
    }

    fn ui_client(&mut self, ui: &mut egui::Ui, idx: usize, out: &mut HostUiOutcome) {
        // Pull pool state out to a local so the allocate-address closure
        // below doesn't need `&mut self` while `self.clients[idx]` is
        // also mutably borrowed for its own `.ui()` call.
        self.ensure_pool_fresh();
        let mut pool = self.pool_take();

        let host_pubkey = self.public_key.clone();
        let host_name = self.name.clone();
        let host_public_ip = self.public_ip.clone();
        let host_listen_port = self.listen_port.clone();
        let host_dns = split_csv(&self.dns);
        let host_mtu: Option<u32> = self.mtu.trim().parse().ok();
        let host_tunnel_remote = wgcore::bare_ip_address(&split_csv(&self.address));
        let mesh_peers = if self.mesh_peers_enabled {
            collect_client_mesh_peers(&self.clients, idx)
        } else {
            Vec::new()
        };

        let ctx = ClientCtx {
            host_pubkey: &host_pubkey,
            host_name: &host_name,
            host_public_ip: &host_public_ip,
            host_listen_port: &host_listen_port,
            host_dns: &host_dns,
            host_mtu,
            host_tunnel_remote,
            mesh_enabled: self.mesh_peers_enabled,
            mesh_peers: &mesh_peers,
            mesh_eoip: self.mesh_eoip,
            host_eoip: self.host_eoip,
        };

        let client_out =
            self.clients[idx].ui(ui, &ctx, || pool.as_mut().and_then(|p| p.allocate().ok()));

        self.pool_put(pool);

        if let Some(m) = client_out.modal {
            out.modal = Some(m);
        }
        if client_out.close_requested {
            out.close_client_requested = Some(idx);
        }
    }

    /// The host's own RouterOS export: unaffected by "Mesh peers together",
    /// since meshing only adds links *between* this host's clients, not a
    /// new kind of link to the host itself -- see [`Self::build_full_model`].
    fn routeros_options(&self) -> RouterOsOptions {
        let mut opts = RouterOsOptions {
            interface_name: self.device_interface_name(),
            no_route_peers: self.unrouted_peer_keys(),
            skip_firewall: !self.manage_firewall,
            ..Default::default()
        };
        for client in &self.clients {
            if self.host_eoip {
                opts.eoip_peers.insert(client.public_key.clone());
            }
            if let Some(addr) = wgcore::bare_ip_address(&split_csv(&client.address)) {
                opts.peer_remote_addresses
                    .insert(client.public_key.clone(), addr);
            }
            if let Some(tid) = client.get_tunnel_id() {
                opts.peer_tunnel_ids.insert(client.public_key.clone(), tid);
            }
        }
        opts
    }

    fn build_routeros_script(&mut self) -> Result<String, String> {
        let host = self.build_full_model()?;
        Ok(wgcore::host_to_routeros_script(&host, &self.routeros_options()))
    }

    /// The host's own OpenWrt/UCI export, unaffected by "Mesh peers
    /// together" for the same reason as [`Self::build_routeros_script`].
    fn build_openwrt_script(&mut self) -> Result<String, String> {
        let host = self.build_full_model()?;
        let ros = self.routeros_options();
        let opts = wgcore::OpenWrtOptions {
            eoip: self.host_eoip,
            eoip_peers: Some(ros.eoip_peers),
            peer_remote_addresses: ros.peer_remote_addresses,
            peer_tunnel_ids: ros.peer_tunnel_ids,
            interface_name: ros.interface_name,
            no_route_peers: ros.no_route_peers,
            skip_firewall: ros.skip_firewall,
            ..Default::default()
        };
        Ok(wgcore::host_to_openwrt_script(&host, &opts))
    }

    fn build_pfsense_script(&mut self) -> Result<String, String> {
        let host = self.build_full_model()?;
        Ok(wgcore::host_to_pfsense_script(&host, &wgcore::PfSenseOptions::default()))
    }
}
