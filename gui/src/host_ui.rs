use eframe::egui;

use crate::client_ui::ClientCtx;
use crate::host_tab::{HostSubTab, HostTabState};
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
}

impl HostTabState {
    pub fn ui(&mut self, ui: &mut egui::Ui) -> HostUiOutcome {
        let mut out = HostUiOutcome::default();

        // -- sub-tab strip: "Host Settings", one per client, "+" --------
        ui.horizontal_wrapped(|ui| {
            if ui.selectable_label(matches!(self.selected, HostSubTab::Settings), "Host Settings").clicked() {
                self.selected = HostSubTab::Settings;
            }
            for i in 0..self.clients.len() {
                let selected = matches!(self.selected, HostSubTab::Client(idx) if idx == i);
                let name = self.clients[i].name.clone();
                if ui.selectable_label(selected, name).clicked() {
                    self.selected = HostSubTab::Client(i);
                }
            }
            if ui.button("+").clicked() {
                self.new_client_tab(None);
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
        egui::ScrollArea::vertical().id_source(("host-scroll", self.id)).show(ui, |ui| {
            ui.group(|ui| {
                ui.colored_label(theme::ACCENT_DARK, egui::RichText::new("Host — [Interface]").strong());
                ui.checkbox(&mut self.advanced, "Advanced settings (DNS, MTU, Table, FwMark, hooks, SaveConfig) — most hosts don't need these");

                egui::Grid::new(("host-grid", self.id)).num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.name);
                    ui.end_row();

                    ui.label("Private Key:");
                    ui.horizontal(|ui| {
                        ui.add_enabled(self.manual_key, theme::mono(egui::TextEdit::singleline(&mut self.private_key)).desired_width(320.0));
                        if ui.checkbox(&mut self.manual_key, "Manual entry").changed() && !self.manual_key {
                            self.refresh_public_key();
                        }
                        if ui.button("Generate").clicked() {
                            self.regenerate_key();
                        }
                        theme::copy_button(ui, &self.private_key);
                    });
                    ui.end_row();

                    ui.label("Public Key:");
                    ui.horizontal(|ui| {
                        ui.add_enabled(false, theme::mono(egui::TextEdit::singleline(&mut self.public_key)).desired_width(320.0));
                        theme::copy_button(ui, &self.public_key);
                    });
                    ui.end_row();

                    ui.label("Address(es):");
                    ui.text_edit_singleline(&mut self.address);
                    ui.end_row();

                    ui.label("Listen Port:");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.listen_port).desired_width(70.0));
                        if ui.button("Random").clicked() {
                            self.randomize_listen_port();
                        }
                    });
                    ui.end_row();

                    if self.advanced {
                        ui.label("DNS:");
                        ui.text_edit_singleline(&mut self.dns);
                        ui.end_row();
                        ui.label("MTU:");
                        ui.add(egui::TextEdit::singleline(&mut self.mtu).desired_width(60.0));
                        ui.end_row();
                        ui.label("Table:");
                        ui.text_edit_singleline(&mut self.table);
                        ui.end_row();
                        ui.label("FwMark:");
                        ui.text_edit_singleline(&mut self.fwmark);
                        ui.end_row();
                        ui.label("SaveConfig:");
                        ui.checkbox(&mut self.save_config, "");
                        ui.end_row();
                    }

                    ui.label("Public IP Address:");
                    ui.text_edit_singleline(&mut self.public_ip);
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
            ui.horizontal_wrapped(|ui| {
                if ui.button("Load Configuration...").clicked() {
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

                if ui.button("Save Configuration...").clicked() {
                    match self.build_full_model() {
                        Ok(host) => {
                            if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{}.conf", host.name)).add_filter("WireGuard config", &["conf"]).save_file() {
                                match std::fs::write(&path, host.full_config()) {
                                    Ok(_) => out.modal = Some(Modal::Info { title: "Saved".into(), body: format!("Saved '{}' with {} peer(s) to:\n{}", host.name, host.peers.len(), path.display()) }),
                                    Err(e) => out.modal = Some(Modal::Error { title: "Save failed".into(), body: e.to_string() }),
                                }
                            }
                        }
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                    }
                }

                if ui.button("Preview Configuration").clicked() {
                    match self.build_full_model() {
                        Ok(host) => out.modal = Some(Modal::Preview { title: format!("Preview — {}.conf", host.name), body: host.full_config() }),
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                    }
                }

                if ui.button("Copy Configuration").clicked() {
                    match self.build_full_model() {
                        Ok(host) => ui.output_mut(|o| o.copied_text = host.full_config()),
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                    }
                }

                if ui.button("Convert for RouterOS").clicked() {
                    match self.build_routeros_script() {
                        Ok(script) => ui.output_mut(|o| o.copied_text = script),
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                    }
                }

                if ui.button("Preview RouterOS Script").clicked() {
                    match self.build_routeros_script() {
                        Ok(script) => out.modal = Some(Modal::Preview { title: format!("RouterOS Script — {}", self.name), body: script }),
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                    }
                }

                if ui.button("Apply Changes").clicked() {
                    match self.build_interface_model() {
                        Ok(_) => out.modal = Some(Modal::Info { title: "Applied".into(), body: format!("Changes applied for '{}'.", self.name) }),
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid host settings".into(), body: e }),
                    }
                }

                if theme::danger_button(ui, "Close Host Tab").clicked() {
                    out.close_requested = true;
                }
            });
        });
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

        let ctx = ClientCtx {
            host_pubkey: &host_pubkey,
            host_name: &host_name,
            host_public_ip: &host_public_ip,
            host_listen_port: &host_listen_port,
            host_dns: &host_dns,
            host_mtu,
            host_tunnel_remote,
        };

        let client_out = self.clients[idx].ui(ui, &ctx, || pool.as_mut().and_then(|p| p.allocate().ok()));

        self.pool_put(pool);

        if let Some(m) = client_out.modal {
            out.modal = Some(m);
        }
        if client_out.close_requested {
            out.close_client_requested = Some(idx);
        }
    }

    fn build_routeros_script(&mut self) -> Result<String, String> {
        let host = self.build_full_model()?;
        let mut opts = RouterOsOptions::default();
        for client in &self.clients {
            if let Some(addr) = wgcore::bare_ip_address(&split_csv(&client.address)) {
                opts.peer_remote_addresses.insert(client.public_key.clone(), addr);
            }
            if let Some(tid) = client.get_tunnel_id() {
                opts.peer_tunnel_ids.insert(client.public_key.clone(), tid);
            }
        }
        Ok(wgcore::host_to_routeros_script(&host, &opts))
    }
}
