use eframe::egui;

use crate::client_tab::ClientTabState;
use crate::modal::Modal;
use crate::theme::{self, TEXT_MUTED};
use wgcore::{host_to_routeros_script, RouterOsOptions};

#[derive(Default)]
pub struct ClientUiOutcome {
    pub close_requested: bool,
    pub modal: Option<Modal>,
    pub sync_ran: bool,
}

pub struct ClientCtx<'a> {
    pub host_pubkey: &'a str,
    pub host_name: &'a str,
    pub host_public_ip: &'a str,
    pub host_listen_port: &'a str,
    pub host_dns: &'a [String],
    pub host_mtu: Option<u32>,
    pub host_tunnel_remote: Option<String>, // bare IP of the host, for RouterOS EoIP
}

impl ClientTabState {
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &ClientCtx<'_>,
        mut allocate_address: impl FnMut() -> Option<String>,
    ) -> ClientUiOutcome {
        let mut out = ClientUiOutcome::default();

        egui::ScrollArea::vertical().id_source(("client-scroll", self.id)).show(ui, |ui| {
            ui.group(|ui| {
                ui.colored_label(theme::ACCENT_DARK, egui::RichText::new("Client — its own [Interface]").strong());
                ui.checkbox(&mut self.advanced, "Advanced settings (DNS, MTU) — for fine-tuning; most clients don't need these");

                egui::Grid::new(("client-iface-grid", self.id)).num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.name);
                    ui.end_row();

                    ui.label("Private Key:");
                    ui.horizontal(|ui| {
                        let resp = ui.add_enabled(self.manual_key, theme::mono(egui::TextEdit::singleline(&mut self.private_key)).desired_width(320.0));
                        if resp.changed() || ui.checkbox(&mut self.manual_key, "Manual entry").changed() {
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

                    ui.label("Address:");
                    ui.horizontal(|ui| {
                        ui.add_enabled(self.address_manual, egui::TextEdit::singleline(&mut self.address).desired_width(140.0));
                        ui.checkbox(&mut self.address_manual, "Manual entry");
                        if ui.button("Reassign").clicked() {
                            match allocate_address() {
                                Some(addr) => self.address = addr,
                                None => {
                                    out.modal = Some(Modal::Error {
                                        title: "No subnet".into(),
                                        body: "The host needs an Address like 10.10.0.1/24 set (and applied) before \
                                               clients can auto-assign an IP from its subnet.".into(),
                                    })
                                }
                            }
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
                    }
                });
                theme::hint(ui, "Auto-assigned from the host's subnet, DNS/MTU e.g. 1.1.1.1 / 1420 (optional).");
            });

            ui.add_space(6.0);

            ui.group(|ui| {
                ui.colored_label(theme::ACCENT_DARK, egui::RichText::new("Link back to host — this client's [Peer] entry").strong());

                egui::Grid::new(("client-peer-grid", self.id)).num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
                    ui.label("Allowed IPs:");
                    ui.text_edit_singleline(&mut self.allowed_ips);
                    ui.end_row();

                    ui.label("Host Endpoint:");
                    ui.horizontal(|ui| {
                        ui.add_enabled(self.endpoint_manual, egui::TextEdit::singleline(&mut self.endpoint).desired_width(160.0));
                        if ui.checkbox(&mut self.endpoint_manual, "Manual entry").changed() && !self.endpoint_manual {
                            self.refresh_endpoint(ctx.host_public_ip, ctx.host_listen_port);
                        }
                    });
                    ui.end_row();

                    if self.advanced {
                        ui.label("Keepalive (s):");
                        ui.add(egui::TextEdit::singleline(&mut self.keepalive).desired_width(50.0));
                        ui.end_row();
                    }

                    ui.label("EoIP Tunnel ID:");
                    ui.horizontal(|ui| {
                        ui.add_enabled(self.tunnel_id_manual, egui::TextEdit::singleline(&mut self.tunnel_id).desired_width(70.0));
                        ui.checkbox(&mut self.tunnel_id_manual, "Manual entry");
                        if ui.button("Generate").clicked() {
                            self.generate_tunnel_id();
                        }
                    });
                    ui.end_row();

                    ui.label("Pre-shared key:");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.use_psk, "Use");
                        ui.add_enabled(self.use_psk && self.psk_manual, theme::mono(egui::TextEdit::singleline(&mut self.psk)).desired_width(220.0));
                        ui.checkbox(&mut self.psk_manual, "Manual entry");
                        if ui.button("Generate").clicked() {
                            self.generate_psk();
                        }
                    });
                    ui.end_row();
                });
                theme::hint(ui, "0.0.0.0/0 sends ALL traffic through the tunnel. Endpoint auto-fills from the host's \
                                 Public IP + Listen Port unless set manually. Tunnel ID is only used by the RouterOS export.");
            });

            ui.add_space(4.0);
            ui.colored_label(TEXT_MUTED, "Note: opening a config here applies it to THIS tab, replacing its current settings.");
            ui.add_space(4.0);

            ui.horizontal_wrapped(|ui| {
                if ui.button("Open Client Config...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().add_filter("WireGuard config", &["conf"]).pick_file() {
                        match std::fs::read_to_string(&path) {
                            Ok(text) => {
                                let name = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| self.name.clone());
                                match wgcore::load_host_from_config(&text, &name) {
                                    Ok(host) => {
                                        // Mirrors `_load_from_client()`: the
                                        // Tunnel ID field belongs to this
                                        // tab, not to the file being
                                        // opened, so it rides through
                                        // unchanged rather than resetting
                                        // to this fresh tab's default of 1.
                                        let tunnel_id = self.tunnel_id.clone();
                                        let tunnel_id_manual = self.tunnel_id_manual;
                                        *self = ClientTabState::from_loaded_host(self.id, &host);
                                        self.tunnel_id = tunnel_id;
                                        self.tunnel_id_manual = tunnel_id_manual;
                                        out.modal = Some(Modal::Info { title: "Loaded".into(), body: format!("Loaded '{}'.", path.display()) });
                                    }
                                    Err(e) => out.modal = Some(Modal::Error { title: "Failed to load config".into(), body: e.to_string() }),
                                }
                            }
                            Err(e) => out.modal = Some(Modal::Error { title: "Failed to load config".into(), body: e.to_string() }),
                        }
                    }
                }

                if ui.button("Save Configuration...").clicked() {
                    match self.sync(ctx.host_pubkey, ctx.host_name) {
                        Ok(synced) => {
                            out.sync_ran = true;
                            if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{}.conf", synced.client_model.name)).add_filter("WireGuard config", &["conf"]).save_file() {
                                match std::fs::write(&path, synced.client_model.full_config()) {
                                    Ok(_) => out.modal = Some(Modal::Info { title: "Saved".into(), body: format!("Saved to {}", path.display()) }),
                                    Err(e) => out.modal = Some(Modal::Error { title: "Save failed".into(), body: e.to_string() }),
                                }
                            }
                        }
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid client settings".into(), body: e }),
                    }
                }

                if ui.button("Preview Configuration").clicked() {
                    match self.sync(ctx.host_pubkey, ctx.host_name) {
                        Ok(synced) => {
                            out.sync_ran = true;
                            out.modal = Some(Modal::Preview { title: format!("Preview — {}.conf", synced.client_model.name), body: synced.client_model.full_config() });
                        }
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid client settings".into(), body: e }),
                    }
                }

                if ui.button("Copy Configuration").clicked() {
                    match self.sync(ctx.host_pubkey, ctx.host_name) {
                        Ok(synced) => {
                            out.sync_ran = true;
                            ui.output_mut(|o| o.copied_text = synced.client_model.full_config());
                        }
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid client settings".into(), body: e }),
                    }
                }

                if ui.button("Convert for RouterOS").clicked() {
                    match self.sync(ctx.host_pubkey, ctx.host_name) {
                        Ok(synced) => {
                            out.sync_ran = true;
                            let script = self.build_routeros_script(&synced.client_model, ctx);
                            ui.output_mut(|o| o.copied_text = script);
                        }
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid client settings".into(), body: e }),
                    }
                }

                if ui.button("Preview RouterOS Script").clicked() {
                    match self.sync(ctx.host_pubkey, ctx.host_name) {
                        Ok(synced) => {
                            out.sync_ran = true;
                            let script = self.build_routeros_script(&synced.client_model, ctx);
                            out.modal = Some(Modal::Preview { title: format!("RouterOS Script — {}", synced.client_model.name), body: script });
                        }
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid client settings".into(), body: e }),
                    }
                }

                if ui.button("Sync from Host").clicked() {
                    self.apply_host_defaults(
                        ctx.host_dns,
                        ctx.host_mtu,
                        ctx.host_public_ip,
                        ctx.host_listen_port,
                        true,
                        &mut allocate_address,
                    );
                    self.refresh_advanced_lock();
                    out.modal = Some(Modal::Info {
                        title: "Synced from host".into(),
                        body: "DNS, MTU, and Endpoint were refreshed from the host (Address is left as-is to avoid \
                               wasting pool addresses). Click Apply Changes to save.".into(),
                    });
                }

                if ui.button("Apply Changes").clicked() {
                    match self.sync(ctx.host_pubkey, ctx.host_name) {
                        Ok(_) => {
                            out.sync_ran = true;
                            out.modal = Some(Modal::Info { title: "Applied".into(), body: format!("Changes applied for '{}'.", self.name) });
                        }
                        Err(e) => out.modal = Some(Modal::Error { title: "Invalid client settings".into(), body: e }),
                    }
                }

                if theme::danger_button(ui, "Remove Client").clicked() {
                    out.close_requested = true;
                }
            });
        });

        out
    }

    fn build_routeros_script(&self, client_model: &wgcore::WireGuardHost, ctx: &ClientCtx<'_>) -> String {
        let mut opts = RouterOsOptions::default();
        if let Some(host_addr) = &ctx.host_tunnel_remote {
            opts.peer_remote_addresses.insert(ctx.host_pubkey.to_string(), host_addr.clone());
        }
        if let Some(tid) = self.get_tunnel_id() {
            opts.peer_tunnel_ids.insert(ctx.host_pubkey.to_string(), tid);
        }
        host_to_routeros_script(client_model, &opts)
    }
}
