use std::path::PathBuf;

use eframe::egui;

use crate::db;
use crate::host_tab::HostTabState;
use crate::modal::Modal;
use crate::project::{HostProjectDict, ProjectFile, PROJECT_FORMAT_VERSION};
use crate::theme;

#[derive(Clone)]
enum PendingConfirm {
    CloseHost { host_idx: usize },
    CloseClient { host_idx: usize, client_idx: usize },
    ResetProject,
    /// Confirmed replacement of the in-memory project with `data`, loaded
    /// from `path` (with `password` if it was encrypted) via "Restore From
    /// Backup..." in the Database window -- unlike plain "Open Project",
    /// this one asks first, since it's framed as restoring over whatever
    /// is currently open rather than a routine file pick.
    RestoreProject {
        data: ProjectFile,
        path: PathBuf,
        password: Option<String>,
    },
}

/// What a password prompt window (see `ui_password_prompt`) is for --
/// unlocking an encrypted project being opened (either "Open Project" or
/// "Restore From Backup..."), or (optionally) encrypting one that's about
/// to be written to disk.
enum PendingPassword {
    OpenLocked { path: PathBuf },
    RestoreLocked { path: PathBuf },
    SaveProject { path: PathBuf, project: ProjectFile },
}

/// Which of the three encryption actions the password dialog (see
/// `ui_encryption_dialog`) is currently showing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EncryptionDialogKind {
    Enable,
    ChangePassword,
    Disable,
}

/// State for the password prompt window: which action it's for, the
/// password typed so far, and an error from the last attempt (if any --
/// e.g. a wrong password), shown inline so the window stays open to retry.
struct PasswordPrompt {
    action: PendingPassword,
    input: String,
    error: Option<String>,
}

pub struct WgStudioApp {
    hosts: Vec<HostTabState>,
    selected_host: usize,
    host_counter: u64,
    confirm_close: bool,
    modal: Option<Modal>,
    confirm: Option<(String, String, PendingConfirm)>,
    password_prompt: Option<PasswordPrompt>,
    theme_applied: bool,

    // -- Project file/encryption tracking, Database window, action log --
    /// Where the currently open project last loaded from or saved to, if
    /// anywhere -- backup, restore, "show file location", and the
    /// encryption controls in the Database window all act on this file.
    /// `None` until the project has been saved or opened at least once.
    current_project_path: Option<PathBuf>,
    /// The password the current project file is encrypted with, if any --
    /// kept in memory only (never written back to disk itself) so backups
    /// and "Save" can reuse it without re-prompting.
    current_project_password: Option<String>,
    db_window_open: bool,
    /// Auto-backup configuration -- persisted independently of any single
    /// project file (see `db::AppSettings`'s doc comment).
    settings: db::AppSettings,
    /// Cheap `Instant` gate so the (comparatively expensive) auto-backup
    /// due-check only runs about once a minute rather than every frame.
    next_auto_backup_check: std::time::Instant,
    pending_encryption_dialog: Option<EncryptionDialogKind>,
    encryption_password_input: String,
    encryption_password_confirm: String,
    encryption_error: Option<String>,
    action_log_window_open: bool,
    pending_clear_action_log: bool,
}

impl Default for WgStudioApp {
    fn default() -> Self {
        let mut app = WgStudioApp {
            hosts: Vec::new(),
            selected_host: 0,
            host_counter: 0,
            confirm_close: true,
            modal: None,
            confirm: None,
            password_prompt: None,
            theme_applied: false,
            current_project_path: None,
            current_project_password: None,
            db_window_open: false,
            settings: db::load_settings(),
            next_auto_backup_check: std::time::Instant::now(),
            pending_encryption_dialog: None,
            encryption_password_input: String::new(),
            encryption_password_confirm: String::new(),
            encryption_error: None,
            action_log_window_open: false,
            pending_clear_action_log: false,
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

    /// Records one user action to the persisted action log (see the
    /// "Journal" button, bottom right). A logging failure shouldn't mask
    /// or interrupt the action it's describing, which has already
    /// succeeded by the time this is called -- so it only goes to stderr.
    fn log_action(&mut self, message: impl Into<String>) {
        if let Err(e) = db::log_action(message) {
            eprintln!("Could not write to the action log: {e:#}");
        }
    }

    /// Builds the current in-memory project as a `ProjectFile`, syncing
    /// every host's (and its clients') form state first -- the same two
    /// steps `save_project` always did, now shared with backups and
    /// auto-backups too.
    fn snapshot_project(&mut self) -> Result<ProjectFile, String> {
        let mut hosts_dicts: Vec<HostProjectDict> = Vec::with_capacity(self.hosts.len());
        for host in &mut self.hosts {
            host.build_full_model()?;
            hosts_dicts.push(host.to_project_dict());
        }
        Ok(ProjectFile {
            version: PROJECT_FORMAT_VERSION,
            hosts: hosts_dicts,
        })
    }

    // -- Header -----------------------------------------------------------

    fn ui_header(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("header").show(ui, |ui| {
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

            egui::Frame::default().fill(theme::BG_HEADER).inner_margin(egui::Margin::symmetric(12, 10)).show(ui, |ui| {
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
                        if ui.button("Database...").clicked() {
                            self.db_window_open = true;
                        }
                        // ui.checkbox(&mut self.confirm_close, "Confirm before closing tabs");
                        ui.checkbox(&mut self.confirm_close, "");
                    });
                });
            });
        });
    }

    // -- Host tab strip -----------------------------------------------------

    fn ui_host_tabs(&mut self, ui: &mut egui::Ui) {
        // Drain every host's (and every one of its clients') "Apply to
        // Device" progress unconditionally, not just the selected one --
        // see `HostTabState::poll_deploys`'s doc comment for why.
        for host in &mut self.hosts {
            if let Some(m) = host.poll_deploys() {
                self.modal = Some(m);
            }
        }
        if self.hosts.iter().any(|h| h.any_deploy_running()) {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                for i in 0..self.hosts.len() {
                    let name = self.hosts[i].name.clone();
                    if crate::deploy::labeled_tab_button(ui, i == self.selected_host, &name, &self.hosts[i].deploy).clicked() {
                        self.selected_host = i;
                    }
                }
                if ui.button("+").clicked() {
                    let idx = self.new_host_tab();
                    let name = self.hosts[idx].name.clone();
                    self.log_action(format!("Added host '{name}'"));
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
            let host_name = self.hosts[idx].name.clone();
            let out = self.hosts[idx].ui(ui);
            if let Some(client_name) = &out.client_added {
                self.log_action(format!("Added client '{client_name}' to host '{host_name}'"));
            }

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
                    let client_name = self.hosts[idx].clients[client_idx].name.clone();
                    self.hosts[idx].close_client_tab(client_idx);
                    self.log_action(format!("Removed client '{client_name}' from host '{host_name}'"));
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
                    self.log_action(format!("Removed host '{host_name}'"));
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
            // No native title-bar close button on any of these: egui draws
            // it as two bare lines in the "button text" color with no
            // background behind them (see `close_button` in its own
            // `containers/window.rs`) -- against this app's white window
            // background, that color is the same white used for text on
            // this theme's blue/dark button fills elsewhere, making the X
            // unreadable. Every one of these already has an explicit
            // dismiss button, so the X was always redundant, not just
            // broken -- simplest fix is to not draw it at all.
            match &modal {
                Modal::Info { title, body } => {
                    egui::Window::new(title.clone())
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
                                    ui.ctx().copy_text(body.clone());
                                }
                                if ui.button("Close").clicked() {
                                    self.modal = None;
                                }
                            });
                        });
                }
            }
        }

        if let Some((title, body, _)) = self.confirm.clone() {
            let mut decision: Option<bool> = None;
            egui::Window::new(title)
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
            if let Some(yes) = decision {
                let (_, _, action) = self.confirm.take().unwrap();
                if yes {
                    match action {
                        PendingConfirm::CloseHost { host_idx } => {
                            if let Some(h) = self.hosts.get(host_idx) {
                                let name = h.name.clone();
                                self.close_host_tab(host_idx);
                                self.log_action(format!("Removed host '{name}'"));
                            }
                        }
                        PendingConfirm::CloseClient {
                            host_idx,
                            client_idx,
                        } => {
                            if let Some(h) = self.hosts.get_mut(host_idx) {
                                if let Some(c) = h.clients.get(client_idx) {
                                    let client_name = c.name.clone();
                                    let host_name = h.name.clone();
                                    h.close_client_tab(client_idx);
                                    self.log_action(format!(
                                        "Removed client '{client_name}' from host '{host_name}'"
                                    ));
                                }
                            }
                        }
                        PendingConfirm::ResetProject => self.reset_project(),
                        PendingConfirm::RestoreProject { data, path, password } => {
                            self.finish_restore_project(data, path, password);
                        }
                    }
                }
            }
        }

        self.ui_password_prompt(ctx);
    }

    /// Password prompt window for both halves of project encryption: this
    /// covers unlocking an encrypted project on open (password required,
    /// wrong password re-shows the same window with an inline error) and
    /// optionally encrypting one on save (password may be left blank for
    /// no encryption at all).
    fn ui_password_prompt(&mut self, ctx: &egui::Context) {
        let Some(prompt) = &mut self.password_prompt else {
            return;
        };
        let is_unlock = matches!(
            prompt.action,
            PendingPassword::OpenLocked { .. } | PendingPassword::RestoreLocked { .. }
        );
        let title = if is_unlock {
            "Encrypted project -- enter password"
        } else {
            "Encrypt project? (optional)"
        };
        let confirm_label = if is_unlock { "Unlock" } else { "Save" };

        let mut submit = false;
        let mut cancel = false;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                if !is_unlock {
                    ui.label("Leave blank to save without encryption.");
                }
                let response = ui.add(
                    egui::TextEdit::singleline(&mut prompt.input)
                        .password(true)
                        .desired_width(240.0)
                        .hint_text("Password"),
                );
                if let Some(err) = &prompt.error {
                    ui.colored_label(theme::DANGER, err);
                }
                ui.horizontal(|ui| {
                    if ui.button(confirm_label).clicked()
                        || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    {
                        submit = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if cancel {
            self.password_prompt = None;
            return;
        }
        if !submit {
            return;
        }

        let Some(PasswordPrompt { action, input, .. }) = self.password_prompt.take() else {
            return;
        };
        match action {
            PendingPassword::OpenLocked { path } => match db::unlock(&path, &input) {
                Ok(data) => self.finish_open_project(data, path, Some(input)),
                Err(e) => {
                    self.password_prompt = Some(PasswordPrompt {
                        action: PendingPassword::OpenLocked { path },
                        input: String::new(),
                        error: Some(format!("{e:#}")),
                    });
                }
            },
            PendingPassword::RestoreLocked { path } => match db::unlock(&path, &input) {
                Ok(data) => self.confirm_restore(data, path, Some(input)),
                Err(e) => {
                    self.password_prompt = Some(PasswordPrompt {
                        action: PendingPassword::RestoreLocked { path },
                        input: String::new(),
                        error: Some(format!("{e:#}")),
                    });
                }
            },
            PendingPassword::SaveProject { path, project } => {
                self.finish_save_project(path, project, &input);
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
        if self.modal.is_some()
            || self.confirm.is_some()
            || self.password_prompt.is_some()
            || self.db_window_open
            || self.pending_encryption_dialog.is_some()
            || self.action_log_window_open
            || self.hosts.is_empty()
        {
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
            let host_name = self.hosts[idx].name.clone();
            let client_idx = self.hosts[idx].new_client_tab(None);
            let client_name = self.hosts[idx].clients[client_idx].name.clone();
            self.log_action(format!("Added client '{client_name}' to host '{host_name}'"));
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
                        let host_name = self.hosts[idx].name.clone();
                        let client_name = self.hosts[idx].clients[client_idx].name.clone();
                        self.hosts[idx].close_client_tab(client_idx);
                        self.log_action(format!("Removed client '{client_name}' from host '{host_name}'"));
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
                        let host_name = self.hosts[idx].name.clone();
                        self.close_host_tab(idx);
                        self.log_action(format!("Removed host '{host_name}'"));
                    }
                }
            }
        }
    }

    // -- Project I/O ----------------------------------------------------

    fn open_project(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("WireGuard Studio project", &["db", "json"])
            .pick_file()
        else {
            return;
        };
        match db::try_open(&path) {
            Ok(db::OpenOutcome::Ready(data)) => self.finish_open_project(data, path, None),
            Ok(db::OpenOutcome::Locked) => {
                self.password_prompt = Some(PasswordPrompt {
                    action: PendingPassword::OpenLocked { path },
                    input: String::new(),
                    error: None,
                });
            }
            Err(e) => self.error(
                "Failed to open project",
                format!("Could not read this file:\n{e:#}"),
            ),
        }
    }

    fn finish_open_project(&mut self, data: ProjectFile, path: PathBuf, password: Option<String>) {
        self.load_project(data);
        self.current_project_path = Some(path.clone());
        self.current_project_password = password;
        self.log_action(format!("Opened project: {}", path.display()));
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
        let project = match self.snapshot_project() {
            Ok(p) => p,
            Err(e) => return self.error("Save failed", e),
        };

        let Some(path) = rfd::FileDialog::new()
            .set_file_name("wireguard-project.db")
            .add_filter("WireGuard Studio project", &["db"])
            .save_file()
        else {
            return;
        };

        // Encryption is optional -- ask for a password (which can be left
        // blank) before actually writing the file.
        self.password_prompt = Some(PasswordPrompt {
            action: PendingPassword::SaveProject { path, project },
            input: String::new(),
            error: None,
        });
    }

    fn finish_save_project(&mut self, path: PathBuf, project: ProjectFile, password: &str) {
        let password_opt = (!password.is_empty()).then_some(password);
        if let Err(e) = db::save(&path, &project, password_opt) {
            return self.error("Save failed", format!("{e:#}"));
        }
        // The project file contains every host/client's private key in
        // plaintext when unencrypted, so it needs the same owner-only
        // permissions as an exported .conf, not just the
        // WireGuardHost::save() path.
        if let Err(e) = wgcore::set_owner_only_permissions(&path) {
            return self.error("Save failed", e.to_string());
        }
        self.current_project_password = password_opt.map(str::to_string);
        self.current_project_path = Some(path.clone());
        self.log_action(format!("Saved project: {}", path.display()));
        self.info("Saved", format!("Project saved to:\n{}", path.display()));
    }

    fn reset_project(&mut self) {
        self.hosts.clear();
        self.host_counter = 0;
        self.new_host_tab();
        self.log_action("Project reset (all hosts and clients removed)");
    }

    // -- Database window: backup/restore, auto-backup, encryption -------

    /// Writes the current in-memory project to a new file the user picks,
    /// encrypted the same way as the current project (if at all) -- no
    /// extra password prompt, since this reuses whatever's already set.
    fn backup_project(&mut self) {
        let project = match self.snapshot_project() {
            Ok(p) => p,
            Err(e) => return self.error("Backup failed", e),
        };
        let default_name = format!("wireguard-studio_backup_{}.db", chrono::Local::now().format("%Y-%m-%d"));
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(default_name)
            .add_filter("WireGuard Studio project", &["db"])
            .save_file()
        else {
            return;
        };
        match db::save(&path, &project, self.current_project_password.as_deref()) {
            Ok(()) => {
                let _ = wgcore::set_owner_only_permissions(&path);
                self.log_action(format!("Backed up project to: {}", path.display()));
                self.info("Backup created", format!("Backup saved to:\n{}", path.display()));
            }
            Err(e) => self.error("Backup failed", format!("{e:#}")),
        }
    }

    /// Picks a backup file and, once it's confirmed readable (prompting
    /// for a password first if it's encrypted), asks for confirmation
    /// before replacing the current in-memory project with it -- unlike
    /// "Open Project", this one is framed as an explicit, deliberate
    /// restore over whatever's currently open.
    fn restore_project_pick(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("WireGuard Studio project", &["db", "json"])
            .pick_file()
        else {
            return;
        };
        match db::try_open(&path) {
            Ok(db::OpenOutcome::Ready(data)) => self.confirm_restore(data, path, None),
            Ok(db::OpenOutcome::Locked) => {
                self.password_prompt = Some(PasswordPrompt {
                    action: PendingPassword::RestoreLocked { path },
                    input: String::new(),
                    error: None,
                });
            }
            Err(e) => self.error(
                "Failed to load backup",
                format!("Could not read this file:\n{e:#}"),
            ),
        }
    }

    fn confirm_restore(&mut self, data: ProjectFile, path: PathBuf, password: Option<String>) {
        self.confirm = Some((
            "Restore project".into(),
            format!(
                "Replace the current project with the one from:\n{}\n\nUnsaved changes in the current project will be lost.",
                path.display()
            ),
            PendingConfirm::RestoreProject { data, path, password },
        ));
    }

    fn finish_restore_project(&mut self, data: ProjectFile, path: PathBuf, password: Option<String>) {
        self.load_project(data);
        self.current_project_path = Some(path.clone());
        self.current_project_password = password;
        self.log_action(format!("Restored project from backup: {}", path.display()));
        self.info("Project restored", format!("Restored from:\n{}", path.display()));
    }

    /// Reveals the current project file in the system file manager (Finder
    /// on macOS, Explorer on Windows, ...).
    fn reveal_project_location(&mut self) {
        let Some(path) = &self.current_project_path else {
            return;
        };
        if let Err(e) = opener::reveal(path) {
            self.error("Could not show file location", e.to_string());
        }
    }

    fn pick_auto_backup_dir(&mut self) {
        let Some(dir) = rfd::FileDialog::new().pick_folder() else {
            return;
        };
        self.settings.auto_backup_dir = Some(dir.to_string_lossy().into_owned());
        if let Err(e) = db::save_settings(&self.settings) {
            self.error("Settings not saved", format!("{e:#}"));
        }
    }

    /// Runs an automatic backup if one is enabled and due. Called about
    /// once a minute from `update` -- see `next_auto_backup_check`.
    fn maybe_run_auto_backup(&mut self) {
        if !self.settings.auto_backup_enabled {
            return;
        }
        let due = match &self.settings.last_auto_backup_at {
            Some(ts) => chrono::DateTime::parse_from_rfc3339(ts)
                .map(|dt| {
                    let elapsed_hours = (chrono::Local::now() - dt.with_timezone(&chrono::Local)).num_hours();
                    elapsed_hours >= self.settings.auto_backup_interval_hours as i64
                })
                .unwrap_or(true),
            None => true,
        };
        if !due {
            return;
        }
        // A form with a validation error right now just means "try again
        // on the next check" -- an automatic background tick is the wrong
        // place to interrupt the user with an error dialog about it.
        let Ok(project) = self.snapshot_project() else {
            return;
        };
        match db::run_auto_backup(&project, self.current_project_password.as_deref(), &self.settings) {
            Ok(dest) => {
                self.settings.last_auto_backup_at = Some(chrono::Local::now().to_rfc3339());
                let _ = db::save_settings(&self.settings);
                self.log_action(format!("Automatic backup created: {}", dest.display()));
            }
            Err(e) => eprintln!("Automatic backup failed: {e:#}"),
        }
    }

    /// Enables, disables, or changes the password of the current project
    /// file's encryption. Since the whole in-memory model is already held
    /// in `self.hosts` rather than a live database connection, this is
    /// just "write it back out with a different key", unlike
    /// `attestation_db`'s equivalent (which has to re-export a live
    /// SQLCipher connection into a fresh file).
    fn reencrypt_current_project(&mut self, new_password: &str) {
        let Some(path) = self.current_project_path.clone() else {
            return;
        };
        let project = match self.snapshot_project() {
            Ok(p) => p,
            Err(e) => return self.error("Encryption change failed", e),
        };
        let password_opt = (!new_password.is_empty()).then_some(new_password);
        if let Err(e) = db::save(&path, &project, password_opt) {
            return self.error("Encryption change failed", format!("{e:#}"));
        }
        if let Err(e) = wgcore::set_owner_only_permissions(&path) {
            return self.error("Encryption change failed", e.to_string());
        }
        self.current_project_password = password_opt.map(str::to_string);
        let enabled = self.current_project_password.is_some();
        self.log_action(if enabled {
            "Project encryption enabled or password changed"
        } else {
            "Project encryption disabled"
        });
        self.info(
            "Done",
            if enabled { "Encryption enabled." } else { "Encryption disabled." },
        );
    }

    /// The "Database..." window: whole-project backup/restore, scheduled
    /// automatic backups, and project file encryption -- reachable only
    /// from its own header button, separate from the everyday
    /// Save/Open-Project buttons.
    fn ui_database_window(&mut self, ctx: &egui::Context) {
        if !self.db_window_open {
            return;
        }
        egui::Window::new("Project Database")
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .default_height(520.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    ui.add_space(4.0);
                    ui.label(
                        "Saves/loads the whole project file (every host and client) -- handy for \
                         moving it to another device.",
                    );
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("💾 Backup Project...").clicked() {
                            self.backup_project();
                        }
                        if ui.button("📂 Restore From Backup...").clicked() {
                            self.restore_project_pick();
                        }
                    });
                    ui.add_space(14.0);

                    ui.group(|ui| {
                        ui.set_width(ui.available_width());
                        if ui
                            .checkbox(&mut self.settings.auto_backup_enabled, "Automatic backups")
                            .changed()
                        {
                            if let Err(e) = db::save_settings(&self.settings) {
                                self.error("Settings not saved", format!("{e:#}"));
                            }
                            // Just turned on -- don't wait a whole interval
                            // for the first one.
                            self.next_auto_backup_check = std::time::Instant::now();
                        }

                        ui.add_enabled_ui(self.settings.auto_backup_enabled, |ui| {
                            ui.add_space(6.0);
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Frequency:");
                                let intervals: [(u32, &str); 5] = [
                                    (1, "every hour"),
                                    (6, "every 6 hours"),
                                    (12, "every 12 hours"),
                                    (24, "daily"),
                                    (168, "weekly"),
                                ];
                                let current_label = intervals
                                    .iter()
                                    .find(|(h, _)| *h == self.settings.auto_backup_interval_hours)
                                    .map(|(_, l)| *l)
                                    .unwrap_or("custom interval");
                                egui::ComboBox::from_id_salt("auto_backup_interval")
                                    .selected_text(current_label)
                                    .show_ui(ui, |ui| {
                                        for (hours, label) in intervals {
                                            if ui
                                                .selectable_label(
                                                    self.settings.auto_backup_interval_hours == hours,
                                                    label,
                                                )
                                                .clicked()
                                            {
                                                self.settings.auto_backup_interval_hours = hours;
                                                if let Err(e) = db::save_settings(&self.settings) {
                                                    self.error("Settings not saved", format!("{e:#}"));
                                                }
                                            }
                                        }
                                    });
                            });
                            ui.add_space(4.0);
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Backup folder:");
                                let dir_display = self
                                    .settings
                                    .auto_backup_dir_path()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|_| "could not determine".to_string());
                                ui.weak(dir_display);
                                if ui.button("Change Folder...").clicked() {
                                    self.pick_auto_backup_dir();
                                }
                            });
                            ui.add_space(4.0);
                            let last_backup_label = match &self.settings.last_auto_backup_at {
                                Some(ts) => chrono::DateTime::parse_from_rfc3339(ts)
                                    .map(|dt| dt.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
                                    .unwrap_or_else(|_| ts.clone()),
                                None => "never yet".to_string(),
                            };
                            ui.weak(format!(
                                "Last automatic backup: {last_backup_label}. Keeping the last {} copies.",
                                self.settings.auto_backup_keep_count
                            ));
                        });
                    });
                    ui.add_space(10.0);

                    ui.group(|ui| {
                        ui.set_width(ui.available_width());
                        if self.current_project_path.is_none() {
                            ui.weak("Save the project to a file first to enable encryption.");
                        } else {
                            if self.current_project_password.is_some() {
                                ui.colored_label(theme::SUCCESS, "🔒 Project encryption is on");
                            } else {
                                ui.weak("🔓 Project encryption is off");
                            }
                            ui.add_space(4.0);
                            ui.label(
                                "With encryption on, the password is required every time this \
                                 project file is opened. A forgotten password can't be recovered \
                                 -- there's no backdoor. Keep it somewhere safe.",
                            );
                            ui.add_space(6.0);
                            ui.horizontal_wrapped(|ui| {
                                if self.current_project_password.is_none() {
                                    if ui.button("🔒 Enable Encryption...").clicked() {
                                        self.pending_encryption_dialog = Some(EncryptionDialogKind::Enable);
                                        self.encryption_password_input.clear();
                                        self.encryption_password_confirm.clear();
                                        self.encryption_error = None;
                                    }
                                } else {
                                    if ui.button("🔑 Change Password...").clicked() {
                                        self.pending_encryption_dialog = Some(EncryptionDialogKind::ChangePassword);
                                        self.encryption_password_input.clear();
                                        self.encryption_password_confirm.clear();
                                        self.encryption_error = None;
                                    }
                                    if ui
                                        .add(egui::Button::new(
                                            egui::RichText::new("🔓 Disable Encryption...").color(theme::DANGER),
                                        ))
                                        .clicked()
                                    {
                                        self.pending_encryption_dialog = Some(EncryptionDialogKind::Disable);
                                        self.encryption_error = None;
                                    }
                                }
                            });
                        }
                    });
                    ui.add_space(10.0);

                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(
                                self.current_project_path.is_some(),
                                egui::Button::new("📂 Show Project File Location"),
                            )
                            .clicked()
                        {
                            self.reveal_project_location();
                        }
                        if theme::danger_button(ui, "🗑 Clear Current Project").clicked() {
                            self.confirm = Some((
                                "Reset project".into(),
                                "This will remove every host and client tab and can't be undone. Reset the project?".into(),
                                PendingConfirm::ResetProject,
                            ));
                        }
                    });
                });

                ui.add_space(8.0);
                ui.separator();
                if ui.button("Close").clicked() {
                    self.db_window_open = false;
                }
            });
    }

    /// Enable / change-password / disable dialog for project encryption,
    /// opened from the buttons in `ui_database_window`.
    fn ui_encryption_dialog(&mut self, ctx: &egui::Context) {
        let Some(kind) = self.pending_encryption_dialog else {
            return;
        };
        let needs_password = matches!(kind, EncryptionDialogKind::Enable | EncryptionDialogKind::ChangePassword);
        let title = match kind {
            EncryptionDialogKind::Enable => "Enable Project Encryption",
            EncryptionDialogKind::ChangePassword => "Change Project Password",
            EncryptionDialogKind::Disable => "Disable Project Encryption",
        };
        let mut do_confirm = false;
        let mut do_cancel = false;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(420.0)
            .show(ctx, |ui| {
                if needs_password {
                    ui.label("New password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.encryption_password_input)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(4.0);
                    ui.label("Confirm password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.encryption_password_confirm)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(6.0);
                    ui.colored_label(
                        theme::WARNING,
                        "A forgotten password can't be recovered -- the data would be lost for \
                         good. Write it down somewhere safe.",
                    );
                } else {
                    ui.label("Disable encryption and store the project file as plain text?");
                    ui.add_space(4.0);
                    ui.colored_label(theme::DANGER, "The file on disk will become readable without a password.");
                }
                if let Some(err) = &self.encryption_error {
                    ui.add_space(6.0);
                    ui.colored_label(theme::DANGER, err);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let confirm_label = match kind {
                        EncryptionDialogKind::Enable => "Enable",
                        EncryptionDialogKind::ChangePassword => "Change Password",
                        EncryptionDialogKind::Disable => "Disable",
                    };
                    if ui.button(confirm_label).clicked() {
                        do_confirm = true;
                    }
                    if ui.button("Cancel").clicked() {
                        do_cancel = true;
                    }
                });
            });

        if do_confirm {
            if needs_password {
                if self.encryption_password_input.is_empty() {
                    self.encryption_error = Some("Password cannot be empty".to_string());
                } else if self.encryption_password_input != self.encryption_password_confirm {
                    self.encryption_error = Some("Passwords do not match".to_string());
                } else {
                    let password = self.encryption_password_input.clone();
                    self.reencrypt_current_project(&password);
                    self.encryption_password_input.clear();
                    self.encryption_password_confirm.clear();
                    self.pending_encryption_dialog = None;
                    self.encryption_error = None;
                }
            } else {
                self.reencrypt_current_project("");
                self.pending_encryption_dialog = None;
                self.encryption_error = None;
            }
        } else if do_cancel {
            self.pending_encryption_dialog = None;
            self.encryption_password_input.clear();
            self.encryption_password_confirm.clear();
            self.encryption_error = None;
        }
    }

    // -- Action log ("Journal") ----------------------------------------

    fn ui_status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status_bar").show(ui, |ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("📋 Journal").clicked() {
                    self.action_log_window_open = true;
                }
            });
        });
    }

    fn ui_action_log_window(&mut self, ctx: &egui::Context) {
        if self.action_log_window_open {
            let entries = db::load_action_log();
            egui::Window::new("Action Log")
                .collapsible(false)
                .resizable(true)
                .anchor(egui::Align2::RIGHT_BOTTOM, [-12.0, -44.0])
                .default_width(480.0)
                .default_height(420.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("Entries: {}", entries.len()));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Close").clicked() {
                                self.action_log_window_open = false;
                            }
                            if ui
                                .add_enabled(!entries.is_empty(), egui::Button::new("🗑 Clear Log"))
                                .clicked()
                            {
                                self.pending_clear_action_log = true;
                            }
                        });
                    });
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if entries.is_empty() {
                            ui.weak("The log is empty.");
                        }
                        for entry in &entries {
                            ui.horizontal(|ui| {
                                ui.weak(&entry.logged_at);
                                ui.label(&entry.message);
                            });
                        }
                    });
                });
        }

        if self.pending_clear_action_log {
            egui::Window::new("Clear Action Log")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .default_width(360.0)
                .show(ctx, |ui| {
                    ui.label("Clear the entire action log? This cannot be undone.");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Clear").clicked() {
                            match db::clear_action_log() {
                                Ok(count) => self.info("Cleared", format!("Removed {count} entries.")),
                                Err(e) => self.error("Failed to clear log", format!("{e:#}")),
                            }
                            self.pending_clear_action_log = false;
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_clear_action_log = false;
                        }
                    });
                });
        }
    }
}

impl eframe::App for WgStudioApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if !self.theme_applied {
            theme::apply_theme(&ctx);
            self.theme_applied = true;
        }

        // Auto-backup due-check: a cheap `Instant` comparison, gated to
        // about once a minute so the (comparatively expensive) date
        // parsing and actual file copy don't run every frame.
        // `request_repaint_after` guarantees this keeps getting called to
        // make that check even while the user isn't interacting with the
        // window -- egui otherwise only redraws on demand.
        if std::time::Instant::now() >= self.next_auto_backup_check {
            self.next_auto_backup_check = std::time::Instant::now() + std::time::Duration::from_secs(60);
            self.maybe_run_auto_backup();
        }
        ctx.request_repaint_after(std::time::Duration::from_secs(60));

        self.handle_shortcuts(&ctx);
        self.ui_header(ui);
        // The bottom status bar must be shown before the central panel --
        // `CentralPanel` fills whatever space is left over after every
        // other panel *already registered this frame*, so showing it first
        // would leave no room reserved for the status bar and the two
        // would overlap.
        self.ui_status_bar(ui);
        self.ui_host_tabs(ui);
        self.ui_modal(&ctx);
        self.ui_database_window(&ctx);
        self.ui_encryption_dialog(&ctx);
        self.ui_action_log_window(&ctx);
    }
}
