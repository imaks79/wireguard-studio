//! "Apply to Device": deploy a generated config to a real device over SSH
//! (MikroTik/OpenWrt), or just export a plain `.conf` file (a bare
//! WireGuard client never gets an SSH round-trip -- see `DeviceType::PlainWg`).
//! Shared by both host and client tabs: each owns its own [`DeployState`]
//! and renders it through [`render_apply_dialog`]/[`render_log_window`].
//!
//! SSH work runs on a plain background thread (this app has no async
//! runtime anywhere else, so a blocking client -- `ssh2`/libssh2 -- fits
//! better than pulling one in just for this) and reports back over an
//! `mpsc` channel that [`DeployState::poll`] drains once per frame.
//!
//! Host keys are intentionally never checked (no known_hosts, trust-on-
//! connect): this is a LAN tool for the user's own devices, not something
//! meant to be pointed at the open internet. The dialog says so.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};

use eframe::egui;

use crate::modal::Modal;
use crate::theme;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DeviceType {
    #[default]
    PlainWg,
    MikroTik,
    OpenWrt,
    PfSense,
}

impl DeviceType {
    /// Human-readable label for the tab tooltip and dialog.
    pub fn label(&self) -> &'static str {
        match self {
            DeviceType::PlainWg => "plain WG client",
            DeviceType::MikroTik => "MikroTik",
            DeviceType::OpenWrt => "OpenWrt router",
            DeviceType::PfSense => "pfSense",
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DeviceType::PlainWg => "plain",
            DeviceType::MikroTik => "mikrotik",
            DeviceType::OpenWrt => "openwrt",
            DeviceType::PfSense => "pfsense",
        }
    }

    fn from_str_or_default(s: &str) -> Self {
        match s {
            "mikrotik" => DeviceType::MikroTik,
            "openwrt" => DeviceType::OpenWrt,
            "pfsense" => DeviceType::PfSense,
            _ => DeviceType::PlainWg,
        }
    }
}

#[derive(Clone)]
enum SshAuth {
    Password(String),
    Key { path: String, passphrase: String },
}

/// Opaque outside this module: other modules receive one via
/// `DialogAction::Connect` and just move it into `DeployState::start`
/// without ever constructing or inspecting it themselves.
pub(crate) struct SshTarget {
    host: String,
    port: u16,
    username: String,
    auth: SshAuth,
}

/// What "Check Availability" found out about a device, best-effort --
/// either field can come back empty if the device doesn't expose it (e.g.
/// OpenWrt has no universal, vendor-independent serial number source).
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub model: Option<String>,
    pub serial: Option<String>,
}

enum Operation {
    Apply(String),
    Check,
    Import,
}

enum DeployOutcome {
    Applied,
    Checked(DeviceInfo),
    Imported(Vec<wgcore::ImportedInterface>),
}

enum DeployProgress {
    Log(String),
    Done(Result<DeployOutcome, String>),
}

struct DeployHandle {
    rx: Receiver<DeployProgress>,
}

fn start_ssh_operation(target: SshTarget, device_type: DeviceType, op: Operation) -> DeployHandle {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = run_operation(&target, device_type, op, &tx);
        let _ = tx.send(DeployProgress::Done(result));
    });
    DeployHandle { rx }
}

fn run_operation(target: &SshTarget, device_type: DeviceType, op: Operation, tx: &Sender<DeployProgress>) -> Result<DeployOutcome, String> {
    let mut log = |s: String| {
        let _ = tx.send(DeployProgress::Log(s));
    };

    log(format!("Connecting to {}:{}...\n", target.host, target.port));
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).map_err(|e| {
        // EBADF from a plain connect() is what macOS reports when a network
        // content filter drops the flow, closing the socket underneath it.
        let hint = if cfg!(target_os = "macos") && e.raw_os_error() == Some(9) {
            "\n\nThis usually means a firewall app on this Mac (Little Snitch, LuLu, ...) blocked the \
             connection -- allow wireguard-studio to reach this address in its rules, then try again."
        } else {
            ""
        };
        format!("TCP connect to {}:{} failed: {e}{hint}", target.host, target.port)
    })?;
    let mut sess = ssh2::Session::new().map_err(|e| format!("SSH session init failed: {e}"))?;
    sess.set_tcp_stream(tcp);
    sess.handshake().map_err(|e| format!("SSH handshake failed: {e}"))?;

    match &target.auth {
        SshAuth::Password(pw) => sess
            .userauth_password(&target.username, pw)
            .map_err(|e| format!("Password authentication failed: {e}"))?,
        SshAuth::Key { path, passphrase } => {
            let pass = if passphrase.is_empty() { None } else { Some(passphrase.as_str()) };
            sess.userauth_pubkey_file(&target.username, None, Path::new(path), pass)
                .map_err(|e| format!("Key authentication failed: {e}"))?;
        }
    }
    if !sess.authenticated() {
        return Err("Authentication failed".to_string());
    }
    log("Authenticated.\n".to_string());

    match op {
        Operation::Apply(script) => {
            let result = match device_type {
                DeviceType::PlainWg => Ok(()), // never actually reaches here -- see render_apply_dialog
                DeviceType::OpenWrt | DeviceType::PfSense => run_posix_shell_script(&sess, &script, &mut log),
                DeviceType::MikroTik => run_mikrotik(&sess, &script, &mut log),
            };
            result.map(|()| DeployOutcome::Applied)
        }
        Operation::Check => {
            let info = match device_type {
                DeviceType::PlainWg => DeviceInfo::default(), // Check is hidden for this type
                DeviceType::OpenWrt => check_openwrt(&sess, &mut log)?,
                DeviceType::MikroTik => check_mikrotik(&sess, &mut log)?,
                DeviceType::PfSense => check_pfsense(&sess, &mut log)?,
            };
            Ok(DeployOutcome::Checked(info))
        }
        Operation::Import => {
            let interfaces = match device_type {
                DeviceType::OpenWrt => import_openwrt(&sess, &mut log)?,
                DeviceType::MikroTik => import_mikrotik(&sess, &mut log)?,
                // The button is only offered for the two types above.
                DeviceType::PlainWg | DeviceType::PfSense => Vec::new(),
            };
            Ok(DeployOutcome::Imported(interfaces))
        }
    }
}

/// Like [`run_exec_capture`], but nothing the command prints reaches the
/// log -- for reading configuration back, where the output is full of
/// private and pre-shared keys that have no business in a log window.
fn run_exec_quiet(sess: &ssh2::Session, command: &str) -> Result<(String, i32), String> {
    let mut output = String::new();
    let mut capture = |chunk: String| output.push_str(&chunk);
    let mut channel = sess.channel_session().map_err(|e| format!("Failed to open channel: {e}"))?;
    channel.exec(command).map_err(|e| format!("Failed to query the device: {e}"))?;
    stream_channel_output(&mut channel, &mut capture);
    channel.wait_close().map_err(|e| format!("Failed waiting for the device to answer: {e}"))?;
    let status = channel.exit_status().unwrap_or(-1);
    Ok((output, status))
}

fn log_imported(interfaces: &[wgcore::ImportedInterface], log: &mut dyn FnMut(String)) {
    log(format!("Found {} WireGuard interface(s).\n", interfaces.len()));
    for iface in interfaces {
        log(format!("  {} -- {} peer(s)\n", iface.name, iface.peers.len()));
    }
}

/// Everything WireGuard lives in `/etc/config/network` on OpenWrt, so one
/// `uci show network` is the whole read.
fn import_openwrt(sess: &ssh2::Session, log: &mut dyn FnMut(String)) -> Result<Vec<wgcore::ImportedInterface>, String> {
    log("Reading WireGuard interfaces (uci show network; output not logged, it contains keys)...\n".to_string());
    let (output, status) = run_exec_quiet(sess, "uci show network")?;
    if status != 0 {
        return Err(format!("'uci show network' exited with status {status} -- is this an OpenWrt device?"));
    }
    let interfaces = wgcore::parse_openwrt_network(&output);
    log_imported(&interfaces, log);
    Ok(interfaces)
}

/// See [`wgcore::ROUTEROS_DUMP_COMMANDS`]: only the first command (the
/// interfaces themselves) has to succeed. The rest are best-effort, since
/// what they read doesn't exist on every RouterOS version/setup.
fn import_mikrotik(sess: &ssh2::Session, log: &mut dyn FnMut(String)) -> Result<Vec<wgcore::ImportedInterface>, String> {
    log("Reading WireGuard interfaces, peers and addresses (output not logged, it contains keys)...\n".to_string());
    let mut dump = String::new();
    for (i, command) in wgcore::ROUTEROS_DUMP_COMMANDS.iter().enumerate() {
        let (output, status) = run_exec_quiet(sess, command)?;
        if i == 0 && (status != 0 || !output.contains("@IF")) {
            // A router with no WireGuard interfaces prints nothing at all,
            // which is a valid (empty) answer; anything else printed here
            // is RouterOS explaining why the command didn't run.
            let complaint = output.trim();
            if status != 0 || !complaint.is_empty() {
                return Err(format!(
                    "Could not read WireGuard interfaces (RouterOS 7+ is required){}",
                    if complaint.is_empty() { ".".to_string() } else { format!(": {complaint}") }
                ));
            }
        }
        dump.push_str(&output);
        dump.push('\n');
    }
    let interfaces = wgcore::parse_routeros_dump(&dump);
    log_imported(&interfaces, log);
    Ok(interfaces)
}

/// Runs one command to completion, capturing its combined stdout+stderr as
/// a `String` (in addition to streaming it to `log` as usual) -- used by
/// the identity-check commands below, which need to parse the output.
fn run_exec_capture(sess: &ssh2::Session, command: &str, log: &mut dyn FnMut(String)) -> Result<(String, i32), String> {
    let mut channel = sess.channel_session().map_err(|e| format!("Failed to open channel: {e}"))?;
    channel.exec(command).map_err(|e| format!("Failed to run '{command}': {e}"))?;
    let mut output = String::new();
    {
        let mut capturing = |chunk: String| {
            output.push_str(&chunk);
            log(chunk);
        };
        stream_channel_output(&mut channel, &mut capturing);
    }
    channel.wait_close().map_err(|e| format!("Failed waiting for '{command}' to finish: {e}"))?;
    let status = channel.exit_status().unwrap_or(-1);
    Ok((output, status))
}

/// OpenWrt identity: `ubus call system board` returns JSON with a "model"
/// field on any reasonably current build; older/minimal images fall back
/// to the plain-text `/tmp/sysinfo/model`. There's no universal,
/// vendor-independent serial number source on OpenWrt, so `serial` is
/// deliberately always left unset here rather than guessing at one.
fn check_openwrt(sess: &ssh2::Session, log: &mut dyn FnMut(String)) -> Result<DeviceInfo, String> {
    log("Querying device identity (ubus call system board)...\n".to_string());
    let (output, _status) = run_exec_capture(sess, "ubus call system board 2>/dev/null", log)?;
    let mut info = DeviceInfo { model: parse_openwrt_board_model(&output), serial: None };
    if info.model.is_none() {
        let (model_file, _status) = run_exec_capture(sess, "cat /tmp/sysinfo/model 2>/dev/null", log)?;
        let model_file = model_file.trim();
        if !model_file.is_empty() {
            info.model = Some(model_file.to_string());
        }
    }
    Ok(info)
}

/// Pulls "model" (falling back to "board_name") out of `ubus call system
/// board`'s JSON output. Pure/parsing-only so it's unit-testable without a
/// live SSH session -- `check_openwrt` is the only caller.
fn parse_openwrt_board_model(ubus_output: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(ubus_output.trim()).ok()?;
    json.get("model")
        .and_then(|v| v.as_str())
        .or_else(|| json.get("board_name").and_then(|v| v.as_str()))
        .map(str::to_string)
}

/// MikroTik identity: `/system routerboard print` gives `model` and
/// `serial-number` on real RouterBOARD hardware. A CHR/x86 virtual router
/// has no routerboard at all, so this falls back to `/system resource
/// print`'s `board-name` for the model (there's no serial number to find
/// on a VM either way).
fn check_mikrotik(sess: &ssh2::Session, log: &mut dyn FnMut(String)) -> Result<DeviceInfo, String> {
    log("Querying device identity (/system routerboard print)...\n".to_string());
    let (output, _status) = run_exec_capture(sess, "/system routerboard print", log)?;
    let mut info = parse_routeros_kv_lines(&output, &["model"], &["serial-number"]);
    if info.model.is_none() {
        let (output, _status) = run_exec_capture(sess, "/system resource print", log)?;
        info.model = parse_routeros_kv_lines(&output, &["board-name"], &[]).model;
    }
    Ok(info)
}

/// Parses RouterOS's `key: value` print output (one pair per line,
/// right-aligned keys), pulling the model out of whichever of
/// `model_keys` appears (first match wins) and the serial out of
/// whichever of `serial_keys` appears. Pure/parsing-only so it's
/// unit-testable without a live SSH session -- `check_mikrotik` is the
/// only caller.
fn parse_routeros_kv_lines(output: &str, model_keys: &[&str], serial_keys: &[&str]) -> DeviceInfo {
    let mut info = DeviceInfo::default();
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if info.model.is_none() && model_keys.iter().any(|k| key.eq_ignore_ascii_case(k)) {
            info.model = Some(value.to_string());
        }
        if info.serial.is_none() && serial_keys.iter().any(|k| key.eq_ignore_ascii_case(k)) {
            info.serial = Some(value.to_string());
        }
    }
    info
}

/// pfSense identity: FreeBSD's `kenv` reliably exposes SMBIOS fields on
/// real hardware (including Netgate appliances) without needing any extra
/// package like `dmidecode` installed -- a VM/CHR-style install may report
/// nothing for either, which is left as `None` rather than guessed at.
/// `/etc/version` (pfSense's own version file) is appended to the model
/// for context when present, since "it's reachable" alone is less useful
/// without knowing which pfSense release it's running.
fn check_pfsense(sess: &ssh2::Session, log: &mut dyn FnMut(String)) -> Result<DeviceInfo, String> {
    log("Querying device identity (kenv smbios.system.*)...\n".to_string());
    let (product, _status) = run_exec_capture(sess, "kenv smbios.system.product 2>/dev/null", log)?;
    let (serial, _status) = run_exec_capture(sess, "kenv smbios.system.serial 2>/dev/null", log)?;
    let (version, _status) = run_exec_capture(sess, "cat /etc/version 2>/dev/null", log)?;
    let serial = serial.trim();
    Ok(DeviceInfo {
        model: combine_pfsense_model(&product, &version),
        serial: if serial.is_empty() { None } else { Some(serial.to_string()) },
    })
}

/// "<product> (pfSense <version>)" -- whichever of the two `kenv`/`/etc/
/// version` reads actually came back non-empty (a CHR-style VM install
/// often has no SMBIOS product string at all). Pure/parsing-only so it's
/// unit-testable without a live SSH session -- `check_pfsense` is the
/// only caller.
fn combine_pfsense_model(product: &str, version: &str) -> Option<String> {
    let product = product.trim();
    let version = version.trim();
    match (product.is_empty(), version.is_empty()) {
        (false, false) => Some(format!("{product} (pfSense {version})")),
        (false, true) => Some(product.to_string()),
        (true, false) => Some(format!("pfSense {version}")),
        (true, true) => None,
    }
}

/// Reads a channel's stdout, then its stderr, to EOF, forwarding every
/// chunk to `log` as it arrives. Sequential (stdout fully, then stderr) --
/// fine for the modest, bounded output these scripts produce; a firehose
/// of interleaved output on both streams at once could in principle
/// deadlock a naive reader like this, but that's not a realistic shape
/// for a `uci`/RouterOS setup script.
fn stream_channel_output(channel: &mut ssh2::Channel, log: &mut dyn FnMut(String)) {
    let mut buf = [0u8; 4096];
    loop {
        match channel.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => log(String::from_utf8_lossy(&buf[..n]).into_owned()),
        }
    }
    let mut stderr = channel.stderr();
    loop {
        match stderr.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => log(String::from_utf8_lossy(&buf[..n]).into_owned()),
        }
    }
}

/// OpenWrt's and pfSense's own shells are both a normal POSIX `sh`
/// reachable over the SSH exec channel -- pipe the script into it exactly
/// the way the project's own generated scripts are documented to be run
/// (`wget -O - ... | sh`).
fn run_posix_shell_script(sess: &ssh2::Session, script: &str, log: &mut dyn FnMut(String)) -> Result<(), String> {
    let mut channel = sess.channel_session().map_err(|e| format!("Failed to open channel: {e}"))?;
    channel.exec("sh -s").map_err(|e| format!("Failed to run 'sh -s': {e}"))?;
    channel.write_all(script.as_bytes()).map_err(|e| format!("Failed to send script: {e}"))?;
    channel.send_eof().map_err(|e| format!("Failed to close script input: {e}"))?;
    stream_channel_output(&mut channel, log);
    channel.wait_close().map_err(|e| format!("Failed waiting for the remote command to finish: {e}"))?;
    let status = channel.exit_status().unwrap_or(-1);
    if status == 0 {
        Ok(())
    } else {
        Err(format!("Remote script exited with status {status} -- see the log for details."))
    }
}

/// RouterOS's own SSH shell *is* its CLI, not a POSIX shell -- there's
/// nothing to pipe a script into. Upload it via SFTP instead and run
/// `/import` on it, then clean the temp file up.
fn run_mikrotik(sess: &ssh2::Session, script: &str, log: &mut dyn FnMut(String)) -> Result<(), String> {
    let remote_path = "wg-studio-deploy.rsc";
    log(format!("Uploading script to {remote_path} via SFTP...\n"));
    let sftp = sess.sftp().map_err(|e| format!("SFTP init failed (does this device support SFTP?): {e}"))?;
    {
        let mut file = sftp
            .create(Path::new(remote_path))
            .map_err(|e| format!("Failed to create remote file: {e}"))?;
        file.write_all(script.as_bytes()).map_err(|e| format!("Failed to upload script: {e}"))?;
    }

    log(format!("Running /import file-name={remote_path} ...\n"));
    let (output, status) = run_exec_capture(sess, &format!("/import file-name={remote_path}"), log)?;

    let _ = sftp.unlink(Path::new(remote_path)); // best-effort cleanup

    mikrotik_import_succeeded(status, &output)
}

/// RouterOS's `/import` doesn't reliably surface a shell-style exit code
/// over an SSH exec channel, so this is a heuristic, not a guarantee:
/// non-zero exit, or the output mentioning "error" (RouterOS prints
/// readable "error: ..." lines for a bad command rather than aborting
/// with a non-zero status), both count as failure.
fn mikrotik_import_succeeded(exit_status: i32, output: &str) -> Result<(), String> {
    if exit_status != 0 {
        return Err(format!("Remote import exited with status {exit_status} -- see the log for details."));
    }
    if output.to_lowercase().contains("error") {
        return Err("RouterOS reported an error while importing the script -- see the log for details.".to_string());
    }
    Ok(())
}

/// Persisted deploy state (project.json) plus the interactive dialog/log
/// window state. `Clone` is implemented by hand below (not derived): an
/// in-flight `DeployHandle` holds a non-cloneable `Receiver`, and cloning a
/// tab (`ClientTabState` derives `Clone`) shouldn't duplicate a live SSH
/// session anyway -- only the persisted form fields and `applied` status
/// carry over, the transient dialog/log/handle state resets.
pub struct DeployState {
    /// Free-text human name for whoever/whatever this config is actually
    /// handed to -- "Vasya's laptop", "Front desk router" -- independent
    /// of the tab's own `name` field (which is the WireGuard interface's
    /// name, not a note about the physical recipient). Most useful for a
    /// plain WG client, which has no IP/model/serial of its own to show in
    /// the tooltip once applied.
    client_label: String,
    device_type: DeviceType,
    target_ip: String,
    ssh_port: String,
    ssh_username: String,
    auth_is_key: bool,
    password: String,
    key_path: String,
    key_passphrase: String,

    pub show_dialog: bool,
    pub show_log: bool,
    pub log: String,
    running: bool,
    /// Title for the error modal if the run `handle` belongs to fails --
    /// "Apply failed", "Check failed", ...
    pending_error_title: &'static str,
    handle: Option<DeployHandle>,
    /// WireGuard interfaces a "Copy Interface from Device" run found, kept
    /// here until the owning tab shows its picker and takes them.
    pub imported: Option<Vec<wgcore::ImportedInterface>>,

    /// Whether this tab's configuration has been successfully applied to
    /// a device at some point -- drives the green tab fill. This is
    /// "was applied", not "is currently in sync": editing fields after a
    /// successful apply doesn't clear it. Only cleared by a fresh failed
    /// attempt overwriting `applied_device_type`/`applied_ip`... actually
    /// it isn't cleared by failure either, on purpose -- a flaky retry
    /// shouldn't erase a previously-confirmed-good deploy.
    pub applied: bool,
    pub applied_device_type: Option<DeviceType>,
    pub applied_ip: String,

    /// Best-effort results of the last successful "Check Availability" --
    /// shown in the tab's tooltip alongside (or instead of) the applied
    /// status. Not required to have applied a config first.
    checked_model: Option<String>,
    checked_serial: Option<String>,
}

impl Clone for DeployState {
    fn clone(&self) -> Self {
        DeployState {
            client_label: self.client_label.clone(),
            device_type: self.device_type,
            target_ip: self.target_ip.clone(),
            ssh_port: self.ssh_port.clone(),
            ssh_username: self.ssh_username.clone(),
            auth_is_key: self.auth_is_key,
            password: self.password.clone(),
            key_path: self.key_path.clone(),
            key_passphrase: self.key_passphrase.clone(),
            show_dialog: false,
            show_log: false,
            log: String::new(),
            running: false,
            pending_error_title: "Apply failed",
            handle: None,
            imported: None,
            applied: self.applied,
            applied_device_type: self.applied_device_type,
            applied_ip: self.applied_ip.clone(),
            checked_model: self.checked_model.clone(),
            checked_serial: self.checked_serial.clone(),
        }
    }
}

impl Default for DeployState {
    fn default() -> Self {
        DeployState {
            client_label: String::new(),
            device_type: DeviceType::PlainWg,
            target_ip: String::new(),
            ssh_port: "22".to_string(),
            ssh_username: String::new(),
            auth_is_key: false,
            password: String::new(),
            key_path: String::new(),
            key_passphrase: String::new(),
            show_dialog: false,
            show_log: false,
            log: String::new(),
            running: false,
            pending_error_title: "Apply failed",
            handle: None,
            imported: None,
            applied: false,
            applied_device_type: None,
            applied_ip: String::new(),
            checked_model: None,
            checked_serial: None,
        }
    }
}

impl DeployState {
    /// Drains any pending progress from an in-flight deploy. Call this
    /// unconditionally every frame for *every* tab, not just the one
    /// currently visible -- a deploy started on one tab must still finish
    /// (and mark it green) even if the user switched away from it.
    pub fn poll(&mut self) -> Option<Modal> {
        let handle = self.handle.as_ref()?;
        let mut out = None;
        loop {
            match handle.rx.try_recv() {
                Ok(DeployProgress::Log(s)) => self.log.push_str(&s),
                Ok(DeployProgress::Done(result)) => {
                    self.running = false;
                    out = Some(match result {
                        Ok(DeployOutcome::Applied) => {
                            self.applied = true;
                            self.applied_device_type = Some(self.device_type);
                            self.applied_ip = self.target_ip.clone();
                            let who = if self.client_label.is_empty() { String::new() } else { format!(" ({})", self.client_label) };
                            Modal::Info {
                                title: "Applied".into(),
                                body: format!("Successfully applied to {} ({}){who}.", self.target_ip, self.device_type.label()),
                            }
                        }
                        Ok(DeployOutcome::Checked(info)) => {
                            self.checked_model = info.model.clone();
                            self.checked_serial = info.serial.clone();
                            let who = if self.client_label.is_empty() { String::new() } else { format!(" ({})", self.client_label) };
                            let mut body = format!("{}{who} at {} is reachable.", self.device_type.label(), self.target_ip);
                            match (&info.model, &info.serial) {
                                (Some(m), Some(s)) => body.push_str(&format!("\nModel: {m}\nSerial: {s}")),
                                (Some(m), None) => body.push_str(&format!("\nModel: {m}\n(Serial number not available on this device.)")),
                                (None, Some(s)) => body.push_str(&format!("\nSerial: {s}\n(Model not available.)")),
                                (None, None) => body.push_str("\n(Model/serial number not available on this device.)"),
                            }
                            Modal::Info { title: "Device reachable".into(), body }
                        }
                        Ok(DeployOutcome::Imported(interfaces)) => {
                            self.handle = None;
                            if interfaces.is_empty() {
                                return Some(Modal::Info {
                                    title: "No WireGuard interfaces".into(),
                                    body: format!("{} at {} has no WireGuard interfaces configured.", self.device_type.label(), self.target_ip),
                                });
                            }
                            // No modal: the owning tab opens its picker.
                            self.show_dialog = false;
                            self.imported = Some(interfaces);
                            return None;
                        }
                        Err(e) => Modal::Error { title: self.pending_error_title.into(), body: e },
                    });
                    self.handle = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.running = false;
                    self.handle = None;
                    break;
                }
            }
        }
        out
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub(crate) fn start(&mut self, target: SshTarget, device_type: DeviceType, script: String) {
        self.log.clear();
        self.running = true;
        self.pending_error_title = "Apply failed";
        self.handle = Some(start_ssh_operation(target, device_type, Operation::Apply(script)));
    }

    /// "Check Availability": connects and authenticates like an apply
    /// would, then runs a read-only identity query instead of touching any
    /// configuration. Never marks the tab as applied.
    pub(crate) fn start_check(&mut self, target: SshTarget, device_type: DeviceType) {
        self.log.clear();
        self.running = true;
        self.pending_error_title = "Check failed";
        self.handle = Some(start_ssh_operation(target, device_type, Operation::Check));
    }

    /// "Copy Interface from Device": reads every WireGuard interface the
    /// device has into [`Self::imported`]. Read-only, like a check.
    fn start_import(&mut self, target: SshTarget, device_type: DeviceType) {
        self.log.clear();
        self.running = true;
        self.pending_error_title = "Copy from device failed";
        self.imported = None;
        self.handle = Some(start_ssh_operation(target, device_type, Operation::Import));
    }

    /// The same device and SSH credentials for another tab -- a second
    /// interface copied from this device -- without this tab's own
    /// "applied" status.
    pub fn for_another_tab(&self) -> DeployState {
        let mut copy = self.clone();
        copy.applied = false;
        copy.applied_device_type = None;
        copy.applied_ip.clear();
        copy
    }

    /// "MikroTik at 192.168.88.1", for messages about a finished import.
    pub fn target_description(&self) -> String {
        format!("{} at {}", self.device_type.label(), self.target_ip.trim())
    }

    /// Bookkeeping for the plain-WG-client path, which never touches SSH
    /// at all -- see `DialogAction::PlainExport`.
    pub fn mark_applied_plain(&mut self) {
        self.applied = true;
        self.applied_device_type = Some(DeviceType::PlainWg);
        self.applied_ip.clear();
    }

    pub fn to_project_dict(&self) -> crate::project::DeployProjectDict {
        crate::project::DeployProjectDict {
            client_label: self.client_label.clone(),
            device_type: self.device_type.as_str().to_string(),
            target_ip: self.target_ip.clone(),
            ssh_port: self.ssh_port.clone(),
            ssh_username: self.ssh_username.clone(),
            auth_is_key: self.auth_is_key,
            password: if self.password.is_empty() { None } else { Some(self.password.clone()) },
            key_path: if self.key_path.is_empty() { None } else { Some(self.key_path.clone()) },
            key_passphrase: if self.key_passphrase.is_empty() { None } else { Some(self.key_passphrase.clone()) },
            applied: self.applied,
            applied_device_type: self.applied_device_type.map(|d| d.as_str().to_string()),
            applied_ip: self.applied_ip.clone(),
            checked_model: self.checked_model.clone(),
            checked_serial: self.checked_serial.clone(),
        }
    }

    pub fn from_project_dict(d: &crate::project::DeployProjectDict) -> Self {
        DeployState {
            client_label: d.client_label.clone(),
            device_type: DeviceType::from_str_or_default(&d.device_type),
            target_ip: d.target_ip.clone(),
            ssh_port: if d.ssh_port.trim().is_empty() { "22".to_string() } else { d.ssh_port.clone() },
            ssh_username: d.ssh_username.clone(),
            auth_is_key: d.auth_is_key,
            password: d.password.clone().unwrap_or_default(),
            key_path: d.key_path.clone().unwrap_or_default(),
            key_passphrase: d.key_passphrase.clone().unwrap_or_default(),
            show_dialog: false,
            show_log: false,
            log: String::new(),
            running: false,
            pending_error_title: "Apply failed",
            handle: None,
            imported: None,
            applied: d.applied,
            applied_device_type: d.applied_device_type.as_deref().map(DeviceType::from_str_or_default),
            applied_ip: d.applied_ip.clone(),
            checked_model: d.checked_model.clone(),
            checked_serial: d.checked_serial.clone(),
        }
    }
}

/// What the user asked the dialog to do this frame, if anything. Building
/// the actual script needs `&mut self` on the *whole* host/client tab
/// (`build_full_model`/`sync`), which can't happen while `state` (a field
/// of that same tab) is already borrowed here -- so this just reports the
/// intent back, and `host_ui.rs`/`client_ui.rs` act on it afterward with
/// their own unrestricted borrow.
pub enum DialogAction {
    None,
    /// `label` is `state.client_label`, trimmed -- empty if the user left
    /// it blank, in which case the caller should fall back to the tab's
    /// own name for the suggested export file name.
    PlainExport { label: String },
    Connect { device_type: DeviceType, target: SshTarget },
}

/// Fixed width for every single-line text field in the dialog -- an
/// unconstrained `TextEdit` inside an `egui::Grid` cell can end up sized
/// from the (initially unknown) column width on the first frame the grid
/// is shown, which reads as "the field's barely there". A fixed width
/// sidesteps that entirely.
const FIELD_WIDTH: f32 = 220.0;

fn build_target(state: &DeployState) -> SshTarget {
    let port: u16 = state.ssh_port.trim().parse().unwrap_or(22);
    let auth = if state.auth_is_key {
        SshAuth::Key { path: state.key_path.clone(), passphrase: state.key_passphrase.clone() }
    } else {
        SshAuth::Password(state.password.clone())
    };
    SshTarget {
        host: state.target_ip.trim().to_string(),
        port,
        username: state.ssh_username.trim().to_string(),
        auth,
    }
}

/// `allow_import` adds "Copy Interface from Device" -- for host tabs only,
/// since what comes back is a whole interface with its peer list.
pub fn render_apply_dialog(ctx: &egui::Context, state: &mut DeployState, tab_label: &str, allow_import: bool) -> DialogAction {
    if !state.show_dialog {
        return DialogAction::None;
    }
    let mut action = DialogAction::None;

    egui::Window::new(format!("Apply Configuration — {tab_label}"))
        .id(egui::Id::new(("deploy-dialog", tab_label)))
        .collapsible(false)
        .resizable(false)
        .default_width(380.0)
        .show(ctx, |ui| {
            ui.label("Client name (optional):");
            ui.add(egui::TextEdit::singleline(&mut state.client_label).desired_width(FIELD_WIDTH).hint_text("e.g. \"Vasya's laptop\", \"Front desk router\""));
            theme::hint(
                ui,
                "A note about who/what this actually is -- shown on this tab once applied, and used as \
                 the suggested file name for a plain client's export. Doesn't affect the config itself.",
            );
            ui.add_space(6.0);

            ui.label("Device type:");
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut state.device_type, DeviceType::PlainWg, "Plain WG client");
                ui.selectable_value(&mut state.device_type, DeviceType::MikroTik, "MikroTik");
                ui.selectable_value(&mut state.device_type, DeviceType::OpenWrt, "OpenWrt router");
                ui.selectable_value(&mut state.device_type, DeviceType::PfSense, "pfSense");
            });
            if state.device_type == DeviceType::PfSense {
                theme::hint(
                    ui,
                    "Drives FreeBSD's native kernel WireGuard directly (ifconfig/wg(8)), not pfSense's \
                     own WireGuard GUI package -- the tunnel won't show up on the VPN > WireGuard page. \
                     Needs pfSense 2.7.0+.",
                );
            }
            ui.add_space(6.0);

            if state.device_type == DeviceType::PlainWg {
                theme::hint(
                    ui,
                    "No SSH connection for a plain client -- this just exports the .conf file and \
                     marks this tab as applied.",
                );
                if ui.button("Export & Mark as Applied").clicked() {
                    action = DialogAction::PlainExport { label: state.client_label.trim().to_string() };
                }
            } else {
                egui::Grid::new(("deploy-grid", tab_label)).num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                    ui.label("IP address:");
                    ui.add(egui::TextEdit::singleline(&mut state.target_ip).desired_width(FIELD_WIDTH));
                    ui.end_row();

                    ui.label("SSH port:");
                    ui.add(egui::TextEdit::singleline(&mut state.ssh_port).desired_width(60.0));
                    ui.end_row();

                    ui.label("Username:");
                    ui.add(egui::TextEdit::singleline(&mut state.ssh_username).desired_width(FIELD_WIDTH));
                    ui.end_row();

                    ui.label("Auth method:");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut state.auth_is_key, false, "Password");
                        ui.selectable_value(&mut state.auth_is_key, true, "Private key");
                    });
                    ui.end_row();

                    if state.auth_is_key {
                        ui.label("Key file:");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut state.key_path).desired_width(FIELD_WIDTH - 80.0));
                            if ui.button("Browse...").clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    state.key_path = path.display().to_string();
                                }
                            }
                        });
                        ui.end_row();

                        ui.label("Key passphrase:");
                        ui.add(egui::TextEdit::singleline(&mut state.key_passphrase).password(true).desired_width(FIELD_WIDTH));
                        ui.end_row();
                    } else {
                        ui.label("Password:");
                        ui.add(egui::TextEdit::singleline(&mut state.password).password(true).desired_width(FIELD_WIDTH));
                        ui.end_row();
                    }
                });

                theme::hint(
                    ui,
                    "Host key is not verified -- only use this against devices on your own trusted \
                     local network.",
                );
                ui.add_space(6.0);

                if state.running {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Connecting / running...");
                    });
                } else {
                    let ready = !state.target_ip.trim().is_empty() && !state.ssh_username.trim().is_empty();
                    ui.horizontal(|ui| {
                        if ui.add_enabled(ready, egui::Button::new("Check Availability")).clicked() {
                            let target = build_target(state);
                            let device_type = state.device_type;
                            state.start_check(target, device_type);
                        }
                        if ui.add_enabled(ready, egui::Button::new("Connect & Apply")).clicked() {
                            action = DialogAction::Connect { device_type: state.device_type, target: build_target(state) };
                        }
                    });
                    if allow_import && matches!(state.device_type, DeviceType::OpenWrt | DeviceType::MikroTik) {
                        let clicked = ui
                            .add_enabled(ready, egui::Button::new("Copy Interface from Device"))
                            .on_hover_text(
                                "Reads the WireGuard interfaces that already exist on the device -- keys, \
                                 addresses, port and every peer -- so one can be edited here and applied \
                                 back. Changes nothing on the device.",
                            )
                            .clicked();
                        if clicked {
                            let target = build_target(state);
                            let device_type = state.device_type;
                            state.start_import(target, device_type);
                        }
                    }
                }
            }
            ui.add_space(6.0);
            if ui.button("Cancel").clicked() {
                state.show_dialog = false;
            }
        });

    action
}

/// Live-updating log viewer -- reads `state.log` fresh every frame, so it
/// keeps moving while a deploy is running without needing to be reopened.
pub fn render_log_window(ctx: &egui::Context, state: &mut DeployState, tab_label: &str) {
    if !state.show_log {
        return;
    }
    egui::Window::new(format!("Deploy Log — {tab_label}"))
        .id(egui::Id::new(("deploy-log", tab_label)))
        .collapsible(false)
        .default_size([560.0, 360.0])
        .show(ctx, |ui| {
            egui::ScrollArea::vertical().max_height(300.0).stick_to_bottom(true).show(ui, |ui| {
                ui.add(egui::Label::new(egui::RichText::new(&state.log).monospace()).selectable(true));
            });
            ui.horizontal(|ui| {
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(state.log.clone());
                }
                if ui.button("Close").clicked() {
                    state.show_log = false;
                }
            });
        });
}

/// A tab's label in a tab strip, outlined green with a hover tooltip once
/// its configuration has been successfully applied to a device.
/// "Model: X" / "Serial: Y" lines from the last successful "Check
/// Availability", if any -- `None` if nothing's been checked yet.
/// "Name: ..." / "Model: ..." / "Serial: ..." lines for the tab's hover
/// tooltip -- whatever's known, in that order -- or `None` if nothing is
/// (no client name set and nothing's ever been checked).
fn tooltip_extra_lines(state: &DeployState) -> Option<String> {
    let mut lines = Vec::new();
    if !state.client_label.is_empty() {
        lines.push(format!("Name: {}", state.client_label));
    }
    if let Some(model) = &state.checked_model {
        lines.push(format!("Model: {model}"));
    }
    if let Some(serial) = &state.checked_serial {
        lines.push(format!("Serial: {serial}"));
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

/// A tab's label in a tab strip. Once its configuration has been
/// successfully applied to a device, the label is filled solid green
/// (rather than just outlined) so it's obvious at a glance across a whole
/// row of tabs -- with a hover tooltip naming the device type/address and,
/// if "Check Availability" was ever run, the model/serial number found.
/// A tab that's only been *checked* (not applied) still gets that same
/// tooltip on hover, just without the green fill.
pub fn labeled_tab_button(ui: &mut egui::Ui, selected: bool, text: &str, state: &DeployState) -> egui::Response {
    if !state.applied {
        let resp = ui.selectable_label(selected, text);
        return match tooltip_extra_lines(state) {
            Some(info) => resp.on_hover_text(info),
            None => resp,
        };
    }

    let device = state.applied_device_type.map(|d| d.label()).unwrap_or("device");
    let mut tooltip = if state.applied_ip.is_empty() {
        format!("Config applied to: {device}")
    } else {
        format!("Config applied to: {device} ({})", state.applied_ip)
    };
    if let Some(info) = tooltip_extra_lines(state) {
        tooltip.push('\n');
        tooltip.push_str(&info);
    }

    egui::Frame::new()
        .fill(theme::SUCCESS)
        .inner_margin(egui::Margin::symmetric(6, 3))
        .show(ui, |ui| {
            // Scoped to this inner `ui` only -- see `theme::hint` for the
            // same pattern -- so it doesn't bleed into sibling tab labels.
            ui.style_mut().visuals.override_text_color = Some(egui::Color32::WHITE);
            ui.selectable_label(selected, text)
        })
        .inner
        .on_hover_text(tooltip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mikrotik_success_requires_zero_exit_and_no_error_text() {
        assert!(mikrotik_import_succeeded(0, "script.rsc imported successfully").is_ok());
        assert!(mikrotik_import_succeeded(1, "script.rsc imported successfully").is_err());
        assert!(mikrotik_import_succeeded(0, "failure: error near line 3").is_err());
    }

    #[test]
    fn device_type_round_trips_through_its_string_form() {
        for dt in [DeviceType::PlainWg, DeviceType::MikroTik, DeviceType::OpenWrt, DeviceType::PfSense] {
            assert_eq!(DeviceType::from_str_or_default(dt.as_str()), dt);
        }
        assert_eq!(DeviceType::from_str_or_default("nonsense"), DeviceType::PlainWg);
    }

    #[test]
    fn openwrt_board_model_prefers_model_then_falls_back_to_board_name() {
        assert_eq!(
            parse_openwrt_board_model(r#"{"model":"Cudy TR3000","board_name":"cudy,tr3000"}"#),
            Some("Cudy TR3000".to_string())
        );
        assert_eq!(
            parse_openwrt_board_model(r#"{"board_name":"cudy,tr3000"}"#),
            Some("cudy,tr3000".to_string())
        );
        assert_eq!(parse_openwrt_board_model("not json"), None);
        assert_eq!(parse_openwrt_board_model("{}"), None);
    }

    #[test]
    fn routeros_kv_lines_extract_model_and_serial_by_first_matching_key() {
        let output = "\
       routerboard: yes
        board-name: RB750Gr3
             model: RB750Gr3
     serial-number: ABCD1234EF
";
        let info = parse_routeros_kv_lines(output, &["model"], &["serial-number"]);
        assert_eq!(info.model.as_deref(), Some("RB750Gr3"));
        assert_eq!(info.serial.as_deref(), Some("ABCD1234EF"));
    }

    #[test]
    fn routeros_kv_lines_ignore_blank_values_and_unmatched_keys() {
        let output = "        model: \n   board-name: CHR\n";
        let info = parse_routeros_kv_lines(output, &["board-name"], &["serial-number"]);
        assert_eq!(info.model.as_deref(), Some("CHR"));
        assert_eq!(info.serial, None);
    }

    #[test]
    fn pfsense_model_combines_whichever_source_is_available() {
        assert_eq!(combine_pfsense_model("Netgate 6100", "2.7.2"), Some("Netgate 6100 (pfSense 2.7.2)".to_string()));
        assert_eq!(combine_pfsense_model("Netgate 6100", ""), Some("Netgate 6100".to_string()));
        assert_eq!(combine_pfsense_model("", "2.7.2"), Some("pfSense 2.7.2".to_string()));
        assert_eq!(combine_pfsense_model("", ""), None);
    }
}
