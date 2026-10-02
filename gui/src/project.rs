//! On-disk project format. Field names intentionally match the Python
//! GUI's `HostTab.to_dict()` / `ClientTab.to_dict()` output, so a project
//! saved by `wireguard_gui.py` can be opened here (and vice versa).

use serde::{Deserialize, Serialize};

pub const PROJECT_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectFile {
    pub version: u32,
    pub hosts: Vec<HostProjectDict>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostProjectDict {
    pub name: String,
    pub private_key: Option<String>,
    #[serde(default)]
    pub address: Vec<String>,
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub dns: Vec<String>,
    pub mtu: Option<u32>,
    pub table: Option<String>,
    pub fw_mark: Option<String>,
    #[serde(default)]
    pub pre_up: Vec<String>,
    #[serde(default)]
    pub post_up: Vec<String>,
    #[serde(default)]
    pub pre_down: Vec<String>,
    #[serde(default)]
    pub post_down: Vec<String>,
    pub save_config: Option<bool>,
    /// Current field name for the host's externally-reachable address.
    #[serde(default)]
    pub public_ip: Option<String>,
    /// Older projects stored a combined "host:port" endpoint instead;
    /// kept here purely so old files still load (see
    /// `HostTabState::apply_project_dict`).
    #[serde(default)]
    pub public_endpoint: Option<String>,
    #[serde(default)]
    pub manual_key: bool,
    /// "Mesh peers together": whether this host's own clients/peers should
    /// also be peered directly with each other (full mesh among them), in
    /// addition to each one's link back to this host. Absent in projects
    /// saved before this option existed.
    #[serde(default)]
    pub mesh_peers_enabled: bool,
    /// "+ EoIP (L2) between them": whether each meshed peer pair's RouterOS
    /// export should also bridge over EoIP. Absent in projects saved before
    /// this option existed.
    #[serde(default)]
    pub mesh_eoip: bool,
    /// "EoIP to peers": whether this host builds EoIP tunnels to its own
    /// clients. Absent (so off) in projects saved before this option existed.
    #[serde(default)]
    pub host_eoip: bool,
    /// "Apply to Device..." state for this host's own generated config.
    /// Absent in projects saved before this option existed.
    #[serde(default)]
    pub deploy: DeployProjectDict,
    #[serde(default)]
    pub clients: Vec<ClientProjectDict>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientProjectDict {
    pub name: String,
    pub private_key: Option<String>,
    #[serde(default)]
    pub address: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    pub mtu: Option<u32>,
    #[serde(default)]
    pub manual_key: bool,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    #[serde(default)]
    pub endpoint_manual: bool,
    /// This peer's own externally-reachable address, used only so *other*
    /// mesh peers of the same host can reach it directly. Blank/absent
    /// means it can't be dialed (it can still dial out to reach others).
    #[serde(default)]
    pub public_ip: Option<String>,
    /// Fixed listen port to pair with `public_ip` for the same reason.
    /// Blank/absent lets the OS pick an ephemeral port at runtime, same as
    /// before this field existed.
    #[serde(default)]
    pub listen_port: Option<u16>,
    pub persistent_keepalive: Option<u32>,
    #[serde(default)]
    pub use_preshared_key: bool,
    pub preshared_key: Option<String>,
    pub tunnel_id: Option<u32>,
    #[serde(default)]
    pub tunnel_id_manual: bool,
    /// "Apply to Device..." state for this client's own generated config.
    /// Absent in projects saved before this option existed.
    #[serde(default)]
    pub deploy: DeployProjectDict,
}

/// "Apply to Device...": SSH target + credentials (stored in plaintext,
/// same as WireGuard private keys already are -- the whole project file
/// gets owner-only permissions on save either way) and whether this tab's
/// config has been successfully applied to a device before. Plain-WG-client
/// applies never touch SSH at all -- `device_type`/`applied_device_type`
/// just record which kind of "apply" was last used.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployProjectDict {
    /// Free-text human name for whoever/whatever this config is handed
    /// to ("Vasya's laptop", "Front desk router") -- independent of the
    /// tab's own WireGuard interface name. Absent in projects saved
    /// before this option existed.
    #[serde(default)]
    pub client_label: String,
    #[serde(default)]
    pub device_type: String, // "plain" | "mikrotik" | "openwrt"
    #[serde(default)]
    pub target_ip: String,
    #[serde(default)]
    pub ssh_port: String,
    #[serde(default)]
    pub ssh_username: String,
    #[serde(default)]
    pub auth_is_key: bool,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub key_passphrase: Option<String>,
    #[serde(default)]
    pub applied: bool,
    #[serde(default)]
    pub applied_device_type: Option<String>,
    #[serde(default)]
    pub applied_ip: String,
    /// Best-effort results of the last successful "Check Availability".
    /// Absent in projects saved before this option existed.
    #[serde(default)]
    pub checked_model: Option<String>,
    #[serde(default)]
    pub checked_serial: Option<String>,
}
