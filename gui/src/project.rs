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
    pub persistent_keepalive: Option<u32>,
    #[serde(default)]
    pub use_preshared_key: bool,
    pub preshared_key: Option<String>,
    pub tunnel_id: Option<u32>,
    #[serde(default)]
    pub tunnel_id_manual: bool,
}
