use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::host::{HostOptions, WireGuardHost};

/// Serializable form of a host's own `[Interface]` fields (not its
/// peers) -- the Rust equivalent of `host_to_dict()` / `host_from_dict()`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostDict {
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
}

pub fn host_to_dict(host: &WireGuardHost) -> HostDict {
    HostDict {
        name: host.name.clone(),
        private_key: Some(host.private_key.clone()),
        address: host.address.clone(),
        listen_port: host.listen_port,
        dns: host.dns.clone(),
        mtu: host.mtu,
        table: host.table.clone(),
        fw_mark: host.fw_mark.clone(),
        pre_up: host.pre_up.clone(),
        post_up: host.post_up.clone(),
        pre_down: host.pre_down.clone(),
        post_down: host.post_down.clone(),
        save_config: host.save_config,
    }
}

/// Inverse of `host_to_dict()`. Does not restore peers -- add those
/// separately.
pub fn host_from_dict(d: &HostDict) -> Result<WireGuardHost> {
    WireGuardHost::new(
        d.name.clone(),
        HostOptions {
            private_key: d.private_key.clone(),
            address: d.address.clone(),
            listen_port: d.listen_port,
            dns: d.dns.clone(),
            mtu: d.mtu,
            table: d.table.clone(),
            fw_mark: d.fw_mark.clone(),
            pre_up: d.pre_up.clone(),
            post_up: d.post_up.clone(),
            pre_down: d.pre_down.clone(),
            post_down: d.post_down.clone(),
            save_config: d.save_config,
        },
    )
}
