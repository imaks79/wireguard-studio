use std::fs;
use std::path::Path;

use crate::error::{Result, WgError};
use crate::keys::{generate_private_key, public_key_from_private, validate_cidr_list, validate_key};
use crate::peer::Peer;

/// One WireGuard interface: an office gateway, a roadwarrior client, a
/// server -- anything that gets its own `[Interface]` section and keypair.
///
/// Every field WireGuard's `[Interface]` section supports is exposed:
/// PrivateKey, Address, ListenPort, DNS, MTU, Table, PreUp/PostUp/PreDown/
/// PostDown, SaveConfig, FwMark.
#[derive(Debug, Clone)]
pub struct WireGuardHost {
    pub name: String,
    pub private_key: String,
    pub public_key: String,

    pub address: Vec<String>,
    pub listen_port: Option<u16>,
    pub dns: Vec<String>,
    pub mtu: Option<u32>,
    pub table: Option<String>,
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
    pub save_config: Option<bool>,
    pub fw_mark: Option<String>,

    pub peers: Vec<Peer>,
}

/// Every field of `[Interface]` other than `name`, gathered together so
/// `WireGuardHost::new` doesn't need a dozen positional parameters.
/// `Default::default()` gives you "auto-generate the key, no address,
/// nothing else set", matching every keyword argument being optional in
/// the Python constructor.
#[derive(Debug, Clone, Default)]
pub struct HostOptions {
    pub private_key: Option<String>, // None -> auto-generate
    pub address: Vec<String>,
    pub listen_port: Option<u16>,
    pub dns: Vec<String>,
    pub mtu: Option<u32>,
    pub table: Option<String>, // "auto" | "off" | number, as text
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
    pub save_config: Option<bool>,
    pub fw_mark: Option<String>,
}

impl WireGuardHost {
    pub fn new(name: impl Into<String>, opts: HostOptions) -> Result<Self> {
        let name = name.into();

        let private_key = match opts.private_key {
            None => generate_private_key(),
            Some(k) => validate_key(&k, "private_key")?,
        };
        let public_key = public_key_from_private(&private_key)?;

        let address = validate_cidr_list(&opts.address, "address")?;

        if let Some(port) = opts.listen_port {
            if port == 0 {
                return Err(WgError::Value(
                    "listen_port must be between 1 and 65535".into(),
                ));
            }
        }

        Ok(WireGuardHost {
            name,
            private_key,
            public_key,
            address,
            listen_port: opts.listen_port,
            dns: opts.dns,
            mtu: opts.mtu,
            table: opts.table,
            pre_up: opts.pre_up,
            post_up: opts.post_up,
            pre_down: opts.pre_down,
            post_down: opts.post_down,
            save_config: opts.save_config,
            fw_mark: opts.fw_mark,
            peers: Vec::new(),
        })
    }

    /// Convenience constructor for the common case of just a name with
    /// everything else defaulted (auto-generated key, no address).
    pub fn simple(name: impl Into<String>) -> Result<Self> {
        Self::new(name, HostOptions::default())
    }

    // -- Peer management ----------------------------------------------

    pub fn add_peer(&mut self, peer: Peer) -> &Peer {
        self.peers.push(peer);
        self.peers.last().unwrap()
    }

    /// Add `other` as a peer of this host, pulling its public key
    /// automatically -- no manual copy/paste of keys needed.
    #[allow(clippy::too_many_arguments)]
    pub fn add_peer_host(
        &mut self,
        other: &WireGuardHost,
        allowed_ips: Vec<String>,
        endpoint: Option<String>,
        persistent_keepalive: Option<u32>,
        preshared_key: Option<String>,
    ) -> Result<()> {
        let peer = Peer::build(
            other.public_key.clone(),
            allowed_ips,
            endpoint,
            persistent_keepalive,
            preshared_key,
            Some(other.name.clone()),
        )?;
        self.add_peer(peer);
        Ok(())
    }

    // -- Rendering -------------------------------------------------------

    pub fn interface_config(&self, include_private_key: bool) -> String {
        let mut lines = vec!["[Interface]".to_string()];
        if include_private_key {
            lines.push(format!("PrivateKey = {}", self.private_key));
        }
        if !self.address.is_empty() {
            lines.push(format!("Address = {}", self.address.join(", ")));
        }
        if let Some(p) = self.listen_port {
            lines.push(format!("ListenPort = {p}"));
        }
        if !self.dns.is_empty() {
            lines.push(format!("DNS = {}", self.dns.join(", ")));
        }
        if let Some(m) = self.mtu {
            lines.push(format!("MTU = {m}"));
        }
        if let Some(t) = &self.table {
            lines.push(format!("Table = {t}"));
        }
        for cmd in &self.pre_up {
            lines.push(format!("PreUp = {cmd}"));
        }
        for cmd in &self.post_up {
            lines.push(format!("PostUp = {cmd}"));
        }
        for cmd in &self.pre_down {
            lines.push(format!("PreDown = {cmd}"));
        }
        for cmd in &self.post_down {
            lines.push(format!("PostDown = {cmd}"));
        }
        if let Some(sc) = self.save_config {
            lines.push(format!("SaveConfig = {}", if sc { "true" } else { "false" }));
        }
        if let Some(fw) = &self.fw_mark {
            if !fw.is_empty() {
                lines.push(format!("FwMark = {fw}"));
            }
        }
        lines.join("\n")
    }

    pub fn full_config(&self) -> String {
        let mut parts = vec![format!("# {}", self.name), self.interface_config(true)];
        for peer in &self.peers {
            parts.push(String::new());
            parts.push(peer.to_config());
        }
        parts.join("\n") + "\n"
    }

    /// Write this host's config to `<directory>/<name>.conf`. Unix
    /// permissions are tightened to 0600 (best-effort on other platforms,
    /// matching the Python original's `os.chmod`).
    pub fn save(&self, directory: impl AsRef<Path>, filename: Option<&str>) -> Result<std::path::PathBuf> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)?;
        let path = directory.join(filename.map(str::to_string).unwrap_or_else(|| format!("{}.conf", self.name)));
        fs::write(&path, self.full_config())?;
        set_owner_only_permissions(&path)?;
        Ok(path)
    }
}

/// Tighten a just-written file's permissions to owner-read/write only.
/// Best-effort on non-Unix platforms, where this isn't meaningful for all
/// filesystems. Public so callers that write private-key-bearing files
/// directly (e.g. the GUI's own export/save paths) can apply the same
/// hardening that [`WireGuardHost::save`] applies internally.
pub fn set_owner_only_permissions(path: &Path) -> Result<()> {
    imp::set_owner_only_permissions(path)
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(super) fn set_owner_only_permissions(path: &Path) -> Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    pub(super) fn set_owner_only_permissions(_path: &Path) -> Result<()> {
        Ok(())
    }
}
