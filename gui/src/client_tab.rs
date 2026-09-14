use wgcore::{
    generate_preshared_key, generate_private_key, public_key_from_private, HostOptions, Peer,
    WireGuardHost,
};

use crate::project::ClientProjectDict;
use crate::util::{parse_u32, split_csv};

/// One peer of a host, which is itself a full `WireGuardHost` (its own
/// `[Interface]` plus one `[Peer]` entry linking back to the host). Rust
/// port of Tkinter's `ClientTab`, minus the widget plumbing.
#[derive(Clone)]
pub struct ClientTabState {
    pub id: u64,
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub manual_key: bool,
    pub address: String,
    pub address_manual: bool,
    pub dns: String,
    pub mtu: String,
    pub allowed_ips: String,
    pub endpoint: String,
    pub endpoint_manual: bool,
    pub keepalive: String,
    pub use_psk: bool,
    pub psk_manual: bool,
    pub psk: String,
    pub tunnel_id: String,
    pub tunnel_id_manual: bool,
    pub advanced: bool,
}

/// Output of [`ClientTabState::sync`]: the client's own full config, plus
/// the `[Peer]` entry that represents it inside the parent host's peer
/// list. Both are derived from the *same* resolved pre-shared key so the
/// two sides of the link can never silently drift apart.
pub struct ClientSync {
    pub client_model: WireGuardHost,
    pub host_peer: Peer,
}

impl ClientTabState {
    pub fn new(id: u64, default_name: &str, default_tunnel_id: u32) -> Self {
        let private_key = generate_private_key();
        let public_key = public_key_from_private(&private_key).unwrap_or_default();
        ClientTabState {
            id,
            name: default_name.to_string(),
            private_key,
            public_key,
            manual_key: false,
            address: String::new(),
            address_manual: false,
            dns: String::new(),
            // Left blank rather than pre-filled with "1420": the host's
            // own MTU (if it has one) should win when a fresh client is
            // built via `HostTabState::new_client_tab`, which applies
            // host defaults first and only then falls back to "1420" if
            // still blank -- matching the Python original's order in
            // `ClientTab.__init__`. Pre-filling here would make that
            // fallback run before the host default ever gets a chance.
            mtu: String::new(),
            allowed_ips: "0.0.0.0/0".to_string(),
            endpoint: String::new(),
            endpoint_manual: false,
            keepalive: "25".to_string(),
            use_psk: true,
            psk_manual: false,
            psk: String::new(),
            tunnel_id: default_tunnel_id.to_string(),
            tunnel_id_manual: false,
            advanced: false,
        }
    }

    /// Populate from an existing client config that was loaded from disk
    /// (`Open Client Config...`), the way `_load_from_client` does. The
    /// resulting tab is fully editable, since a client tab always has a
    /// private key (unlike a bare `[Peer]` entry on the host side).
    pub fn from_loaded_host(id: u64, host: &WireGuardHost) -> Self {
        let mut s = ClientTabState::new(id, &host.name, 1);
        s.manual_key = true;
        s.address_manual = true;
        s.endpoint_manual = true;
        s.tunnel_id_manual = true;
        s.name = host.name.clone();
        s.private_key = host.private_key.clone();
        s.public_key = host.public_key.clone();
        s.address = host.address.join(", ");
        s.dns = host.dns.join(", ");
        s.mtu = host.mtu.map(|m| m.to_string()).unwrap_or_default();
        if let Some(p) = host.peers.first() {
            s.allowed_ips = if p.allowed_ips.is_empty() {
                "0.0.0.0/0".to_string()
            } else {
                p.allowed_ips.join(", ")
            };
            if let Some(ep) = &p.endpoint {
                s.endpoint = ep.clone();
            }
            if let Some(ka) = p.persistent_keepalive {
                s.keepalive = ka.to_string();
            }
            s.use_psk = p.preshared_key.is_some();
            s.psk = p.preshared_key.clone().unwrap_or_default();
            s.psk_manual = !s.psk.is_empty();
        }
        s.refresh_advanced_lock();
        s
    }

    pub fn regenerate_key(&mut self) {
        self.private_key = generate_private_key();
        self.refresh_public_key();
    }

    pub fn refresh_public_key(&mut self) {
        let trimmed = self.private_key.trim();
        if trimmed.is_empty() {
            self.public_key.clear();
            return;
        }
        self.public_key = public_key_from_private(trimmed)
            .unwrap_or_else(|_| "(invalid private key)".to_string());
    }

    pub fn generate_psk(&mut self) {
        self.psk = generate_preshared_key();
        self.use_psk = true;
    }

    pub fn generate_tunnel_id(&mut self) {
        self.tunnel_id = crate::util::random_tunnel_id().to_string();
    }

    pub fn get_tunnel_id(&self) -> Option<u32> {
        self.tunnel_id.trim().parse().ok()
    }

    /// Auto-fill Host Endpoint from the host's Public IP + Listen Port.
    /// No-op while in manual mode.
    pub fn refresh_endpoint(&mut self, host_public_ip: &str, host_listen_port: &str) {
        if self.endpoint_manual {
            return;
        }
        let public_ip = host_public_ip.trim();
        let port = host_listen_port.trim();
        self.endpoint = if !public_ip.is_empty() && !port.is_empty() {
            format!("{public_ip}:{port}")
        } else if !public_ip.is_empty() {
            public_ip.to_string()
        } else {
            String::new()
        };
    }

    /// Fill in convenience defaults derived from the parent host: Address
    /// from the pool (if blank), DNS/MTU from the host (blank fields only
    /// unless `force`), and Endpoint. Address is never force-overwritten,
    /// since reassigning it would silently burn another pool IP.
    pub fn apply_host_defaults(
        &mut self,
        host_dns: &[String],
        host_mtu: Option<u32>,
        host_public_ip: &str,
        host_listen_port: &str,
        force: bool,
        mut allocate_address: impl FnMut() -> Option<String>,
    ) {
        if self.address.trim().is_empty() {
            if let Some(addr) = allocate_address() {
                self.address = addr;
            }
        }
        if force || self.dns.trim().is_empty() {
            if !host_dns.is_empty() {
                self.dns = host_dns.join(", ");
            }
        }
        if force || self.mtu.trim().is_empty() {
            if let Some(m) = host_mtu {
                self.mtu = m.to_string();
            }
        }
        self.refresh_endpoint(host_public_ip, host_listen_port);
    }

    /// Auto-unlock advanced fields if they already hold non-default data,
    /// so nothing the user already set is hidden behind a collapsed
    /// section.
    pub fn refresh_advanced_lock(&mut self) {
        let has_advanced_data = !self.dns.trim().is_empty()
            || !matches!(self.mtu.trim(), "" | "1420")
            || !matches!(self.keepalive.trim(), "" | "25");
        self.advanced = has_advanced_data;
    }

    fn resolve_psk(&mut self) -> Option<String> {
        if !self.use_psk {
            return None;
        }
        if self.psk_manual && !self.psk.trim().is_empty() {
            return Some(self.psk.trim().to_string());
        }
        if self.psk.trim().is_empty() {
            self.psk = generate_preshared_key();
        }
        Some(self.psk.clone())
    }

    /// Rebuild this client's model from the form: its own `[Interface]`
    /// plus [Peer] entry pointing at the host, and the `[Peer]` entry that
    /// belongs on the *host's* side. Mirrors `ClientTab.sync_to_model()`.
    pub fn sync(&mut self, host_pubkey: &str, host_name: &str) -> Result<ClientSync, String> {
        let name = {
            let n = self.name.trim();
            if n.is_empty() {
                self.name.clone()
            } else {
                n.to_string()
            }
        };
        let private_key = if self.private_key.trim().is_empty() {
            generate_private_key()
        } else {
            self.private_key.trim().to_string()
        };
        let mtu = parse_u32(&self.mtu, "MTU")?;
        let keepalive = parse_u32(&self.keepalive, "Keepalive")?;

        let mut client = WireGuardHost::new(
            &name,
            HostOptions {
                private_key: Some(private_key),
                address: split_csv(&self.address),
                dns: split_csv(&self.dns),
                mtu,
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())?;

        self.private_key = client.private_key.clone();
        self.public_key = client.public_key.clone();

        let psk = self.resolve_psk();
        self.psk = psk.clone().unwrap_or_default();

        let allowed = {
            let a = split_csv(&self.allowed_ips);
            if a.is_empty() {
                vec!["0.0.0.0/0".to_string()]
            } else {
                a
            }
        };
        let client_peer = Peer::build(
            host_pubkey.to_string(),
            allowed,
            if self.endpoint.trim().is_empty() {
                None
            } else {
                Some(self.endpoint.trim().to_string())
            },
            keepalive,
            psk.clone(),
            Some(host_name.to_string()),
        )
        .map_err(|e| e.to_string())?;
        client.add_peer(client_peer);

        let host_peer_ips = {
            let a = split_csv(&self.address);
            if a.is_empty() {
                vec!["0.0.0.0/0".to_string()]
            } else {
                a
            }
        };
        let host_peer = Peer::build(
            self.public_key.clone(),
            host_peer_ips,
            None,
            None,
            psk,
            Some(name),
        )
        .map_err(|e| e.to_string())?;

        Ok(ClientSync {
            client_model: client,
            host_peer,
        })
    }

    pub fn to_project_dict(&self) -> ClientProjectDict {
        ClientProjectDict {
            name: self.name.clone(),
            private_key: Some(self.private_key.clone()),
            address: split_csv(&self.address),
            dns: split_csv(&self.dns),
            mtu: self.mtu.trim().parse().ok(),
            manual_key: self.manual_key,
            allowed_ips: {
                let a = split_csv(&self.allowed_ips);
                if a.is_empty() {
                    vec!["0.0.0.0/0".to_string()]
                } else {
                    a
                }
            },
            endpoint: if self.endpoint.trim().is_empty() {
                None
            } else {
                Some(self.endpoint.trim().to_string())
            },
            endpoint_manual: self.endpoint_manual,
            persistent_keepalive: self.keepalive.trim().parse().ok(),
            use_preshared_key: self.use_psk,
            preshared_key: if self.psk.is_empty() { None } else { Some(self.psk.clone()) },
            tunnel_id: self.get_tunnel_id(),
            tunnel_id_manual: self.tunnel_id_manual,
        }
    }

    pub fn from_project_dict(id: u64, d: &ClientProjectDict) -> Self {
        let mut s = ClientTabState::new(id, &d.name, d.tunnel_id.unwrap_or(1));
        s.private_key = d.private_key.clone().unwrap_or_else(generate_private_key);
        s.refresh_public_key();
        s.address = d.address.join(", ");
        s.dns = d.dns.join(", ");
        s.mtu = d.mtu.map(|m| m.to_string()).unwrap_or_default();
        s.manual_key = d.manual_key;
        s.address_manual = true;
        s.allowed_ips = if d.allowed_ips.is_empty() {
            "0.0.0.0/0".to_string()
        } else {
            d.allowed_ips.join(", ")
        };
        s.endpoint = d.endpoint.clone().unwrap_or_default();
        s.endpoint_manual = d.endpoint_manual;
        if let Some(ka) = d.persistent_keepalive {
            s.keepalive = ka.to_string();
        }
        s.use_psk = d.use_preshared_key;
        s.psk = d.preshared_key.clone().unwrap_or_default();
        s.psk_manual = d.preshared_key.is_some();
        if let Some(tid) = d.tunnel_id {
            s.tunnel_id = tid.to_string();
        }
        s.tunnel_id_manual = d.tunnel_id_manual;
        s.refresh_advanced_lock();
        s
    }
}
