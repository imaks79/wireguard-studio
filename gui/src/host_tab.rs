use wgcore::{
    generate_private_key, public_key_from_private, HostOptions, IpAddressPool, WireGuardHost,
};

use crate::client_tab::ClientTabState;
use crate::project::HostProjectDict;
use crate::util::{parse_u32, resolve_listen_port, split_csv, split_lines};

/// Which sub-tab of a host is currently visible: its own Host Settings
/// form, or one of its clients by index into `HostTabState::clients`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostSubTab {
    Settings,
    Client(usize),
}

/// One WireGuard interface, with a nested set of client tabs. Rust port
/// of Tkinter's `HostTab`, minus the widget plumbing.
pub struct HostTabState {
    pub id: u64,
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub manual_key: bool,
    pub address: String,
    pub listen_port: String,
    pub dns: String,
    pub mtu: String,
    pub table: String,
    pub fwmark: String,
    pub save_config: bool,
    pub pre_up: String,
    pub post_up: String,
    pub pre_down: String,
    pub post_down: String,
    pub public_ip: String,
    pub advanced: bool,

    pub clients: Vec<ClientTabState>,
    pub selected: HostSubTab,
    client_counter: u32,

    /// Peers that came from `load_from_config()` (a raw `.conf` loaded
    /// via "Load Configuration...") but have no corresponding client tab.
    /// Mirrors the Python original: `HostTab.sync_to_model()` starts from
    /// `old_peers = list(self.host.peers)`, so any peer never claimed by a
    /// client tab rides along through every rebuild. Not part of the
    /// project-file schema, matching `host_to_dict()`'s omission of peers
    /// there too -- these only survive for the current session.
    loaded_peers: Vec<wgcore::Peer>,

    pool_cidr: Option<String>,
    pool: Option<IpAddressPool>,
}

impl HostTabState {
    pub fn new(id: u64, default_name: &str) -> Self {
        let private_key = generate_private_key();
        let public_key = public_key_from_private(&private_key).unwrap_or_default();
        HostTabState {
            id,
            name: default_name.to_string(),
            private_key,
            public_key,
            manual_key: false,
            address: String::new(),
            listen_port: crate::util::generate_random_listen_port().to_string(),
            dns: String::new(),
            mtu: "1420".to_string(),
            table: String::new(),
            fwmark: String::new(),
            save_config: false,
            pre_up: String::new(),
            post_up: String::new(),
            pre_down: String::new(),
            post_down: String::new(),
            public_ip: String::new(),
            advanced: false,
            clients: Vec::new(),
            selected: HostSubTab::Settings,
            client_counter: 0,
            loaded_peers: Vec::new(),
            pool_cidr: None,
            pool: None,
        }
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

    pub fn randomize_listen_port(&mut self) {
        self.listen_port = crate::util::generate_random_listen_port().to_string();
    }

    pub fn refresh_advanced_lock(&mut self) {
        let has_advanced_data = !self.dns.trim().is_empty()
            || !matches!(self.mtu.trim(), "" | "1420")
            || !self.table.trim().is_empty()
            || !self.fwmark.trim().is_empty()
            || self.save_config
            || !split_lines(&self.pre_up).is_empty()
            || !split_lines(&self.post_up).is_empty()
            || !split_lines(&self.pre_down).is_empty()
            || !split_lines(&self.post_down).is_empty();
        self.advanced = has_advanced_data;
    }

    /// Returns (and lazily builds/rebuilds) the IP pool clients draw
    /// addresses from, keyed off this host's first Address entry. The
    /// host's own address is reserved so it's never handed to a client.
    fn ensure_pool(&mut self) -> Option<&mut IpAddressPool> {
        let first_cidr = split_csv(&self.address).into_iter().next()?;
        if self.pool_cidr.as_deref() != Some(first_cidr.as_str()) {
            let mut pool = IpAddressPool::new(&first_cidr, None, &[]).ok()?;
            pool.reserve(&first_cidr).ok()?;
            self.pool = Some(pool);
            self.pool_cidr = Some(first_cidr);
        }
        self.pool.as_mut()
    }

    /// Make sure `self.pool` reflects the current Address field, without
    /// holding onto the returned reference (used right before
    /// [`Self::pool_take`] so a later closure can own the pool locally
    /// instead of re-borrowing `self`).
    pub fn ensure_pool_fresh(&mut self) {
        let _ = self.ensure_pool();
    }

    pub fn pool_take(&mut self) -> Option<IpAddressPool> {
        self.pool.take()
    }

    pub fn pool_put(&mut self, pool: Option<IpAddressPool>) {
        self.pool = pool;
    }

    pub fn new_client_tab(&mut self, loaded: Option<WireGuardHost>) -> usize {
        self.client_counter += 1;
        let idx = self.clients.len();
        let default_name = format!("{}-client-{}", self.name, self.client_counter);
        let mut client = match loaded {
            Some(host) => ClientTabState::from_loaded_host(self.id * 100_000 + idx as u64, &host),
            None => {
                let mut c = ClientTabState::new(self.id * 100_000 + idx as u64, &default_name, self.client_counter);
                let host_mtu: Option<u32> = self.mtu.trim().parse().ok();
                let host_dns = split_csv(&self.dns);
                let public_ip = self.public_ip.clone();
                let listen_port = self.listen_port.clone();
                c.apply_host_defaults(&host_dns, host_mtu, &public_ip, &listen_port, false, || {
                    self.ensure_pool().and_then(|p| p.allocate().ok())
                });
                // Host didn't specify its own MTU -- fall back to
                // WireGuard's usual default rather than leaving the field
                // blank. Must run *after* apply_host_defaults so a host
                // that does have its own MTU gets inherited instead.
                if c.mtu.trim().is_empty() {
                    c.mtu = "1420".to_string();
                }
                c
            }
        };
        client.refresh_advanced_lock();
        self.clients.push(client);
        self.selected = HostSubTab::Client(idx);
        idx
    }

    /// Browser-style Ctrl+1..Ctrl+9 tab switching, scoped to this host's
    /// own sub-tabs (Host Settings counts as tab 0). Index 8 (Ctrl+9)
    /// always jumps to the last sub-tab, matching browser convention.
    pub fn select_subtab_by_shortcut_index(&mut self, index: usize) {
        let total = 1 + self.clients.len();
        if total == 0 {
            return;
        }
        let target = if index == 8 {
            total - 1
        } else if index < total {
            index
        } else {
            return;
        };
        self.selected = if target == 0 { HostSubTab::Settings } else { HostSubTab::Client(target - 1) };
    }

    pub fn close_client_tab(&mut self, idx: usize) {
        if idx < self.clients.len() {
            self.clients.remove(idx);
        }
        self.selected = match self.selected {
            HostSubTab::Client(i) if i == idx => HostSubTab::Settings,
            HostSubTab::Client(i) if i > idx => HostSubTab::Client(i - 1),
            other => other,
        };
    }

    /// Rebuild this host's own `[Interface]` model from the form (peers
    /// are not attached here -- see `build_full_model`).
    pub fn build_interface_model(&mut self) -> Result<WireGuardHost, String> {
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
        let listen_port = resolve_listen_port(&self.listen_port)?;
        let mtu = parse_u32(&self.mtu, "MTU")?;

        let host = WireGuardHost::new(
            &name,
            HostOptions {
                private_key: Some(private_key),
                address: split_csv(&self.address),
                listen_port,
                dns: split_csv(&self.dns),
                mtu,
                table: {
                    let t = self.table.trim();
                    if t.is_empty() {
                        None
                    } else {
                        Some(t.to_string())
                    }
                },
                pre_up: split_lines(&self.pre_up),
                post_up: split_lines(&self.post_up),
                pre_down: split_lines(&self.pre_down),
                post_down: split_lines(&self.post_down),
                save_config: Some(self.save_config),
                fw_mark: {
                    let f = self.fwmark.trim();
                    if f.is_empty() {
                        None
                    } else {
                        Some(f.to_string())
                    }
                },
            },
        )
        .map_err(|e| e.to_string())?;

        self.name = name;
        self.private_key = host.private_key.clone();
        self.public_key = host.public_key.clone();
        if let Some(p) = host.listen_port {
            self.listen_port = p.to_string();
        }
        Ok(host)
    }

    /// Sync this host and every client tab (clients first, so the host's
    /// peer list reflects each client's latest settings), returning the
    /// fully assembled host including every client folded in as a
    /// `[Peer]` block.
    pub fn build_full_model(&mut self) -> Result<WireGuardHost, String> {
        let mut host = self.build_interface_model()?;
        let host_pubkey = host.public_key.clone();
        let host_name = host.name.clone();
        for client in &mut self.clients {
            client.refresh_endpoint(&self.public_ip, &self.listen_port);
            let synced = client.sync(&host_pubkey, &host_name)?;
            host.add_peer(synced.host_peer);
        }
        for peer in &self.loaded_peers {
            host.add_peer(peer.clone());
        }
        Ok(host)
    }

    pub fn load_from_config(&mut self, text: &str, name: &str) -> Result<usize, String> {
        let host = wgcore::load_host_from_config(text, name).map_err(|e| e.to_string())?;
        let peer_count = host.peers.len();
        // The loaded peers have no client tab of their own (this only
        // replaces the host's own [Interface] fields, the same way the
        // Python original's `load_configuration()` does), so stash them
        // to ride along through every future rebuild -- see
        // `loaded_peers`'s doc comment.
        self.loaded_peers = host.peers.clone();
        self.name = host.name.clone();
        self.private_key = host.private_key.clone();
        self.public_key = host.public_key.clone();
        self.address = host.address.join(", ");
        self.listen_port = host.listen_port.map(|p| p.to_string()).unwrap_or_default();
        self.dns = host.dns.join(", ");
        self.mtu = host.mtu.map(|m| m.to_string()).unwrap_or_default();
        self.table = host.table.clone().unwrap_or_default();
        self.fwmark = host.fw_mark.clone().unwrap_or_default();
        self.save_config = host.save_config.unwrap_or(false);
        self.pre_up = host.pre_up.join("\n");
        self.post_up = host.post_up.join("\n");
        self.pre_down = host.pre_down.join("\n");
        self.post_down = host.post_down.join("\n");
        self.refresh_advanced_lock();
        self.manual_key = true;
        Ok(peer_count)
    }

    pub fn to_project_dict(&self) -> HostProjectDict {
        HostProjectDict {
            name: self.name.clone(),
            private_key: Some(self.private_key.clone()),
            address: split_csv(&self.address),
            listen_port: self.listen_port.trim().parse().ok(),
            dns: split_csv(&self.dns),
            mtu: self.mtu.trim().parse().ok(),
            table: if self.table.trim().is_empty() { None } else { Some(self.table.clone()) },
            fw_mark: if self.fwmark.trim().is_empty() { None } else { Some(self.fwmark.clone()) },
            pre_up: split_lines(&self.pre_up),
            post_up: split_lines(&self.post_up),
            pre_down: split_lines(&self.pre_down),
            post_down: split_lines(&self.post_down),
            save_config: Some(self.save_config),
            public_ip: Some(self.public_ip.clone()),
            public_endpoint: None,
            manual_key: self.manual_key,
            clients: self.clients.iter().map(ClientTabState::to_project_dict).collect(),
        }
    }

    pub fn from_project_dict(id: u64, d: &HostProjectDict) -> Self {
        let mut s = HostTabState::new(id, &d.name);
        s.private_key = d.private_key.clone().unwrap_or_else(generate_private_key);
        s.refresh_public_key();
        s.address = d.address.join(", ");
        s.listen_port = d.listen_port.map(|p| p.to_string()).unwrap_or_default();
        s.dns = d.dns.join(", ");
        s.mtu = d.mtu.map(|m| m.to_string()).unwrap_or_default();
        s.table = d.table.clone().unwrap_or_default();
        s.fwmark = d.fw_mark.clone().unwrap_or_default();
        s.save_config = d.save_config.unwrap_or(false);
        s.pre_up = d.pre_up.join("\n");
        s.post_up = d.post_up.join("\n");
        s.pre_down = d.pre_down.join("\n");
        s.post_down = d.post_down.join("\n");
        // "public_ip" is the current format; fall back to the older
        // combined "public_endpoint" (host:port) field, keeping just the
        // address part, for projects saved before this split.
        s.public_ip = d.public_ip.clone().unwrap_or_default();
        if s.public_ip.is_empty() {
            if let Some(legacy) = &d.public_endpoint {
                s.public_ip = legacy.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| legacy.clone());
            }
        }
        s.manual_key = d.manual_key;
        s.refresh_advanced_lock();

        for (i, cd) in d.clients.iter().enumerate() {
            s.clients.push(ClientTabState::from_project_dict(id * 100_000 + i as u64, cd));
        }
        s.client_counter = d.clients.len() as u32;
        s
    }
}
