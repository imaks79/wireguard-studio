use wgcore::{
    address_lists_overlap, generate_private_key, public_key_from_private, HostOptions,
    IpAddressPool, WireGuardHost,
};

use crate::client_tab::ClientTabState;
use crate::deploy::DeployState;
use crate::modal::Modal;
use crate::project::{ExtraPeerDict, HostProjectDict};
use crate::util::{parse_u32, resolve_listen_port, split_csv, split_lines};

/// Which sub-tab of a host is currently visible: its own Host Settings
/// form, or one of its clients by index into `HostTabState::clients`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostSubTab {
    Settings,
    Client(usize),
}

/// One sibling peer (client) of the same host to add as a `[Peer]` block
/// when "Mesh peers together" is enabled, so every peer of a host reaches
/// every other peer of that host directly, in addition to each one's own
/// link back to the host. Mirrors the netbird idea of a full mesh between
/// nodes, applied here between a host's own clients rather than between
/// separate hosts -- every peer effectively also acts as a host that the
/// others can dial.
#[derive(Clone)]
pub struct MeshPeerInfo {
    pub name: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
}

/// When mesh peers are in play, checks `own_address` (one peer's own
/// `Address` field, already split) against every entry in `mesh_peers`,
/// and every pair of mesh peers against each other -- since two of this
/// peer's siblings having overlapping addresses is just as much a
/// conflict in this peer's `[Peer]` table as this peer's own address
/// overlapping one of them. Returns a human-readable description of the
/// first conflict found, or `None` if there isn't one.
pub fn find_mesh_address_conflict(own_address: &[String], mesh_peers: &[MeshPeerInfo]) -> Option<String> {
    for peer in mesh_peers {
        if address_lists_overlap(own_address, &peer.allowed_ips) {
            return Some(format!("this peer's Address overlaps '{}'s", peer.name));
        }
    }
    for i in 0..mesh_peers.len() {
        for j in (i + 1)..mesh_peers.len() {
            if address_lists_overlap(&mesh_peers[i].allowed_ips, &mesh_peers[j].allowed_ips) {
                return Some(format!("'{}' and '{}' have overlapping addresses", mesh_peers[i].name, mesh_peers[j].name));
            }
        }
    }
    None
}

/// For client `self_idx` in `clients` (all belonging to the same host),
/// collect every *other* client that has enough information to be linked
/// (a public key and at least one address). Each client's own `Address`
/// field becomes the `AllowedIPs` of the peer entry its siblings get for
/// it -- the same convention already used for a client's `AllowedIPs` on
/// the host side. A client only gets a usable `Endpoint` for its siblings
/// if it set its own `public_ip` (optionally with a fixed `listen_port`);
/// otherwise it can still dial *out* to reach the others, it just can't be
/// dialed itself.
pub fn collect_client_mesh_peers(clients: &[ClientTabState], self_idx: usize) -> Vec<MeshPeerInfo> {
    clients
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != self_idx)
        .filter_map(|(_, other)| {
            let public_key = other.public_key.trim();
            if public_key.is_empty() {
                return None;
            }
            let allowed_ips = split_csv(&other.address);
            if allowed_ips.is_empty() {
                return None;
            }
            Some(MeshPeerInfo {
                name: other.name.clone(),
                public_key: public_key.to_string(),
                allowed_ips,
                endpoint: other.mesh_endpoint(),
            })
        })
        .collect()
}

/// A peer of this host known only by its public half -- copied from a
/// device or loaded from a `.conf` -- so it has no client tab (there's no
/// private key to build that client's own config from). Edited as a row of
/// the host's "Other peers" table; every field is the raw form text.
#[derive(Clone, Default)]
pub struct ExtraPeer {
    pub name: String,
    pub public_key: String,
    pub allowed_ips: String,
    pub endpoint: String,
    pub keepalive: String,
    pub psk: String,
    /// Whether the device should route this peer's Allowed IPs through the
    /// tunnel (OpenWrt `route_allowed_ips`, a RouterOS `/ip/route` entry).
    pub route: bool,
}

impl ExtraPeer {
    fn from_peer(peer: &wgcore::Peer, route: bool) -> Self {
        ExtraPeer {
            name: peer.comment.clone().unwrap_or_default(),
            public_key: peer.public_key.clone(),
            allowed_ips: peer.allowed_ips.join(", "),
            endpoint: peer.endpoint.clone().unwrap_or_default(),
            keepalive: peer.persistent_keepalive.map(|ka| ka.to_string()).unwrap_or_default(),
            psk: peer.preshared_key.clone().unwrap_or_default(),
            route,
        }
    }

    fn from_imported(peer: &wgcore::ImportedPeer) -> Self {
        ExtraPeer {
            name: peer.name.clone(),
            public_key: peer.public_key.clone(),
            allowed_ips: peer.allowed_ips.join(", "),
            endpoint: peer.endpoint.clone().unwrap_or_default(),
            keepalive: peer.persistent_keepalive.map(|ka| ka.to_string()).unwrap_or_default(),
            psk: peer.preshared_key.clone().unwrap_or_default(),
            route: peer.route_allowed_ips,
        }
    }

    fn to_peer(&self, position: usize) -> Result<wgcore::Peer, String> {
        let label = if self.name.trim().is_empty() { format!("#{position}") } else { format!("'{}'", self.name.trim()) };
        let non_empty = |text: &str| Some(text.trim().to_string()).filter(|t| !t.is_empty());
        let keepalive = parse_u32(&self.keepalive, "Keepalive").map_err(|e| format!("Other peer {label}: {e}"))?;
        wgcore::Peer::build(
            self.public_key.trim().to_string(),
            split_csv(&self.allowed_ips),
            non_empty(&self.endpoint),
            keepalive.filter(|ka| *ka > 0),
            non_empty(&self.psk),
            non_empty(&self.name),
        )
        .map_err(|e| format!("Other peer {label}: {e}"))
    }
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

    /// "Mesh peers together": when on, every client of this host also gets
    /// a `[Peer]` block for every *other* client of this host, in addition
    /// to its own link back to the host -- so instead of one star, this
    /// host's peers form a full mesh among themselves too. Inspired by
    /// netbird's full-mesh peer topology.
    pub mesh_peers_enabled: bool,
    /// "+ EoIP (L2) between them": on top of `mesh_peers_enabled`'s routed
    /// WireGuard links, also give each meshed peer pair a MikroTik EoIP
    /// tunnel in their RouterOS export. Only meaningful while
    /// `mesh_peers_enabled` is on; RouterOS export only.
    pub mesh_eoip: bool,
    /// "EoIP to peers": whether this host builds an EoIP (L2) tunnel to
    /// each of its own clients. Off by default -- most setups only need
    /// the routed WireGuard link.
    pub host_eoip: bool,

    /// "Apply to Device..." state for this host itself (its own generated
    /// config, not its clients' -- each client has its own `deploy` too).
    pub deploy: DeployState,

    pub clients: Vec<ClientTabState>,
    pub selected: HostSubTab,
    client_counter: u32,

    /// The interface's name on the device this host is applied to (the
    /// UCI section on OpenWrt, the interface name on RouterOS). Blank means
    /// "derive it from `name`". Filled in by "Copy Interface from Device"
    /// so applying back lands on that same interface.
    pub device_interface: String,
    /// Whether applying to RouterOS/OpenWrt also sets up firewall rules for
    /// the tunnel. Switched off for an interface copied from a device,
    /// whose firewall is already whatever its owner made it.
    pub manage_firewall: bool,
    /// Peers with no client tab of their own: copied from a device, loaded
    /// from a raw `.conf` via "Load Configuration...", or added by hand.
    /// They ride along through every rebuild, after the client tabs' peers.
    pub extra_peers: Vec<ExtraPeer>,

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
            mesh_peers_enabled: false,
            mesh_eoip: false,
            host_eoip: false,
            deploy: DeployState::default(),
            clients: Vec::new(),
            selected: HostSubTab::Settings,
            client_counter: 0,
            device_interface: String::new(),
            manage_firewall: true,
            extra_peers: Vec::new(),
            pool_cidr: None,
            pool: None,
        }
    }

    pub fn regenerate_key(&mut self) {
        self.private_key = generate_private_key();
        self.refresh_public_key();
    }

    /// Drains any pending "Apply to Device" progress for this host and
    /// every one of its clients, regardless of which sub-tab is currently
    /// selected -- so a background deploy still finishes (and marks its
    /// tab green) even if the user switched to a different host or client
    /// tab while it was running. Call this once per frame, unconditionally,
    /// for every host in the project.
    pub fn poll_deploys(&mut self) -> Option<Modal> {
        let mut out = self.deploy.poll();
        for client in &mut self.clients {
            if let Some(m) = client.deploy.poll() {
                out = Some(m);
            }
        }
        out
    }

    /// Whether this host or any of its clients has a deploy in flight --
    /// used to keep the UI repainting on a timer so the log window (and
    /// the eventual green tab outline) update promptly.
    pub fn any_deploy_running(&self) -> bool {
        self.deploy.is_running() || self.clients.iter().any(|c| c.deploy.is_running())
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
    /// `[Peer]` block. When "Mesh peers together" is on, each client's own
    /// model also gets a `[Peer]` block for every *other* client of this
    /// host (see [`collect_client_mesh_peers`]) -- the host's own peer
    /// list (this method's return value) is a plain star either way, since
    /// meshing only adds links *between* peers, not a new kind of link to
    /// the host itself.
    pub fn build_full_model(&mut self) -> Result<WireGuardHost, String> {
        let mut host = self.build_interface_model()?;
        let host_pubkey = host.public_key.clone();
        let host_name = host.name.clone();

        let mesh_lists: Vec<Vec<MeshPeerInfo>> = if self.mesh_peers_enabled {
            (0..self.clients.len()).map(|i| collect_client_mesh_peers(&self.clients, i)).collect()
        } else {
            vec![Vec::new(); self.clients.len()]
        };

        for (idx, client) in self.clients.iter_mut().enumerate() {
            let mesh_peers = &mesh_lists[idx];
            if let Some(conflict) = find_mesh_address_conflict(&split_csv(&client.address), mesh_peers) {
                return Err(format!(
                    "\"Mesh peers together\" is on, but {conflict} -- WireGuard peers on the same \
                     interface can't have overlapping AllowedIPs. Give each peer its own, non-overlapping \
                     Address, or turn the mesh option off."
                ));
            }
            client.refresh_endpoint(&self.public_ip, &self.listen_port);
            let synced = client.sync(&host_pubkey, &host_name, mesh_peers)?;
            host.add_peer(synced.host_peer);
        }
        for (i, extra) in self.extra_peers.iter().enumerate() {
            let peer = extra.to_peer(i + 1)?;
            if host.peers.iter().any(|p| p.public_key == peer.public_key) {
                return Err(format!(
                    "Public key {} is used by more than one peer of this host -- remove the duplicate \
                     (a client tab and an \"Other peers\" row, or two rows).",
                    peer.public_key
                ));
            }
            host.add_peer(peer);
        }
        Ok(host)
    }

    /// Public keys of the "Other peers" rows the device shouldn't route.
    pub fn unrouted_peer_keys(&self) -> std::collections::HashSet<String> {
        self.extra_peers.iter().filter(|p| !p.route).map(|p| p.public_key.trim().to_string()).collect()
    }

    /// The explicit device-side interface name, if one is set.
    pub fn device_interface_name(&self) -> Option<String> {
        Some(self.device_interface.trim().to_string()).filter(|n| !n.is_empty())
    }

    /// Replace this host's own settings with an interface read from a
    /// device ("Copy Interface from Device"). Its peers become "Other
    /// peers" rows -- except ones whose public key already belongs to one
    /// of this host's client tabs, which stay represented by that tab.
    /// Returns (peers added as rows, peers matched to a client tab).
    pub fn load_from_device(&mut self, iface: &wgcore::ImportedInterface) -> Result<(usize, usize), String> {
        let private_key = wgcore::validate_key(iface.private_key.trim(), "private key")
            .map_err(|e| format!("Interface '{}': could not read a usable private key from the device ({e}).", iface.name))?;
        self.name = iface.name.clone();
        self.device_interface = iface.name.clone();
        self.private_key = private_key;
        self.manual_key = true;
        self.refresh_public_key();
        self.address = iface.address.join(", ");
        self.listen_port = iface.listen_port.map(|p| p.to_string()).unwrap_or_default();
        self.mtu = iface.mtu.map(|m| m.to_string()).unwrap_or_default();
        self.manage_firewall = false;
        self.extra_peers.clear();
        let mut matched = 0;
        for peer in &iface.peers {
            if self.clients.iter().any(|c| c.public_key.trim() == peer.public_key) {
                matched += 1;
            } else {
                self.extra_peers.push(ExtraPeer::from_imported(peer));
            }
        }
        self.refresh_advanced_lock();
        self.selected = HostSubTab::Settings;
        Ok((self.extra_peers.len(), matched))
    }

    pub fn load_from_config(&mut self, text: &str, name: &str) -> Result<usize, String> {
        let host = wgcore::load_host_from_config(text, name).map_err(|e| e.to_string())?;
        let peer_count = host.peers.len();
        // The loaded peers have no client tab of their own (this only
        // replaces the host's own [Interface] fields, the same way the
        // Python original's `load_configuration()` does), so they become
        // "Other peers" rows -- see `extra_peers`'s doc comment. Routed, as
        // a peer of a plain wg-quick config always is.
        self.extra_peers = host.peers.iter().map(|p| ExtraPeer::from_peer(p, true)).collect();
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
            mesh_peers_enabled: self.mesh_peers_enabled,
            mesh_eoip: self.mesh_eoip,
            host_eoip: self.host_eoip,
            deploy: self.deploy.to_project_dict(),
            device_interface: self.device_interface_name(),
            skip_firewall: !self.manage_firewall,
            extra_peers: self
                .extra_peers
                .iter()
                .map(|p| ExtraPeerDict {
                    name: p.name.clone(),
                    public_key: p.public_key.trim().to_string(),
                    allowed_ips: split_csv(&p.allowed_ips),
                    endpoint: Some(p.endpoint.trim().to_string()).filter(|e| !e.is_empty()),
                    persistent_keepalive: p.keepalive.trim().parse().ok(),
                    preshared_key: Some(p.psk.trim().to_string()).filter(|k| !k.is_empty()),
                    route: p.route,
                })
                .collect(),
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
        s.mesh_peers_enabled = d.mesh_peers_enabled;
        s.mesh_eoip = d.mesh_eoip;
        s.host_eoip = d.host_eoip;
        s.deploy = DeployState::from_project_dict(&d.deploy);
        s.device_interface = d.device_interface.clone().unwrap_or_default();
        s.manage_firewall = !d.skip_firewall;
        s.extra_peers = d
            .extra_peers
            .iter()
            .map(|p| ExtraPeer {
                name: p.name.clone(),
                public_key: p.public_key.clone(),
                allowed_ips: p.allowed_ips.join(", "),
                endpoint: p.endpoint.clone().unwrap_or_default(),
                keepalive: p.persistent_keepalive.map(|ka| ka.to_string()).unwrap_or_default(),
                psk: p.preshared_key.clone().unwrap_or_default(),
                route: p.route,
            })
            .collect();
        s.refresh_advanced_lock();

        for (i, cd) in d.clients.iter().enumerate() {
            s.clients.push(ClientTabState::from_project_dict(id * 100_000 + i as u64, cd));
        }
        s.client_counter = d.clients.len() as u32;
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_with_address(id: u64, name: &str, address: &str) -> ClientTabState {
        let mut c = ClientTabState::new(id, name, 1);
        c.address = address.to_string();
        c
    }

    #[test]
    fn collect_client_mesh_peers_excludes_self_and_uses_endpoint_only_when_set() {
        let a = client_with_address(1, "a", "10.0.0.1/32");
        let mut b = client_with_address(2, "b", "10.0.0.2/32");
        b.public_ip = "203.0.113.5".to_string();
        b.listen_port = "51820".to_string();
        let c = client_with_address(3, "c", "10.0.0.3/32");
        let clients = vec![a, b, c];

        let peers = collect_client_mesh_peers(&clients, 0);
        assert_eq!(peers.len(), 2);
        assert!(peers.iter().all(|p| p.name != "a"));

        let b_peer = peers.iter().find(|p| p.name == "b").unwrap();
        assert_eq!(b_peer.endpoint.as_deref(), Some("203.0.113.5:51820"));
        assert_eq!(b_peer.allowed_ips, vec!["10.0.0.2/32".to_string()]);

        let c_peer = peers.iter().find(|p| p.name == "c").unwrap();
        assert_eq!(c_peer.endpoint, None, "peer with no public_ip must not get an Endpoint");
    }

    #[test]
    fn mesh_enabled_client_sync_adds_a_peer_block_per_sibling() {
        let host = HostTabState::new(1, "host");
        let clients = vec![
            client_with_address(1, "a", "10.0.0.1/32"),
            client_with_address(2, "b", "10.0.0.2/32"),
        ];
        let mesh_for_a = collect_client_mesh_peers(&clients, 0);

        let mut a = clients[0].clone();
        let synced = a.sync(&host.public_key, &host.name, &mesh_for_a).unwrap();

        // One peer back to the host, one peer for the meshed sibling.
        assert_eq!(synced.client_model.peers.len(), 2);
        let mesh_peer = synced
            .client_model
            .peers
            .iter()
            .find(|p| p.public_key == clients[1].public_key)
            .expect("sibling should be present as a [Peer] block");
        assert_eq!(mesh_peer.allowed_ips, vec!["10.0.0.2/32".to_string()]);
        assert_eq!(mesh_peer.persistent_keepalive, Some(25));
    }

    #[test]
    fn mesh_disabled_client_sync_has_only_the_host_peer() {
        let host = HostTabState::new(1, "host");
        let mut a = client_with_address(1, "a", "10.0.0.1/32");
        let synced = a.sync(&host.public_key, &host.name, &[]).unwrap();
        assert_eq!(synced.client_model.peers.len(), 1);
    }

    #[test]
    fn build_full_model_keeps_the_host_side_a_plain_star() {
        let mut host = HostTabState::new(1, "host");
        host.address = "10.0.0.0/24".to_string();
        host.mesh_peers_enabled = true;
        host.new_client_tab(None);
        host.new_client_tab(None);
        host.clients[0].address = "10.0.0.11/32".to_string();
        host.clients[1].address = "10.0.0.12/32".to_string();

        let built = host.build_full_model().expect("mesh build should succeed");
        // The host's own [Peer] table is unaffected by peer-to-peer mesh --
        // still exactly one entry per client, same as with mesh off.
        assert_eq!(built.peers.len(), 2);
    }

    fn imported_interface(client_key: &str) -> wgcore::ImportedInterface {
        let peer = |name: &str, public_key: String, route: bool| wgcore::ImportedPeer {
            name: name.to_string(),
            public_key,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            endpoint: Some("203.0.113.9:51820".to_string()),
            persistent_keepalive: Some(25),
            preshared_key: None,
            route_allowed_ips: route,
        };
        wgcore::ImportedInterface {
            name: "wg0".to_string(),
            private_key: generate_private_key(),
            address: vec!["10.0.0.1/24".to_string()],
            listen_port: Some(51820),
            mtu: None,
            peers: vec![
                peer("uplink", WireGuardHost::simple("x").unwrap().public_key, false),
                peer("known client", client_key.to_string(), true),
            ],
        }
    }

    #[test]
    fn load_from_device_keeps_client_tabs_and_turns_the_rest_into_other_peers() {
        let mut host = HostTabState::new(1, "host-1");
        host.address = "10.0.0.1/24".to_string();
        host.new_client_tab(None);
        let iface = imported_interface(&host.clients[0].public_key.clone());

        assert_eq!(host.load_from_device(&iface).unwrap(), (1, 1));
        assert_eq!(host.name, "wg0");
        assert_eq!(host.device_interface, "wg0");
        assert_eq!(host.private_key, iface.private_key);
        assert!(!host.manage_firewall, "a copied interface's firewall is left to its owner");
        assert_eq!(host.unrouted_peer_keys().len(), 1);

        // One peer per client tab plus the imported row, each key once.
        let built = host.build_full_model().unwrap();
        assert_eq!(built.peers.len(), 2);
        assert_eq!(built.peers[1].comment.as_deref(), Some("uplink"));
        assert_eq!(built.peers[1].endpoint.as_deref(), Some("203.0.113.9:51820"));

        // ...and it all survives a project save/load.
        let reloaded = HostTabState::from_project_dict(2, &host.to_project_dict());
        assert_eq!(reloaded.device_interface, "wg0");
        assert!(!reloaded.manage_firewall);
        assert_eq!(reloaded.extra_peers.len(), 1);
        assert_eq!(reloaded.extra_peers[0].allowed_ips, "0.0.0.0/0");
        assert!(!reloaded.extra_peers[0].route);
    }

    #[test]
    fn a_public_key_shared_by_two_peers_is_rejected() {
        let mut host = HostTabState::new(1, "host-1");
        host.address = "10.0.0.1/24".to_string();
        host.new_client_tab(None);
        host.extra_peers.push(ExtraPeer { public_key: host.clients[0].public_key.clone(), ..Default::default() });
        assert!(host.build_full_model().unwrap_err().contains("more than one peer"));
    }

    #[test]
    fn overlapping_client_addresses_are_rejected_when_meshed() {
        let mut host = HostTabState::new(1, "host");
        host.address = "10.0.0.0/24".to_string();
        host.mesh_peers_enabled = true;
        host.new_client_tab(None);
        host.new_client_tab(None);
        host.clients[0].address = "10.0.0.11/32".to_string();
        host.clients[1].address = "10.0.0.11/32".to_string();

        let err = host.build_full_model().unwrap_err();
        assert!(err.contains("overlap"), "unexpected error: {err}");
    }
}
