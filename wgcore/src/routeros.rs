//! Render a RouterOS (MikroTik) CLI script that recreates a host's
//! WireGuard interface, address(es), peers, an EoIP tunnel riding on top
//! of each point-to-point peer, a basic firewall allowance for the
//! tunnel, and static routes for each peer's AllowedIPs.
//!
//! Paste the output directly into an SSH/terminal session on the router
//! (RouterOS v7+, which has native WireGuard support).

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::host::WireGuardHost;

fn routeros_str(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn routeros_interface_name(name: &str, fallback: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let cleaned = cleaned.trim_matches('-');
    let result = if cleaned.is_empty() { fallback } else { cleaned };
    result.chars().take(32).collect()
}

/// Return the bare IP if `cidr_list` is exactly one /32 (or /128) address,
/// else `None`. EoIP needs one specific remote endpoint, not a routed
/// subnet, so a peer whose AllowedIPs is a range (e.g. a full-tunnel
/// 0.0.0.0/0) doesn't have a usable "other end" address.
pub fn single_ip_address(cidr_list: &[String]) -> Option<String> {
    if cidr_list.len() != 1 {
        return None;
    }
    let net: ipnet::IpNet = cidr_list[0].parse().ok()?;
    let is_host = match net {
        ipnet::IpNet::V4(n) => n.prefix_len() == 32,
        ipnet::IpNet::V6(n) => n.prefix_len() == 128,
    };
    if !is_host {
        return None;
    }
    Some(net.network().to_string())
}

/// Return the bare IP of the first entry in `cidr_list`, regardless of its
/// prefix length. Unlike `single_ip_address()`, this doesn't require a
/// lone /32 -- it's for reading "this host's own address" out of a normal
/// subnet-style Address field like 10.10.0.1/24.
pub fn bare_ip_address(cidr_list: &[String]) -> Option<String> {
    let first = cidr_list.first()?;
    if let Ok(net) = first.parse::<ipnet::IpNet>() {
        return Some(net.addr().to_string());
    }
    first.split('/').next().map(str::to_string)
}

/// A tunnel-id derived from both peers' WireGuard public keys.
/// Order-independent so generating the script from either side of the
/// link produces the same id. `pub(crate)` so [`crate::openwrt`] can reuse
/// the exact same derivation -- a RouterOS peer and an OpenWrt peer of the
/// same link need to land on the same id too, not just two RouterOS ends.
pub(crate) fn eoip_tunnel_id(pubkey_a: &str, pubkey_b: &str) -> u32 {
    let mut pair = [pubkey_a, pubkey_b];
    pair.sort();
    let joined = format!("{}|{}", pair[0], pair[1]);
    let digest = Sha256::digest(joined.as_bytes());
    let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    // Interpret the hex digest as a big number mod 65000, +1, same as the
    // Python `int(digest, 16) % 65000 + 1`. A u128 easily covers this: we
    // only need the low-order bits for a modulus this small, so folding
    // the digest bytes through a running remainder avoids needing
    // bignum arithmetic.
    let mut rem: u64 = 0;
    for ch in hex.chars() {
        let digit = ch.to_digit(16).unwrap() as u64;
        rem = (rem * 16 + digit) % 65000;
    }
    (rem as u32) + 1
}

#[derive(Debug, Clone, Default)]
pub struct RouterOsOptions {
    /// Maps a peer's public_key to the bare IP that peer is actually
    /// configured with (its own Address field) -- this is what EoIP's
    /// remote-address is built from.
    pub peer_remote_addresses: HashMap<String, String>,
    /// Maps a peer's public_key to the EoIP tunnel-id to use for it.
    pub peer_tunnel_ids: HashMap<String, u32>,
    /// Public keys of peers whose EoIP tunnel-id must never be silently
    /// renumbered on a local collision, unlike an ordinary client's.
    ///
    /// `eoip_tunnel_id()` is order-independent (it sorts the two public
    /// keys before hashing), so both ends of a host-to-host mesh link
    /// always compute the *same* starting id on their own. But each end's
    /// script is generated independently, and the collision-avoidance
    /// loop below only knows about tunnel-ids already used *on that one
    /// host* -- so if host A happens to have some other peer already
    /// sitting on that id, A's copy gets silently bumped while host B's
    /// (which has a different set of other peers) doesn't, and the two
    /// scripts end up disagreeing on the id for what's supposed to be the
    /// same tunnel. Pinning the mesh side keeps it fixed at the
    /// deterministic value on both ends; the (safe to change, since only
    /// one script ever encodes it) client causing the collision is what
    /// gets flagged instead.
    pub pinned_tunnel_ids: HashSet<String>,
    /// Public keys of the peers that should get an EoIP tunnel. Opt-in:
    /// a peer not listed here gets only its plain WireGuard link, so an
    /// empty set (the default) generates no EoIP at all.
    pub eoip_peers: HashSet<String>,
    pub interface_name: Option<String>,
}

pub fn host_to_routeros_script(host: &WireGuardHost, opts: &RouterOsOptions) -> String {
    let iface = routeros_interface_name(opts.interface_name.as_deref().unwrap_or(&host.name), "wg0");
    let mut lines: Vec<String> = vec![
        format!("# RouterOS WireGuard setup for '{}'", host.name),
        "# Generated by WireGuard Config Studio -- review before applying,".to_string(),
        "# especially the firewall and route sections, since every network differs.".to_string(),
        String::new(),
        "/interface/wireguard".to_string(),
    ];

    let mut iface_cmd = vec![
        format!("add name={}", routeros_str(&iface)),
        format!("private-key={}", routeros_str(&host.private_key)),
    ];
    if let Some(p) = host.listen_port {
        iface_cmd.push(format!("listen-port={p}"));
    }
    if let Some(m) = host.mtu {
        iface_cmd.push(format!("mtu={m}"));
    }
    lines.push(iface_cmd.join(" "));
    lines.push(String::new());

    if !host.address.is_empty() {
        lines.push("/ip/address".to_string());
        for addr in &host.address {
            lines.push(format!(
                "add address={} interface={}",
                routeros_str(addr),
                routeros_str(&iface)
            ));
        }
        lines.push(String::new());
    }

    if !host.peers.is_empty() {
        lines.push("/interface/wireguard/peers".to_string());
        for peer in &host.peers {
            let mut cmd = vec![
                format!("add interface={}", routeros_str(&iface)),
                format!("public-key={}", routeros_str(&peer.public_key)),
            ];
            if !peer.allowed_ips.is_empty() {
                cmd.push(format!("allowed-address={}", peer.allowed_ips.join(",")));
            }
            if let Some(ep) = &peer.endpoint {
                if let Some((ep_host, ep_port)) = ep.rsplit_once(':') {
                    if !ep_host.is_empty() {
                        cmd.push(format!("endpoint-address={}", routeros_str(ep_host)));
                        if ep_port.chars().all(|c| c.is_ascii_digit()) && !ep_port.is_empty() {
                            cmd.push(format!("endpoint-port={ep_port}"));
                        }
                    }
                } else if !ep.is_empty() {
                    cmd.push(format!("endpoint-address={}", routeros_str(ep)));
                }
            }
            if let Some(ka) = peer.persistent_keepalive {
                cmd.push(format!("persistent-keepalive={ka}s"));
            }
            if let Some(psk) = &peer.preshared_key {
                cmd.push(format!("preshared-key={}", routeros_str(psk)));
            }
            if let Some(c) = &peer.comment {
                cmd.push(format!("comment={}", routeros_str(c)));
            }
            lines.push(cmd.join(" "));
        }
        lines.push(String::new());
    }

    let mut any_real_eoip = false;
    if !host.peers.is_empty() {
        let local_ip = bare_ip_address(&host.address);

        let mut eoip_lines: Vec<String> = Vec::new();
        let mut used_tunnel_ids: HashSet<u32> = HashSet::new();

        for peer in &host.peers {
            if !opts.eoip_peers.contains(&peer.public_key) {
                continue;
            }
            let label = peer
                .comment
                .clone()
                .unwrap_or_else(|| peer.public_key.chars().take(8).collect());

            let remote_ip = opts
                .peer_remote_addresses
                .get(&peer.public_key)
                .cloned()
                .or_else(|| single_ip_address(&peer.allowed_ips));

            let remote_ip = match remote_ip {
                Some(ip) => ip,
                None => {
                    eoip_lines.push(format!(
                        "# Skipped EoIP to {label}: no known address for it (its AllowedIPs is a \
                         range, e.g. a full-tunnel 0.0.0.0/0, not one address)."
                    ));
                    continue;
                }
            };
            let local_ip = match &local_ip {
                Some(ip) => ip.clone(),
                None => {
                    eoip_lines.push(format!(
                        "# Skipped EoIP to {label}: this host has no address of its own."
                    ));
                    continue;
                }
            };
            any_real_eoip = true;

            let mut tunnel_id = opts
                .peer_tunnel_ids
                .get(&peer.public_key)
                .copied()
                .unwrap_or_else(|| eoip_tunnel_id(&host.public_key, &peer.public_key));
            let original_id = tunnel_id;
            if opts.pinned_tunnel_ids.contains(&peer.public_key) {
                if used_tunnel_ids.contains(&tunnel_id) {
                    eoip_lines.push(format!(
                        "# WARNING: tunnel-id {tunnel_id} for {label} collides with another peer \
                         already assigned on this host. It's pinned (the other end of a mesh link \
                         between hosts, which must use this exact id on both sides) so it was NOT \
                         auto-adjusted -- give the *other* colliding peer a different tunnel-id \
                         instead, or this EoIP tunnel won't come up correctly."
                    ));
                }
            } else {
                let mut attempts = 0;
                while used_tunnel_ids.contains(&tunnel_id) && attempts < 70000 {
                    tunnel_id = if tunnel_id < 65535 { tunnel_id + 1 } else { 1 };
                    attempts += 1;
                }
                if tunnel_id != original_id {
                    eoip_lines.push(format!(
                        "# NOTE: tunnel-id {original_id} for {label} was already used by another client \
                         on this host; auto-adjusted to {tunnel_id} to avoid a conflict. If {original_id} \
                         was meant to be fixed, update the other router to match {tunnel_id} instead."
                    ));
                }
            }
            used_tunnel_ids.insert(tunnel_id);

            let eoip_name = format!(
                "eoip-{}",
                routeros_interface_name(peer.comment.as_deref().unwrap_or("peer"), "peer")
            );
            let cmd = vec![
                format!("add name={}", routeros_str(&eoip_name)),
                format!("remote-address={}", routeros_str(&remote_ip)),
                format!("local-address={}", routeros_str(&local_ip)),
                format!("tunnel-id={tunnel_id}"),
                format!("comment={}", routeros_str(&format!("EoIP to {label}, over WireGuard"))),
            ];
            eoip_lines.push(cmd.join(" "));
        }

        if any_real_eoip {
            lines.push("/interface/eoip".to_string());
            lines.extend(eoip_lines);
            lines.push(
                "# Each eoip-* interface carries raw Ethernet over the WireGuard tunnel. Add it to a"
                    .to_string(),
            );
            lines.push(
                "# bridge (e.g. /interface/bridge/port add bridge=your-bridge interface=eoip-...) to"
                    .to_string(),
            );
            lines.push("# extend a LAN across the link, or leave it unbridged for a routed L2 hop.".to_string());
            lines.push(String::new());
        } else if !eoip_lines.is_empty() {
            lines.push(
                "# No EoIP tunnels generated: none of this host's peers have a single-address \
                 AllowedIPs to target."
                    .to_string(),
            );
            lines.push(String::new());
        }
    }

    lines.push("/ip/firewall/filter".to_string());
    if let Some(p) = host.listen_port {
        lines.push(format!(
            "add chain=input protocol=udp dst-port={p} action=accept comment={}",
            routeros_str(&format!("Allow WireGuard ({iface})"))
        ));
    }
    if any_real_eoip {
        lines.push(format!(
            "add chain=input protocol=gre action=accept comment={}",
            routeros_str("Allow EoIP (GRE)")
        ));
    }
    lines.push(format!(
        "add chain=forward in-interface={} action=accept comment={}",
        routeros_str(&iface),
        routeros_str(&format!("Allow {iface} forward in"))
    ));
    lines.push(format!(
        "add chain=forward out-interface={} action=accept comment={}",
        routeros_str(&iface),
        routeros_str(&format!("Allow {iface} forward out"))
    ));
    lines.push(String::new());

    let mut route_targets: Vec<String> = Vec::new();
    for peer in &host.peers {
        for allowed in &peer.allowed_ips {
            if !route_targets.contains(allowed) {
                route_targets.push(allowed.clone());
            }
        }
    }
    if !route_targets.is_empty() {
        lines.push("/ip/route".to_string());
        for target in &route_targets {
            if target == "0.0.0.0/0" || target == "::/0" {
                lines.push(format!(
                    "# NOTE: {target} becomes your default route via {iface} -- adjust distance= \
                     below if you already have one"
                ));
            }
            lines.push(format!(
                "add dst-address={} gateway={} comment={}",
                routeros_str(target),
                routeros_str(&iface),
                routeros_str(&format!("via {iface}"))
            ));
        }
        lines.push(String::new());
    }

    lines.push(format!(
        "/interface/wireguard/print where name={}",
        routeros_str(&iface)
    ));
    lines.push(format!(
        "# Verify peers with: /interface/wireguard/peers/print where interface={}",
        routeros_str(&iface)
    ));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostOptions;
    use crate::peer::Peer;

    /// Find the `tunnel-id=` on the one EoIP `add` line whose `comment=`
    /// contains `label` -- a script can have several EoIP lines (one per
    /// peer), so grabbing just the first `add name=...` risks silently
    /// reading a different peer's id than the one under test.
    fn extract_tunnel_id(script: &str, label: &str) -> u32 {
        script
            .lines()
            .find(|l| l.starts_with("add name=") && l.contains("remote-address=") && l.contains(label))
            .unwrap_or_else(|| panic!("no EoIP add line mentioning {label:?} in:\n{script}"))
            .split("tunnel-id=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .expect("matched line should contain a tunnel-id")
            .parse()
            .unwrap()
    }

    /// A mesh link's EoIP id must come out identical from both hosts'
    /// independently-generated scripts, even when one host's *other*
    /// peers happen to already occupy that exact id -- that's exactly the
    /// scenario `pinned_tunnel_ids` exists to protect against (see its doc
    /// comment): without it, only the colliding side gets silently
    /// bumped, and the two scripts end up disagreeing on the id.
    #[test]
    fn mesh_eoip_tunnel_id_agrees_on_both_sides_despite_a_local_collision() {
        let host_a = WireGuardHost::new("host-a", HostOptions { address: vec!["172.16.1.1/24".into()], ..Default::default() }).unwrap();
        let host_b = WireGuardHost::new("host-b", HostOptions { address: vec!["172.16.2.1/24".into()], ..Default::default() }).unwrap();
        let base_id = eoip_tunnel_id(&host_a.public_key, &host_b.public_key);

        // Host A's script: an ordinary client peer deliberately pinned (via
        // peer_tunnel_ids, exactly as a user-set Tunnel ID field would be)
        // to the same id the mesh link would also land on, plus the mesh
        // peer for host B itself.
        let mut a = host_a.clone();
        let colliding_client_pubkey = WireGuardHost::simple("some-client").unwrap().public_key;
        a.add_peer(Peer::build(colliding_client_pubkey.clone(), vec!["172.16.1.5/32".into()], None, None, None, Some("some-client".into())).unwrap());
        a.add_peer(Peer::build(host_b.public_key.clone(), host_b.address.clone(), None, Some(25), None, Some("Mesh — host-b".into())).unwrap());

        let mut opts_a = RouterOsOptions::default();
        opts_a.peer_tunnel_ids.insert(colliding_client_pubkey.clone(), base_id);
        opts_a.peer_remote_addresses.insert(host_b.public_key.clone(), "172.16.2.1".into());
        opts_a.pinned_tunnel_ids.insert(host_b.public_key.clone());
        opts_a.eoip_peers.extend([host_b.public_key.clone(), colliding_client_pubkey.clone()]);
        let script_a = host_to_routeros_script(&a, &opts_a);

        // Host B's script: nothing else competing for the id, just the
        // mesh peer for host A.
        let mut b = host_b.clone();
        b.add_peer(Peer::build(host_a.public_key.clone(), host_a.address.clone(), None, Some(25), None, Some("Mesh — host-a".into())).unwrap());

        let mut opts_b = RouterOsOptions::default();
        opts_b.peer_remote_addresses.insert(host_a.public_key.clone(), "172.16.1.1".into());
        opts_b.pinned_tunnel_ids.insert(host_a.public_key.clone());
        opts_b.eoip_peers.insert(host_a.public_key.clone());
        let script_b = host_to_routeros_script(&b, &opts_b);

        assert_eq!(extract_tunnel_id(&script_a, "Mesh"), base_id, "pinned mesh id must not be bumped by the colliding client");
        assert_eq!(extract_tunnel_id(&script_b, "Mesh"), base_id);
        assert!(script_a.contains("WARNING: tunnel-id"), "the collision should still be flagged instead of silently resolved");
    }

    #[test]
    fn no_eoip_unless_peer_is_opted_in() {
        let mut host = WireGuardHost::new("h", HostOptions { address: vec!["172.16.1.1/24".into()], ..Default::default() }).unwrap();
        let pk = WireGuardHost::simple("c").unwrap().public_key;
        host.add_peer(Peer::build(pk.clone(), vec!["172.16.1.5/32".into()], None, None, None, Some("c".into())).unwrap());

        let off = host_to_routeros_script(&host, &RouterOsOptions::default());
        assert!(!off.contains("/interface/eoip") && !off.contains("protocol=gre"));

        let mut opts = RouterOsOptions::default();
        opts.eoip_peers.insert(pk);
        assert!(host_to_routeros_script(&host, &opts).contains("/interface/eoip"));
    }
}
