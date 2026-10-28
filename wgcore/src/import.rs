//! Read WireGuard interfaces back *from* a router: parse what OpenWrt's
//! `uci show network` or a RouterOS field dump printed into
//! [`ImportedInterface`]s, so an interface that already exists on a device
//! can be loaded, edited and applied back.
//!
//! Parsing only -- running the commands over SSH is the caller's job. The
//! RouterOS side has no stable machine-readable print format, so
//! [`ROUTEROS_DUMP_COMMANDS`] makes the router print one `key=value` line
//! per field instead, which is what [`parse_routeros_dump`] expects.

use std::collections::HashMap;

/// One WireGuard interface as found on a device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportedInterface {
    /// The interface's name on the device (UCI section / RouterOS name).
    pub name: String,
    pub private_key: String,
    pub address: Vec<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u32>,
    pub peers: Vec<ImportedPeer>,
}

/// One peer of an [`ImportedInterface`]. Only its public half is known --
/// the peer's own private key never leaves the peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportedPeer {
    pub name: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u32>,
    pub preshared_key: Option<String>,
    /// Whether the device itself routes this peer's AllowedIPs through the
    /// tunnel: OpenWrt's `route_allowed_ips`. Always `false` for RouterOS,
    /// which never derives routes from a peer -- they live separately in
    /// `/ip/route` and aren't imported.
    pub route_allowed_ips: bool,
}

fn endpoint_from(host: &str, port: &str) -> Option<String> {
    let host = host.trim();
    let port = port.trim();
    if host.is_empty() {
        return None;
    }
    if port.is_empty() || port == "0" {
        return Some(host.to_string());
    }
    if host.contains(':') && !host.starts_with('[') {
        return Some(format!("[{host}]:{port}"));
    }
    Some(format!("{host}:{port}"))
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

// -- OpenWrt -----------------------------------------------------------------

/// Split the value side of a `uci show` line into its items: one for a
/// plain option, several for a list (`'a' 'b'`). Handles the `'\''` escape
/// uci uses for a literal quote.
fn parse_uci_values(raw: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = raw.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut current = String::new();
        if c == '\'' {
            chars.next();
            loop {
                match chars.next() {
                    None => break,
                    Some('\'') => {
                        // '\'' = close quote, escaped quote, reopen quote.
                        let mut ahead = chars.clone();
                        if ahead.next() == Some('\\') && ahead.next() == Some('\'') && ahead.next() == Some('\'') {
                            current.push('\'');
                            chars = ahead;
                        } else {
                            break;
                        }
                    }
                    Some(ch) => current.push(ch),
                }
            }
        } else {
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() {
                    break;
                }
                current.push(ch);
                chars.next();
            }
        }
        values.push(current);
    }
    values
}

#[derive(Default)]
struct UciSection {
    name: String,
    kind: String,
    options: HashMap<String, Vec<String>>,
}

impl UciSection {
    fn first(&self, option: &str) -> &str {
        self.options.get(option).and_then(|v| v.first()).map(String::as_str).unwrap_or("")
    }

    fn list(&self, option: &str) -> Vec<String> {
        // A list written as one space-separated option (older configs) is
        // equivalent to a real UCI list, so accept both.
        self.options
            .get(option)
            .map(|values| values.iter().flat_map(|v| v.split_whitespace()).map(str::to_string).collect())
            .unwrap_or_default()
    }
}

/// Parse the output of `uci show network` into every `proto='wireguard'`
/// interface it describes, each with its `wireguard_<name>` peer sections.
pub fn parse_openwrt_network(uci_show_output: &str) -> Vec<ImportedInterface> {
    let mut sections: Vec<UciSection> = Vec::new();
    for line in uci_show_output.lines() {
        let Some((key, value)) = line.trim().split_once('=') else { continue };
        let mut parts = key.splitn(3, '.');
        let (Some(config), Some(section)) = (parts.next(), parts.next()) else { continue };
        if config != "network" {
            continue;
        }
        match parts.next() {
            None => sections.push(UciSection {
                name: section.to_string(),
                kind: parse_uci_values(value).into_iter().next().unwrap_or_default(),
                options: HashMap::new(),
            }),
            Some(option) => {
                if let Some(s) = sections.iter_mut().rev().find(|s| s.name == section) {
                    s.options.insert(option.to_string(), parse_uci_values(value));
                }
            }
        }
    }

    sections
        .iter()
        .filter(|s| s.kind == "interface" && s.first("proto") == "wireguard")
        .map(|iface| {
            let peer_kind = format!("wireguard_{}", iface.name);
            let peers = sections
                .iter()
                .filter(|s| s.kind == peer_kind)
                .enumerate()
                .map(|(i, p)| ImportedPeer {
                    name: non_empty(p.first("description")).unwrap_or_else(|| format!("peer{}", i + 1)),
                    public_key: p.first("public_key").trim().to_string(),
                    allowed_ips: p.list("allowed_ips"),
                    endpoint: endpoint_from(p.first("endpoint_host"), p.first("endpoint_port")),
                    persistent_keepalive: p.first("persistent_keepalive").trim().parse().ok().filter(|ka| *ka > 0),
                    preshared_key: non_empty(p.first("preshared_key")),
                    route_allowed_ips: p.first("route_allowed_ips") == "1",
                })
                .collect();
            ImportedInterface {
                name: iface.name.clone(),
                private_key: iface.first("private_key").trim().to_string(),
                address: iface.list("addresses"),
                listen_port: iface.first("listen_port").trim().parse().ok(),
                mtu: iface.first("mtu").trim().parse().ok(),
                peers,
            }
        })
        .collect()
}

// -- RouterOS ----------------------------------------------------------------

/// RouterOS console commands that print every WireGuard interface, peer and
/// interface address as `key=value` lines, one record per `@IF` / `@PEER` /
/// `@ADDR` / `@PEERNAME` marker line. Run each one separately and feed the
/// concatenated output to [`parse_routeros_dump`]: the later ones are
/// allowed to fail (no IPv6 package; no peer `name` property before
/// RouterOS 7.15) without taking the rest down with them.
///
/// `get` is used rather than `print` because it returns the real private
/// and pre-shared keys whatever the console's hide-sensitive setting is.
pub const ROUTEROS_DUMP_COMMANDS: &[&str] = &[
    ":foreach i in=[/interface/wireguard/find] do={ :put \"@IF\"; \
     :put (\"name=\" . [/interface/wireguard/get $i name]); \
     :put (\"private-key=\" . [/interface/wireguard/get $i private-key]); \
     :put (\"listen-port=\" . [/interface/wireguard/get $i listen-port]); \
     :put (\"mtu=\" . [/interface/wireguard/get $i mtu]) }",
    ":foreach i in=[/interface/wireguard/peers/find] do={ :put \"@PEER\"; \
     :put (\"interface=\" . [/interface/wireguard/peers/get $i interface]); \
     :put (\"public-key=\" . [/interface/wireguard/peers/get $i public-key]); \
     :put (\"allowed-address=\" . [:tostr [/interface/wireguard/peers/get $i allowed-address]]); \
     :put (\"endpoint-address=\" . [/interface/wireguard/peers/get $i endpoint-address]); \
     :put (\"endpoint-port=\" . [/interface/wireguard/peers/get $i endpoint-port]); \
     :put (\"persistent-keepalive=\" . [/interface/wireguard/peers/get $i persistent-keepalive]); \
     :put (\"preshared-key=\" . [/interface/wireguard/peers/get $i preshared-key]); \
     :put (\"comment=\" . [/interface/wireguard/peers/get $i comment]) }",
    ":foreach i in=[/ip/address/find] do={ :put \"@ADDR\"; \
     :put (\"interface=\" . [/ip/address/get $i interface]); \
     :put (\"address=\" . [/ip/address/get $i address]) }",
    ":foreach i in=[/ipv6/address/find where !dynamic] do={ :put \"@ADDR\"; \
     :put (\"interface=\" . [/ipv6/address/get $i interface]); \
     :put (\"address=\" . [/ipv6/address/get $i address]) }",
    ":foreach i in=[/interface/wireguard/peers/find] do={ :put \"@PEERNAME\"; \
     :put (\"public-key=\" . [/interface/wireguard/peers/get $i public-key]); \
     :put (\"name=\" . [/interface/wireguard/peers/get $i name]) }",
];

/// RouterOS prints a time value either as `00:00:25` or as `25s` / `1m30s`.
fn parse_routeros_seconds(text: &str) -> Option<u32> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if text.contains(':') {
        let mut total = 0u32;
        for part in text.split(':') {
            total = total.checked_mul(60)?.checked_add(part.trim().parse().ok()?)?;
        }
        return Some(total);
    }
    let mut total = 0u32;
    let mut number = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            number.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            'w' => 604800,
            _ => return None,
        };
        total = total.checked_add(number.parse::<u32>().ok()?.checked_mul(unit)?)?;
        number.clear();
    }
    if !number.is_empty() {
        total = total.checked_add(number.parse().ok()?)?;
    }
    Some(total)
}

/// Parse the combined output of [`ROUTEROS_DUMP_COMMANDS`].
pub fn parse_routeros_dump(output: &str) -> Vec<ImportedInterface> {
    let mut records: Vec<(String, HashMap<String, String>)> = Vec::new();
    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(marker) = line.trim().strip_prefix('@') {
            records.push((marker.to_string(), HashMap::new()));
        } else if let (Some((key, value)), Some((_, fields))) = (line.split_once('='), records.last_mut()) {
            fields.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    let field = |fields: &HashMap<String, String>, key: &str| fields.get(key).cloned().unwrap_or_default();

    let mut peer_names: HashMap<String, String> = HashMap::new();
    for (kind, fields) in &records {
        if kind == "PEERNAME" {
            peer_names.insert(field(fields, "public-key"), field(fields, "name"));
        }
    }

    let mut interfaces: Vec<ImportedInterface> = records
        .iter()
        .filter(|(kind, fields)| kind == "IF" && !field(fields, "name").is_empty())
        .map(|(_, fields)| ImportedInterface {
            name: field(fields, "name"),
            private_key: field(fields, "private-key"),
            address: Vec::new(),
            listen_port: field(fields, "listen-port").parse().ok().filter(|p| *p != 0),
            mtu: field(fields, "mtu").parse().ok(),
            peers: Vec::new(),
        })
        .collect();

    for (kind, fields) in &records {
        let Some(iface) = interfaces.iter_mut().find(|i| i.name == field(fields, "interface")) else { continue };
        match kind.as_str() {
            "ADDR" => {
                if let Some(addr) = non_empty(&field(fields, "address")) {
                    iface.address.push(addr);
                }
            }
            "PEER" => {
                let public_key = field(fields, "public-key");
                let name = non_empty(&field(fields, "comment"))
                    .or_else(|| peer_names.get(&public_key).and_then(|n| non_empty(n)))
                    .unwrap_or_else(|| format!("peer{}", iface.peers.len() + 1));
                iface.peers.push(ImportedPeer {
                    name,
                    allowed_ips: field(fields, "allowed-address")
                        .split([';', ','])
                        .filter_map(non_empty)
                        .collect(),
                    endpoint: endpoint_from(&field(fields, "endpoint-address"), &field(fields, "endpoint-port")),
                    persistent_keepalive: parse_routeros_seconds(&field(fields, "persistent-keepalive")).filter(|ka| *ka > 0),
                    preshared_key: non_empty(&field(fields, "preshared-key")),
                    route_allowed_ips: false,
                    public_key,
                });
            }
            _ => {}
        }
    }
    interfaces
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openwrt_finds_every_wireguard_interface_with_its_own_peers() {
        let output = "\
network.loopback=interface
network.loopback.proto='static'
network.wg0=interface
network.wg0.proto='wireguard'
network.wg0.private_key='PRIV0='
network.wg0.listen_port='51820'
network.wg0.addresses='10.0.0.1/24' 'fd00::1/64'
network.@wireguard_wg0[0]=wireguard_wg0
network.@wireguard_wg0[0].description='Vasya'\\''s phone'
network.@wireguard_wg0[0].public_key='PUB1='
network.@wireguard_wg0[0].allowed_ips='10.0.0.2/32'
network.@wireguard_wg0[0].route_allowed_ips='1'
network.@wireguard_wg0[0].persistent_keepalive='25'
network.wg0_office=wireguard_wg0
network.wg0_office.public_key='PUB2='
network.wg0_office.preshared_key='PSK2='
network.wg0_office.allowed_ips='10.0.0.3/32' '192.168.5.0/24'
network.wg0_office.endpoint_host='vpn.example.com'
network.wg0_office.endpoint_port='51821'
network.wg1=interface
network.wg1.proto='wireguard'
network.wg1.private_key='PRIV1='
network.wg1.mtu='1380'
network.@wireguard_wg1[0]=wireguard_wg1
network.@wireguard_wg1[0].public_key='PUB3='
";
        let found = parse_openwrt_network(output);
        assert_eq!(found.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["wg0", "wg1"]);

        let wg0 = &found[0];
        assert_eq!(wg0.private_key, "PRIV0=");
        assert_eq!(wg0.listen_port, Some(51820));
        assert_eq!(wg0.address, ["10.0.0.1/24", "fd00::1/64"]);
        assert_eq!(wg0.peers.len(), 2);
        assert_eq!(wg0.peers[0].name, "Vasya's phone");
        assert_eq!(wg0.peers[0].persistent_keepalive, Some(25));
        assert!(wg0.peers[0].route_allowed_ips);
        assert_eq!(wg0.peers[1].name, "peer2");
        assert_eq!(wg0.peers[1].allowed_ips, ["10.0.0.3/32", "192.168.5.0/24"]);
        assert_eq!(wg0.peers[1].endpoint.as_deref(), Some("vpn.example.com:51821"));
        assert_eq!(wg0.peers[1].preshared_key.as_deref(), Some("PSK2="));
        assert!(!wg0.peers[1].route_allowed_ips);

        assert_eq!(found[1].mtu, Some(1380));
        assert_eq!(found[1].listen_port, None);
        assert_eq!(found[1].peers.len(), 1);
        assert_eq!(found[1].peers[0].public_key, "PUB3=");
    }

    #[test]
    fn routeros_dump_groups_peers_and_addresses_by_interface() {
        let output = "\
@IF\r
name=wg-office\r
private-key=PRIV0=\r
listen-port=13231\r
mtu=1420\r
@IF
name=wg2
private-key=PRIV1=
listen-port=0
mtu=1400
@PEER
interface=wg-office
public-key=PUB1=
allowed-address=10.0.0.2/32;192.168.5.0/24
endpoint-address=203.0.113.9
endpoint-port=51820
persistent-keepalive=00:00:25
preshared-key=PSK1=
comment=branch
@PEER
interface=wg2
public-key=PUB2=
allowed-address=0.0.0.0/0
endpoint-address=
endpoint-port=0
persistent-keepalive=
preshared-key=
comment=
@ADDR
interface=wg-office
address=10.0.0.1/24
@ADDR
interface=ether1
address=192.168.88.1/24
@PEERNAME
public-key=PUB2=
name=laptop
";
        let found = parse_routeros_dump(output);
        assert_eq!(found.len(), 2);

        let office = &found[0];
        assert_eq!(office.name, "wg-office");
        assert_eq!(office.private_key, "PRIV0=");
        assert_eq!(office.listen_port, Some(13231));
        assert_eq!(office.address, ["10.0.0.1/24"]);
        assert_eq!(office.peers.len(), 1);
        assert_eq!(office.peers[0].name, "branch");
        assert_eq!(office.peers[0].allowed_ips, ["10.0.0.2/32", "192.168.5.0/24"]);
        assert_eq!(office.peers[0].endpoint.as_deref(), Some("203.0.113.9:51820"));
        assert_eq!(office.peers[0].persistent_keepalive, Some(25));
        assert_eq!(office.peers[0].preshared_key.as_deref(), Some("PSK1="));

        let wg2 = &found[1];
        assert_eq!(wg2.listen_port, None);
        assert!(wg2.address.is_empty());
        assert_eq!(wg2.peers[0].name, "laptop", "falls back to the peer's own name when it has no comment");
        assert_eq!(wg2.peers[0].endpoint, None);
        assert_eq!(wg2.peers[0].persistent_keepalive, None);
        assert_eq!(wg2.peers[0].preshared_key, None);
    }

    #[test]
    fn routeros_time_values_parse_in_both_printed_forms() {
        assert_eq!(parse_routeros_seconds("00:00:25"), Some(25));
        assert_eq!(parse_routeros_seconds("00:01:30"), Some(90));
        assert_eq!(parse_routeros_seconds("25s"), Some(25));
        assert_eq!(parse_routeros_seconds("1m30s"), Some(90));
        assert_eq!(parse_routeros_seconds(""), None);
        assert_eq!(parse_routeros_seconds("soon"), None);
    }
}
