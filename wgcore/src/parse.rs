use crate::error::{Result, WgError};
use crate::host::{HostOptions, WireGuardHost};
use crate::peer::Peer;

/// Parse "Key = Value" lines within a section, ignoring blanks/comments.
fn parse_kv_lines(lines: &[String]) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for raw_line in lines {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            pairs.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    pairs
}

/// Parse the text of a standard wg-quick `.conf` file (one `[Interface]`
/// section plus zero or more `[Peer]` sections) back into a
/// `WireGuardHost`, including its peers. Returns `Err` if the file has no
/// `PrivateKey` (which happens if it's been redacted for sharing).
pub fn load_host_from_config(text: &str, name: &str) -> Result<WireGuardHost> {
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let mut header: Option<String> = None;
    let mut body: Vec<String> = Vec::new();

    for raw_line in text.lines() {
        let stripped = raw_line.trim();
        if stripped.starts_with('[') && stripped.ends_with(']') {
            if let Some(h) = header.take() {
                sections.push((h, std::mem::take(&mut body)));
            }
            header = Some(stripped[1..stripped.len() - 1].trim().to_lowercase());
        } else {
            body.push(raw_line.to_string());
        }
    }
    if let Some(h) = header.take() {
        sections.push((h, body));
    }

    let mut opts = HostOptions::default();
    let mut private_key: Option<String> = None;
    let mut peers: Vec<Peer> = Vec::new();

    for (section_header, section_lines) in &sections {
        let pairs = parse_kv_lines(section_lines);

        if section_header == "interface" {
            for (key, value) in &pairs {
                match key.to_lowercase().as_str() {
                    "privatekey" => private_key = Some(value.clone()),
                    "address" => opts
                        .address
                        .extend(value.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from)),
                    "listenport" => {
                        opts.listen_port = Some(value.parse().map_err(|_| {
                            WgError::Parse(format!("ListenPort is not a valid number: {value:?}"))
                        })?)
                    }
                    "dns" => opts
                        .dns
                        .extend(value.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from)),
                    "mtu" => {
                        opts.mtu = Some(
                            value
                                .parse()
                                .map_err(|_| WgError::Parse(format!("MTU is not a valid number: {value:?}")))?,
                        )
                    }
                    "table" => opts.table = Some(value.clone()),
                    "preup" => opts.pre_up.push(value.clone()),
                    "postup" => opts.post_up.push(value.clone()),
                    "predown" => opts.pre_down.push(value.clone()),
                    "postdown" => opts.post_down.push(value.clone()),
                    "saveconfig" => opts.save_config = Some(value.eq_ignore_ascii_case("true")),
                    "fwmark" => opts.fw_mark = Some(value.clone()),
                    _ => {}
                }
            }
        } else if section_header == "peer" {
            let mut public_key: Option<String> = None;
            let mut preshared_key: Option<String> = None;
            let mut allowed_ips: Vec<String> = Vec::new();
            let mut endpoint: Option<String> = None;
            let mut persistent_keepalive: Option<u32> = None;

            for (key, value) in &pairs {
                match key.to_lowercase().as_str() {
                    "publickey" => public_key = Some(value.clone()),
                    "presharedkey" => preshared_key = Some(value.clone()),
                    "allowedips" => {
                        allowed_ips = value.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
                    }
                    "endpoint" => endpoint = Some(value.clone()),
                    "persistentkeepalive" => {
                        persistent_keepalive = Some(value.parse().map_err(|_| {
                            WgError::Parse(format!("PersistentKeepalive is not a valid number: {value:?}"))
                        })?)
                    }
                    _ => {}
                }
            }

            if let Some(pk) = public_key {
                peers.push(Peer::build(
                    pk,
                    allowed_ips,
                    endpoint,
                    persistent_keepalive,
                    preshared_key,
                    None,
                )?);
            }
        }
    }

    let private_key = private_key.ok_or_else(|| {
        WgError::InvalidKey(
            "No [Interface] PrivateKey found in this file -- it may have been redacted before \
             sharing. A host can't be reconstructed without its private key."
                .to_string(),
        )
    })?;

    opts.private_key = Some(private_key);
    let mut host = WireGuardHost::new(name, opts)?;
    for peer in peers {
        host.add_peer(peer);
    }
    Ok(host)
}
