//! wgcore
//!
//! A small library for building WireGuard tunnel configurations
//! programmatically, instead of hand-writing `.conf` files.
//!
//! Rust port of `wireguard_manager.py`. See that file's module docstring
//! for the original design notes; the same ideas apply here:
//!
//! - [`WireGuardHost`] represents one WireGuard interface (an office
//!   router, a client laptop, whatever). It holds every field that can
//!   appear in an `[Interface]` section, plus its own keypair.
//! - Private keys can be supplied manually or generated automatically
//!   (X25519, via `x25519-dalek`).
//! - [`Peer`] represents one `[Peer]` entry. Hosts can be linked together
//!   with [`WireGuardHost::add_peer_host`], which pulls the public key
//!   from the other host automatically.
//! - [`WireGuardNetwork`] is an optional convenience layer for managing
//!   many hosts at once and writing all of their `.conf` files out in one
//!   go.

mod dict;
mod error;
mod host;
mod keys;
mod network;
mod parse;
mod peer;
mod pool;
mod routeros;

pub use dict::{host_from_dict, host_to_dict, HostDict};
pub use error::{Result, WgError};
pub use host::{set_owner_only_permissions, HostOptions, WireGuardHost};
pub use keys::{generate_preshared_key, generate_private_key, public_key_from_private, validate_key};
pub use network::WireGuardNetwork;
pub use parse::load_host_from_config;
pub use peer::Peer;
pub use pool::IpAddressPool;
pub use routeros::{bare_ip_address, host_to_routeros_script, single_ip_address, RouterOsOptions};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_derive_keypair() {
        let priv_key = generate_private_key();
        let pub_key = public_key_from_private(&priv_key).unwrap();
        assert_eq!(pub_key.len(), 44); // 32 bytes base64-encoded
    }

    #[test]
    fn host_roundtrips_through_conf_text() {
        let mut host = WireGuardHost::new(
            "office-hq",
            HostOptions {
                address: vec!["10.10.0.1/24".into()],
                listen_port: Some(51820),
                ..Default::default()
            },
        )
        .unwrap();
        let other = WireGuardHost::simple("client-alice").unwrap();
        host.add_peer_host(&other, vec!["10.10.0.2/32".into()], None, None, None).unwrap();

        let text = host.full_config();
        let parsed = load_host_from_config(&text, "office-hq").unwrap();
        assert_eq!(parsed.private_key, host.private_key);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].public_key, other.public_key);
    }

    #[test]
    fn pool_allocates_and_skips_reserved() {
        let mut pool = IpAddressPool::new("10.10.0.0/24", None, &["10.10.0.1".to_string()]).unwrap();
        let first = pool.allocate().unwrap();
        assert_ne!(first, "10.10.0.1/32");
        assert!(first.starts_with("10.10.0."));
    }

    #[test]
    fn dict_roundtrip() {
        let host = WireGuardHost::new(
            "branch",
            HostOptions {
                address: vec!["10.10.1.1/24".into()],
                mtu: Some(1420),
                ..Default::default()
            },
        )
        .unwrap();
        let d = host_to_dict(&host);
        let json = serde_json::to_string(&d).unwrap();
        let d2: HostDict = serde_json::from_str(&json).unwrap();
        let host2 = host_from_dict(&d2).unwrap();
        assert_eq!(host2.private_key, host.private_key);
        assert_eq!(host2.mtu, Some(1420));
    }
}
