//! Key handling.
//!
//! The Python original generated keys via the `cryptography` package with
//! a fallback to shelling out to the `wg` CLI binary if that package
//! wasn't installed. In Rust we depend on `x25519-dalek` unconditionally
//! (it's a small, pure-Rust, dependency-light crate, in keeping with this
//! project's "stay dependency-light" philosophy), so there's no runtime
//! fallback to a CLI tool to worry about -- the native implementation is
//! always available.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Result, WgError};

/// Generate a new WireGuard private key, base64-encoded.
pub fn generate_private_key() -> String {
    let secret = StaticSecret::random_from_rng(OsRng);
    STANDARD.encode(secret.to_bytes())
}

/// Derive the matching public key for a given base64 private key.
pub fn public_key_from_private(private_key_b64: &str) -> Result<String> {
    let raw = STANDARD
        .decode(private_key_b64.trim())
        .map_err(|e| WgError::InvalidKey(format!("Invalid private key: {e}")))?;
    let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        WgError::InvalidKey(format!(
            "Invalid private key: expected 32 bytes, got {}",
            raw.len()
        ))
    })?;
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(STANDARD.encode(public.as_bytes()))
}

/// Generate an optional per-peer pre-shared symmetric key.
pub fn generate_preshared_key() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    STANDARD.encode(buf)
}

/// WireGuard keys are 32 raw bytes, base64-encoded -> 44 chars, '=' padded.
pub fn validate_key(value: &str, field_name: &str) -> Result<String> {
    let raw = STANDARD
        .decode(value)
        .map_err(|e| WgError::InvalidKey(format!("{field_name} is not valid base64: {e}")))?;
    if raw.len() != 32 {
        return Err(WgError::InvalidKey(format!(
            "{field_name} must decode to 32 bytes, got {}",
            raw.len()
        )));
    }
    Ok(value.to_string())
}

/// Validate a list of CIDR/IP strings, accepting either a bare address
/// (implicit /32 or /128, mirroring Python's `ipaddress.ip_network`) or an
/// explicit `addr/prefix` form.
pub fn validate_cidr_list(values: &[String], field_name: &str) -> Result<Vec<String>> {
    for v in values {
        parse_ip_or_network(v)
            .map_err(|e| WgError::InvalidCidr(format!("Invalid entry in {field_name} ({v:?}): {e}")))?;
    }
    Ok(values.to_vec())
}

/// Parse either a bare IP address or a full CIDR network string.
pub fn parse_ip_or_network(v: &str) -> std::result::Result<ipnet::IpNet, String> {
    if let Ok(net) = v.parse::<ipnet::IpNet>() {
        return Ok(net);
    }
    v.parse::<std::net::IpAddr>()
        .map(ipnet::IpNet::from)
        .map_err(|e| e.to_string())
}
