use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Result, WgError};
use crate::host::{HostOptions, WireGuardHost};
use crate::keys::generate_preshared_key;
use crate::peer::Peer;
use crate::pool::IpAddressPool;

/// Holds a collection of hosts (offices + clients) and can bulk-export
/// them. Optional convenience layer for managing many hosts at once.
#[derive(Default)]
pub struct WireGuardNetwork {
    pub hosts: HashMap<String, WireGuardHost>,
    pub pools: HashMap<String, IpAddressPool>,
    host_order: Vec<String>,
}

impl WireGuardNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_host(&mut self, host: WireGuardHost) -> Result<&WireGuardHost> {
        if self.hosts.contains_key(&host.name) {
            return Err(WgError::Value(format!("Host name {:?} already exists", host.name)));
        }
        let name = host.name.clone();
        self.hosts.insert(name.clone(), host);
        self.host_order.push(name.clone());
        Ok(self.hosts.get(&name).unwrap())
    }

    pub fn create_pool(
        &mut self,
        name: &str,
        cidr: &str,
        host_prefix: Option<u8>,
        reserve: &[String],
    ) -> Result<()> {
        if self.pools.contains_key(name) {
            return Err(WgError::Value(format!("Pool name {name:?} already exists")));
        }
        let pool = IpAddressPool::new(cidr, host_prefix, reserve)?;
        self.pools.insert(name.to_string(), pool);
        Ok(())
    }

    /// Create a host. If `pool` is given (the name of a pool created via
    /// `create_pool`), the host's `address` is auto-assigned from that
    /// pool instead of being passed in manually.
    pub fn create_host(&mut self, name: &str, mut opts: HostOptions, pool: Option<&str>) -> Result<()> {
        if let Some(pool_name) = pool {
            if !opts.address.is_empty() {
                return Err(WgError::Value("Pass either `address` or `pool`, not both".into()));
            }
            let pool = self
                .pools
                .get_mut(pool_name)
                .ok_or_else(|| WgError::Value(format!("No such pool: {pool_name:?}")))?;
            opts.address = vec![pool.allocate()?];
        }
        let host = WireGuardHost::new(name, opts)?;
        self.add_host(host)?;
        Ok(())
    }

    /// Link two existing hosts as peers of each other in both directions.
    #[allow(clippy::too_many_arguments)]
    pub fn mesh(
        &mut self,
        a: &str,
        b: &str,
        allowed_ips_a_to_b: Vec<String>,
        allowed_ips_b_to_a: Vec<String>,
        endpoint_a: Option<String>,
        endpoint_b: Option<String>,
        keepalive: Option<u32>,
        use_preshared_key: bool,
    ) -> Result<()> {
        let psk = if use_preshared_key { Some(generate_preshared_key()) } else { None };

        let (host_a_pub, host_a_name) = {
            let ha = self.hosts.get(a).ok_or_else(|| WgError::Value(format!("No such host: {a:?}")))?;
            (ha.public_key.clone(), ha.name.clone())
        };
        let (host_b_pub, host_b_name) = {
            let hb = self.hosts.get(b).ok_or_else(|| WgError::Value(format!("No such host: {b:?}")))?;
            (hb.public_key.clone(), hb.name.clone())
        };

        let peer_b_for_a = Peer::build(
            host_b_pub,
            allowed_ips_a_to_b,
            endpoint_b,
            keepalive,
            psk.clone(),
            Some(host_b_name),
        )?;
        let peer_a_for_b = Peer::build(
            host_a_pub,
            allowed_ips_b_to_a,
            endpoint_a,
            keepalive,
            psk,
            Some(host_a_name),
        )?;

        self.hosts.get_mut(a).unwrap().add_peer(peer_b_for_a);
        self.hosts.get_mut(b).unwrap().add_peer(peer_a_for_b);
        Ok(())
    }

    pub fn save_all(&self, directory: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
        let directory = directory.as_ref();
        // Preserve insertion order, matching the Python dict's iteration
        // order (dicts are insertion-ordered as of Python 3.7+).
        self.host_order
            .iter()
            .map(|name| self.hosts.get(name).unwrap().save(directory, None))
            .collect()
    }
}
