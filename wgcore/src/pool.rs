//! Hands out unique addresses from a subnet, e.g. so you don't have to
//! track "which /32 is free in 10.10.0.0/24" by hand for every client.
//!
//! ```ignore
//! let mut pool = IpAddressPool::new("10.10.0.0/24", None, &["10.10.0.1".into()])?; // gateway
//! let addr = pool.allocate()?; // -> "10.10.0.2/32"
//! ```

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::error::{Result, WgError};

pub struct IpAddressPool {
    network: IpNet,
    host_prefix: u8,
    allocated: HashSet<IpAddr>,
    reserved: HashSet<IpAddr>,
}

impl IpAddressPool {
    /// `host_prefix` mirrors the Python default of a literal `32` (not
    /// "the network's own max prefix length"), so IPv4 pools default to
    /// handing out /32s the way the original did.
    pub fn new(cidr: &str, host_prefix: Option<u8>, reserve: &[String]) -> Result<Self> {
        let network: IpNet = cidr
            .parse()
            .map_err(|e| WgError::InvalidCidr(format!("{cidr}: {e}")))?;
        let max_prefix = match network {
            IpNet::V4(_) => 32,
            IpNet::V6(_) => 128,
        };
        let host_prefix = host_prefix.unwrap_or(32);
        if host_prefix < 1 || host_prefix > max_prefix {
            return Err(WgError::Value(format!(
                "host_prefix must be between 1 and {max_prefix}"
            )));
        }

        let mut pool = IpAddressPool {
            network,
            host_prefix,
            allocated: HashSet::new(),
            reserved: HashSet::new(),
        };
        for addr in reserve {
            pool.reserve(addr)?;
        }
        Ok(pool)
    }

    /// Mark an address as unavailable (e.g. a gateway with a static IP).
    pub fn reserve(&mut self, address: &str) -> Result<()> {
        let ip_str = address.split('/').next().unwrap_or(address);
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| WgError::Value(format!("{address}: {e}")))?;
        if !self.network.contains(&ip) {
            return Err(WgError::Value(format!(
                "{address} is not inside {}",
                self.network
            )));
        }
        self.reserved.insert(ip);
        Ok(())
    }

    /// Return the next free address as a CIDR string, e.g. "10.10.0.5/32".
    pub fn allocate(&mut self) -> Result<String> {
        for ip in self.network.hosts() {
            if self.reserved.contains(&ip) || self.allocated.contains(&ip) {
                continue;
            }
            self.allocated.insert(ip);
            return Ok(format!("{ip}/{}", self.host_prefix));
        }
        Err(WgError::PoolExhausted(format!(
            "IP pool for {} is exhausted",
            self.network
        )))
    }

    /// Free up a previously allocated address so it can be reused.
    pub fn release(&mut self, address: &str) {
        if let Some(ip_str) = address.split('/').next() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                self.allocated.remove(&ip);
            }
        }
    }

    pub fn describe(&self) -> String {
        let used = self.allocated.len() + self.reserved.len();
        // Mirrors Python's `network.num_addresses`: 2^(bits - prefix),
        // including the network/broadcast addresses this pool itself
        // never hands out.
        let total: u128 = match &self.network {
            IpNet::V4(n) => 1u128 << (32 - n.prefix_len() as u32),
            IpNet::V6(n) => 1u128 << (128 - n.prefix_len() as u32),
        };
        format!("IpAddressPool({}, {used}/{total} used)", self.network)
    }

    pub fn network_str(&self) -> String {
        self.network.to_string()
    }
}
