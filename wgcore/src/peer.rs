use crate::error::Result;
use crate::keys::{validate_cidr_list, validate_key};

/// One `[Peer]` block, as it will appear inside *someone else's* config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>, // "host:port"
    pub persistent_keepalive: Option<u32>,
    pub preshared_key: Option<String>,
    pub comment: Option<String>, // e.g. "Office - Berlin"
}

impl Peer {
    pub fn new(public_key: impl Into<String>) -> Result<Self> {
        let public_key = public_key.into();
        validate_key(&public_key, "Peer.public_key")?;
        Ok(Peer {
            public_key,
            ..Default::default()
        })
    }

    pub fn with_allowed_ips(mut self, allowed_ips: Vec<String>) -> Result<Self> {
        validate_cidr_list(&allowed_ips, "Peer.allowed_ips")?;
        self.allowed_ips = allowed_ips;
        Ok(self)
    }

    pub fn with_endpoint(mut self, endpoint: Option<String>) -> Self {
        self.endpoint = endpoint;
        self
    }

    pub fn with_persistent_keepalive(mut self, keepalive: Option<u32>) -> Self {
        self.persistent_keepalive = keepalive;
        self
    }

    pub fn with_preshared_key(mut self, psk: Option<String>) -> Result<Self> {
        if let Some(k) = &psk {
            validate_key(k, "Peer.preshared_key")?;
        }
        self.preshared_key = psk;
        Ok(self)
    }

    pub fn with_comment(mut self, comment: Option<String>) -> Self {
        self.comment = comment;
        self
    }

    /// Full constructor mirroring the Python dataclass's `__init__`
    /// (all fields validated together, same as `__post_init__`).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        public_key: impl Into<String>,
        allowed_ips: Vec<String>,
        endpoint: Option<String>,
        persistent_keepalive: Option<u32>,
        preshared_key: Option<String>,
        comment: Option<String>,
    ) -> Result<Self> {
        let public_key = public_key.into();
        validate_key(&public_key, "Peer.public_key")?;
        if let Some(k) = &preshared_key {
            validate_key(k, "Peer.preshared_key")?;
        }
        if !allowed_ips.is_empty() {
            validate_cidr_list(&allowed_ips, "Peer.allowed_ips")?;
        }
        Ok(Peer {
            public_key,
            allowed_ips,
            endpoint,
            persistent_keepalive,
            preshared_key,
            comment,
        })
    }

    pub fn to_config(&self) -> String {
        let mut lines = Vec::new();
        if let Some(c) = &self.comment {
            lines.push(format!("# {c}"));
        }
        lines.push("[Peer]".to_string());
        lines.push(format!("PublicKey = {}", self.public_key));
        if let Some(psk) = &self.preshared_key {
            lines.push(format!("PresharedKey = {psk}"));
        }
        if !self.allowed_ips.is_empty() {
            lines.push(format!("AllowedIPs = {}", self.allowed_ips.join(", ")));
        }
        if let Some(ep) = &self.endpoint {
            lines.push(format!("Endpoint = {ep}"));
        }
        if let Some(ka) = self.persistent_keepalive {
            lines.push(format!("PersistentKeepalive = {ka}"));
        }
        lines.join("\n")
    }
}
