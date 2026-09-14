use thiserror::Error;

/// Mirrors Python's `WireGuardKeyError`, but broadened to cover every
/// failure mode this crate can produce (key errors, bad CIDRs, exhausted
/// pools, bad numeric fields, parse failures). Kept as one enum, the way
/// the original code raised one exception type for all of these.
#[derive(Debug, Error, Clone)]
pub enum WgError {
    #[error("{0}")]
    InvalidKey(String),

    #[error("{0}")]
    InvalidCidr(String),

    #[error("{0}")]
    PoolExhausted(String),

    #[error("{0}")]
    Value(String),

    #[error("{0}")]
    Parse(String),

    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for WgError {
    fn from(e: std::io::Error) -> Self {
        WgError::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, WgError>;
