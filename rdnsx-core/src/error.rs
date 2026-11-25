//! Error types for RDNSx Core

use thiserror::Error;

/// Result type alias for RDNSx operations
pub type Result<T> = std::result::Result<T, DnsxError>;

/// Main error type for RDNSx operations
#[derive(Error, Debug)]
pub enum DnsxError {
    /// DNS resolution error
    #[error("DNS resolution failed: {0}")]
    Resolve(String),

    /// Query timeout
    #[error("DNS query timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Invalid input (domain, IP, etc.)
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Validation error
    #[error("Validation failed: {0}")]
    Validation(String),

    /// Resolver configuration error
    #[error("Resolver configuration error: {0}")]
    ResolverConfig(String),

    /// Network I/O error
    #[error("Network I/O error: {0}")]
    Network(#[from] std::io::Error),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Export error (Elasticsearch, MongoDB, etc.)
    #[error("Export error: {0}")]
    Export(String),

    /// Wildcard detection error
    #[error("Wildcard detection error: {0}")]
    Wildcard(String),

    /// Bruteforce error
    #[error("Bruteforce error: {0}")]
    Bruteforce(String),

    /// Address parsing error
    #[error("Address parsing error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    /// Generic error with context
    #[error("{0}")]
    Other(String),
}

impl DnsxError {
    /// Create a new resolve error
    pub fn resolve(msg: impl Into<String>) -> Self {
        Self::Resolve(msg.into())
    }

    /// Create a new timeout error
    pub fn timeout(duration: std::time::Duration) -> Self {
        Self::Timeout(duration)
    }

    /// Create a new invalid input error
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Create a new validation error
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }
}
