//! DNS record structures and implementations

use std::time::SystemTime;
use serde::{Deserialize, Serialize};

use crate::{RecordType, RecordValue, ResponseCode};

/// DNS record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsRecord {
    /// Domain name queried
    pub domain: String,
    /// Record type
    pub record_type: RecordType,
    /// Record value(s)
    pub value: RecordValue,
    /// Time to live
    pub ttl: u32,
    /// Response code
    pub response_code: ResponseCode,
    /// Resolver used
    pub resolver: String,
    /// Query timestamp
    pub timestamp: SystemTime,
    /// Query time in milliseconds
    pub query_time_ms: f64,
}

impl DnsRecord {
    /// Create a new DNS record
    pub fn new(
        domain: String,
        record_type: RecordType,
        value: RecordValue,
        ttl: u32,
        response_code: ResponseCode,
        resolver: String,
        query_time_ms: f64,
    ) -> Self {
        Self {
            domain,
            record_type,
            value,
            ttl,
            response_code,
            resolver,
            timestamp: SystemTime::now(),
            query_time_ms,
        }
    }
}

impl std::fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{}]",
            self.domain,
            self.value.to_string()
        )
    }
}