//! DNS record structures and implementations

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

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

    /// Create a placeholder record describing a negative answer
    /// (NXDOMAIN, SERVFAIL, REFUSED, or NOERROR with no data).
    pub fn negative(
        domain: String,
        record_type: RecordType,
        response_code: ResponseCode,
        resolver: String,
        query_time_ms: f64,
    ) -> Self {
        Self::new(
            domain,
            record_type,
            RecordValue::Empty,
            0,
            response_code,
            resolver,
            query_time_ms,
        )
    }

    /// Whether this record represents a negative answer rather than data
    pub fn is_negative(&self) -> bool {
        matches!(self.value, RecordValue::Empty)
    }
}

impl std::fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_negative() {
            write!(f, "{} [{}]", self.domain, self.response_code)
        } else {
            write!(f, "{} [{}]", self.domain, self.value)
        }
    }
}
