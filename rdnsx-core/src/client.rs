//! Main DNSx client

use std::net::IpAddr;
use crate::config::DnsxOptions;
use crate::error::Result;
use crate::query::QueryEngine;
use crate::resolver::ResolverPool;
use crate::types::{DnsRecord, RecordType};

/// Main DNSx client
pub struct DnsxClient {
    query_engine: QueryEngine,
}

impl DnsxClient {
    /// Create a new DNSx client with default options
    pub fn new() -> Result<Self> {
        Self::with_options(DnsxOptions::default())
    }

    /// Create a new DNSx client with custom options
    pub fn with_options(options: DnsxOptions) -> Result<Self> {
        let resolver_pool = ResolverPool::new(&options)?;
        let query_engine = QueryEngine::new(resolver_pool);

        Ok(Self { query_engine })
    }

    /// Query a domain for a specific record type
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<DnsRecord>> {
        self.query_engine.query(domain, record_type).await
    }

    /// Lookup IPv4 addresses for a domain (A records)
    pub async fn lookup_ipv4(&self, domain: &str) -> Result<Vec<std::net::Ipv4Addr>> {
        self.query_engine.lookup_ipv4(domain).await
    }

    /// Lookup IPv6 addresses for a domain (AAAA records)
    pub async fn lookup_ipv6(&self, domain: &str) -> Result<Vec<std::net::Ipv6Addr>> {
        self.query_engine.lookup_ipv6(domain).await
    }

    /// Lookup all IP addresses for a domain (A and AAAA records)
    pub async fn lookup(&self, domain: &str) -> Result<Vec<std::net::IpAddr>> {
        let mut ips = Vec::new();

        // Get IPv4 addresses
        if let Ok(ipv4s) = self.lookup_ipv4(domain).await {
            ips.extend(ipv4s.into_iter().map(IpAddr::V4));
        }

        // Get IPv6 addresses
        if let Ok(ipv6s) = self.lookup_ipv6(domain).await {
            ips.extend(ipv6s.into_iter().map(IpAddr::V6));
        }

        Ok(ips)
    }
}

impl Default for DnsxClient {
    fn default() -> Self {
        Self::new().expect("Failed to create DNSx client with default options")
    }
}
