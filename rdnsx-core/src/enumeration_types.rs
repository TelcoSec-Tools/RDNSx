//! Common enumeration result types

use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// Results from IPv6 enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6EnumerationResult {
    pub domain: String,
    pub ipv6_addresses: Vec<IpAddr>,
    pub ipv4_addresses: Vec<IpAddr>,
    pub dual_stack: bool,
    pub ipv6_only: bool,
}

/// Results from passive DNS enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveDnsResult {
    pub domain: String,
    pub subdomains: Vec<PassiveSubdomain>,
    pub historical_ips: Vec<HistoricalIp>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub data_sources: Vec<String>,
}

/// Passive DNS subdomain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveSubdomain {
    pub name: String,
    pub record_type: String,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub source: String,
}

/// Historical IP address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalIp {
    pub ip: IpAddr,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// DNS server fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerFingerprint {
    pub server: String,
    pub version_bind: Option<String>,
    pub recursion_available: bool,
    pub dnssec_support: bool,
    pub edns_support: bool,
    pub response_time_ms: u64,
}

/// Results from ASN enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnEnumerationResult {
    pub asn: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub country: Option<String>,
    pub ipv4_prefixes: Vec<String>,
    pub ipv6_prefixes: Vec<String>,
    pub total_ipv4_addresses: u64,
    pub total_ipv6_addresses: u64,
}