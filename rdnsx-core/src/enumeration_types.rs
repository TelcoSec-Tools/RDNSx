//! Common enumeration result types

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
    /// Sources that failed, with the reason
    #[serde(default)]
    pub source_errors: Vec<String>,
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
    /// Address that was probed
    pub address: Option<String>,
    /// CHAOS TXT version.bind (software version banner)
    pub version_bind: Option<String>,
    /// CHAOS TXT hostname.bind
    pub hostname_bind: Option<String>,
    /// CHAOS TXT id.server (NSID-style server identity)
    pub id_server: Option<String>,
    /// Server answered a recursive query for a name outside its zones (open resolver)
    pub recursion_available: bool,
    /// Server returned RRSIGs when asked with the DO bit
    pub dnssec_support: bool,
    /// Server echoed an EDNS(0) OPT record
    pub edns_support: bool,
    /// Server answered over TCP
    pub tcp_support: bool,
    /// Round-trip time of the first probe
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
