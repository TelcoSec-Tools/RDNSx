//! RDNSx Core - Fast and multi-purpose DNS toolkit library
//!
//! This library provides a high-performance DNS resolution engine with support for
//! multiple record types, wildcard filtering, subdomain enumeration, and database exports.

#![forbid(unsafe_code)]

pub mod asn;
pub mod bruteforce;
pub mod cache;
pub mod cdn_detection;
pub mod client;
pub mod concurrency;
pub mod config;
pub mod dns_records;
pub mod dnssec_analysis;
pub mod email_security;
pub mod enumeration;
pub mod enumeration_types;
pub mod error;
pub mod export;
pub mod hickory_ext;
pub mod input;
pub mod output;
pub mod query;
pub mod raw;
pub mod record_types;
pub mod record_values;
pub mod resolver;
pub mod response_codes;
pub mod types;
pub mod utils;
pub mod wildcard;
pub mod zone_transfer;

pub use bruteforce::Bruteforcer;
pub use cache::{CacheStats, CachedDnsClient, DnsCache, DnsQuery};
pub use cdn_detection::CdnDetectionResult;
pub use client::DnsxClient;
pub use concurrency::{
    AdaptiveBatchSizer, ConcurrencyConfig, ConcurrentProcessor, DomainStreamer, ProcessingMetrics,
    RateLimiter,
};
pub use config::{DnsxOptions, ExportConfig, DEFAULT_RESOLVERS};
pub use dnssec_analysis::{DnssecEnumerationResult, ZoneWalkingResult};
pub use email_security::EmailSecurityResult;
pub use enumeration::{DnsEnumerator, HistoricalIp, PassiveSubdomain};
pub use enumeration_types::{DnsServerFingerprint, Ipv6EnumerationResult, PassiveDnsResult};
pub use error::{DnsxError, Result};
#[cfg(feature = "cassandra")]
pub use export::cassandra::{CassandraConfig, CassandraMetrics};
#[cfg(feature = "cassandra")]
pub use export::CassandraExporter;
#[cfg(feature = "elasticsearch")]
pub use export::ElasticsearchExporter;
pub use export::Exporter;
#[cfg(feature = "mongodb")]
pub use export::MongodbExporter;
pub use input::{parse_asn, parse_ip_range, parse_ip_range_limited, reverse_ip};
pub use query::QueryResponse;
pub use resolver::{QueryOutcome, ResolverPool};
pub use types::{DnsRecord, RecordType, RecordValue, ResponseCode};
pub use wildcard::{WildcardAnalysis, WildcardBypassAttempt, WildcardFilter};
pub use zone_transfer::ZoneTransferResult;

#[cfg(test)]
mod tests;
