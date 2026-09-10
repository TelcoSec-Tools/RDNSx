//! RDNSx Core - Fast and multi-purpose DNS toolkit library
//!
//! This library provides a high-performance DNS resolution engine with support for
//! multiple record types, wildcard filtering, subdomain enumeration, and database exports.

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
pub mod input;
pub mod output;
pub mod query;
pub mod record_types;
pub mod record_values;
pub mod resolver;
pub mod response_codes;
pub mod types;
pub mod utils;
pub mod wildcard;
pub mod zone_transfer;

pub use cache::{DnsCache, CachedDnsClient, CacheStats, DnsQuery};
pub use client::DnsxClient;
pub use concurrency::{ConcurrentProcessor, ConcurrencyConfig, ProcessingMetrics, DomainStreamer, AdaptiveBatchSizer, RateLimiter};
pub use config::{DnsxOptions, ExportConfig, DEFAULT_RESOLVERS};
pub use enumeration::{DnsEnumerator, PassiveSubdomain, HistoricalIp};
pub use zone_transfer::ZoneTransferResult;
pub use email_security::EmailSecurityResult;
pub use cdn_detection::CdnDetectionResult;
pub use dnssec_analysis::{DnssecEnumerationResult, ZoneWalkingResult};
pub use enumeration_types::{Ipv6EnumerationResult, DnsServerFingerprint, PassiveDnsResult};
pub use error::{DnsxError, Result};
pub use types::{DnsRecord, RecordType, ResponseCode, RecordValue};
pub use export::{Exporter, CassandraExporter, ElasticsearchExporter, MongodbExporter};
pub use export::cassandra::{CassandraConfig, CassandraMetrics};
pub use bruteforce::Bruteforcer;
pub use wildcard::{WildcardFilter, WildcardAnalysis, WildcardBypassAttempt};
pub use resolver::ResolverPool;
pub use input::{parse_asn, parse_ip_range, parse_ip_range_limited, reverse_ip};

#[cfg(test)]
mod tests;
