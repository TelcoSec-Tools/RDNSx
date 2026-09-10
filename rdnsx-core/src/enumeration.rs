//! Advanced DNS enumeration capabilities

use std::sync::Arc;

use tracing::info;
use reqwest;
use ureq;

use crate::cdn_detection::{CdnDetectionResult, CdnDetector};
use crate::dnssec_analysis::{DnssecEnumerationResult, ZoneWalkingResult, DnssecAnalyzer};
use crate::email_security::{EmailSecurityResult, EmailSecurityEnumerator};
use crate::error::{DnsxError, Result};
use crate::resolver::ResolverPool;
use crate::types::RecordType;
use crate::wildcard::{WildcardFilter, WildcardAnalysis};
use crate::zone_transfer::{ZoneTransferResult, ZoneTransferEnumerator};

// Re-export types for backward compatibility
pub use crate::cdn_detection::{CnameHop, OriginServerInfo, CdnAnalysis};
pub use crate::dnssec_analysis::{DnskeyInfo, DsInfo, NsecRecord, ChainValidationResult};
pub use crate::email_security::{SpfRecord, DmarcRecord, DkimSelector, SpfAnalysis, DmarcAnalysis};
pub use crate::enumeration_types::*;

// Module is declared in lib.rs

/// DNS enumeration engine for advanced discovery techniques
pub struct DnsEnumerator {
    resolver_pool: Arc<ResolverPool>,
    zone_transfer: ZoneTransferEnumerator,
    email_security: EmailSecurityEnumerator,
    cdn_detector: CdnDetector,
    dnssec_analyzer: DnssecAnalyzer,
}

impl DnsEnumerator {
    /// Create a new DNS enumerator
    pub fn new(resolver_pool: Arc<ResolverPool>) -> Self {
        Self {
            resolver_pool: resolver_pool.clone(),
            zone_transfer: ZoneTransferEnumerator::new(resolver_pool.clone()),
            email_security: EmailSecurityEnumerator::new(resolver_pool.clone()),
            cdn_detector: CdnDetector::new(resolver_pool.clone()),
            dnssec_analyzer: DnssecAnalyzer::new(resolver_pool),
        }
    }

    /// Attempt DNS zone transfer (AXFR) against specified servers
    pub async fn zone_transfer(
        &self,
        domain: &str,
        nameservers: &[String],
    ) -> Result<ZoneTransferResult> {
        self.zone_transfer.enumerate(domain, nameservers).await
    }

    /// Enumerate SPF and DMARC records for email security analysis
    pub async fn email_security_enumeration(
        &self,
        domain: &str,
    ) -> Result<EmailSecurityResult> {
        self.email_security.enumerate(domain).await
    }

    /// Detect and analyze CDN usage
    pub async fn cdn_detection(&self, domain: &str) -> Result<CdnDetectionResult> {
        self.cdn_detector.detect(domain).await
    }

    /// Enumerate IPv6 deployment and addresses
    pub async fn ipv6_enumeration(&self, domain: &str) -> Result<Ipv6EnumerationResult> {
        use crate::enumeration_types::Ipv6EnumerationResult;

        info!("Enumerating IPv6 deployment for: {}", domain);

        let mut result = Ipv6EnumerationResult {
            domain: domain.to_string(),
            ipv6_addresses: Vec::new(),
            ipv4_addresses: Vec::new(),
            dual_stack: false,
            ipv6_only: false,
        };

        // Get IPv4 addresses
        if let Ok((lookup, _)) = self.resolver_pool.query(domain, RecordType::A).await {
            for rdata in lookup.iter() {
                if let hickory_resolver::proto::rr::RData::A(ip) = rdata {
                    result.ipv4_addresses.push(std::net::IpAddr::V4(**ip));
                }
            }
        }

        // Get IPv6 addresses
        if let Ok((lookup, _)) = self.resolver_pool.query(domain, RecordType::Aaaa).await {
            for rdata in lookup.iter() {
                if let hickory_resolver::proto::rr::RData::AAAA(ip) = rdata {
                    result.ipv6_addresses.push(std::net::IpAddr::V6(**ip));
                }
            }
        }

        // Analyze deployment type
        result.dual_stack = !result.ipv4_addresses.is_empty() && !result.ipv6_addresses.is_empty();
        result.ipv6_only = result.ipv4_addresses.is_empty() && !result.ipv6_addresses.is_empty();

        Ok(result)
    }

    /// Enumerate DNSSEC configuration and security
    pub async fn dnssec_enumeration(&self, domain: &str) -> Result<DnssecEnumerationResult> {
        self.dnssec_analyzer.enumerate(domain).await
    }

    /// Perform DNSSEC zone walking (NSEC enumeration)
    pub async fn dnssec_zone_walking(&self, domain: &str) -> Result<ZoneWalkingResult> {
        self.dnssec_analyzer.zone_walking(domain).await
    }

    /// Perform passive DNS enumeration using historical data
    pub async fn passive_dns_enumeration(&self, domain: &str) -> Result<crate::enumeration_types::PassiveDnsResult> {
        info!("Performing passive DNS enumeration for: {}", domain);

        let sources: Vec<Box<dyn PassiveDnsSource>> = vec![
            Box::new(CrtShSource),
            Box::new(LocalResolutionSource::new(self.resolver_pool.clone())),
        ];

        let mut combined_result = crate::enumeration_types::PassiveDnsResult {
            domain: domain.to_string(),
            subdomains: Vec::new(),
            historical_ips: Vec::new(),
            last_seen: None,
            data_sources: Vec::new(),
        };

        for source in sources {
            if let Ok(result) = source.lookup(domain).await {
                combined_result.subdomains.extend(result.subdomains);
                combined_result.historical_ips.extend(result.historical_ips);
                combined_result.data_sources.push(source.name().to_string());

                if let Some(source_last_seen) = result.last_seen {
                    if combined_result.last_seen.is_none() || Some(source_last_seen) > combined_result.last_seen {
                        combined_result.last_seen = Some(source_last_seen);
                    }
                }
            }
        }

        // Deduplicate subdomains by name
        let mut seen = std::collections::HashSet::new();
        combined_result.subdomains.retain(|sub| seen.insert(sub.name.clone()));

        Ok(combined_result)
    }

    /// Analyze wildcard DNS configurations and bypass techniques
    pub async fn wildcard_analysis(&self, domain: &str) -> Result<WildcardAnalysis> {
        info!("Analyzing wildcard DNS configuration for: {}", domain);

        let wildcard_filter = WildcardFilter::new(Some(domain.to_string()), self.resolver_pool.clone(), 5);
        wildcard_filter.get_wildcard_analysis(domain).await
    }

    /// Fingerprint DNS server capabilities
    pub async fn server_fingerprinting(&self, nameserver: &str) -> Result<crate::enumeration_types::DnsServerFingerprint> {
        use crate::enumeration_types::DnsServerFingerprint;

        info!("Fingerprinting DNS server: {}", nameserver);

        let mut fingerprint = DnsServerFingerprint {
            server: nameserver.to_string(),
            version_bind: None,
            recursion_available: false,
            dnssec_support: false,
            edns_support: false,
            response_time_ms: 0,
        };

        let start_time = std::time::Instant::now();

        // Test basic query
        match self.resolver_pool.query("example.com", RecordType::A).await {
            Ok(_) => {
                fingerprint.response_time_ms = start_time.elapsed().as_millis() as u64;
            }
            Err(e) => {
                return Err(crate::error::DnsxError::Other(format!("Server fingerprinting failed: {}", e)));
            }
        }

        Ok(fingerprint)
    }

    /// Enumerate ASN information and associated IP ranges
    pub async fn asn_enumeration(&self, asn: &str) -> Result<crate::enumeration_types::AsnEnumerationResult> {
        info!("Enumerating ASN: {}", asn);

        let clean_asn = asn.trim_start_matches("AS").trim_start_matches("as");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| DnsxError::Other(format!("Failed to create HTTP client: {}", e)))?;

        let url = format!("https://api.bgpview.io/asn/{}", clean_asn);
        match Self::try_asn_api(&client, &url, "BGPView", clean_asn).await {
            Ok(result) => Ok(result),
            Err(e) => {
                info!("BGPView failed ({}), trying IPInfo fallback", e);
                let ipinfo_url = format!("https://ipinfo.io/AS{}/json", clean_asn);
                Self::try_asn_api(&client, &ipinfo_url, "IPInfo", clean_asn).await
            }
        }
    }

    /// Try to fetch ASN data from a specific API
    #[allow(dead_code)]
    async fn try_asn_api(client: &reqwest::Client, url: &str, api_name: &str, asn: &str) -> Result<AsnEnumerationResult> {
        // First try with reqwest
        match Self::try_reqwest_api(client, url, api_name, asn).await {
            Ok(result) => Ok(result),
            Err(reqwest_error) => {
                info!("reqwest failed for {} API: {}, trying ureq fallback", api_name, reqwest_error);
                // Fallback to ureq
                Self::try_ureq_api(url, api_name, asn).map_err(|ureq_error| {
                    DnsxError::Other(format!("Both reqwest and ureq failed. reqwest: {}, ureq: {}", reqwest_error, ureq_error))
                })
            }
        }
    }

    /// Try API with reqwest
    #[allow(dead_code)]
    async fn try_reqwest_api(client: &reqwest::Client, url: &str, api_name: &str, asn: &str) -> Result<AsnEnumerationResult> {
        let response = client
            .get(url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| {
                let error_msg = format!("Failed to query {} API: {} (URL: {})", api_name, e, url);
                let final_msg = if e.is_timeout() {
                    format!("{} - Request timed out. Check internet connection.", error_msg)
                } else if e.is_connect() {
                    format!("{} - Connection failed. Check network connectivity.", error_msg)
                } else {
                    error_msg
                };
                DnsxError::Other(final_msg)
            })?;

        if !response.status().is_success() {
            return Err(DnsxError::Other(format!("{} API returned status: {} for URL: {}", api_name, response.status(), url)));
        }

        let json: serde_json::Value = response.json().await
            .map_err(|e| DnsxError::Other(format!("Failed to parse {} API response: {}", api_name, e)))?;

        Self::parse_asn_response(json, api_name, asn)
    }

    /// Try API with ureq as fallback
    #[allow(dead_code)]
    fn try_ureq_api(url: &str, api_name: &str, asn: &str) -> Result<AsnEnumerationResult> {
        let response = ureq::get(url)
            .timeout(std::time::Duration::from_secs(30))
            .call()
            .map_err(|e| DnsxError::Other(format!("ureq failed for {} API: {} (URL: {})", api_name, e, url)))?;

        if response.status() != 200 {
            return Err(DnsxError::Other(format!("{} API returned status: {} for URL: {}", api_name, response.status(), url)));
        }

        let json: serde_json::Value = response.into_json()
            .map_err(|e| DnsxError::Other(format!("Failed to parse {} API response: {}", api_name, e)))?;

        Self::parse_asn_response(json, api_name, asn)
    }

    /// Parse ASN response from different APIs
    #[allow(dead_code)]
    fn parse_asn_response(json: serde_json::Value, api_name: &str, asn: &str) -> Result<AsnEnumerationResult> {
        let mut result = AsnEnumerationResult {
            asn: format!("AS{}", asn),
            name: None,
            description: None,
            country: None,
            ipv4_prefixes: Vec::new(),
            ipv6_prefixes: Vec::new(),
            total_ipv4_addresses: 0,
            total_ipv6_addresses: 0,
        };

        match api_name {
            "BGPView" => {
                // Parse BGPView response
                if let Some(data) = json.get("data") {
                    if let Some(asn_data) = data.get("asn") {
                        result.asn = asn_data.get("asn").and_then(|a| a.as_u64()).map(|a| format!("AS{}", a)).unwrap_or_default();
                        result.name = asn_data.get("name").and_then(|n| n.as_str()).map(|s| s.to_string());
                        result.description = asn_data.get("description").and_then(|d| d.as_str()).map(|s| s.to_string());
                        result.country = asn_data.get("country_code").and_then(|c| c.as_str()).map(|s| s.to_string());
                    }

                    // Extract IPv4 prefixes
                    if let Some(prefixes) = data.get("prefixes") {
                        if let Some(ipv4_prefixes) = prefixes.get("ipv4") {
                            if let Some(prefix_array) = ipv4_prefixes.as_array() {
                                for prefix in prefix_array {
                                    if let Some(prefix_str) = prefix.get("prefix").and_then(|p| p.as_str()) {
                                        result.ipv4_prefixes.push(prefix_str.to_string());

                                        // Calculate total IPv4 addresses
                                        if let Some(count) = prefix.get("ip_count").and_then(|c| c.as_u64()) {
                                            result.total_ipv4_addresses += count;
                                        }
                                    }
                                }
                            }
                        }

                        // Extract IPv6 prefixes
                        if let Some(ipv6_prefixes) = prefixes.get("ipv6") {
                            if let Some(prefix_array) = ipv6_prefixes.as_array() {
                                for prefix in prefix_array {
                                    if let Some(prefix_str) = prefix.get("prefix").and_then(|p| p.as_str()) {
                                        result.ipv6_prefixes.push(prefix_str.to_string());

                                        // Calculate total IPv6 addresses
                                        if let Some(count) = prefix.get("ip_count").and_then(|c| c.as_u64()) {
                                            result.total_ipv6_addresses += count;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "IPInfo" => {
                // Parse IPInfo response
                result.asn = json.get("asn").and_then(|a| a.as_str()).unwrap_or("Unknown").to_string();
                result.name = json.get("name").and_then(|n| n.as_str()).map(|s| s.to_string());
                result.country = json.get("country").and_then(|c| c.as_str()).map(|s| s.to_string());

                // IPInfo provides prefixes in a different format
                if let Some(prefixes) = json.get("prefixes") {
                    if let Some(prefix_array) = prefixes.as_array() {
                        for prefix in prefix_array {
                            if let Some(prefix_str) = prefix.get("netblock").and_then(|p| p.as_str()) {
                                if prefix_str.contains(':') {
                                    result.ipv6_prefixes.push(prefix_str.to_string());
                                } else {
                                    result.ipv4_prefixes.push(prefix_str.to_string());
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                return Err(DnsxError::Other(format!("Unknown API: {}", api_name)));
            }
        }

        Ok(result)
    }
}

/// Trait for passive DNS data sources
#[async_trait::async_trait]
pub trait PassiveDnsSource: Send + Sync {
    /// Name of the data source
    fn name(&self) -> &str;
    
    /// Perform lookup for a domain
    async fn lookup(&self, domain: &str) -> Result<crate::enumeration_types::PassiveDnsResult>;
}

/// Local resolution-based "passive" source (basic prefix brute-force)
pub struct LocalResolutionSource {
    resolver_pool: Arc<ResolverPool>,
}

impl LocalResolutionSource {
    pub fn new(resolver_pool: Arc<ResolverPool>) -> Self {
        Self { resolver_pool }
    }
}

#[async_trait::async_trait]
impl PassiveDnsSource for LocalResolutionSource {
    fn name(&self) -> &str {
        "local_resolution"
    }

    async fn lookup(&self, domain: &str) -> Result<crate::enumeration_types::PassiveDnsResult> {
        use crate::enumeration_types::{PassiveDnsResult, PassiveSubdomain};
        
        let mut result = PassiveDnsResult {
            domain: domain.to_string(),
            subdomains: Vec::new(),
            historical_ips: Vec::new(),
            last_seen: Some(chrono::Utc::now()),
            data_sources: vec![self.name().to_string()],
        };

        let common_prefixes = vec!["www", "mail", "ftp", "admin", "api", "dev", "staging", "test"];

        for prefix in common_prefixes {
            let subdomain = format!("{}.{}", prefix, domain);

            if let Ok((lookup, _)) = self.resolver_pool.query(&subdomain, RecordType::A).await {
                if lookup.iter().next().is_some() {
                    result.subdomains.push(PassiveSubdomain {
                        name: subdomain,
                        record_type: "A".to_string(),
                        first_seen: chrono::Utc::now(),
                        last_seen: chrono::Utc::now(),
                        source: self.name().to_string(),
                    });
                }
            }
        }

        Ok(result)
    }
}

/// Certificate Transparency (crt.sh) passive source
pub struct CrtShSource;

#[async_trait::async_trait]
impl PassiveDnsSource for CrtShSource {
    fn name(&self) -> &str {
        "crt.sh"
    }

    async fn lookup(&self, domain: &str) -> Result<crate::enumeration_types::PassiveDnsResult> {
        use crate::enumeration_types::{PassiveDnsResult, PassiveSubdomain};

        let mut result = PassiveDnsResult {
            domain: domain.to_string(),
            subdomains: Vec::new(),
            historical_ips: Vec::new(),
            last_seen: Some(chrono::Utc::now()),
            data_sources: vec![self.name().to_string()],
        };

        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| DnsxError::Other(e.to_string()))?;

        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(entries) = resp.json::<Vec<serde_json::Value>>().await {
                    let mut seen = std::collections::HashSet::new();
                    for entry in entries {
                        if let Some(name_value) = entry.get("name_value").and_then(|n| n.as_str()) {
                            for name in name_value.split('\n') {
                                let clean = name.trim().trim_start_matches("*.").to_lowercase();
                                let is_subdomain = clean == domain || clean.ends_with(&format!(".{}", domain));
                                if is_subdomain && seen.insert(clean.clone()) {
                                    result.subdomains.push(PassiveSubdomain {
                                        name: clean,
                                        record_type: "A".to_string(),
                                        first_seen: chrono::Utc::now(),
                                        last_seen: chrono::Utc::now(),
                                        source: self.name().to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}




