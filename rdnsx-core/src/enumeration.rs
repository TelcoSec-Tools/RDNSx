//! Advanced DNS enumeration capabilities

use crate::hickory_ext::LookupExt;
use std::sync::Arc;

use tracing::info;

use crate::cdn_detection::{CdnDetectionResult, CdnDetector};
use crate::dnssec_analysis::{DnssecAnalyzer, DnssecEnumerationResult, ZoneWalkingResult};
use crate::email_security::{EmailSecurityEnumerator, EmailSecurityResult};
use crate::error::{DnsxError, Result};
use crate::resolver::ResolverPool;
use crate::types::RecordType;
use crate::wildcard::{WildcardAnalysis, WildcardFilter};
use crate::zone_transfer::{ZoneTransferEnumerator, ZoneTransferResult};

// Re-export types for backward compatibility
pub use crate::cdn_detection::{CdnAnalysis, CnameHop, OriginServerInfo};
pub use crate::dnssec_analysis::{ChainValidationResult, DnskeyInfo, DsInfo, NsecRecord};
pub use crate::email_security::{DkimSelector, DmarcAnalysis, DmarcRecord, SpfAnalysis, SpfRecord};
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
    pub async fn email_security_enumeration(&self, domain: &str) -> Result<EmailSecurityResult> {
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

    /// Perform DNSSEC zone walking, stopping after `max_names` names
    pub async fn dnssec_zone_walking_limited(
        &self,
        domain: &str,
        max_names: usize,
    ) -> Result<ZoneWalkingResult> {
        self.dnssec_analyzer
            .zone_walking_limited(domain, max_names)
            .await
    }

    /// Validate the DNSSEC chain of trust for a zone
    pub async fn dnssec_validate_chain(&self, domain: &str) -> Result<ChainValidationResult> {
        self.dnssec_analyzer.validate_chain(domain).await
    }

    /// Authoritative nameservers (NS records) of a zone
    pub async fn authoritative_nameservers(&self, domain: &str) -> Result<Vec<String>> {
        crate::raw::authoritative_nameservers(&self.resolver_pool, domain).await
    }

    /// Perform passive DNS enumeration using historical data
    pub async fn passive_dns_enumeration(
        &self,
        domain: &str,
    ) -> Result<crate::enumeration_types::PassiveDnsResult> {
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
            source_errors: Vec::new(),
        };

        for source in sources {
            let lookup = source.lookup(domain).await;
            if let Err(e) = &lookup {
                combined_result
                    .source_errors
                    .push(format!("{}: {}", source.name(), e));
            }
            if let Ok(result) = lookup {
                combined_result.subdomains.extend(result.subdomains);
                combined_result.historical_ips.extend(result.historical_ips);
                combined_result.data_sources.push(source.name().to_string());

                if let Some(source_last_seen) = result.last_seen {
                    if combined_result.last_seen.is_none()
                        || Some(source_last_seen) > combined_result.last_seen
                    {
                        combined_result.last_seen = Some(source_last_seen);
                    }
                }
            }
        }

        // Deduplicate subdomains by name
        let mut seen = std::collections::HashSet::new();
        combined_result
            .subdomains
            .retain(|sub| seen.insert(sub.name.clone()));

        Ok(combined_result)
    }

    /// Analyze wildcard DNS configurations and bypass techniques
    pub async fn wildcard_analysis(&self, domain: &str) -> Result<WildcardAnalysis> {
        info!("Analyzing wildcard DNS configuration for: {}", domain);

        let wildcard_filter =
            WildcardFilter::new(Some(domain.to_string()), self.resolver_pool.clone(), 5);
        wildcard_filter.get_wildcard_analysis(domain).await
    }

    /// Fingerprint a DNS server by querying it directly.
    ///
    /// `nameserver` is a host name or IP, optionally with a port. `zone` is used
    /// for the DNSSEC probe (a zone the server is authoritative for); without it
    /// the root zone is used, which only recursive servers will answer.
    pub async fn server_fingerprinting(&self, nameserver: &str) -> Result<DnsServerFingerprint> {
        self.server_fingerprinting_for_zone(nameserver, None).await
    }

    /// Fingerprint a DNS server, probing DNSSEC with records from `zone`
    pub async fn server_fingerprinting_for_zone(
        &self,
        nameserver: &str,
        zone: Option<&str>,
    ) -> Result<DnsServerFingerprint> {
        use crate::raw::{self, RawQueryOptions};
        use hickory_resolver::proto::rr::{DNSClass, RecordType as HRecordType};

        info!("Fingerprinting DNS server: {}", nameserver);

        let addr = raw::resolve_server(&self.resolver_pool, nameserver)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| DnsxError::Other(format!("No address for {}", nameserver)))?;

        let mut fingerprint = DnsServerFingerprint {
            server: nameserver.to_string(),
            address: Some(addr.to_string()),
            version_bind: None,
            hostname_bind: None,
            id_server: None,
            recursion_available: false,
            dnssec_support: false,
            edns_support: false,
            tcp_support: false,
            response_time_ms: 0,
        };

        // 1. Liveness / EDNS: SOA of the probe zone with an OPT record
        let probe_zone = raw::fqdn(zone.unwrap_or("."))?;
        let start = std::time::Instant::now();
        let edns_probe = raw::raw_query(
            addr,
            &probe_zone,
            HRecordType::SOA,
            RawQueryOptions::default(),
        )
        .await
        .map_err(|e| DnsxError::Other(format!("Server fingerprinting failed: {}", e)))?;
        fingerprint.response_time_ms = start.elapsed().as_millis() as u64;
        fingerprint.edns_support = edns_probe.edns.is_some();

        // 2. CHAOS identity banners
        let chaos = RawQueryOptions {
            class: DNSClass::CH,
            edns: false,
            ..Default::default()
        };
        for (label, slot) in [
            ("version.bind", &mut fingerprint.version_bind),
            ("hostname.bind", &mut fingerprint.hostname_bind),
            ("id.server", &mut fingerprint.id_server),
        ] {
            if let Ok(name) = raw::fqdn(label) {
                if let Ok(msg) = raw::raw_query(addr, &name, HRecordType::TXT, chaos).await {
                    *slot = raw::first_txt(&msg);
                }
            }
        }

        // 3. Recursion: ask for a name the server is unlikely to be authoritative for
        let recursive = RawQueryOptions {
            recursion_desired: true,
            ..Default::default()
        };
        if let Ok(name) = raw::fqdn("example.com") {
            if let Ok(msg) = raw::raw_query(addr, &name, HRecordType::A, recursive).await {
                fingerprint.recursion_available = msg.recursion_available
                    && msg.response_code == hickory_resolver::proto::op::ResponseCode::NoError
                    && !msg.answers.is_empty();
            }
        }

        // 4. DNSSEC: RRSIGs returned with the DO bit set
        let dnssec = RawQueryOptions {
            dnssec_ok: true,
            recursion_desired: zone.is_none(),
            ..Default::default()
        };
        if let Ok(msg) = raw::raw_query(addr, &probe_zone, HRecordType::SOA, dnssec).await {
            fingerprint.dnssec_support = msg
                .answers
                .iter()
                .any(|r| r.record_type() == HRecordType::RRSIG);
        }

        // 5. TCP transport
        fingerprint.tcp_support = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);

        Ok(fingerprint)
    }

    /// Enumerate ASN information and associated IP ranges
    pub async fn asn_enumeration(
        &self,
        asn: &str,
    ) -> Result<crate::enumeration_types::AsnEnumerationResult> {
        info!("Enumerating ASN: {}", asn);

        let clean_asn = asn.trim_start_matches("AS").trim_start_matches("as");

        let clean_asn = clean_asn.to_string();
        if clean_asn.is_empty() || !clean_asn.chars().all(|c| c.is_ascii_digit()) {
            return Err(DnsxError::invalid_input(format!("Invalid ASN: {}", asn)));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("rdnsx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| DnsxError::Other(format!("Failed to create HTTP client: {}", e)))?;

        // RIPEstat: free, no API key, covers all RIRs
        match Self::try_ripestat(&client, &clean_asn).await {
            Ok(result) => Ok(result),
            Err(ripe_error) => {
                info!("RIPEstat failed ({}), trying BGPView", ripe_error);
                let url = format!("https://api.bgpview.io/asn/{}/prefixes", clean_asn);
                let json = Self::get_json(&client, &url).await.map_err(|bgp_error| {
                    DnsxError::Other(format!(
                        "ASN lookup failed. RIPEstat: {}; BGPView: {}",
                        ripe_error, bgp_error
                    ))
                })?;
                Self::parse_asn_response(json, "BGPView", &clean_asn)
            }
        }
    }

    async fn get_json(client: &reqwest::Client, url: &str) -> Result<serde_json::Value> {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| DnsxError::Other(format!("Request to {} failed: {}", url, e)))?;
        if !response.status().is_success() {
            return Err(DnsxError::Other(format!(
                "{} returned status {}",
                url,
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|e| DnsxError::Other(format!("Invalid JSON from {}: {}", url, e)))
    }

    /// Fetch announced prefixes (and the AS name) from RIPEstat
    async fn try_ripestat(client: &reqwest::Client, asn: &str) -> Result<AsnEnumerationResult> {
        let prefixes_url = format!(
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}",
            asn
        );
        let json = Self::get_json(client, &prefixes_url).await?;
        let mut result = Self::parse_asn_response(json, "RIPEstat", asn)?;

        let overview_url = format!(
            "https://stat.ripe.net/data/as-overview/data.json?resource=AS{}",
            asn
        );
        if let Ok(overview) = Self::get_json(client, &overview_url).await {
            result.name = overview
                .pointer("/data/holder")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
        Ok(result)
    }

    /// Parse ASN response from different APIs
    fn parse_asn_response(
        json: serde_json::Value,
        api_name: &str,
        asn: &str,
    ) -> Result<AsnEnumerationResult> {
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

        let push_prefix = |result: &mut AsnEnumerationResult, prefix: &str| {
            let Ok(net) = prefix.parse::<ipnetwork::IpNetwork>() else {
                return;
            };
            match net {
                ipnetwork::IpNetwork::V4(v4) => {
                    result.total_ipv4_addresses += 1u64 << (32 - u32::from(v4.prefix()));
                    result.ipv4_prefixes.push(prefix.to_string());
                }
                ipnetwork::IpNetwork::V6(v6) => {
                    // Count in /64 networks would be more useful, but keep addresses (saturating)
                    let bits = 128 - u32::from(v6.prefix());
                    let count = if bits >= 64 { u64::MAX } else { 1u64 << bits };
                    result.total_ipv6_addresses = result.total_ipv6_addresses.saturating_add(count);
                    result.ipv6_prefixes.push(prefix.to_string());
                }
            }
        };

        match api_name {
            "RIPEstat" => {
                if let Some(prefixes) = json.pointer("/data/prefixes").and_then(|p| p.as_array()) {
                    for prefix in prefixes {
                        if let Some(p) = prefix.get("prefix").and_then(|p| p.as_str()) {
                            push_prefix(&mut result, p);
                        }
                    }
                }
            }
            "BGPView" => {
                for family in ["ipv4_prefixes", "ipv6_prefixes"] {
                    if let Some(prefixes) = json
                        .pointer(&format!("/data/{}", family))
                        .and_then(|p| p.as_array())
                    {
                        for prefix in prefixes {
                            if let Some(p) = prefix.get("prefix").and_then(|p| p.as_str()) {
                                push_prefix(&mut result, p);
                            }
                            if result.name.is_none() {
                                result.name = prefix
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .map(|s| s.to_string());
                                result.description = prefix
                                    .get("description")
                                    .and_then(|d| d.as_str())
                                    .map(|s| s.to_string());
                                result.country = prefix
                                    .get("country_code")
                                    .and_then(|c| c.as_str())
                                    .map(|s| s.to_string());
                            }
                        }
                    }
                }
            }
            _ => {
                return Err(DnsxError::Other(format!("Unknown API: {}", api_name)));
            }
        }

        result.ipv4_prefixes.sort();
        result.ipv4_prefixes.dedup();
        result.ipv6_prefixes.sort();
        result.ipv6_prefixes.dedup();

        if result.ipv4_prefixes.is_empty() && result.ipv6_prefixes.is_empty() {
            return Err(DnsxError::Other(format!(
                "{} returned no prefixes for AS{}",
                api_name, asn
            )));
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

/// Active check of a few common names. Not passive: it sends queries for each
/// name. Kept as a source so results are labelled "active_probe".
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
        "active_probe"
    }

    async fn lookup(&self, domain: &str) -> Result<crate::enumeration_types::PassiveDnsResult> {
        use crate::enumeration_types::{PassiveDnsResult, PassiveSubdomain};

        let mut result = PassiveDnsResult {
            domain: domain.to_string(),
            subdomains: Vec::new(),
            historical_ips: Vec::new(),
            last_seen: Some(chrono::Utc::now()),
            data_sources: vec![self.name().to_string()],
            source_errors: Vec::new(),
        };

        let common_prefixes = vec![
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        ];

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
            source_errors: Vec::new(),
        };

        let domain = domain.trim().trim_end_matches('.').to_lowercase();
        if domain.is_empty()
            || !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(DnsxError::invalid_input(format!(
                "Invalid domain for crt.sh: {}",
                domain
            )));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent(concat!("rdnsx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| DnsxError::Other(e.to_string()))?;

        // q=%.example.com (URL-encoded wildcard); the domain was validated above
        let response = client
            .get("https://crt.sh/")
            .query(&[("q", format!("%.{}", domain).as_str()), ("output", "json")])
            .send()
            .await
            .map_err(|e| DnsxError::Other(format!("crt.sh request failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(DnsxError::Other(format!(
                "crt.sh returned status {}",
                response.status()
            )));
        }
        let entries: Vec<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| DnsxError::Other(format!("Invalid crt.sh response: {}", e)))?;

        // Track first/last certificate logging time per name
        let mut seen: std::collections::HashMap<
            String,
            (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>),
        > = std::collections::HashMap::new();
        for entry in entries {
            let logged = entry
                .get("entry_timestamp")
                .and_then(|t| t.as_str())
                .and_then(|t| chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f").ok())
                .map(|t| t.and_utc());
            let Some(name_value) = entry.get("name_value").and_then(|n| n.as_str()) else {
                continue;
            };
            for name in name_value.split('\n') {
                let clean = name.trim().trim_start_matches("*.").to_lowercase();
                let is_subdomain = clean == domain || clean.ends_with(&format!(".{}", domain));
                if !is_subdomain {
                    continue;
                }
                let ts = logged.unwrap_or_else(chrono::Utc::now);
                let span = seen.entry(clean).or_insert((ts, ts));
                span.0 = span.0.min(ts);
                span.1 = span.1.max(ts);
            }
        }

        let mut names: Vec<_> = seen.into_iter().collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, (first, last)) in names {
            result.subdomains.push(PassiveSubdomain {
                name,
                record_type: "CT".to_string(),
                first_seen: first,
                last_seen: last,
                source: self.name().to_string(),
            });
        }
        result.last_seen = result.subdomains.iter().map(|s| s.last_seen).max();

        Ok(result)
    }
}
