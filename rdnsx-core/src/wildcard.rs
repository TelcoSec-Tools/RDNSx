//! Wildcard DNS filtering

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use rand::Rng;
use tracing::debug;

use crate::error::Result;
use crate::resolver::ResolverPool;
use crate::types::RecordType;

use crate::types::DnsRecord;

use serde::{Deserialize, Serialize};

/// Wildcard detection and bypass results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WildcardAnalysis {
    pub domain: String,
    pub has_wildcard: bool,
    pub wildcard_ips: Vec<String>,
    pub wildcard_records: Vec<DnsRecord>,
    pub bypass_attempts: Vec<WildcardBypassAttempt>,
    pub confidence_score: f64, // 0.0 to 1.0
}

/// Attempt to bypass wildcard detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WildcardBypassAttempt {
    pub technique: String,
    pub test_domain: String,
    pub success: bool,
    pub response_ip: Option<String>,
}

/// Enhanced wildcard filter for DNS records with bypass techniques
#[derive(Clone)]
pub struct WildcardFilter {
    /// Wildcard answers per zone level (domain -> IPs returned for random names;
    /// an empty set means no wildcard)
    patterns: Arc<DashMap<String, HashSet<IpAddr>>>,
    /// Domain for wildcard detection
    base_domain: Option<String>,
    /// Resolver pool for testing wildcards
    resolver_pool: Arc<ResolverPool>,
    /// Wildcard analysis results
    analysis_cache: Arc<DashMap<String, WildcardAnalysis>>,
}

/// Helper struct for domain resolution testing
struct DomainResolutionResult {
    /// The resolver gave an answer (as opposed to an invalid name or a network error)
    answered: bool,
    resolved: bool,
    ip: Option<String>,
}

impl WildcardFilter {
    /// Create a new wildcard filter
    pub fn new(
        base_domain: Option<String>,
        resolver_pool: Arc<ResolverPool>,
        _threshold: usize,
    ) -> Self {
        Self {
            patterns: Arc::new(DashMap::new()),
            base_domain,
            resolver_pool,
            analysis_cache: Arc::new(DashMap::new()),
        }
    }

    /// Perform comprehensive wildcard analysis for a domain
    pub async fn analyze_wildcard(&self, domain: &str) -> Result<WildcardAnalysis> {
        // Check cache first
        if let Some(analysis) = self.analysis_cache.get(domain) {
            return Ok(analysis.clone());
        }

        let mut analysis = WildcardAnalysis {
            domain: domain.to_string(),
            has_wildcard: false,
            wildcard_ips: Vec::new(),
            wildcard_records: Vec::new(),
            bypass_attempts: Vec::new(),
            confidence_score: 0.0,
        };

        // Test multiple random subdomains for consistency
        let mut test_results = Vec::new();
        for _ in 0..5 {
            let test_domain = Self::random_subdomain(domain);
            if let Ok((lookup, _)) = self.resolver_pool.query(&test_domain, RecordType::A).await {
                for rdata in lookup.iter() {
                    if let hickory_resolver::proto::rr::RData::A(ip) = rdata {
                        let ip_str = ip.to_string();
                        test_results.push(ip_str.clone());

                        // Store the wildcard record
                        let record = DnsRecord {
                            domain: test_domain.clone(),
                            record_type: crate::types::RecordType::A,
                            value: crate::types::RecordValue::Ip(std::net::IpAddr::V4(**ip)),
                            ttl: 300,
                            response_code: crate::types::ResponseCode::NoError,
                            resolver: "".to_string(),
                            timestamp: std::time::SystemTime::now(),
                            query_time_ms: 0.0,
                        };
                        analysis.wildcard_records.push(record);
                    }
                }
            }
        }

        // Analyze results for wildcard patterns
        if !test_results.is_empty() {
            // Check if all test domains resolve to the same IP (strong wildcard indicator)
            let first_ip = &test_results[0];
            let all_same = test_results.iter().all(|ip| ip == first_ip);

            if all_same && test_results.len() >= 3 {
                analysis.has_wildcard = true;
                analysis.wildcard_ips.push(first_ip.clone());
                analysis.confidence_score = 0.9;
            } else {
                // Check for patterns in IPs (weaker indicator)
                let unique_ips: std::collections::HashSet<_> =
                    test_results.iter().cloned().collect();
                if unique_ips.len() == 1 {
                    analysis.has_wildcard = true;
                    analysis.wildcard_ips.extend(unique_ips);
                    analysis.confidence_score = 0.7;
                }
            }
        }

        // Attempt wildcard bypass techniques
        if analysis.has_wildcard {
            analysis.bypass_attempts = self.attempt_bypass_techniques(domain).await;
        }

        // Cache the analysis
        self.analysis_cache
            .insert(domain.to_string(), analysis.clone());

        Ok(analysis)
    }

    /// Attempt various wildcard bypass techniques
    async fn attempt_bypass_techniques(&self, domain: &str) -> Vec<WildcardBypassAttempt> {
        let mut attempts = Vec::new();

        // Technique 1: Use invalid DNS characters
        let invalid_chars = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")"];
        for &ch in &invalid_chars {
            let test_domain = format!("test{}.{}", ch, domain);
            let result = self.test_domain_resolution(&test_domain).await;
            attempts.push(WildcardBypassAttempt {
                technique: format!("Invalid character: {}", ch),
                test_domain,
                success: result.answered && !result.resolved,
                response_ip: result.ip,
            });
        }

        // Technique 2: Use very long subdomains
        let long_subdomain = format!("{}.{}", "a".repeat(100), domain);
        let result = self.test_domain_resolution(&long_subdomain).await;
        attempts.push(WildcardBypassAttempt {
            technique: "Long subdomain (>100 chars)".to_string(),
            test_domain: long_subdomain,
            success: result.answered && !result.resolved,
            response_ip: result.ip,
        });

        // Technique 3: Use underscore in subdomain
        let underscore_domain = format!("test_subdomain.{}", domain);
        let result = self.test_domain_resolution(&underscore_domain).await;
        attempts.push(WildcardBypassAttempt {
            technique: "Underscore in subdomain".to_string(),
            test_domain: underscore_domain,
            success: result.answered && !result.resolved,
            response_ip: result.ip,
        });

        attempts
    }

    /// Test if a domain resolves (helper for bypass techniques)
    async fn test_domain_resolution(&self, domain: &str) -> DomainResolutionResult {
        match self.resolver_pool.query(domain, RecordType::A).await {
            Ok((lookup, _)) => {
                let ip = lookup.iter().find_map(|rdata| match rdata {
                    hickory_resolver::proto::rr::RData::A(ip) => Some(ip.to_string()),
                    _ => None,
                });
                DomainResolutionResult {
                    answered: true,
                    resolved: ip.is_some(),
                    ip,
                }
            }
            Err(_) => DomainResolutionResult {
                answered: false,
                resolved: false,
                ip: None,
            },
        }
    }

    /// Get wildcard analysis for a domain
    pub async fn get_wildcard_analysis(&self, domain: &str) -> Result<WildcardAnalysis> {
        self.analyze_wildcard(domain).await
    }

    /// Advanced filtering with wildcard analysis
    pub async fn advanced_filter(&self, records: Vec<DnsRecord>) -> Result<Vec<DnsRecord>> {
        if self.base_domain.is_none() {
            return Ok(records);
        }

        let mut filtered = Vec::new();
        let mut domain_groups: HashMap<String, Vec<DnsRecord>> = HashMap::new();

        // Group records by domain
        for record in records {
            domain_groups
                .entry(record.domain.clone())
                .or_default()
                .push(record);
        }

        // Analyze each domain group
        for (domain, domain_records) in domain_groups {
            let analysis = self.analyze_wildcard(&domain).await?;

            if analysis.has_wildcard && analysis.confidence_score > 0.7 {
                // Check if domain records match wildcard pattern
                let should_filter = domain_records.iter().any(|record| {
                    if let crate::types::RecordValue::Ip(ip) = &record.value {
                        analysis.wildcard_ips.contains(&ip.to_string())
                    } else {
                        false
                    }
                });

                if !should_filter {
                    filtered.extend(domain_records);
                } else {
                    debug!(
                        "Filtered {} wildcard records for domain {}",
                        domain_records.len(),
                        domain
                    );
                }
            } else {
                // No wildcard detected, keep all records
                filtered.extend(domain_records);
            }
        }

        Ok(filtered)
    }

    /// Generate a random subdomain for testing wildcards
    fn random_subdomain(base: &str) -> String {
        let mut rng = rand::thread_rng();
        let random_str: String = (0..16)
            .map(|_| rng.gen_range(b'a'..=b'z') as char)
            .collect();
        format!("{}.{}", random_str, base)
    }

    /// IPs that random (non-existent) names under `domain` resolve to.
    /// An empty set means the level has no wildcard.
    pub async fn wildcard_ips(&self, domain: &str) -> HashSet<IpAddr> {
        if let Some(ips) = self.patterns.get(domain) {
            return ips.clone();
        }

        let mut ips = HashSet::new();
        // Two probes: wildcards backed by round-robin pools may return different IPs
        for _ in 0..2 {
            let test_domain = Self::random_subdomain(domain);
            for record_type in [RecordType::A, RecordType::Aaaa] {
                if let Ok((lookup, _)) = self.resolver_pool.query(&test_domain, record_type).await {
                    for rdata in lookup.iter() {
                        match rdata {
                            hickory_resolver::proto::rr::RData::A(ip) => {
                                ips.insert(IpAddr::V4(**ip));
                            }
                            hickory_resolver::proto::rr::RData::AAAA(ip) => {
                                ips.insert(IpAddr::V6(**ip));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if !ips.is_empty() {
            debug!("Detected wildcard DNS for {}: {:?}", domain, ips);
        }
        self.patterns.insert(domain.to_string(), ips.clone());
        ips
    }

    /// Test if a domain level has wildcard DNS
    pub async fn test_wildcard(&self, domain: &str) -> Result<bool> {
        Ok(!self.wildcard_ips(domain).await.is_empty())
    }

    /// Parent levels of `domain` to test for wildcards, closest first, stopping at the
    /// base domain if one was given.
    fn parent_levels(&self, domain: &str) -> Vec<String> {
        let domain = domain.trim_end_matches('.');
        let parts: Vec<&str> = domain.split('.').collect();
        let base = self.base_domain.as_deref().map(|b| b.trim_end_matches('.'));
        let mut levels = Vec::new();
        for i in 1..parts.len() {
            let level = parts[i..].join(".");
            if parts.len() - i < 2 {
                break; // don't probe TLDs
            }
            if let Some(base) = base {
                if !(level == base || level.ends_with(&format!(".{}", base))) {
                    break;
                }
            }
            levels.push(level);
        }
        levels
    }

    /// Check if a domain sits under a wildcard
    pub async fn is_wildcard(&self, domain: &str) -> Result<bool> {
        for level in self.parent_levels(domain) {
            if self.test_wildcard(&level).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether a specific answer is explained by a wildcard above `domain`
    pub async fn is_wildcard_answer(&self, domain: &str, ip: &IpAddr) -> bool {
        for level in self.parent_levels(domain) {
            if self.wildcard_ips(&level).await.contains(ip) {
                return true;
            }
        }
        false
    }

    /// Drop address records whose IP matches the wildcard answer of a parent level.
    /// Non-address records and negative answers are kept.
    pub async fn filter_by_ip(&self, records: Vec<DnsRecord>) -> Result<Vec<DnsRecord>> {
        let mut filtered = Vec::with_capacity(records.len());
        for record in records {
            if let crate::types::RecordValue::Ip(ip) = &record.value {
                if self.is_wildcard_answer(&record.domain, ip).await {
                    debug!("Filtered wildcard record {} -> {}", record.domain, ip);
                    continue;
                }
            }
            filtered.push(record);
        }
        Ok(filtered)
    }

    /// Filter records to remove wildcard matches
    pub async fn filter(&self, records: Vec<DnsRecord>) -> Result<Vec<DnsRecord>> {
        if self.base_domain.is_none() {
            // No base domain specified, skip wildcard filtering
            return Ok(records);
        }

        // Use IP-based filtering for efficiency
        self.filter_by_ip(records).await
    }
}
