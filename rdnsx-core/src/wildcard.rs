//! Wildcard DNS filtering

use std::collections::HashMap;
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
    /// Wildcard patterns detected (domain -> is_wildcard)
    patterns: Arc<DashMap<String, bool>>,
    /// Domain for wildcard detection
    base_domain: Option<String>,
    /// Resolver pool for testing wildcards
    resolver_pool: Arc<ResolverPool>,
    /// Threshold for considering IP as wildcard (number of domains pointing to same IP)
    threshold: usize,
    /// Wildcard analysis results
    analysis_cache: Arc<DashMap<String, WildcardAnalysis>>,
}

/// Helper struct for domain resolution testing
struct DomainResolutionResult {
    resolved: bool,
    ip: Option<String>,
}

impl WildcardFilter {
    /// Create a new wildcard filter
    pub fn new(
        base_domain: Option<String>,
        resolver_pool: Arc<ResolverPool>,
        threshold: usize,
    ) -> Self {
        Self {
            patterns: Arc::new(DashMap::new()),
            base_domain,
            resolver_pool,
            threshold,
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
                let unique_ips: std::collections::HashSet<_> = test_results.iter().cloned().collect();
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
        self.analysis_cache.insert(domain.to_string(), analysis.clone());

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
                success: !result.resolved,
                response_ip: result.ip,
            });
        }

        // Technique 2: Use very long subdomains
        let long_subdomain = format!("{}.{}", "a".repeat(100), domain);
        let result = self.test_domain_resolution(&long_subdomain).await;
        attempts.push(WildcardBypassAttempt {
            technique: "Long subdomain (>100 chars)".to_string(),
            test_domain: long_subdomain,
            success: !result.resolved,
            response_ip: result.ip,
        });

        // Technique 3: Use underscore in subdomain
        let underscore_domain = format!("test_subdomain.{}", domain);
        let result = self.test_domain_resolution(&underscore_domain).await;
        attempts.push(WildcardBypassAttempt {
            technique: "Underscore in subdomain".to_string(),
            test_domain: underscore_domain,
            success: !result.resolved,
            response_ip: result.ip,
        });

        attempts
    }

    /// Test if a domain resolves (helper for bypass techniques)
    async fn test_domain_resolution(&self, domain: &str) -> DomainResolutionResult {
        match self.resolver_pool.query(domain, RecordType::A).await {
            Ok((lookup, _)) => {
                for rdata in lookup.iter() {
                    if let hickory_resolver::proto::rr::RData::A(ip) = rdata {
                        return DomainResolutionResult {
                            resolved: true,
                            ip: Some(ip.to_string()),
                        };
                    }
                }
                DomainResolutionResult {
                    resolved: false,
                    ip: None,
                }
            }
            Err(_) => DomainResolutionResult {
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
            domain_groups.entry(record.domain.clone())
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
                    debug!("Filtered {} wildcard records for domain {}", domain_records.len(), domain);
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

    /// Test if a domain level has wildcard DNS
    pub async fn test_wildcard(&self, domain: &str) -> Result<bool> {
        // Check cache first
        if let Some(is_wildcard) = self.patterns.get(domain) {
            return Ok(*is_wildcard);
        }

        // Test with a random subdomain that shouldn't exist
        let test_domain = Self::random_subdomain(domain);
        
        match self.resolver_pool.query(&test_domain, RecordType::A).await {
            Ok(_) => {
                // Random domain resolved, likely a wildcard
                self.patterns.insert(domain.to_string(), true);
                debug!("Detected wildcard DNS for {}", domain);
                Ok(true)
            }
            Err(_) => {
                // Random domain didn't resolve, not a wildcard
                self.patterns.insert(domain.to_string(), false);
                Ok(false)
            }
        }
    }

    /// Check if a domain matches a wildcard pattern
    pub async fn is_wildcard(&self, domain: &str) -> Result<bool> {
        // Extract domain levels to test
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return Ok(false);
        }

        // Test each level for wildcards
        for i in 1..parts.len() {
            let domain_to_test = parts[i..].join(".");
            if self.test_wildcard(&domain_to_test).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Filter records by grouping by IP and detecting wildcards
    pub async fn filter_by_ip(&self, records: Vec<DnsRecord>) -> Result<Vec<DnsRecord>> {
        // Group records by IP address
        let mut ip_to_domains: HashMap<String, Vec<DnsRecord>> = HashMap::new();
        
        for record in records {
            if let crate::types::RecordValue::Ip(ip) = &record.value {
                let ip_str = ip.to_string();
                ip_to_domains.entry(ip_str).or_default().push(record);
            } else {
                // Non-IP records, keep them with their value as key
                ip_to_domains
                    .entry(record.value.to_string())
                    .or_default()
                    .push(record);
            }
        }

        let mut filtered = Vec::new();

        // Check each IP group for wildcard patterns
        for (ip, domain_records) in ip_to_domains {
            // If many domains point to same IP, likely a wildcard
            if domain_records.len() >= self.threshold {
                // Test if it's a wildcard
                let mut is_wildcard_ip = false;
                if let Some(first_record) = domain_records.first() {
                    if let Ok(true) = self.is_wildcard(&first_record.domain).await {
                        is_wildcard_ip = true;
                    }
                }

                if !is_wildcard_ip {
                    filtered.extend(domain_records);
                } else {
                    debug!("Filtered {} wildcard records for IP {}", domain_records.len(), ip);
                }
            } else {
                // Small number of domains, likely legitimate
                filtered.extend(domain_records);
            }
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
