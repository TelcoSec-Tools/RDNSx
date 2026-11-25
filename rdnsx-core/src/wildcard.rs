//! Wildcard DNS filtering

use crate::hickory_ext::LookupExt;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use rand::RngExt;
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
    /// Wildcard answers per zone level (what random names under it resolve to;
    /// an empty pattern means no wildcard)
    patterns: Arc<DashMap<String, WildcardPattern>>,
    /// Random names probed per level
    probes: usize,
    /// Domain for wildcard detection
    base_domain: Option<String>,
    /// Resolver pool for testing wildcards
    resolver_pool: Arc<ResolverPool>,
    /// Wildcard analysis results
    analysis_cache: Arc<DashMap<String, WildcardAnalysis>>,
}

/// Answers that random names under one zone level resolve to
#[derive(Debug, Clone, Default)]
struct WildcardPattern {
    ips: HashSet<IpAddr>,
    /// CNAME targets of the wildcard (lower case, no trailing dot)
    cnames: HashSet<String>,
}

impl WildcardPattern {
    fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.cnames.is_empty()
    }
}

fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

impl WildcardFilter {
    /// Create a new wildcard filter.
    ///
    /// `probes` is the number of random names resolved per zone level (clamped to
    /// 2..=5). More probes catch more of a wildcard's rotating IP pool.
    pub fn new(
        base_domain: Option<String>,
        resolver_pool: Arc<ResolverPool>,
        probes: usize,
    ) -> Self {
        Self {
            patterns: Arc::new(DashMap::new()),
            probes: probes.clamp(2, 5),
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

        // Resolve several random subdomains. A wildcard answers all of them; wildcards
        // backed by round-robin pools may return a different subset of IPs each time.
        const PROBES: usize = 5;
        let mut probe_ips: Vec<std::collections::BTreeSet<String>> = Vec::new();
        for _ in 0..PROBES {
            let test_domain = Self::random_subdomain(domain);
            if let Ok((lookup, _)) = self.resolver_pool.query(&test_domain, RecordType::A).await {
                let mut ips = std::collections::BTreeSet::new();
                for rdata in lookup.iter() {
                    if let hickory_resolver::proto::rr::RData::A(ip) = rdata {
                        ips.insert(ip.to_string());

                        // Store the wildcard record
                        let record = DnsRecord {
                            domain: test_domain.clone(),
                            record_type: crate::types::RecordType::A,
                            value: crate::types::RecordValue::Ip(std::net::IpAddr::V4(ip.0)),
                            ttl: 300,
                            response_code: crate::types::ResponseCode::NoError,
                            resolver: "".to_string(),
                            timestamp: std::time::SystemTime::now(),
                            query_time_ms: 0.0,
                        };
                        analysis.wildcard_records.push(record);
                    }
                }
                if !ips.is_empty() {
                    probe_ips.push(ips);
                }
            }
        }

        // Most random names resolving is a wildcard; identical answers raise confidence
        if probe_ips.len() >= 3 {
            let all_same = probe_ips.iter().all(|ips| ips == &probe_ips[0]);
            let union: std::collections::BTreeSet<String> =
                probe_ips.iter().flatten().cloned().collect();
            analysis.has_wildcard = true;
            analysis.wildcard_ips.extend(union);
            analysis.confidence_score = match (all_same, probe_ips.len() == PROBES) {
                (true, true) => 0.95,
                (true, false) | (false, true) => 0.8,
                (false, false) => 0.6,
            };
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

    /// Find record types the wildcard does not cover.
    ///
    /// A wildcard usually exists for one or two types (A, or a CNAME). If random
    /// names return nothing for another type (MX, TXT, AAAA...), querying candidate
    /// names for that type tells real hosts apart from wildcard matches. A type
    /// counts as a working bypass ("success") when random names get no answer for it.
    async fn attempt_bypass_techniques(&self, domain: &str) -> Vec<WildcardBypassAttempt> {
        let mut attempts = Vec::new();
        for rtype in [
            RecordType::Aaaa,
            RecordType::Mx,
            RecordType::Txt,
            RecordType::Ns,
            RecordType::Soa,
        ] {
            let test_domain = Self::random_subdomain(domain);
            let answer = match self.resolver_pool.query(&test_domain, rtype).await {
                Ok((lookup, _)) => {
                    let first = lookup
                        .answers()
                        .iter()
                        .find(|r| r.record_type() == rtype.to_hickory())
                        .map(|r| r.data.to_string());
                    Some(first)
                }
                Err(_) => None,
            };
            let Some(first) = answer else {
                continue; // no answer at all: inconclusive
            };
            attempts.push(WildcardBypassAttempt {
                technique: format!("Query {} instead of A", rtype),
                test_domain,
                success: first.is_none(),
                response_ip: first,
            });
        }
        attempts
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
        let mut rng = rand::rng();
        let random_str: String = (0..16)
            .map(|_| rng.random_range(b'a'..=b'z') as char)
            .collect();
        format!("{}.{}", random_str, base)
    }

    /// What random (non-existent) names under `domain` resolve to
    async fn pattern(&self, domain: &str) -> WildcardPattern {
        if let Some(p) = self.patterns.get(domain) {
            return p.clone();
        }

        let mut pattern = WildcardPattern::default();
        // Several probes: wildcards backed by round-robin pools return different IPs
        for _ in 0..self.probes {
            let test_domain = Self::random_subdomain(domain);
            for record_type in [RecordType::A, RecordType::Aaaa] {
                if let Ok((lookup, _)) = self.resolver_pool.query(&test_domain, record_type).await {
                    for rdata in lookup.iter() {
                        match rdata {
                            hickory_resolver::proto::rr::RData::A(ip) => {
                                pattern.ips.insert(IpAddr::V4(**ip));
                            }
                            hickory_resolver::proto::rr::RData::AAAA(ip) => {
                                pattern.ips.insert(IpAddr::V6(**ip));
                            }
                            hickory_resolver::proto::rr::RData::CNAME(target) => {
                                pattern.cnames.insert(norm(&target.0.to_string()));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if !pattern.is_empty() {
            debug!("Detected wildcard DNS for {}: {:?}", domain, pattern);
        }
        self.patterns.insert(domain.to_string(), pattern.clone());
        pattern
    }

    /// IPs that random (non-existent) names under `domain` resolve to.
    /// An empty set means the level has no address wildcard.
    pub async fn wildcard_ips(&self, domain: &str) -> HashSet<IpAddr> {
        self.pattern(domain).await.ips
    }

    /// Test if a domain level has wildcard DNS
    pub async fn test_wildcard(&self, domain: &str) -> Result<bool> {
        Ok(!self.pattern(domain).await.is_empty())
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

    /// Whether a CNAME from `domain` to `target` is the wildcard's CNAME
    pub async fn is_wildcard_cname(&self, domain: &str, target: &str) -> bool {
        let target = norm(target);
        for level in self.parent_levels(domain) {
            if self.pattern(&level).await.cnames.contains(&target) {
                return true;
            }
        }
        false
    }

    /// Drop answers explained by a wildcard of a parent level: address records
    /// with a wildcard IP, and CNAMEs to the wildcard's CNAME target together with
    /// the rest of their chain (whose records are owned by the target names).
    /// Non-address records and negative answers are kept.
    pub async fn filter_by_ip(&self, records: Vec<DnsRecord>) -> Result<Vec<DnsRecord>> {
        // Names reached through a wildcard CNAME, followed down the chain
        let mut tainted: HashSet<String> = HashSet::new();
        for record in &records {
            if let crate::types::RecordValue::Domain(target) = &record.value {
                if record.record_type == RecordType::Cname
                    && (tainted.contains(&norm(&record.domain))
                        || self.is_wildcard_cname(&record.domain, target).await)
                {
                    tainted.insert(norm(&record.domain));
                    tainted.insert(norm(target));
                }
            }
        }

        let mut filtered = Vec::with_capacity(records.len());
        for record in records {
            if tainted.contains(&norm(&record.domain)) {
                debug!("Filtered wildcard CNAME chain record {}", record.domain);
                continue;
            }
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
