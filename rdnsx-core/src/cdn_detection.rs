//! CDN detection and analysis
//!
//! A domain is reported as behind a CDN only on direct evidence:
//!
//! 1. its CNAME chain ends in a known CDN suffix (e.g. `*.cloudfront.net`), or
//! 2. one of its addresses is announced by a CDN edge network (live ASN lookup), or
//! 3. one of its addresses is in a CDN's published edge ranges (built-in fallback).
//!
//! Cloud hosting networks (AWS, Google Cloud, Azure, ...) are reported as the hosting
//! provider, not as a CDN: an EC2 instance announced by AS16509 is not behind
//! CloudFront unless the CNAME says so.
//!
//! ASN data comes from the Team Cymru IP-to-ASN DNS service: every address that is
//! analysed is sent (as a DNS name) to `origin.asn.cymru.com` through the configured
//! resolvers. Disable it with [`CdnDetector::with_asn_lookup`] when that matters.

use crate::hickory_ext::LookupExt;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

use hickory_resolver::proto::rr::RData;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::resolver::ResolverPool;
use crate::types::RecordType;

/// Results from CDN detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnDetectionResult {
    pub domain: String,
    /// CDN identified from the CNAME chain or the address ownership
    pub cdn_provider: Option<String>,
    pub cname_chain: Vec<CnameHop>,
    /// First address of the final name (often a CDN edge, not the real origin)
    pub origin_ip: Option<IpAddr>,
    /// All addresses (A and AAAA) of the final name
    pub addresses: Vec<IpAddr>,
    pub analysis: CdnAnalysis,
    pub ttl_analysis: Option<TtlAnalysis>,
    pub geographic_distribution: Option<GeographicDistribution>,
}

/// CNAME chain hop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnameHop {
    pub from: String,
    pub to: String,
}

/// CDN analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnAnalysis {
    pub is_behind_cdn: bool,
    /// 0.0 when there is no evidence; 0.85 to 0.98 depending on how many independent
    /// signals (CNAME, ASN, published ranges) agree
    pub confidence_score: f64,
    pub detected_providers: Vec<String>,
    pub origin_server_info: Option<OriginServerInfo>,
    pub security_implications: Vec<String>,
    pub detection_reasons: Vec<String>,
}

/// TTL of the address records (informational only, not used for detection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlAnalysis {
    pub average_ttl: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
}

/// Network spread of the addresses (informational only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicDistribution {
    /// Distinct RIR registration countries of the announcing prefixes. This is
    /// where the address block is registered, not where the servers are, and
    /// anycast CDNs usually show a single country.
    pub unique_registry_countries: usize,
    pub unique_asns: usize,
    /// Distinct /16 (IPv4) or /32 (IPv6) networks
    pub unique_networks: usize,
    pub is_geographically_distributed: bool,
}

/// Owner information for the first address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginServerInfo {
    pub ip: IpAddr,
    /// The address belongs to a cloud hosting network or a CDN
    pub is_cloud_provider: bool,
    pub provider: Option<String>,
    pub asn_info: Option<AsnInfo>,
}

/// ASN information for an IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: u32,
    pub organization: String,
    /// The AS is a CDN edge network (Cloudflare, Akamai, Fastly, ...)
    pub is_cdn_asn: bool,
    /// The AS is a cloud hosting network (AWS, Google Cloud, Azure, ...)
    pub is_cloud_asn: bool,
    /// Announced prefix covering the IP
    pub prefix: Option<String>,
    /// RIR registration country of the prefix (not the physical location of the server)
    pub country: Option<String>,
    /// Where the data came from: "team-cymru" (live DNS lookup)
    pub source: String,
}

/// CDN edge networks
const CDN_ASNS: &[(u32, &str)] = &[
    (13335, "Cloudflare"),
    (209242, "Cloudflare"),
    (20940, "Akamai"),
    (16625, "Akamai"),
    (12222, "Akamai"),
    (21342, "Akamai"),
    (21399, "Akamai"),
    (32787, "Akamai"),
    (35994, "Akamai"),
    (54113, "Fastly"),
    (60068, "CDN77"),
    (22822, "Edgio (Limelight)"),
    (15133, "Edgio (Edgecast)"),
    (19551, "Imperva Incapsula"),
    (30148, "Sucuri"),
    (200325, "Bunny CDN"),
];

/// Cloud hosting networks: hosting, not by themselves evidence of a CDN
const CLOUD_ASNS: &[(u32, &str)] = &[
    (16509, "Amazon AWS"),
    (14618, "Amazon AWS"),
    (15169, "Google"),
    (396982, "Google Cloud"),
    (19527, "Google"),
    (8075, "Microsoft Azure"),
    (8068, "Microsoft"),
    (8069, "Microsoft"),
    (14061, "DigitalOcean"),
    (63949, "Akamai Connected Cloud (Linode)"),
    (16276, "OVHcloud"),
    (24940, "Hetzner"),
    (31898, "Oracle Cloud"),
    (45102, "Alibaba Cloud"),
];

/// CNAME suffixes of CDN and edge platforms
const CDN_CNAME_SUFFIXES: &[(&str, &str)] = &[
    ("cloudflare.net", "Cloudflare"),
    ("cloudfront.net", "Amazon CloudFront"),
    ("awsglobalaccelerator.com", "AWS Global Accelerator"),
    ("akamai.net", "Akamai"),
    ("akamaiedge.net", "Akamai"),
    ("akamaized.net", "Akamai"),
    ("akamaihd.net", "Akamai"),
    ("edgesuite.net", "Akamai"),
    ("edgekey.net", "Akamai"),
    ("fastly.net", "Fastly"),
    ("fastlylb.net", "Fastly"),
    ("kxcdn.com", "KeyCDN"),
    ("stackpathcdn.com", "StackPath"),
    ("stackpathdns.com", "StackPath"),
    ("b-cdn.net", "Bunny CDN"),
    ("cdn77.org", "CDN77"),
    ("cdn77.net", "CDN77"),
    ("incapdns.net", "Imperva Incapsula"),
    ("impervadns.net", "Imperva Incapsula"),
    ("sucuri.net", "Sucuri"),
    ("llnwd.net", "Edgio (Limelight)"),
    ("llnw.net", "Edgio (Limelight)"),
    ("edgecastcdn.net", "Edgio (Edgecast)"),
    ("edgio.net", "Edgio"),
    ("azureedge.net", "Microsoft Azure CDN"),
    ("azurefd.net", "Microsoft Azure Front Door"),
    ("cachefly.net", "CacheFly"),
    ("netlify.app", "Netlify"),
    ("vercel-dns.com", "Vercel"),
];

/// Published edge ranges, used when the live ASN lookup is disabled or fails.
/// Sources: https://www.cloudflare.com/ips/ and https://api.fastly.com/public-ip-list
/// (main blocks only; the live ASN lookup is authoritative).
const CDN_RANGES: &[(&str, &str)] = &[
    ("173.245.48.0/20", "Cloudflare"),
    ("103.21.244.0/22", "Cloudflare"),
    ("103.22.200.0/22", "Cloudflare"),
    ("103.31.4.0/22", "Cloudflare"),
    ("141.101.64.0/18", "Cloudflare"),
    ("108.162.192.0/18", "Cloudflare"),
    ("190.93.240.0/20", "Cloudflare"),
    ("188.114.96.0/20", "Cloudflare"),
    ("197.234.240.0/22", "Cloudflare"),
    ("198.41.128.0/17", "Cloudflare"),
    ("162.158.0.0/15", "Cloudflare"),
    ("104.16.0.0/13", "Cloudflare"),
    ("104.24.0.0/14", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("131.0.72.0/22", "Cloudflare"),
    ("2400:cb00::/32", "Cloudflare"),
    ("2606:4700::/32", "Cloudflare"),
    ("2803:f800::/32", "Cloudflare"),
    ("2405:b500::/32", "Cloudflare"),
    ("2405:8100::/32", "Cloudflare"),
    ("2a06:98c0::/29", "Cloudflare"),
    ("2c0f:f248::/32", "Cloudflare"),
    ("23.235.32.0/20", "Fastly"),
    ("151.101.0.0/16", "Fastly"),
    ("146.75.0.0/17", "Fastly"),
    ("199.232.0.0/16", "Fastly"),
];

/// CDN detection functionality
pub struct CdnDetector {
    resolver_pool: Arc<ResolverPool>,
    asn_lookup: bool,
}

impl CdnDetector {
    /// Create a new CDN detector (live ASN lookups enabled)
    pub fn new(resolver_pool: Arc<ResolverPool>) -> Self {
        Self {
            resolver_pool,
            asn_lookup: true,
        }
    }

    /// Enable or disable the Team Cymru ASN lookups. Without them only the CNAME
    /// chain and the built-in published ranges are used.
    pub fn with_asn_lookup(mut self, enabled: bool) -> Self {
        self.asn_lookup = enabled;
        self
    }

    /// Detect and analyze CDN usage
    pub async fn detect(&self, domain: &str) -> Result<CdnDetectionResult> {
        info!("Detecting CDN usage for: {}", domain);

        let chain = self.follow_cname_chain(domain).await?;

        let mut addresses = Vec::new();
        let mut ttls = Vec::new();
        for rtype in [RecordType::A, RecordType::Aaaa] {
            if let Ok((lookup, _)) = self.resolver_pool.query(&chain.final_domain, rtype).await {
                for record in lookup.answers() {
                    let ip = match &record.data {
                        RData::A(ip) => IpAddr::V4(ip.0),
                        RData::AAAA(ip) => IpAddr::V6(ip.0),
                        _ => continue,
                    };
                    if !addresses.contains(&ip) {
                        addresses.push(ip);
                    }
                    ttls.push(record.ttl);
                }
            }
        }

        // Owner of every address (one ASN lookup per address)
        let mut owners = Vec::with_capacity(addresses.len());
        for ip in &addresses {
            owners.push((*ip, self.get_asn_info(*ip).await));
        }

        let origin_server_info = owners.first().map(|(ip, asn)| Self::origin_info(*ip, asn));

        let mut result = CdnDetectionResult {
            domain: domain.to_string(),
            cdn_provider: None,
            cname_chain: chain.chain,
            origin_ip: addresses.first().copied(),
            addresses: addresses.clone(),
            analysis: CdnAnalysis {
                is_behind_cdn: false,
                confidence_score: 0.0,
                detected_providers: Vec::new(),
                origin_server_info,
                security_implications: Vec::new(),
                detection_reasons: Vec::new(),
            },
            ttl_analysis: Self::analyze_ttl(&ttls),
            geographic_distribution: (!addresses.is_empty())
                .then(|| Self::analyze_distribution(&owners)),
        };

        Self::analyze(&mut result, chain.provider, &owners);
        Ok(result)
    }

    /// Follow the CNAME chain (at most 10 hops)
    async fn follow_cname_chain(&self, domain: &str) -> Result<CnameChainResult> {
        let mut current = domain.trim_end_matches('.').to_string();
        let mut visited = std::collections::HashSet::new();
        let mut chain = Vec::new();
        let mut provider = None;

        for _ in 0..10 {
            if !visited.insert(current.to_lowercase()) {
                break;
            }
            let Ok((lookup, _)) = self
                .resolver_pool
                .query(&current, RecordType::Cname)
                .await
            else {
                break;
            };
            let Some(target) = lookup.iter().find_map(|r| match r {
                RData::CNAME(c) => Some(c.0.to_string().trim_end_matches('.').to_string()),
                _ => None,
            }) else {
                break;
            };
            chain.push(CnameHop {
                from: current.clone(),
                to: target.clone(),
            });
            if let Some(p) = identify_cdn_provider(&target) {
                provider = Some(p.to_string());
            }
            current = target;
        }

        Ok(CnameChainResult {
            chain,
            provider,
            final_domain: current,
        })
    }

    /// Live ASN lookup (None when disabled or unavailable)
    async fn get_asn_info(&self, ip: IpAddr) -> Option<AsnInfo> {
        if !self.asn_lookup {
            return None;
        }
        let record = crate::asn::lookup_ip_asn(&self.resolver_pool, &ip).await.ok()?;
        Some(AsnInfo {
            asn: record.asn,
            organization: record
                .as_name
                .unwrap_or_else(|| format!("AS{}", record.asn)),
            is_cdn_asn: cdn_asn(record.asn).is_some(),
            is_cloud_asn: cloud_asn(record.asn).is_some(),
            prefix: Some(record.prefix),
            country: record.country,
            source: "team-cymru".to_string(),
        })
    }

    fn origin_info(ip: IpAddr, asn: &Option<AsnInfo>) -> OriginServerInfo {
        let provider = asn
            .as_ref()
            .and_then(|a| cdn_asn(a.asn).or_else(|| cloud_asn(a.asn)))
            .or_else(|| cdn_range(ip))
            .map(str::to_string);
        OriginServerInfo {
            ip,
            is_cloud_provider: provider.is_some(),
            provider,
            asn_info: asn.clone(),
        }
    }

    fn analyze(
        result: &mut CdnDetectionResult,
        cname_provider: Option<String>,
        owners: &[(IpAddr, Option<AsnInfo>)],
    ) {
        let analysis = &mut result.analysis;
        let mut signals = 0usize;
        let mut providers: BTreeSet<String> = BTreeSet::new();

        if let Some(provider) = &cname_provider {
            signals += 1;
            providers.insert(provider.clone());
            analysis
                .detection_reasons
                .push(format!("CNAME chain points to {}", provider));
        }

        let mut asn_hit = false;
        let mut range_hit = false;
        let mut cloud_hosts = BTreeSet::new();
        for (ip, asn) in owners {
            match asn {
                Some(a) if a.is_cdn_asn => {
                    let name = cdn_asn(a.asn).unwrap_or("CDN");
                    providers.insert(name.to_string());
                    if !asn_hit {
                        analysis.detection_reasons.push(format!(
                            "{} is announced by CDN network AS{} ({})",
                            ip, a.asn, a.organization
                        ));
                    }
                    asn_hit = true;
                }
                Some(a) if a.is_cloud_asn => {
                    cloud_hosts.insert(cloud_asn(a.asn).unwrap_or("cloud").to_string());
                }
                Some(_) => {}
                None => {
                    if let Some(name) = cdn_range(*ip) {
                        providers.insert(name.to_string());
                        if !range_hit {
                            analysis.detection_reasons.push(format!(
                                "{} is in {}'s published edge ranges",
                                ip, name
                            ));
                        }
                        range_hit = true;
                    }
                }
            }
        }
        signals += usize::from(asn_hit) + usize::from(range_hit);

        for host in &cloud_hosts {
            analysis.detection_reasons.push(format!(
                "Addresses are hosted on {} (cloud hosting, not by itself a CDN)",
                host
            ));
        }

        analysis.is_behind_cdn = signals > 0;
        analysis.confidence_score = match signals {
            0 => 0.0,
            1 => 0.85,
            _ => 0.98,
        };
        analysis.detected_providers = providers.into_iter().collect();
        result.cdn_provider = cname_provider.or_else(|| analysis.detected_providers.first().cloned());

        if analysis.is_behind_cdn {
            analysis.security_implications.push(
                "Addresses are CDN edges: the origin server is likely not directly visible"
                    .to_string(),
            );
            analysis.security_implications.push(
                "Look for the origin via historical DNS, other subdomains, MX/SPF hosts or certificates"
                    .to_string(),
            );
            if let Some(provider) = &result.cdn_provider {
                analysis
                    .security_implications
                    .extend(provider_security_implications(provider));
            }
        }
    }

    fn analyze_ttl(ttls: &[u32]) -> Option<TtlAnalysis> {
        if ttls.is_empty() {
            return None;
        }
        let sum: u64 = ttls.iter().map(|&t| u64::from(t)).sum();
        Some(TtlAnalysis {
            average_ttl: (sum / ttls.len() as u64) as u32,
            min_ttl: *ttls.iter().min().unwrap_or(&0),
            max_ttl: *ttls.iter().max().unwrap_or(&0),
        })
    }

    fn analyze_distribution(owners: &[(IpAddr, Option<AsnInfo>)]) -> GeographicDistribution {
        let mut asns = BTreeSet::new();
        let mut countries = BTreeSet::new();
        let mut networks = BTreeSet::new();
        for (ip, asn) in owners {
            if let Some(a) = asn {
                asns.insert(a.asn);
                if let Some(c) = &a.country {
                    countries.insert(c.clone());
                }
            }
            networks.insert(match ip {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    format!("{}.{}", o[0], o[1])
                }
                IpAddr::V6(v6) => {
                    let s = v6.segments();
                    format!("{:x}:{:x}", s[0], s[1])
                }
            });
        }
        GeographicDistribution {
            unique_registry_countries: countries.len(),
            unique_asns: asns.len(),
            unique_networks: networks.len(),
            is_geographically_distributed: asns.len() > 1 || networks.len() > 2,
        }
    }
}

/// CDN named by a CNAME target, matched on whole-label suffixes
pub fn identify_cdn_provider(domain: &str) -> Option<&'static str> {
    let domain = domain.trim_end_matches('.').to_lowercase();
    CDN_CNAME_SUFFIXES
        .iter()
        .find(|(suffix, _)| domain == *suffix || domain.ends_with(&format!(".{}", suffix)))
        .map(|(_, name)| *name)
}

fn cdn_asn(asn: u32) -> Option<&'static str> {
    CDN_ASNS.iter().find(|(a, _)| *a == asn).map(|(_, n)| *n)
}

fn cloud_asn(asn: u32) -> Option<&'static str> {
    CLOUD_ASNS.iter().find(|(a, _)| *a == asn).map(|(_, n)| *n)
}

/// CDN whose published edge ranges contain `ip`
pub fn cdn_range(ip: IpAddr) -> Option<&'static str> {
    CDN_RANGES.iter().find_map(|(net, name)| {
        net.parse::<IpNetwork>()
            .ok()
            .filter(|n| n.contains(ip))
            .map(|_| *name)
    })
}

fn provider_security_implications(provider: &str) -> Vec<String> {
    let lines: &[&str] = match provider {
        "Cloudflare" => &[
            "Cloudflare bot management may block or challenge automated scanning",
            "Direct-to-origin access is often still possible if the origin IP leaks",
        ],
        "Akamai" => &["Akamai Bot Manager may block or rate-limit automated scanning"],
        "Fastly" => &["Fastly edges may apply WAF rules (Next-Gen WAF)"],
        "Amazon CloudFront" => &["CloudFront distributions are often paired with AWS WAF and Shield"],
        "Microsoft Azure CDN" | "Microsoft Azure Front Door" => {
            &["Azure Front Door may apply Azure WAF policies"]
        }
        "Imperva Incapsula" => &["Imperva applies WAF and bot protection at the edge"],
        _ => &[],
    };
    lines.iter().map(|s| s.to_string()).collect()
}

/// Result of CNAME chain following
#[derive(Debug)]
struct CnameChainResult {
    chain: Vec<CnameHop>,
    provider: Option<String>,
    final_domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cname_matching_uses_suffixes() {
        assert_eq!(
            identify_cdn_provider("d111111abcdef8.cloudfront.net."),
            Some("Amazon CloudFront")
        );
        assert_eq!(identify_cdn_provider("e1234.a.akamaiedge.net"), Some("Akamai"));
        // Plain AWS, Google and Azure hosting names are not CDNs
        assert_eq!(identify_cdn_provider("bucket.s3.amazonaws.com"), None);
        assert_eq!(identify_cdn_provider("ghs.googlehosted.com"), None);
        assert_eq!(identify_cdn_provider("app.azurewebsites.net"), None);
        // Substrings inside a label don't match
        assert_eq!(identify_cdn_provider("notcloudfront.net.example.com"), None);
        assert_eq!(identify_cdn_provider("myfastly.net"), None);
    }

    #[test]
    fn published_ranges() {
        assert_eq!(cdn_range("104.16.1.1".parse().unwrap()), Some("Cloudflare"));
        assert_eq!(cdn_range("2606:4700::1".parse().unwrap()), Some("Cloudflare"));
        assert_eq!(cdn_range("151.101.1.1".parse().unwrap()), Some("Fastly"));
        // Ranges the old table got wrong
        assert_eq!(cdn_range("34.120.0.1".parse().unwrap()), None);
        assert_eq!(cdn_range("52.1.1.1".parse().unwrap()), None);
        assert_eq!(cdn_range("23.1.1.1".parse().unwrap()), None);
    }

    fn empty_result() -> CdnDetectionResult {
        CdnDetectionResult {
            domain: "example.com".into(),
            cdn_provider: None,
            cname_chain: Vec::new(),
            origin_ip: None,
            addresses: Vec::new(),
            analysis: CdnAnalysis {
                is_behind_cdn: false,
                confidence_score: 0.0,
                detected_providers: Vec::new(),
                origin_server_info: None,
                security_implications: Vec::new(),
                detection_reasons: Vec::new(),
            },
            ttl_analysis: None,
            geographic_distribution: None,
        }
    }

    fn asn(asn: u32) -> Option<AsnInfo> {
        Some(AsnInfo {
            asn,
            organization: format!("AS{}", asn),
            is_cdn_asn: cdn_asn(asn).is_some(),
            is_cloud_asn: cloud_asn(asn).is_some(),
            prefix: None,
            country: Some("US".into()),
            source: "team-cymru".into(),
        })
    }

    #[test]
    fn cloud_hosting_alone_is_not_a_cdn() {
        let mut r = empty_result();
        let owners = vec![("3.5.6.7".parse().unwrap(), asn(16509))];
        CdnDetector::analyze(&mut r, None, &owners);
        assert!(!r.analysis.is_behind_cdn);
        assert_eq!(r.analysis.confidence_score, 0.0);
        assert!(r.cdn_provider.is_none());
    }

    #[test]
    fn cdn_asn_and_cname_agree() {
        let mut r = empty_result();
        let owners = vec![("104.16.1.1".parse().unwrap(), asn(13335))];
        CdnDetector::analyze(&mut r, Some("Cloudflare".into()), &owners);
        assert!(r.analysis.is_behind_cdn);
        assert_eq!(r.analysis.confidence_score, 0.98);
        assert_eq!(r.cdn_provider.as_deref(), Some("Cloudflare"));
    }

    #[test]
    fn range_fallback_without_asn() {
        let mut r = empty_result();
        let owners = vec![("151.101.1.1".parse().unwrap(), None)];
        CdnDetector::analyze(&mut r, None, &owners);
        assert!(r.analysis.is_behind_cdn);
        assert_eq!(r.cdn_provider.as_deref(), Some("Fastly"));
    }
}
