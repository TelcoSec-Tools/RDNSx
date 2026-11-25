//! CDN detection and analysis

use crate::hickory_ext::LookupExt;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

use crate::error::Result;
use crate::resolver::ResolverPool;
use crate::types::RecordType;

use serde::{Deserialize, Serialize};

/// Results from CDN detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnDetectionResult {
    pub domain: String,
    pub cdn_provider: Option<String>,
    pub cname_chain: Vec<CnameHop>,
    pub origin_ip: Option<IpAddr>,
    pub analysis: CdnAnalysis,
    pub ttl_analysis: Option<TtlAnalysis>,
    pub geographic_distribution: Option<GeographicDistribution>,
    pub response_time_analysis: Option<ResponseTimeAnalysis>,
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
    pub confidence_score: f64,
    pub detected_providers: Vec<String>,
    pub origin_server_info: Option<OriginServerInfo>,
    pub security_implications: Vec<String>,
    pub detection_reasons: Vec<String>,
}

/// TTL analysis for CDN detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlAnalysis {
    pub average_ttl: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub ttl_consistency_score: f64,
    pub cdn_typical_ttl: bool,
}

/// Geographic distribution analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicDistribution {
    /// Distinct registry countries of the announcing prefixes (0 when unknown)
    pub unique_countries: usize,
    pub unique_asns: usize,
    pub is_geographically_distributed: bool,
    pub distribution_score: f64,
}

/// Response time analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTimeAnalysis {
    pub average_response_time_ms: f64,
    pub min_response_time_ms: f64,
    pub max_response_time_ms: f64,
    pub response_consistency_score: f64,
    pub cdn_typical_performance: bool,
}

/// Origin server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginServerInfo {
    pub ip: IpAddr,
    pub is_cloud_provider: bool,
    pub provider: Option<String>,
    pub asn_info: Option<AsnInfo>,
}

/// ASN information for IP addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: u32,
    pub organization: String,
    pub is_cdn_asn: bool,
    /// Announced prefix covering the IP
    pub prefix: Option<String>,
    /// Registry country of the prefix (not the physical location of the server)
    pub country: Option<String>,
    /// Where the data came from: "team-cymru" (live DNS lookup) or
    /// "heuristic" (built-in, incomplete IP range table)
    pub source: String,
}

/// CDN detection functionality
pub struct CdnDetector {
    resolver_pool: Arc<ResolverPool>,
}

impl CdnDetector {
    /// Create a new CDN detector
    pub fn new(resolver_pool: Arc<ResolverPool>) -> Self {
        Self { resolver_pool }
    }

    /// Detect and analyze CDN usage
    pub async fn detect(&self, domain: &str) -> Result<CdnDetectionResult> {
        info!("Detecting CDN usage for: {}", domain);

        let mut result = CdnDetectionResult {
            domain: domain.to_string(),
            cdn_provider: None,
            cname_chain: Vec::new(),
            origin_ip: None,
            ttl_analysis: None,
            geographic_distribution: None,
            response_time_analysis: None,
            analysis: CdnAnalysis {
                is_behind_cdn: false,
                confidence_score: 0.0,
                detected_providers: Vec::new(),
                origin_server_info: None,
                security_implications: Vec::new(),
                detection_reasons: Vec::new(),
            },
        };

        // Follow CNAME chain
        let cname_result = self.follow_cname_chain(domain).await?;
        result.cname_chain = cname_result.chain;
        result.cdn_provider = cname_result.provider;

        // Resolve final domain to IP and gather additional data
        let mut all_ips = Vec::new();
        let mut all_ttls = Vec::new();

        if let Ok((lookup, _)) = self
            .resolver_pool
            .query(&cname_result.final_domain, crate::RecordType::A)
            .await
        {
            for record in lookup.answers() {
                if let hickory_resolver::proto::rr::RData::A(ip) = &record.data {
                    let ip_addr = IpAddr::V4(ip.0);
                    all_ips.push(ip_addr);
                    all_ttls.push(record.ttl);
                }
            }

            if !all_ips.is_empty() {
                result.origin_ip = Some(all_ips[0]);

                // Analyze origin server
                let origin_info = self.analyze_origin_server(all_ips[0]).await?;
                result.analysis.origin_server_info = Some(origin_info);
            }
        }

        // Perform TTL analysis
        if !all_ttls.is_empty() {
            result.ttl_analysis = Some(self.analyze_ttl(&all_ttls));
        }

        // Perform geographic distribution analysis
        if !all_ips.is_empty() {
            result.geographic_distribution =
                Some(self.analyze_geographic_distribution(&all_ips).await?);
        }

        // Perform response time analysis
        result.response_time_analysis = Some(
            self.analyze_response_time(&cname_result.final_domain)
                .await?,
        );

        // Perform comprehensive analysis
        result.analysis = self.analyze_cdn_usage(&result).await?;

        Ok(result)
    }

    /// Follow CNAME chain and detect CDN providers
    async fn follow_cname_chain(&self, domain: &str) -> Result<CnameChainResult> {
        let mut current_domain = domain.to_string();
        let mut visited = std::collections::HashSet::new();
        let mut chain = Vec::new();
        let mut provider = None;

        for _ in 0..10 {
            // Prevent infinite loops
            if visited.contains(&current_domain) {
                break;
            }
            visited.insert(current_domain.clone());

            if let Ok((lookup, _)) = self
                .resolver_pool
                .query(&current_domain, RecordType::Cname)
                .await
            {
                if let Some(hickory_resolver::proto::rr::RData::CNAME(cname)) = lookup.iter().next()
                {
                    let cname_target = cname.to_string();
                    chain.push(CnameHop {
                        from: current_domain.clone(),
                        to: cname_target.clone(),
                    });

                    current_domain = cname_target;

                    // Check if this looks like a CDN
                    if let Some(detected_provider) = Self::identify_cdn_provider(&current_domain) {
                        provider = Some(detected_provider);
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(CnameChainResult {
            chain,
            provider,
            final_domain: current_domain,
        })
    }

    /// Identify CDN provider from domain patterns with improved heuristics
    fn identify_cdn_provider(domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();

        // Major CDN providers with comprehensive pattern matching
        if domain_lower.contains("cloudflare")
            || domain_lower.contains("cdn.cloudflare")
            || domain_lower.ends_with(".cloudflare.net")
            || domain_lower.ends_with(".cloudflarestream.com")
        {
            Some("Cloudflare".to_string())
        } else if domain_lower.contains("cloudfront")
            || domain_lower.contains("amazonaws")
            || domain_lower.ends_with(".cloudfront.net")
            || domain_lower.contains("awsglobalaccelerator")
        {
            Some("Amazon CloudFront".to_string())
        } else if domain_lower.contains("akamai")
            || domain_lower.contains("edgesuite")
            || domain_lower.contains("edgekey")
            || domain_lower.contains("akamaiedge")
            || domain_lower.ends_with(".akamai.net")
            || domain_lower.ends_with(".akamaized.net")
        {
            Some("Akamai".to_string())
        } else if domain_lower.contains("fastly")
            || domain_lower.ends_with(".fastly.net")
            || domain_lower.contains("fastlylb")
        {
            Some("Fastly".to_string())
        } else if domain_lower.contains("keycdn") || domain_lower.ends_with(".kxcdn.com") {
            Some("KeyCDN".to_string())
        } else if domain_lower.contains("stackpath")
            || domain_lower.contains("stackpathcdn")
            || domain_lower.ends_with(".stackpathcdn.com")
        {
            Some("StackPath".to_string())
        } else if domain_lower.contains("bunnycdn")
            || domain_lower.contains("bunny.net")
            || domain_lower.ends_with(".b-cdn.net")
        {
            Some("Bunny CDN".to_string())
        } else if domain_lower.contains("cdn77") || domain_lower.contains("cdn77.net") {
            Some("CDN77".to_string())
        } else if domain_lower.contains("incapsula")
            || domain_lower.contains("imperva")
            || domain_lower.contains("iphlp")
            || domain_lower.ends_with(".incapdns.net")
        {
            Some("Imperva Incapsula".to_string())
        } else if domain_lower.contains("sucuri") || domain_lower.ends_with(".sucuri.net") {
            Some("Sucuri".to_string())
        } else if domain_lower.contains("stackpath") || domain_lower.ends_with(".stackpathdns.com")
        {
            Some("StackPath".to_string())
        } else if domain_lower.contains("cdnify")
            || domain_lower.contains("limelight")
            || domain_lower.ends_with(".llnwd.net")
        {
            Some("Limelight Networks".to_string())
        } else if domain_lower.contains("level3")
            || domain_lower.contains("centurylink")
            || domain_lower.ends_with(".level3.net")
        {
            Some("CenturyLink/Level3".to_string())
        } else if domain_lower.contains("cdn.video")
            || domain_lower.contains("cdnsun")
            || domain_lower.ends_with(".cdnsun.net")
        {
            Some("CDN Sun".to_string())
        } else if domain_lower.contains("chinacache") || domain_lower.contains("c3cache") {
            Some("ChinaCache".to_string())
        } else if domain_lower.contains("azure")
            || domain_lower.contains("azureedge")
            || domain_lower.ends_with(".azureedge.net")
        {
            Some("Microsoft Azure CDN".to_string())
        } else if domain_lower.contains("google")
            || domain_lower.contains("googlevideo")
            || domain_lower.ends_with(".googleusercontent.com")
            || domain_lower.ends_with(".appspot.com")
        {
            Some("Google Cloud CDN".to_string())
        } else if domain_lower.contains("verizon")
            || domain_lower.contains("edgecast")
            || domain_lower.ends_with(".edgecastcdn.net")
        {
            Some("Verizon EdgeCast".to_string())
        } else if domain_lower.contains("leaseweb") || domain_lower.ends_with(".leasewebcdn.com") {
            Some("Leaseweb CDN".to_string())
        } else if domain_lower.contains("highwinds") || domain_lower.contains("cdn.highwinds") {
            Some("Highwinds".to_string())
        } else if domain_lower.contains("cachefly") {
            Some("CacheFly".to_string())
        } else if domain_lower.contains("mirror-image") || domain_lower.contains("mirrorimage") {
            Some("Mirror Image".to_string())
        } else if domain_lower.contains("cdn.jsdelivr") || domain_lower.contains("jsdelivr") {
            Some("jsDelivr".to_string())
        } else if domain_lower.contains("unpkg") {
            Some("UNPKG".to_string())
        } else if domain_lower.contains("cdnjs") {
            Some("CDNJS".to_string())
        } else if domain_lower.contains("bootcdn") {
            Some("BootCDN".to_string())
        } else {
            None
        }
    }

    /// Analyze origin server information with comprehensive IP range detection
    async fn analyze_origin_server(&self, ip: IpAddr) -> Result<OriginServerInfo> {
        let mut info = OriginServerInfo {
            ip,
            is_cloud_provider: false,
            provider: None,
            asn_info: None,
        };

        // Get ASN information
        if let Ok(asn_info) = self.get_asn_info(ip).await {
            info.asn_info = Some(asn_info);
        }

        // Check if IP belongs to known cloud providers and CDNs
        if let IpAddr::V4(ipv4) = ip {
            let octets = ipv4.octets();
            let ip_u32 = u32::from_be_bytes(octets);

            // Amazon AWS ranges (comprehensive)
            if Self::is_aws_ip(ip_u32) {
                info.is_cloud_provider = true;
                info.provider = Some("Amazon AWS".to_string());
            }
            // Google Cloud ranges (comprehensive)
            else if Self::is_google_cloud_ip(ip_u32) {
                info.is_cloud_provider = true;
                info.provider = Some("Google Cloud".to_string());
            }
            // Microsoft Azure ranges (comprehensive)
            else if Self::is_azure_ip(ip_u32) {
                info.is_cloud_provider = true;
                info.provider = Some("Microsoft Azure".to_string());
            }
            // DigitalOcean ranges
            else if Self::is_digitalocean_ip(ip_u32) {
                info.is_cloud_provider = true;
                info.provider = Some("DigitalOcean".to_string());
            }
            // Linode ranges
            else if Self::is_linode_ip(ip_u32) {
                info.is_cloud_provider = true;
                info.provider = Some("Linode".to_string());
            }
            // Cloudflare IP ranges (for origin servers that might be Cloudflare)
            else if Self::is_cloudflare_ip(ip_u32) {
                info.is_cloud_provider = true;
                info.provider = Some("Cloudflare".to_string());
            }
            // Akamai IP ranges
            else if Self::is_akamai_ip(ip_u32) {
                info.is_cloud_provider = true;
                info.provider = Some("Akamai".to_string());
            }
            // Fastly IP ranges
            else if Self::is_fastly_ip(ip_u32) {
                info.is_cloud_provider = true;
                info.provider = Some("Fastly".to_string());
            }
        }

        // Prefer live ASN data over the built-in range table
        if info.provider.is_none() {
            if let Some(asn) = info.asn_info.as_ref().filter(|a| a.is_cdn_asn) {
                info.is_cloud_provider = true;
                info.provider = Some(asn.organization.clone());
            }
        }

        Ok(info)
    }

    /// Get ASN information for an IP address.
    ///
    /// Uses the Team Cymru IP-to-ASN DNS service; falls back to a built-in table
    /// of well-known provider ranges (marked `source: "heuristic"`).
    async fn get_asn_info(&self, ip: IpAddr) -> Result<AsnInfo> {
        const CDN_ASNS: &[u32] = &[
            13335, 209242, // Cloudflare
            20940, 16625, 12222, 21342, 21399, 32787, 35994, // Akamai
            54113, // Fastly
            16509, 14618, // Amazon
            15169, 396982, 19527, // Google
            8068, 8075, 8069, // Microsoft
            60068, 12008,  // CDN77 / StackPath
            22822,  // Edgio / Limelight
            19551,  // Imperva Incapsula
            30148,  // Sucuri
            13414,  // Twitter
            32934,  // Facebook
            200325, // bunny.net
        ];

        if let Ok(record) = crate::asn::lookup_ip_asn(&self.resolver_pool, &ip).await {
            return Ok(AsnInfo {
                asn: record.asn,
                organization: record
                    .as_name
                    .unwrap_or_else(|| format!("AS{}", record.asn)),
                is_cdn_asn: CDN_ASNS.contains(&record.asn),
                prefix: Some(record.prefix),
                country: record.country,
                source: "team-cymru".to_string(),
            });
        }

        if let IpAddr::V4(ipv4) = ip {
            let ip_u32 = u32::from_be_bytes(ipv4.octets());
            let known = [
                (13335, "Cloudflare"),
                (20940, "Akamai"),
                (54113, "Fastly"),
                (16509, "Amazon"),
                (15169, "Google"),
                (8075, "Microsoft"),
            ];
            for (asn, org) in known {
                if Self::is_asn_range(ip_u32, asn) {
                    return Ok(AsnInfo {
                        asn,
                        organization: org.to_string(),
                        is_cdn_asn: true,
                        prefix: None,
                        country: None,
                        source: "heuristic".to_string(),
                    });
                }
            }
        }

        Err(crate::error::DnsxError::Other(format!(
            "ASN unknown for {}",
            ip
        )))
    }

    /// Simple ASN range detection (simplified for demo)
    fn is_asn_range(ip: u32, asn: u32) -> bool {
        // This is a very simplified ASN detection
        // Real ASN detection would require a proper ASN database
        match asn {
            13335 => Self::is_cloudflare_ip(ip),            // Cloudflare
            20940 | 16625 => Self::is_akamai_ip(ip),        // Akamai
            54113 => Self::is_fastly_ip(ip),                // Fastly
            16509 => Self::is_aws_ip(ip),                   // AWS
            396982 | 15169 => Self::is_google_cloud_ip(ip), // Google
            8068 | 8075 => Self::is_azure_ip(ip),           // Azure
            _ => false,
        }
    }

    /// Check if IP belongs to AWS ranges
    fn is_aws_ip(ip: u32) -> bool {
        // AWS EC2 ranges (major regions, simplified for performance)
        let aws_ranges = [
            // us-east-1: 3.0.0.0/8, 52.0.0.0/8, 54.0.0.0/8
            (0x03000000, 0x03FFFFFF), // 3.0.0.0/8
            (0x34000000, 0x34FFFFFF), // 52.0.0.0/8
            (0x36000000, 0x36FFFFFF), // 54.0.0.0/8
            // us-west-2: 13.248.0.0/14, 18.0.0.0/8, 34.0.0.0/8
            (0x0DF80000, 0x0DFBFFFF), // 13.248.0.0/14
            (0x12000000, 0x12FFFFFF), // 18.0.0.0/8
            (0x22000000, 0x22FFFFFF), // 34.0.0.0/8
            // eu-west-1: 34.240.0.0/13, 52.208.0.0/13
            (0x22F00000, 0x22F7FFFF), // 34.240.0.0/13
            (0x34D00000, 0x34D7FFFF), // 52.208.0.0/13
        ];

        aws_ranges
            .iter()
            .any(|&(start, end)| ip >= start && ip <= end)
    }

    /// Check if IP belongs to Google Cloud ranges
    fn is_google_cloud_ip(ip: u32) -> bool {
        let google_ranges = [
            // Google Cloud: 35.184.0.0/13, 35.192.0.0/14, 35.196.0.0/15, etc.
            (0x23B80000, 0x23BFFFFF), // 35.184.0.0/13
            (0x23C00000, 0x23C3FFFF), // 35.192.0.0/14
            (0x23C40000, 0x23C5FFFF), // 35.196.0.0/15
            (0x23C80000, 0x23CBFFFF), // 35.200.0.0/13
            (0x23D00000, 0x23D3FFFF), // 35.208.0.0/12
        ];

        google_ranges
            .iter()
            .any(|&(start, end)| ip >= start && ip <= end)
    }

    /// Check if IP belongs to Azure ranges
    fn is_azure_ip(ip: u32) -> bool {
        let azure_ranges = [
            // Azure: 20.0.0.0/8, 40.64.0.0/12, 52.0.0.0/8, etc.
            (0x14000000, 0x14FFFFFF), // 20.0.0.0/8
            (0x28400000, 0x284FFFFF), // 40.64.0.0/12
            (0x28600000, 0x287FFFFF), // 40.96.0.0/12
            (0x28800000, 0x289FFFFF), // 40.112.0.0/12
            (0x34C00000, 0x34FFFFFF), // 52.192.0.0/10
        ];

        azure_ranges
            .iter()
            .any(|&(start, end)| ip >= start && ip <= end)
    }

    /// Check if IP belongs to DigitalOcean ranges
    fn is_digitalocean_ip(ip: u32) -> bool {
        let do_ranges = [
            // DigitalOcean: 10.0.0.0/8, 45.55.0.0/16, 104.131.0.0/16, etc.
            (0x2D370000, 0x2D37FFFF), // 45.55.0.0/16
            (0x68830000, 0x6883FFFF), // 104.131.0.0/16
            (0x68840000, 0x6884FFFF), // 104.132.0.0/16
            (0x68870000, 0x6887FFFF), // 104.135.0.0/16
        ];

        do_ranges
            .iter()
            .any(|&(start, end)| ip >= start && ip <= end)
    }

    /// Check if IP belongs to Linode ranges
    fn is_linode_ip(ip: u32) -> bool {
        let linode_ranges = [
            // Linode: 45.33.0.0/16, 66.228.0.0/16, 96.126.0.0/16, etc.
            (0x2D210000, 0x2D21FFFF), // 45.33.0.0/16
            (0x42E40000, 0x42E4FFFF), // 66.228.0.0/16
            (0x607E0000, 0x607EFFFF), // 96.126.0.0/16
            (0x618C0000, 0x618CFFFF), // 97.107.128.0/17
        ];

        linode_ranges
            .iter()
            .any(|&(start, end)| ip >= start && ip <= end)
    }

    /// Check if IP belongs to Cloudflare ranges
    fn is_cloudflare_ip(ip: u32) -> bool {
        let cf_ranges = [
            // Cloudflare: 173.245.48.0/20, 103.21.244.0/22, etc.
            (0xADF53000, 0xADF53FFF), // 173.245.48.0/20
            (0x6715F400, 0x6715F7FF), // 103.21.244.0/22
            (0x6721F000, 0x6721F3FF), // 103.31.240.0/22
        ];

        cf_ranges
            .iter()
            .any(|&(start, end)| ip >= start && ip <= end)
    }

    /// Check if IP belongs to Akamai ranges
    fn is_akamai_ip(ip: u32) -> bool {
        let akamai_ranges = [
            // Akamai: 23.0.0.0/8, 45.64.0.0/16, 92.122.0.0/15, etc.
            (0x17000000, 0x17FFFFFF), // 23.0.0.0/8
            (0x2D400000, 0x2D40FFFF), // 45.64.0.0/16
            (0x5C7A0000, 0x5C7BFFFF), // 92.122.0.0/15
        ];

        akamai_ranges
            .iter()
            .any(|&(start, end)| ip >= start && ip <= end)
    }

    /// Check if IP belongs to Fastly ranges
    fn is_fastly_ip(ip: u32) -> bool {
        let fastly_ranges = [
            // Fastly: 23.235.32.0/20, 43.249.72.0/22, etc.
            (0x17EB2000, 0x17EB2FFF), // 23.235.32.0/20
            (0x2BF94800, 0x2BF94BFF), // 43.249.72.0/22
            (0x2BF96000, 0x2BF963FF), // 43.249.96.0/22
        ];

        fastly_ranges
            .iter()
            .any(|&(start, end)| ip >= start && ip <= end)
    }

    /// Perform comprehensive CDN analysis
    async fn analyze_cdn_usage(&self, result: &CdnDetectionResult) -> Result<CdnAnalysis> {
        let mut analysis = CdnAnalysis {
            is_behind_cdn: false,
            confidence_score: 0.0,
            detected_providers: Vec::new(),
            origin_server_info: result.analysis.origin_server_info.clone(),
            security_implications: Vec::new(),
            detection_reasons: Vec::new(),
        };

        let mut score = 0.0;
        let mut reasons = Vec::new();

        // High confidence indicators (weight: 0.8-1.0)
        if let Some(provider) = &result.cdn_provider {
            analysis.detected_providers.push(provider.clone());
            score += 0.9;
            reasons.push(format!("Explicit CDN provider detected: {}", provider));
        }

        // Medium confidence indicators (weight: 0.4-0.7)
        if let Some(ttl_analysis) = &result.ttl_analysis {
            if ttl_analysis.cdn_typical_ttl {
                score += 0.5;
                reasons.push(format!(
                    "TTL pattern typical for CDN (avg: {}s)",
                    ttl_analysis.average_ttl
                ));
            }
            if ttl_analysis.ttl_consistency_score > 0.7 {
                score += 0.3;
                reasons.push("High TTL consistency across records".to_string());
            }
        }

        if let Some(resp_analysis) = &result.response_time_analysis {
            if resp_analysis.cdn_typical_performance {
                score += 0.6;
                reasons.push(format!(
                    "Fast, consistent response times (avg: {:.1}ms)",
                    resp_analysis.average_response_time_ms
                ));
            }
        }

        if let Some(geo_dist) = &result.geographic_distribution {
            if geo_dist.is_geographically_distributed {
                score += 0.7;
                reasons.push(format!(
                    "Geographically distributed IPs ({} networks)",
                    geo_dist.unique_countries
                ));
            }
        }

        // Low confidence indicators (weight: 0.1-0.3)
        if result.cname_chain.len() > 2 {
            score += 0.4;
            reasons.push(format!(
                "Long CNAME chain ({} hops)",
                result.cname_chain.len()
            ));
        } else if result.cname_chain.len() > 1 {
            score += 0.2;
            reasons.push("Multiple CNAME redirects".to_string());
        }

        let domain_lower = result.domain.to_lowercase();
        if domain_lower.contains("cdn")
            || domain_lower.contains("edge")
            || domain_lower.contains("cache")
            || domain_lower.contains("static")
            || domain_lower.contains("assets")
            || domain_lower.contains("media")
        {
            score += 0.3;
            reasons.push("Domain contains CDN-related keywords".to_string());
        }

        if let Some(origin) = &result.analysis.origin_server_info {
            if origin.is_cloud_provider {
                score += 0.4;
                reasons.push(format!(
                    "Origin server hosted on cloud provider: {}",
                    origin.provider.as_deref().unwrap_or("Unknown")
                ));
                analysis.detected_providers.push(format!(
                    "{} Origin",
                    origin.provider.as_deref().unwrap_or("Cloud")
                ));
            }

            if let Some(asn_info) = &origin.asn_info {
                if asn_info.is_cdn_asn {
                    score += 0.8;
                    reasons.push(format!(
                        "IP belongs to known CDN ASN {} ({})",
                        asn_info.asn, asn_info.organization
                    ));
                    analysis
                        .detected_providers
                        .push(format!("ASN {} ({})", asn_info.asn, asn_info.organization));
                }
            }
        }

        // Apply sigmoid function to score for better confidence distribution
        let normalized_score = score / 3.0f64; // Normalize to 0-1 range
        analysis.confidence_score =
            1.0f64 / (1.0f64 + (-6.0f64 * (normalized_score - 0.5f64)).exp()); // Sigmoid centered at 0.5
        analysis.is_behind_cdn = analysis.confidence_score >= 0.6;
        analysis.detection_reasons = reasons;

        // Generate security implications based on detected providers
        if analysis.is_behind_cdn {
            analysis
                .security_implications
                .push("Traffic is likely protected by CDN WAF".to_string());
            analysis
                .security_implications
                .push("Origin server IP may be hidden from direct access".to_string());
            analysis
                .security_implications
                .push("CDN provides DDoS protection and global caching".to_string());

            // Provider-specific security implications
            if let Some(provider) = &result.cdn_provider {
                let provider_implications = self.get_provider_security_implications(provider);
                analysis.security_implications.extend(provider_implications);
            }

            // Additional implications based on analysis
            if let Some(ttl_analysis) = &result.ttl_analysis {
                if ttl_analysis.average_ttl > 3600 {
                    analysis
                        .security_implications
                        .push("Long TTL may delay security updates".to_string());
                }
            }

            if let Some(resp_analysis) = &result.response_time_analysis {
                if resp_analysis.average_response_time_ms < 50.0 {
                    analysis
                        .security_implications
                        .push("Very fast responses suggest global edge network".to_string());
                }
            }
        }

        Ok(analysis)
    }

    /// Get provider-specific security implications
    fn get_provider_security_implications(&self, provider: &str) -> Vec<String> {
        match provider {
            "Cloudflare" => vec![
                "Cloudflare blocks many automated security scanners".to_string(),
                "Consider Cloudflare-specific bypass techniques (e.g., headers)".to_string(),
                "Cloudflare has strong DDoS protection and bot management".to_string(),
                "Origin IP hidden behind Cloudflare's proxy network".to_string(),
            ],
            "Akamai" => vec![
                "Akamai has advanced bot detection and blocking".to_string(),
                "Large global network with strong security features".to_string(),
                "May use proprietary security headers for protection".to_string(),
            ],
            "Fastly" => vec![
                "Fastly provides real-time security and DDoS protection".to_string(),
                "Known for high-performance edge computing capabilities".to_string(),
                "May use custom security rules and WAF".to_string(),
            ],
            "Amazon CloudFront" => vec![
                "AWS Shield provides advanced DDoS protection".to_string(),
                "Integrates with AWS WAF for application-level protection".to_string(),
                "Origin may be protected by additional AWS security services".to_string(),
            ],
            "Microsoft Azure CDN" => vec![
                "Azure Front Door provides global security and acceleration".to_string(),
                "Integrates with Azure WAF and security services".to_string(),
                "May use Azure-specific security headers".to_string(),
            ],
            "Google Cloud CDN" => vec![
                "Google Cloud Armor provides advanced security features".to_string(),
                "Integrates with Google's global security infrastructure".to_string(),
                "May leverage Google's machine learning for threat detection".to_string(),
            ],
            "Imperva Incapsula" => vec![
                "Advanced bot management and DDoS protection".to_string(),
                "Known for strong application security features".to_string(),
                "May use proprietary security technologies".to_string(),
            ],
            _ => vec![format!(
                "{} provides CDN-level security and DDoS protection",
                provider
            )],
        }
    }

    /// Analyze TTL patterns for CDN detection
    fn analyze_ttl(&self, ttls: &[u32]) -> TtlAnalysis {
        let min_ttl = *ttls.iter().min().unwrap_or(&300);
        let max_ttl = *ttls.iter().max().unwrap_or(&300);
        let avg_ttl = ttls.iter().sum::<u32>() as f64 / ttls.len() as f64;

        // Calculate consistency score (lower variance = higher consistency)
        let variance = ttls
            .iter()
            .map(|&ttl| (ttl as f64 - avg_ttl).powi(2))
            .sum::<f64>()
            / ttls.len() as f64;
        let consistency_score = 1.0 / (1.0 + variance.sqrt() / avg_ttl);

        // Check if TTL is typical for CDN (usually 300-3600 seconds for CDN edge records)
        let cdn_typical_ttl = (300.0..=3600.0).contains(&avg_ttl);

        TtlAnalysis {
            average_ttl: avg_ttl as u32,
            min_ttl,
            max_ttl,
            ttl_consistency_score: consistency_score,
            cdn_typical_ttl,
        }
    }

    /// Analyze geographic distribution of IP addresses
    async fn analyze_geographic_distribution(
        &self,
        ips: &[IpAddr],
    ) -> Result<GeographicDistribution> {
        let unique_ips: std::collections::HashSet<_> = ips.iter().copied().collect();

        let mut asns = std::collections::HashSet::new();
        let mut countries = std::collections::HashSet::new();
        for ip in &unique_ips {
            if let Ok(info) = self.get_asn_info(*ip).await {
                asns.insert(info.asn);
                if let Some(country) = info.country {
                    countries.insert(country);
                }
            }
        }

        // Distinct /16 (IPv4) or /32 (IPv6) networks as a spread indicator
        let networks: std::collections::HashSet<_> = unique_ips
            .iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    format!("{}.{}", o[0], o[1])
                }
                IpAddr::V6(v6) => {
                    let s = v6.segments();
                    format!("{:x}:{:x}", s[0], s[1])
                }
            })
            .collect();

        let unique_asns = asns.len();
        let unique_countries = countries.len();
        let is_geographically_distributed =
            unique_countries > 1 || networks.len() > 2 || unique_asns > 2;
        let distribution_score = if is_geographically_distributed {
            0.8
        } else if networks.len() > 1 || unique_asns > 1 {
            0.5
        } else {
            0.1
        };

        Ok(GeographicDistribution {
            unique_countries,
            unique_asns,
            is_geographically_distributed,
            distribution_score,
        })
    }

    /// Analyze response time patterns
    async fn analyze_response_time(&self, domain: &str) -> Result<ResponseTimeAnalysis> {
        // Perform multiple queries to measure response time
        let mut response_times = Vec::new();

        for _ in 0..3 {
            let start = std::time::Instant::now();
            let result = self.resolver_pool.query(domain, RecordType::A).await;
            let duration = start.elapsed();

            if result.is_ok() {
                response_times.push(duration.as_millis() as f64);
            }
        }

        if response_times.is_empty() {
            return Ok(ResponseTimeAnalysis {
                average_response_time_ms: 1000.0, // Default high value
                min_response_time_ms: 1000.0,
                max_response_time_ms: 1000.0,
                response_consistency_score: 0.0,
                cdn_typical_performance: false,
            });
        }

        let min_time = response_times.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_time = response_times.iter().fold(0.0f64, |a, &b| a.max(b));
        let avg_time = response_times.iter().sum::<f64>() / response_times.len() as f64;

        // Calculate consistency score
        let variance = response_times
            .iter()
            .map(|&time| (time - avg_time).powi(2))
            .sum::<f64>()
            / response_times.len() as f64;
        let consistency_score = 1.0 / (1.0 + variance.sqrt() / avg_time);

        // CDN typically provides fast, consistent response times (< 100ms average)
        let cdn_typical_performance = avg_time < 100.0 && consistency_score > 0.7;

        Ok(ResponseTimeAnalysis {
            average_response_time_ms: avg_time,
            min_response_time_ms: min_time,
            max_response_time_ms: max_time,
            response_consistency_score: consistency_score,
            cdn_typical_performance,
        })
    }
}

/// Result of CNAME chain following
#[derive(Debug)]
struct CnameChainResult {
    chain: Vec<CnameHop>,
    provider: Option<String>,
    final_domain: String,
}
