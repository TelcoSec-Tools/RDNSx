//! DNS enumeration command implementation

use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use rdnsx_core::{config::DnsxOptions, DnsEnumerator, ResolverPool};

use crate::cli::Config;
use crate::output_writer::OutputWriter;

/// DNS enumeration command arguments
#[derive(Args)]
pub struct EnumerateArgs {
    /// Enumeration technique to use
    #[arg(short, long, value_enum)]
    pub technique: EnumerationTechnique,

    /// Target domain or ASN for enumeration (use ASN format like AS15169 for ASN enumeration)
    #[arg(long)]
    pub target: String,

    /// Recursive resolvers to use for lookups (comma-separated; default: from config)
    #[arg(long)]
    pub nameservers: Option<String>,

    /// Servers to attempt AXFR against (comma-separated). Default: the target's
    /// authoritative nameservers (NS records)
    #[arg(long)]
    pub axfr_servers: Option<String>,

    /// Servers to fingerprint (comma-separated). Default: the target itself if it is
    /// a server, otherwise the target zone's authoritative nameservers
    #[arg(long)]
    pub fingerprint_servers: Option<String>,

    /// Maximum names to discover with DNSSEC zone walking
    #[arg(long, default_value = "1000")]
    pub max_names: usize,

    /// Maximum concurrent enumeration tasks
    #[arg(long, default_value = "10")]
    pub concurrent: usize,
}

/// Enumeration techniques available
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum EnumerationTechnique {
    /// Attempt DNS zone transfer (AXFR)
    ZoneTransfer,
    /// Enumerate email security records (SPF, DMARC, DKIM)
    EmailSecurity,
    /// Detect CDN usage and configuration
    CdnDetection,
    /// Enumerate IPv6 deployment and addresses
    Ipv6Enumeration,
    /// Fingerprint DNS server capabilities
    ServerFingerprint,
    /// Enumerate DNSSEC configuration and security
    DnssecEnumeration,
    /// Perform DNSSEC zone walking (NSEC enumeration)
    DnssecZoneWalking,
    /// Analyze wildcard DNS configurations and bypass techniques
    WildcardAnalysis,
    /// Perform passive DNS enumeration using historical data
    PassiveDns,
    /// Enumerate ASN information and associated IP ranges
    AsnEnumeration,
    /// Comprehensive enumeration (all techniques)
    Comprehensive,
}

pub async fn run(args: EnumerateArgs, config: Config) -> Result<()> {
    // Create DNS options with custom settings
    let mut dns_options = DnsxOptions {
        resolvers: config.core_config.resolvers.servers.clone(),
        timeout: std::time::Duration::from_secs(config.core_config.resolvers.timeout),
        retries: config.core_config.resolvers.retries,
        concurrency: args.concurrent,
        rate_limit: config.core_config.performance.rate_limit,
    };

    // Override nameservers if specified
    if let Some(nameservers) = &args.nameservers {
        dns_options.resolvers = nameservers
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }

    // Create resolver pool and enumerator
    let resolver_pool = Arc::new(ResolverPool::new(&dns_options)?);
    let enumerator = DnsEnumerator::new(resolver_pool.clone());
    let mut output = OutputWriter::new(
        config.output_file.clone(),
        config.json_output,
        config.silent,
    )?;

    let split = |list: &Option<String>| -> Vec<String> {
        list.as_deref()
            .map(|l| {
                l.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    // Empty means "discover the zone's authoritative nameservers"
    let axfr_servers = split(&args.axfr_servers);

    let needs_fingerprint = matches!(
        args.technique,
        EnumerationTechnique::ServerFingerprint | EnumerationTechnique::Comprehensive
    );
    let (fingerprint_servers, fingerprint_zone) = if !needs_fingerprint {
        (Vec::new(), None)
    } else if args.fingerprint_servers.is_some() {
        (split(&args.fingerprint_servers), Some(args.target.clone()))
    } else {
        let ns = enumerator
            .authoritative_nameservers(&args.target)
            .await
            .unwrap_or_default();
        if ns.is_empty() {
            // Not a zone: treat the target as a server address or host name
            (vec![args.target.clone()], None)
        } else {
            (ns, Some(args.target.clone()))
        }
    };
    let fingerprint = FingerprintTargets {
        servers: &fingerprint_servers,
        zone: fingerprint_zone.as_deref(),
    };

    match args.technique {
        EnumerationTechnique::ZoneTransfer => {
            perform_zone_transfer(&enumerator, &args.target, &axfr_servers, &mut output).await?;
        }
        EnumerationTechnique::EmailSecurity => {
            perform_email_security_enumeration(&enumerator, &args.target, &mut output).await?;
        }
        EnumerationTechnique::CdnDetection => {
            perform_cdn_detection(&enumerator, &args.target, &mut output).await?;
        }
        EnumerationTechnique::Ipv6Enumeration => {
            perform_ipv6_enumeration(&enumerator, &args.target, &mut output).await?;
        }
        EnumerationTechnique::ServerFingerprint => {
            perform_server_fingerprinting(&enumerator, &args.target, &fingerprint, &mut output)
                .await?;
        }
        EnumerationTechnique::DnssecEnumeration => {
            perform_dnssec_enumeration(&enumerator, &args.target, &mut output).await?;
        }
        EnumerationTechnique::DnssecZoneWalking => {
            perform_dnssec_zone_walking(&enumerator, &args.target, args.max_names, &mut output)
                .await?;
        }
        EnumerationTechnique::WildcardAnalysis => {
            perform_wildcard_analysis(&enumerator, &args.target, &mut output).await?;
        }
        EnumerationTechnique::PassiveDns => {
            perform_passive_dns_enumeration(&enumerator, &args.target, &mut output).await?;
        }
        EnumerationTechnique::AsnEnumeration => {
            perform_asn_enumeration(&enumerator, &args.target, &mut output).await?;
        }
        EnumerationTechnique::Comprehensive => {
            perform_comprehensive_enumeration(
                &enumerator,
                &args.target,
                &axfr_servers,
                &fingerprint,
                &mut output,
            )
            .await?;
        }
    }

    output.flush()?;
    Ok(())
}

async fn perform_zone_transfer(
    enumerator: &DnsEnumerator,
    domain: &str,
    nameservers: &[String],
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator.zone_transfer(domain, nameservers).await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!("🔄 Attempting DNS zone transfer for: {}", domain))?;
    if nameservers.is_empty() {
        output.write_line("📡 Using the zone's authoritative nameservers (NS records)")?;
    } else {
        output.write_line(&format!("📡 Using nameservers: {:?}", nameservers))?;
    }
    output.write_line("")?;

    match enumerator.zone_transfer(domain, nameservers).await {
        Ok(result) => {
            output.write_line(&format!("📊 Zone Transfer Results for {}", result.domain))?;
            output.write_line(&"=".repeat(50))?;

            if !result.successful_transfers.is_empty() {
                output.write_line("✅ Successful transfers from:")?;
                for ns in &result.successful_transfers {
                    output.write_line(&format!("  • {}", ns))?;
                }
            }

            if !result.failed_transfers.is_empty() {
                output.write_line("\n❌ Failed transfers:")?;
                for (ns, error) in &result.failed_transfers {
                    output.write_line(&format!("  • {}: {}", ns, error))?;
                }
            }

            output.write_line(&format!(
                "\n📋 Discovered records: {}",
                result.records.len()
            ))?;

            if !result.records.is_empty() {
                output.write_line("\n🔍 Record Summary:")?;
                let mut record_types = std::collections::HashMap::new();

                for record in &result.records {
                    *record_types.entry(record.record_type).or_insert(0) += 1;
                }

                for (record_type, count) in record_types {
                    output.write_line(&format!("  • {:?}: {} records", record_type, count))?;
                }

                output.write_line("\n📄 Detailed Records:")?;
                for record in result.records.iter().take(20) {
                    // Show first 20 records
                    output.write_line(&format!("  {}", record))?;
                }

                if result.records.len() > 20 {
                    output.write_line(&format!(
                        "  ... and {} more records",
                        result.records.len() - 20
                    ))?;
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Zone transfer failed: {}", e);
        }
    }

    Ok(())
}

async fn perform_email_security_enumeration(
    enumerator: &DnsEnumerator,
    domain: &str,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator.email_security_enumeration(domain).await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!("🔐 Enumerating email security for: {}", domain))?;
    output.write_line("")?;

    match enumerator.email_security_enumeration(domain).await {
        Ok(result) => {
            output.write_line(&format!("📧 Email Security Analysis for {}", result.domain))?;
            output.write_line(&"=".repeat(50))?;

            if !result.spf_records.is_empty() {
                output.write_line("\n📋 SPF Records:")?;
                for (i, spf) in result.spf_records.iter().enumerate() {
                    output.write_line(&format!("  {}. {}", i + 1, spf.content))?;
                    output.write_line(&format!("     (via: {})", spf.resolver))?;
                }
            } else {
                output.write_line("\n❌ No SPF records found")?;
            }

            if let Some(dmarc) = &result.dmarc_record {
                output.write_line("\n🔒 DMARC Record:")?;
                output.write_line(&format!("  {}", dmarc.content))?;
                output.write_line(&format!("  (via: {})", dmarc.resolver))?;
            } else {
                output.write_line("\n❌ No DMARC record found")?;
            }

            if !result.dkim_selectors.is_empty() {
                output.write_line("\n🔑 DKIM Selectors:")?;
                for dkim in &result.dkim_selectors {
                    output.write_line(&format!("  • {}: {}", dkim.selector, dkim.record))?;
                }
            } else {
                output.write_line("\n❌ No DKIM selectors found")?;
            }

            // Provide security recommendations
            output.write_line("\n💡 Security Recommendations:")?;

            if result.spf_records.is_empty() {
                output.write_line("  • Add SPF record to prevent email spoofing")?;
            }

            if result.dmarc_record.is_none() {
                output.write_line("  • Add DMARC record for email authentication")?;
            }

            if result.dkim_selectors.is_empty() {
                output.write_line("  • Configure DKIM for email signing")?;
            }
        }
        Err(e) => {
            eprintln!("❌ Email security enumeration failed: {}", e);
        }
    }

    Ok(())
}

async fn perform_cdn_detection(
    enumerator: &DnsEnumerator,
    domain: &str,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator.cdn_detection(domain).await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!("🌐 Detecting CDN usage for: {}", domain))?;
    output.write_line("")?;

    match enumerator.cdn_detection(domain).await {
        Ok(result) => {
            output.write_line(&format!("🚀 CDN Detection Results for {}", result.domain))?;
            output.write_line(&"=".repeat(50))?;

            if let Some(provider) = &result.cdn_provider {
                output.write_line(&format!("✅ CDN Provider Detected: {}", provider))?;
            } else {
                output.write_line("❌ No CDN provider detected")?;
            }

            if !result.cname_chain.is_empty() {
                output.write_line("\n🔗 CNAME Chain:")?;
                for (i, hop) in result.cname_chain.iter().enumerate() {
                    output.write_line(&format!("  {}. {} → {}", i + 1, hop.from, hop.to))?;
                }
            }

            if let Some(ip) = result.origin_ip {
                output.write_line(&format!("\n🏠 Origin IP: {}", ip))?;
            }

            // Provide insights
            if result.cdn_provider.is_some() {
                output.write_line("\n💡 Insights:")?;
                output.write_line("  • Traffic is likely served through a CDN")?;
                output.write_line("  • Origin server may be protected from direct access")?;
                output.write_line("  • Consider CDN-specific enumeration techniques")?;
            }
        }
        Err(e) => {
            eprintln!("❌ CDN detection failed: {}", e);
        }
    }

    Ok(())
}

async fn perform_ipv6_enumeration(
    enumerator: &DnsEnumerator,
    domain: &str,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator.ipv6_enumeration(domain).await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!("🌐 Enumerating IPv6 deployment for: {}", domain))?;
    output.write_line("")?;

    match enumerator.ipv6_enumeration(domain).await {
        Ok(result) => {
            output.write_line(&format!(
                "🌐 IPv6 Enumeration Results for {}",
                result.domain
            ))?;
            output.write_line(&"=".repeat(50))?;

            if !result.ipv4_addresses.is_empty() {
                output.write_line("\n🔢 IPv4 Addresses:")?;
                for ip in &result.ipv4_addresses {
                    output.write_line(&format!("  • {}", ip))?;
                }
            }

            if !result.ipv6_addresses.is_empty() {
                output.write_line("\n🔢 IPv6 Addresses:")?;
                for ip in &result.ipv6_addresses {
                    output.write_line(&format!("  • {}", ip))?;
                }
            }

            output.write_line("\n📊 Deployment Analysis:")?;
            output.write_line(&format!(
                "  • IPv4 addresses: {}",
                result.ipv4_addresses.len()
            ))?;
            output.write_line(&format!(
                "  • IPv6 addresses: {}",
                result.ipv6_addresses.len()
            ))?;

            if result.dual_stack {
                output.write_line("  • 🌐 Dual-stack deployment (IPv4 + IPv6)")?;
            } else if result.ipv6_only {
                output.write_line("  • 🆕 IPv6-only deployment")?;
            } else {
                output.write_line("  • 📡 IPv4-only deployment")?;
            }

            if result.ipv6_addresses.is_empty() {
                output.write_line(
                    "\n💡 Recommendation: Consider enabling IPv6 for better connectivity",
                )?;
            }
        }
        Err(e) => {
            eprintln!("❌ IPv6 enumeration failed: {}", e);
        }
    }

    Ok(())
}

/// Servers to fingerprint and the zone to use for DNSSEC probing
struct FingerprintTargets<'a> {
    servers: &'a [String],
    zone: Option<&'a str>,
}

async fn perform_server_fingerprinting(
    enumerator: &DnsEnumerator,
    target: &str,
    targets: &FingerprintTargets<'_>,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let mut fingerprints = Vec::new();
        for ns in targets.servers {
            match enumerator
                .server_fingerprinting_for_zone(ns, targets.zone)
                .await
            {
                Ok(fingerprint) => fingerprints.push(serde_json::to_value(fingerprint)?),
                Err(e) => {
                    fingerprints.push(serde_json::json!({ "server": ns, "error": e.to_string() }))
                }
            }
        }
        output.write_json(&fingerprints)?;
        return Ok(());
    }

    output.write_line(&format!("🔍 Fingerprinting DNS servers for: {}", target))?;
    output.write_line("")?;

    let yes_no = |b: bool| if b { "✅" } else { "❌" };
    for ns in targets.servers {
        match enumerator
            .server_fingerprinting_for_zone(ns, targets.zone)
            .await
        {
            Ok(fp) => {
                output.write_line(&format!(
                    "🖥️  DNS Server: {} ({})",
                    fp.server,
                    fp.address.as_deref().unwrap_or("?")
                ))?;
                output.write_line(&format!("   Response time: {}ms", fp.response_time_ms))?;
                output.write_line(&format!(
                    "   Open recursion: {}",
                    yes_no(fp.recursion_available)
                ))?;
                output.write_line(&format!(
                    "   DNSSEC signatures: {}",
                    yes_no(fp.dnssec_support)
                ))?;
                output.write_line(&format!("   EDNS(0): {}", yes_no(fp.edns_support)))?;
                output.write_line(&format!("   TCP: {}", yes_no(fp.tcp_support)))?;
                if let Some(version) = &fp.version_bind {
                    output.write_line(&format!("   version.bind: {}", version))?;
                }
                if let Some(host) = &fp.hostname_bind {
                    output.write_line(&format!("   hostname.bind: {}", host))?;
                }
                if let Some(id) = &fp.id_server {
                    output.write_line(&format!("   id.server: {}", id))?;
                }
                output.write_line("")?;
            }
            Err(e) => {
                eprintln!("❌ Failed to fingerprint {}: {}", ns, e);
            }
        }
    }

    Ok(())
}

async fn perform_dnssec_enumeration(
    enumerator: &DnsEnumerator,
    domain: &str,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator.dnssec_enumeration(domain).await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!(
        "🔒 Enumerating DNSSEC configuration for: {}",
        domain
    ))?;
    output.write_line("")?;

    match enumerator.dnssec_enumeration(domain).await {
        Ok(result) => {
            output.write_line(&format!("🔐 DNSSEC Analysis for {}", result.domain))?;
            output.write_line(&"=".repeat(50))?;

            output.write_line(&format!(
                "DNSSEC Status: {}",
                if result.dnssec_enabled {
                    "✅ Enabled"
                } else {
                    "❌ Disabled"
                }
            ))?;

            if result.dnssec_enabled {
                if !result.dnskey_records.is_empty() {
                    output.write_line("\n🔑 DNSKEY Records:")?;
                    for dnskey in &result.dnskey_records {
                        output.write_line(&format!(
                            "  • Key Tag: {}, Algorithm: {}, Flags: {}",
                            dnskey.key_tag, dnskey.algorithm, dnskey.flags
                        ))?;
                    }
                }

                if !result.ds_records.is_empty() {
                    output.write_line("\n📋 DS Records:")?;
                    for ds in &result.ds_records {
                        output.write_line(&format!(
                            "  • Key Tag: {}, Algorithm: {}, Digest Type: {}",
                            ds.key_tag, ds.algorithm, ds.digest_type
                        ))?;
                        let digest_preview = if ds.digest.len() >= 16 {
                            &ds.digest[..16]
                        } else {
                            &ds.digest
                        };
                        output.write_line(&format!("    Digest: {}", digest_preview))?;
                    }
                }

                output.write_line("\n📊 Record Counts:")?;
                output.write_line(&format!("  • RRSIG records: {}", result.rrsig_records))?;
                output.write_line(&format!("  • NSEC records: {}", result.nsec_records))?;
                output.write_line(&format!("  • NSEC3PARAM records: {}", result.nsec3_records))?;

                if let Some(chain) = &result.chain_validation {
                    output.write_line(&format!(
                        "\n⛓️  Chain of trust: {}",
                        if chain.chain_valid {
                            "✅ Valid"
                        } else {
                            "❌ Broken"
                        }
                    ))?;
                    if let Some(status) = &chain.trust_anchor_status {
                        output.write_line(&format!("  • {}", status))?;
                    }
                }

                if !result.security_issues.is_empty() {
                    output.write_line("\n⚠️  Security Issues:")?;
                    for issue in &result.security_issues {
                        output.write_line(&format!("  • {}", issue))?;
                    }
                } else {
                    output.write_line("\n✅ No security issues detected")?;
                }
            } else {
                output.write_line("\n💡 Recommendation: Enable DNSSEC for enhanced security")?;
            }
        }
        Err(e) => {
            eprintln!("❌ DNSSEC enumeration failed: {}", e);
        }
    }

    Ok(())
}

async fn perform_dnssec_zone_walking(
    enumerator: &DnsEnumerator,
    domain: &str,
    max_names: usize,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator
            .dnssec_zone_walking_limited(domain, max_names)
            .await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!(
        "🚶 Performing DNSSEC zone walking for: {}",
        domain
    ))?;
    output.write_line("")?;

    match enumerator
        .dnssec_zone_walking_limited(domain, max_names)
        .await
    {
        Ok(result) => {
            output.write_line(&format!(
                "🚶 DNSSEC Zone Walking Results for {}",
                result.domain
            ))?;
            output.write_line(&"=".repeat(50))?;

            output.write_line(&format!(
                "Enumeration Status: {}",
                if result.enumeration_successful {
                    "✅ Successful"
                } else {
                    "❌ Failed"
                }
            ))?;
            output.write_line(&format!("Denial of existence: {}", result.denial_type))?;
            if let Some(ns) = &result.nameserver {
                output.write_line(&format!("Nameserver: {}", ns))?;
            }
            output.write_line(&format!("Stopped: {}", result.stop_reason))?;

            if !result.nsec_chain.is_empty() {
                output.write_line("\n🔗 NSEC Chain:")?;
                for nsec in &result.nsec_chain {
                    output.write_line(&format!("  {} → {}", nsec.owner, nsec.next_domain))?;
                }
            }

            if !result.discovered_names.is_empty() {
                output.write_line("\n🔍 Discovered Names:")?;
                for name in &result.discovered_names {
                    output.write_line(&format!("  • {}", name))?;
                }
            }

            if result.enumeration_successful {
                output.write_line(
                    "\n💡 Zone walking successful - DNSSEC NSEC records can be enumerated",
                )?;
            } else {
                output.write_line("\n💡 Zone walking not possible (see the reason above)")?;
            }
        }
        Err(e) => {
            eprintln!("❌ DNSSEC zone walking failed: {}", e);
        }
    }

    Ok(())
}

async fn perform_wildcard_analysis(
    enumerator: &DnsEnumerator,
    domain: &str,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator.wildcard_analysis(domain).await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!(
        "🎭 Analyzing wildcard DNS configuration for: {}",
        domain
    ))?;
    output.write_line("")?;

    match enumerator.wildcard_analysis(domain).await {
        Ok(analysis) => {
            output.write_line(&format!(
                "🎭 Wildcard Analysis Results for {}",
                analysis.domain
            ))?;
            output.write_line(&"=".repeat(50))?;

            output.write_line(&format!(
                "Wildcard Status: {}",
                if analysis.has_wildcard {
                    "✅ Detected"
                } else {
                    "❌ Not Detected"
                }
            ))?;
            output.write_line(&format!(
                "Confidence Score: {:.1}%",
                analysis.confidence_score * 100.0
            ))?;

            if !analysis.wildcard_ips.is_empty() {
                output.write_line("\n🌐 Wildcard IP Addresses:")?;
                for ip in &analysis.wildcard_ips {
                    output.write_line(&format!("  • {}", ip))?;
                }
            }

            if !analysis.wildcard_records.is_empty() {
                output.write_line("\n📋 Sample Wildcard Records:")?;
                for record in analysis.wildcard_records.iter().take(3) {
                    output.write_line(&format!("  • {}", record.domain))?;
                }
                if analysis.wildcard_records.len() > 3 {
                    output.write_line(&format!(
                        "  ... and {} more test records",
                        analysis.wildcard_records.len() - 3
                    ))?;
                }
            }

            if !analysis.bypass_attempts.is_empty() {
                output.write_line("\n🛡️ Wildcard Bypass Attempts:")?;
                let successful_bypasses: Vec<_> = analysis
                    .bypass_attempts
                    .iter()
                    .filter(|attempt| attempt.success)
                    .collect();

                if !successful_bypasses.is_empty() {
                    output.write_line("  ✅ Successful bypass techniques:")?;
                    for attempt in &successful_bypasses {
                        output.write_line(&format!(
                            "    • {}: {}",
                            attempt.technique, attempt.test_domain
                        ))?;
                    }
                } else {
                    output.write_line("  ❌ No bypass techniques successful")?;
                }

                let failed_count = analysis.bypass_attempts.len() - successful_bypasses.len();
                if failed_count > 0 {
                    output.write_line(&format!("  📊 {} bypass attempts failed", failed_count))?;
                }
            }

            // Provide recommendations
            output.write_line("\n💡 Recommendations:")?;
            if analysis.has_wildcard {
                output.write_line(
                    "  • Wildcard DNS is active - consider targeted subdomain enumeration",
                )?;
                if analysis.confidence_score > 0.8 {
                    output.write_line(
                        "  • High confidence wildcard detection - most subdomains will resolve",
                    )?;
                }
                if !analysis.bypass_attempts.is_empty() {
                    output.write_line(
                        "  • Some bypass techniques work - can find non-wildcard domains",
                    )?;
                }
            } else {
                output.write_line(
                    "  • No wildcard DNS detected - standard enumeration should work well",
                )?;
            }
        }
        Err(e) => {
            eprintln!("❌ Wildcard analysis failed: {}", e);
        }
    }

    Ok(())
}

async fn perform_passive_dns_enumeration(
    enumerator: &DnsEnumerator,
    domain: &str,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator.passive_dns_enumeration(domain).await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!(
        "📚 Performing passive DNS enumeration for: {}",
        domain
    ))?;
    output.write_line("Note: queries Certificate Transparency logs (crt.sh) and actively probes a few common names.")?;
    output.write_line("")?;

    match enumerator.passive_dns_enumeration(domain).await {
        Ok(result) => {
            output.write_line(&format!("📚 Passive DNS Results for {}", result.domain))?;
            output.write_line(&"=".repeat(50))?;

            if let Some(last_seen) = result.last_seen {
                output.write_line(&format!(
                    "Last Seen: {}",
                    last_seen.format("%Y-%m-%d %H:%M:%S UTC")
                ))?;
            }

            if !result.subdomains.is_empty() {
                output.write_line("\n🔍 Discovered Subdomains:")?;
                for subdomain in &result.subdomains {
                    output.write_line(&format!(
                        "  • {} ({}) - First: {}, Last: {}",
                        subdomain.name,
                        subdomain.record_type,
                        subdomain.first_seen.format("%Y-%m-%d"),
                        subdomain.last_seen.format("%Y-%m-%d")
                    ))?;
                }
            } else {
                output.write_line("\n❌ No subdomains discovered")?;
            }

            if !result.historical_ips.is_empty() {
                output.write_line("\n🏠 Historical IP Addresses:")?;
                for historical_ip in &result.historical_ips {
                    output.write_line(&format!(
                        "  • {} - First: {}, Last: {}",
                        historical_ip.ip,
                        historical_ip.first_seen.format("%Y-%m-%d"),
                        historical_ip.last_seen.format("%Y-%m-%d")
                    ))?;
                }
            }

            if !result.data_sources.is_empty() {
                output.write_line("\n📊 Data Sources:")?;
                for source in &result.data_sources {
                    output.write_line(&format!("  • {}", source))?;
                }
            }

            if !result.source_errors.is_empty() {
                output.write_line("\n⚠️  Failed sources:")?;
                for error in &result.source_errors {
                    output.write_line(&format!("  • {}", error))?;
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Passive DNS enumeration failed: {}", e);
        }
    }

    Ok(())
}

async fn perform_asn_enumeration(
    enumerator: &DnsEnumerator,
    asn: &str,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        let result = enumerator.asn_enumeration(asn).await?;
        output.write_json(&result)?;
        return Ok(());
    }

    output.write_line(&format!("🏢 Enumerating ASN information for: {}", asn))?;
    output.write_line("")?;

    match enumerator.asn_enumeration(asn).await {
        Ok(result) => {
            output.write_line(&format!("🏢 ASN Enumeration Results for {}", result.asn))?;
            output.write_line(&"=".repeat(50))?;

            if let Some(name) = &result.name {
                output.write_line(&format!("🏷️  Name: {}", name))?;
            }

            if let Some(description) = &result.description {
                output.write_line(&format!("📝 Description: {}", description))?;
            }

            if let Some(country) = &result.country {
                output.write_line(&format!("🌍 Country: {}", country))?;
            }

            output.write_line("\n📊 Network Summary:")?;
            output.write_line(&format!(
                "  • IPv4 prefixes: {}",
                result.ipv4_prefixes.len()
            ))?;
            output.write_line(&format!(
                "  • IPv6 prefixes: {}",
                result.ipv6_prefixes.len()
            ))?;
            output.write_line(&format!(
                "  • Total IPv4 addresses: {}",
                result.total_ipv4_addresses
            ))?;
            output.write_line(&format!(
                "  • Total IPv6 addresses: {}",
                result.total_ipv6_addresses
            ))?;

            if !result.ipv4_prefixes.is_empty() {
                output.write_line("\n🔢 IPv4 Prefixes:")?;
                for prefix in result.ipv4_prefixes.iter().take(10) {
                    // Show first 10
                    output.write_line(&format!("  • {}", prefix))?;
                }
                if result.ipv4_prefixes.len() > 10 {
                    output.write_line(&format!(
                        "  ... and {} more IPv4 prefixes",
                        result.ipv4_prefixes.len() - 10
                    ))?;
                }
            }

            if !result.ipv6_prefixes.is_empty() {
                output.write_line("\n🔢 IPv6 Prefixes:")?;
                for prefix in result.ipv6_prefixes.iter().take(10) {
                    // Show first 10
                    output.write_line(&format!("  • {}", prefix))?;
                }
                if result.ipv6_prefixes.len() > 10 {
                    output.write_line(&format!(
                        "  ... and {} more IPv6 prefixes",
                        result.ipv6_prefixes.len() - 10
                    ))?;
                }
            }

            // Provide recommendations
            output.write_line("\n💡 Usage Recommendations:")?;
            output
                .write_line("  • Use these IP ranges with PTR enumeration: rdnsx ptr <prefix>")?;
            output.write_line(
                "  • Combine with subdomain enumeration for comprehensive reconnaissance",
            )?;
            if result.total_ipv4_addresses > 1000000 {
                output.write_line("  • Large ASN - consider rate limiting for PTR enumeration")?;
            }
        }
        Err(e) => {
            eprintln!("❌ ASN enumeration failed: {}", e);
            eprintln!("\n💡 Troubleshooting:");
            eprintln!("  • Ensure ASN format is correct (e.g., AS15169 or 15169)");
            eprintln!("  • For online ASN enumeration, internet connectivity to BGPView/IPInfo APIs is required");
        }
    }

    Ok(())
}

async fn perform_comprehensive_enumeration(
    enumerator: &DnsEnumerator,
    domain: &str,
    axfr_servers: &[String],
    fingerprint: &FingerprintTargets<'_>,
    output: &mut OutputWriter,
) -> Result<()> {
    if output.is_json() {
        // Report failures instead of silently dropping them
        fn section<T: serde::Serialize>(result: rdnsx_core::Result<T>) -> serde_json::Value {
            match result {
                Ok(value) => serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            }
        }

        let mut fingerprints = Vec::new();
        for ns in fingerprint.servers {
            let mut value = section(
                enumerator
                    .server_fingerprinting_for_zone(ns, fingerprint.zone)
                    .await,
            );
            if let Some(obj) = value.as_object_mut() {
                obj.entry("server").or_insert_with(|| serde_json::json!(ns));
            }
            fingerprints.push(value);
        }

        let comprehensive = serde_json::json!({
            "domain": domain,
            "zone_transfer": section(enumerator.zone_transfer(domain, axfr_servers).await),
            "dnssec": section(enumerator.dnssec_enumeration(domain).await),
            "wildcard_analysis": section(enumerator.wildcard_analysis(domain).await),
            "passive_dns": section(enumerator.passive_dns_enumeration(domain).await),
            "email_security": section(enumerator.email_security_enumeration(domain).await),
            "cdn_detection": section(enumerator.cdn_detection(domain).await),
            "ipv6_enumeration": section(enumerator.ipv6_enumeration(domain).await),
            "server_fingerprints": fingerprints,
        });

        output.write_json(&comprehensive)?;
        return Ok(());
    }

    output.write_line(&format!(
        "🔬 Performing comprehensive DNS enumeration for: {}",
        domain
    ))?;
    output.write_line(&"=".repeat(60))?;
    output.write_line("")?;

    // Zone Transfer
    if let Err(e) = perform_zone_transfer(enumerator, domain, axfr_servers, output).await {
        eprintln!("Zone transfer enumeration failed: {}", e);
    }

    output.write_line(&format!("\n{}\n", "=".repeat(60)))?;

    // DNSSEC Enumeration
    if let Err(e) = perform_dnssec_enumeration(enumerator, domain, output).await {
        eprintln!("DNSSEC enumeration failed: {}", e);
    }

    output.write_line(&format!("\n{}\n", "=".repeat(60)))?;

    // Wildcard Analysis
    if let Err(e) = perform_wildcard_analysis(enumerator, domain, output).await {
        eprintln!("Wildcard analysis failed: {}", e);
    }

    output.write_line(&format!("\n{}\n", "=".repeat(60)))?;

    // Passive DNS Enumeration
    if let Err(e) = perform_passive_dns_enumeration(enumerator, domain, output).await {
        eprintln!("Passive DNS enumeration failed: {}", e);
    }

    output.write_line(&format!("\n{}\n", "=".repeat(60)))?;

    // Email Security
    if let Err(e) = perform_email_security_enumeration(enumerator, domain, output).await {
        eprintln!("Email security enumeration failed: {}", e);
    }

    output.write_line(&format!("\n{}\n", "=".repeat(60)))?;

    // CDN Detection
    if let Err(e) = perform_cdn_detection(enumerator, domain, output).await {
        eprintln!("CDN detection failed: {}", e);
    }

    output.write_line(&format!("\n{}\n", "=".repeat(60)))?;

    // IPv6 Enumeration
    if let Err(e) = perform_ipv6_enumeration(enumerator, domain, output).await {
        eprintln!("IPv6 enumeration failed: {}", e);
    }

    output.write_line(&format!("\n{}\n", "=".repeat(60)))?;

    // Server Fingerprinting
    if let Err(e) = perform_server_fingerprinting(enumerator, domain, fingerprint, output).await {
        eprintln!("Server fingerprinting failed: {}", e);
    }

    output.write_line("🎉 Comprehensive enumeration completed!")?;

    Ok(())
}
