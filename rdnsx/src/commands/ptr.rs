//! PTR command implementation

use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use futures::stream::{self, StreamExt};
use rdnsx_core::{
    parse_ip_range_limited, reverse_ip, DnsEnumerator, DnsxClient, RecordType, ResolverPool,
};

use crate::cli::Config;
use crate::exporters::{CassandraTuning, ExportSink};
use crate::output_writer::OutputWriter;

#[derive(Args)]
pub struct PtrArgs {
    /// IP range (CIDR) or ASN (e.g., 173.0.84.0/24 or AS17012)
    #[arg()]
    pub input: String,
}

pub async fn run(args: PtrArgs, config: Config) -> Result<()> {
    // Create DNS client
    let dns_options = rdnsx_core::config::DnsxOptions {
        resolvers: config.core_config.resolvers.servers.clone(),
        timeout: std::time::Duration::from_secs(config.core_config.resolvers.timeout),
        retries: config.core_config.resolvers.retries,
        concurrency: config.core_config.performance.threads,
        rate_limit: config.core_config.performance.rate_limit,
    };
    let resolver_pool = Arc::new(ResolverPool::new(&dns_options)?);
    let client = Arc::new(DnsxClient::from_pool(Arc::clone(&resolver_pool)));

    // Create output writer
    let mut output = OutputWriter::new(
        config.output_file.clone(),
        config.json_output,
        config.silent,
    )?;

    // Parse input - check if it's an ASN or IP range
    let ips = if args.input.to_uppercase().starts_with("AS") {
        // ASN input - use ASN enumeration to get IP ranges
        if !config.silent {
            eprintln!("🔍 Enumerating ASN {} for IP ranges...", args.input);
        }

        let enumerator = DnsEnumerator::new(Arc::clone(&resolver_pool));

        // Get ASN information
        let asn_result = enumerator
            .asn_enumeration(&args.input)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to enumerate ASN {}: {}", args.input, e))?;

        if !config.silent {
            eprintln!(
                "📊 Found {} IPv4 prefixes and {} IPv6 prefixes for {}",
                asn_result.ipv4_prefixes.len(),
                asn_result.ipv6_prefixes.len(),
                asn_result.asn
            );
        }

        // Convert prefixes to IP ranges, but limit to reasonable sizes
        let mut all_ips = Vec::new();
        let max_total = 10000usize;

        for prefix in &asn_result.ipv4_prefixes {
            let remaining = max_total.saturating_sub(all_ips.len());
            if remaining == 0 {
                if !config.silent {
                    eprintln!(
                        "⚠️  Limiting to 10,000 IPs total (ASN {} has many ranges)",
                        args.input
                    );
                }
                break;
            }
            let max_for_prefix = remaining.min(1000);
            match parse_ip_range_limited(prefix, max_for_prefix) {
                Ok(range_ips) => {
                    all_ips.extend(range_ips);
                }
                Err(e) => {
                    if !config.silent {
                        eprintln!("⚠️  Skipping invalid prefix {}: {}", prefix, e);
                    }
                }
            }
        }

        if all_ips.is_empty() {
            anyhow::bail!("No valid IP addresses found for ASN {}", args.input);
        }

        all_ips
    } else if args.input.contains('/') {
        // CIDR notation - add size limits
        let max_ips = 10000;
        let range_ips = parse_ip_range_limited(&args.input, max_ips)
            .map_err(|e| anyhow::anyhow!("Failed to parse IP range: {}", e))?;
        range_ips
    } else {
        // Single IP address
        vec![args
            .input
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid IP address: {}", e))?]
    };

    if !config.silent {
        eprintln!(
            "🔍 Performing PTR lookups for {} IP addresses...",
            ips.len()
        );

        // Show warning for large ranges
        if ips.len() > 1000 {
            eprintln!("⚠️  Large IP range detected - this may take some time. Consider using smaller ranges for faster results.");
        }
    }

    // Bounded concurrency; the resolver pool also enforces the configured rate limit
    let concurrency = config.core_config.performance.threads.clamp(1, 50);

    let sink = ExportSink::from_config(&config, CassandraTuning::default()).await?;

    let results = stream::iter(ips)
        .map(|ip| {
            let client = Arc::clone(&client);
            async move {
                let ptr_domain = reverse_ip(&ip);
                client.query(&ptr_domain, RecordType::Ptr).await
            }
        })
        .buffer_unordered(concurrency);
    let mut results = std::pin::pin!(results);

    // Results are written as they arrive
    let mut success_count = 0;
    let mut empty_count = 0;
    let mut error_count = 0;
    while let Some(result) = results.next().await {
        match result {
            Ok(records) if !records.is_empty() => {
                success_count += 1;
                for record in &records {
                    output.write_record(record, false)?;
                    sink.export(record).await;
                }
                output.flush()?;
            }
            Ok(_) => empty_count += 1,
            Err(e) => {
                error_count += 1;
                tracing::debug!("PTR lookup failed: {}", e);
            }
        }
    }
    sink.finish().await?;

    if !config.silent {
        eprintln!("✅ PTR enumeration completed:");
        eprintln!("   • Successful lookups: {}", success_count);
        eprintln!("   • No PTR record: {}", empty_count);
        eprintln!("   • Failed lookups: {}", error_count);
        eprintln!(
            "   • Total processed: {}",
            success_count + empty_count + error_count
        );
    }

    output.flush()?;
    Ok(())
}
