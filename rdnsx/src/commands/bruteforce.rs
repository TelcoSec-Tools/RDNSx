//! Bruteforce command implementation

use std::sync::Arc;

use anyhow::{bail, Result};
use clap::Args;
use rdnsx_core::{Bruteforcer, DnsxClient, RecordType, ResolverPool, WildcardFilter};

use crate::cli::Config;
use crate::exporters::{CassandraTuning, ExportSink};
use crate::output_writer::OutputWriter;

#[derive(Args)]
pub struct BruteforceArgs {
    /// Target domain(s)
    #[arg(short, long, required = true)]
    pub domain: Vec<String>,

    /// Wordlist file or comma-separated words (use - for stdin)
    #[arg(short, long)]
    pub wordlist: String,

    /// Placeholder string (default: FUZZ)
    #[arg(long, default_value = "FUZZ")]
    pub placeholder: String,

    /// Record type to query (default: A)
    #[arg(long, default_value = "A")]
    pub record_type: String,

    /// Keep results that only match a wildcard record (wildcard filtering is on by default)
    #[arg(long)]
    pub no_wildcard_filter: bool,
}

pub async fn run(args: BruteforceArgs, config: Config) -> Result<()> {
    // Parse record type
    let record_type = match args.record_type.to_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::Aaaa,
        "CNAME" => RecordType::Cname,
        "MX" => RecordType::Mx,
        "TXT" => RecordType::Txt,
        "NS" => RecordType::Ns,
        "SOA" => RecordType::Soa,
        "PTR" => RecordType::Ptr,
        "SRV" => RecordType::Srv,
        "CAA" => RecordType::Caa,
        _ => {
            bail!("Unsupported record type: {}", args.record_type);
        }
    };

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

    let sink = ExportSink::from_config(&config, CassandraTuning::default()).await?;

    // Process each domain
    for domain in &args.domain {
        if !config.silent {
            eprintln!("Enumerating subdomains for {}", domain);
        }

        let mut bruteforcer =
            Bruteforcer::new(Arc::clone(&client), config.core_config.performance.threads);
        if !args.no_wildcard_filter {
            // With a placeholder (FUZZ.dev.example.com) the zone to probe is what follows it
            let base = match domain.find(&args.placeholder) {
                Some(pos) => domain[pos + args.placeholder.len()..]
                    .trim_start_matches('.')
                    .to_string(),
                None => domain.clone(),
            };
            let filter = WildcardFilter::new(Some(base.clone()), Arc::clone(&resolver_pool), 3);
            if filter.test_wildcard(&base).await.unwrap_or(false) && !config.silent {
                eprintln!(
                    "Wildcard DNS detected on {}: filtering wildcard answers",
                    domain
                );
            }
            bruteforcer = bruteforcer.with_wildcard_filter(filter);
        }

        let results = bruteforcer
            .enumerate_with_records(domain, &args.wordlist, &args.placeholder, record_type)
            .await?;

        for (subdomain, records) in results {
            if !config.silent {
                eprintln!(
                    "Found subdomain: {} with {} records",
                    subdomain,
                    records.len()
                );
            }
            for record in records {
                output.write_record(&record, false)?;
                sink.export(&record).await;
            }
        }
    }

    sink.finish().await?;
    output.flush()?;
    Ok(())
}
