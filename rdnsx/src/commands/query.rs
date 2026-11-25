//! Query command implementation

use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use rdnsx_core::{
    config::DnsxOptions, AdaptiveBatchSizer, CachedDnsClient, ConcurrencyConfig,
    ConcurrentProcessor, DnsCache, DnsRecord, DnsxClient, DomainStreamer, Exporter,
    ProcessingMetrics, RecordType, ResolverPool, ResponseCode, WildcardFilter,
};

use crate::cli::Config;
use crate::output_writer::OutputWriter;

#[derive(Args)]
pub struct QueryArgs {
    /// Domains to query
    #[arg(value_name = "DOMAIN")]
    pub domains: Vec<String>,

    /// Input file (default: stdin)
    #[arg(short, long)]
    pub list: Option<String>,

    /// DNS record types to query (can be repeated)
    #[arg(short = 't', long = "record-type", value_name = "TYPE", action = clap::ArgAction::Append)]
    pub record_type: Vec<String>,

    /// A records (default if no record types specified)
    #[arg(short, long)]
    pub a: bool,

    /// AAAA records
    #[arg(long)]
    pub aaaa: bool,

    /// CNAME records
    #[arg(long)]
    pub cname: bool,

    /// MX records
    #[arg(long)]
    pub mx: bool,

    /// TXT records
    #[arg(long)]
    pub txt: bool,

    /// NS records
    #[arg(long)]
    pub ns: bool,

    /// SOA records
    #[arg(long)]
    pub soa: bool,

    /// PTR records
    #[arg(long)]
    pub ptr: bool,

    /// SRV records
    #[arg(long)]
    pub srv: bool,

    /// CAA records
    #[arg(long)]
    pub caa: bool,

    /// CERT records
    #[arg(long)]
    pub cert: bool,

    /// DNAME records
    #[arg(long)]
    pub dname: bool,

    /// DNSKEY records
    #[arg(long)]
    pub dnskey: bool,

    /// DS records
    #[arg(long)]
    pub ds: bool,

    /// HINFO records
    #[arg(long)]
    pub hinfo: bool,

    /// HTTPS records
    #[arg(long)]
    pub https: bool,

    /// KEY records
    #[arg(long)]
    pub key: bool,

    /// LOC records
    #[arg(long)]
    pub loc: bool,

    /// NAPTR records
    #[arg(long)]
    pub naptr: bool,

    /// NSEC records
    #[arg(long)]
    pub nsec: bool,

    /// NSEC3 records
    #[arg(long)]
    pub nsec3: bool,

    /// OPT records
    #[arg(long)]
    pub opt: bool,

    /// RRSIG records
    #[arg(long)]
    pub rrsig: bool,

    /// SSHFP records
    #[arg(long)]
    pub sshfp: bool,

    /// SVCB records
    #[arg(long)]
    pub svcb: bool,

    /// TLSA records
    #[arg(long)]
    pub tlsa: bool,

    /// URI records
    #[arg(long)]
    pub uri: bool,

    /// ASN information
    #[arg(long)]
    pub asn: bool,

    /// Filter by response code (comma-separated)
    #[arg(long)]
    pub rcode: Option<String>,

    /// Domain for wildcard detection
    #[arg(short = 'w', long)]
    pub wildcard_domain: Option<String>,

    /// Response values only
    #[arg(long)]
    pub resp_only: bool,

    /// Use streaming mode for large files (reduces memory usage)
    #[arg(long)]
    pub stream: bool,

    /// Enable DNS response caching (reduces redundant queries)
    #[arg(long)]
    pub cache: bool,

    /// Cache TTL in seconds (default: 300)
    #[arg(long, default_value = "300")]
    pub cache_ttl: u64,

    /// Maximum cache size (default: 10000)
    #[arg(long, default_value = "10000")]
    pub cache_size: usize,

    /// Cassandra batch size (default: 1000)
    #[arg(long, default_value = "1000")]
    pub cassandra_batch_size: usize,

    /// Number of Cassandra worker threads (default: 4)
    #[arg(long, default_value = "4")]
    pub cassandra_workers: usize,
}

pub async fn run(args: QueryArgs, config: Config) -> Result<()> {
    // Determine record types to query
    let record_types = determine_record_types(&args);

    // Create DNS client
    let dns_options = DnsxOptions {
        resolvers: config.core_config.resolvers.servers.clone(),
        timeout: std::time::Duration::from_secs(config.core_config.resolvers.timeout),
        retries: config.core_config.resolvers.retries,
        concurrency: config.core_config.performance.threads,
        rate_limit: config.core_config.performance.rate_limit,
    };
    let resolver_pool = Arc::new(ResolverPool::new(&dns_options)?);
    let client = DnsxClient::from_pool(Arc::clone(&resolver_pool));

    // Create wildcard filter if domain specified
    let wildcard_filter: Option<WildcardFilter> =
        if let Some(ref base_domain) = args.wildcard_domain {
            let resolver_pool = Arc::clone(&resolver_pool);
            Some(WildcardFilter::new(
                Some(base_domain.clone()),
                resolver_pool,
                10, // Default threshold: 10 domains pointing to same IP
            ))
        } else {
            None
        };

    // Parse response code filter
    let allowed_rcodes = parse_rcodes(&args.rcode)?;

    // Create output writer
    let mut output = OutputWriter::new(
        config.output_file.clone(),
        config.json_output,
        config.silent,
    )?;

    // Create exporters if configured
    let exporters = build_exporters(&args, &config).await?;

    // Determine if we should use streaming mode
    let use_streaming = args.stream || args.list.is_some(); // Auto-enable for files

    let domains: Vec<String> = if use_streaming && args.list.is_some() {
        // Use streaming for large files
        if !config.silent {
            eprintln!("Using streaming mode for large file processing");
        }
        Vec::new() // We'll stream domains directly
    } else {
        // Load all domains into memory for small lists or stdin
        // Read stdin only when no domains were given on the command line
        let mut domains = if args.list.is_some() || args.domains.is_empty() {
            read_domains(&args.list)?
        } else {
            Vec::new()
        };
        domains.extend(args.domains.clone());

        if domains.is_empty() {
            if !config.silent {
                eprintln!("No domains to process. Use --list to specify a file or provide domains as arguments.");
            }
            return Ok(());
        }
        domains
    };

    // Create adaptive batch sizer if enabled
    let mut adaptive_batcher = AdaptiveBatchSizer::new(1000, 100, 10000);

    // Create concurrency configuration with adaptive batching
    let concurrency_config = ConcurrencyConfig {
        max_concurrent: config.core_config.performance.threads,
        batch_size: adaptive_batcher.current_size(),
        timeout: std::time::Duration::from_secs(config.core_config.resolvers.timeout),
        // The resolver pool enforces the configured rate limit for every query
        rate_limit: 0,
    };

    // Create cached client if caching is enabled
    let (client_clone, cached_client_ref): (
        Arc<dyn rdnsx_core::DnsQuery + Send + Sync>,
        Option<Arc<CachedDnsClient<DnsxClient>>>,
    ) = if args.cache {
        if !config.silent {
            eprintln!(
                "DNS caching enabled (TTL: {}s, max size: {})",
                args.cache_ttl, args.cache_size
            );
        }
        let cache = DnsCache::new(
            args.cache_size,
            std::time::Duration::from_secs(args.cache_ttl),
        );
        let cached_client = Arc::new(CachedDnsClient::new(client, cache));
        (
            cached_client.clone() as Arc<dyn rdnsx_core::DnsQuery + Send + Sync>,
            Some(cached_client),
        )
    } else {
        (
            Arc::new(client) as Arc<dyn rdnsx_core::DnsQuery + Send + Sync>,
            None,
        )
    };

    // Create the concurrent processor with all record types and domains
    let processor = ConcurrentProcessor::new(concurrency_config, {
        let record_types = record_types.clone();
        let client = Arc::clone(&client_clone);
        let allowed_rcodes = allowed_rcodes.clone();
        let wildcard_filter = wildcard_filter.clone();
        let silent = config.silent;

        move |domain: String| {
            let record_types = record_types.clone();
            let client = Arc::clone(&client);
            let allowed_rcodes = allowed_rcodes.clone();
            let wildcard_filter = wildcard_filter.clone();
            let silent = silent;

            Box::pin(async move {
                let mut all_records = Vec::new();

                // Query each record type for this domain
                for record_type in &record_types {
                    match client.query_response(&domain, *record_type).await {
                        Ok(response) => {
                            // With an rcode filter, report negative answers too (as
                            // "domain [NXDOMAIN]") and keep only the matching codes.
                            let records = if allowed_rcodes.is_empty() {
                                response.records
                            } else if allowed_rcodes.contains(&response.response_code) {
                                response.into_records_or_negative()
                            } else {
                                Vec::new()
                            };

                            // Apply wildcard filtering if enabled
                            let filtered_records = if let Some(ref filter) = wildcard_filter {
                                filter.filter(records.clone()).await.unwrap_or_else(|e| {
                                    if !silent {
                                        eprintln!(
                                            "Warning: Wildcard filtering failed for {}: {}",
                                            domain, e
                                        );
                                    }
                                    records
                                })
                            } else {
                                records
                            };

                            all_records.extend(filtered_records);
                        }
                        Err(e) => {
                            if !silent {
                                eprintln!("Error querying {} ({:?}): {}", domain, record_type, e);
                            }
                        }
                    }
                }

                Ok(all_records)
            })
        }
    });

    // Process domains concurrently with adaptive batching
    let (all_records, metrics) =
        if let (true, Some(list_path)) = (use_streaming, args.list.as_ref()) {
            // Streaming mode for large files with adaptive batching
            let file = std::fs::File::open(list_path)?;
            let reader = std::io::BufReader::new(file);
            let streamer = DomainStreamer::new(reader);

            let domain_iter = streamer.stream_domains().filter_map(|result| match result {
                Ok(domain) if !domain.is_empty() => Some(domain),
                Ok(_) => None, // Skip empty lines
                Err(e) => {
                    eprintln!("Error reading domain: {}", e);
                    None
                }
            });

            // Collect domains for adaptive batching
            let mut domains_vec: Vec<String> = domain_iter.collect();
            // Domains given on the command line are processed too
            domains_vec.extend(args.domains.iter().cloned());

            // Process with adaptive batching
            process_with_adaptive_batching(
                processor,
                domains_vec,
                &mut adaptive_batcher,
                !config.silent,
            )
            .await
            .map_err(anyhow::Error::from)?
        } else {
            // In-memory processing for smaller lists
            processor.process_stream(domains.into_iter()).await?
        };

    if !config.silent {
        eprintln!(
            "Processed {} domains, collected {} records ({:.1} qps)",
            metrics.total_domains,
            all_records.len(),
            metrics.queries_per_second
        );

        // Show cache statistics if caching was enabled
        if let Some(ref cached_client) = cached_client_ref {
            let cache_stats = cached_client.cache_stats();
            eprintln!(
                "Cache: {} total entries ({} valid, {} expired)",
                cache_stats.total_entries, cache_stats.valid_entries, cache_stats.expired_entries
            );
        }

        for (name, exporter) in &exporters {
            if let Some(summary) = exporter_summary(name, exporter.as_ref()) {
                eprintln!("{}", summary);
            }
        }
    }

    // Output all records
    for record in all_records {
        output.write_record(&record, args.resp_only)?;

        for (name, exporter) in &exporters {
            if let Err(e) = exporter.export(record.clone()).await {
                if !config.silent {
                    eprintln!("Warning: Failed to export to {}: {}", name, e);
                }
            }
        }
    }

    // Flush exporters
    for (name, exporter) in &exporters {
        exporter
            .flush()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to flush {}: {}", name, e))?;
    }

    output.flush()?;
    Ok(())
}

fn determine_record_types(args: &QueryArgs) -> Vec<RecordType> {
    let mut types = Vec::new();

    // If --record-type is specified, use those
    if !args.record_type.is_empty() {
        for rt in &args.record_type {
            match rt.to_uppercase().as_str() {
                "A" => types.push(RecordType::A),
                "AAAA" => types.push(RecordType::Aaaa),
                "CNAME" => types.push(RecordType::Cname),
                "MX" => types.push(RecordType::Mx),
                "TXT" => types.push(RecordType::Txt),
                "NS" => types.push(RecordType::Ns),
                "SOA" => types.push(RecordType::Soa),
                "PTR" => types.push(RecordType::Ptr),
                "SRV" => types.push(RecordType::Srv),
                "CAA" => types.push(RecordType::Caa),
                "CERT" => types.push(RecordType::Cert),
                "DNAME" => types.push(RecordType::Dname),
                "DNSKEY" => types.push(RecordType::Dnskey),
                "DS" => types.push(RecordType::Ds),
                "HINFO" => types.push(RecordType::Hinfo),
                "HTTPS" => types.push(RecordType::Https),
                "KEY" => types.push(RecordType::Key),
                "LOC" => types.push(RecordType::Loc),
                "NAPTR" => types.push(RecordType::Naptr),
                "NSEC" => types.push(RecordType::Nsec),
                "NSEC3" => types.push(RecordType::Nsec3),
                "OPT" => types.push(RecordType::Opt),
                "RRSIG" => types.push(RecordType::Rrsig),
                "SSHFP" => types.push(RecordType::Sshfp),
                "SVCB" => types.push(RecordType::Svcb),
                "TLSA" => types.push(RecordType::Tlsa),
                "URI" => types.push(RecordType::Uri),
                _ => eprintln!("Warning: Unknown record type '{}', ignoring", rt),
            }
        }
        return types;
    }

    // Fall back to individual flags
    if args.aaaa {
        types.push(RecordType::Aaaa);
    }
    if args.cname {
        types.push(RecordType::Cname);
    }
    if args.mx {
        types.push(RecordType::Mx);
    }
    if args.txt {
        types.push(RecordType::Txt);
    }
    if args.ns {
        types.push(RecordType::Ns);
    }
    if args.soa {
        types.push(RecordType::Soa);
    }
    if args.ptr {
        types.push(RecordType::Ptr);
    }
    if args.srv {
        types.push(RecordType::Srv);
    }
    if args.caa {
        types.push(RecordType::Caa);
    }
    if args.cert {
        types.push(RecordType::Cert);
    }
    if args.dname {
        types.push(RecordType::Dname);
    }
    if args.dnskey {
        types.push(RecordType::Dnskey);
    }
    if args.ds {
        types.push(RecordType::Ds);
    }
    if args.hinfo {
        types.push(RecordType::Hinfo);
    }
    if args.https {
        types.push(RecordType::Https);
    }
    if args.key {
        types.push(RecordType::Key);
    }
    if args.loc {
        types.push(RecordType::Loc);
    }
    if args.naptr {
        types.push(RecordType::Naptr);
    }
    if args.nsec {
        types.push(RecordType::Nsec);
    }
    if args.nsec3 {
        types.push(RecordType::Nsec3);
    }
    if args.opt {
        types.push(RecordType::Opt);
    }
    if args.rrsig {
        types.push(RecordType::Rrsig);
    }
    if args.sshfp {
        types.push(RecordType::Sshfp);
    }
    if args.svcb {
        types.push(RecordType::Svcb);
    }
    if args.tlsa {
        types.push(RecordType::Tlsa);
    }
    if args.uri {
        types.push(RecordType::Uri);
    }

    // Default to A if no specific types requested
    if types.is_empty() || args.a {
        types.push(RecordType::A);
    }

    types
}

fn read_domains(input_file: &Option<String>) -> Result<Vec<String>> {
    let lines = if let Some(file) = input_file {
        std::fs::read_to_string(file)?
            .lines()
            .map(|s| s.to_string())
            .collect()
    } else {
        // Read from stdin (not from an interactive terminal: nothing would arrive)
        use std::io::{self, BufRead, IsTerminal};
        let stdin = io::stdin();
        if stdin.is_terminal() {
            Vec::new()
        } else {
            stdin.lock().lines().collect::<io::Result<Vec<String>>>()?
        }
    };

    Ok(lines.into_iter().filter(|s| !s.trim().is_empty()).collect())
}

fn parse_rcodes(rcode_str: &Option<String>) -> Result<Vec<ResponseCode>> {
    if let Some(rcodes) = rcode_str {
        let mut result = Vec::new();
        for code_str in rcodes.split(',') {
            let code = match code_str.trim().to_uppercase().as_str() {
                "NOERROR" => ResponseCode::NoError,
                "SERVFAIL" => ResponseCode::ServFail,
                "NXDOMAIN" => ResponseCode::NxDomain,
                "REFUSED" => ResponseCode::Refused,
                "FORMERR" => ResponseCode::FormErr,
                "NOTIMP" => ResponseCode::NotImp,
                _ => continue, // Skip unknown codes
            };
            result.push(code);
        }
        Ok(result)
    } else {
        Ok(Vec::new()) // No filter
    }
}

/// Process domains with adaptive batch sizing based on performance
async fn process_with_adaptive_batching<F>(
    processor: ConcurrentProcessor<String, F>,
    domains: Vec<String>,
    adaptive_batcher: &mut AdaptiveBatchSizer,
    verbose: bool,
) -> rdnsx_core::error::Result<(Vec<DnsRecord>, ProcessingMetrics)>
where
    F: Fn(String) -> futures::future::BoxFuture<'static, rdnsx_core::error::Result<Vec<DnsRecord>>>
        + Send
        + Sync
        + 'static,
{
    let mut all_records = Vec::new();
    let mut total_metrics = ProcessingMetrics::default();
    let start_time = std::time::Instant::now();

    // Process in chunks with adaptive batch sizing
    let mut start_idx = 0;
    let mut iteration = 0;

    while start_idx < domains.len() {
        let batch_size = adaptive_batcher
            .current_size()
            .min(domains.len() - start_idx);
        let end_idx = start_idx + batch_size;

        if verbose && iteration > 0 {
            eprintln!(
                "Processing batch {}-{} (adaptive batch size: {})",
                start_idx + 1,
                end_idx,
                batch_size
            );
        }

        // Create a new processor with the current batch size
        let batch_processor = ConcurrentProcessor::new(
            ConcurrencyConfig {
                max_concurrent: processor.config().max_concurrent,
                batch_size: batch_size.min(1000), // Cap internal batch size
                timeout: processor.config().timeout,
                rate_limit: processor.config().rate_limit,
            },
            {
                let query_fn = Arc::clone(processor.query_fn());
                move |domain: String| {
                    let query_fn = Arc::clone(&query_fn);
                    Box::pin(async move { query_fn(domain).await })
                }
            },
        );

        let batch_domains = domains[start_idx..end_idx].to_vec();
        let (batch_records, batch_metrics) = batch_processor
            .process_stream(batch_domains.into_iter())
            .await?;

        all_records.extend(batch_records);
        total_metrics.total_domains += batch_metrics.total_domains;
        total_metrics.successful_queries += batch_metrics.successful_queries;
        total_metrics.failed_queries += batch_metrics.failed_queries;
        total_metrics.total_query_time += batch_metrics.total_query_time;

        // Adjust batch size based on performance
        if batch_metrics.queries_per_second > 0.0 {
            adaptive_batcher.adjust(batch_metrics.queries_per_second);
        }

        start_idx = end_idx;
        iteration += 1;
    }

    // Calculate final metrics
    let total_time = start_time.elapsed();
    if total_metrics.total_domains > 0 {
        total_metrics.average_query_time =
            total_metrics.total_query_time / total_metrics.total_domains as u32;
    }
    if total_time.as_secs_f64() > 0.0 {
        total_metrics.queries_per_second =
            total_metrics.total_domains as f64 / total_time.as_secs_f64();
    }

    Ok((all_records, total_metrics))
}

/// Exporters enabled in the configuration, by name
type NamedExporters = Vec<(&'static str, Box<dyn Exporter>)>;

/// Build the exporters enabled in the config. Fails if an exporter is enabled but
/// this binary was built without it.
async fn build_exporters(args: &QueryArgs, config: &Config) -> Result<NamedExporters> {
    let export = &config.core_config.export;
    #[allow(unused_mut)]
    let mut exporters: NamedExporters = Vec::new();
    let _ = args;

    if export.elasticsearch.enabled {
        #[cfg(feature = "export-elasticsearch")]
        exporters.push((
            "Elasticsearch",
            Box::new(
                rdnsx_core::ElasticsearchExporter::new(
                    &export.elasticsearch.url,
                    &export.elasticsearch.index,
                    export.batch_size,
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create Elasticsearch exporter: {}", e))?,
            ),
        ));
        #[cfg(not(feature = "export-elasticsearch"))]
        anyhow::bail!("Elasticsearch export is enabled but rdnsx was built without the export-elasticsearch feature");
    }

    if export.mongodb.enabled {
        #[cfg(feature = "export-mongodb")]
        exporters.push((
            "MongoDB",
            Box::new(
                rdnsx_core::MongodbExporter::new(
                    &export.mongodb.url,
                    &export.mongodb.database,
                    &export.mongodb.collection,
                    export.batch_size,
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create MongoDB exporter: {}", e))?,
            ),
        ));
        #[cfg(not(feature = "export-mongodb"))]
        anyhow::bail!(
            "MongoDB export is enabled but rdnsx was built without the export-mongodb feature"
        );
    }

    if export.cassandra.enabled {
        #[cfg(feature = "export-cassandra")]
        {
            let cassandra = &export.cassandra;
            let non_empty = |s: &str| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            };
            let cassandra_config = rdnsx_core::CassandraConfig {
                contact_points: cassandra.contact_points.clone(),
                username: non_empty(&cassandra.username),
                password: non_empty(&cassandra.password),
                keyspace: cassandra.keyspace.clone(),
                table: cassandra.table.clone(),
                batch_size: args.cassandra_batch_size,
                num_workers: args.cassandra_workers,
                ..Default::default()
            };
            exporters.push((
                "Cassandra",
                Box::new(
                    rdnsx_core::CassandraExporter::with_config(cassandra_config)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("Failed to create Cassandra exporter: {}", e)
                        })?,
                ),
            ));
        }
        #[cfg(not(feature = "export-cassandra"))]
        anyhow::bail!(
            "Cassandra export is enabled but rdnsx was built without the export-cassandra feature"
        );
    }

    Ok(exporters)
}

/// One-line performance summary for exporters that track metrics
fn exporter_summary(name: &str, exporter: &dyn Exporter) -> Option<String> {
    let metrics = exporter.metrics_summary()?;
    Some(format!("{}: {}", name, metrics))
}
