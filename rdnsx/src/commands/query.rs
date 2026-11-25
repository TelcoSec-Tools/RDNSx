//! Query command implementation

use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use rdnsx_core::{
    config::DnsxOptions, CachedDnsClient, DnsCache, DnsxClient, RecordType, RecordValue,
    ResolverPool, ResponseCode, WildcardFilter,
};

use crate::cli::Config;
use crate::exporters::{CassandraTuning, ExportSink};
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

    /// AFSDB records
    #[arg(long)]
    pub afsdb: bool,

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

    /// Add the origin ASN, prefix and registry country of each address
    /// (Team Cymru DNS lookup: the addresses are sent to asn.cymru.com)
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

    /// Deprecated, no effect: input is always read lazily and results are
    /// written as each domain completes
    #[arg(long, hide = true)]
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
    use futures::stream::{self, StreamExt};

    let record_types = determine_record_types(&args)?;

    let dns_options = DnsxOptions {
        resolvers: config.core_config.resolvers.servers.clone(),
        timeout: std::time::Duration::from_secs(config.core_config.resolvers.timeout),
        retries: config.core_config.resolvers.retries,
        concurrency: config.core_config.performance.threads,
        rate_limit: config.core_config.performance.rate_limit,
    };
    let resolver_pool = Arc::new(ResolverPool::new(&dns_options)?);
    let client = DnsxClient::from_pool(Arc::clone(&resolver_pool));

    let wildcard_filter: Option<WildcardFilter> = args.wildcard_domain.as_ref().map(|base| {
        WildcardFilter::new(Some(base.clone()), Arc::clone(&resolver_pool), 3)
    });

    let allowed_rcodes = parse_rcodes(&args.rcode)?;

    let mut output = OutputWriter::new(
        config.output_file.clone(),
        config.json_output,
        config.silent,
    )?;

    let sink = ExportSink::from_config(
        &config,
        CassandraTuning {
            batch_size: args.cassandra_batch_size,
            workers: args.cassandra_workers,
        },
    )
    .await?;

    let (client, cached_client): (
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
        let cached = Arc::new(CachedDnsClient::new(client, cache));
        (cached.clone(), Some(cached))
    } else {
        (Arc::new(client), None)
    };

    // Domains are read lazily and results are written as soon as each domain
    // completes, so memory use does not grow with the size of the input.
    let domains = domain_source(&args)?;
    let concurrency = config.core_config.performance.threads.max(1);
    let start = std::time::Instant::now();

    let results = stream::iter(domains)
        .filter_map(|line| async move {
            match line {
                Ok(d) => {
                    let d = d.trim().to_string();
                    (!d.is_empty() && !d.starts_with('#')).then_some(d)
                }
                Err(e) => {
                    eprintln!("Error reading domain: {}", e);
                    None
                }
            }
        })
        .map(|domain| {
            let client = Arc::clone(&client);
            let record_types = record_types.clone();
            let allowed_rcodes = allowed_rcodes.clone();
            let wildcard_filter = wildcard_filter.clone();
            async move {
                let mut records = Vec::new();
                let mut errors = Vec::new();
                for record_type in &record_types {
                    match client.query_response(&domain, *record_type).await {
                        Ok(response) => {
                            // With an rcode filter, report negative answers too (as
                            // "domain [NXDOMAIN]") and keep only the matching codes.
                            let found = if allowed_rcodes.is_empty() {
                                response.records
                            } else if allowed_rcodes.contains(&response.response_code) {
                                response.into_records_or_negative()
                            } else {
                                Vec::new()
                            };
                            let found = match &wildcard_filter {
                                Some(filter) => match filter.filter(found.clone()).await {
                                    Ok(kept) => kept,
                                    Err(e) => {
                                        errors.push(format!(
                                            "Wildcard filtering failed for {}: {}",
                                            domain, e
                                        ));
                                        found
                                    }
                                },
                                None => found,
                            };
                            records.extend(found);
                        }
                        Err(e) => errors.push(format!(
                            "Error querying {} ({}): {}",
                            domain, record_type, e
                        )),
                    }
                }
                (records, errors, record_types.len())
            }
        })
        .buffer_unordered(concurrency);
    let mut results = std::pin::pin!(results);

    let mut total_domains = 0usize;
    let mut total_queries = 0usize;
    let mut failed_queries = 0usize;
    let mut total_records = 0usize;
    while let Some((records, errors, queries)) = results.next().await {
        total_domains += 1;
        total_queries += queries;
        failed_queries += errors.len();
        for error in &errors {
            eprintln!("{}", error);
        }
        for record in &records {
            let asn = if args.asn {
                match &record.value {
                    RecordValue::Ip(ip) => {
                        rdnsx_core::asn::lookup_ip_asn(&resolver_pool, ip).await.ok()
                    }
                    _ => None,
                }
            } else {
                None
            };
            output.write_record_with_asn(record, args.resp_only, asn.as_ref())?;
            sink.export(record).await;
        }
        total_records += records.len();
        output.flush()?;
    }

    if total_domains == 0 && !config.silent {
        eprintln!(
            "No domains to process. Use --list to specify a file or provide domains as arguments."
        );
    }

    if !config.silent {
        let secs = start.elapsed().as_secs_f64();
        eprintln!(
            "Processed {} domains, collected {} records ({:.1} queries/s)",
            total_domains,
            total_records,
            if secs > 0.0 { total_queries as f64 / secs } else { 0.0 }
        );
        if let Some(cached) = &cached_client {
            let stats = cached.cache_stats();
            eprintln!(
                "Cache: {} total entries ({} valid, {} expired)",
                stats.total_entries, stats.valid_entries, stats.expired_entries
            );
        }
    }

    sink.finish().await?;
    output.flush()?;

    if total_queries > 0 && failed_queries == total_queries {
        anyhow::bail!(
            "All {} queries failed (no resolver answered); check --resolvers and network access",
            total_queries
        );
    }
    Ok(())
}

/// Domains to query, read lazily: the `--list` file, or stdin when no domains
/// were given on the command line, followed by the command-line domains.
fn domain_source(
    args: &QueryArgs,
) -> Result<Box<dyn Iterator<Item = std::io::Result<String>> + Send>> {
    use std::io::{BufRead, IsTerminal};

    let cli: Vec<std::io::Result<String>> = args.domains.iter().cloned().map(Ok).collect();
    let input: Box<dyn Iterator<Item = std::io::Result<String>> + Send> =
        if let Some(path) = &args.list {
            let file = std::fs::File::open(path)
                .map_err(|e| anyhow::anyhow!("Cannot open {}: {}", path, e))?;
            Box::new(std::io::BufReader::new(file).lines())
        } else if args.domains.is_empty() && !std::io::stdin().is_terminal() {
            Box::new(std::io::BufReader::new(std::io::stdin()).lines())
        } else {
            Box::new(std::iter::empty())
        };
    Ok(Box::new(input.chain(cli)))
}

fn determine_record_types(args: &QueryArgs) -> Result<Vec<RecordType>> {
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
                "AFSDB" => types.push(RecordType::Afsdb),
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
                "RRSIG" => types.push(RecordType::Rrsig),
                "SSHFP" => types.push(RecordType::Sshfp),
                "SVCB" => types.push(RecordType::Svcb),
                "TLSA" => types.push(RecordType::Tlsa),
                "URI" => types.push(RecordType::Uri),
                _ => anyhow::bail!("Unknown record type '{}'", rt),
            }
        }
        return Ok(types);
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
    if args.afsdb {
        types.push(RecordType::Afsdb);
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

    Ok(types)
}

fn parse_rcodes(rcode_str: &Option<String>) -> Result<Vec<ResponseCode>> {
    let Some(rcodes) = rcode_str else {
        return Ok(Vec::new()); // No filter
    };
    rcodes
        .split(',')
        .filter(|c| !c.trim().is_empty())
        .map(|c| {
            ResponseCode::from_name(c)
                .ok_or_else(|| anyhow::anyhow!("Unknown response code '{}'", c.trim()))
        })
        .collect()
}
