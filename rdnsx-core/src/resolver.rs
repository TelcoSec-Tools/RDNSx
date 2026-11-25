//! DNS resolver pool implementation

use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

use crate::concurrency::RateLimiter;
use crate::config::DnsxOptions;
use crate::error::{DnsxError, Result};
use crate::types::{RecordType, ResponseCode};
use crate::utils;

/// DNS resolver pool with connection reuse
pub struct ResolverPool {
    /// Resolvers with their addresses; the first one is the primary
    resolvers: Vec<(Arc<TokioAsyncResolver>, String)>,
    /// Concurrency semaphore
    semaphore: Arc<Semaphore>,
    /// Query timeout
    timeout: Duration,
    /// Round-robin index for load balancing
    rr_index: std::sync::atomic::AtomicUsize,
    /// Optional global rate limiter (queries per second)
    rate_limiter: Option<RateLimiter>,
}

/// Result of a single DNS query, including the response code
pub struct QueryOutcome {
    /// Records returned (empty for negative answers)
    pub lookup: hickory_resolver::lookup::Lookup,
    /// Address of the resolver that produced this answer
    pub resolver: String,
    /// DNS response code
    pub response_code: ResponseCode,
}

fn empty_lookup(
    name: &hickory_resolver::proto::rr::Name,
    record_type: RecordType,
) -> hickory_resolver::lookup::Lookup {
    hickory_resolver::lookup::Lookup::new_with_max_ttl(
        hickory_resolver::proto::op::Query::query(name.clone(), record_type.to_hickory()),
        Arc::new([]),
    )
}

impl ResolverPool {
    /// Create a new resolver pool
    pub fn new(options: &DnsxOptions) -> Result<Self> {
        let resolvers = if options.resolvers.is_empty() {
            return Err(DnsxError::validation("At least one resolver is required"));
        } else {
            options.resolvers.clone()
        };

        // Parse and validate resolvers
        let mut resolver_configs = Vec::new();
        for resolver_str in &resolvers {
            let addr = utils::parse_resolver(resolver_str)?;
            resolver_configs.push(addr);
        }

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = options.timeout;
        resolver_opts.attempts = options.retries.max(1) as usize;
        resolver_opts.validate = false; // Don't validate, just resolve
        resolver_opts.use_hosts_file = false; // Don't use hosts file

        let mut pool = Vec::with_capacity(resolver_configs.len());
        for addr in &resolver_configs {
            let config = create_resolver_config(&[addr.to_string()])?;
            debug!("Creating resolver for {}", addr);
            let resolver = TokioAsyncResolver::tokio(config, resolver_opts.clone());
            pool.push((Arc::new(resolver), addr.to_string()));
        }

        let rate_limiter = if options.rate_limit > 0 {
            Some(RateLimiter::new(options.rate_limit))
        } else {
            None
        };

        Ok(Self {
            resolvers: pool,
            semaphore: Arc::new(Semaphore::new(options.concurrency.max(1))),
            timeout: options.timeout,
            rr_index: std::sync::atomic::AtomicUsize::new(0),
            rate_limiter,
        })
    }

    /// Query DNS with a specific record type.
    ///
    /// Negative answers (NXDOMAIN, NODATA, SERVFAIL, REFUSED...) are returned as an
    /// empty lookup. Use [`ResolverPool::query_full`] to also get the response code.
    pub async fn query(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<(hickory_resolver::lookup::Lookup, String)> {
        let outcome = self.query_full(domain, record_type).await?;
        Ok((outcome.lookup, outcome.resolver))
    }

    /// Query DNS and return the lookup together with the response code and resolver used.
    ///
    /// Resolvers are chosen round-robin. A definitive answer (NOERROR or NXDOMAIN) is
    /// returned immediately; SERVFAIL/REFUSED/timeouts fail over to the next resolver.
    /// If every resolver answered with an error code, the last code is returned with an
    /// empty lookup. Only when no resolver answered at all is an error returned.
    pub async fn query_full(&self, domain: &str, record_type: RecordType) -> Result<QueryOutcome> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| DnsxError::Other(format!("Failed to acquire semaphore: {}", e)))?;

        if let Some(limiter) = &self.rate_limiter {
            limiter.wait().await;
        }

        let domain_name = hickory_resolver::Name::parse(domain, None)
            .map_err(|e| DnsxError::invalid_input(format!("Invalid domain name: {}", e)))?;

        let total = self.resolvers.len();
        let start = self
            .rr_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % total;

        let mut last_negative: Option<QueryOutcome> = None;
        let mut last_error: Option<String> = None;

        for offset in 0..total {
            let index = (start + offset) % total;
            let (resolver, resolver_addr) = &self.resolvers[index];

            debug!(
                "Querying {} ({}) using resolver at {}",
                domain, record_type, resolver_addr
            );
            let result = tokio::time::timeout(
                self.timeout,
                resolver.lookup(domain_name.clone(), record_type.to_hickory()),
            )
            .await;

            match result {
                Ok(Ok(lookup)) => {
                    trace!(
                        "Query successful for {} ({}): {} records",
                        domain,
                        record_type,
                        lookup.iter().count()
                    );
                    return Ok(QueryOutcome {
                        lookup,
                        resolver: resolver_addr.clone(),
                        response_code: ResponseCode::NoError,
                    });
                }
                Ok(Err(e)) => {
                    if let hickory_resolver::error::ResolveErrorKind::NoRecordsFound {
                        response_code,
                        ..
                    } = e.kind()
                    {
                        let code = ResponseCode::from_hickory(*response_code);
                        let outcome = QueryOutcome {
                            lookup: empty_lookup(&domain_name, record_type),
                            resolver: resolver_addr.clone(),
                            response_code: code,
                        };
                        // NOERROR (NODATA) and NXDOMAIN are authoritative answers: stop here.
                        if matches!(code, ResponseCode::NoError | ResponseCode::NxDomain) {
                            return Ok(outcome);
                        }
                        debug!(
                            "Resolver {} returned {} for {}, trying next",
                            resolver_addr, code, domain
                        );
                        last_negative = Some(outcome);
                    } else {
                        debug!("Resolver {} failed for {}: {}", resolver_addr, domain, e);
                        last_error = Some(format!("{}: {}", resolver_addr, e));
                    }
                }
                Err(_) => {
                    warn!(
                        "Query timeout for {} ({}) on resolver {}",
                        domain, record_type, resolver_addr
                    );
                    last_error = Some(format!("{}: timeout", resolver_addr));
                }
            }
        }

        if let Some(outcome) = last_negative {
            return Ok(outcome);
        }

        Err(DnsxError::resolve(format!(
            "All resolvers failed for {} ({}): {}",
            domain,
            record_type,
            last_error.unwrap_or_else(|| "no resolvers".to_string())
        )))
    }

    /// Get primary resolver address
    pub fn primary_resolver(&self) -> &str {
        &self.resolvers[0].1
    }

    /// Look up `domain` with DNSSEC validation enabled (hickory's validator, anchored
    /// at the IANA root key). Succeeds only if the answer, or the proof of
    /// non-existence, validates.
    pub async fn validated_lookup(&self, domain: &str, record_type: RecordType) -> Result<()> {
        let mut opts = ResolverOpts::default();
        opts.timeout = self.timeout;
        opts.validate = true;
        opts.use_hosts_file = false;
        let config = create_resolver_config(&[self.resolvers[0].1.clone()])?;
        let resolver = TokioAsyncResolver::tokio(config, opts);

        let name = hickory_resolver::Name::parse(domain, None)
            .map_err(|e| DnsxError::invalid_input(format!("Invalid domain name: {}", e)))?;
        match tokio::time::timeout(
            self.timeout * 4,
            resolver.lookup(name, record_type.to_hickory()),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(DnsxError::resolve(e.to_string())),
            Err(_) => Err(DnsxError::resolve("validation timed out")),
        }
    }

    /// Addresses of all configured resolvers, primary first
    pub fn resolver_addresses(&self) -> Vec<String> {
        self.resolvers
            .iter()
            .map(|(_, addr)| addr.clone())
            .collect()
    }

    /// Lookup A records (IPv4)
    pub async fn lookup_ipv4(&self, domain: &str) -> Result<Vec<std::net::Ipv4Addr>> {
        let (lookup, _) = self.query(domain, RecordType::A).await?;
        let mut ips = Vec::new();

        for rdata in lookup.iter() {
            if let RData::A(ipv4) = rdata {
                ips.push(**ipv4);
            }
        }

        Ok(ips)
    }

    /// Lookup AAAA records (IPv6)
    pub async fn lookup_ipv6(&self, domain: &str) -> Result<Vec<std::net::Ipv6Addr>> {
        let (lookup, _) = self.query(domain, RecordType::Aaaa).await?;
        let mut ips = Vec::new();

        for rdata in lookup.iter() {
            if let RData::AAAA(ipv6) = rdata {
                ips.push(**ipv6);
            }
        }

        Ok(ips)
    }
}

/// Create resolver config from resolver addresses
fn create_resolver_config(addrs: &[String]) -> Result<ResolverConfig> {
    use hickory_resolver::config::{NameServerConfig, Protocol};
    use std::net::{SocketAddr, ToSocketAddrs};

    let mut config = ResolverConfig::new();

    for addr in addrs {
        let socket_addr: SocketAddr = addr
            .to_socket_addrs()
            .map_err(|e| {
                DnsxError::ResolverConfig(format!("Invalid resolver address {}: {}", addr, e))
            })?
            .next()
            .ok_or_else(|| DnsxError::ResolverConfig(format!("Failed to resolve {}", addr)))?;

        config.add_name_server(NameServerConfig {
            socket_addr,
            protocol: Protocol::Udp, // Default to UDP
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
            tls_config: None,
        });
    }

    Ok(config)
}
