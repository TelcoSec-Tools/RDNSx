//! DNS resolver pool implementation

use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

use crate::config::DnsxOptions;
use crate::error::{DnsxError, Result};
use crate::types::RecordType;
use crate::utils;

/// DNS resolver pool with connection reuse
pub struct ResolverPool {
    /// Primary resolver
    resolver: Arc<TokioAsyncResolver>,
    /// Primary resolver address
    primary_resolver_addr: String,
    /// Backup resolvers
    backup_resolvers: Vec<Arc<TokioAsyncResolver>>,
    /// Backup resolver addresses
    _backup_resolver_addrs: Vec<String>,
    /// Concurrency semaphore
    semaphore: Arc<Semaphore>,
    /// Query timeout
    timeout: Duration,
    /// Number of retries
    _retries: u32,
    /// Round-robin index for load balancing
    rr_index: std::sync::atomic::AtomicUsize,
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

        // Store primary resolver address
        let primary_resolver_addr = resolver_configs[0];

        // Create primary resolver
        let primary_config = create_resolver_config(&resolver_configs[0..1].iter().map(|addr| addr.to_string()).collect::<Vec<_>>())?;
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = options.timeout;
        resolver_opts.attempts = options.retries as usize;
        resolver_opts.validate = false; // Don't validate, just resolve
        resolver_opts.use_hosts_file = false; // Don't use hosts file
        resolver_opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6; // Prefer IPv4

        // Create primary resolver using specified primary configuration
        debug!("Creating primary resolver for {} with config: {:?}", primary_resolver_addr, primary_config);
        debug!("Resolver options: timeout={:?}, attempts={}, validate={}", resolver_opts.timeout, resolver_opts.attempts, resolver_opts.validate);
        let resolver = TokioAsyncResolver::tokio(primary_config, resolver_opts.clone());

        // Create backup resolvers if any
        let mut backup_resolvers = Vec::new();
        let mut backup_resolver_addrs = Vec::new();
        if resolver_configs.len() > 1 {
            for config in &resolver_configs[1..] {
                let backup_config = create_resolver_config(&[config.to_string()])?;
                let backup_resolver = TokioAsyncResolver::tokio(
                    backup_config,
                    resolver_opts.clone(),
                );
                backup_resolvers.push(backup_resolver);
                backup_resolver_addrs.push(config.to_string());
            }
        }

        Ok(Self {
            resolver: Arc::new(resolver),
            primary_resolver_addr: primary_resolver_addr.to_string(),
            backup_resolvers: backup_resolvers.into_iter().map(Arc::new).collect(),
            _backup_resolver_addrs: backup_resolver_addrs,
            semaphore: Arc::new(Semaphore::new(options.concurrency)),
            timeout: options.timeout,
            _retries: options.retries,
            rr_index: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Query DNS with a specific record type
    pub async fn query(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<(hickory_resolver::lookup::Lookup, String)> {
        let _permit = self.semaphore.acquire().await.map_err(|e| {
            DnsxError::Other(format!("Failed to acquire semaphore: {}", e))
        })?;

        let domain_name = hickory_resolver::Name::parse(domain, None)
            .map_err(|e| DnsxError::invalid_input(format!("Invalid domain name: {}", e)))?;

        // Use round-robin load balancing across all resolvers
        let resolver_index = self.rr_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % (self.backup_resolvers.len() + 1);

        let (resolver, resolver_addr) = if resolver_index == 0 {
            // Primary resolver
            (&self.resolver, self.primary_resolver_addr.clone())
        } else {
            // Backup resolver
            let backup_index = resolver_index - 1;
            (&self.backup_resolvers[backup_index], "backup-resolver".to_string())
        };

        debug!("Querying {} ({}) using resolver at {}", domain, record_type, resolver_addr);
        let result = tokio::time::timeout(self.timeout, resolver.lookup(domain_name.clone(), record_type.to_hickory()))
            .await;

        match result {
            Ok(Ok(lookup)) => {
                debug!("Query successful for {} ({}), lookup contains {} records", domain, record_type, lookup.iter().count());
                for rdata in lookup.iter() {
                    debug!("Found record: {:?}", rdata);
                }
                Ok((lookup, resolver_addr.to_string()))
            }
            Ok(Err(e)) => {
                if let hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    let empty_lookup = hickory_resolver::lookup::Lookup::new_with_max_ttl(
                        hickory_resolver::proto::op::Query::query(domain_name.clone(), record_type.to_hickory()),
                        std::sync::Arc::new([])
                    );
                    return Ok((empty_lookup, resolver_addr.to_string()));
                }
                debug!("Resolver {} failed for {}: {}", resolver_addr, domain, e);
                // Try other resolvers with failover
                self.try_failover_resolvers(&domain_name, record_type, resolver_index).await
            }
            Err(_) => {
                warn!("Query timeout for {} ({}) on resolver {}", domain, record_type, resolver_addr);
                // Try other resolvers with failover
                self.try_failover_resolvers(&domain_name, record_type, resolver_index).await
            }
        }
    }

    /// Get primary resolver address
    pub fn primary_resolver(&self) -> &str {
        &self.primary_resolver_addr
    }

    /// Try failover resolvers if the selected resolver fails
    async fn try_failover_resolvers(
        &self,
        domain_name: &hickory_resolver::proto::rr::Name,
        record_type: RecordType,
        failed_index: usize,
    ) -> Result<(hickory_resolver::lookup::Lookup, String)> {
        let total_resolvers = self.backup_resolvers.len() + 1;

        // Try all other resolvers except the failed one
        for i in 0..total_resolvers {
            if i == failed_index {
                continue; // Skip the failed resolver
            }

            let (resolver, resolver_addr) = if i == 0 {
                // Primary resolver
                (&self.resolver, self.primary_resolver_addr.clone())
            } else {
                // Backup resolver
                (&self.backup_resolvers[i - 1], "backup-resolver".to_string())
            };

            let result = tokio::time::timeout(self.timeout, resolver.lookup(domain_name.clone(), record_type.to_hickory()))
                .await;

            match result {
                Ok(Ok(response)) => {
                    trace!("Failover resolver {} succeeded", resolver_addr);
                    return Ok((response, resolver_addr.to_string()));
                }
                Ok(Err(e)) => {
                    if let hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                        let empty_lookup = hickory_resolver::lookup::Lookup::new_with_max_ttl(
                            hickory_resolver::proto::op::Query::query(domain_name.clone(), record_type.to_hickory()),
                            std::sync::Arc::new([])
                        );
                        return Ok((empty_lookup, resolver_addr.to_string()));
                    }
                    debug!("Failover resolver {} failed: {}", resolver_addr, e);
                }
                Err(_) => {
                    debug!("Failover resolver {} timeout", resolver_addr);
                }
            }
        }

        Err(DnsxError::resolve("All resolvers failed"))
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
            .map_err(|e| DnsxError::ResolverConfig(format!("Invalid resolver address {}: {}", addr, e)))?
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
