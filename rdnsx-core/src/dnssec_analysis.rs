//! DNSSEC enumeration and analysis

use crate::hickory_ext::LookupExt;
use hickory_resolver::proto::dnssec::PublicKey;
use std::sync::Arc;
use tracing::{debug, info, warn};

use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::rr::{RData, RecordType as HRecordType};

use crate::raw::{self, RawQueryOptions};

use crate::error::{DnsxError, Result};
use crate::resolver::ResolverPool;
use crate::types::RecordType;

use serde::{Deserialize, Serialize};

/// Results from DNSSEC enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecEnumerationResult {
    pub domain: String,
    pub dnssec_enabled: bool,
    pub dnskey_records: Vec<DnskeyInfo>,
    pub ds_records: Vec<DsInfo>,
    pub rrsig_records: usize,
    pub nsec_records: usize,
    pub nsec3_records: usize,
    pub security_issues: Vec<String>,
    pub recommendations: Vec<String>,
    /// Chain-of-trust check (DS matches a DNSKEY, and signatures validate)
    pub chain_validation: Option<ChainValidationResult>,
}

/// DNSKEY record information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnskeyInfo {
    pub key_tag: u16,
    pub algorithm: u8,
    pub flags: u16,
    pub protocol: u8,
    pub resolver: String,
    pub key_type: String,
}

/// DS record information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsInfo {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
    pub resolver: String,
}

/// Results from DNSSEC zone walking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneWalkingResult {
    pub domain: String,
    pub discovered_names: Vec<String>,
    pub nsec_chain: Vec<NsecRecord>,
    pub enumeration_successful: bool,
    pub total_names_found: usize,
    /// Denial-of-existence scheme detected: "NSEC", "NSEC3" or "none"
    pub denial_type: String,
    /// Nameserver that was walked
    pub nameserver: Option<String>,
    /// Why the walk stopped
    pub stop_reason: String,
}

/// NSEC record information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsecRecord {
    pub owner: String,
    pub next_domain: String,
    pub types: Vec<String>,
}

/// Default cap on names discovered by NSEC zone walking
pub const DEFAULT_ZONE_WALK_LIMIT: usize = 1000;

/// DNSSEC analysis functionality
pub struct DnssecAnalyzer {
    resolver_pool: Arc<ResolverPool>,
}

impl DnssecAnalyzer {
    /// Create a new DNSSEC analyzer
    pub fn new(resolver_pool: Arc<ResolverPool>) -> Self {
        Self { resolver_pool }
    }

    /// First reachable address of the zone's authoritative nameservers
    async fn authoritative_server(&self, domain: &str) -> Option<(String, std::net::SocketAddr)> {
        let servers = raw::authoritative_nameservers(&self.resolver_pool, domain)
            .await
            .ok()?;
        for ns in servers {
            if let Ok(addrs) = raw::resolve_server(&self.resolver_pool, &ns).await {
                if let Some(addr) = addrs.into_iter().next() {
                    return Some((ns, addr));
                }
            }
        }
        None
    }

    /// Perform DNSSEC enumeration and analysis
    pub async fn enumerate(&self, domain: &str) -> Result<DnssecEnumerationResult> {
        info!("Enumerating DNSSEC configuration for: {}", domain);

        let mut result = DnssecEnumerationResult {
            domain: domain.to_string(),
            dnssec_enabled: false,
            dnskey_records: Vec::new(),
            ds_records: Vec::new(),
            rrsig_records: 0,
            nsec_records: 0,
            nsec3_records: 0,
            security_issues: Vec::new(),
            recommendations: Vec::new(),
            chain_validation: None,
        };

        // DNSKEY records at the apex
        if let Ok((lookup, resolver_addr)) =
            self.resolver_pool.query(domain, RecordType::Dnskey).await
        {
            for rdata in lookup.iter() {
                if let RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) = rdata {
                    result.dnssec_enabled = true;
                    result.dnskey_records.push(DnskeyInfo {
                        key_tag: dnskey.calculate_key_tag().unwrap_or(0),
                        algorithm: u8::from(dnskey.public_key().algorithm()),
                        flags: dnskey.flags(),
                        protocol: 3,
                        resolver: resolver_addr.clone(),
                        key_type: self.analyze_dnskey_flags(dnskey.flags()),
                    });
                }
            }
        }

        // DS records are published by the parent but queried at the child name
        if let Ok((lookup, resolver_addr)) = self.resolver_pool.query(domain, RecordType::Ds).await
        {
            for rdata in lookup.iter() {
                if let RData::DNSSEC(DNSSECRData::DS(ds)) = rdata {
                    result.ds_records.push(DsInfo {
                        key_tag: ds.key_tag(),
                        algorithm: u8::from(ds.algorithm()),
                        digest_type: u8::from(ds.digest_type()),
                        digest: hex::encode(ds.digest()),
                        resolver: resolver_addr.clone(),
                    });
                }
            }
        }

        // Signatures and denial-of-existence: ask an authoritative server directly,
        // since recursive lookups only expose the answer section.
        if let Some((_, server)) = self.authoritative_server(domain).await {
            if let Ok(apex) = raw::fqdn(domain) {
                let opts = RawQueryOptions {
                    dnssec_ok: true,
                    ..Default::default()
                };
                if let Ok(msg) = raw::raw_query(server, &apex, HRecordType::SOA, opts).await {
                    result.rrsig_records = msg
                        .answers
                        .iter()
                        .filter(|r| r.record_type() == HRecordType::RRSIG)
                        .count();
                }
                if let Ok(msg) = raw::raw_query(server, &apex, HRecordType::NSEC, opts).await {
                    result.nsec_records = msg
                        .answers
                        .iter()
                        .filter(|r| r.record_type() == HRecordType::NSEC)
                        .count();
                }
                if let Ok(msg) = raw::raw_query(server, &apex, HRecordType::NSEC3PARAM, opts).await
                {
                    result.nsec3_records = msg
                        .answers
                        .iter()
                        .filter(|r| r.record_type() == HRecordType::NSEC3PARAM)
                        .count();
                }
            }
        } else {
            debug!(
                "No reachable authoritative nameserver for {}; falling back to resolver",
                domain
            );
            if let Ok((lookup, _)) = self.resolver_pool.query(domain, RecordType::Rrsig).await {
                result.rrsig_records = lookup.iter().count();
            }
            if let Ok((lookup, _)) = self.resolver_pool.query(domain, RecordType::Nsec).await {
                result.nsec_records = lookup.iter().count();
            }
        }

        if result.rrsig_records > 0 {
            result.dnssec_enabled = true;
        }

        if result.dnssec_enabled {
            result.chain_validation = self.validate_chain_inner(domain, &result).await.ok();
        }

        self.analyze_dnssec_security(&mut result);

        Ok(result)
    }

    /// Analyze DNSKEY flags to identify key role (ZSK vs KSK)
    fn analyze_dnskey_flags(&self, flags: u16) -> String {
        match flags {
            256 => "ZSK (Zone Signing Key)".to_string(),
            257 => "KSK (Key Signing Key)".to_string(),
            _ => format!("Flags ({})", flags),
        }
    }

    /// Analyze DNSSEC security and generate recommendations
    fn analyze_dnssec_security(&self, result: &mut DnssecEnumerationResult) {
        if !result.dnssec_enabled {
            result
                .recommendations
                .push("Consider enabling DNSSEC for enhanced security".to_string());
            return;
        }

        if result.dnskey_records.is_empty() {
            result
                .security_issues
                .push("DNSSEC signatures found but no DNSKEY records".to_string());
        }

        if result.ds_records.is_empty() {
            result
                .security_issues
                .push("No DS record in the parent zone: the zone is signed but not chained (island of security)".to_string());
            result
                .recommendations
                .push("Publish DS records for the KSK in the parent zone".to_string());
        }

        if result.rrsig_records == 0 {
            result
                .security_issues
                .push("No RRSIG over the SOA record".to_string());
            result
                .recommendations
                .push("Check that the zone is properly signed".to_string());
        }

        for dnskey in &result.dnskey_records {
            // RSAMD5 (1), DSA (3), RSASHA1 (5), DSA-NSEC3-SHA1 (6), RSASHA1-NSEC3-SHA1 (7)
            if matches!(dnskey.algorithm, 1 | 3 | 5 | 6 | 7) {
                result.security_issues.push(format!(
                    "Deprecated DNSSEC algorithm {} in use (key tag {})",
                    dnskey.algorithm, dnskey.key_tag
                ));
                result
                    .recommendations
                    .push("Migrate to ECDSAP256SHA256 (13) or ED25519 (15)".to_string());
            }
        }

        for ds in &result.ds_records {
            if ds.digest_type == 1 {
                result.security_issues.push(format!(
                    "DS record with SHA-1 digest (key tag {})",
                    ds.key_tag
                ));
            }
        }

        if result.nsec_records > 0 {
            result
                .security_issues
                .push("Zone uses NSEC: its contents can be enumerated by zone walking".to_string());
            result.recommendations.push(
                "Use NSEC3 (or compact denial of existence) to prevent zone walking".to_string(),
            );
        } else if result.nsec3_records == 0 {
            result
                .security_issues
                .push("Could not determine the denial-of-existence scheme (no NSEC or NSEC3PARAM at the apex)".to_string());
        }

        if let Some(chain) = &result.chain_validation {
            for error in &chain.validation_errors {
                result
                    .security_issues
                    .push(format!("Chain of trust: {}", error));
            }
        }

        if result.security_issues.is_empty() {
            result
                .recommendations
                .push("DNSSEC configuration appears secure".to_string());
        }
    }

    /// Perform DNSSEC zone walking (NSEC enumeration) with the default name limit
    pub async fn zone_walking(&self, domain: &str) -> Result<ZoneWalkingResult> {
        self.zone_walking_limited(domain, DEFAULT_ZONE_WALK_LIMIT)
            .await
    }

    /// Walk the NSEC chain of a zone, starting at the apex and following each
    /// record's "next owner" field until the chain loops back to the apex.
    /// Queries go to an authoritative nameserver.
    pub async fn zone_walking_limited(
        &self,
        domain: &str,
        max_names: usize,
    ) -> Result<ZoneWalkingResult> {
        info!("Performing DNSSEC zone walking for: {}", domain);

        let (ns_name, server) = self.authoritative_server(domain).await.ok_or_else(|| {
            DnsxError::Other(format!(
                "No reachable authoritative nameserver for {}",
                domain
            ))
        })?;
        let mut result = self
            .zone_walking_with_server(domain, server, max_names)
            .await?;
        result.nameserver = Some(format!("{} ({})", ns_name, server));
        Ok(result)
    }

    /// Walk the NSEC chain of `domain` using a specific authoritative server
    pub async fn zone_walking_with_server(
        &self,
        domain: &str,
        server: std::net::SocketAddr,
        max_names: usize,
    ) -> Result<ZoneWalkingResult> {
        let apex = raw::fqdn(domain)?;
        let mut result = ZoneWalkingResult {
            domain: domain.to_string(),
            discovered_names: Vec::new(),
            nsec_chain: Vec::new(),
            enumeration_successful: false,
            total_names_found: 0,
            denial_type: "none".to_string(),
            nameserver: None,
            stop_reason: String::new(),
        };

        result.nameserver = Some(server.to_string());

        let opts = RawQueryOptions {
            dnssec_ok: true,
            ..Default::default()
        };

        // Detect NSEC3: walking hashed names is not possible without offline cracking
        if let Ok(msg) = raw::raw_query(server, &apex, HRecordType::NSEC3PARAM, opts).await {
            if msg
                .answers
                .iter()
                .any(|r| r.record_type() == HRecordType::NSEC3PARAM)
            {
                warn!("{} uses NSEC3; zone walking is not possible", domain);
                result.denial_type = "NSEC3".to_string();
                result.stop_reason = "Zone uses NSEC3 (hashed owner names)".to_string();
                return Ok(result);
            }
        }

        let mut current = apex.clone();
        let mut visited = std::collections::HashSet::new();

        loop {
            if result.discovered_names.len() >= max_names {
                result.stop_reason = format!("Reached the limit of {} names", max_names);
                break;
            }
            if !visited.insert(current.to_lowercase()) {
                result.stop_reason = "Chain loop detected".to_string();
                break;
            }

            let msg = match raw::raw_query(server, &current, HRecordType::NSEC, opts).await {
                Ok(msg) => msg,
                Err(e) => {
                    result.stop_reason = format!("Query for {} failed: {}", current, e);
                    break;
                }
            };

            let nsec = msg.answers.iter().find_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::NSEC(nsec)) if r.name == current => Some(nsec.clone()),
                _ => None,
            });

            let Some(nsec) = nsec else {
                result.stop_reason = format!("No NSEC record returned for {}", current);
                break;
            };

            result.denial_type = "NSEC".to_string();
            let owner = current.to_string().trim_end_matches('.').to_string();
            let next = nsec.next_domain_name().clone();
            let next_str = next.to_string().trim_end_matches('.').to_string();

            if !result.discovered_names.contains(&owner) {
                result.discovered_names.push(owner.clone());
            }
            result.nsec_chain.push(NsecRecord {
                owner,
                next_domain: next_str,
                types: nsec.type_bit_maps().map(|t| t.to_string()).collect(),
            });

            // The last NSEC record points back to the apex
            if next.to_lowercase() == apex.to_lowercase() {
                result.enumeration_successful = true;
                result.stop_reason = "Walked the complete chain".to_string();
                break;
            }
            current = next;
        }

        if !result.enumeration_successful && result.nsec_chain.len() > 1 {
            // A partial walk still enumerated real names
            result.enumeration_successful = true;
        }
        result.total_names_found = result.discovered_names.len();
        Ok(result)
    }

    /// Validate the DNSSEC chain of trust
    pub async fn validate_chain(&self, domain: &str) -> Result<ChainValidationResult> {
        info!("Validating DNSSEC chain of trust for: {}", domain);
        let dnssec_info = self.enumerate(domain).await?;
        match dnssec_info.chain_validation {
            Some(chain) => Ok(chain),
            None => Ok(ChainValidationResult {
                domain: domain.to_string(),
                chain_valid: false,
                validation_errors: vec!["DNSSEC not enabled".to_string()],
                trust_anchor_status: None,
            }),
        }
    }

    async fn validate_chain_inner(
        &self,
        domain: &str,
        info: &DnssecEnumerationResult,
    ) -> Result<ChainValidationResult> {
        let mut result = ChainValidationResult {
            domain: domain.to_string(),
            chain_valid: false,
            validation_errors: Vec::new(),
            trust_anchor_status: None,
        };

        if info.dnskey_records.is_empty() {
            result
                .validation_errors
                .push("No DNSKEY records found".to_string());
        }

        // 1. The parent's DS must match one of the zone's DNSKEYs
        let name = raw::fqdn(domain)?;
        let (ds_lookup, _) = self.resolver_pool.query(domain, RecordType::Ds).await?;
        let (key_lookup, _) = self.resolver_pool.query(domain, RecordType::Dnskey).await?;
        let keys: Vec<_> = key_lookup
            .iter()
            .filter_map(|r| match r {
                RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
                _ => None,
            })
            .collect();
        let ds_records: Vec<_> = ds_lookup
            .iter()
            .filter_map(|r| match r {
                RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds.clone()),
                _ => None,
            })
            .collect();

        if ds_records.is_empty() {
            result
                .validation_errors
                .push("No DS record in parent zone".to_string());
        } else {
            let matched = ds_records.iter().any(|ds| {
                keys.iter()
                    .any(|key| ds.covers(&name, key).unwrap_or(false))
            });
            if !matched {
                result
                    .validation_errors
                    .push("No DS record in the parent matches any DNSKEY of the zone".to_string());
            }
        }

        // 2. Full signature validation from the root trust anchor (hickory validator)
        match self
            .resolver_pool
            .validated_lookup(domain, RecordType::Soa)
            .await
        {
            Ok(()) => {
                result.trust_anchor_status =
                    Some("Validated from the IANA root trust anchor".to_string());
            }
            Err(e) => {
                result.trust_anchor_status = Some("Validation failed".to_string());
                result
                    .validation_errors
                    .push(format!("Signature validation failed: {}", e));
            }
        }

        result.chain_valid = result.validation_errors.is_empty();
        Ok(result)
    }
}

/// Results from DNSSEC chain validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainValidationResult {
    pub domain: String,
    pub chain_valid: bool,
    pub validation_errors: Vec<String>,
    pub trust_anchor_status: Option<String>,
}
