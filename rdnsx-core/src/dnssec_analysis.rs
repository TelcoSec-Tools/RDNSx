//! DNSSEC enumeration and analysis

use std::sync::Arc;
use tracing::{info, warn};

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
}

/// NSEC record information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsecRecord {
    pub owner: String,
    pub next_domain: String,
    pub types: Vec<String>,
}

/// DNSSEC analysis functionality
pub struct DnssecAnalyzer {
    resolver_pool: Arc<ResolverPool>,
}

impl DnssecAnalyzer {
    /// Create a new DNSSEC analyzer
    pub fn new(resolver_pool: Arc<ResolverPool>) -> Self {
        Self { resolver_pool }
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
        };

        // Check for DNSKEY records (indicates DNSSEC)
        if let Ok((lookup, resolver_addr)) = self.resolver_pool.query(domain, RecordType::Dnskey).await {
            for rdata in lookup.iter() {
                if let hickory_resolver::proto::rr::RData::DNSSEC(hickory_resolver::proto::rr::dnssec::rdata::DNSSECRData::DNSKEY(dnskey)) = rdata {
                    result.dnssec_enabled = true;
                    let key_type = self.analyze_dnskey_flags(dnskey.flags());
                    result.dnskey_records.push(DnskeyInfo {
                        key_tag: dnskey.calculate_key_tag().unwrap_or(0),
                        algorithm: u8::from(dnskey.algorithm()),
                        flags: dnskey.flags(),
                        protocol: 3,
                        resolver: resolver_addr.clone(),
                        key_type,
                    });
                }
            }
        }

        // Check for DS records
        if let Ok((lookup, resolver_addr)) = self.resolver_pool.query(domain, RecordType::Ds).await {
            for rdata in lookup.iter() {
                if let hickory_resolver::proto::rr::RData::DNSSEC(hickory_resolver::proto::rr::dnssec::rdata::DNSSECRData::DS(ds)) = rdata {
                    result.dnssec_enabled = true;
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

        // Check for RRSIG records
        if let Ok((lookup, _)) = self.resolver_pool.query(domain, RecordType::Rrsig).await {
            let count = lookup.iter().count();
            if count > 0 {
                result.dnssec_enabled = true;
                result.rrsig_records = count;
            }
        }

        // Check for NSEC records (DNSSEC proof of non-existence)
        if let Ok((lookup, _)) = self.resolver_pool.query(domain, RecordType::Nsec).await {
            let count = lookup.iter().count();
            if count > 0 {
                result.dnssec_enabled = true;
                result.nsec_records = count;
            }
        }

        // Check for NSEC3 records
        if let Ok((lookup, _)) = self.resolver_pool.query(domain, RecordType::Nsec3).await {
            let count = lookup.iter().count();
            if count > 0 {
                result.dnssec_enabled = true;
                result.nsec3_records = count;
            }
        }

        // Analyze security issues and generate recommendations
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
        // Check for common DNSSEC issues
        if result.dnssec_enabled {
            if result.dnskey_records.is_empty() {
                result.security_issues.push("DNSSEC enabled but no DNSKEY records found".to_string());
            }

            if result.ds_records.is_empty() && result.domain.contains('.') {
                result.security_issues.push("No DS records found in parent zone".to_string());
                result.recommendations.push("Ensure DS records are properly published in parent zone".to_string());
            }

            if result.rrsig_records == 0 {
                result.security_issues.push("DNSSEC enabled but no RRSIG records found".to_string());
                result.recommendations.push("Check if zone is properly signed".to_string());
            }

            // Check for algorithm security
            for dnskey in &result.dnskey_records {
                if dnskey.algorithm == 1 || dnskey.algorithm == 5 {
                    result.security_issues.push(format!("Weak DNSSEC algorithm {} in use", dnskey.algorithm));
                    result.recommendations.push("Consider upgrading to stronger algorithms (ECDSA or Ed25519)".to_string());
                }
            }

            // Check for NSEC vs NSEC3
            if result.nsec_records > 0 && result.nsec3_records > 0 {
                result.recommendations.push("Both NSEC and NSEC3 records found - consider standardizing".to_string());
            } else if result.nsec_records == 0 && result.nsec3_records == 0 && result.dnssec_enabled {
                result.security_issues.push("No NSEC or NSEC3 records found".to_string());
            }

        } else {
            result.recommendations.push("Consider enabling DNSSEC for enhanced security".to_string());
        }

        // General recommendations
        if result.dnssec_enabled && result.security_issues.is_empty() {
            result.recommendations.push("DNSSEC configuration appears secure".to_string());
        }
    }

    /// Perform DNSSEC zone walking (NSEC enumeration)
    pub async fn zone_walking(&self, domain: &str) -> Result<ZoneWalkingResult> {
        info!("Performing DNSSEC zone walking for: {}", domain);

        let mut result = ZoneWalkingResult {
            domain: domain.to_string(),
            discovered_names: Vec::new(),
            nsec_chain: Vec::new(),
            enumeration_successful: false,
            total_names_found: 0,
        };

        // First check if DNSSEC is enabled
        let dnssec_check = self.enumerate(domain).await?;
        if !dnssec_check.dnssec_enabled {
            return Err(DnsxError::Other("DNSSEC not enabled on this domain".to_string()));
        }

        // Check if NSEC or NSEC3 is in use
        let use_nsec3 = dnssec_check.nsec3_records > dnssec_check.nsec_records;

        if use_nsec3 {
            // NSEC3 zone walking is more complex and may not be practical
            warn!("NSEC3 detected - zone walking is more difficult with NSEC3");
            result.enumeration_successful = false;
        } else {
            let mut current_name = domain.to_string();
            let mut visited = std::collections::HashSet::new();

            for _ in 0..25 {
                if visited.contains(&current_name) {
                    break;
                }
                visited.insert(current_name.clone());

                let test_subdomain = format!("000-nonexistent-{}.{}", rand::random::<u16>(), current_name);
                if let Ok((lookup, _)) = self.resolver_pool.query(&test_subdomain, RecordType::Nsec).await {
                    let mut found_next = false;
                    for rdata in lookup.iter() {
                        if let hickory_resolver::proto::rr::RData::DNSSEC(hickory_resolver::proto::rr::dnssec::rdata::DNSSECRData::NSEC(nsec)) = rdata {
                            let next_name = nsec.next_domain_name().to_string();
                            let mut types = Vec::new();
                            for record_type in nsec.type_bit_maps() {
                                types.push(format!("{}", record_type));
                            }

                            result.nsec_chain.push(NsecRecord {
                                owner: current_name.clone(),
                                next_domain: next_name.clone(),
                                types,
                            });

                            if !result.discovered_names.contains(&next_name) {
                                result.discovered_names.push(next_name.clone());
                            }

                            current_name = next_name.trim_end_matches('.').to_string();
                            found_next = true;
                            break;
                        }
                    }
                    if !found_next {
                        break;
                    }
                } else {
                    break;
                }
            }

            result.enumeration_successful = !result.nsec_chain.is_empty();
            result.total_names_found = result.discovered_names.len();
        }

        Ok(result)
    }

    /// Validate DNSSEC chain of trust
    pub async fn validate_chain(&self, domain: &str) -> Result<ChainValidationResult> {
        info!("Validating DNSSEC chain of trust for: {}", domain);

        let mut result = ChainValidationResult {
            domain: domain.to_string(),
            chain_valid: false,
            validation_errors: Vec::new(),
            trust_anchor_status: None,
        };

        // Get DNSKEY records
        let dnssec_info = self.enumerate(domain).await?;

        if !dnssec_info.dnssec_enabled {
            result.validation_errors.push("DNSSEC not enabled".to_string());
            return Ok(result);
        }

        // Basic validation (simplified - in practice, you'd verify signatures)
        if dnssec_info.dnskey_records.is_empty() {
            result.validation_errors.push("No DNSKEY records found".to_string());
        }

        if dnssec_info.rrsig_records == 0 {
            result.validation_errors.push("No RRSIG records found".to_string());
        }

        // Check parent DS records for chain of trust
        if domain.contains('.') {
            let parent_domain = domain.split('.').skip(1).collect::<Vec<&str>>().join(".");
            if let Ok(parent_ds) = self.resolver_pool.query(&parent_domain, RecordType::Ds).await {
                if parent_ds.0.iter().next().is_none() {
                    result.validation_errors.push("No DS record in parent zone".to_string());
                }
            }
        }

        result.chain_valid = result.validation_errors.is_empty();

        Ok(result)
    }
}

/// Results from DNSSEC chain validation
#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    pub domain: String,
    pub chain_valid: bool,
    pub validation_errors: Vec<String>,
    pub trust_anchor_status: Option<String>,
}