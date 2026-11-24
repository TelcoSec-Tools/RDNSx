//! Email security record enumeration (SPF, DMARC, DKIM)

use std::sync::Arc;
use tracing::info;

use crate::error::Result;
use crate::resolver::ResolverPool;
use crate::types::RecordType;

use serde::{Deserialize, Serialize};

/// Results from email security enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSecurityResult {
    pub domain: String,
    pub spf_records: Vec<SpfRecord>,
    pub dmarc_record: Option<DmarcRecord>,
    pub dkim_selectors: Vec<DkimSelector>,
}

/// SPF record information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfRecord {
    pub content: String,
    pub resolver: String,
}

/// DMARC record information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcRecord {
    pub content: String,
    pub resolver: String,
}

/// DKIM selectors commonly used by mail providers and platforms
pub const COMMON_DKIM_SELECTORS: &[&str] = &[
    "default",
    "dkim",
    "dkim1",
    "dkim2",
    "mail",
    "smtp",
    "email",
    "key1",
    "key2",
    "google", // Google Workspace
    "selector1",
    "selector2", // Microsoft 365
    "k1",
    "k2",
    "k3", // Mailchimp / Mandrill
    "mandrill",
    "s1",
    "s2", // SendGrid and others
    "zoho",
    "zmail", // Zoho
    "protonmail",
    "protonmail2",
    "protonmail3",
    "sig1", // iCloud
    "fm1",
    "fm2",
    "fm3", // Fastmail
    "mxvault",
    "everlytickey1",
    "everlytickey2",
    "turbo-smtp",
    "pm",
    "scph0219",
];

/// Whether a TXT string looks like a DKIM key record. Many records omit "v=DKIM1",
/// so also accept records carrying a public key tag.
fn is_dkim_record(txt: &str) -> bool {
    let t = txt.trim_start();
    t.starts_with("v=DKIM1") || t.split(';').any(|tag| tag.trim().starts_with("p="))
}

/// DKIM selector information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimSelector {
    pub selector: String,
    pub record: String,
}

/// Email security enumeration functionality
pub struct EmailSecurityEnumerator {
    resolver_pool: Arc<ResolverPool>,
}

impl EmailSecurityEnumerator {
    /// Create a new email security enumerator
    pub fn new(resolver_pool: Arc<ResolverPool>) -> Self {
        Self { resolver_pool }
    }

    /// Enumerate SPF and DMARC records for email security analysis
    pub async fn enumerate(&self, domain: &str) -> Result<EmailSecurityResult> {
        info!("Enumerating email security for: {}", domain);

        let mut result = EmailSecurityResult {
            domain: domain.to_string(),
            spf_records: Vec::new(),
            dmarc_record: None,
            dkim_selectors: Vec::new(),
        };

        // Get SPF record
        if let Ok((lookup, resolver_addr)) = self
            .resolver_pool
            .query(domain, crate::RecordType::Txt)
            .await
        {
            for rdata in lookup.iter() {
                if let hickory_resolver::proto::rr::RData::TXT(txt) = rdata {
                    let txt_content = txt
                        .iter()
                        .map(|bytes| String::from_utf8_lossy(bytes))
                        .collect::<Vec<_>>()
                        .join("");

                    if txt_content.starts_with("v=spf1") {
                        result.spf_records.push(SpfRecord {
                            content: txt_content,
                            resolver: resolver_addr.clone(),
                        });
                    }
                }
            }
        }

        // Get DMARC record
        let dmarc_domain = format!("_dmarc.{}", domain);
        if let Ok((lookup, resolver_addr)) = self
            .resolver_pool
            .query(&dmarc_domain, RecordType::Txt)
            .await
        {
            for rdata in lookup.iter() {
                if let hickory_resolver::proto::rr::RData::TXT(txt) = rdata {
                    let txt_content = txt
                        .iter()
                        .map(|bytes| String::from_utf8_lossy(bytes))
                        .collect::<Vec<_>>()
                        .join("");

                    if txt_content.starts_with("v=DMARC1") {
                        result.dmarc_record = Some(DmarcRecord {
                            content: txt_content,
                            resolver: resolver_addr.clone(),
                        });
                        break; // Only expect one DMARC record
                    }
                }
            }
        }

        // Probe common DKIM selectors (records live at <selector>._domainkey.<domain>)
        let lookups = COMMON_DKIM_SELECTORS.iter().map(|selector| {
            let dkim_domain = format!("{}._domainkey.{}", selector, domain);
            async move {
                let records = match self
                    .resolver_pool
                    .query(&dkim_domain, RecordType::Txt)
                    .await
                {
                    Ok((lookup, _)) => lookup
                        .iter()
                        .filter_map(|rdata| match rdata {
                            hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                                txt.iter()
                                    .map(|bytes| String::from_utf8_lossy(bytes))
                                    .collect::<Vec<_>>()
                                    .join(""),
                            ),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    Err(_) => Vec::new(),
                };
                (*selector, records)
            }
        });

        for (selector, records) in futures::future::join_all(lookups).await {
            if let Some(record) = records.into_iter().find(|r| is_dkim_record(r)) {
                result.dkim_selectors.push(DkimSelector {
                    selector: selector.to_string(),
                    record,
                });
            }
        }

        Ok(result)
    }

    /// Analyze SPF record for security issues
    pub fn analyze_spf(&self, spf_record: &str) -> SpfAnalysis {
        let mut analysis = SpfAnalysis {
            is_valid: false,
            includes: Vec::new(),
            has_all: false,
            all_mechanism: None,
            warnings: Vec::new(),
            recommendations: Vec::new(),
        };

        // Basic SPF validation
        if !spf_record.starts_with("v=spf1") {
            analysis
                .warnings
                .push("SPF record does not start with 'v=spf1'".to_string());
            return analysis;
        }

        analysis.is_valid = true;

        // Parse mechanisms
        let mechanisms: Vec<&str> = spf_record.split_whitespace().collect();

        for mechanism in mechanisms.iter().skip(1) {
            // Skip "v=spf1"
            if let Some(inc) = mechanism.strip_prefix("include:") {
                analysis.includes.push(inc.to_string());
            } else if mechanism.starts_with("+all")
                || mechanism.starts_with("-all")
                || mechanism.starts_with("~all")
                || mechanism.starts_with("?all")
            {
                analysis.has_all = true;
                analysis.all_mechanism = Some(mechanism.to_string());
            }
        }

        // Generate recommendations
        if !analysis.has_all {
            analysis.recommendations.push(
                "Add an 'all' mechanism to specify what to do with non-matching sources"
                    .to_string(),
            );
        }

        if analysis.includes.len() > 10 {
            analysis
                .warnings
                .push("Too many include mechanisms may cause DNS lookup limits".to_string());
        }

        analysis
    }

    /// Analyze DMARC record for security issues
    pub fn analyze_dmarc(&self, dmarc_record: &str) -> DmarcAnalysis {
        let mut analysis = DmarcAnalysis {
            is_valid: false,
            policy: None,
            subdomain_policy: None,
            percentage: 100,
            rua: None,
            ruf: None,
            warnings: Vec::new(),
            recommendations: Vec::new(),
        };

        if !dmarc_record.starts_with("v=DMARC1") {
            analysis
                .warnings
                .push("DMARC record does not start with 'v=DMARC1'".to_string());
            return analysis;
        }

        analysis.is_valid = true;

        // Parse tags
        let tags: Vec<&str> = dmarc_record.split(';').collect();

        for tag in tags.iter().skip(1) {
            // Skip "v=DMARC1"
            let tag = tag.trim();
            if let Some((key, value)) = tag.split_once('=') {
                match key {
                    "p" => analysis.policy = Some(value.to_string()),
                    "sp" => analysis.subdomain_policy = Some(value.to_string()),
                    "pct" => {
                        if let Ok(pct) = value.parse::<u8>() {
                            analysis.percentage = pct;
                        }
                    }
                    "rua" => analysis.rua = Some(value.to_string()),
                    "ruf" => analysis.ruf = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        // Generate recommendations
        if analysis.policy.as_deref() != Some("reject") {
            analysis
                .recommendations
                .push("Consider using 'p=reject' for maximum protection".to_string());
        }

        if analysis.percentage < 100 {
            analysis
                .warnings
                .push("DMARC is not applied to all emails".to_string());
        }

        if analysis.rua.is_none() {
            analysis
                .recommendations
                .push("Add 'rua' tag to receive aggregate reports".to_string());
        }

        analysis
    }
}

/// SPF record analysis results
#[derive(Debug, Clone)]
pub struct SpfAnalysis {
    pub is_valid: bool,
    pub includes: Vec<String>,
    pub has_all: bool,
    pub all_mechanism: Option<String>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// DMARC record analysis results
#[derive(Debug, Clone)]
pub struct DmarcAnalysis {
    pub is_valid: bool,
    pub policy: Option<String>,
    pub subdomain_policy: Option<String>,
    pub percentage: u8,
    pub rua: Option<String>,
    pub ruf: Option<String>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}
#[cfg(test)]
mod dkim_tests {
    use super::is_dkim_record;

    #[test]
    fn recognises_dkim_records() {
        assert!(is_dkim_record("v=DKIM1; k=rsa; p=MIGf"));
        assert!(is_dkim_record("k=rsa; p=MIGf"));
        assert!(!is_dkim_record("v=spf1 -all"));
    }
}
