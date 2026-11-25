//! Email security record enumeration (SPF, DMARC, DKIM)

use crate::hickory_ext::{LookupExt, TxtExt};
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
    /// Domain the DMARC record was found at: the domain itself, or a parent
    /// (organizational domain fallback, RFC 7489 section 6.6.3)
    pub dmarc_domain: Option<String>,
    pub dkim_selectors: Vec<DkimSelector>,
    /// Analysis of the SPF record(s); several records is itself an error
    pub spf_analysis: Option<SpfAnalysis>,
    pub dmarc_analysis: Option<DmarcAnalysis>,
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

/// `domain` and its parents down to two labels, for the DMARC lookup
fn dmarc_candidates(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .collect();
    (0..labels.len().saturating_sub(1).max(1))
        .map(|i| labels[i..].join("."))
        .collect()
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
            dmarc_domain: None,
            dkim_selectors: Vec::new(),
            spf_analysis: None,
            dmarc_analysis: None,
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

        // DMARC: the domain itself, then its parents (organizational domain
        // fallback; without a public suffix list, parents down to two labels)
        for candidate in dmarc_candidates(domain) {
            let dmarc_domain = format!("_dmarc.{}", candidate);
            let Ok((lookup, resolver_addr)) = self
                .resolver_pool
                .query(&dmarc_domain, RecordType::Txt)
                .await
            else {
                continue;
            };
            let found = lookup.iter().find_map(|rdata| match rdata {
                hickory_resolver::proto::rr::RData::TXT(txt) => {
                    let content = txt
                        .iter()
                        .map(|bytes| String::from_utf8_lossy(bytes))
                        .collect::<Vec<_>>()
                        .join("");
                    content
                        .trim_start()
                        .to_ascii_lowercase()
                        .starts_with("v=dmarc1")
                        .then_some(content)
                }
                _ => None,
            });
            if let Some(content) = found {
                result.dmarc_record = Some(DmarcRecord {
                    content,
                    resolver: resolver_addr,
                });
                result.dmarc_domain = Some(candidate);
                break;
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

        if !result.spf_records.is_empty() {
            let mut analysis = self.analyze_spf(&result.spf_records[0].content);
            if result.spf_records.len() > 1 {
                analysis.is_valid = false;
                analysis.warnings.insert(
                    0,
                    format!(
                        "{} SPF records published: receivers treat this as a permanent error (RFC 7208 4.5)",
                        result.spf_records.len()
                    ),
                );
            }
            result.spf_analysis = Some(analysis);
        }
        if let Some(dmarc) = &result.dmarc_record {
            let mut analysis = self.analyze_dmarc(&dmarc.content);
            if result.dmarc_domain.as_deref() != Some(domain.trim_end_matches('.')) {
                analysis.warnings.push(format!(
                    "No DMARC record at {}: the policy of {} applies",
                    domain,
                    result.dmarc_domain.as_deref().unwrap_or("?")
                ));
            }
            result.dmarc_analysis = Some(analysis);
        }

        Ok(result)
    }

    /// Analyze SPF record for security issues.
    ///
    /// The DNS lookup count covers the mechanisms of this record only (include, a,
    /// mx, ptr, exists, redirect); includes are not followed.
    pub fn analyze_spf(&self, spf_record: &str) -> SpfAnalysis {
        let mut analysis = SpfAnalysis {
            is_valid: false,
            includes: Vec::new(),
            has_all: false,
            all_mechanism: None,
            dns_lookups: 0,
            warnings: Vec::new(),
            recommendations: Vec::new(),
        };

        let mut terms = spf_record.split_whitespace();
        if !terms
            .next()
            .is_some_and(|v| v.eq_ignore_ascii_case("v=spf1"))
        {
            analysis
                .warnings
                .push("SPF record does not start with 'v=spf1'".to_string());
            return analysis;
        }
        analysis.is_valid = true;

        let mut has_redirect = false;
        for term in terms {
            let lower = term.to_ascii_lowercase();
            let (qualifier, mechanism) = match lower.chars().next() {
                Some(q @ ('+' | '-' | '~' | '?')) => (q, &lower[1..]),
                _ => ('+', lower.as_str()),
            };
            let name = mechanism
                .split([':', '/', '='])
                .next()
                .unwrap_or_default();
            match name {
                "all" => {
                    analysis.has_all = true;
                    analysis.all_mechanism = Some(term.to_string());
                    match qualifier {
                        '+' => analysis.warnings.push(
                            "'+all' (or a bare 'all') authorizes every host on the Internet to send mail"
                                .to_string(),
                        ),
                        '?' => analysis
                            .warnings
                            .push("'?all' is neutral: it gives no protection".to_string()),
                        _ => {}
                    }
                }
                "include" => {
                    analysis.dns_lookups += 1;
                    if let Some(target) = term.split_once(':').map(|(_, t)| t) {
                        analysis.includes.push(target.to_string());
                    }
                }
                "a" | "mx" | "exists" => analysis.dns_lookups += 1,
                "ptr" => {
                    analysis.dns_lookups += 1;
                    analysis
                        .warnings
                        .push("'ptr' mechanism is deprecated (RFC 7208 5.5)".to_string());
                }
                "redirect" => {
                    analysis.dns_lookups += 1;
                    has_redirect = true;
                }
                _ => {}
            }
        }

        if !analysis.has_all && !has_redirect {
            analysis.recommendations.push(
                "Add an 'all' mechanism (e.g. '-all') to specify what to do with non-matching sources"
                    .to_string(),
            );
        }
        if analysis.dns_lookups > 10 {
            analysis.warnings.push(format!(
                "{} DNS-querying mechanisms in this record alone: over the limit of 10 (RFC 7208 4.6.4)",
                analysis.dns_lookups
            ));
        } else if !analysis.includes.is_empty() {
            analysis.recommendations.push(format!(
                "{} lookups in this record; includes add their own, so check the total stays under 10",
                analysis.dns_lookups
            ));
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

        if !dmarc_record
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("v=dmarc1")
        {
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
        match analysis.policy.as_deref() {
            None => {
                analysis.is_valid = false;
                analysis
                    .warnings
                    .push("DMARC record has no 'p' (policy) tag".to_string());
            }
            Some("none") => analysis.warnings.push(
                "p=none only monitors: spoofed mail is still delivered".to_string(),
            ),
            _ => {}
        }
        if analysis.subdomain_policy.as_deref() == Some("none")
            && analysis.policy.as_deref() != Some("none")
        {
            analysis
                .warnings
                .push("sp=none leaves subdomains unprotected".to_string());
        }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfAnalysis {
    pub is_valid: bool,
    pub includes: Vec<String>,
    pub has_all: bool,
    pub all_mechanism: Option<String>,
    /// DNS-querying mechanisms in this record (not counting nested includes)
    pub dns_lookups: usize,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// DMARC record analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    use super::*;

    #[test]
    fn dmarc_fallback_candidates() {
        assert_eq!(
            dmarc_candidates("mail.eu.example.com"),
            vec!["mail.eu.example.com", "eu.example.com", "example.com"]
        );
        assert_eq!(dmarc_candidates("example.com"), vec!["example.com"]);
    }

    fn spf(record: &str) -> SpfAnalysis {
        // analyze_spf does not touch the resolver pool
        let pool = crate::resolver::ResolverPool::new(&crate::config::DnsxOptions::default())
            .unwrap();
        EmailSecurityEnumerator::new(std::sync::Arc::new(pool)).analyze_spf(record)
    }

    #[test]
    fn spf_analysis() {
        let a = spf("v=spf1 include:_spf.google.com mx a ptr ~all");
        assert_eq!(a.dns_lookups, 4);
        assert!(a.warnings.iter().any(|w| w.contains("ptr")));
        assert!(spf("v=spf1 +all").warnings.iter().any(|w| w.contains("+all")));
        assert!(spf("v=spf1 all").warnings.iter().any(|w| w.contains("+all")));
        let many = (0..11).map(|i| format!("include:s{}.example", i)).collect::<Vec<_>>().join(" ");
        assert!(spf(&format!("v=spf1 {} -all", many))
            .warnings
            .iter()
            .any(|w| w.contains("over the limit")));
    }

    #[test]
    fn recognises_dkim_records() {
        assert!(is_dkim_record("v=DKIM1; k=rsa; p=MIGf"));
        assert!(is_dkim_record("k=rsa; p=MIGf"));
        assert!(!is_dkim_record("v=spf1 -all"));
    }
}
