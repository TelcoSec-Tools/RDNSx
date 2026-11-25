//! Subdomain bruteforcing

use std::collections::HashSet;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use tracing::debug;

use crate::client::DnsxClient;
use crate::error::Result;
use crate::input::read_wordlist;
use crate::types::{DnsRecord, RecordType};
use crate::wildcard::WildcardFilter;

/// Subdomain bruteforcer
pub struct Bruteforcer {
    client: Arc<DnsxClient>,
    concurrency: usize,
    wildcard_filter: Option<WildcardFilter>,
}

impl Bruteforcer {
    /// Create a new bruteforcer
    pub fn new(client: Arc<DnsxClient>, concurrency: usize) -> Self {
        Self {
            client,
            concurrency: concurrency.max(1),
            wildcard_filter: None,
        }
    }

    /// Drop results that are only answered by a wildcard record
    pub fn with_wildcard_filter(mut self, filter: WildcardFilter) -> Self {
        self.wildcard_filter = Some(filter);
        self
    }

    /// Generate subdomain candidates from wordlist and domain
    fn generate_subdomains(domain: &str, words: Vec<String>, placeholder: &str) -> Vec<String> {
        let mut seen = HashSet::new();
        words
            .into_iter()
            .map(|word| {
                let word = word.trim().to_string();
                if domain.contains(placeholder) {
                    domain.replace(placeholder, &word)
                } else {
                    format!("{}.{}", word, domain)
                }
            })
            .filter(|candidate| seen.insert(candidate.clone()))
            .collect()
    }

    /// Enumerate subdomains for a domain using a wordlist (A records)
    pub async fn enumerate(
        &self,
        domain: &str,
        wordlist_source: &str,
        placeholder: &str,
    ) -> Result<Vec<String>> {
        Ok(self
            .enumerate_with_records(domain, wordlist_source, placeholder, RecordType::A)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    /// Enumerate subdomains and return all DNS records found.
    ///
    /// Candidates are resolved with at most `concurrency` queries in flight, so
    /// memory stays flat regardless of wordlist size.
    pub async fn enumerate_with_records(
        &self,
        domain: &str,
        wordlist_source: &str,
        placeholder: &str,
        record_type: RecordType,
    ) -> Result<Vec<(String, Vec<DnsRecord>)>> {
        let words = read_wordlist(wordlist_source)?;
        debug!("Loaded {} words from wordlist", words.len());

        let subdomains = Self::generate_subdomains(domain, words, placeholder);
        debug!("Generated {} subdomain candidates", subdomains.len());

        let client = &self.client;
        let filter = self.wildcard_filter.as_ref();

        let found: Vec<(String, Vec<DnsRecord>)> = stream::iter(subdomains)
            .map(|subdomain| async move {
                let records = match client.query(&subdomain, record_type).await {
                    Ok(records) if !records.is_empty() => records,
                    _ => return None,
                };
                let records = match filter {
                    Some(filter) => filter.filter_by_ip(records).await.ok()?,
                    None => records,
                };
                if records.is_empty() {
                    None
                } else {
                    Some((subdomain, records))
                }
            })
            .buffer_unordered(self.concurrency)
            .filter_map(|result| async move { result })
            .collect()
            .await;

        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_deduplicates_candidates() {
        let words = vec!["www".to_string(), " api ".to_string(), "www".to_string()];
        let subs = Bruteforcer::generate_subdomains("example.com", words, "FUZZ");
        assert_eq!(subs, vec!["www.example.com", "api.example.com"]);
    }

    #[test]
    fn replaces_placeholder() {
        let words = vec!["dev".to_string()];
        let subs = Bruteforcer::generate_subdomains("FUZZ.internal.example.com", words, "FUZZ");
        assert_eq!(subs, vec!["dev.internal.example.com"]);
    }
}
