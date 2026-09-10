//! Subdomain bruteforcing

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::debug;

use crate::client::DnsxClient;
use crate::error::Result;
use crate::input::read_wordlist;
use crate::types::RecordType;

/// Subdomain bruteforcer
pub struct Bruteforcer {
    client: Arc<DnsxClient>,
    concurrency: usize,
}

impl Bruteforcer {
    /// Create a new bruteforcer
    pub fn new(client: Arc<DnsxClient>, concurrency: usize) -> Self {
        Self {
            client,
            concurrency,
        }
    }

    /// Generate subdomain candidates from wordlist and domain
    fn generate_subdomains(domain: &str, words: Vec<String>, placeholder: &str) -> Vec<String> {
        let mut subdomains = Vec::new();

        for word in words {
            let subdomain = if domain.contains(placeholder) {
                domain.replace(placeholder, &word)
            } else {
                format!("{}.{}", word.trim(), domain)
            };
            debug!("Generated subdomain: {} -> {}", word.trim(), subdomain);
            subdomains.push(subdomain);
        }

        subdomains
    }

    /// Enumerate subdomains for a domain using a wordlist
    pub async fn enumerate(
        &self,
        domain: &str,
        wordlist_source: &str,
        placeholder: &str,
    ) -> Result<Vec<String>> {
        // Read wordlist
        let words = read_wordlist(wordlist_source)?;
        debug!("Loaded {} words from wordlist", words.len());

        // Generate subdomain candidates
        let subdomains = Self::generate_subdomains(domain, words, placeholder);
        debug!("Generated {} subdomain candidates", subdomains.len());

        // Query subdomains sequentially for now (to avoid complexity)
        let mut found = Vec::new();

        for subdomain in subdomains {
            match self.client.lookup_ipv4(&subdomain).await {
                Ok(ips) if !ips.is_empty() => {
                    debug!("Found subdomain: {}", subdomain);
                    found.push(subdomain);
                }
                _ => {} // Subdomain doesn't exist or failed to resolve
            }
        }

        // Deduplicate
        let unique: HashSet<String> = HashSet::from_iter(found);
        Ok(unique.into_iter().collect())
    }

    /// Enumerate subdomains and return all DNS records found
    pub async fn enumerate_with_records(
        &self,
        domain: &str,
        wordlist_source: &str,
        placeholder: &str,
        record_type: RecordType,
    ) -> Result<Vec<(String, Vec<crate::types::DnsRecord>)>> {
        // Read wordlist
        let words = read_wordlist(wordlist_source)?;
        debug!("Loaded {} words from wordlist", words.len());

        // Generate subdomain candidates
        let subdomains = Self::generate_subdomains(domain, words, placeholder);
        debug!("Generated {} subdomain candidates", subdomains.len());

        // Query subdomains concurrently
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        for subdomain in subdomains {
            let client = Arc::clone(&self.client);
            let permit = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit.acquire().await.ok();
                match client.query(&subdomain, record_type).await {
                    Ok(records) if !records.is_empty() => Some((subdomain, records)),
                    _ => None,
                }
            });

            handles.push(handle);
        }

        // Collect results
        let mut found = Vec::new();
        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                found.push(result);
            }
        }

        Ok(found)
    }
}
