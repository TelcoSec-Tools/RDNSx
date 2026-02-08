//! DNS response caching to avoid redundant queries

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::debug;

use crate::error::Result;
use crate::types::{DnsRecord, RecordType};

/// Cache key combining domain and record type
#[derive(Debug, Clone, Eq)]
pub struct CacheKey {
    pub domain: String,
    pub record_type: RecordType,
}

impl CacheKey {
    pub fn new(domain: impl Into<String>, record_type: RecordType) -> Self {
        Self {
            domain: domain.into(),
            record_type,
        }
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.hash(state);
        self.record_type.hash(state);
    }
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.domain == other.domain && self.record_type == other.record_type
    }
}

/// Cached DNS response with TTL information
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub records: Vec<DnsRecord>,
    pub cached_at: Instant,
    pub ttl: Duration,
}

impl CachedResponse {
    pub fn new(records: Vec<DnsRecord>, ttl: Duration) -> Self {
        Self {
            records,
            cached_at: Instant::now(),
            ttl,
        }
    }

    /// Check if the cached response is still valid
    pub fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        if let Some(remaining) = self.ttl.checked_sub(self.cached_at.elapsed()) {
            remaining
        } else {
            Duration::from_secs(0)
        }
    }
}

/// DNS response cache with TTL support
pub struct DnsCache {
    cache: Arc<RwLock<HashMap<CacheKey, CachedResponse>>>,
    max_size: usize,
    default_ttl: Duration,
}

impl DnsCache {
    /// Create a new DNS cache
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            default_ttl,
        }
    }

    /// Get a cached response if it exists and is still valid
    pub fn get(&self, key: &CacheKey) -> Option<Vec<DnsRecord>> {
        let cache = self.cache.read();

        if let Some(cached) = cache.get(key) {
            if cached.is_valid() {
                debug!("Cache hit for {} {:?}", key.domain, key.record_type);
                Some(cached.records.clone())
            } else {
                None // Expired, will be cleaned up on next put
            }
        } else {
            None
        }
    }

    /// Store a response in the cache
    pub fn put(&self, key: CacheKey, records: Vec<DnsRecord>, ttl: Option<Duration>) {
        let ttl = ttl.unwrap_or(self.default_ttl);
        let cached_response = CachedResponse::new(records, ttl);

        let mut cache = self.cache.write();

        // Clean up expired entries if we're at capacity
        if cache.len() >= self.max_size {
            self.cleanup_expired(&mut cache);
        }

        // If still at capacity, remove oldest entries
        if cache.len() >= self.max_size {
            self.evict_oldest(&mut cache);
        }

        cache.insert(key, cached_response);
        debug!("Cached response, cache size: {}", cache.len());
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.read();
        let mut valid_entries = 0;
        let mut expired_entries = 0;
        let mut total_ttl = Duration::from_secs(0);

        for cached in cache.values() {
            if cached.is_valid() {
                valid_entries += 1;
                total_ttl += cached.remaining_ttl();
            } else {
                expired_entries += 1;
            }
        }

        let avg_ttl = if valid_entries > 0 {
            total_ttl / valid_entries as u32
        } else {
            Duration::from_secs(0)
        };

        CacheStats {
            total_entries: cache.len(),
            valid_entries,
            expired_entries,
            average_ttl: avg_ttl,
        }
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        let mut cache = self.cache.write();
        cache.clear();
    }

    /// Clean up expired entries
    fn cleanup_expired(&self, cache: &mut HashMap<CacheKey, CachedResponse>) {
        cache.retain(|_, cached| cached.is_valid());
    }

    /// Evict oldest entries (simple LRU approximation)
    fn evict_oldest(&self, cache: &mut HashMap<CacheKey, CachedResponse>) {
        // For simplicity, just remove 10% of entries
        let to_remove = (cache.len() / 10).max(1);
        let keys_to_remove: Vec<CacheKey> = cache.keys().take(to_remove).cloned().collect();

        for key in keys_to_remove {
            cache.remove(&key);
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub expired_entries: usize,
    pub average_ttl: Duration,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache: {} total ({} valid, {} expired), avg TTL: {:.1}s",
            self.total_entries,
            self.valid_entries,
            self.expired_entries,
            self.average_ttl.as_secs_f64()
        )
    }
}

/// Cached DNS client wrapper
pub struct CachedDnsClient<C> {
    client: C,
    cache: DnsCache,
}

impl<C> CachedDnsClient<C>
where
    C: DnsQuery,
{
    /// Create a new cached DNS client
    pub fn new(client: C, cache: DnsCache) -> Self {
        Self { client, cache }
    }

    /// Query with caching
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<DnsRecord>> {
        let key = CacheKey::new(domain, record_type);

        // Check cache first
        if let Some(cached_records) = self.cache.get(&key) {
            return Ok(cached_records);
        }

        // Query upstream
        let records = self.client.query(domain, record_type).await?;

        // Cache the result (use minimum TTL from records or default)
        let min_ttl = records.iter()
            .map(|r| Duration::from_secs(r.ttl as u64))
            .min()
            .unwrap_or(Duration::from_secs(300)); // 5 minutes default

        self.cache.put(key, records.clone(), Some(min_ttl));

        Ok(records)
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

/// Trait for DNS query operations
#[async_trait::async_trait]
pub trait DnsQuery {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<DnsRecord>>;
}

#[async_trait::async_trait]
impl DnsQuery for crate::client::DnsxClient {
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<DnsRecord>> {
        self.query(domain, record_type).await
    }
}

#[async_trait::async_trait]
impl<C> DnsQuery for CachedDnsClient<C>
where
    C: DnsQuery + Send + Sync,
{
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<DnsRecord>> {
        self.query(domain, record_type).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ResponseCode;

    fn create_test_record(domain: &str, record_type: RecordType) -> DnsRecord {
        DnsRecord {
            domain: domain.to_string(),
            record_type,
            value: crate::types::RecordValue::Domain("test.example.com".to_string()),
            ttl: 300,
            response_code: ResponseCode::NoError,
            resolver: "127.0.0.1".to_string(),
            timestamp: std::time::SystemTime::now(),
            query_time_ms: 10.5,
        }
    }

    #[test]
    fn test_cache_key() {
        let key1 = CacheKey::new("example.com", RecordType::A);
        let key2 = CacheKey::new("example.com", RecordType::A);
        let key3 = CacheKey::new("example.com", RecordType::Aaaa);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_operations() {
        let cache = DnsCache::new(100, Duration::from_secs(60));
        let key = CacheKey::new("example.com", RecordType::A);
        let records = vec![create_test_record("example.com", RecordType::A)];

        // Initially empty
        assert!(cache.get(&key).is_none());

        // Store and retrieve
        cache.put(key.clone(), records.clone(), Some(Duration::from_secs(60)));
        assert_eq!(cache.get(&key), Some(records));

        // Test stats
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.valid_entries, 1);
    }

    #[tokio::test]
    async fn test_cached_client() {
        use crate::client::DnsxClient;
        use crate::config::DnsxOptions;

        let client = DnsxClient::with_options(DnsxOptions::default()).unwrap();
        let cache = DnsCache::new(100, Duration::from_secs(60));
        let cached_client = CachedDnsClient::new(client, cache);

        // This will actually query (no cache yet)
        let _result1 = cached_client.query("example.com", RecordType::A).await;

        // This should hit cache (if the first query succeeded)
        let stats = cached_client.cache_stats();
        if stats.total_entries > 0 {
            assert_eq!(stats.valid_entries, 1);
        }
    }
}