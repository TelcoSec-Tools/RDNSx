//! Configuration types and file handling

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::error::{DnsxError, Result};

/// Default resolvers (Google, Cloudflare, Quad9)
pub const DEFAULT_RESOLVERS: &[&str] = &["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"];

/// Default query timeout
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default number of retries
pub const DEFAULT_RETRIES: u32 = 3;

/// Default concurrency level
pub const DEFAULT_CONCURRENCY: usize = 100;

/// Default rate limit (queries per second, 0 = unlimited)
pub const DEFAULT_RATE_LIMIT: u64 = 0;

/// Default export batch size
pub const DEFAULT_EXPORT_BATCH_SIZE: usize = 1000;

/// DNSx client options (for internal use)
#[derive(Debug, Clone)]
pub struct DnsxOptions {
    /// DNS resolvers to use
    pub resolvers: Vec<String>,
    /// Query timeout
    pub timeout: std::time::Duration,
    /// Number of retries for failed queries
    pub retries: u32,
    /// Maximum concurrent queries
    pub concurrency: usize,
    /// Rate limit (queries per second, 0 = unlimited)
    pub rate_limit: u64,
}

impl Default for DnsxOptions {
    fn default() -> Self {
        Self {
            resolvers: DEFAULT_RESOLVERS.iter().map(|s| s.to_string()).collect(),
            timeout: DEFAULT_TIMEOUT,
            retries: DEFAULT_RETRIES,
            concurrency: DEFAULT_CONCURRENCY,
            rate_limit: DEFAULT_RATE_LIMIT,
        }
    }
}

/// Main configuration structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// DNS resolver configuration
    #[serde(default)]
    pub resolvers: ResolverConfig,

    /// Performance settings
    #[serde(default)]
    pub performance: PerformanceConfig,

    /// Export configuration
    #[serde(default)]
    pub export: ExportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    /// DNS server addresses
    #[serde(default = "default_resolvers")]
    pub servers: Vec<String>,

    /// Query timeout in seconds
    #[serde(default = "default_timeout_secs")]
    pub timeout: u64,

    /// Number of retries for failed queries
    #[serde(default = "default_retries")]
    pub retries: u32,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            servers: default_resolvers(),
            timeout: default_timeout_secs(),
            retries: default_retries(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum concurrent queries
    #[serde(default = "default_concurrency")]
    pub threads: usize,

    /// Rate limit (queries per second, 0 = unlimited)
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            threads: default_concurrency(),
            rate_limit: default_rate_limit(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Batch size for database exports
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Elasticsearch export settings
    #[serde(default)]
    pub elasticsearch: ElasticsearchConfig,

    /// MongoDB export settings
    #[serde(default)]
    pub mongodb: MongodbConfig,

    /// Cassandra export settings
    #[serde(default)]
    pub cassandra: CassandraConfig,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            batch_size: default_batch_size(),
            elasticsearch: ElasticsearchConfig::default(),
            mongodb: MongodbConfig::default(),
            cassandra: CassandraConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticsearchConfig {
    /// Enable Elasticsearch export
    #[serde(default)]
    pub enabled: bool,

    /// Elasticsearch server URL
    #[serde(default = "default_es_url")]
    pub url: String,

    /// Index name
    #[serde(default = "default_es_index")]
    pub index: String,
}

impl Default for ElasticsearchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_es_url(),
            index: default_es_index(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongodbConfig {
    /// Enable MongoDB export
    #[serde(default)]
    pub enabled: bool,

    /// MongoDB connection URL
    #[serde(default = "default_mongo_url")]
    pub url: String,

    /// Database name
    #[serde(default = "default_mongo_db")]
    pub database: String,

    /// Collection name
    #[serde(default = "default_mongo_collection")]
    pub collection: String,
}

impl Default for MongodbConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_mongo_url(),
            database: default_mongo_db(),
            collection: default_mongo_collection(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CassandraConfig {
    /// Enable Cassandra export
    #[serde(default)]
    pub enabled: bool,

    /// Contact points (host:port)
    #[serde(default = "default_cassandra_points")]
    pub contact_points: Vec<String>,

    /// Username
    #[serde(default)]
    pub username: String,

    /// Password
    #[serde(default)]
    pub password: String,

    /// Keyspace name
    #[serde(default = "default_cassandra_keyspace")]
    pub keyspace: String,

    /// Table name
    #[serde(default = "default_cassandra_table")]
    pub table: String,
}

impl Default for CassandraConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            contact_points: default_cassandra_points(),
            username: String::new(),
            password: String::new(),
            keyspace: default_cassandra_keyspace(),
            table: default_cassandra_table(),
        }
    }
}

// Default value functions
fn default_resolvers() -> Vec<String> {
    DEFAULT_RESOLVERS.iter().map(|s| s.to_string()).collect()
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT.as_secs()
}

fn default_retries() -> u32 {
    DEFAULT_RETRIES
}

fn default_concurrency() -> usize {
    DEFAULT_CONCURRENCY
}

fn default_rate_limit() -> u64 {
    DEFAULT_RATE_LIMIT
}

fn default_batch_size() -> usize {
    DEFAULT_EXPORT_BATCH_SIZE
}

fn default_es_url() -> String {
    "http://localhost:9200".to_string()
}

fn default_es_index() -> String {
    "dnsx-records".to_string()
}

fn default_mongo_url() -> String {
    "mongodb://localhost:27017".to_string()
}

fn default_mongo_db() -> String {
    "dnsx".to_string()
}

fn default_mongo_collection() -> String {
    "records".to_string()
}

fn default_cassandra_points() -> Vec<String> {
    vec!["127.0.0.1:9042".to_string()]
}

fn default_cassandra_keyspace() -> String {
    "dnsx".to_string()
}

fn default_cassandra_table() -> String {
    "records".to_string()
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path).map_err(|e| {
            DnsxError::Other(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;

        let config: Config = toml::from_str(&contents).map_err(|e| {
            DnsxError::Other(format!(
                "Failed to parse config file {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(config)
    }

    /// Load configuration with fallback to defaults
    pub fn load_with_fallback(config_path: Option<&Path>) -> Result<Self> {
        // An explicitly requested config file must load: silently falling back to
        // defaults would run with different resolvers and limits than intended.
        let env_path = std::env::var("RDNSX_CONFIG").ok().filter(|p| !p.is_empty());
        let path = config_path
            .map(Path::to_path_buf)
            .or_else(|| env_path.map(Into::into));
        let mut config = match path {
            Some(path) => Self::from_file(&path)?,
            None => Self::default(),
        };
        config.apply_env_overrides();
        Ok(config)
    }

    /// Apply settings from `RDNSX_*` environment variables (see the configuration
    /// guide). Environment values override the file; CLI flags override both.
    /// Credentials can be supplied this way instead of being stored in TOML.
    pub fn apply_env_overrides(&mut self) {
        self.apply_overrides_from(|name| std::env::var(name).ok());
    }

    fn apply_overrides_from(&mut self, get: impl Fn(&str) -> Option<String>) {
        let var = |name: &str| {
            get(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let list = |v: String| -> Vec<String> {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        if let Some(v) = var("RDNSX_RESOLVERS") {
            self.resolvers.servers = list(v);
        }
        if let Some(v) = var("RDNSX_TIMEOUT").and_then(|v| v.parse().ok()) {
            self.resolvers.timeout = v;
        }
        if let Some(v) = var("RDNSX_RETRIES").and_then(|v| v.parse().ok()) {
            self.resolvers.retries = v;
        }
        if let Some(v) = var("RDNSX_THREADS").and_then(|v| v.parse().ok()) {
            self.performance.threads = v;
        }
        if let Some(v) = var("RDNSX_RATE_LIMIT").and_then(|v| v.parse().ok()) {
            self.performance.rate_limit = v;
        }
        if let Some(v) = var("RDNSX_ES_URL") {
            self.export.elasticsearch.url = v;
        }
        if let Some(v) = var("RDNSX_ES_INDEX") {
            self.export.elasticsearch.index = v;
        }
        if let Some(v) = var("RDNSX_MONGODB_URL") {
            self.export.mongodb.url = v;
        }
        if let Some(v) = var("RDNSX_CASSANDRA_CONTACT_POINTS") {
            self.export.cassandra.contact_points = list(v);
        }
        if let Some(v) = var("RDNSX_CASSANDRA_USERNAME") {
            self.export.cassandra.username = v;
        }
        if let Some(v) = var("RDNSX_CASSANDRA_PASSWORD") {
            self.export.cassandra.password = v;
        }
    }

    /// Create example configuration file
    pub fn create_example_config(path: &Path) -> Result<()> {
        let example = r#"# RDNSx Configuration File
# Place this file in your working directory or specify with --config

[resolvers]
# DNS servers to use for queries
servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
# Query timeout in seconds
timeout = 5
# Number of retries for failed queries
retries = 3

[performance]
# Maximum concurrent queries
threads = 100
# Rate limit (queries per second, 0 = unlimited)
rate_limit = 0

[export]
# Batch size for database exports
batch_size = 1000

[export.elasticsearch]
# Enable Elasticsearch export
enabled = false
# Elasticsearch server URL
url = "http://localhost:9200"
# Index name for DNS records
index = "dnsx-records"

[export.mongodb]
# Enable MongoDB export
enabled = false
# MongoDB connection URL
url = "mongodb://localhost:27017"
# Database name
database = "dnsx"
# Collection name
collection = "records"

[export.cassandra]
# Credentials can also come from RDNSX_CASSANDRA_USERNAME / RDNSX_CASSANDRA_PASSWORD
# Enable Cassandra export
enabled = false
# Cassandra contact points (host:port)
contact_points = ["127.0.0.1:9042"]
# Authentication (leave empty for no auth)
username = ""
password = ""
# Keyspace name
keyspace = "dnsx"
# Table name
table = "records"
"#;

        fs::write(path, example)
            .map_err(|e| DnsxError::Other(format!("Failed to write example config file: {}", e)))?;

        println!("Created example configuration file: {}", path.display());
        println!("Edit this file to customize RDNSx settings");
        Ok(())
    }
}

#[cfg(test)]
mod env_override_tests {
    use super::*;

    #[test]
    fn env_values_override_file_values() {
        let mut config = Config::default();
        let env = |name: &str| match name {
            "RDNSX_RESOLVERS" => Some("9.9.9.9, 1.1.1.1".to_string()),
            "RDNSX_TIMEOUT" => Some("9".to_string()),
            "RDNSX_RATE_LIMIT" => Some("250".to_string()),
            "RDNSX_CASSANDRA_PASSWORD" => Some("s3cret".to_string()),
            "RDNSX_THREADS" => Some("not-a-number".to_string()),
            _ => None,
        };
        let threads_before = config.performance.threads;
        config.apply_overrides_from(env);

        assert_eq!(config.resolvers.servers, vec!["9.9.9.9", "1.1.1.1"]);
        assert_eq!(config.resolvers.timeout, 9);
        assert_eq!(config.performance.rate_limit, 250);
        assert_eq!(config.export.cassandra.password, "s3cret");
        assert_eq!(
            config.performance.threads, threads_before,
            "invalid values are ignored"
        );
    }
}
