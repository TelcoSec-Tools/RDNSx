//! Database export modules

#[cfg(feature = "cassandra")]
pub mod cassandra;
#[cfg(feature = "elasticsearch")]
pub mod elasticsearch;
#[cfg(feature = "mongodb")]
pub mod mongodb;

#[cfg(feature = "cassandra")]
pub use cassandra::CassandraExporter;
#[cfg(feature = "elasticsearch")]
pub use elasticsearch::ElasticsearchExporter;
#[cfg(feature = "mongodb")]
pub use mongodb::MongodbExporter;

use crate::error::Result;
use crate::types::DnsRecord;
use async_trait::async_trait;

/// Common export trait
#[async_trait]
pub trait Exporter: Send + Sync {
    /// Export a DNS record
    async fn export(&self, record: DnsRecord) -> Result<()>;

    /// Flush any pending writes
    async fn flush(&self) -> Result<()>;

    /// Optional one-line performance summary (records written, errors...)
    fn metrics_summary(&self) -> Option<String> {
        None
    }
}
