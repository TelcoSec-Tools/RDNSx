//! MongoDB exporter

use std::sync::Arc;

use async_trait::async_trait;
use mongodb::{
    bson::{doc, Document},
    Client, Collection, Database, IndexModel,
};
use tokio::sync::Mutex;
use tracing::debug;

use crate::error::{DnsxError, Result};
use crate::export::Exporter;
use crate::types::DnsRecord;

/// MongoDB exporter
pub struct MongodbExporter {
    collection: Arc<Collection<Document>>,
    batch_size: usize,
    buffer: Arc<Mutex<Vec<Document>>>,
}

impl MongodbExporter {
    /// Create a new MongoDB exporter
    pub async fn new(
        url: &str,
        database: &str,
        collection: &str,
        batch_size: usize,
    ) -> Result<Self> {
        let client = Client::with_uri_str(url)
            .await
            .map_err(|e| DnsxError::Export(format!("Failed to connect to MongoDB: {}", e)))?;

        let db: Database = client.database(database);
        let coll: Collection<Document> = db.collection(collection);

        // Create indexes
        ensure_indexes(&coll).await?;

        Ok(Self {
            collection: Arc::new(coll),
            batch_size,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Flush buffer to MongoDB
    async fn flush_buffer(&self) -> Result<()> {
        let mut buffer = self.buffer.lock().await;
        if buffer.is_empty() {
            return Ok(());
        }

        let documents = buffer.clone();
        let doc_count = documents.len();

        self.collection
            .insert_many(documents)
            .await
            .map_err(|e| DnsxError::Export(format!("MongoDB insert error: {}", e)))?;

        buffer.clear();
        debug!("Flushed {} documents to MongoDB", doc_count);
        Ok(())
    }
}

/// Ensure indexes exist on collection
async fn ensure_indexes(collection: &Collection<Document>) -> Result<()> {
    let indexes = vec![
        IndexModel::builder().keys(doc! { "domain": 1 }).build(),
        IndexModel::builder()
            .keys(doc! { "record_type": 1 })
            .build(),
        IndexModel::builder().keys(doc! { "timestamp": -1 }).build(),
        IndexModel::builder()
            .keys(doc! { "domain": 1, "record_type": 1 })
            .build(),
    ];

    collection
        .create_indexes(indexes)
        .await
        .map_err(|e| DnsxError::Export(format!("Failed to create indexes: {}", e)))?;

    Ok(())
}

#[async_trait]
impl Exporter for MongodbExporter {
    async fn export(&self, record: DnsRecord) -> Result<()> {
        let timestamp = record
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let doc = doc! {
            "timestamp": timestamp,
            "domain": record.domain,
            "record_type": format!("{}", record.record_type),
            "value": record.value.to_string(),
            "resolver": record.resolver,
            "ttl": record.ttl as i32,
            "response_code": format!("{}", record.response_code),
            "query_time_ms": record.query_time_ms,
        };

        let mut buffer = self.buffer.lock().await;
        buffer.push(doc);

        // Flush if buffer is full
        if buffer.len() >= self.batch_size {
            drop(buffer);
            self.flush_buffer().await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        self.flush_buffer().await
    }
}
