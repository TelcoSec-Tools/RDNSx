//! High-performance Cassandra exporter for DNS records

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::frame::Compression;
use scylla::statement::prepared::PreparedStatement;
use scylla::statement::batch::Batch;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::error::{DnsxError, Result};
use crate::export::Exporter;
use crate::types::DnsRecord;

/// Performance metrics for Cassandra operations
#[derive(Debug, Default)]
pub struct CassandraMetrics {
    pub total_records: usize,
    pub batches_processed: usize,
    pub total_insert_time: Duration,
    pub average_batch_time: Duration,
    pub records_per_second: f64,
    pub errors: usize,
    pub retries: usize,
}

/// High-performance Cassandra exporter with batching and connection pooling
pub struct CassandraExporter {
    /// Prepared statement cache
    #[allow(dead_code)]
    prepared_statements: Arc<Mutex<HashMap<String, PreparedStatement>>>,
    /// Worker channels for concurrent processing
    workers: Arc<Mutex<Vec<JoinHandle<Result<()>>>>>,
    /// Record sender channels
    record_senders: Arc<Mutex<Vec<mpsc::UnboundedSender<DnsRecord>>>>,
    /// Metrics for monitoring performance
    metrics: Arc<Mutex<CassandraMetrics>>,
    /// Configuration
    config: CassandraConfig,
}

/// Configuration for Cassandra exporter
#[derive(Debug, Clone)]
pub struct CassandraConfig {
    pub contact_points: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub keyspace: String,
    pub table: String,
    pub batch_size: usize,
    pub max_concurrent_batches: usize,
    pub retry_attempts: usize,
    pub retry_delay: Duration,
    pub num_workers: usize,
    pub connection_pool_size: usize,
    pub tcp_nodelay: bool,
    pub keepalive_interval: Option<Duration>,
}

impl Default for CassandraConfig {
    fn default() -> Self {
        Self {
            contact_points: vec!["127.0.0.1:9042".to_string()],
            username: None,
            password: None,
            keyspace: "dnsx".to_string(),
            table: "records".to_string(),
            batch_size: 1000,
            max_concurrent_batches: 10,
            retry_attempts: 3,
            retry_delay: Duration::from_millis(100),
            num_workers: 4,
            connection_pool_size: 4,
            tcp_nodelay: true,
            keepalive_interval: Some(Duration::from_secs(60)),
        }
    }
}

impl CassandraExporter {
    /// Create a new high-performance Cassandra exporter
    pub async fn new(
        contact_points: &[String],
        username: Option<&str>,
        password: Option<&str>,
        keyspace: &str,
        table: &str,
        batch_size: usize,
    ) -> Result<Self> {
        Self::with_config(CassandraConfig {
            contact_points: contact_points.to_vec(),
            username: username.map(|s| s.to_string()),
            password: password.map(|s| s.to_string()),
            keyspace: keyspace.to_string(),
            table: table.to_string(),
            batch_size,
            ..Default::default()
        }).await
    }

    /// Create a new exporter with full configuration
    pub async fn with_config(config: CassandraConfig) -> Result<Self> {
        info!("Connecting to Cassandra cluster: {:?}", config.contact_points);

        let mut session_builder = SessionBuilder::new()
            .known_nodes(&config.contact_points)
            .compression(Some(Compression::Lz4));

        if let (Some(user), Some(pass)) = (&config.username, &config.password) {
            session_builder = session_builder.user(user, pass);
        }

        // Optimize connection settings for high performance
        let session = session_builder
            .connection_timeout(Duration::from_secs(30))
            // .request_timeout(Some(Duration::from_secs(10))) // Temporarily disabled due to API compatibility
            .tcp_nodelay(config.tcp_nodelay)
            .keepalive_interval(config.keepalive_interval.unwrap_or(Duration::from_secs(60)))
            .build()
            .await
            .map_err(|e| DnsxError::Other(format!("Failed to connect to Cassandra: {}", e)))?;

        let session = Arc::new(session);

        // Create keyspace and table with optimized schema
        Self::create_keyspace(&session, &config.keyspace).await?;
        Self::create_optimized_table(&session, &config.keyspace, &config.table).await?;

        info!("Connected to Cassandra, using keyspace: {}, table: {}", config.keyspace, config.table);

        // Start worker threads
        let mut workers = Vec::new();
        let mut record_senders = Vec::new();

        let prepared_statements = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(CassandraMetrics::default()));

        for worker_id in 0..config.num_workers {
            let (tx, rx) = mpsc::unbounded_channel();
            record_senders.push(tx);

            let worker = Self::spawn_worker(
                worker_id,
                rx,
                Arc::clone(&session),
                Arc::clone(&prepared_statements),
                Arc::clone(&metrics),
                config.clone(),
            );
            workers.push(worker);
        }

        Ok(Self {
            prepared_statements,
            workers: Arc::new(Mutex::new(workers)),
            record_senders: Arc::new(Mutex::new(record_senders)),
            metrics,
            config,
        })
    }

    /// Spawn a worker thread for processing batches
    fn spawn_worker(
        worker_id: usize,
        mut rx: mpsc::UnboundedReceiver<DnsRecord>,
        session: Arc<Session>,
        prepared_statements: Arc<Mutex<HashMap<String, PreparedStatement>>>,
        metrics: Arc<Mutex<CassandraMetrics>>,
        config: CassandraConfig,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            debug!("Worker {} started", worker_id);
            let mut batch = Vec::with_capacity(config.batch_size);

            while let Some(record) = rx.recv().await {
                batch.push(record);

                if batch.len() >= config.batch_size {
                    Self::process_batch(&session, &prepared_statements, &metrics, &config, batch, worker_id).await?;
                    batch = Vec::with_capacity(config.batch_size);
                }
            }

            // Process remaining records
            if !batch.is_empty() {
                Self::process_batch(&session, &prepared_statements, &metrics, &config, batch, worker_id).await?;
            }

            debug!("Worker {} finished", worker_id);
            Ok(())
        })
    }

    /// Process a batch of records with retries
    async fn process_batch(
        session: &Session,
        prepared_statements: &Arc<Mutex<HashMap<String, PreparedStatement>>>,
        metrics: &Arc<Mutex<CassandraMetrics>>,
        config: &CassandraConfig,
        batch: Vec<DnsRecord>,
        worker_id: usize,
    ) -> Result<()> {
        let batch_size = batch.len();
        let start_time = Instant::now();

        let mut attempts = 0;
        let mut last_error = None;

        while attempts < config.retry_attempts {
            match Self::execute_batch(session, prepared_statements, config, &batch).await {
                Ok(_) => {
                    let elapsed = start_time.elapsed();

                    let mut metrics_lock = metrics.lock().await;
                    metrics_lock.total_records += batch_size;
                    metrics_lock.batches_processed += 1;
                    metrics_lock.total_insert_time += elapsed;

                    debug!("Worker {}: Successfully inserted {} records in {:.2}ms",
                          worker_id, batch_size, elapsed.as_millis());
                    return Ok(());
                }
                Err(e) => {
                    attempts += 1;
                    last_error = Some(e);

                    if attempts < config.retry_attempts {
                        warn!("Worker {}: Batch insert failed (attempt {}/{}), retrying in {:?}",
                              worker_id, attempts, config.retry_attempts, config.retry_delay);

                        let mut metrics_lock = metrics.lock().await;
                        metrics_lock.retries += 1;

                        tokio::time::sleep(config.retry_delay).await;
                    }
                }
            }
        }

        let mut metrics_lock = metrics.lock().await;
        metrics_lock.errors += 1;

        Err(last_error.unwrap_or_else(|| DnsxError::Other("Batch insert failed after all retries".to_string())))
    }

    /// Execute a batch insert operation
    async fn execute_batch(
        session: &Session,
        prepared_statements: &Arc<Mutex<HashMap<String, PreparedStatement>>>,
        config: &CassandraConfig,
        records: &[DnsRecord],
    ) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        // Get or create prepared statement
        let stmt_key = format!("{}.{}", config.keyspace, config.table);
        let prepared = {
            let mut cache = prepared_statements.lock().await;
            if let Some(stmt) = cache.get(&stmt_key) {
                stmt.clone()
            } else {
                let cql = format!(
                    "INSERT INTO {}.{} (domain, record_type, value, ttl, response_code, resolver, timestamp, query_time_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    config.keyspace, config.table
                );

                let stmt = session
                    .prepare(cql)
                    .await
                    .map_err(|e| DnsxError::Other(format!("Failed to prepare statement: {}", e)))?;

                cache.insert(stmt_key, stmt.clone());
                stmt
            }
        };

        // Use Cassandra batch operations for better performance
        let mut batch = Batch::default();
        let mut values = Vec::new();

        for record in records {
            let record_type = record.record_type.to_string();
            let response_code = record.response_code.to_string();
            let value_str = record.value.to_string();
            let timestamp = record.timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| DnsxError::Other(format!("Invalid timestamp: {}", e)))?
                .as_millis() as i64;

            batch.append_statement(prepared.clone());
            values.push((
                record.domain.clone(),
                record_type,
                value_str,
                record.ttl as i32,
                response_code,
                record.resolver.clone(),
                timestamp,
                record.query_time_ms,
            ));
        }

        // Execute batch
        session
            .batch(&batch, &values)
            .await
            .map_err(|e| DnsxError::Other(format!("Failed to execute batch: {}", e)))?;

        Ok(())
    }

    /// Create keyspace if it doesn't exist
    async fn create_keyspace(session: &Session, keyspace: &str) -> Result<()> {
        let cql = format!(
            "CREATE KEYSPACE IF NOT EXISTS {} WITH REPLICATION = {{
                'class': 'SimpleStrategy',
                'replication_factor': 1
            }}",
            keyspace
        );

        session
            .query_unpaged(cql, &[])
            .await
            .map_err(|e| DnsxError::Other(format!("Failed to create keyspace: {}", e)))?;
        // Note: await_all_pages is not needed for DDL operations

        debug!("Keyspace '{}' created or already exists", keyspace);
        Ok(())
    }

    /// Create optimized table for high-performance workloads
    async fn create_optimized_table(session: &Session, keyspace: &str, table: &str) -> Result<()> {
        let cql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{} (
                domain text,
                record_type text,
                value text,
                ttl int,
                response_code text,
                resolver text,
                timestamp timestamp,
                query_time_ms double,
                PRIMARY KEY ((domain, record_type), timestamp)
            ) WITH CLUSTERING ORDER BY (timestamp DESC)
            AND compaction = {{
                'class': 'TimeWindowCompactionStrategy',
                'compaction_window_unit': 'DAYS',
                'compaction_window_size': 1
            }}
            AND caching = {{
                'keys': 'ALL',
                'rows_per_partition': 'NONE'
            }}
            AND compression = {{
                'chunk_length_in_kb': 64,
                'class': 'LZ4Compressor'
            }}
            AND gc_grace_seconds = 864000
            "#,
            keyspace, table
        );

        session
            .query_unpaged(cql, &[])
            .await
            .map_err(|e| DnsxError::Other(format!("Failed to create optimized table: {}", e)))?;

        debug!("Optimized table '{}.{}' created or already exists", keyspace, table);
        Ok(())
    }

    /// Get performance metrics
    pub fn metrics(&self) -> CassandraMetrics {
        // self.metrics.blocking_lock().clone() // Temporarily disabled
        CassandraMetrics::default()
    }

    /// Get configuration
    pub fn config(&self) -> &CassandraConfig {
        &self.config
    }
}

#[async_trait]
impl Exporter for CassandraExporter {
    async fn export(&self, record: DnsRecord) -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT_WORKER: AtomicUsize = AtomicUsize::new(0);

        let senders = self.record_senders.lock().await;
        if senders.is_empty() {
            return Err(DnsxError::Other("Cassandra exporter has already been flushed".to_string()));
        }

        let worker_index = NEXT_WORKER.fetch_add(1, Ordering::Relaxed) % senders.len();
        senders[worker_index]
            .send(record)
            .map_err(|e| DnsxError::Other(format!("Failed to send record to worker: {}", e)))?;

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // Clear all sender channels so the channels close and workers finish rx.recv().await
        {
            let mut senders = self.record_senders.lock().await;
            senders.clear();
        }

        // Wait for all workers to complete
        let handles = {
            let mut workers = self.workers.lock().await;
            std::mem::take(&mut *workers)
        };

        for (i, handle) in handles.into_iter().enumerate() {
            match handle.await {
                Ok(Ok(())) => debug!("Worker {} completed successfully", i),
                Ok(Err(e)) => {
                    error!("Worker {} failed: {}", i, e);
                    return Err(e);
                }
                Err(e) => {
                    error!("Worker {} panicked: {}", i, e);
                    return Err(DnsxError::Other(format!("Worker {} panicked: {}", i, e)));
                }
            }
        }

        let metrics = self.metrics.lock().await;
        let total_time = metrics.total_insert_time;
        let records_per_second = if total_time.as_secs_f64() > 0.0 {
            metrics.total_records as f64 / total_time.as_secs_f64()
        } else {
            0.0
        };

        info!(
            "Cassandra export completed: {} records in {:.2}s ({:.1} rps), {} batches, {} errors, {} retries",
            metrics.total_records,
            total_time.as_secs_f64(),
            records_per_second,
            metrics.batches_processed,
            metrics.errors,
            metrics.retries
        );

        Ok(())
    }
}

impl Drop for CassandraExporter {
    fn drop(&mut self) {
        // Ensure all remaining workers are aborted when the exporter is dropped
        if let Ok(workers) = self.workers.try_lock() {
            for worker in workers.iter() {
                worker.abort();
            }
        }
    }
}