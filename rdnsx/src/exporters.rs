//! Database exporters shared by the commands that produce DNS records

use anyhow::Result;
use rdnsx_core::{DnsRecord, Exporter};

use crate::cli::Config;

/// Cassandra tuning that only the CLI knows about
#[cfg_attr(not(feature = "export-cassandra"), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub struct CassandraTuning {
    pub batch_size: usize,
    pub workers: usize,
}

impl Default for CassandraTuning {
    fn default() -> Self {
        Self {
            batch_size: 1000,
            workers: 4,
        }
    }
}

/// The exporters enabled in the configuration
pub struct ExportSink {
    exporters: Vec<(&'static str, Box<dyn Exporter>)>,
    silent: bool,
}

impl ExportSink {
    /// Build the exporters enabled in the config. Fails if an exporter is enabled but
    /// this binary was built without it.
    pub async fn from_config(config: &Config, cassandra_tuning: CassandraTuning) -> Result<Self> {
        let export = &config.core_config.export;
        #[allow(unused_mut)]
        let mut exporters: Vec<(&'static str, Box<dyn Exporter>)> = Vec::new();
        let _ = cassandra_tuning;

        if export.elasticsearch.enabled {
            #[cfg(feature = "export-elasticsearch")]
            exporters.push((
                "Elasticsearch",
                Box::new(
                    rdnsx_core::ElasticsearchExporter::new(
                        &export.elasticsearch.url,
                        &export.elasticsearch.index,
                        export.batch_size,
                    )
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to create Elasticsearch exporter: {}", e)
                    })?,
                ),
            ));
            #[cfg(not(feature = "export-elasticsearch"))]
            anyhow::bail!("Elasticsearch export is enabled but rdnsx was built without the export-elasticsearch feature");
        }

        if export.mongodb.enabled {
            #[cfg(feature = "export-mongodb")]
            exporters.push((
                "MongoDB",
                Box::new(
                    rdnsx_core::MongodbExporter::new(
                        &export.mongodb.url,
                        &export.mongodb.database,
                        &export.mongodb.collection,
                        export.batch_size,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to create MongoDB exporter: {}", e))?,
                ),
            ));
            #[cfg(not(feature = "export-mongodb"))]
            anyhow::bail!(
                "MongoDB export is enabled but rdnsx was built without the export-mongodb feature"
            );
        }

        if export.cassandra.enabled {
            #[cfg(feature = "export-cassandra")]
            {
                let cassandra = &export.cassandra;
                let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());
                let cassandra_config = rdnsx_core::CassandraConfig {
                    contact_points: cassandra.contact_points.clone(),
                    username: non_empty(&cassandra.username),
                    password: non_empty(&cassandra.password),
                    keyspace: cassandra.keyspace.clone(),
                    table: cassandra.table.clone(),
                    batch_size: cassandra_tuning.batch_size,
                    num_workers: cassandra_tuning.workers,
                    ..Default::default()
                };
                exporters.push((
                    "Cassandra",
                    Box::new(
                        rdnsx_core::CassandraExporter::with_config(cassandra_config)
                            .await
                            .map_err(|e| {
                                anyhow::anyhow!("Failed to create Cassandra exporter: {}", e)
                            })?,
                    ),
                ));
            }
            #[cfg(not(feature = "export-cassandra"))]
            anyhow::bail!(
                "Cassandra export is enabled but rdnsx was built without the export-cassandra feature"
            );
        }

        Ok(Self {
            exporters,
            silent: config.silent,
        })
    }

    /// Send one record to every exporter (failures are reported, not fatal)
    pub async fn export(&self, record: &DnsRecord) {
        for (name, exporter) in &self.exporters {
            if let Err(e) = exporter.export(record.clone()).await {
                eprintln!("Warning: Failed to export to {}: {}", name, e);
            }
        }
    }

    /// Flush every exporter and print their summaries
    pub async fn finish(&self) -> Result<()> {
        for (name, exporter) in &self.exporters {
            exporter
                .flush()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to flush {}: {}", name, e))?;
            if !self.silent {
                if let Some(metrics) = exporter.metrics_summary() {
                    eprintln!("{}: {}", name, metrics);
                }
            }
        }
        Ok(())
    }
}
