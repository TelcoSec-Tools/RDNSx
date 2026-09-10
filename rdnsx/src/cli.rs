//! CLI argument parsing

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::commands::{bruteforce, enumerate, ptr, query};
use rdnsx_core::config::Config as CoreConfig;

#[derive(Parser)]
#[command(name = "rdnsx")]
#[command(about = "Fast and multi-purpose DNS toolkit by TelcoSec", long_about = None)]
#[command(before_help = crate::BANNER)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Output file
    #[arg(short, long, global = true)]
    pub output: Option<String>,

    /// JSON output format
    #[arg(long, global = true)]
    pub json: bool,

    /// Silent mode (minimal output)
    #[arg(long, global = true)]
    pub silent: bool,

    /// Create example configuration file and exit
    #[arg(long, help = "Create an example configuration file at the specified path")]
    pub create_config: Option<PathBuf>,
}

/// Runtime configuration combining CLI args with config file
#[derive(Debug, Clone)]
pub struct Config {
    pub core_config: CoreConfig,
    pub output_file: Option<String>,
    pub json_output: bool,
    pub silent: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Query domains from list/stdin
    Query(query::QueryArgs),
    /// Enumerate subdomains (bruteforce)
    Bruteforce(bruteforce::BruteforceArgs),
    /// Reverse DNS lookups (IP ranges)
    Ptr(ptr::PtrArgs),
    /// Advanced DNS enumeration techniques (including ASN enumeration)
    Enumerate(enumerate::EnumerateArgs),
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        // Handle config file creation (before loading config)
        if let Some(config_path) = &self.create_config {
            CoreConfig::create_example_config(config_path)?;
            return Ok(());
        }

        // Require a command when not creating config, or print help and fail
        let command = match self.command {
            Some(cmd) => cmd,
            None => {
                use clap::CommandFactory;
                let _ = Cli::command().print_help();
                println!();
                return Err(anyhow::anyhow!("A subcommand is required (use --help for more information)"));
            }
        };

        // Load configuration
        let core_config = CoreConfig::load_with_fallback(self.config.as_deref())?;

        // Override config with CLI arguments
        let config = Config {
            core_config,
            output_file: self.output,
            json_output: self.json,
            silent: self.silent,
        };

        match command {
            Commands::Query(args) => query::run(args, config).await,
            Commands::Bruteforce(args) => bruteforce::run(args, config).await,
            Commands::Ptr(args) => ptr::run(args, config).await,
            Commands::Enumerate(args) => enumerate::run(args, config).await,
        }
    }
}
