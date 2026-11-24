//! RDNSx CLI - Fast and multi-purpose DNS toolkit

#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

mod cli;
mod commands;
mod output_writer;

use cli::Cli;

pub const BANNER: &str = r#"
██████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝╚██╗██╔╝
██████╔╝██║  ██║██╔██╗ ██║███████╗ ╚███╔╝
██╔══██╗██║  ██║██║╚██╗██║╚════██║ ██╔██╗
██║  ██║██████╔╝██║ ╚████║███████║██╔╝ ██╗
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

              TelcoSec RDNSx
    Fast and multi-purpose DNS toolkit
"#;

pub fn print_banner() {
    print!("{}", BANNER);
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments first to check for silent mode
    let cli = Cli::parse();

    // Print banner unless silent mode is enabled
    if !cli.silent {
        print_banner();
        println!();
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    cli.run().await
}
