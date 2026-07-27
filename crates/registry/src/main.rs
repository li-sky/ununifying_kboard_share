//! Standalone registry HTTP server. Designed to sit behind nginx for TLS.

use anyhow::Result;
use clap::Parser;
use kbshare_net::registry::{serve_http, RegistryStore};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    bind: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let store = RegistryStore::new();
    serve_http(store, &args.bind)
}
