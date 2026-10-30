//! Fenrir daemon entry point
//!
//! Requires the "cli" feature.

#![cfg(feature = "cli")]

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Fenrir - Threat Discovery & Adaptive Inference Engine initializing...");
    Ok(())
}
