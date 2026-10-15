//! Garmr daemon entry point

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Garmr - Consensus & Verification Sentinel initializing...");
    Ok(())
}
