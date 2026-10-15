//! Pack agent entry point

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Pack - Swarm Sensing Agent initializing...");
    Ok(())
}
