//! Orthrus daemon entry point

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Orthrus - Containment & Policy Enforcer initializing...");
    Ok(())
}
