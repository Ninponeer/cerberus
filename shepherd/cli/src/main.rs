//! Cerberus Shepherd CLI - The Operator's Harness.
//!
//! Command-line interface for operating the Cerberus swarm defense system.
//! Provides status queries, verdict inspection, containment approval,
//! rollback, and operator key management.

use cerberus_shepherd_lib::{
    config::ShepherdConfig,
    error::{Result, ShepherdError},
    swarm::{OverrideAction, Swarm},
    yggdrasil::YggdrasilClient,
    GarmrClient, OrthrusClient,
};
use clap::{Parser, Subcommand};
use cerberus_core::crypto::SigningKeyWrapper;
use cerberus_orthrus::platform::MockPlatformAdapter;
use cerberus_orthrus::policy::ContainmentPolicy;
use std::sync::Arc;
use std::path::PathBuf;

/// Cerberus Shepherd - Operator Control CLI for the Cerberus swarm defense system.
#[derive(Parser, Debug)]
#[command(author, version, about = "Cerberus Shepherd - Operator's Harness", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to Shepherd configuration file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Path to Yggdrasil store directory
    #[arg(long, global = true)]
    yggdrasil: Option<PathBuf>,

    /// Enable debug logging
    #[arg(short, long, global = true)]
    debug: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show swarm status overview
    Status,

    /// List verdicts from Yggdrasil knowledge graph
    Verdicts {
        /// Maximum number of verdicts to show
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Show only confirmed verdicts
        #[arg(long)]
        confirmed: bool,
    },

    /// Show details of a specific verdict
    Verdict {
        /// Verdict ID
        verdict_id: String,
    },

    /// Show observations for an entity (agent, host, user)
    Observations {
        /// Entity identifier (agent ID, hostname, or user)
        entity: String,

        /// Maximum number of observations
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Show device information
    Device {
        /// Device ID
        device_id: String,
    },

    /// Show trust scores for swarm nodes
    Nodes,

    /// Approve a pending containment (generate + execute approval token)
    Approve {
        /// Directive ID to approve
        directive_id: String,

        /// Verdict confidence (0.0-1.0)
        #[arg(long, default_value = "0.9")]
        confidence: f32,
    },

    /// Roll back a containment by directive ID
    Rollback {
        /// Directive ID to roll back
        directive_id: String,
    },

    /// List active containments
    Containments,

    /// Override a Garmr verdict (allow/deny/modify)
    Override {
        /// Verdict ID
        verdict_id: String,

        /// Override action: allow, deny, or modify
        #[arg(long)]
        action: String,
    },

    /// Build a network isolation directive (dry-run preview)
    Isolate {
        /// Target IP address
        target_ip: String,

        /// Rationale for isolation
        #[arg(long, default_value = "Operator-directed containment")]
        rationale: String,

        /// Urgency (0.0-1.0)
        #[arg(long, default_value = "0.9")]
        urgency: f32,
    },

    /// Build a credential suspension directive (dry-run preview)
    Suspend {
        /// Target user ID
        user_id: String,

        /// Rationale for suspension
        #[arg(long, default_value = "Operator-directed credential suspend")]
        rationale: String,

        /// Urgency (0.0-1.0)
        #[arg(long, default_value = "0.9")]
        urgency: f32,
    },

    /// Generate and display operator signing key
    KeysGenerate {
        /// Output path for key file
        #[arg(long)]
        output: Option<PathBuf>,

        /// Operator name
        #[arg(long, default_value = "operator")]
        name: String,
    },

    /// Show Shepherd configuration
    Config,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.debug {
        unsafe {
            std::env::set_var("RUST_LOG", "debug");
        }
        tracing_subscriber::fmt::init();
    }

    // Load configuration
    let config_path = cli
        .config
        .unwrap_or_else(ShepherdConfig::default_config_path);
    let mut config = ShepherdConfig::load(&config_path)?;

    // Override Yggdrasil path if specified
    if let Some(ref yggdrasil_path) = cli.yggdrasil {
        config.yggdrasil_store_path = yggdrasil_path.clone();
    }

    println!("{}", config);

    // Initialize sub-clients
    let yggdrasil = YggdrasilClient::open(&config.yggdrasil_store_path)?;
    let garmr = GarmrClient::new()?;
    let signing_key = SigningKeyWrapper::generate();
    let platform = Arc::new(MockPlatformAdapter::new());
    let orthrus = OrthrusClient::new(
        "shepherd-cli".to_string(),
        signing_key,
        platform,
        ContainmentPolicy::default(),
        config.spiffe_id().to_string(),
    )?;

    let mut swarm = Swarm::new(yggdrasil, garmr, orthrus);

    match cli.command {
        Commands::Status => cmd_status(&swarm).await?,
        Commands::Verdicts { limit, confirmed } => {
            cmd_verdicts(&swarm, limit, confirmed).await?
        }
        Commands::Verdict { verdict_id } => cmd_verdict(&swarm, &verdict_id).await?,
        Commands::Observations { entity, limit } => {
            cmd_observations(&swarm, &entity, limit).await?
        }
        Commands::Device { device_id } => cmd_device(&swarm, &device_id).await?,
        Commands::Nodes => cmd_nodes(&swarm).await?,
        Commands::Approve {
            directive_id,
            confidence,
        } => cmd_approve(&mut swarm, &directive_id, confidence).await?,
        Commands::Rollback { directive_id } => {
            cmd_rollback(&mut swarm, &directive_id).await?
        }
        Commands::Containments => cmd_containments(&swarm).await?,
        Commands::Override {
            verdict_id,
            action,
        } => cmd_override(&swarm, &verdict_id, &action).await?,
        Commands::Isolate {
            target_ip,
            rationale,
            urgency,
        } => cmd_isolate(&target_ip, &rationale, urgency),
        Commands::Suspend {
            user_id,
            rationale,
            urgency,
        } => cmd_suspend(&user_id, &rationale, urgency),
        Commands::KeysGenerate { output, name } => cmd_keys_generate(output, &name)?,
        Commands::Config => cmd_config(&config),
    }

    Ok(())
}

async fn cmd_status(swarm: &Swarm) -> Result<()> {
    let status = swarm.status()?;
    println!("=== Cerberus Swarm Status ===");
    println!("Total nodes: {}", status.total_nodes);
    println!("Active containments: {}", status.active_containments);
    println!("Average trust score: {:.2}", status.average_trust_score);
    println!("Active verdicts: {}", status.active_verdicts);
    println!("Confirmed verdicts: {}", status.confirmed_verdicts);
    println!("Suspicious verdicts: {}", status.suspicious_verdicts);

    if !status.nodes.is_empty() {
        println!("\n--- Node Trust Scores ---");
        for node in &status.nodes {
            println!(
                "  {:<20} score={:.2} obs={} accurate={}",
                node.agent_id, node.score, node.observation_count, node.accurate_verdict_count
            );
        }
    }
    Ok(())
}

async fn cmd_verdicts(swarm: &Swarm, limit: usize, confirmed: bool) -> Result<()> {
    let verdicts = swarm.yggdrasil().list_verdicts(limit)?;
    println!("=== Verdicts (limit: {}) ===", limit);
    for v in &verdicts {
        if confirmed && v.classification != "Confirmed" {
            continue;
        }
        println!(
            "  [{}] {} conf={:.2} class={} threat={} nodes={}",
            v.verdict_id,
            v.timestamp_ns,
            v.confidence,
            v.classification,
            v.threat_class,
            v.participating_nodes.len()
        );
        println!("      rationale: {}", v.rationale);
        println!(
            "      actions: {}",
            v.recommended_actions.join(", ")
        );
    }
    Ok(())
}

async fn cmd_verdict(swarm: &Swarm, verdict_id: &str) -> Result<()> {
    match swarm.get_verdict(verdict_id)? {
        Some(v) => {
            println!("=== Verdict {} ===", v.verdict_id);
            println!("  Correlation: {}", v.correlation_id);
            println!("  Confidence: {:.2}", v.confidence);
            println!("  Classification: {}", v.classification);
            println!("  Threat class: {}", v.threat_class);
            println!("  Rationale: {}", v.rationale);
            println!("  Garmr instance: {}", v.garmr_instance);
            println!("  Participating nodes: {:?}", v.participating_nodes);
            println!("  Evidence trail: {:?}", v.evidence_trail);
            println!("  Recommended actions: {:?}", v.recommended_actions);
        }
        None => {
            println!("Verdict {} not found", verdict_id);
        }
    }
    Ok(())
}

async fn cmd_observations(swarm: &Swarm, entity: &str, limit: usize) -> Result<()> {
    let obs = swarm
        .yggdrasil()
        .get_observations_for_entity(entity, limit)?;
    println!(
        "=== Observations for entity '{}' (limit: {}) ===",
        entity, limit
    );
    for o in &obs {
        println!(
            "  [{}] agent={} ts={} type={:?} conf={:.2}",
            o.observation_id, o.agent_id, o.timestamp_ns, o.obs_type, o.confidence
        );
    }
    Ok(())
}

async fn cmd_device(swarm: &Swarm, device_id: &str) -> Result<()> {
    match swarm.get_device(device_id)? {
        Some(d) => {
            println!("=== Device {} ===", d.id);
            println!("  Hostname: {}", d.hostname);
            println!("  IPs: {:?}", d.ips);
            println!("  OS: {}", d.os);
            println!("  Role: {}", d.role);
            println!("  Tier: {}", d.tier);
            println!("  Trust score: {:.2}", d.trust_score);
            println!("  Status: {}", d.status);
        }
        None => {
            println!("Device {} not found", device_id);
        }
    }
    Ok(())
}

async fn cmd_nodes(swarm: &Swarm) -> Result<()> {
    let scores = swarm.yggdrasil().get_all_trust_scores()?;
    println!("=== Swarm Node Trust Scores ===");
    for s in &scores {
        println!(
            "  {:<25} score={:.2} obs={} accurate={}",
            s.agent_id, s.score, s.observation_count, s.accurate_verdict_count
        );
    }
    Ok(())
}

async fn cmd_approve(
    swarm: &mut Swarm,
    directive_id: &str,
    confidence: f32,
) -> Result<()> {
    // Build a mock directive for the given ID
    let directive = cerberus_shepherd_lib::orthrus::OrthrusClient::build_network_isolate_directive(
        directive_id.to_string(),
        "10.0.0.99".to_string(),
        "Operator approval via CLI".to_string(),
        0.9,
    );

    let token = swarm.approve_containment(&directive, confidence).await?;
    println!("=== Approval Token Generated ===");
    println!("  Token ID: {}", token.token_id);
    println!("  Directive: {}", token.directive_id);
    println!("  Operator: {}", token.operator_id);
    println!("  Granted at: {}", token.granted_at_ns);
    println!("  Expires at: {}", token.expires_at_ns);
    Ok(())
}

async fn cmd_rollback(swarm: &mut Swarm, directive_id: &str) -> Result<()> {
    swarm.rollback_containment(directive_id).await?;
    println!("Rollback initiated for directive {}", directive_id);
    Ok(())
}

async fn cmd_containments(swarm: &Swarm) -> Result<()> {
    let containments = swarm.list_active_containments();
    println!("=== Active Containments ===");
    if containments.is_empty() {
        println!("  None");
    } else {
        for c in &containments {
            println!(
                "  [{}] directive={} action={:?} created={}",
                c.record_id, c.directive_id, c.action_type, c.created_at_ns
            );
        }
    }
    Ok(())
}

async fn cmd_override(
    swarm: &Swarm,
    verdict_id: &str,
    action_str: &str,
) -> Result<()> {
    let action = match action_str.to_lowercase().as_str() {
        "allow" => OverrideAction::Allow,
        "deny" => OverrideAction::Deny,
        "modify" => OverrideAction::Modify,
        _ => return Err(ShepherdError::Validation(format!("Invalid override action: {action_str}"))),
    };

    let rationale = match action {
        OverrideAction::Allow => "Operator allowed verdict".to_string(),
        OverrideAction::Deny => "Operator denied verdict".to_string(),
        OverrideAction::Modify => "Operator modified verdict".to_string(),
    };

    let result = swarm.override_verdict(verdict_id, action, rationale)?;
    println!("=== Override Result ===");
    println!("  Verdict: {}", result.verdict_id);
    println!("  Classification: {}", result.classification);
    println!("  Rationale: {}", result.rationale);
    Ok(())
}

fn cmd_isolate(target_ip: &str, rationale: &str, urgency: f32) {
    let directive = cerberus_shepherd_lib::orthrus::OrthrusClient::build_network_isolate_directive(
        format!("dir-{}", uuid::Uuid::now_v7()),
        target_ip.to_string(),
        rationale.to_string(),
        urgency,
    );
    println!("=== Network Isolation Directive (dry-run) ===");
    println!("  Directive ID: {}", directive.directive_id);
    println!("  Target IP: {}", target_ip);
    println!("  Rationale: {}", rationale);
    println!("  Urgency: {:.2}", urgency);
    println!("  Requires confirmation: {}", directive.requires_confirmation);
}

fn cmd_suspend(user_id: &str, rationale: &str, urgency: f32) {
    let directive = cerberus_shepherd_lib::orthrus::OrthrusClient::build_credential_suspend_directive(
        format!("dir-{}", uuid::Uuid::now_v7()),
        user_id.to_string(),
        rationale.to_string(),
        urgency,
    );
    println!("=== Credential Suspend Directive (dry-run) ===");
    println!("  Directive ID: {}", directive.directive_id);
    println!("  Target user: {}", user_id);
    println!("  Rationale: {}", rationale);
    println!("  Urgency: {:.2}", urgency);
    println!("  Requires confirmation: {}", directive.requires_confirmation);
}

fn cmd_keys_generate(output: Option<PathBuf>, name: &str) -> Result<()> {
    let keystore = cerberus_shepherd_lib::operator::KeyStore::default();
    keystore.ensure_dir()?;

    let spiffe_id = format!("spiffe://cerberus.local/shepherd/cli/{}", name);
    let identity = cerberus_shepherd_lib::operator::OperatorIdentity::generate(
        name.to_string(),
        spiffe_id,
    );

    let key_path = output.unwrap_or_else(|| keystore.active_key_path());
    identity.save_key_to_file(&key_path)?;

    // Save identity metadata
    let identity_path = keystore.identity_path();
    let identity_json = serde_json::to_string_pretty(&identity)
        .map_err(|e| cerberus_shepherd_lib::error::ShepherdError::Serialization(e))?;
    std::fs::write(&identity_path, identity_json)
        .map_err(|e| cerberus_shepherd_lib::error::ShepherdError::Yggdrasil(format!("Failed to write identity: {e}")))?;

    println!("=== Operator Key Generated ===");
    println!("  SPIFFE ID: {}", identity.spiffe_id);
    println!("  Key path: {}", key_path.display());
    println!("  Identity path: {}", identity_path.display());
    println!("  Cert fingerprint: {}", identity.cert_fingerprint);
    Ok(())
}

fn cmd_config(config: &ShepherdConfig) {
    println!("=== Shepherd Configuration ===");
    println!("{}", config);
}
