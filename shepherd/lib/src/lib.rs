//! Cerberus Shepherd - Operator Control Library.
//!
//! Provides the core library for the Cerberus Shepherd operator CLI,
//! including operator key management, approval token signing, Yggdrasil
//! knowledge graph queries, Garmr verdict evaluation, and Orthrus
//! containment orchestration.
//!
//! # Architecture
//!
//! Shepherd is the management plane operator's harness. It:
//! - Reads verdicts, observations, and entities from Yggdrasil's RocksDB store
//! - Generates cryptographically signed ApprovalTokens for Orthrus
//! - Provides human override authority over Garmr verdicts
//! - Manages operator Ed25519 signing keys
//!
//! # Example
//!
//! ```no_run
//! use cerberus_shepherd_lib::config::ShepherdConfig;
//! use cerberus_shepherd_lib::yggdrasil::YggdrasilClient;
//! use cerberus_shepherd_lib::swarm::Swarm;
//! use cerberus_shepherd_lib::GarmrClient;
//! use cerberus_shepherd_lib::OrthrusClient;
//! use cerberus_core::crypto::SigningKeyWrapper;
//! use std::sync::Arc;
//! use cerberus_orthrus::platform::MockPlatformAdapter;
//! use cerberus_orthrus::policy::ContainmentPolicy;
//!
//! # async {
//! let config = ShepherdConfig::default();
//! let yggdrasil = YggdrasilClient::open(&config.yggdrasil_store_path)
//!     .expect("Yggdrasil store should exist");
//! let garmr = GarmrClient::new().expect("Garmr should initialize");
//! let signing_key = SigningKeyWrapper::generate();
//! let platform = Arc::new(MockPlatformAdapter::new());
//! let orthrus = OrthrusClient::new(
//!     "shepherd-01".to_string(),
//!     signing_key,
//!     platform,
//!     ContainmentPolicy::default(),
//!     "shepherd:operator:rick".to_string(),
//! ).expect("Orthrus should initialize");
//!
//! let swarm = Swarm::new(yggdrasil, garmr, orthrus);
//! let status = swarm.status().expect("Swarm status query should succeed");
//! println!("Swarm nodes: {}, avg trust: {:.2}",
//!     status.total_nodes, status.average_trust_score);
//! # };
//! ```

pub mod approval;
pub mod config;
pub mod error;
pub mod garmr;
pub mod operator;
pub mod orthrus;
pub mod swarm;
pub mod yggdrasil;

pub use approval::{ApprovalTokenBuilder, build_containment_policy};
pub use config::ShepherdConfig;
pub use error::{Result, ShepherdError};
pub use garmr::GarmrClient;
pub use operator::{KeyStore, OperatorIdentity};
pub use orthrus::OrthrusClient;
pub use swarm::{OverrideAction, Swarm};
pub use yggdrasil::{
    DeviceSummary, ObservationSummary, TrustScoreSummary, VerdictSummary, YggdrasilClient,
};
