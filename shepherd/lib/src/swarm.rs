//! High-level swarm operations for the Shepherd operator.
//!
//! Combines Yggdrasil queries, Garmr verdict evaluation, and Orthrus
//! containment into operator-facing operations.

use crate::error::{Result, ShepherdError};
use crate::yggdrasil::{
    DeviceSummary, ObservationSummary, TrustScoreSummary, VerdictSummary, YggdrasilClient,
};
use crate::{GarmrClient, OrthrusClient};
use cerberus_core::action::ActionDirective;
use cerberus_core::verdict::Verdict;
use uuid::Uuid;

/// Swarm status overview for the operator dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SwarmStatus {
    pub total_nodes: usize,
    pub active_verdicts: usize,
    pub confirmed_verdicts: usize,
    pub suspicious_verdicts: usize,
    pub active_containments: usize,
    pub average_trust_score: f32,
    pub nodes: Vec<TrustScoreSummary>,
    pub recent_verdicts: Vec<VerdictSummary>,
}

/// Swarm operations facade.
pub struct Swarm {
    yggdrasil: YggdrasilClient,
    garmr: GarmrClient,
    orthrus: OrthrusClient,
}

impl Swarm {
    /// Create a new Swarm facade with all sub-clients.
    pub fn new(
        yggdrasil: YggdrasilClient,
        garmr: GarmrClient,
        orthrus: OrthrusClient,
    ) -> Self {
        Self {
            yggdrasil,
            garmr,
            orthrus,
        }
    }

    /// Returns a reference to the Yggdrasil client for direct queries.
    pub fn yggdrasil(&self) -> &YggdrasilClient {
        &self.yggdrasil
    }

    /// Get overall swarm status for operator display.
    pub fn status(&self) -> Result<SwarmStatus> {
        let trust_scores = self.yggdrasil.get_all_trust_scores()?;
        let active_containments = self.orthrus.list_active_containments().len();

        let average_trust = if trust_scores.is_empty() {
            0.0
        } else {
            trust_scores.iter().map(|s| s.score).sum::<f32>() / trust_scores.len() as f32
        };

        Ok(SwarmStatus {
            total_nodes: trust_scores.len(),
            active_verdicts: 0, // Placeholder - Yggdrasil doesn't expose list-all yet
            confirmed_verdicts: 0,
            suspicious_verdicts: 0,
            active_containments,
            average_trust_score: average_trust,
            nodes: trust_scores,
            recent_verdicts: Vec::new(),
        })
    }

    /// Get a verdict summary by ID.
    pub fn get_verdict(&self, verdict_id: &str) -> Result<Option<VerdictSummary>> {
        let verdict = self.yggdrasil.get_verdict(verdict_id)?;
        Ok(verdict.map(|v| self.verdict_to_summary(&v)))
    }

    /// Get observations for a specific entity (agent, host, user).
    pub fn get_observations_for_entity(
        &self,
        entity: &str,
        limit: usize,
    ) -> Result<Vec<ObservationSummary>> {
        let observations = self
            .yggdrasil
            .get_observations_for_entity(entity, limit)?;
        Ok(observations
            .into_iter()
            .map(|o| ObservationSummary {
                observation_id: o.observation_id,
                agent_id: o.agent_id,
                timestamp_ns: o.timestamp_ns,
                obs_type: format!("{:?}", o.obs_type),
                confidence: o.confidence,
                classification: o
                    .evidence
                    .fields
                    .get("classification")
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
                yggdrasil_refs: o.yggdrasil_refs,
            })
            .collect())
    }

    /// Get device information by ID.
    pub fn get_device(&self, device_id: &str) -> Result<Option<DeviceSummary>> {
        let device = self.yggdrasil.get_device(device_id)?;
        Ok(device.map(|d| DeviceSummary {
            id: d.id,
            hostname: d.hostname,
            ips: d.ips,
            os: d.os,
            role: d.role,
            tier: d.tier,
            trust_score: d.trust_score,
            status: "ACTIVE".to_string(), // Yggdrasil DeviceEntity doesn't have status field
        }))
    }

    /// Get trust score for a specific node.
    pub fn get_node_trust(&self, agent_id: &str) -> Result<Option<f32>> {
        self.yggdrasil.get_trust_score(agent_id)
    }

    /// Approve a pending containment: generate an approval token and
    /// execute it through Orthrus.
    pub async fn approve_containment(
        &mut self,
        directive: &ActionDirective,
        verdict_confidence: f32,
    ) -> Result<cerberus_orthrus::policy::ApprovalToken> {
        let token = self
            .orthrus
            .generate_approval_token(directive, None)?;
        // Execute with the approval token
        let _result = self
            .orthrus
            .execute_with_approval(directive, verdict_confidence, token.clone())
            .await?;
        Ok(token)
    }

    /// Roll back a containment by directive ID.
    pub async fn rollback_containment(&mut self, directive_id: &str) -> Result<()> {
        self.orthrus.rollback(directive_id).await
    }

    /// List all active containments.
    pub fn list_active_containments(&self) -> Vec<cerberus_orthrus::policy::RollbackRecord> {
        self.orthrus.list_active_containments()
    }

    /// Create a network isolation directive for a target IP.
    pub fn build_isolate_directive(
        target_ip: String,
        rationale: String,
        urgency: f32,
    ) -> ActionDirective {
        let directive_id = format!("dir-{}", Uuid::now_v7());
        OrthrusClient::build_network_isolate_directive(
            directive_id,
            target_ip,
            rationale,
            urgency,
        )
    }

    /// Create a credential suspension directive for a user.
    pub fn build_suspend_directive(
        user_id: String,
        rationale: String,
        urgency: f32,
    ) -> ActionDirective {
        let directive_id = format!("dir-{}", Uuid::now_v7());
        OrthrusClient::build_credential_suspend_directive(
            directive_id,
            user_id,
            rationale,
            urgency,
        )
    }

    /// Override a Garmr verdict: allow, deny, or modify the recommended
    /// actions. This is the Shepherd's human override authority.
    pub fn override_verdict(
        &self,
        verdict_id: &str,
        action: OverrideAction,
        rationale: String,
    ) -> Result<VerdictSummary> {
        let verdict = self
            .yggdrasil
            .get_verdict(verdict_id)?
            .ok_or_else(|| ShepherdError::NotFound(format!("Verdict {verdict_id} not found")))?;

        match action {
            OverrideAction::Allow => {
                // Allow the verdict's recommended actions to proceed
                // (no change needed - Orthrus will execute them)
                Ok(self.verdict_to_summary(&verdict))
            }
            OverrideAction::Deny => {
                // Deny: downgrade classification to Benign
                let mut summary = self.verdict_to_summary(&verdict);
                summary.classification = "DENIED_BY_OPERATOR".to_string();
                summary.rationale = rationale;
                Ok(summary)
            }
            OverrideAction::Modify => {
                // Modify: operator supplies new actions (not implemented in this version)
                let mut summary = self.verdict_to_summary(&verdict);
                summary.rationale = format!("MODIFIED: {rationale}");
                Ok(summary)
            }
        }
    }

    /// Convert a core Verdict to a VerdictSummary for display.
    fn verdict_to_summary(&self, v: &Verdict) -> VerdictSummary {
        VerdictSummary {
            verdict_id: v.verdict_id.clone(),
            timestamp_ns: v.timestamp_ns,
            correlation_id: v.correlation_id.clone(),
            confidence: v.confidence,
            classification: format!("{:?}", v.classification),
            threat_class: v.threat_class.clone(),
            participating_nodes: v.participating_nodes.clone(),
            evidence_trail: v.evidence_trail.clone(),
            recommended_actions: v
                .recommended_actions
                .iter()
                .map(|a| format!("{:?}", a.action_type))
                .collect(),
            rationale: v.rationale.clone(),
            garmr_instance: v.garmr_instance.clone(),
        }
    }
}

/// Operator override actions for a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideAction {
    Allow,
    Deny,
    Modify,
}

impl std::str::FromStr for OverrideAction {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "allow" => Ok(OverrideAction::Allow),
            "deny" => Ok(OverrideAction::Deny),
            "modify" => Ok(OverrideAction::Modify),
            _ => Err(format!("Invalid override action: {s}")),
        }
    }
}
