//! Approval token management for Shepherd operator authorization.
//!
//! Shepherd generates cryptographically signed ApprovalTokens that
//! Orthrus verifies before executing containment directives that
//! fall below the autonomous confidence threshold.

use crate::error::{Result, ShepherdError};
use cerberus_core::action::ActionDirective;
use cerberus_core::crypto::{SigningKeyWrapper, VerifyingKeyWrapper};
use cerberus_orthrus::policy::{ApprovalToken, ContainmentPolicy};
use chrono::Utc;
use uuid::Uuid;

/// Builder for creating and signing ApprovalTokens.
#[derive(Debug, Clone)]
pub struct ApprovalTokenBuilder {
    signing_key: SigningKeyWrapper,
    operator_id: String,
    default_ttl_sec: i64,
}

impl ApprovalTokenBuilder {
    /// Create a new builder with the operator's signing key.
    pub fn new(signing_key: SigningKeyWrapper, operator_id: String, default_ttl_sec: i64) -> Self {
        Self {
            signing_key,
            operator_id,
            default_ttl_sec,
        }
    }

    /// Sign an approval token for the given directive.
    ///
    /// The token authorizes Orthrus to execute the directive even when
    /// the verdict confidence is below the autonomous threshold.
    pub fn sign_for_directive(
        &self,
        directive: &ActionDirective,
        ttl_sec: Option<i64>,
    ) -> Result<ApprovalToken> {
        let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let ttl = ttl_sec.unwrap_or(self.default_ttl_sec);
        let expires_at_ns = now_ns + (ttl * 1_000_000_000);

        let token_id = format!("tok-{}", Uuid::now_v7());

        let payload = ApprovalToken::canonical_payload(
            &token_id,
            &directive.directive_id,
            &self.operator_id,
            now_ns,
            expires_at_ns,
        );

        let sig = self.signing_key.sign(&payload);
        let signature = sig.to_bytes().to_vec();

        Ok(ApprovalToken {
            token_id,
            directive_id: directive.directive_id.clone(),
            operator_id: self.operator_id.clone(),
            granted_at_ns: now_ns,
            expires_at_ns,
            signature,
        })
    }

    /// Verify an approval token using the operator's verifying key.
    pub fn verify_token(
        token: &ApprovalToken,
        verifying_key: &VerifyingKeyWrapper,
    ) -> Result<()> {
        token.verify(verifying_key).map_err(|e| {
            ShepherdError::Orthrus(format!("Approval token verification failed: {e}"))
        })
    }

    /// Check whether a token has expired.
    pub fn is_expired(token: &ApprovalToken) -> bool {
        let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        token.is_expired(now_ns)
    }

    /// Returns the operator ID associated with this builder.
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }
}

/// Convenience: create a pre-populated ContainmentPolicy with the
/// operator's verifying key set for Orthrus integration.
pub fn build_containment_policy(
    operator_verifying_key: Option<VerifyingKeyWrapper>,
    force_human_approval: bool,
) -> ContainmentPolicy {
    let mut policy = ContainmentPolicy::default();
    policy.force_human_approval = force_human_approval;
    policy.operator_verifying_key = operator_verifying_key;
    policy
}
