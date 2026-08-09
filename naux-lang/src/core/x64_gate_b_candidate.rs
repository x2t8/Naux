//! Gate B authority for the sealed, non-executable encoder-policy-1.5
//! candidate capsule.
//!
//! Emission owns profile generation. Verification regenerates the complete
//! frozen weighted profile before replaying candidate construction. Neither
//! path maps, executes, packages, or times candidate bytes.

use super::corevm0_gate_a::CoreVmGateAWorkload;
use super::x64_gate_b_profile::{
    emit_x64_gate_b_weighted_profile, X64GateBWeightedProfile, X64GateBWeightedProfileError,
};
use super::x64_native_lighthouse::{X64NativeLighthouseError, X64NativeLighthousePackage};
use super::x64_target::candidate::{
    build_x64_target_policy15_candidate_capsule, verify_x64_target_policy15_candidate_capsule,
};
use super::x64_target::{
    VerifiedX64TargetPolicy15CandidateCapsule, X64TargetPolicy15CandidateCapsule,
    X64TargetPolicy15CandidateError,
};
use std::fmt;

#[derive(Debug)]
pub enum X64GateBPolicy15CandidateError {
    Profile(X64GateBWeightedProfileError),
    Lighthouse(String),
    Candidate(X64TargetPolicy15CandidateError),
}

impl fmt::Display for X64GateBPolicy15CandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(error) => write!(formatter, "{error}"),
            Self::Lighthouse(error) => {
                write!(
                    formatter,
                    "Gate B policy-1.5 candidate lighthouse failed: {error}"
                )
            }
            Self::Candidate(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for X64GateBPolicy15CandidateError {}

impl From<X64GateBWeightedProfileError> for X64GateBPolicy15CandidateError {
    fn from(value: X64GateBWeightedProfileError) -> Self {
        Self::Profile(value)
    }
}

impl From<X64NativeLighthouseError> for X64GateBPolicy15CandidateError {
    fn from(value: X64NativeLighthouseError) -> Self {
        Self::Lighthouse(value.to_string())
    }
}

impl From<X64TargetPolicy15CandidateError> for X64GateBPolicy15CandidateError {
    fn from(value: X64TargetPolicy15CandidateError) -> Self {
        Self::Candidate(value)
    }
}

/// Regenerate the canonical Gate B profile and materialize its exact
/// non-executable policy-1.5 candidate.
pub fn emit_x64_gate_b_policy15_candidate_capsule(
) -> Result<X64TargetPolicy15CandidateCapsule, X64GateBPolicy15CandidateError> {
    let profile = emit_x64_gate_b_weighted_profile()?;
    build_from_fresh_profile(&profile)
}

/// Independently regenerate Gate B evidence and the complete candidate, then
/// compare the claimed capsule. The returned witness has no execution API.
pub fn verify_x64_gate_b_policy15_candidate_capsule(
    candidate: &X64TargetPolicy15CandidateCapsule,
) -> Result<VerifiedX64TargetPolicy15CandidateCapsule<'_>, X64GateBPolicy15CandidateError> {
    let profile = emit_x64_gate_b_weighted_profile()?;
    let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bound = package.source_bound()?;
    verify_x64_target_policy15_candidate_capsule(
        candidate,
        bound,
        profile.profile(),
        profile.profile_hash(),
    )
    .map_err(Into::into)
}

fn build_from_fresh_profile(
    profile: &X64GateBWeightedProfile,
) -> Result<X64TargetPolicy15CandidateCapsule, X64GateBPolicy15CandidateError> {
    let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bound = package.source_bound()?;
    build_x64_target_policy15_candidate_capsule(bound, profile.profile(), profile.profile_hash())
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        X64_TARGET_ENCODER_POLICY_VERSION, X64_TARGET_POLICY15_ENCODER_POLICY_VERSION,
    };

    #[test]
    #[ignore = "full 2.526-billion-work Gate B profile is regenerated twice; run explicitly in release mode"]
    fn frozen_gate_b_candidate_capsule_emits_and_independently_replays() {
        let candidate =
            emit_x64_gate_b_policy15_candidate_capsule().expect("candidate capsule must emit");
        let artifact = candidate.candidate_artifact();
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
        assert_eq!(
            artifact.program.encoder_policy_version,
            X64_TARGET_POLICY15_ENCODER_POLICY_VERSION
        );
        assert_eq!(artifact.program.code.len(), 3_214);
        assert_eq!(
            candidate.prospective_candidate_code_hash().to_hex(),
            "0e392caf51dbc65f9e36e08c678118e78b8f6aed90bf1df0edbf4b5c6a5f5173"
        );
        assert_eq!(
            candidate.prospective_realization_hash().to_hex(),
            "172b508e9648501162e28274afa3bcec0632f9cb3212e38f2b87b21ad7516198"
        );
        assert_eq!(
            candidate.capsule_hash().to_hex(),
            "12fce4c6336b3c34a34ad05961b4fb75ae45427ca7b75b7bace98efdab886d24"
        );
        assert_eq!(
            artifact.program.plan_hash.to_hex(),
            "f2145ac06a2c0cb789aced9a8751f6c6cbe8ddc14575a4ccbfa5b47f3fd9c5bd"
        );
        assert_eq!(
            artifact.program.code_hash.to_hex(),
            "ea1646e517562e42b2469420d6e4b4e16d86dcc9458ab03363acac60aa02b991"
        );
        assert_eq!(
            artifact.semantic_hash.to_hex(),
            "4a290fde1eaf4c0df98383818af4a18b531ae6d86f5d859926e63f4620fde99c"
        );
        println!(
            "policy-1.5 candidate capsule={} plan={} code={} semantic={}",
            candidate.capsule_hash().to_hex(),
            artifact.program.plan_hash.to_hex(),
            artifact.program.code_hash.to_hex(),
            artifact.semantic_hash.to_hex(),
        );
        verify_x64_gate_b_policy15_candidate_capsule(&candidate)
            .expect("candidate capsule must independently replay");
    }
}
