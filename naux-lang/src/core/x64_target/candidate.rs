//! Sealed, non-executable encoder-policy-1.5 candidate boundary.
//!
//! A candidate is regenerated from an already source-bound policy-1.4 target
//! and sealed profile evidence.  It deliberately does not implement or expose
//! any conversion into the native runner's `SourceBoundX64TargetArtifact`.

use super::raw::{
    self, RawProspectiveExecutionAuthority, RawProspectiveLabelDisposition, RawProspectiveShadow,
    RawProspectiveSharedJoinPartition, RawProspectiveSharedJoinRealization,
};
use super::*;
use crate::core::encoding::sha256;
use crate::core::schema::SemanticHash;
use std::fmt;

pub const X64_TARGET_POLICY15_CANDIDATE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TARGET_POLICY15_CANDIDATE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TARGET_POLICY15_ENCODER_POLICY_VERSION: (u16, u16, u16) = (1, 5, 0);

const CANDIDATE_CAPSULE_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-capsule:v1\0";

const FROZEN_GATE_B_PROFILE_ROOT: SemanticHash = SemanticHash([
    0xea, 0x09, 0x58, 0xfd, 0x43, 0x46, 0xc0, 0xa2, 0xa2, 0x09, 0xb8, 0x31, 0x63, 0x37, 0x48, 0x70,
    0x97, 0x26, 0xe1, 0xba, 0x23, 0xee, 0x27, 0x12, 0x56, 0x5f, 0x6d, 0x2b, 0xe6, 0x27, 0x22, 0xa5,
]);
const FROZEN_PROSPECTIVE_REALIZATION_HASH: SemanticHash = SemanticHash([
    0x17, 0x2b, 0x50, 0x8e, 0x96, 0x48, 0x50, 0x11, 0x62, 0xe2, 0x82, 0x74, 0xaf, 0xa3, 0xbc, 0xec,
    0x06, 0x32, 0xf9, 0xcb, 0x32, 0x12, 0xe3, 0x8f, 0x2b, 0x87, 0xb2, 0x1a, 0xd7, 0x51, 0x61, 0x98,
]);
const FROZEN_PROSPECTIVE_CODE_HASH: SemanticHash = SemanticHash([
    0x0e, 0x39, 0x2c, 0xaf, 0x51, 0xdb, 0xc6, 0x5f, 0x9e, 0x36, 0xe0, 0x8c, 0x67, 0x81, 0x18, 0xe7,
    0x8b, 0x8f, 0x6a, 0xed, 0x90, 0xbf, 0x1d, 0xf0, 0xed, 0xbf, 0x4b, 0x5c, 0x6a, 0x5f, 0x51, 0x73,
]);
const FROZEN_CANDIDATE_CAPSULE_HASH: SemanticHash = SemanticHash([
    0x12, 0xfc, 0xe4, 0xc6, 0x33, 0x6b, 0x3c, 0x34, 0xa3, 0x4a, 0xd0, 0x59, 0x61, 0xb4, 0xfb, 0x75,
    0xae, 0x45, 0x42, 0x7c, 0xa7, 0xb7, 0x5b, 0x7b, 0xac, 0xe9, 0x8e, 0xfd, 0xab, 0x88, 0x6d, 0x24,
]);
const FROZEN_CANDIDATE_PLAN_HASH: SemanticHash = SemanticHash([
    0xf2, 0x14, 0x5a, 0xc0, 0x6a, 0x2c, 0x0c, 0xb7, 0x89, 0xac, 0xed, 0x9a, 0x87, 0x51, 0xf6, 0xc6,
    0xcb, 0xe8, 0xdd, 0xc1, 0x45, 0x75, 0xa4, 0xcc, 0xbf, 0xa5, 0xb4, 0x7f, 0x3f, 0xd9, 0xc5, 0xbd,
]);
const FROZEN_CANDIDATE_CODE_HASH: SemanticHash = SemanticHash([
    0xea, 0x16, 0x46, 0xe5, 0x17, 0x56, 0x2e, 0x42, 0xb2, 0x46, 0x94, 0x20, 0xd6, 0xe4, 0xb4, 0xe1,
    0x6d, 0x86, 0xdc, 0xc9, 0x45, 0x8a, 0xb0, 0x33, 0x63, 0xac, 0xac, 0x60, 0xaa, 0x02, 0xb9, 0x91,
]);
const FROZEN_CANDIDATE_SEMANTIC_HASH: SemanticHash = SemanticHash([
    0x4a, 0x29, 0x0f, 0xde, 0x1e, 0xaf, 0x4c, 0x0d, 0xf9, 0x83, 0x83, 0x81, 0x8a, 0xf4, 0xa1, 0x8b,
    0x53, 0x1a, 0xe6, 0xd8, 0x6f, 0x5d, 0x85, 0x99, 0x26, 0xe6, 0x3f, 0x46, 0x20, 0xfd, 0xe9, 0x9c,
]);

/// Durable identity for prospective policy-1.5 output.
///
/// The nested target artifact is inspectable, but no accepted execution API
/// consumes this type and the ordinary target verifier intentionally rejects
/// its encoder-policy version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetPolicy15CandidateCapsule {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    baseline_target_semantic_hash: SemanticHash,
    baseline_target_plan_hash: SemanticHash,
    baseline_target_code_hash: SemanticHash,
    source_core_hash: SemanticHash,
    source_ssa_hash: SemanticHash,
    source_machine_ir_hash: SemanticHash,
    profile_schema_version: (u16, u16, u16),
    profile_policy_version: (u16, u16, u16),
    profile_evidence_root: SemanticHash,
    prospective_realization_hash: SemanticHash,
    prospective_candidate_code_hash: SemanticHash,
    candidate: X64TargetArtifact,
    capsule_hash: SemanticHash,
}

impl X64TargetPolicy15CandidateCapsule {
    pub const fn baseline_target_semantic_hash(&self) -> SemanticHash {
        self.baseline_target_semantic_hash
    }

    pub const fn baseline_target_plan_hash(&self) -> SemanticHash {
        self.baseline_target_plan_hash
    }

    pub const fn baseline_target_code_hash(&self) -> SemanticHash {
        self.baseline_target_code_hash
    }

    pub const fn profile_evidence_root(&self) -> SemanticHash {
        self.profile_evidence_root
    }

    pub const fn prospective_realization_hash(&self) -> SemanticHash {
        self.prospective_realization_hash
    }

    /// Code hash from the prospective-proof domain used by ADR-0049/0050.
    pub const fn prospective_candidate_code_hash(&self) -> SemanticHash {
        self.prospective_candidate_code_hash
    }

    /// Complete policy-1.5 target identity. This remains non-executable.
    pub const fn candidate_artifact(&self) -> &X64TargetArtifact {
        &self.candidate
    }

    pub const fn capsule_hash(&self) -> SemanticHash {
        self.capsule_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64TargetPolicy15CandidateCapsule<'candidate> {
    candidate: &'candidate X64TargetPolicy15CandidateCapsule,
}

/// Owned capability for reconstructing the one ADR-0051 candidate inside a
/// fresh ADR-0053 worker. This is deliberately distinct from full Gate B
/// profile verification and has no public constructor or export.
#[derive(Clone, Debug)]
pub(crate) struct ProcessReconstructedX64TargetPolicy15Candidate {
    candidate: X64TargetPolicy15CandidateCapsule,
}

impl ProcessReconstructedX64TargetPolicy15Candidate {
    pub(crate) const fn candidate(&self) -> &X64TargetPolicy15CandidateCapsule {
        &self.candidate
    }
}

/// Owned capability for packaging the one accepted ADR-0051 candidate behind
/// the candidate-specific ADR-0054 standalone authority.  It is deliberately
/// distinct from both native-process reconstruction and ordinary source-bound
/// policy-1.4 authority.
#[derive(Clone, Debug)]
pub(crate) struct StandaloneReconstructedX64TargetPolicy15Candidate {
    candidate: X64TargetPolicy15CandidateCapsule,
}

impl StandaloneReconstructedX64TargetPolicy15Candidate {
    pub(crate) const fn candidate(&self) -> &X64TargetPolicy15CandidateCapsule {
        &self.candidate
    }
}

impl<'candidate> VerifiedX64TargetPolicy15CandidateCapsule<'candidate> {
    pub const fn candidate(self) -> &'candidate X64TargetPolicy15CandidateCapsule {
        self.candidate
    }
}

/// Frozen ADR-0051 capsule identity used by the narrower ADR-0053 protocol.
pub const fn x64_target_policy15_accepted_candidate_capsule_hash() -> SemanticHash {
    FROZEN_CANDIDATE_CAPSULE_HASH
}

#[derive(Debug)]
pub enum X64TargetPolicy15CandidateError {
    InvalidSource(X64TargetSourceError),
    InvalidEvidence { field: &'static str },
    EncoderReplay(String),
    Encoding(X64TargetEncodeError),
    Profile(X64TargetProfileError),
    ArtifactIdentity { field: &'static str },
    CapsuleHashMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64TargetPolicy15CandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource(error) => write!(formatter, "{error}"),
            Self::InvalidEvidence { field } => {
                write!(formatter, "policy-1.5 candidate has invalid {field}")
            }
            Self::EncoderReplay(error) => {
                write!(formatter, "policy-1.5 candidate raw replay failed: {error}")
            }
            Self::Encoding(error) => write!(formatter, "{error}"),
            Self::Profile(error) => write!(formatter, "{error}"),
            Self::ArtifactIdentity { field } => {
                write!(
                    formatter,
                    "policy-1.5 candidate has invalid {field} identity"
                )
            }
            Self::CapsuleHashMismatch => {
                formatter.write_str("policy-1.5 candidate capsule seal does not replay")
            }
            Self::ReplayMismatch => formatter.write_str(
                "policy-1.5 candidate differs from complete source/profile regeneration",
            ),
        }
    }
}

impl std::error::Error for X64TargetPolicy15CandidateError {}

impl From<X64TargetEncodeError> for X64TargetPolicy15CandidateError {
    fn from(value: X64TargetEncodeError) -> Self {
        Self::Encoding(value)
    }
}

impl From<X64TargetProfileError> for X64TargetPolicy15CandidateError {
    fn from(value: X64TargetProfileError) -> Self {
        Self::Profile(value)
    }
}

/// Internal construction authority used by the Gate B evidence owner.
///
/// The evidence root is not interpreted here. Its owning module must provide
/// a canonical, freshly emitted or independently verified root.
pub(crate) fn build_x64_target_policy15_candidate_capsule(
    baseline: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    profile: &X64TargetExecutionProfile,
    profile_evidence_root: SemanticHash,
) -> Result<X64TargetPolicy15CandidateCapsule, X64TargetPolicy15CandidateError> {
    let candidate = reconstruct_candidate(baseline, profile, profile_evidence_root)?;
    verify_x64_target_policy15_candidate_capsule(
        &candidate,
        baseline,
        profile,
        profile_evidence_root,
    )?;
    Ok(candidate)
}

/// Fresh source/profile/raw replay for a claimed non-executable capsule.
pub(crate) fn verify_x64_target_policy15_candidate_capsule<'candidate>(
    candidate: &'candidate X64TargetPolicy15CandidateCapsule,
    baseline: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    profile: &X64TargetExecutionProfile,
    profile_evidence_root: SemanticHash,
) -> Result<VerifiedX64TargetPolicy15CandidateCapsule<'candidate>, X64TargetPolicy15CandidateError>
{
    if x64_target_policy15_candidate_capsule_hash(candidate)? != candidate.capsule_hash {
        return Err(X64TargetPolicy15CandidateError::CapsuleHashMismatch);
    }
    let replayed = reconstruct_candidate(baseline, profile, profile_evidence_root)?;
    if replayed != *candidate {
        return Err(X64TargetPolicy15CandidateError::ReplayMismatch);
    }
    Ok(VerifiedX64TargetPolicy15CandidateCapsule { candidate })
}

/// Reconstruct the exact accepted ADR-0051 executable image from the
/// canonical source-bound policy-1.4 program and the deterministic raw
/// prospective encoder. The full profile is verified once by the parent's
/// ADR-0052 witness; this child-only path cannot select any other candidate.
pub(crate) fn reconstruct_frozen_x64_target_policy15_candidate_for_process(
    baseline: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
) -> Result<ProcessReconstructedX64TargetPolicy15Candidate, X64TargetPolicy15CandidateError> {
    Ok(ProcessReconstructedX64TargetPolicy15Candidate {
        candidate: reconstruct_frozen_candidate(baseline, "process")?,
    })
}

/// Reconstruct the exact frozen candidate for ADR-0054 packaging without
/// granting native-runner or ordinary standalone authority.
pub(crate) fn reconstruct_frozen_x64_target_policy15_candidate_for_standalone(
    baseline: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
) -> Result<StandaloneReconstructedX64TargetPolicy15Candidate, X64TargetPolicy15CandidateError> {
    Ok(StandaloneReconstructedX64TargetPolicy15Candidate {
        candidate: reconstruct_frozen_candidate(baseline, "standalone")?,
    })
}

fn reconstruct_frozen_candidate(
    baseline: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    boundary: &'static str,
) -> Result<X64TargetPolicy15CandidateCapsule, X64TargetPolicy15CandidateError> {
    let rebound = verify_x64_target_source(
        baseline.artifact(),
        baseline.source_machine_ir(),
        baseline.source_ssa(),
        baseline.source_core(),
    )
    .map_err(X64TargetPolicy15CandidateError::InvalidSource)?;
    let baseline_artifact = rebound.artifact();
    let baseline_program = rebound.program();
    let replayed = raw::encode(baseline_program)
        .map_err(|error| X64TargetPolicy15CandidateError::EncoderReplay(error.to_string()))?;
    if replayed.labels != baseline_program.labels
        || replayed.fixups != baseline_program.fixups
        || replayed.code != baseline_program.code
    {
        return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
            field: match boundary {
                "standalone" => "standalone policy-1.4 raw replay",
                _ => "process policy-1.4 raw replay",
            },
        });
    }
    let prospective = &replayed.realization.prospective_shared_join_realization;
    let shadow = replayed.prospective_shadow.as_ref().ok_or(
        X64TargetPolicy15CandidateError::InvalidEvidence {
            field: match boundary {
                "standalone" => "standalone complete prospective shadow",
                _ => "process complete prospective shadow",
            },
        },
    )?;
    if !prospective.complete
        || prospective.candidate_code_hash != FROZEN_PROSPECTIVE_CODE_HASH
        || prospective.candidate_code_bytes != shadow.code.len() as u64
        || prospective.candidate_atom_count != shadow.atoms.len() as u64
        || prospective.labels.len() != shadow.labels.len()
        || prospective.fixups.len() != shadow.fixups.len()
    {
        return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
            field: match boundary {
                "standalone" => "standalone prospective reconstruction",
                _ => "process prospective reconstruction",
            },
        });
    }

    let mut candidate_program = baseline_program.clone();
    candidate_program.encoder_policy_version = X64_TARGET_POLICY15_ENCODER_POLICY_VERSION;
    candidate_program.labels = shadow.labels.clone();
    candidate_program.fixups = shadow.fixups.clone();
    candidate_program.code = shadow.code.clone();
    candidate_program.plan_hash = SemanticHash::ZERO;
    candidate_program.code_hash = SemanticHash::ZERO;
    let candidate_artifact = X64TargetArtifact::seal(candidate_program)?;
    if candidate_artifact.program.plan_hash != FROZEN_CANDIDATE_PLAN_HASH
        || candidate_artifact.program.code_hash != FROZEN_CANDIDATE_CODE_HASH
        || candidate_artifact.semantic_hash != FROZEN_CANDIDATE_SEMANTIC_HASH
    {
        return Err(X64TargetPolicy15CandidateError::ArtifactIdentity {
            field: match boundary {
                "standalone" => "frozen standalone candidate",
                _ => "frozen process candidate",
            },
        });
    }

    let mut candidate = X64TargetPolicy15CandidateCapsule {
        schema_version: X64_TARGET_POLICY15_CANDIDATE_SCHEMA_VERSION,
        policy_version: X64_TARGET_POLICY15_CANDIDATE_POLICY_VERSION,
        baseline_target_semantic_hash: baseline_artifact.semantic_hash,
        baseline_target_plan_hash: baseline_program.plan_hash,
        baseline_target_code_hash: baseline_program.code_hash,
        source_core_hash: baseline_program.source_core_hash,
        source_ssa_hash: baseline_program.source_ssa_hash,
        source_machine_ir_hash: baseline_program.source_machine_ir_hash,
        profile_schema_version: X64_TARGET_PROFILE_SCHEMA_VERSION,
        profile_policy_version: X64_TARGET_PROFILE_POLICY_VERSION,
        profile_evidence_root: FROZEN_GATE_B_PROFILE_ROOT,
        prospective_realization_hash: FROZEN_PROSPECTIVE_REALIZATION_HASH,
        prospective_candidate_code_hash: FROZEN_PROSPECTIVE_CODE_HASH,
        candidate: candidate_artifact,
        capsule_hash: SemanticHash::ZERO,
    };
    candidate.capsule_hash = x64_target_policy15_candidate_capsule_hash(&candidate)?;
    if candidate.capsule_hash != FROZEN_CANDIDATE_CAPSULE_HASH {
        return Err(X64TargetPolicy15CandidateError::CapsuleHashMismatch);
    }
    Ok(candidate)
}

pub fn x64_target_policy15_candidate_capsule_hash(
    candidate: &X64TargetPolicy15CandidateCapsule,
) -> Result<SemanticHash, X64TargetPolicy15CandidateError> {
    validate_candidate_artifact_identity(&candidate.candidate)?;
    let mut bytes = Vec::with_capacity(CANDIDATE_CAPSULE_DOMAIN.len() + 24 + (13 * 32));
    bytes.extend_from_slice(CANDIDATE_CAPSULE_DOMAIN);
    candidate_put_version(&mut bytes, candidate.schema_version);
    candidate_put_version(&mut bytes, candidate.policy_version);
    candidate_put_hash(&mut bytes, candidate.baseline_target_semantic_hash);
    candidate_put_hash(&mut bytes, candidate.baseline_target_plan_hash);
    candidate_put_hash(&mut bytes, candidate.baseline_target_code_hash);
    candidate_put_hash(&mut bytes, candidate.source_core_hash);
    candidate_put_hash(&mut bytes, candidate.source_ssa_hash);
    candidate_put_hash(&mut bytes, candidate.source_machine_ir_hash);
    candidate_put_version(&mut bytes, candidate.profile_schema_version);
    candidate_put_version(&mut bytes, candidate.profile_policy_version);
    candidate_put_hash(&mut bytes, candidate.profile_evidence_root);
    candidate_put_hash(&mut bytes, candidate.prospective_realization_hash);
    candidate_put_hash(&mut bytes, candidate.prospective_candidate_code_hash);
    candidate_put_version(
        &mut bytes,
        candidate.candidate.program.encoder_policy_version,
    );
    candidate_put_hash(&mut bytes, candidate.candidate.program.plan_hash);
    candidate_put_hash(&mut bytes, candidate.candidate.program.code_hash);
    candidate_put_hash(&mut bytes, candidate.candidate.semantic_hash);
    Ok(SemanticHash(sha256(&bytes)))
}

fn reconstruct_candidate(
    baseline: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    profile: &X64TargetExecutionProfile,
    profile_evidence_root: SemanticHash,
) -> Result<X64TargetPolicy15CandidateCapsule, X64TargetPolicy15CandidateError> {
    let rebound = verify_x64_target_source(
        baseline.artifact(),
        baseline.source_machine_ir(),
        baseline.source_ssa(),
        baseline.source_core(),
    )
    .map_err(X64TargetPolicy15CandidateError::InvalidSource)?;
    let baseline_artifact = rebound.artifact();
    let baseline_program = rebound.program();
    validate_profile_envelope(profile, baseline_artifact, profile_evidence_root)?;

    let replayed = raw::encode(baseline_program)
        .map_err(|error| X64TargetPolicy15CandidateError::EncoderReplay(error.to_string()))?;
    if replayed.labels != baseline_program.labels
        || replayed.fixups != baseline_program.fixups
        || replayed.code != baseline_program.code
    {
        return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
            field: "policy-1.4 raw replay",
        });
    }
    let shadow = replayed.prospective_shadow.as_ref().ok_or(
        X64TargetPolicy15CandidateError::InvalidEvidence {
            field: "complete prospective shadow",
        },
    )?;
    validate_profile_realization(
        profile,
        &replayed.realization.prospective_shared_join_realization,
        shadow,
    )?;

    let mut candidate_program = baseline_program.clone();
    candidate_program.encoder_policy_version = X64_TARGET_POLICY15_ENCODER_POLICY_VERSION;
    candidate_program.labels = shadow.labels.clone();
    candidate_program.fixups = shadow.fixups.clone();
    candidate_program.code = shadow.code.clone();
    candidate_program.plan_hash = SemanticHash::ZERO;
    candidate_program.code_hash = SemanticHash::ZERO;
    let candidate_artifact = X64TargetArtifact::seal(candidate_program)?;

    let prospective = &profile.prospective_shared_join_realization;
    let mut candidate = X64TargetPolicy15CandidateCapsule {
        schema_version: X64_TARGET_POLICY15_CANDIDATE_SCHEMA_VERSION,
        policy_version: X64_TARGET_POLICY15_CANDIDATE_POLICY_VERSION,
        baseline_target_semantic_hash: baseline_artifact.semantic_hash,
        baseline_target_plan_hash: baseline_program.plan_hash,
        baseline_target_code_hash: baseline_program.code_hash,
        source_core_hash: baseline_program.source_core_hash,
        source_ssa_hash: baseline_program.source_ssa_hash,
        source_machine_ir_hash: baseline_program.source_machine_ir_hash,
        profile_schema_version: profile.schema_version,
        profile_policy_version: profile.policy_version,
        profile_evidence_root,
        prospective_realization_hash: prospective.realization_hash,
        prospective_candidate_code_hash: prospective.candidate_code_hash,
        candidate: candidate_artifact,
        capsule_hash: SemanticHash::ZERO,
    };
    candidate.capsule_hash = x64_target_policy15_candidate_capsule_hash(&candidate)?;
    Ok(candidate)
}

fn validate_profile_envelope(
    profile: &X64TargetExecutionProfile,
    baseline: &X64TargetArtifact,
    profile_evidence_root: SemanticHash,
) -> Result<(), X64TargetPolicy15CandidateError> {
    if profile_evidence_root == SemanticHash::ZERO {
        return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
            field: "profile evidence root",
        });
    }
    if profile.schema_version != X64_TARGET_PROFILE_SCHEMA_VERSION
        || profile.policy_version != X64_TARGET_PROFILE_POLICY_VERSION
        || profile.encoder_policy_version != X64_TARGET_ENCODER_POLICY_VERSION
        || profile.target_semantic_hash != baseline.semantic_hash
        || profile.target_plan_hash != baseline.program.plan_hash
        || profile.target_code_hash != baseline.program.code_hash
        || !profile.optimized_realization
        || !profile.shared_join_composition.complete
    {
        return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
            field: "profile envelope",
        });
    }
    let prospective = &profile.prospective_shared_join_realization;
    if !prospective.complete
        || !prospective.machine_semantic_proof.complete
        || prospective.machine_semantic_proof.register_rows == 0
        || prospective.machine_semantic_proof.decoded_bytes == 0
        || prospective.machine_semantic_proof.decoded_instructions == 0
        || prospective.machine_semantic_proof.symbolic_nodes == 0
        || prospective.machine_semantic_proof.reference_route_events == 0
        || x64_target_prospective_shared_join_realization_hash(prospective)?
            != prospective.realization_hash
    {
        return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
            field: "prospective semantic proof",
        });
    }
    Ok(())
}

fn validate_profile_realization(
    profile: &X64TargetExecutionProfile,
    raw: &RawProspectiveSharedJoinRealization,
    shadow: &RawProspectiveShadow,
) -> Result<(), X64TargetPolicy15CandidateError> {
    let prospective = &profile.prospective_shared_join_realization;
    let raw_summary_matches = raw.complete
        && prospective.baseline_code_bytes == raw.baseline_code_bytes
        && prospective.baseline_code_hash == raw.baseline_code_hash
        && prospective.candidate_code_bytes == raw.candidate_code_bytes
        && prospective.candidate_code_hash == raw.candidate_code_hash
        && prospective.code_bytes_added == raw.code_bytes_added
        && prospective.code_bytes_removed == raw.code_bytes_removed
        && prospective.baseline_atom_count == raw.baseline_atom_count
        && prospective.candidate_atom_count == raw.candidate_atom_count
        && prospective.atom_count_added == raw.atom_count_added
        && prospective.atom_count_removed == raw.atom_count_removed
        && prospective.baseline_fixup_count == raw.baseline_fixup_count
        && prospective.candidate_fixup_count == raw.candidate_fixup_count
        && prospective.fixup_count_added == raw.fixup_count_added
        && prospective.fixup_count_removed == raw.fixup_count_removed
        && prospective.body_replicas == raw.body_replicas
        && prospective.shared_join_authority_atoms == raw.shared_join_authority_atoms
        && prospective.label_count == shadow.labels.len() as u64
        && prospective.candidate_code_bytes == shadow.code.len() as u64
        && prospective.candidate_atom_count == shadow.atoms.len() as u64
        && prospective.candidate_fixup_count == shadow.fixups.len() as u64;
    if !raw_summary_matches
        || prospective.atoms.len() != raw.atoms.len()
        || prospective.labels.len() != raw.labels.len()
        || prospective.fixups.len() != raw.fixups.len()
    {
        return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
            field: "prospective realization summary",
        });
    }

    for (declared, replayed) in prospective.atoms.iter().zip(&raw.atoms) {
        if declared.physical_owner != replayed.physical_owner
            || declared.semantic_event != X64TargetProfileEvent::from(replayed.semantic_event)
            || declared.class != X64TargetProfileTemplateClass::from(replayed.class)
            || declared.start != replayed.start
            || declared.end != replayed.end
            || declared.static_bytes != replayed.end.saturating_sub(replayed.start)
            || !authority_matches(declared.execution_authority, replayed.execution_authority)
        {
            return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
                field: "prospective atom receipt",
            });
        }
    }
    for ((declared, replayed), label) in prospective
        .labels
        .iter()
        .zip(&raw.labels)
        .zip(&shadow.labels)
    {
        if declared.label != replayed.label
            || declared.owner != replayed.owner
            || declared.code_offset != replayed.code_offset
            || declared.owning_atom != replayed.owning_atom
            || declared.disposition != label_disposition(replayed.disposition)
            || label.id != replayed.label
            || label.owner != replayed.owner
            || label.code_offset != replayed.code_offset
        {
            return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
                field: "prospective label receipt",
            });
        }
    }
    for ((declared, replayed), fixup) in prospective
        .fixups
        .iter()
        .zip(&raw.fixups)
        .zip(&shadow.fixups)
    {
        if declared.fixup_index != replayed.fixup_index
            || declared.owning_atom != replayed.owning_atom
            || declared.patch_offset != replayed.patch_offset
            || declared.target != replayed.target
            || declared.addend != replayed.addend
            || fixup.patch_offset != replayed.patch_offset
            || fixup.target != replayed.target
            || fixup.addend != replayed.addend
        {
            return Err(X64TargetPolicy15CandidateError::InvalidEvidence {
                field: "prospective fixup receipt",
            });
        }
    }
    Ok(())
}

fn validate_candidate_artifact_identity(
    artifact: &X64TargetArtifact,
) -> Result<(), X64TargetPolicy15CandidateError> {
    if artifact.program.encoder_policy_version != X64_TARGET_POLICY15_ENCODER_POLICY_VERSION {
        return Err(X64TargetPolicy15CandidateError::ArtifactIdentity {
            field: "encoder policy",
        });
    }
    if x64_target_plan_hash(&artifact.program)? != artifact.program.plan_hash {
        return Err(X64TargetPolicy15CandidateError::ArtifactIdentity { field: "plan hash" });
    }
    if x64_target_code_hash(&artifact.program.code)? != artifact.program.code_hash {
        return Err(X64TargetPolicy15CandidateError::ArtifactIdentity { field: "code hash" });
    }
    if x64_target_semantic_hash(&artifact.program)? != artifact.semantic_hash {
        return Err(X64TargetPolicy15CandidateError::ArtifactIdentity {
            field: "semantic hash",
        });
    }
    Ok(())
}

fn authority_matches(
    declared: X64TargetProspectiveExecutionAuthority,
    replayed: RawProspectiveExecutionAuthority,
) -> bool {
    match (declared, replayed) {
        (
            X64TargetProspectiveExecutionAuthority::Semantic { event: declared },
            RawProspectiveExecutionAuthority::SemanticEvent(replayed),
        ) => declared == X64TargetProfileEvent::from(replayed),
        (
            X64TargetProspectiveExecutionAuthority::SharedJoin {
                target: declared_target,
                root: declared_root,
                authority_trigger: declared_trigger,
                partition: declared_partition,
            },
            RawProspectiveExecutionAuthority::SharedJoin {
                target: replayed_target,
                root: replayed_root,
                authority_trigger: replayed_trigger,
                partition: replayed_partition,
            },
        ) => {
            declared_target == replayed_target
                && declared_root == replayed_root
                && declared_trigger == replayed_trigger
                && matches!(
                    (declared_partition, replayed_partition),
                    (
                        X64TargetProspectiveSharedJoinPartition::All,
                        RawProspectiveSharedJoinPartition::All,
                    ) | (
                        X64TargetProspectiveSharedJoinPartition::Else,
                        RawProspectiveSharedJoinPartition::Else,
                    )
                )
        }
        (
            X64TargetProspectiveExecutionAuthority::Static,
            RawProspectiveExecutionAuthority::Static,
        ) => true,
        _ => false,
    }
}

fn label_disposition(
    disposition: RawProspectiveLabelDisposition,
) -> X64TargetProspectiveLabelDisposition {
    match disposition {
        RawProspectiveLabelDisposition::Live => X64TargetProspectiveLabelDisposition::Live,
        RawProspectiveLabelDisposition::ReachabilityTombstone => {
            X64TargetProspectiveLabelDisposition::UnreachableTombstone
        }
        RawProspectiveLabelDisposition::UniqueChainTombstone => {
            X64TargetProspectiveLabelDisposition::Policy14ConsumedTombstone
        }
        RawProspectiveLabelDisposition::SharedJoinTombstone => {
            X64TargetProspectiveLabelDisposition::SharedJoinConsumedTombstone
        }
    }
}

fn candidate_put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn candidate_put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::{
        CoreVmGateAWorkload, COREVM0_GATE_A_CALL_DEPTH_LIMIT, COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
    };
    use crate::core::x64_native_lighthouse::{
        x64_native_lighthouse_case, X64NativeLighthousePackage,
    };

    fn fixture() -> (
        X64NativeLighthousePackage,
        X64TargetExecutionProfile,
        SemanticHash,
    ) {
        let case = x64_native_lighthouse_case(0).expect("canonical case");
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix package");
        let arguments = package.case_arguments(&case).expect("typed arguments");
        let profiled = profile_source_bound_x64_target_plan(
            package.source_bound().expect("source-bound target"),
            arguments,
            EvaluationBudget::new(
                COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
                COREVM0_GATE_A_CALL_DEPTH_LIMIT,
            ),
        )
        .expect("profile");
        (package, profiled.profile, SemanticHash([0x51; 32]))
    }

    #[test]
    fn candidate_capsule_is_sealed_replayable_and_non_executable() {
        let (package, profile, evidence_root) = fixture();
        let baseline = package.source_bound().expect("source-bound target");
        let capsule =
            build_x64_target_policy15_candidate_capsule(baseline, &profile, evidence_root)
                .expect("candidate capsule");
        let verified = verify_x64_target_policy15_candidate_capsule(
            &capsule,
            baseline,
            &profile,
            evidence_root,
        )
        .expect("candidate replay");

        assert_eq!(verified.candidate(), &capsule);
        assert_eq!(capsule.candidate.program.encoder_policy_version, (1, 5, 0));
        assert_eq!(capsule.candidate.program.code.len(), 3_214);
        assert_eq!(package.target().program.code.len(), 3_097);
        assert_eq!(package.target().program.encoder_policy_version, (1, 4, 0));
        assert_eq!(
            capsule.candidate.program.functions,
            package.target().program.functions
        );
        assert_eq!(capsule.candidate.program.abi, package.target().program.abi);
        assert_eq!(
            capsule.candidate.program.frame,
            package.target().program.frame
        );
        assert_eq!(
            capsule.candidate.program.source_machine_ir_hash,
            package.target().program.source_machine_ir_hash
        );
        assert_eq!(
            capsule.baseline_target_semantic_hash,
            package.target().semantic_hash
        );
        assert_eq!(
            capsule.prospective_candidate_code_hash,
            profile
                .prospective_shared_join_realization
                .candidate_code_hash
        );
        assert!(matches!(
            verify_x64_target_r1_s7a(&capsule.candidate),
            Err(X64TargetVerificationErrors(_))
        ));
    }

    #[test]
    fn candidate_capsule_rejects_resealed_identity_and_payload_mutations() {
        let (package, profile, evidence_root) = fixture();
        let baseline = package.source_bound().expect("source-bound target");
        let capsule =
            build_x64_target_policy15_candidate_capsule(baseline, &profile, evidence_root)
                .expect("candidate capsule");

        let mut wrong_root = capsule.clone();
        wrong_root.profile_evidence_root = SemanticHash([0x52; 32]);
        wrong_root.capsule_hash =
            x64_target_policy15_candidate_capsule_hash(&wrong_root).expect("reseal");
        assert!(matches!(
            verify_x64_target_policy15_candidate_capsule(
                &wrong_root,
                baseline,
                &profile,
                evidence_root,
            ),
            Err(X64TargetPolicy15CandidateError::ReplayMismatch)
        ));

        let mut wrong_byte = capsule.clone();
        wrong_byte.candidate.program.code[0] ^= 1;
        wrong_byte.candidate.program.code_hash =
            x64_target_code_hash(&wrong_byte.candidate.program.code).expect("code hash");
        wrong_byte.candidate.semantic_hash =
            x64_target_semantic_hash(&wrong_byte.candidate.program).expect("semantic hash");
        wrong_byte.capsule_hash =
            x64_target_policy15_candidate_capsule_hash(&wrong_byte).expect("reseal");
        assert!(matches!(
            verify_x64_target_policy15_candidate_capsule(
                &wrong_byte,
                baseline,
                &profile,
                evidence_root,
            ),
            Err(X64TargetPolicy15CandidateError::ReplayMismatch)
        ));

        let mut wrong_label = capsule.clone();
        wrong_label.candidate.program.labels[1].code_offset += 1;
        wrong_label.candidate.program.plan_hash =
            x64_target_plan_hash(&wrong_label.candidate.program).expect("plan hash");
        wrong_label.candidate.semantic_hash =
            x64_target_semantic_hash(&wrong_label.candidate.program).expect("semantic hash");
        wrong_label.capsule_hash =
            x64_target_policy15_candidate_capsule_hash(&wrong_label).expect("reseal");
        assert!(matches!(
            verify_x64_target_policy15_candidate_capsule(
                &wrong_label,
                baseline,
                &profile,
                evidence_root,
            ),
            Err(X64TargetPolicy15CandidateError::ReplayMismatch)
        ));

        let mut wrong_fixup = capsule.clone();
        wrong_fixup.candidate.program.fixups[0].addend -= 1;
        wrong_fixup.candidate.semantic_hash =
            x64_target_semantic_hash(&wrong_fixup.candidate.program).expect("semantic hash");
        wrong_fixup.capsule_hash =
            x64_target_policy15_candidate_capsule_hash(&wrong_fixup).expect("reseal");
        assert!(matches!(
            verify_x64_target_policy15_candidate_capsule(
                &wrong_fixup,
                baseline,
                &profile,
                evidence_root,
            ),
            Err(X64TargetPolicy15CandidateError::ReplayMismatch)
        ));

        let mut resealed_evidence = profile.clone();
        resealed_evidence.prospective_shared_join_realization.labels[0].owning_atom += 1;
        resealed_evidence
            .prospective_shared_join_realization
            .realization_hash = x64_target_prospective_shared_join_realization_hash(
            &resealed_evidence.prospective_shared_join_realization,
        )
        .expect("realization reseal");
        assert!(matches!(
            build_x64_target_policy15_candidate_capsule(
                baseline,
                &resealed_evidence,
                evidence_root,
            ),
            Err(X64TargetPolicy15CandidateError::InvalidEvidence {
                field: "prospective label receipt"
            })
        ));

        let mut incomplete = profile.clone();
        incomplete
            .prospective_shared_join_realization
            .machine_semantic_proof
            .complete = false;
        assert!(matches!(
            build_x64_target_policy15_candidate_capsule(baseline, &incomplete, evidence_root),
            Err(X64TargetPolicy15CandidateError::InvalidEvidence {
                field: "prospective semantic proof"
            })
        ));

        assert!(matches!(
            build_x64_target_policy15_candidate_capsule(baseline, &profile, SemanticHash::ZERO,),
            Err(X64TargetPolicy15CandidateError::InvalidEvidence {
                field: "profile evidence root"
            })
        ));

        let bounds = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)
            .expect("Bounds package");
        assert!(matches!(
            verify_x64_target_policy15_candidate_capsule(
                &capsule,
                bounds.source_bound().expect("source-bound Bounds target"),
                &profile,
                evidence_root,
            ),
            Err(X64TargetPolicy15CandidateError::InvalidEvidence {
                field: "profile envelope"
            })
        ));
    }
}
