//! Candidate-specific ADR-0054 standalone authority.
//!
//! This type cannot be converted into the ordinary R1-S8 authority or a
//! source-bound policy-1.4 target.  It binds the exact accepted ADR-0052 and
//! ADR-0053 witnesses to one closed profile selection and regenerates every
//! selected target fact internally.

use super::corevm0_gate_a::{
    corevm0_gate_a_manifest, CoreVmGateAError, CoreVmGateAWorkload, COREVM0_GATE_A_BOUNDS_CASES,
    COREVM0_GATE_A_TOTAL_CASES,
};
use super::schema::SemanticHash;
use super::x64_gate_b_candidate_admission::{
    x64_gate_b_policy15_candidate_accepted_correctness_results_hash,
    VerifiedX64GateBPolicy15CandidateCorrectness, X64GateBPolicy15CandidateSelection,
};
use super::x64_gate_b_candidate_process::{
    verify_x64_gate_b_policy15_candidate_process_evidence,
    x64_gate_b_policy15_candidate_accepted_process_results_hash,
    VerifiedX64GateBPolicy15CandidateProcess, X64GateBPolicy15CandidateProcessError,
};
use super::x64_native::{x64_native_canonical_abi_hash, X64NativeEvidenceError};
use super::x64_native_lighthouse::{X64NativeLighthouseError, X64NativeLighthousePackage};
use super::x64_standalone_authority::X64StandaloneAuthorityBinding;
use super::x64_standalone_protocol::X64StandaloneProfile;
use super::x64_target::{
    reconstruct_frozen_x64_target_policy15_candidate_for_standalone,
    x64_target_policy15_accepted_candidate_capsule_hash,
    StandaloneReconstructedX64TargetPolicy15Candidate, X64TargetAbi, X64TargetArtifact,
    X64TargetPolicy15CandidateError, X64_TARGET_ENCODER_POLICY_VERSION,
    X64_TARGET_POLICY15_ENCODER_POLICY_VERSION,
};
use std::fmt;
use std::sync::OnceLock;

pub const X64_GATE_B_POLICY15_STANDALONE_AUTHORITY_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_STANDALONE_AUTHORITY_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

#[derive(Debug)]
pub enum X64GateBPolicy15StandaloneAuthorityError {
    Corpus(CoreVmGateAError),
    Lighthouse(String),
    Candidate(X64TargetPolicy15CandidateError),
    Process(X64GateBPolicy15CandidateProcessError),
    NativeEvidence(X64NativeEvidenceError),
    InvalidField { field: &'static str },
    MetricOverflow { field: &'static str },
}

impl fmt::Display for X64GateBPolicy15StandaloneAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(error) => write!(formatter, "candidate standalone corpus failed: {error}"),
            Self::Lighthouse(error) => write!(
                formatter,
                "candidate standalone source replay failed: {error}"
            ),
            Self::Candidate(error) => write!(
                formatter,
                "candidate standalone reconstruction failed: {error}"
            ),
            Self::Process(error) => write!(
                formatter,
                "candidate standalone process binding failed: {error}"
            ),
            Self::NativeEvidence(error) => write!(
                formatter,
                "candidate standalone ABI binding failed: {error}"
            ),
            Self::InvalidField { field } => write!(
                formatter,
                "candidate standalone authority has invalid {field}"
            ),
            Self::MetricOverflow { field } => write!(
                formatter,
                "candidate standalone authority {field} overflowed"
            ),
        }
    }
}

impl std::error::Error for X64GateBPolicy15StandaloneAuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Corpus(error) => Some(error),
            Self::Candidate(error) => Some(error),
            Self::Process(error) => Some(error),
            Self::NativeEvidence(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreVmGateAError> for X64GateBPolicy15StandaloneAuthorityError {
    fn from(value: CoreVmGateAError) -> Self {
        Self::Corpus(value)
    }
}

impl From<X64NativeLighthouseError> for X64GateBPolicy15StandaloneAuthorityError {
    fn from(value: X64NativeLighthouseError) -> Self {
        Self::Lighthouse(value.to_string())
    }
}

impl From<X64TargetPolicy15CandidateError> for X64GateBPolicy15StandaloneAuthorityError {
    fn from(value: X64TargetPolicy15CandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl From<X64GateBPolicy15CandidateProcessError> for X64GateBPolicy15StandaloneAuthorityError {
    fn from(value: X64GateBPolicy15CandidateProcessError) -> Self {
        Self::Process(value)
    }
}

impl From<X64NativeEvidenceError> for X64GateBPolicy15StandaloneAuthorityError {
    fn from(value: X64NativeEvidenceError) -> Self {
        Self::NativeEvidence(value)
    }
}

/// Opaque profile-specific authority rooted in both accepted candidate gates.
pub struct X64GateBPolicy15StandaloneAuthority<'correctness, 'process> {
    profile: X64StandaloneProfile,
    selection: X64GateBPolicy15CandidateSelection,
    package: X64NativeLighthousePackage,
    candidate: StandaloneReconstructedX64TargetPolicy15Candidate,
    correctness: VerifiedX64GateBPolicy15CandidateCorrectness<'correctness>,
    process: VerifiedX64GateBPolicy15CandidateProcess<'process>,
    binding: X64StandaloneAuthorityBinding,
    revalidation: OnceLock<()>,
}

impl fmt::Debug for X64GateBPolicy15StandaloneAuthority<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X64GateBPolicy15StandaloneAuthority")
            .field("profile", &self.profile)
            .field("selection", &self.selection)
            .field("candidate_capsule_hash", &self.candidate_capsule_hash())
            .field("correctness_results_hash", &self.correctness_results_hash())
            .field("process_results_hash", &self.process_results_hash())
            .field("target_artifact_hash", &self.target_artifact_hash())
            .finish()
    }
}

impl X64GateBPolicy15StandaloneAuthority<'_, '_> {
    pub const fn profile(&self) -> X64StandaloneProfile {
        self.profile
    }

    pub const fn selection(&self) -> X64GateBPolicy15CandidateSelection {
        self.selection
    }

    pub const fn manifest_hash(&self) -> SemanticHash {
        self.binding.manifest_hash
    }

    pub const fn candidate_capsule_hash(&self) -> SemanticHash {
        self.candidate.candidate().capsule_hash()
    }

    pub const fn correctness_results_hash(&self) -> SemanticHash {
        self.binding.semantic_results_hash
    }

    pub const fn process_results_hash(&self) -> SemanticHash {
        self.binding.process_results_hash
    }

    pub const fn source_core_hash(&self) -> SemanticHash {
        self.binding.source_core_hash
    }

    pub const fn source_ssa_hash(&self) -> SemanticHash {
        self.binding.source_ssa_hash
    }

    pub const fn source_machine_ir_hash(&self) -> SemanticHash {
        self.binding.source_machine_ir_hash
    }

    pub const fn target_artifact_hash(&self) -> SemanticHash {
        self.binding.target_artifact_hash
    }

    pub const fn target_plan_hash(&self) -> SemanticHash {
        self.binding.target_plan_hash
    }

    pub const fn target_code_hash(&self) -> SemanticHash {
        self.binding.target_code_hash
    }

    pub const fn canonical_abi_hash(&self) -> SemanticHash {
        self.binding.canonical_abi_hash
    }

    pub const fn entry_offset(&self) -> u32 {
        self.binding.entry_offset
    }

    pub const fn input_lanes(&self) -> u8 {
        self.binding.input_lanes
    }

    pub const fn canonical_case_count(&self) -> u32 {
        self.binding.canonical_case_count
    }

    pub(super) const fn binding(&self) -> X64StandaloneAuthorityBinding {
        self.binding
    }

    pub(super) fn target(&self) -> &X64TargetArtifact {
        match self.profile {
            X64StandaloneProfile::BranchMix => self.candidate.candidate().candidate_artifact(),
            X64StandaloneProfile::Bounds => self.package.target(),
        }
    }

    pub(super) fn target_bytes(&self) -> &[u8] {
        &self.target().program.code
    }

    pub(super) const fn correctness(&self) -> VerifiedX64GateBPolicy15CandidateCorrectness<'_> {
        self.correctness
    }

    pub(super) const fn process(&self) -> VerifiedX64GateBPolicy15CandidateProcess<'_> {
        self.process
    }

    /// Rebind the stored process evidence to the stored correctness witness
    /// and independently reconstruct the selected target once per authority.
    pub(super) fn revalidate_complete(
        &self,
    ) -> Result<(), X64GateBPolicy15StandaloneAuthorityError> {
        if self.revalidation.get().is_some() {
            return Ok(());
        }
        verify_x64_gate_b_policy15_candidate_process_evidence(
            self.correctness,
            self.process.evidence(),
        )?;
        let source = self.package.source_bound()?;
        let replayed_target = match self.profile {
            X64StandaloneProfile::BranchMix => {
                reconstruct_frozen_x64_target_policy15_candidate_for_standalone(source)?
                    .candidate()
                    .candidate_artifact()
                    .clone()
            }
            X64StandaloneProfile::Bounds => source.artifact().clone(),
        };
        if replayed_target != *self.target() {
            return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
                field: "revalidated selected target",
            });
        }
        let _ = self.revalidation.set(());
        Ok(())
    }
}

/// Bind one closed profile to the exact verified ADR-0052/0053 chain.
pub fn authorize_x64_gate_b_policy15_standalone<'correctness, 'process>(
    correctness: VerifiedX64GateBPolicy15CandidateCorrectness<'correctness>,
    process: VerifiedX64GateBPolicy15CandidateProcess<'process>,
    profile: X64StandaloneProfile,
) -> Result<
    X64GateBPolicy15StandaloneAuthority<'correctness, 'process>,
    X64GateBPolicy15StandaloneAuthorityError,
> {
    let correctness_evidence = correctness.evidence();
    let process_evidence = process.evidence();
    verify_x64_gate_b_policy15_candidate_process_evidence(correctness, process_evidence)?;
    if correctness_evidence.results_hash()
        != x64_gate_b_policy15_candidate_accepted_correctness_results_hash()
        || process_evidence.results_hash()
            != x64_gate_b_policy15_candidate_accepted_process_results_hash()
        || correctness_evidence.candidate_capsule_hash()
            != x64_target_policy15_accepted_candidate_capsule_hash()
        || process_evidence.candidate_capsule_hash()
            != x64_target_policy15_accepted_candidate_capsule_hash()
        || process_evidence.correctness_results_hash() != correctness_evidence.results_hash()
    {
        return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
            field: "accepted upstream root vector",
        });
    }

    let manifest = corevm0_gate_a_manifest()?;
    if manifest.total_cases != COREVM0_GATE_A_TOTAL_CASES
        || manifest.cases.len() != COREVM0_GATE_A_TOTAL_CASES as usize
        || correctness_evidence.records().len() != manifest.cases.len()
        || process_evidence.receipts().len() != manifest.cases.len()
        || correctness_evidence.corpus_manifest_hash() != manifest.manifest_hash
        || process_evidence.corpus_manifest_hash() != manifest.manifest_hash
    {
        return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
            field: "canonical corpus envelope",
        });
    }

    let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let candidate =
        reconstruct_frozen_x64_target_policy15_candidate_for_standalone(branch.source_bound()?)?;
    if candidate.candidate().capsule_hash() != correctness_evidence.candidate_capsule_hash() {
        return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
            field: "reconstructed candidate capsule",
        });
    }
    let package = match profile {
        X64StandaloneProfile::BranchMix => branch,
        X64StandaloneProfile::Bounds => {
            X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?
        }
    };
    let selection = match profile {
        X64StandaloneProfile::BranchMix => X64GateBPolicy15CandidateSelection::Policy15Candidate,
        X64StandaloneProfile::Bounds => X64GateBPolicy15CandidateSelection::Policy14Fallback,
    };
    let selected_target = match profile {
        X64StandaloneProfile::BranchMix => candidate.candidate().candidate_artifact(),
        X64StandaloneProfile::Bounds => package.target(),
    };
    let source = package.source_bound()?;
    let source_program = source.program();
    if selected_target.program.source_core_hash != source_program.source_core_hash
        || selected_target.program.source_ssa_hash != source_program.source_ssa_hash
        || selected_target.program.source_machine_ir_hash != source_program.source_machine_ir_hash
        || selected_target.program.abi != X64TargetAbi::r1_s7a()
        || selected_target.program.abi != source_program.abi
        || selected_target.program.entry_offset != source_program.entry_offset
        || selected_target.program.entry_abi != source_program.entry_abi
        || selected_target.program.entry_offset != 0
    {
        return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
            field: "selected target source/ABI envelope",
        });
    }
    let expected_policy = match profile {
        X64StandaloneProfile::BranchMix => X64_TARGET_POLICY15_ENCODER_POLICY_VERSION,
        X64StandaloneProfile::Bounds => X64_TARGET_ENCODER_POLICY_VERSION,
    };
    if selected_target.program.encoder_policy_version != expected_policy {
        return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
            field: "selected encoder policy",
        });
    }

    let input_lanes =
        u8::try_from(selected_target.program.entry_abi.input_lanes.len()).map_err(|_| {
            X64GateBPolicy15StandaloneAuthorityError::MetricOverflow {
                field: "input lane count",
            }
        })?;
    let canonical_abi_hash = x64_native_canonical_abi_hash(source)?;
    let workload = match profile {
        X64StandaloneProfile::BranchMix => CoreVmGateAWorkload::BranchMix,
        X64StandaloneProfile::Bounds => CoreVmGateAWorkload::BoundsOrderedArrayGet,
    };
    let mut matching_cases = 0_u32;
    for (index, ((case, record), receipt)) in manifest
        .cases
        .iter()
        .zip(correctness_evidence.records())
        .zip(process_evidence.receipts())
        .enumerate()
    {
        let ordinal = u32::try_from(index).map_err(|_| {
            X64GateBPolicy15StandaloneAuthorityError::MetricOverflow {
                field: "case ordinal",
            }
        })?;
        if case.ordinal != ordinal
            || record.case_ordinal() != ordinal
            || receipt.case_ordinal() != ordinal
            || record.workload() != case.workload
            || receipt.workload() != case.workload
            || record.input_hash() != case.input_hash
            || receipt.input_hash() != case.input_hash
            || receipt.correctness_record_hash() != record.record_hash()
            || record.candidate_capsule_hash() != correctness_evidence.candidate_capsule_hash()
        {
            return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
                field: "ordered ADR-0052/0053 case binding",
            });
        }
        if case.workload != workload {
            continue;
        }
        matching_cases = matching_cases.checked_add(1).ok_or(
            X64GateBPolicy15StandaloneAuthorityError::MetricOverflow {
                field: "matching case count",
            },
        )?;
        if record.selection() != selection
            || receipt.selection() != selection
            || record.source_machine_ir_hash() != selected_target.program.source_machine_ir_hash
            || record.executed_target_semantic_hash() != selected_target.semantic_hash
            || record.executed_target_plan_hash() != selected_target.program.plan_hash
            || record.executed_target_code_hash() != selected_target.program.code_hash
        {
            return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
                field: "profile selected target evidence",
            });
        }
    }
    let expected_cases = match profile {
        X64StandaloneProfile::BranchMix => COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES,
        X64StandaloneProfile::Bounds => COREVM0_GATE_A_BOUNDS_CASES,
    };
    if matching_cases != expected_cases {
        return Err(X64GateBPolicy15StandaloneAuthorityError::InvalidField {
            field: "profile case count",
        });
    }

    let binding = X64StandaloneAuthorityBinding {
        profile,
        manifest_hash: manifest.manifest_hash,
        source_core_hash: selected_target.program.source_core_hash,
        source_ssa_hash: selected_target.program.source_ssa_hash,
        source_machine_ir_hash: selected_target.program.source_machine_ir_hash,
        target_artifact_hash: selected_target.semantic_hash,
        target_plan_hash: selected_target.program.plan_hash,
        target_code_hash: selected_target.program.code_hash,
        canonical_abi_hash,
        entry_offset: selected_target.program.entry_offset,
        input_lanes,
        semantic_results_hash: correctness_evidence.results_hash(),
        process_results_hash: process_evidence.results_hash(),
        canonical_case_count: matching_cases,
    };
    Ok(X64GateBPolicy15StandaloneAuthority {
        profile,
        selection,
        package,
        candidate,
        correctness,
        process,
        binding,
        revalidation: OnceLock::new(),
    })
}
