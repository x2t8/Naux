//! Opaque R1-S7b-to-R1-S8 standalone seed authority.
//!
//! This boundary never accepts raw target bytes or caller-supplied identity
//! claims. It regenerates one exact lighthouse source chain, independently
//! source-replays its R1-S7a target, and binds that target to every canonical
//! R1-S7b correspondence record for the selected workload.

use super::core_ssa::{
    core_ssa_semantic_bytes, CoreSsaArtifact, SsaTerminator, CORE_SSA_LOWERING_POLICY_VERSION,
    CORE_SSA_MAX_BLOCKS, CORE_SSA_MAX_CFG_DEPTH, CORE_SSA_MAX_DIAGNOSTICS, CORE_SSA_MAX_EDGES,
    CORE_SSA_MAX_ENVIRONMENT_COPY_WORK, CORE_SSA_MAX_FUNCTIONS, CORE_SSA_MAX_INSTRUCTIONS,
    CORE_SSA_MAX_LIVE_VALUE_SLOTS, CORE_SSA_MAX_SEMANTIC_BYTES, CORE_SSA_MAX_VALUES,
    CORE_SSA_SCHEMA_VERSION,
};
use super::corevm0_gate_a::{
    corevm0_gate_a_evidence_hash, corevm0_gate_a_manifest, CoreVmGateAAssurance,
    CoreVmGateACorpusManifest, CoreVmGateAError, CoreVmGateAExecutionBudget, CoreVmGateAUsage,
    CoreVmGateAWorkload, COREVM0_GATE_A_BOUNDS_CASES, COREVM0_GATE_A_MAX_EFFECTS_PER_ENGINE,
    COREVM0_GATE_A_TOTAL_CASES,
};
use super::corevm0_r1_s4::{
    corevm0_r1_s4_evidence_hash, COREVM0_R1_S4_BINDING_VERSION, COREVM0_R1_S4_ERASURE_VERSION,
    COREVM0_R1_S4_EVIDENCE_VERSION, COREVM0_R1_S4_REPLAY_VERSION,
};
use super::machine_ir::{
    machine_ir_semantic_bytes, MachineInstructionKind, MachineIrArtifact, MachineIrLimits,
    MachineTerminator, MACHINE_IR_LOWERING_POLICY_VERSION, MACHINE_IR_SCHEMA_VERSION,
};
use super::polyvariant_r1_s4::{
    PolyvariantR1S4Budget, PolyvariantR1S4Usage, POLYVARIANT_R1_S4_VERSION,
    R1_S4_MAX_CONTROL_SPLITS_HARD_CAP, R1_S4_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
    R1_S4_MAX_HELPER_DEPTH, R1_S4_MAX_HELPER_UNFOLDS_HARD_CAP,
    R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP, R1_S4_MAX_RESIDUAL_BYTES_HARD_CAP,
    R1_S4_MAX_RESIDUAL_NODES_HARD_CAP, R1_S4_MAX_VARIANTS_HARD_CAP, R1_S4_MAX_WORK_UNITS_HARD_CAP,
};
use super::schema::SemanticHash;
use super::translation_correspondence::{
    R1S5CoreSsaCorrespondenceEvidence, R1S6MachineIrCorrespondenceEvidence,
    TranslationCorrespondenceLimits, R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION,
    R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION, R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION,
    R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION,
};
use super::x64_native::{
    x64_native_canonical_abi_hash, X64NativeEvidenceError, X64NativeLimits, X64NativeMappingState,
    X64_NATIVE_ENTRY_POLICY_VERSION, X64_NATIVE_EVIDENCE_SCHEMA_VERSION,
    X64_NATIVE_MAX_DIAGNOSTICS, X64_NATIVE_MAX_RECORD_BYTES, X64_NATIVE_RUNNER_POLICY_VERSION,
    X64_NATIVE_RUNNER_SCHEMA_VERSION, X64_NATIVE_SYSCALL_POLICY_VERSION,
};
use super::x64_native_ipc::{X64_NATIVE_IPC_SCHEMA_VERSION, X64_NATIVE_PROCESS_POLICY_VERSION};
use super::x64_native_lighthouse::{X64NativeLighthouseError, X64NativeLighthousePackage};
use super::x64_native_process::{
    verify_x64_native_process_evidence_r1_s7bc, VerifiedX64NativeProcessEvidence,
    X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES, X64_NATIVE_PROCESS_SCHEMA_VERSION,
    X64_NATIVE_PROCESS_TIMEOUT_MILLIS,
};
use super::x64_standalone_protocol::X64StandaloneProfile;
use super::x64_target::{
    x64_target_plan_bytes, x64_target_semantic_bytes, SourceBoundX64TargetArtifact,
    X64InstructionKind, X64TargetArtifact, X64TargetLimits, X64Terminator,
    X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION, X64_TARGET_ENCODER_POLICY_VERSION,
    X64_TARGET_LOWERING_POLICY_VERSION, X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE,
    X64_TARGET_MAX_CORRESPONDENCE_RECORDS, X64_TARGET_SCHEMA_VERSION,
};
use std::fmt;
use std::sync::OnceLock;

/// One hash-bearing field in the finite native target binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneAuthorityHashField {
    SourceMachineIr,
    TargetArtifact,
    TargetPlan,
    TargetCode,
    CanonicalAbi,
}

impl X64StandaloneAuthorityHashField {
    const fn description(self) -> &'static str {
        match self {
            Self::SourceMachineIr => "source Machine IR",
            Self::TargetArtifact => "target artifact",
            Self::TargetPlan => "target plan",
            Self::TargetCode => "target code",
            Self::CanonicalAbi => "canonical ABI",
        }
    }
}

/// Fail-closed rejection while forming standalone seed authority.
#[derive(Debug)]
pub enum X64StandaloneAuthorityError {
    Manifest(CoreVmGateAError),
    Regeneration {
        profile: X64StandaloneProfile,
        message: String,
    },
    ManifestShape {
        expected: u32,
        declared: u32,
        actual: usize,
    },
    ProcessManifestMismatch {
        expected: SemanticHash,
        actual: SemanticHash,
    },
    CorrespondenceManifestMismatch {
        expected: SemanticHash,
        actual: SemanticHash,
    },
    EvidenceRecordCount {
        expected: usize,
        actual: usize,
    },
    NonCanonicalOrdinal {
        expected: u32,
        manifest: u32,
        evidence: u32,
    },
    InputHashMismatch {
        case_ordinal: u32,
        expected: SemanticHash,
        actual: SemanticHash,
    },
    HashMismatch {
        profile: X64StandaloneProfile,
        case_ordinal: u32,
        field: X64StandaloneAuthorityHashField,
        expected: SemanticHash,
        actual: SemanticHash,
    },
    EntryOffsetMismatch {
        profile: X64StandaloneProfile,
        case_ordinal: u32,
        expected: u32,
        actual: u32,
    },
    InputLaneCountOverflow {
        actual: usize,
    },
    InputLaneCountMismatch {
        profile: X64StandaloneProfile,
        case_ordinal: u32,
        expected: u8,
        actual: u8,
    },
    WorkloadCaseCount {
        profile: X64StandaloneProfile,
        expected: u32,
        actual: u32,
    },
    InheritedEnvelopeMismatch {
        stage: &'static str,
        field: &'static str,
    },
    MetricOverflow {
        field: &'static str,
    },
    NativeEvidence(X64NativeEvidenceError),
}

impl fmt::Display for X64StandaloneAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(formatter, "cannot regenerate Gate A manifest: {error}"),
            Self::Regeneration { profile, message } => {
                write!(formatter, "cannot regenerate {profile:?} standalone seed: {message}")
            }
            Self::ManifestShape {
                expected,
                declared,
                actual,
            } => write!(
                formatter,
                "standalone authority requires {expected} canonical cases; \
                 manifest declares {declared} and contains {actual}"
            ),
            Self::ProcessManifestMismatch { expected, actual } => write!(
                formatter,
                "R1-S7b process manifest {actual} differs from regenerated manifest {expected}"
            ),
            Self::CorrespondenceManifestMismatch { expected, actual } => write!(
                formatter,
                "R1-S7b correspondence manifest {actual} differs from regenerated manifest {expected}"
            ),
            Self::EvidenceRecordCount { expected, actual } => write!(
                formatter,
                "standalone authority requires {expected} ordered correspondence records; found {actual}"
            ),
            Self::NonCanonicalOrdinal {
                expected,
                manifest,
                evidence,
            } => write!(
                formatter,
                "standalone authority expected case {expected}; \
                 manifest contains {manifest} and evidence contains {evidence}"
            ),
            Self::InputHashMismatch {
                case_ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "standalone authority case {case_ordinal} input hash {actual} \
                 differs from canonical hash {expected}"
            ),
            Self::HashMismatch {
                profile,
                case_ordinal,
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "standalone {profile:?} case {case_ordinal} {} hash {actual} \
                 differs from regenerated hash {expected}",
                field.description()
            ),
            Self::EntryOffsetMismatch {
                profile,
                case_ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "standalone {profile:?} case {case_ordinal} entry offset {actual} \
                 differs from regenerated offset {expected}"
            ),
            Self::InputLaneCountOverflow { actual } => write!(
                formatter,
                "standalone target input lane count {actual} does not fit the frozen u8 identity"
            ),
            Self::InputLaneCountMismatch {
                profile,
                case_ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "standalone {profile:?} case {case_ordinal} input lane count {actual} \
                 differs from regenerated count {expected}"
            ),
            Self::WorkloadCaseCount {
                profile,
                expected,
                actual,
            } => write!(
                formatter,
                "standalone {profile:?} authority requires {expected} canonical cases; found {actual}"
            ),
            Self::InheritedEnvelopeMismatch { stage, field } => write!(
                formatter,
                "standalone authority rejected noncanonical inherited {stage} {field}"
            ),
            Self::MetricOverflow { field } => {
                write!(formatter, "standalone authority {field} does not fit its frozen width")
            }
            Self::NativeEvidence(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for X64StandaloneAuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            Self::NativeEvidence(error) => Some(error),
            _ => None,
        }
    }
}

impl From<X64NativeEvidenceError> for X64StandaloneAuthorityError {
    fn from(error: X64NativeEvidenceError) -> Self {
        Self::NativeEvidence(error)
    }
}

/// Exact immutable identities carried across the R1-S7b/R1-S8 boundary.
///
/// This snapshot is crate-private and can only be obtained from an opaque
/// authority. It is encoded into downstream plans and artifacts, but it is
/// never accepted as a substitute for the live authority that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneAuthorityBinding {
    pub(super) profile: X64StandaloneProfile,
    pub(super) manifest_hash: SemanticHash,
    pub(super) source_core_hash: SemanticHash,
    pub(super) source_ssa_hash: SemanticHash,
    pub(super) source_machine_ir_hash: SemanticHash,
    pub(super) target_artifact_hash: SemanticHash,
    pub(super) target_plan_hash: SemanticHash,
    pub(super) target_code_hash: SemanticHash,
    pub(super) canonical_abi_hash: SemanticHash,
    pub(super) entry_offset: u32,
    pub(super) input_lanes: u8,
    pub(super) semantic_results_hash: SemanticHash,
    pub(super) process_results_hash: SemanticHash,
    pub(super) canonical_case_count: u32,
}

/// Complete sealed R1-S4 identity, hard-limit budget, and exact usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedR1S4 {
    pub(super) evidence_schema_version: (u16, u16, u16),
    pub(super) replay_version: (u16, u16, u16),
    pub(super) binding_version: (u16, u16, u16),
    pub(super) construction_version: (u16, u16, u16),
    pub(super) specialization_policy_version: (u16, u16, u16),
    pub(super) erasure_version: (u16, u16, u16),
    pub(super) core_interpreter_semantics_hash: SemanticHash,
    pub(super) definitional_artifact_hash: SemanticHash,
    pub(super) source_program_hash: SemanticHash,
    pub(super) source_program_image_hash: SemanticHash,
    pub(super) binding_time_request_hash: SemanticHash,
    pub(super) binding_time_certificate_hash: SemanticHash,
    pub(super) specialization_request_hash: SemanticHash,
    pub(super) specialization_policy_hash: SemanticHash,
    pub(super) specialization_stage_request_hash: SemanticHash,
    pub(super) control_hash: SemanticHash,
    pub(super) static_table_hash: SemanticHash,
    pub(super) summary_table_hash: SemanticHash,
    pub(super) variant_table_hash: SemanticHash,
    pub(super) residual_hash: SemanticHash,
    pub(super) binding_hash: SemanticHash,
    pub(super) erasure_hash: SemanticHash,
    pub(super) evidence_hash: SemanticHash,
    pub(super) hard_budget: PolyvariantR1S4Budget,
    pub(super) max_helper_depth: u32,
    pub(super) usage: PolyvariantR1S4Usage,
    pub(super) residual_nodes: u64,
    pub(super) residual_bytes: u64,
    pub(super) residual_functions: u64,
    pub(super) loop_variants: u64,
    pub(super) residual_nodes_scanned: u64,
    pub(super) residual_calls: u64,
    pub(super) residual_tail_calls: u64,
    pub(super) residual_ifs: u64,
}

/// Complete aggregate R1-S5 Gate A identity and sealed resource vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedGateA {
    pub(super) schema_version: (u16, u16, u16),
    pub(super) replay_version: (u16, u16, u16),
    pub(super) numeric_contract_version: (u16, u16, u16),
    pub(super) corpus_version: (u16, u16, u16),
    pub(super) generator_version: (u16, u16, u16),
    pub(super) finite_bounded_validation: bool,
    pub(super) numeric_contract_hash: SemanticHash,
    pub(super) branch_s4_evidence_hash: SemanticHash,
    pub(super) branch_source_program_hash: SemanticHash,
    pub(super) branch_source_program_image_hash: SemanticHash,
    pub(super) branch_definitional_artifact_hash: SemanticHash,
    pub(super) core_interpreter_semantics_hash: SemanticHash,
    pub(super) branch_residual_hash: SemanticHash,
    pub(super) branch_s4_binding_hash: SemanticHash,
    pub(super) branch_s4_erasure_hash: SemanticHash,
    pub(super) bounds_source_program_hash: SemanticHash,
    pub(super) bounds_definitional_artifact_hash: SemanticHash,
    pub(super) bounds_residual_hash: SemanticHash,
    pub(super) bounds_s4_evidence_hash: SemanticHash,
    pub(super) manifest_hash: SemanticHash,
    pub(super) semantic_results_hash: SemanticHash,
    pub(super) telemetry_hash: SemanticHash,
    pub(super) evidence_hash: SemanticHash,
    pub(super) generator_seed: u64,
    pub(super) edge_cases: u32,
    pub(super) exhaustive_cases: u32,
    pub(super) generated_cases: u32,
    pub(super) bounds_cases: u32,
    pub(super) total_cases: u32,
    pub(super) total_array_elements: u64,
    pub(super) max_effects_per_engine: u32,
    pub(super) hard_budget: CoreVmGateAExecutionBudget,
    pub(super) usage: CoreVmGateAUsage,
}

/// Canonical R1-S5 Core SSA hard-limit vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedCoreSsaLimits {
    pub(super) max_functions: u64,
    pub(super) max_blocks: u64,
    pub(super) max_instructions: u64,
    pub(super) max_values: u64,
    pub(super) max_edges: u64,
    pub(super) max_cfg_depth: u32,
    pub(super) max_semantic_bytes: u64,
    pub(super) max_live_value_slots: u64,
    pub(super) max_diagnostics: u32,
    pub(super) max_environment_copy_work: u64,
}

/// Exact structural R1-S5 Core SSA usage of the regenerated workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedCoreSsaUsage {
    pub(super) functions: u64,
    pub(super) blocks: u64,
    pub(super) instructions: u64,
    pub(super) values: u64,
    pub(super) cfg_edges: u64,
    pub(super) semantic_bytes: u64,
}

/// Selected R1-S5 artifact structure plus the sealed aggregate correspondence
/// that transitively binds both BranchMix and Bounds artifacts to all 51
/// canonical cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedCoreSsa {
    pub(super) schema_version: (u16, u16, u16),
    pub(super) lowering_policy_version: (u16, u16, u16),
    pub(super) correspondence_schema_version: (u16, u16, u16),
    pub(super) correspondence_policy_version: (u16, u16, u16),
    pub(super) source_core_hash: SemanticHash,
    pub(super) artifact_hash: SemanticHash,
    pub(super) correspondence_manifest_hash: SemanticHash,
    pub(super) correspondence_results_hash: SemanticHash,
    pub(super) correspondence_limits: TranslationCorrespondenceLimits,
    pub(super) correspondence_records: u32,
    pub(super) limits: X64StandaloneInheritedCoreSsaLimits,
    pub(super) usage: X64StandaloneInheritedCoreSsaUsage,
}

/// Exact structural R1-S6 Machine IR usage of the regenerated workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedMachineIrUsage {
    pub(super) functions: u64,
    pub(super) blocks: u64,
    pub(super) instructions: u64,
    pub(super) registers: u64,
    pub(super) cfg_edges: u64,
    pub(super) operands: u64,
    pub(super) lowering_work: u64,
    pub(super) semantic_bytes: u64,
}

/// Selected R1-S6 artifact structure plus the sealed aggregate correspondence
/// that transitively binds both predecessor SSA artifacts and both Machine IR
/// artifacts to all 51 canonical cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedMachineIr {
    pub(super) schema_version: (u16, u16, u16),
    pub(super) lowering_policy_version: (u16, u16, u16),
    pub(super) correspondence_schema_version: (u16, u16, u16),
    pub(super) correspondence_policy_version: (u16, u16, u16),
    pub(super) source_core_hash: SemanticHash,
    pub(super) source_ssa_hash: SemanticHash,
    pub(super) artifact_hash: SemanticHash,
    pub(super) correspondence_manifest_hash: SemanticHash,
    pub(super) correspondence_results_hash: SemanticHash,
    pub(super) correspondence_limits: TranslationCorrespondenceLimits,
    pub(super) correspondence_records: u32,
    pub(super) limits: MachineIrLimits,
    pub(super) usage: X64StandaloneInheritedMachineIrUsage,
}

/// Exact structural R1-S7a target usage of the regenerated workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedTargetUsage {
    pub(super) source_functions: u64,
    pub(super) source_blocks: u64,
    pub(super) source_instructions: u64,
    pub(super) target_operations: u64,
    pub(super) labels: u64,
    pub(super) fixups: u64,
    pub(super) lowering_work: u64,
    pub(super) plan_bytes: u64,
    pub(super) semantic_bytes: u64,
    pub(super) code_bytes: u64,
    pub(super) frame_bytes: u32,
    pub(super) outgoing_bytes: u32,
    pub(super) input_lanes: u32,
    pub(super) correspondence_records: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedTarget {
    pub(super) schema_version: (u16, u16, u16),
    pub(super) lowering_policy_version: (u16, u16, u16),
    pub(super) encoder_policy_version: (u16, u16, u16),
    pub(super) correspondence_schema_version: (u16, u16, u16),
    pub(super) source_core_hash: SemanticHash,
    pub(super) source_ssa_hash: SemanticHash,
    pub(super) source_machine_ir_hash: SemanticHash,
    pub(super) plan_hash: SemanticHash,
    pub(super) code_hash: SemanticHash,
    pub(super) artifact_hash: SemanticHash,
    pub(super) canonical_abi_hash: SemanticHash,
    pub(super) correspondence_results_hash: SemanticHash,
    pub(super) limits: X64TargetLimits,
    pub(super) max_correspondence_records: u32,
    pub(super) max_correspondence_effects_per_engine: u32,
    pub(super) usage: X64StandaloneInheritedTargetUsage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedProcessLimits {
    pub(super) timeout_millis: u64,
    pub(super) max_diagnostic_bytes: u64,
    pub(super) max_diagnostic_records: u32,
    pub(super) max_record_bytes: u32,
}

/// Exact successful R1-S7b usage admitted by the live process package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedNativeUsage {
    pub(super) correspondence_records: u32,
    pub(super) process_receipts: u32,
    pub(super) selected_profile_records: u32,
    pub(super) selected_profile_code_mappings: u32,
    pub(super) selected_profile_mapped_code_bytes: u64,
    pub(super) selected_profile_borrowed_arrays: u32,
    pub(super) selected_profile_output_words: u32,
    pub(super) selected_profile_mapping_state_events: u32,
    pub(super) selected_profile_machine_ir_effects: u32,
    pub(super) selected_profile_native_effects: u32,
    pub(super) fallback_records: u32,
    pub(super) captured_diagnostic_bytes: u64,
    pub(super) captured_diagnostic_records: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedNative {
    pub(super) evidence_schema_version: (u16, u16, u16),
    pub(super) runner_schema_version: (u16, u16, u16),
    pub(super) runner_policy_version: (u16, u16, u16),
    pub(super) syscall_policy_version: (u16, u16, u16),
    pub(super) entry_policy_version: (u16, u16, u16),
    pub(super) process_schema_version: (u16, u16, u16),
    pub(super) process_policy_version: (u16, u16, u16),
    pub(super) ipc_schema_version: (u16, u16, u16),
    pub(super) manifest_hash: SemanticHash,
    pub(super) semantic_results_hash: SemanticHash,
    pub(super) process_results_hash: SemanticHash,
    pub(super) limits: X64NativeLimits,
    pub(super) process_limits: X64StandaloneInheritedProcessLimits,
    pub(super) usage: X64StandaloneInheritedNativeUsage,
}

/// Complete inherited predecessor envelope retained by the opaque authority.
///
/// Every field is a fixed-width value copied only after live source replay
/// and process-evidence revalidation. There is deliberately no public
/// constructor and no hash-tuple admission path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneInheritedEnvelope {
    pub(super) r1_s4: X64StandaloneInheritedR1S4,
    pub(super) gate_a_r1_s5: X64StandaloneInheritedGateA,
    pub(super) core_ssa_r1_s5: X64StandaloneInheritedCoreSsa,
    pub(super) machine_ir_r1_s6: X64StandaloneInheritedMachineIr,
    pub(super) target_r1_s7a: X64StandaloneInheritedTarget,
    pub(super) native_r1_s7b: X64StandaloneInheritedNative,
    pub(super) structural_erasure: bool,
    pub(super) upstream_interpreter_dependency: bool,
    pub(super) fallback: bool,
}

/// Freshly regenerated authority facts consumed by downstream verifiers.
///
/// The value can only be minted by replaying the raw borrowed R1-S7b evidence
/// and rebuilding the complete source chain. It deliberately carries no
/// package references or target bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RevalidatedX64StandaloneAuthority {
    pub(super) binding: X64StandaloneAuthorityBinding,
    pub(super) inherited: X64StandaloneInheritedEnvelope,
}

/// Exact byte width of the embedded inherited-envelope field.
///
/// This is not a new independently hashed domain. The bytes are embedded in
/// the existing R1-S8 artifact preimage, whose frozen domain supplies the
/// identity boundary.
pub(super) const X64_STANDALONE_INHERITED_ENVELOPE_BYTES: usize = 2_984;

impl X64StandaloneInheritedEnvelope {
    /// Manual canonical big-endian encoding for the R1-S8 artifact preimage.
    ///
    /// Stage tags make the six fixed sub-envelopes explicit. There are no
    /// Rust-layout, serde, debug-text, or platform-width fields. Within stage
    /// tags 3 and 4, both the selected artifact metadata and that stage's
    /// correspondence schema, policy, manifest, aggregate root, fixed limit
    /// vector, and exact record count have an explicit fixed order.
    pub(super) fn canonical_bytes(
        self,
    ) -> Result<[u8; X64_STANDALONE_INHERITED_ENVELOPE_BYTES], X64StandaloneAuthorityError> {
        let mut encoder = InheritedEnvelopeEncoder::new();

        encoder.u8(1);
        let s4 = self.r1_s4;
        for version in [
            s4.evidence_schema_version,
            s4.replay_version,
            s4.binding_version,
            s4.construction_version,
            s4.specialization_policy_version,
            s4.erasure_version,
        ] {
            encoder.version(version);
        }
        for hash in [
            s4.core_interpreter_semantics_hash,
            s4.definitional_artifact_hash,
            s4.source_program_hash,
            s4.source_program_image_hash,
            s4.binding_time_request_hash,
            s4.binding_time_certificate_hash,
            s4.specialization_request_hash,
            s4.specialization_policy_hash,
            s4.specialization_stage_request_hash,
            s4.control_hash,
            s4.static_table_hash,
            s4.summary_table_hash,
            s4.variant_table_hash,
            s4.residual_hash,
            s4.binding_hash,
            s4.erasure_hash,
            s4.evidence_hash,
        ] {
            encoder.hash(hash);
        }
        for value in [
            s4.hard_budget.max_work_units,
            s4.hard_budget.max_partial_value_nodes,
            s4.hard_budget.max_variants,
            s4.hard_budget.max_control_splits,
            s4.hard_budget.max_dynamic_parameters,
            s4.hard_budget.max_helper_unfolds,
            s4.hard_budget.max_residual_nodes,
            s4.hard_budget.max_residual_bytes,
        ] {
            encoder.u64(value);
        }
        encoder.u32(s4.max_helper_depth);
        for value in [
            s4.usage.work_units,
            s4.usage.partial_value_nodes,
            s4.usage.variants,
            s4.usage.control_splits,
            s4.usage.dynamic_parameters,
            s4.usage.helper_unfolds,
            s4.usage.static_interns,
            s4.usage.summary_entries,
            s4.usage.summary_hits,
            s4.usage.widened_values,
            s4.residual_nodes,
            s4.residual_bytes,
            s4.residual_functions,
            s4.loop_variants,
            s4.residual_nodes_scanned,
            s4.residual_calls,
            s4.residual_tail_calls,
            s4.residual_ifs,
        ] {
            encoder.u64(value);
        }

        encoder.u8(2);
        let gate = self.gate_a_r1_s5;
        for version in [
            gate.schema_version,
            gate.replay_version,
            gate.numeric_contract_version,
            gate.corpus_version,
            gate.generator_version,
        ] {
            encoder.version(version);
        }
        encoder.boolean(gate.finite_bounded_validation);
        for hash in [
            gate.numeric_contract_hash,
            gate.branch_s4_evidence_hash,
            gate.branch_source_program_hash,
            gate.branch_source_program_image_hash,
            gate.branch_definitional_artifact_hash,
            gate.core_interpreter_semantics_hash,
            gate.branch_residual_hash,
            gate.branch_s4_binding_hash,
            gate.branch_s4_erasure_hash,
            gate.bounds_source_program_hash,
            gate.bounds_definitional_artifact_hash,
            gate.bounds_residual_hash,
            gate.bounds_s4_evidence_hash,
            gate.manifest_hash,
            gate.semantic_results_hash,
            gate.telemetry_hash,
            gate.evidence_hash,
        ] {
            encoder.hash(hash);
        }
        encoder.u64(gate.generator_seed);
        for value in [
            gate.edge_cases,
            gate.exhaustive_cases,
            gate.generated_cases,
            gate.bounds_cases,
            gate.total_cases,
        ] {
            encoder.u32(value);
        }
        encoder.u64(gate.total_array_elements);
        encoder.u32(gate.max_effects_per_engine);
        let budget = gate.hard_budget;
        encoder.u32(budget.max_cases);
        encoder.u32(budget.max_array_elements_per_case);
        encoder.u64(budget.max_total_array_elements);
        encoder.u64(budget.seed_steps_per_case);
        encoder.u64(budget.definitional_core_steps_per_case);
        encoder.u64(budget.residual_core_steps_per_case);
        encoder.u32(budget.core_call_depth_per_case);
        encoder.u64(budget.max_total_seed_steps);
        encoder.u64(budget.max_total_definitional_core_steps);
        encoder.u64(budget.max_total_residual_core_steps);
        encoder.u64(gate.usage.seed_steps);
        encoder.u64(gate.usage.definitional_core_steps);
        encoder.u64(gate.usage.residual_core_steps);

        encoder.u8(3);
        let ssa = self.core_ssa_r1_s5;
        encoder.version(ssa.schema_version);
        encoder.version(ssa.lowering_policy_version);
        encoder.version(ssa.correspondence_schema_version);
        encoder.version(ssa.correspondence_policy_version);
        encoder.hash(ssa.source_core_hash);
        encoder.hash(ssa.artifact_hash);
        encoder.hash(ssa.correspondence_manifest_hash);
        encoder.hash(ssa.correspondence_results_hash);
        encode_translation_correspondence_limits(&mut encoder, ssa.correspondence_limits);
        encoder.u32(ssa.correspondence_records);
        for value in [
            ssa.limits.max_functions,
            ssa.limits.max_blocks,
            ssa.limits.max_instructions,
            ssa.limits.max_values,
            ssa.limits.max_edges,
        ] {
            encoder.u64(value);
        }
        encoder.u32(ssa.limits.max_cfg_depth);
        encoder.u64(ssa.limits.max_semantic_bytes);
        encoder.u64(ssa.limits.max_live_value_slots);
        encoder.u32(ssa.limits.max_diagnostics);
        encoder.u64(ssa.limits.max_environment_copy_work);
        for value in [
            ssa.usage.functions,
            ssa.usage.blocks,
            ssa.usage.instructions,
            ssa.usage.values,
            ssa.usage.cfg_edges,
            ssa.usage.semantic_bytes,
        ] {
            encoder.u64(value);
        }

        encoder.u8(4);
        let machine = self.machine_ir_r1_s6;
        encoder.version(machine.schema_version);
        encoder.version(machine.lowering_policy_version);
        encoder.version(machine.correspondence_schema_version);
        encoder.version(machine.correspondence_policy_version);
        encoder.hash(machine.source_core_hash);
        encoder.hash(machine.source_ssa_hash);
        encoder.hash(machine.artifact_hash);
        encoder.hash(machine.correspondence_manifest_hash);
        encoder.hash(machine.correspondence_results_hash);
        encode_translation_correspondence_limits(&mut encoder, machine.correspondence_limits);
        encoder.u32(machine.correspondence_records);
        encode_machine_ir_limits(&mut encoder, machine.limits);
        for value in [
            machine.usage.functions,
            machine.usage.blocks,
            machine.usage.instructions,
            machine.usage.registers,
            machine.usage.cfg_edges,
            machine.usage.operands,
            machine.usage.lowering_work,
            machine.usage.semantic_bytes,
        ] {
            encoder.u64(value);
        }

        encoder.u8(5);
        let target = self.target_r1_s7a;
        for version in [
            target.schema_version,
            target.lowering_policy_version,
            target.encoder_policy_version,
            target.correspondence_schema_version,
        ] {
            encoder.version(version);
        }
        for hash in [
            target.source_core_hash,
            target.source_ssa_hash,
            target.source_machine_ir_hash,
            target.plan_hash,
            target.code_hash,
            target.artifact_hash,
            target.canonical_abi_hash,
            target.correspondence_results_hash,
        ] {
            encoder.hash(hash);
        }
        encode_target_limits(&mut encoder, target.limits);
        encoder.u32(target.max_correspondence_records);
        encoder.u32(target.max_correspondence_effects_per_engine);
        for value in [
            target.usage.source_functions,
            target.usage.source_blocks,
            target.usage.source_instructions,
            target.usage.target_operations,
            target.usage.labels,
            target.usage.fixups,
            target.usage.lowering_work,
            target.usage.plan_bytes,
            target.usage.semantic_bytes,
            target.usage.code_bytes,
        ] {
            encoder.u64(value);
        }
        encoder.u32(target.usage.frame_bytes);
        encoder.u32(target.usage.outgoing_bytes);
        encoder.u32(target.usage.input_lanes);
        encoder.u32(target.usage.correspondence_records);

        encoder.u8(6);
        let native = self.native_r1_s7b;
        for version in [
            native.evidence_schema_version,
            native.runner_schema_version,
            native.runner_policy_version,
            native.syscall_policy_version,
            native.entry_policy_version,
            native.process_schema_version,
            native.process_policy_version,
            native.ipc_schema_version,
        ] {
            encoder.version(version);
        }
        encoder.hash(native.manifest_hash);
        encoder.hash(native.semantic_results_hash);
        encoder.hash(native.process_results_hash);
        encode_native_limits(&mut encoder, native.limits);
        encoder.u64(native.process_limits.timeout_millis);
        encoder.u64(native.process_limits.max_diagnostic_bytes);
        encoder.u32(native.process_limits.max_diagnostic_records);
        encoder.u32(native.process_limits.max_record_bytes);
        let usage = native.usage;
        encoder.u32(usage.correspondence_records);
        encoder.u32(usage.process_receipts);
        encoder.u32(usage.selected_profile_records);
        encoder.u32(usage.selected_profile_code_mappings);
        encoder.u64(usage.selected_profile_mapped_code_bytes);
        encoder.u32(usage.selected_profile_borrowed_arrays);
        encoder.u32(usage.selected_profile_output_words);
        encoder.u32(usage.selected_profile_mapping_state_events);
        encoder.u32(usage.selected_profile_machine_ir_effects);
        encoder.u32(usage.selected_profile_native_effects);
        encoder.u32(usage.fallback_records);
        encoder.u64(usage.captured_diagnostic_bytes);
        encoder.u32(usage.captured_diagnostic_records);

        encoder.boolean(self.structural_erasure);
        encoder.boolean(self.upstream_interpreter_dependency);
        encoder.boolean(self.fallback);
        encoder.finish()
    }
}

struct InheritedEnvelopeEncoder {
    bytes: [u8; X64_STANDALONE_INHERITED_ENVELOPE_BYTES],
    cursor: usize,
    overflow: bool,
}

impl InheritedEnvelopeEncoder {
    fn new() -> Self {
        Self {
            bytes: [0; X64_STANDALONE_INHERITED_ENVELOPE_BYTES],
            cursor: 0,
            overflow: false,
        }
    }

    fn bytes(&mut self, value: &[u8]) {
        if self.overflow {
            return;
        }
        let Some(end) = self.cursor.checked_add(value.len()) else {
            self.overflow = true;
            return;
        };
        let Some(destination) = self.bytes.get_mut(self.cursor..end) else {
            self.overflow = true;
            return;
        };
        destination.copy_from_slice(value);
        self.cursor = end;
    }

    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn version(&mut self, version: (u16, u16, u16)) {
        self.u16(version.0);
        self.u16(version.1);
        self.u16(version.2);
    }

    fn hash(&mut self, hash: SemanticHash) {
        self.bytes(&hash.0);
    }

    fn finish(
        self,
    ) -> Result<[u8; X64_STANDALONE_INHERITED_ENVELOPE_BYTES], X64StandaloneAuthorityError> {
        if self.overflow || self.cursor != X64_STANDALONE_INHERITED_ENVELOPE_BYTES {
            return Err(X64StandaloneAuthorityError::InheritedEnvelopeMismatch {
                stage: "R1-S4..R1-S7b",
                field: "canonical envelope byte width",
            });
        }
        Ok(self.bytes)
    }
}

fn encode_translation_correspondence_limits(
    encoder: &mut InheritedEnvelopeEncoder,
    limits: TranslationCorrespondenceLimits,
) {
    encoder.u32(limits.total_cases);
    encoder.u32(limits.branch_cases);
    encoder.u32(limits.bounds_cases);
    encoder.u32(limits.max_array_elements_per_case);
    encoder.u64(limits.max_total_array_elements);
    encoder.u32(limits.max_effects_per_observation);
    encoder.u64(limits.steps_per_case);
    encoder.u32(limits.call_depth);
    encoder.u64(limits.max_total_steps_per_engine);
}

fn encode_machine_ir_limits(encoder: &mut InheritedEnvelopeEncoder, limits: MachineIrLimits) {
    for value in [
        limits.max_functions,
        limits.max_blocks,
        limits.max_instructions,
        limits.max_registers,
        limits.max_edges,
        limits.max_operands,
        limits.max_lowering_work,
        limits.max_semantic_bytes,
        limits.max_live_register_slots,
        limits.max_execution_steps,
    ] {
        encoder.u64(value);
    }
    encoder.u32(limits.max_call_depth);
    encoder.u32(limits.max_cfg_depth);
    encoder.u32(limits.max_diagnostics);
}

fn encode_target_limits(encoder: &mut InheritedEnvelopeEncoder, limits: X64TargetLimits) {
    for value in [
        limits.max_source_functions,
        limits.max_source_blocks,
        limits.max_source_instructions,
        limits.max_ops,
        limits.max_labels,
        limits.max_fixups,
        limits.max_code_bytes,
        limits.max_semantic_bytes,
    ] {
        encoder.u64(value);
    }
    encoder.u32(limits.max_frame_bytes);
    encoder.u32(limits.max_outgoing_bytes);
    encoder.u32(limits.max_entry_input_lanes);
    encoder.u64(limits.max_lowering_work);
    encoder.u64(limits.max_plan_eval_work);
    encoder.u32(limits.max_cfg_depth);
    encoder.u32(limits.max_diagnostics);
}

fn encode_native_limits(encoder: &mut InheritedEnvelopeEncoder, limits: X64NativeLimits) {
    encoder.u32(limits.code_mappings_per_invocation);
    encoder.u64(limits.max_mapping_bytes);
    encoder.u32(limits.max_entry_lanes);
    encoder.u32(limits.max_borrowed_f64_arrays);
    encoder.u32(limits.output_words);
    encoder.u32(limits.mapping_state_events);
    encoder.u32(limits.max_effects_per_engine);
    encoder.u32(limits.max_correspondence_records);
    encoder.u32(limits.fixed_lighthouse_records);
    encoder.u32(limits.max_record_bytes);
    encoder.u32(limits.max_diagnostics);
}

/// Opaque finite native authority admitted as the sole seed for R1-S8.
///
/// This type owns the exact regenerated source chain and keeps the verified
/// process evidence immutably borrowed. It is not standalone correctness,
/// infinite-domain equivalence, Gate B completion, or performance evidence.
pub struct X64StandaloneSeedAuthority<'evidence> {
    profile: X64StandaloneProfile,
    package: X64NativeLighthousePackage,
    _evidence: VerifiedX64NativeProcessEvidence<'evidence>,
    spine: X64StandaloneAuthorityBinding,
    inherited: X64StandaloneInheritedEnvelope,
    revalidation: OnceLock<RevalidatedX64StandaloneAuthority>,
}

impl fmt::Debug for X64StandaloneSeedAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X64StandaloneSeedAuthority")
            .field("profile", &self.profile)
            .field("manifest_hash", &self.spine.manifest_hash)
            .field("source_core_hash", &self.spine.source_core_hash)
            .field("source_ssa_hash", &self.spine.source_ssa_hash)
            .field("source_machine_ir_hash", &self.spine.source_machine_ir_hash)
            .field("target_artifact_hash", &self.spine.target_artifact_hash)
            .field("target_plan_hash", &self.spine.target_plan_hash)
            .field("target_code_hash", &self.spine.target_code_hash)
            .field("canonical_abi_hash", &self.spine.canonical_abi_hash)
            .field("entry_offset", &self.spine.entry_offset)
            .field("input_lanes", &self.spine.input_lanes)
            .field("semantic_results_hash", &self.spine.semantic_results_hash)
            .field("process_results_hash", &self.spine.process_results_hash)
            .field("canonical_case_count", &self.spine.canonical_case_count)
            .field("structural_erasure", &self.inherited.structural_erasure)
            .field(
                "upstream_interpreter_dependency",
                &self.inherited.upstream_interpreter_dependency,
            )
            .field("fallback", &self.inherited.fallback)
            .finish()
    }
}

impl X64StandaloneSeedAuthority<'_> {
    pub const fn profile(&self) -> X64StandaloneProfile {
        self.profile
    }

    pub const fn manifest_hash(&self) -> SemanticHash {
        self.spine.manifest_hash
    }

    pub const fn source_core_hash(&self) -> SemanticHash {
        self.spine.source_core_hash
    }

    pub const fn source_ssa_hash(&self) -> SemanticHash {
        self.spine.source_ssa_hash
    }

    pub const fn source_machine_ir_hash(&self) -> SemanticHash {
        self.spine.source_machine_ir_hash
    }

    pub const fn target_artifact_hash(&self) -> SemanticHash {
        self.spine.target_artifact_hash
    }

    pub const fn target_plan_hash(&self) -> SemanticHash {
        self.spine.target_plan_hash
    }

    pub const fn target_code_hash(&self) -> SemanticHash {
        self.spine.target_code_hash
    }

    pub const fn canonical_abi_hash(&self) -> SemanticHash {
        self.spine.canonical_abi_hash
    }

    pub const fn entry_offset(&self) -> u32 {
        self.spine.entry_offset
    }

    pub const fn input_lanes(&self) -> u8 {
        self.spine.input_lanes
    }

    pub const fn semantic_results_hash(&self) -> SemanticHash {
        self.spine.semantic_results_hash
    }

    pub const fn process_results_hash(&self) -> SemanticHash {
        self.spine.process_results_hash
    }

    pub const fn canonical_case_count(&self) -> u32 {
        self.spine.canonical_case_count
    }

    pub(super) const fn binding(&self) -> X64StandaloneAuthorityBinding {
        self.spine
    }

    pub(super) const fn structural_erasure(&self) -> bool {
        self.inherited.structural_erasure
    }

    pub(super) const fn upstream_interpreter_dependency(&self) -> bool {
        self.inherited.upstream_interpreter_dependency
    }

    pub(super) const fn fallback(&self) -> bool {
        self.inherited.fallback
    }

    /// Rebuild and compare the complete authority exactly once.
    ///
    /// The authority is immutable and lifetime-bound to immutable process
    /// evidence, so a successful replay may be cached. Concurrent first
    /// callers may duplicate the deterministic replay, but only an exactly
    /// matching value is published.
    pub(super) fn revalidate_complete(
        &self,
    ) -> Result<RevalidatedX64StandaloneAuthority, X64StandaloneAuthorityError> {
        if let Some(revalidated) = self.revalidation.get() {
            return Ok(*revalidated);
        }

        let replayed_process = verify_x64_native_process_evidence_r1_s7bc(
            self._evidence.evidence(),
        )
        .map_err(|error| X64StandaloneAuthorityError::Regeneration {
            profile: self.profile,
            message: format!("R1-S7b process replay failed: {error}"),
        })?;
        let replayed = authorize_x64_standalone_seed_r1_s8(replayed_process, self.profile)?;
        if replayed.spine != self.spine {
            return Err(X64StandaloneAuthorityError::InheritedEnvelopeMismatch {
                stage: "R1-S4..R1-S7b",
                field: "regenerated authority binding",
            });
        }
        if replayed.inherited != self.inherited {
            return Err(X64StandaloneAuthorityError::InheritedEnvelopeMismatch {
                stage: "R1-S4..R1-S7b",
                field: "regenerated inherited envelope",
            });
        }
        let revalidated = RevalidatedX64StandaloneAuthority {
            binding: replayed.spine,
            inherited: replayed.inherited,
        };
        let _ = self.revalidation.set(revalidated);
        match self.revalidation.get().copied() {
            Some(published) => Ok(published),
            None => Ok(revalidated),
        }
    }

    pub(super) fn source_bound(
        &self,
    ) -> Result<SourceBoundX64TargetArtifact<'_, '_, '_, '_>, X64StandaloneAuthorityError> {
        self.package
            .source_bound()
            .map_err(|error| regeneration_error(self.profile, error))
    }

    pub(super) fn target_bytes(&self) -> &[u8] {
        &self.package.target().program.code
    }
}

/// Regenerate and bind one exact lighthouse source chain to complete verified
/// R1-S7b process evidence.
pub fn authorize_x64_standalone_seed_r1_s8<'evidence>(
    evidence: VerifiedX64NativeProcessEvidence<'evidence>,
    profile: X64StandaloneProfile,
) -> Result<X64StandaloneSeedAuthority<'evidence>, X64StandaloneAuthorityError> {
    let workload = workload_for_profile(profile);
    let package = X64NativeLighthousePackage::build(workload)
        .map_err(|error| regeneration_error(profile, error))?;
    let target = package
        .source_bound()
        .map_err(|error| regeneration_error(profile, error))?;
    let manifest = corevm0_gate_a_manifest().map_err(X64StandaloneAuthorityError::Manifest)?;

    let expected_total = usize::try_from(COREVM0_GATE_A_TOTAL_CASES).map_err(|_| {
        X64StandaloneAuthorityError::MetricOverflow {
            field: "total case count",
        }
    })?;
    if manifest.total_cases != COREVM0_GATE_A_TOTAL_CASES || manifest.cases.len() != expected_total
    {
        return Err(X64StandaloneAuthorityError::ManifestShape {
            expected: COREVM0_GATE_A_TOTAL_CASES,
            declared: manifest.total_cases,
            actual: manifest.cases.len(),
        });
    }

    let process = evidence.evidence();
    if process.corpus_manifest_hash() != manifest.manifest_hash {
        return Err(X64StandaloneAuthorityError::ProcessManifestMismatch {
            expected: manifest.manifest_hash,
            actual: process.corpus_manifest_hash(),
        });
    }
    let correspondence = process.correspondence();
    if correspondence.corpus_manifest_hash != manifest.manifest_hash {
        return Err(
            X64StandaloneAuthorityError::CorrespondenceManifestMismatch {
                expected: manifest.manifest_hash,
                actual: correspondence.corpus_manifest_hash,
            },
        );
    }
    if correspondence.records.len() != manifest.cases.len() {
        return Err(X64StandaloneAuthorityError::EvidenceRecordCount {
            expected: manifest.cases.len(),
            actual: correspondence.records.len(),
        });
    }

    let source_core_hash = target.source_core().semantic_hash;
    let source_ssa_hash = target.source_ssa().semantic_hash;
    let source_machine_ir_hash = target.source_machine_ir().semantic_hash;
    let target_artifact_hash = target.semantic_hash();
    let target_plan_hash = target.program().plan_hash;
    let target_code_hash = target.code_hash();
    let canonical_abi_hash = x64_native_canonical_abi_hash(target)?;
    let entry_offset = target.program().entry_offset;
    let input_lanes = u8::try_from(target.program().entry_abi.input_lanes.len()).map_err(|_| {
        X64StandaloneAuthorityError::InputLaneCountOverflow {
            actual: target.program().entry_abi.input_lanes.len(),
        }
    })?;

    let mut matching_cases = 0_u32;
    for (position, (case, record)) in manifest
        .cases
        .iter()
        .zip(&correspondence.records)
        .enumerate()
    {
        let expected_ordinal =
            u32::try_from(position).map_err(|_| X64StandaloneAuthorityError::MetricOverflow {
                field: "case ordinal",
            })?;
        if case.ordinal != expected_ordinal || record.case_ordinal != expected_ordinal {
            return Err(X64StandaloneAuthorityError::NonCanonicalOrdinal {
                expected: expected_ordinal,
                manifest: case.ordinal,
                evidence: record.case_ordinal,
            });
        }
        if record.input_hash != case.input_hash {
            return Err(X64StandaloneAuthorityError::InputHashMismatch {
                case_ordinal: expected_ordinal,
                expected: case.input_hash,
                actual: record.input_hash,
            });
        }
        if case.workload != workload {
            continue;
        }

        matching_cases =
            matching_cases
                .checked_add(1)
                .ok_or(X64StandaloneAuthorityError::MetricOverflow {
                    field: "matching case count",
                })?;
        compare_hash(
            profile,
            expected_ordinal,
            X64StandaloneAuthorityHashField::SourceMachineIr,
            source_machine_ir_hash,
            record.source_machine_ir_hash,
        )?;
        compare_hash(
            profile,
            expected_ordinal,
            X64StandaloneAuthorityHashField::TargetArtifact,
            target_artifact_hash,
            record.target_artifact_hash,
        )?;
        compare_hash(
            profile,
            expected_ordinal,
            X64StandaloneAuthorityHashField::TargetPlan,
            target_plan_hash,
            record.native_execution.target_plan_hash,
        )?;
        compare_hash(
            profile,
            expected_ordinal,
            X64StandaloneAuthorityHashField::TargetCode,
            target_code_hash,
            record.target_code_hash,
        )?;
        compare_hash(
            profile,
            expected_ordinal,
            X64StandaloneAuthorityHashField::CanonicalAbi,
            canonical_abi_hash,
            record.native_execution.canonical_abi_hash,
        )?;
        if record.native_execution.entry_offset != entry_offset {
            return Err(X64StandaloneAuthorityError::EntryOffsetMismatch {
                profile,
                case_ordinal: expected_ordinal,
                expected: entry_offset,
                actual: record.native_execution.entry_offset,
            });
        }
        if record.native_execution.input_lanes != input_lanes {
            return Err(X64StandaloneAuthorityError::InputLaneCountMismatch {
                profile,
                case_ordinal: expected_ordinal,
                expected: input_lanes,
                actual: record.native_execution.input_lanes,
            });
        }
    }

    let expected_cases = expected_case_count(profile);
    if matching_cases != expected_cases {
        return Err(X64StandaloneAuthorityError::WorkloadCaseCount {
            profile,
            expected: expected_cases,
            actual: matching_cases,
        });
    }

    let spine = X64StandaloneAuthorityBinding {
        profile,
        manifest_hash: manifest.manifest_hash,
        source_core_hash,
        source_ssa_hash,
        source_machine_ir_hash,
        target_artifact_hash,
        target_plan_hash,
        target_code_hash,
        canonical_abi_hash,
        entry_offset,
        input_lanes,
        semantic_results_hash: evidence.semantic_results_hash(),
        process_results_hash: evidence.process_results_hash(),
        canonical_case_count: matching_cases,
    };
    let inherited = build_inherited_envelope(
        profile,
        &package,
        target,
        evidence,
        &manifest,
        matching_cases,
    )?;
    Ok(X64StandaloneSeedAuthority {
        profile,
        package,
        _evidence: evidence,
        spine,
        inherited,
        revalidation: OnceLock::new(),
    })
}

fn build_inherited_envelope(
    profile: X64StandaloneProfile,
    package: &X64NativeLighthousePackage,
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    evidence: VerifiedX64NativeProcessEvidence<'_>,
    manifest: &CoreVmGateACorpusManifest,
    selected_profile_records: u32,
) -> Result<X64StandaloneInheritedEnvelope, X64StandaloneAuthorityError> {
    let source_core = target.source_core();
    let source_ssa = target.source_ssa();
    let source_machine_ir = target.source_machine_ir();
    let target_program = target.program();

    let s4_evidence = package.s4_evidence();
    require_inherited(
        corevm0_r1_s4_evidence_hash(s4_evidence) == s4_evidence.evidence_hash,
        "R1-S4",
        "evidence seal",
    )?;
    require_inherited(
        s4_evidence.schema_version == COREVM0_R1_S4_EVIDENCE_VERSION
            && s4_evidence.replay_version == COREVM0_R1_S4_REPLAY_VERSION
            && s4_evidence.binding_version == COREVM0_R1_S4_BINDING_VERSION
            && s4_evidence.s4_policy_version == POLYVARIANT_R1_S4_VERSION
            && s4_evidence.erasure_version == COREVM0_R1_S4_ERASURE_VERSION,
        "R1-S4",
        "version vector",
    )?;
    let expected_s4_budget = canonical_s4_lighthouse_budget();
    require_inherited(
        s4_evidence.budget == expected_s4_budget,
        "R1-S4",
        "hard-limit budget",
    )?;
    require_inherited(
        s4_evidence.residual_hash == source_core.semantic_hash
            && s4_evidence.erasure_hash != SemanticHash::ZERO
            && s4_evidence.binding_hash != SemanticHash::ZERO,
        "R1-S4",
        "residual/erasure binding",
    )?;
    let max_helper_depth = u32::try_from(R1_S4_MAX_HELPER_DEPTH).map_err(|_| {
        X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S4 helper depth",
        }
    })?;
    let r1_s4 = X64StandaloneInheritedR1S4 {
        evidence_schema_version: s4_evidence.schema_version,
        replay_version: s4_evidence.replay_version,
        binding_version: s4_evidence.binding_version,
        construction_version: s4_evidence.construction_version,
        specialization_policy_version: s4_evidence.s4_policy_version,
        erasure_version: s4_evidence.erasure_version,
        core_interpreter_semantics_hash: s4_evidence.core_interpreter_semantics_hash,
        definitional_artifact_hash: s4_evidence.artifact_hash,
        source_program_hash: s4_evidence.program_hash,
        source_program_image_hash: s4_evidence.program_image_hash,
        binding_time_request_hash: s4_evidence.binding_time_request_hash,
        binding_time_certificate_hash: s4_evidence.binding_time_certificate_hash,
        specialization_request_hash: s4_evidence.upstream_request_hash,
        specialization_policy_hash: s4_evidence.s4_policy_hash,
        specialization_stage_request_hash: s4_evidence.s4_request_hash,
        control_hash: s4_evidence.control_hash,
        static_table_hash: s4_evidence.static_table_hash,
        summary_table_hash: s4_evidence.summary_table_hash,
        variant_table_hash: s4_evidence.variant_table_hash,
        residual_hash: s4_evidence.residual_hash,
        binding_hash: s4_evidence.binding_hash,
        erasure_hash: s4_evidence.erasure_hash,
        evidence_hash: s4_evidence.evidence_hash,
        hard_budget: s4_evidence.budget,
        max_helper_depth,
        usage: s4_evidence.usage,
        residual_nodes: s4_evidence.residual_nodes,
        residual_bytes: s4_evidence.residual_bytes,
        residual_functions: s4_evidence.residual_functions,
        loop_variants: s4_evidence.loop_variants,
        residual_nodes_scanned: s4_evidence.residual_nodes_scanned,
        residual_calls: s4_evidence.residual_calls,
        residual_tail_calls: s4_evidence.residual_tail_calls,
        residual_ifs: s4_evidence.residual_ifs,
    };

    let gate_a = package
        .regenerate_gate_a_evidence()
        .map_err(|error| regeneration_error(profile, error))?;
    let gate_a_hash = corevm0_gate_a_evidence_hash(&gate_a).map_err(|error| {
        inherited_regeneration_error(profile, "R1-S5 Gate A evidence encoding", error)
    })?;
    require_inherited(
        gate_a_hash == gate_a.evidence_hash
            && gate_a.assurance == CoreVmGateAAssurance::FiniteBoundedValidation
            && gate_a.corpus == *manifest,
        "R1-S5 Gate A",
        "sealed canonical aggregate",
    )?;
    let (selected_gate_residual, selected_gate_s4) = match profile {
        X64StandaloneProfile::BranchMix => (gate_a.residual_hash, gate_a.s4_evidence_hash),
        X64StandaloneProfile::Bounds => {
            (gate_a.bounds_residual_hash, gate_a.bounds_s4_evidence_hash)
        }
    };
    require_inherited(
        selected_gate_residual == source_core.semantic_hash
            && selected_gate_s4 == s4_evidence.evidence_hash
            && gate_a.corpus.manifest_hash == manifest.manifest_hash
            && gate_a.corpus.total_cases == COREVM0_GATE_A_TOTAL_CASES,
        "R1-S5 Gate A",
        "selected workload lineage",
    )?;
    let gate_a_r1_s5 = X64StandaloneInheritedGateA {
        schema_version: gate_a.schema_version,
        replay_version: gate_a.replay_version,
        numeric_contract_version: gate_a.numeric_contract_version,
        corpus_version: gate_a.corpus.corpus_version,
        generator_version: gate_a.corpus.generator_version,
        finite_bounded_validation: true,
        numeric_contract_hash: gate_a.numeric_contract_hash,
        branch_s4_evidence_hash: gate_a.s4_evidence_hash,
        branch_source_program_hash: gate_a.source_program_hash,
        branch_source_program_image_hash: gate_a.source_program_image_hash,
        branch_definitional_artifact_hash: gate_a.definitional_artifact_hash,
        core_interpreter_semantics_hash: gate_a.core_interpreter_semantics_hash,
        branch_residual_hash: gate_a.residual_hash,
        branch_s4_binding_hash: gate_a.s4_binding_hash,
        branch_s4_erasure_hash: gate_a.s4_erasure_hash,
        bounds_source_program_hash: gate_a.bounds_program_hash,
        bounds_definitional_artifact_hash: gate_a.bounds_definitional_artifact_hash,
        bounds_residual_hash: gate_a.bounds_residual_hash,
        bounds_s4_evidence_hash: gate_a.bounds_s4_evidence_hash,
        manifest_hash: gate_a.corpus.manifest_hash,
        semantic_results_hash: gate_a.results_hash,
        telemetry_hash: gate_a.telemetry_hash,
        evidence_hash: gate_a.evidence_hash,
        generator_seed: gate_a.corpus.generator_seed,
        edge_cases: gate_a.corpus.edge_cases,
        exhaustive_cases: gate_a.corpus.exhaustive_cases,
        generated_cases: gate_a.corpus.generated_cases,
        bounds_cases: gate_a.corpus.bounds_cases,
        total_cases: gate_a.corpus.total_cases,
        total_array_elements: gate_a.corpus.total_array_elements,
        max_effects_per_engine: COREVM0_GATE_A_MAX_EFFECTS_PER_ENGINE,
        hard_budget: gate_a.execution_budget,
        usage: gate_a.usage,
    };

    let (core_ssa_correspondence, machine_ir_correspondence) = package
        .regenerate_translation_correspondences()
        .map_err(|error| regeneration_error(profile, error))?;
    let core_ssa_correspondence_records = u32::try_from(core_ssa_correspondence.records.len())
        .map_err(|_| X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S5 Core SSA correspondence record count",
        })?;
    require_inherited(
        core_ssa_correspondence.schema_version == R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION
            && core_ssa_correspondence.policy_version
                == R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION
            && core_ssa_correspondence.limits == TranslationCorrespondenceLimits::r1()
            && core_ssa_correspondence_records == core_ssa_correspondence.limits.total_cases
            && core_ssa_correspondence_records == manifest.total_cases
            && core_ssa_correspondence.manifest_hash == manifest.manifest_hash
            && core_ssa_correspondence.branch_source_core_hash == gate_a.residual_hash
            && core_ssa_correspondence.bounds_source_core_hash == gate_a.bounds_residual_hash,
        "R1-S5 Core SSA correspondence",
        "schema/policy/limits/manifest/source identities",
    )?;
    let (selected_core_correspondence_source, selected_core_correspondence_ssa) = match profile {
        X64StandaloneProfile::BranchMix => (
            core_ssa_correspondence.branch_source_core_hash,
            core_ssa_correspondence.branch_core_ssa_hash,
        ),
        X64StandaloneProfile::Bounds => (
            core_ssa_correspondence.bounds_source_core_hash,
            core_ssa_correspondence.bounds_core_ssa_hash,
        ),
    };
    require_inherited(
        selected_core_correspondence_source == source_core.semantic_hash
            && selected_core_correspondence_ssa == source_ssa.semantic_hash,
        "R1-S5 Core SSA correspondence",
        "selected source/target identities",
    )?;

    let core_ssa_r1_s5 = inherited_core_ssa(profile, source_ssa, &core_ssa_correspondence)?;
    require_inherited(
        core_ssa_r1_s5.source_core_hash == r1_s4.residual_hash,
        "R1-S5 Core SSA",
        "source residual identity",
    )?;

    let machine_ir_correspondence_records = u32::try_from(machine_ir_correspondence.records.len())
        .map_err(|_| X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S6 Machine IR correspondence record count",
        })?;
    require_inherited(
        machine_ir_correspondence.schema_version == R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION
            && machine_ir_correspondence.policy_version
                == R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION
            && machine_ir_correspondence.limits == TranslationCorrespondenceLimits::r1()
            && machine_ir_correspondence_records == machine_ir_correspondence.limits.total_cases
            && machine_ir_correspondence_records == manifest.total_cases
            && machine_ir_correspondence.manifest_hash == manifest.manifest_hash
            && machine_ir_correspondence.branch_source_core_hash
                == core_ssa_correspondence.branch_source_core_hash
            && machine_ir_correspondence.branch_source_core_ssa_hash
                == core_ssa_correspondence.branch_core_ssa_hash
            && machine_ir_correspondence.bounds_source_core_hash
                == core_ssa_correspondence.bounds_source_core_hash
            && machine_ir_correspondence.bounds_source_core_ssa_hash
                == core_ssa_correspondence.bounds_core_ssa_hash,
        "R1-S6 Machine IR correspondence",
        "schema/policy/limits/manifest/predecessor identities",
    )?;
    let (
        selected_machine_correspondence_source,
        selected_machine_correspondence_ssa,
        selected_machine_correspondence_artifact,
    ) = match profile {
        X64StandaloneProfile::BranchMix => (
            machine_ir_correspondence.branch_source_core_hash,
            machine_ir_correspondence.branch_source_core_ssa_hash,
            machine_ir_correspondence.branch_machine_ir_hash,
        ),
        X64StandaloneProfile::Bounds => (
            machine_ir_correspondence.bounds_source_core_hash,
            machine_ir_correspondence.bounds_source_core_ssa_hash,
            machine_ir_correspondence.bounds_machine_ir_hash,
        ),
    };
    require_inherited(
        selected_machine_correspondence_source == source_core.semantic_hash
            && selected_machine_correspondence_ssa == source_ssa.semantic_hash
            && selected_machine_correspondence_artifact == source_machine_ir.semantic_hash,
        "R1-S6 Machine IR correspondence",
        "selected source/target identities",
    )?;

    let machine_ir_r1_s6 =
        inherited_machine_ir(profile, source_machine_ir, &machine_ir_correspondence)?;
    require_inherited(
        machine_ir_r1_s6.source_core_hash == r1_s4.residual_hash
            && machine_ir_r1_s6.source_ssa_hash == core_ssa_r1_s5.artifact_hash,
        "R1-S6 Machine IR",
        "source replay identities",
    )?;

    let target_correspondence = package
        .regenerate_target_correspondence()
        .map_err(|error| regeneration_error(profile, error))?;
    let target_r1_s7a = inherited_target(
        profile,
        package.target(),
        target_program,
        target.semantic_hash(),
        x64_native_canonical_abi_hash(target)?,
        target_correspondence.results_hash,
        u32::try_from(target_correspondence.records.len()).map_err(|_| {
            X64StandaloneAuthorityError::MetricOverflow {
                field: "R1-S7a correspondence record count",
            }
        })?,
    )?;
    require_inherited(
        target_r1_s7a.source_core_hash == r1_s4.residual_hash
            && target_r1_s7a.source_ssa_hash == core_ssa_r1_s5.artifact_hash
            && target_r1_s7a.source_machine_ir_hash == machine_ir_r1_s6.artifact_hash,
        "R1-S7a target",
        "source replay identities",
    )?;

    let native_r1_s7b = inherited_native(
        profile,
        evidence,
        manifest,
        target_r1_s7a.code_hash,
        target_r1_s7a.artifact_hash,
        target_r1_s7a.plan_hash,
        target_r1_s7a.canonical_abi_hash,
        target_program.entry_offset,
        u8::try_from(target_program.entry_abi.input_lanes.len()).map_err(|_| {
            X64StandaloneAuthorityError::InputLaneCountOverflow {
                actual: target_program.entry_abi.input_lanes.len(),
            }
        })?,
        selected_profile_records,
        target_r1_s7a.usage.code_bytes,
    )?;

    Ok(X64StandaloneInheritedEnvelope {
        r1_s4,
        gate_a_r1_s5,
        core_ssa_r1_s5,
        machine_ir_r1_s6,
        target_r1_s7a,
        native_r1_s7b,
        structural_erasure: true,
        upstream_interpreter_dependency: false,
        fallback: false,
    })
}

const X64_STANDALONE_R1_S4_RESIDUAL_BYTES_BUDGET: u64 = 1_000_000_000;
const _: () =
    assert!(X64_STANDALONE_R1_S4_RESIDUAL_BYTES_BUDGET <= R1_S4_MAX_RESIDUAL_BYTES_HARD_CAP);

/// Exact budget selected by the frozen lighthouse package.
///
/// The residual-byte dimension is deliberately 1,000,000,000, which is
/// below the general R1-S4 hard cap of 1,073,741,824.  Authority admission
/// binds the package's exact budget rather than silently widening it to the
/// implementation-wide ceiling.
const fn canonical_s4_lighthouse_budget() -> PolyvariantR1S4Budget {
    PolyvariantR1S4Budget::new(
        R1_S4_MAX_WORK_UNITS_HARD_CAP,
        R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
        R1_S4_MAX_VARIANTS_HARD_CAP,
        R1_S4_MAX_CONTROL_SPLITS_HARD_CAP,
        R1_S4_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
        R1_S4_MAX_HELPER_UNFOLDS_HARD_CAP,
        R1_S4_MAX_RESIDUAL_NODES_HARD_CAP,
        X64_STANDALONE_R1_S4_RESIDUAL_BYTES_BUDGET,
    )
}

fn inherited_core_ssa(
    profile: X64StandaloneProfile,
    artifact: &CoreSsaArtifact,
    correspondence: &R1S5CoreSsaCorrespondenceEvidence,
) -> Result<X64StandaloneInheritedCoreSsa, X64StandaloneAuthorityError> {
    let program = &artifact.program;
    require_inherited(
        (
            program.schema.major,
            program.schema.minor,
            program.schema.patch,
        ) == CORE_SSA_SCHEMA_VERSION
            && program.lowering_policy_version == CORE_SSA_LOWERING_POLICY_VERSION,
        "R1-S5 Core SSA",
        "schema/policy",
    )?;
    let mut blocks = 0_u64;
    let mut instructions = 0_u64;
    let mut values = 0_u64;
    let mut cfg_edges = 0_u64;
    for function in &program.functions {
        blocks = checked_add(blocks, function.blocks.len(), "Core SSA blocks")?;
        values = checked_add(values, function.parameters.len(), "Core SSA values")?;
        for block in &function.blocks {
            instructions = checked_add(
                instructions,
                block.instructions.len(),
                "Core SSA instructions",
            )?;
            values = checked_add(values, block.instructions.len(), "Core SSA values")?;
            if matches!(block.terminator, SsaTerminator::Branch { .. }) {
                cfg_edges = cfg_edges.checked_add(2).ok_or(
                    X64StandaloneAuthorityError::MetricOverflow {
                        field: "Core SSA CFG edges",
                    },
                )?;
            }
        }
    }
    let semantic_bytes = length_u64(
        core_ssa_semantic_bytes(program)
            .map_err(|error| {
                inherited_regeneration_error(profile, "R1-S5 Core SSA encoding", error)
            })?
            .len(),
        "Core SSA semantic bytes",
    )?;
    let limits = X64StandaloneInheritedCoreSsaLimits {
        max_functions: CORE_SSA_MAX_FUNCTIONS,
        max_blocks: CORE_SSA_MAX_BLOCKS,
        max_instructions: CORE_SSA_MAX_INSTRUCTIONS,
        max_values: CORE_SSA_MAX_VALUES,
        max_edges: CORE_SSA_MAX_EDGES,
        max_cfg_depth: CORE_SSA_MAX_CFG_DEPTH,
        max_semantic_bytes: CORE_SSA_MAX_SEMANTIC_BYTES,
        max_live_value_slots: CORE_SSA_MAX_LIVE_VALUE_SLOTS,
        max_diagnostics: u32::try_from(CORE_SSA_MAX_DIAGNOSTICS).map_err(|_| {
            X64StandaloneAuthorityError::MetricOverflow {
                field: "Core SSA diagnostic cap",
            }
        })?,
        max_environment_copy_work: CORE_SSA_MAX_ENVIRONMENT_COPY_WORK,
    };
    let usage = X64StandaloneInheritedCoreSsaUsage {
        functions: length_u64(program.functions.len(), "Core SSA functions")?,
        blocks,
        instructions,
        values,
        cfg_edges,
        semantic_bytes,
    };
    require_inherited(
        usage.functions <= limits.max_functions
            && usage.blocks <= limits.max_blocks
            && usage.instructions <= limits.max_instructions
            && usage.values <= limits.max_values
            && usage.cfg_edges <= limits.max_edges
            && usage.semantic_bytes <= limits.max_semantic_bytes,
        "R1-S5 Core SSA",
        "usage/limit vector",
    )?;
    Ok(X64StandaloneInheritedCoreSsa {
        schema_version: CORE_SSA_SCHEMA_VERSION,
        lowering_policy_version: program.lowering_policy_version,
        correspondence_schema_version: correspondence.schema_version,
        correspondence_policy_version: correspondence.policy_version,
        source_core_hash: program.source_core_hash,
        artifact_hash: artifact.semantic_hash,
        correspondence_manifest_hash: correspondence.manifest_hash,
        correspondence_results_hash: correspondence.results_hash,
        correspondence_limits: correspondence.limits,
        correspondence_records: u32::try_from(correspondence.records.len()).map_err(|_| {
            X64StandaloneAuthorityError::MetricOverflow {
                field: "R1-S5 Core SSA correspondence record count",
            }
        })?,
        limits,
        usage,
    })
}

fn inherited_machine_ir(
    profile: X64StandaloneProfile,
    artifact: &MachineIrArtifact,
    correspondence: &R1S6MachineIrCorrespondenceEvidence,
) -> Result<X64StandaloneInheritedMachineIr, X64StandaloneAuthorityError> {
    let program = &artifact.program;
    require_inherited(
        (
            program.schema.major,
            program.schema.minor,
            program.schema.patch,
        ) == MACHINE_IR_SCHEMA_VERSION
            && program.lowering_policy_version == MACHINE_IR_LOWERING_POLICY_VERSION
            && program.limits == MachineIrLimits::r1_s6(),
        "R1-S6 Machine IR",
        "schema/policy/limits",
    )?;
    let mut blocks = 0_u64;
    let mut instructions = 0_u64;
    let mut registers = 0_u64;
    let mut cfg_edges = 0_u64;
    let mut operands = 0_u64;
    let mut lowering_work = length_u64(program.functions.len(), "Machine IR functions")?;
    for function in &program.functions {
        blocks = checked_add(blocks, function.blocks.len(), "Machine IR blocks")?;
        registers = checked_add(registers, function.parameters.len(), "Machine IR registers")?;
        lowering_work = checked_add(
            lowering_work,
            function.parameters.len(),
            "Machine IR lowering work",
        )?;
        lowering_work = checked_add(
            lowering_work,
            function.effects.len(),
            "Machine IR lowering work",
        )?;
        lowering_work = checked_add(
            lowering_work,
            function.blocks.len(),
            "Machine IR lowering work",
        )?;
        for block in &function.blocks {
            instructions = checked_add(
                instructions,
                block.instructions.len(),
                "Machine IR instructions",
            )?;
            registers = checked_add(registers, block.instructions.len(), "Machine IR registers")?;
            lowering_work = checked_add(
                lowering_work,
                block.instructions.len(),
                "Machine IR lowering work",
            )?;
            for instruction in &block.instructions {
                let count = machine_instruction_operands(&instruction.kind)?;
                operands = operands.checked_add(count).ok_or(
                    X64StandaloneAuthorityError::MetricOverflow {
                        field: "Machine IR operands",
                    },
                )?;
                lowering_work = lowering_work.checked_add(count).ok_or(
                    X64StandaloneAuthorityError::MetricOverflow {
                        field: "Machine IR lowering work",
                    },
                )?;
            }
            let count = machine_terminator_operands(&block.terminator)?;
            operands =
                operands
                    .checked_add(count)
                    .ok_or(X64StandaloneAuthorityError::MetricOverflow {
                        field: "Machine IR operands",
                    })?;
            lowering_work = lowering_work.checked_add(count).ok_or(
                X64StandaloneAuthorityError::MetricOverflow {
                    field: "Machine IR lowering work",
                },
            )?;
            if matches!(block.terminator, MachineTerminator::Branch { .. }) {
                cfg_edges = cfg_edges.checked_add(2).ok_or(
                    X64StandaloneAuthorityError::MetricOverflow {
                        field: "Machine IR CFG edges",
                    },
                )?;
            }
        }
    }
    let semantic_bytes = length_u64(
        machine_ir_semantic_bytes(program)
            .map_err(|error| {
                inherited_regeneration_error(profile, "R1-S6 Machine IR encoding", error)
            })?
            .len(),
        "Machine IR semantic bytes",
    )?;
    let usage = X64StandaloneInheritedMachineIrUsage {
        functions: length_u64(program.functions.len(), "Machine IR functions")?,
        blocks,
        instructions,
        registers,
        cfg_edges,
        operands,
        lowering_work,
        semantic_bytes,
    };
    let limits = program.limits;
    require_inherited(
        usage.functions <= limits.max_functions
            && usage.blocks <= limits.max_blocks
            && usage.instructions <= limits.max_instructions
            && usage.registers <= limits.max_registers
            && usage.cfg_edges <= limits.max_edges
            && usage.operands <= limits.max_operands
            && usage.lowering_work <= limits.max_lowering_work
            && usage.semantic_bytes <= limits.max_semantic_bytes,
        "R1-S6 Machine IR",
        "usage/limit vector",
    )?;
    Ok(X64StandaloneInheritedMachineIr {
        schema_version: MACHINE_IR_SCHEMA_VERSION,
        lowering_policy_version: program.lowering_policy_version,
        correspondence_schema_version: correspondence.schema_version,
        correspondence_policy_version: correspondence.policy_version,
        source_core_hash: program.source_core_hash,
        source_ssa_hash: program.source_ssa_hash,
        artifact_hash: artifact.semantic_hash,
        correspondence_manifest_hash: correspondence.manifest_hash,
        correspondence_results_hash: correspondence.results_hash,
        correspondence_limits: correspondence.limits,
        correspondence_records: u32::try_from(correspondence.records.len()).map_err(|_| {
            X64StandaloneAuthorityError::MetricOverflow {
                field: "R1-S6 Machine IR correspondence record count",
            }
        })?,
        limits,
        usage,
    })
}

fn inherited_target(
    profile: X64StandaloneProfile,
    artifact: &X64TargetArtifact,
    program: &super::x64_target::X64TargetProgram,
    artifact_hash: SemanticHash,
    canonical_abi_hash: SemanticHash,
    correspondence_results_hash: SemanticHash,
    correspondence_records: u32,
) -> Result<X64StandaloneInheritedTarget, X64StandaloneAuthorityError> {
    require_inherited(
        artifact.semantic_hash == artifact_hash
            && (
                program.schema.major,
                program.schema.minor,
                program.schema.patch,
            ) == X64_TARGET_SCHEMA_VERSION
            && program.lowering_policy_version == X64_TARGET_LOWERING_POLICY_VERSION
            && program.encoder_policy_version == X64_TARGET_ENCODER_POLICY_VERSION
            && program.limits == X64TargetLimits::r1_s7a()
            && correspondence_records == COREVM0_GATE_A_TOTAL_CASES,
        "R1-S7a target",
        "schema/policies/limits/correspondence",
    )?;
    let mut source_blocks = 0_u64;
    let mut source_instructions = 0_u64;
    let mut target_operations = 0_u64;
    let mut lowering_work = length_u64(program.functions.len(), "target functions")?;
    for function in &program.functions {
        source_blocks = checked_add(source_blocks, function.blocks.len(), "target blocks")?;
        lowering_work = checked_add(
            lowering_work,
            function.parameters.len(),
            "target lowering work",
        )?;
        lowering_work = checked_add(
            lowering_work,
            function.effects.len(),
            "target lowering work",
        )?;
        lowering_work = checked_add(lowering_work, function.blocks.len(), "target lowering work")?;
        for block in &function.blocks {
            source_instructions = checked_add(
                source_instructions,
                block.instructions.len(),
                "target instructions",
            )?;
            target_operations = checked_add(
                target_operations,
                block.instructions.len(),
                "target operations",
            )?
            .checked_add(1)
            .ok_or(X64StandaloneAuthorityError::MetricOverflow {
                field: "target operations",
            })?;
            lowering_work = checked_add(
                lowering_work,
                block.instructions.len(),
                "target lowering work",
            )?
            .checked_add(1)
            .ok_or(X64StandaloneAuthorityError::MetricOverflow {
                field: "target lowering work",
            })?;
            let mut operand_count = target_terminator_operands(&block.terminator)?;
            for instruction in &block.instructions {
                operand_count = operand_count
                    .checked_add(target_instruction_operands(&instruction.kind))
                    .ok_or(X64StandaloneAuthorityError::MetricOverflow {
                        field: "target operands",
                    })?;
            }
            lowering_work = lowering_work.checked_add(operand_count).ok_or(
                X64StandaloneAuthorityError::MetricOverflow {
                    field: "target lowering work",
                },
            )?;
        }
    }
    let usage = X64StandaloneInheritedTargetUsage {
        source_functions: length_u64(program.functions.len(), "target functions")?,
        source_blocks,
        source_instructions,
        target_operations,
        labels: length_u64(program.labels.len(), "target labels")?,
        fixups: length_u64(program.fixups.len(), "target fixups")?,
        lowering_work,
        plan_bytes: length_u64(
            x64_target_plan_bytes(program)
                .map_err(|error| {
                    inherited_regeneration_error(profile, "R1-S7a target-plan encoding", error)
                })?
                .len(),
            "target plan bytes",
        )?,
        semantic_bytes: length_u64(
            x64_target_semantic_bytes(program)
                .map_err(|error| {
                    inherited_regeneration_error(profile, "R1-S7a target encoding", error)
                })?
                .len(),
            "target semantic bytes",
        )?,
        code_bytes: length_u64(program.code.len(), "target code bytes")?,
        frame_bytes: program.frame.frame_bytes,
        outgoing_bytes: program.frame.outgoing_bytes,
        input_lanes: u32::try_from(program.entry_abi.input_lanes.len()).map_err(|_| {
            X64StandaloneAuthorityError::MetricOverflow {
                field: "target input lanes",
            }
        })?,
        correspondence_records,
    };
    let limits = program.limits;
    require_inherited(
        usage.source_functions <= limits.max_source_functions
            && usage.source_blocks <= limits.max_source_blocks
            && usage.source_instructions <= limits.max_source_instructions
            && usage.target_operations <= limits.max_ops
            && usage.labels <= limits.max_labels
            && usage.fixups <= limits.max_fixups
            && usage.lowering_work <= limits.max_lowering_work
            && usage.semantic_bytes <= limits.max_semantic_bytes
            && usage.code_bytes <= limits.max_code_bytes
            && usage.frame_bytes <= limits.max_frame_bytes
            && usage.outgoing_bytes <= limits.max_outgoing_bytes
            && usage.input_lanes <= limits.max_entry_input_lanes
            && correspondence_records <= X64_TARGET_MAX_CORRESPONDENCE_RECORDS,
        "R1-S7a target",
        "usage/limit vector",
    )?;
    Ok(X64StandaloneInheritedTarget {
        schema_version: X64_TARGET_SCHEMA_VERSION,
        lowering_policy_version: program.lowering_policy_version,
        encoder_policy_version: program.encoder_policy_version,
        correspondence_schema_version: X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION,
        source_core_hash: program.source_core_hash,
        source_ssa_hash: program.source_ssa_hash,
        source_machine_ir_hash: program.source_machine_ir_hash,
        plan_hash: program.plan_hash,
        code_hash: program.code_hash,
        artifact_hash,
        canonical_abi_hash,
        correspondence_results_hash,
        limits,
        max_correspondence_records: X64_TARGET_MAX_CORRESPONDENCE_RECORDS,
        max_correspondence_effects_per_engine: X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE,
        usage,
    })
}

#[allow(clippy::too_many_arguments)]
fn inherited_native(
    profile: X64StandaloneProfile,
    verified: VerifiedX64NativeProcessEvidence<'_>,
    manifest: &CoreVmGateACorpusManifest,
    target_code_hash: SemanticHash,
    target_artifact_hash: SemanticHash,
    target_plan_hash: SemanticHash,
    canonical_abi_hash: SemanticHash,
    entry_offset: u32,
    input_lanes: u8,
    selected_profile_records: u32,
    target_code_bytes: u64,
) -> Result<X64StandaloneInheritedNative, X64StandaloneAuthorityError> {
    let process = verified.evidence();
    require_inherited(
        process.schema_version() == X64_NATIVE_PROCESS_SCHEMA_VERSION
            && process.process_policy_version() == X64_NATIVE_PROCESS_POLICY_VERSION
            && process.ipc_schema_version() == X64_NATIVE_IPC_SCHEMA_VERSION
            && process.corpus_manifest_hash() == manifest.manifest_hash
            && process.correspondence().corpus_manifest_hash == manifest.manifest_hash,
        "R1-S7b process",
        "schema/policies/manifest",
    )?;
    let record_count = u32::try_from(process.correspondence().records.len()).map_err(|_| {
        X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S7b correspondence record count",
        }
    })?;
    let receipt_count = u32::try_from(process.receipts().len()).map_err(|_| {
        X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S7b process receipt count",
        }
    })?;
    require_inherited(
        record_count == COREVM0_GATE_A_TOTAL_CASES
            && receipt_count == COREVM0_GATE_A_TOTAL_CASES
            && process.correspondence().schema_version == X64_NATIVE_EVIDENCE_SCHEMA_VERSION,
        "R1-S7b process",
        "fixed record counts",
    )?;
    for receipt in process.receipts() {
        require_inherited(
            receipt.schema_version() == X64_NATIVE_PROCESS_SCHEMA_VERSION
                && receipt.process_policy_version() == X64_NATIVE_PROCESS_POLICY_VERSION
                && receipt.ipc_schema_version() == X64_NATIVE_IPC_SCHEMA_VERSION,
            "R1-S7b process",
            "receipt version vector",
        )?;
    }

    let expected_limits = X64NativeLimits::r1_s7b();
    let canonical_mapping_trace = [
        X64NativeMappingState::Unmapped,
        X64NativeMappingState::ReadWrite,
        X64NativeMappingState::ReadExecute,
        X64NativeMappingState::Unmapped,
    ];
    let mut selected_records = 0_u32;
    let mut machine_ir_effects = 0_u32;
    let mut native_effects = 0_u32;
    let mut fallback_records = 0_u32;
    for (case, record) in manifest.cases.iter().zip(&process.correspondence().records) {
        let execution = &record.native_execution;
        require_inherited(
            record.schema_version == X64_NATIVE_EVIDENCE_SCHEMA_VERSION
                && execution.evidence_schema_version == X64_NATIVE_EVIDENCE_SCHEMA_VERSION
                && execution.runner_schema_version == X64_NATIVE_RUNNER_SCHEMA_VERSION
                && execution.runner_policy_version == X64_NATIVE_RUNNER_POLICY_VERSION
                && execution.syscall_policy_version == X64_NATIVE_SYSCALL_POLICY_VERSION
                && execution.entry_policy_version == X64_NATIVE_ENTRY_POLICY_VERSION
                && execution.limits == expected_limits
                && execution.mapping_trace == canonical_mapping_trace
                && execution.copied_rw_code_hash == execution.target_code_hash
                && execution.readback_rx_code_hash == execution.target_code_hash
                && execution.mxcsr_before == 0x0000_1f80
                && execution.mxcsr_after == 0x0000_1f80
                && record.target_artifact_hash == execution.target_artifact_hash
                && record.target_code_hash == execution.target_code_hash
                && record.source_machine_ir_hash == execution.source_machine_ir_hash
                && record.record_hash != SemanticHash::ZERO
                && execution.record_hash != SemanticHash::ZERO,
            "R1-S7b native",
            "record envelope",
        )?;
        if execution.fallback {
            fallback_records = fallback_records.checked_add(1).ok_or(
                X64StandaloneAuthorityError::MetricOverflow {
                    field: "R1-S7b fallback records",
                },
            )?;
        }
        if case.workload != workload_for_profile(profile) {
            continue;
        }
        selected_records =
            selected_records
                .checked_add(1)
                .ok_or(X64StandaloneAuthorityError::MetricOverflow {
                    field: "R1-S7b selected records",
                })?;
        require_inherited(
            execution.target_artifact_hash == target_artifact_hash
                && execution.target_plan_hash == target_plan_hash
                && execution.target_code_hash == target_code_hash
                && execution.canonical_abi_hash == canonical_abi_hash
                && execution.entry_offset == entry_offset
                && execution.input_lanes == input_lanes,
            "R1-S7b native",
            "selected target identity",
        )?;
        machine_ir_effects = machine_ir_effects
            .checked_add(
                u32::try_from(record.machine_ir.effect_trace.len()).map_err(|_| {
                    X64StandaloneAuthorityError::MetricOverflow {
                        field: "R1-S7b Machine IR effects",
                    }
                })?,
            )
            .ok_or(X64StandaloneAuthorityError::MetricOverflow {
                field: "R1-S7b Machine IR effects",
            })?;
        native_effects = native_effects
            .checked_add(
                u32::try_from(record.native.effect_trace.len()).map_err(|_| {
                    X64StandaloneAuthorityError::MetricOverflow {
                        field: "R1-S7b native effects",
                    }
                })?,
            )
            .ok_or(X64StandaloneAuthorityError::MetricOverflow {
                field: "R1-S7b native effects",
            })?;
    }
    require_inherited(
        selected_records == selected_profile_records && fallback_records == 0,
        "R1-S7b native",
        "selected count/fallback",
    )?;
    let selected_profile_mapped_code_bytes = target_code_bytes
        .checked_mul(u64::from(selected_records))
        .ok_or(X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S7b mapped code bytes",
        })?;
    let selected_profile_borrowed_arrays = selected_records;
    let selected_profile_output_words = selected_records
        .checked_mul(expected_limits.output_words)
        .ok_or(X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S7b output words",
        })?;
    let selected_profile_mapping_state_events = selected_records
        .checked_mul(expected_limits.mapping_state_events)
        .ok_or(X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S7b mapping state events",
        })?;
    let max_selected_borrowed_arrays = selected_records
        .checked_mul(expected_limits.max_borrowed_f64_arrays)
        .ok_or(X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S7b borrowed-array cap",
        })?;
    let max_selected_effects = selected_records
        .checked_mul(expected_limits.max_effects_per_engine)
        .ok_or(X64StandaloneAuthorityError::MetricOverflow {
            field: "R1-S7b effect cap",
        })?;
    require_inherited(
        target_code_bytes <= expected_limits.max_mapping_bytes
            && u32::from(input_lanes) <= expected_limits.max_entry_lanes
            && selected_profile_borrowed_arrays <= max_selected_borrowed_arrays
            && machine_ir_effects <= max_selected_effects
            && native_effects <= max_selected_effects,
        "R1-S7b native",
        "usage/limit vector",
    )?;
    Ok(X64StandaloneInheritedNative {
        evidence_schema_version: X64_NATIVE_EVIDENCE_SCHEMA_VERSION,
        runner_schema_version: X64_NATIVE_RUNNER_SCHEMA_VERSION,
        runner_policy_version: X64_NATIVE_RUNNER_POLICY_VERSION,
        syscall_policy_version: X64_NATIVE_SYSCALL_POLICY_VERSION,
        entry_policy_version: X64_NATIVE_ENTRY_POLICY_VERSION,
        process_schema_version: process.schema_version(),
        process_policy_version: process.process_policy_version(),
        ipc_schema_version: process.ipc_schema_version(),
        manifest_hash: process.corpus_manifest_hash(),
        semantic_results_hash: process.semantic_results_hash(),
        process_results_hash: process.results_hash(),
        limits: expected_limits,
        process_limits: X64StandaloneInheritedProcessLimits {
            timeout_millis: X64_NATIVE_PROCESS_TIMEOUT_MILLIS,
            max_diagnostic_bytes: X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES,
            max_diagnostic_records: X64_NATIVE_MAX_DIAGNOSTICS,
            max_record_bytes: X64_NATIVE_MAX_RECORD_BYTES,
        },
        usage: X64StandaloneInheritedNativeUsage {
            correspondence_records: record_count,
            process_receipts: receipt_count,
            selected_profile_records: selected_records,
            selected_profile_code_mappings: selected_records,
            selected_profile_mapped_code_bytes,
            selected_profile_borrowed_arrays,
            selected_profile_output_words,
            selected_profile_mapping_state_events,
            selected_profile_machine_ir_effects: machine_ir_effects,
            selected_profile_native_effects: native_effects,
            fallback_records,
            captured_diagnostic_bytes: 0,
            captured_diagnostic_records: 0,
        },
    })
}

fn machine_instruction_operands(
    kind: &MachineInstructionKind,
) -> Result<u64, X64StandaloneAuthorityError> {
    Ok(match kind {
        MachineInstructionKind::Move(_) | MachineInstructionKind::ArrayLenF64 { .. } => 1,
        MachineInstructionKind::I64Binary { .. }
        | MachineInstructionKind::F64Binary { .. }
        | MachineInstructionKind::I64Compare { .. }
        | MachineInstructionKind::ArrayGetF64Checked { .. } => 2,
        MachineInstructionKind::Call { arguments, .. } => {
            length_u64(arguments.len(), "Machine IR operands")?
        }
    })
}

fn machine_terminator_operands(
    terminator: &MachineTerminator,
) -> Result<u64, X64StandaloneAuthorityError> {
    Ok(match terminator {
        MachineTerminator::Return(_) | MachineTerminator::Branch { .. } => 1,
        MachineTerminator::TailCall { arguments, .. } => {
            length_u64(arguments.len(), "Machine IR operands")?
        }
    })
}

const fn target_instruction_operands(kind: &X64InstructionKind) -> u64 {
    match kind {
        X64InstructionKind::Move(_) | X64InstructionKind::ArrayLenF64 { .. } => 1,
        X64InstructionKind::I64Wrapping { .. }
        | X64InstructionKind::Sse2F64 { .. }
        | X64InstructionKind::I64Setcc { .. }
        | X64InstructionKind::ArrayGetF64Checked { .. } => 2,
    }
}

fn target_terminator_operands(
    terminator: &X64Terminator,
) -> Result<u64, X64StandaloneAuthorityError> {
    Ok(match terminator {
        X64Terminator::Return { .. } | X64Terminator::BranchRel32 { .. } => 1,
        X64Terminator::TailJumpRel32 { arguments, .. } => {
            length_u64(arguments.len(), "target operands")?
        }
    })
}

fn checked_add(
    current: u64,
    additional: usize,
    field: &'static str,
) -> Result<u64, X64StandaloneAuthorityError> {
    current
        .checked_add(length_u64(additional, field)?)
        .ok_or(X64StandaloneAuthorityError::MetricOverflow { field })
}

fn length_u64(length: usize, field: &'static str) -> Result<u64, X64StandaloneAuthorityError> {
    u64::try_from(length).map_err(|_| X64StandaloneAuthorityError::MetricOverflow { field })
}

fn require_inherited(
    condition: bool,
    stage: &'static str,
    field: &'static str,
) -> Result<(), X64StandaloneAuthorityError> {
    if condition {
        Ok(())
    } else {
        Err(X64StandaloneAuthorityError::InheritedEnvelopeMismatch { stage, field })
    }
}

fn inherited_regeneration_error(
    profile: X64StandaloneProfile,
    stage: &'static str,
    error: impl fmt::Display,
) -> X64StandaloneAuthorityError {
    X64StandaloneAuthorityError::Regeneration {
        profile,
        message: format!("{stage}: {error}"),
    }
}

fn compare_hash(
    profile: X64StandaloneProfile,
    case_ordinal: u32,
    field: X64StandaloneAuthorityHashField,
    expected: SemanticHash,
    actual: SemanticHash,
) -> Result<(), X64StandaloneAuthorityError> {
    if actual != expected {
        return Err(X64StandaloneAuthorityError::HashMismatch {
            profile,
            case_ordinal,
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

const fn workload_for_profile(profile: X64StandaloneProfile) -> CoreVmGateAWorkload {
    match profile {
        X64StandaloneProfile::BranchMix => CoreVmGateAWorkload::BranchMix,
        X64StandaloneProfile::Bounds => CoreVmGateAWorkload::BoundsOrderedArrayGet,
    }
}

const fn expected_case_count(profile: X64StandaloneProfile) -> u32 {
    match profile {
        X64StandaloneProfile::BranchMix => COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES,
        X64StandaloneProfile::Bounds => COREVM0_GATE_A_BOUNDS_CASES,
    }
}

fn regeneration_error(
    profile: X64StandaloneProfile,
    error: X64NativeLighthouseError,
) -> X64StandaloneAuthorityError {
    X64StandaloneAuthorityError::Regeneration {
        profile,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_mapping_and_fixed_case_partition_are_exact() {
        assert_eq!(
            workload_for_profile(X64StandaloneProfile::BranchMix),
            CoreVmGateAWorkload::BranchMix
        );
        assert_eq!(
            workload_for_profile(X64StandaloneProfile::Bounds),
            CoreVmGateAWorkload::BoundsOrderedArrayGet
        );
        assert_eq!(expected_case_count(X64StandaloneProfile::BranchMix), 46);
        assert_eq!(expected_case_count(X64StandaloneProfile::Bounds), 5);
        assert_eq!(
            expected_case_count(X64StandaloneProfile::BranchMix)
                + expected_case_count(X64StandaloneProfile::Bounds),
            COREVM0_GATE_A_TOTAL_CASES
        );
    }

    #[test]
    fn inherited_envelope_encoding_has_one_exact_fixed_width() {
        let envelope = blank_inherited_envelope();
        let first = envelope
            .canonical_bytes()
            .expect("fixed-width inherited envelope must encode");
        let second = envelope
            .canonical_bytes()
            .expect("repeated inherited envelope encoding must succeed");
        assert_eq!(first.len(), X64_STANDALONE_INHERITED_ENVELOPE_BYTES);
        assert_eq!(first, second);
        assert_eq!(first[0], 1);
        assert_eq!(
            first[X64_STANDALONE_INHERITED_ENVELOPE_BYTES - 3..],
            [1, 0, 0]
        );
    }

    fn blank_inherited_envelope() -> X64StandaloneInheritedEnvelope {
        let version = (0, 0, 0);
        let hash = SemanticHash::ZERO;
        X64StandaloneInheritedEnvelope {
            r1_s4: X64StandaloneInheritedR1S4 {
                evidence_schema_version: version,
                replay_version: version,
                binding_version: version,
                construction_version: version,
                specialization_policy_version: version,
                erasure_version: version,
                core_interpreter_semantics_hash: hash,
                definitional_artifact_hash: hash,
                source_program_hash: hash,
                source_program_image_hash: hash,
                binding_time_request_hash: hash,
                binding_time_certificate_hash: hash,
                specialization_request_hash: hash,
                specialization_policy_hash: hash,
                specialization_stage_request_hash: hash,
                control_hash: hash,
                static_table_hash: hash,
                summary_table_hash: hash,
                variant_table_hash: hash,
                residual_hash: hash,
                binding_hash: hash,
                erasure_hash: hash,
                evidence_hash: hash,
                hard_budget: PolyvariantR1S4Budget::new(0, 0, 0, 0, 0, 0, 0, 0),
                max_helper_depth: 0,
                usage: PolyvariantR1S4Usage::default(),
                residual_nodes: 0,
                residual_bytes: 0,
                residual_functions: 0,
                loop_variants: 0,
                residual_nodes_scanned: 0,
                residual_calls: 0,
                residual_tail_calls: 0,
                residual_ifs: 0,
            },
            gate_a_r1_s5: X64StandaloneInheritedGateA {
                schema_version: version,
                replay_version: version,
                numeric_contract_version: version,
                corpus_version: version,
                generator_version: version,
                finite_bounded_validation: false,
                numeric_contract_hash: hash,
                branch_s4_evidence_hash: hash,
                branch_source_program_hash: hash,
                branch_source_program_image_hash: hash,
                branch_definitional_artifact_hash: hash,
                core_interpreter_semantics_hash: hash,
                branch_residual_hash: hash,
                branch_s4_binding_hash: hash,
                branch_s4_erasure_hash: hash,
                bounds_source_program_hash: hash,
                bounds_definitional_artifact_hash: hash,
                bounds_residual_hash: hash,
                bounds_s4_evidence_hash: hash,
                manifest_hash: hash,
                semantic_results_hash: hash,
                telemetry_hash: hash,
                evidence_hash: hash,
                generator_seed: 0,
                edge_cases: 0,
                exhaustive_cases: 0,
                generated_cases: 0,
                bounds_cases: 0,
                total_cases: 0,
                total_array_elements: 0,
                max_effects_per_engine: 0,
                hard_budget: CoreVmGateAExecutionBudget {
                    max_cases: 0,
                    max_array_elements_per_case: 0,
                    max_total_array_elements: 0,
                    seed_steps_per_case: 0,
                    definitional_core_steps_per_case: 0,
                    residual_core_steps_per_case: 0,
                    core_call_depth_per_case: 0,
                    max_total_seed_steps: 0,
                    max_total_definitional_core_steps: 0,
                    max_total_residual_core_steps: 0,
                },
                usage: CoreVmGateAUsage::default(),
            },
            core_ssa_r1_s5: X64StandaloneInheritedCoreSsa {
                schema_version: version,
                lowering_policy_version: version,
                correspondence_schema_version: version,
                correspondence_policy_version: version,
                source_core_hash: hash,
                artifact_hash: hash,
                correspondence_manifest_hash: hash,
                correspondence_results_hash: hash,
                correspondence_limits: blank_translation_correspondence_limits(),
                correspondence_records: 0,
                limits: X64StandaloneInheritedCoreSsaLimits {
                    max_functions: 0,
                    max_blocks: 0,
                    max_instructions: 0,
                    max_values: 0,
                    max_edges: 0,
                    max_cfg_depth: 0,
                    max_semantic_bytes: 0,
                    max_live_value_slots: 0,
                    max_diagnostics: 0,
                    max_environment_copy_work: 0,
                },
                usage: X64StandaloneInheritedCoreSsaUsage {
                    functions: 0,
                    blocks: 0,
                    instructions: 0,
                    values: 0,
                    cfg_edges: 0,
                    semantic_bytes: 0,
                },
            },
            machine_ir_r1_s6: X64StandaloneInheritedMachineIr {
                schema_version: version,
                lowering_policy_version: version,
                correspondence_schema_version: version,
                correspondence_policy_version: version,
                source_core_hash: hash,
                source_ssa_hash: hash,
                artifact_hash: hash,
                correspondence_manifest_hash: hash,
                correspondence_results_hash: hash,
                correspondence_limits: blank_translation_correspondence_limits(),
                correspondence_records: 0,
                limits: MachineIrLimits::r1_s6(),
                usage: X64StandaloneInheritedMachineIrUsage {
                    functions: 0,
                    blocks: 0,
                    instructions: 0,
                    registers: 0,
                    cfg_edges: 0,
                    operands: 0,
                    lowering_work: 0,
                    semantic_bytes: 0,
                },
            },
            target_r1_s7a: X64StandaloneInheritedTarget {
                schema_version: version,
                lowering_policy_version: version,
                encoder_policy_version: version,
                correspondence_schema_version: version,
                source_core_hash: hash,
                source_ssa_hash: hash,
                source_machine_ir_hash: hash,
                plan_hash: hash,
                code_hash: hash,
                artifact_hash: hash,
                canonical_abi_hash: hash,
                correspondence_results_hash: hash,
                limits: X64TargetLimits::r1_s7a(),
                max_correspondence_records: 0,
                max_correspondence_effects_per_engine: 0,
                usage: X64StandaloneInheritedTargetUsage {
                    source_functions: 0,
                    source_blocks: 0,
                    source_instructions: 0,
                    target_operations: 0,
                    labels: 0,
                    fixups: 0,
                    lowering_work: 0,
                    plan_bytes: 0,
                    semantic_bytes: 0,
                    code_bytes: 0,
                    frame_bytes: 0,
                    outgoing_bytes: 0,
                    input_lanes: 0,
                    correspondence_records: 0,
                },
            },
            native_r1_s7b: X64StandaloneInheritedNative {
                evidence_schema_version: version,
                runner_schema_version: version,
                runner_policy_version: version,
                syscall_policy_version: version,
                entry_policy_version: version,
                process_schema_version: version,
                process_policy_version: version,
                ipc_schema_version: version,
                manifest_hash: hash,
                semantic_results_hash: hash,
                process_results_hash: hash,
                limits: X64NativeLimits::r1_s7b(),
                process_limits: X64StandaloneInheritedProcessLimits {
                    timeout_millis: 0,
                    max_diagnostic_bytes: 0,
                    max_diagnostic_records: 0,
                    max_record_bytes: 0,
                },
                usage: X64StandaloneInheritedNativeUsage {
                    correspondence_records: 0,
                    process_receipts: 0,
                    selected_profile_records: 0,
                    selected_profile_code_mappings: 0,
                    selected_profile_mapped_code_bytes: 0,
                    selected_profile_borrowed_arrays: 0,
                    selected_profile_output_words: 0,
                    selected_profile_mapping_state_events: 0,
                    selected_profile_machine_ir_effects: 0,
                    selected_profile_native_effects: 0,
                    fallback_records: 0,
                    captured_diagnostic_bytes: 0,
                    captured_diagnostic_records: 0,
                },
            },
            structural_erasure: true,
            upstream_interpreter_dependency: false,
            fallback: false,
        }
    }

    const fn blank_translation_correspondence_limits() -> TranslationCorrespondenceLimits {
        TranslationCorrespondenceLimits {
            total_cases: 0,
            branch_cases: 0,
            bounds_cases: 0,
            max_array_elements_per_case: 0,
            max_total_array_elements: 0,
            max_effects_per_observation: 0,
            steps_per_case: 0,
            call_depth: 0,
            max_total_steps_per_engine: 0,
        }
    }
}
