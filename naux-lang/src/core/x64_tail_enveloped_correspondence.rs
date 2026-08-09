//! Finite ADR-0068 correspondence over the exact sovereign enveloped image.
//!
//! This module independently regenerates the two frozen Gate A workloads from
//! CoreVM0 through the accepted target and tail-image stages. It imports no
//! historical raw/native/process/standalone execution authority. The only
//! executable consumer is the typed ADR-0068 W^X runner.

use super::core_ssa::{lower_core_ssa_r1_s5, CoreSsaArtifact};
use super::corevm0::{branch_mix_kernel_program, CoreVmProgram};
use super::corevm0_definitional::build_definitional_corevm0;
use super::corevm0_gate_a::{
    bounds_ordered_array_get_program, corevm0_gate_a_case_input_hash, corevm0_gate_a_manifest,
    CoreVmGateAEffect, CoreVmGateAError, CoreVmGateAF64, CoreVmGateAOutcome, CoreVmGateAWorkload,
    COREVM0_GATE_A_CALL_DEPTH_LIMIT, COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
    COREVM0_GATE_A_TOTAL_CASES,
};
use super::corevm0_r1_s4::{specialize_corevm0_r1_s4, CoreVmR1S4Specialization};
use super::encoding::sha256;
use super::interpret::{CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome};
use super::machine_ir::{lower_machine_ir_r1_s6, MachineIrArtifact};
use super::polyvariant_r1_s4::PolyvariantR1S4Budget;
use super::schema::{ErrorKind, Mutability, RegionId, SemanticHash, Type};
use super::specialization::{
    validate_specialization_r0a_request, SpecializationBudget, SpecializationRequest,
    SpecializationSlot,
};
use super::staging::{
    certify_binding_time_b0d, validate_binding_time_b0_request, BindingTime, BindingTimeBudget,
    BindingTimeRequest,
};
use super::x64_tail_abi_envelope::{
    emit_x64_tail_abi_envelope_capsule, verify_x64_tail_abi_envelope_capsule,
    X64TailAbiEnvelopeCapsule,
};
use super::x64_tail_body_frontier_capsule::{
    emit_x64_tail_body_frontier_capsule, X64TailBodyFrontierCapsule,
};
use super::x64_tail_body_frontier_realization::{
    emit_x64_tail_body_frontier_realization, X64TailBodyFrontierRealization,
};
use super::x64_tail_candidate_capsule::{emit_x64_tail_candidate_capsule, X64TailCandidateCapsule};
use super::x64_tail_closed_image::{
    emit_x64_tail_closed_image, verify_x64_tail_closed_image, X64TailClosedImage,
};
use super::x64_tail_enveloped_image::{
    emit_x64_tail_enveloped_image, verify_x64_tail_enveloped_image, VerifiedX64TailEnvelopedImage,
    X64TailEnvelopedImage,
};
use super::x64_tail_enveloped_native::{
    execute_x64_tail_enveloped_native_canonical_mxcsr, X64TailEnvelopedNativeExecution,
    X64TailEnvelopedNativeMappingState, X64TailEnvelopedNativeRunnerError,
};
use super::x64_tail_site_binding::{emit_x64_tail_site_binding_proof, X64TailSiteBindingProof};
use super::x64_tail_state_allocation::{
    emit_x64_tail_physical_allocation, X64TailPhysicalAllocation,
};
use super::x64_tail_state_plan::{emit_x64_tail_state_plan, X64TailStatePlan};
use super::x64_tail_template_realization::{
    emit_x64_tail_template_realization, X64TailTemplateRealization,
};
use super::x64_target::{
    evaluate_x64_target_plan, lower_x64_target_r1_s7a, verify_x64_target_source, X64TargetArtifact,
};
use std::fmt;

pub const X64_TAIL_ENVELOPED_CORRESPONDENCE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_CORRESPONDENCE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES: u32 = 51;
pub const X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_RECORDS: u32 = 64;
pub const X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_EFFECTS_PER_RECORD: u32 = 1;
pub const X64_TAIL_ENVELOPED_CORRESPONDENCE_ACCEPTED_ROOT: SemanticHash = SemanticHash([
    0xde, 0xfe, 0xf4, 0x3d, 0x36, 0xe6, 0xeb, 0x01, 0xd2, 0x1e, 0xf5, 0xcb, 0x3a, 0x2f, 0x89, 0xd7,
    0x4b, 0x67, 0x5f, 0xff, 0x42, 0xa8, 0x19, 0xe9, 0x40, 0xae, 0xc9, 0xcb, 0xbd, 0x29, 0xe3, 0xd2,
]);

const RECORD_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-correspondence-record:v1\0";
const RESULTS_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-correspondence-results:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-correspondence-evidence:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailEnvelopedCorrespondenceRecord {
    pub(super) case_ordinal: u32,
    pub(super) workload: CoreVmGateAWorkload,
    pub(super) input_hash: SemanticHash,
    pub(super) target_semantic_hash: SemanticHash,
    pub(super) target_plan_hash: SemanticHash,
    pub(super) image_hash: SemanticHash,
    pub(super) code_hash: SemanticHash,
    pub(super) entry_point: u32,
    pub(super) input_lanes: u8,
    pub(super) copied_rw_code_hash: SemanticHash,
    pub(super) readback_rx_code_hash: SemanticHash,
    pub(super) mapping_trace: [X64TailEnvelopedNativeMappingState; 4],
    pub(super) mxcsr_before: u32,
    pub(super) mxcsr_after: u32,
    pub(super) outcome: CoreVmGateAOutcome,
    pub(super) effect_trace: Vec<CoreVmGateAEffect>,
    pub(super) teardown: bool,
    pub(super) fallback: bool,
    pub(super) record_hash: SemanticHash,
}

impl X64TailEnvelopedCorrespondenceRecord {
    pub const fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub const fn workload(&self) -> CoreVmGateAWorkload {
        self.workload
    }

    pub const fn input_hash(&self) -> SemanticHash {
        self.input_hash
    }

    pub const fn image_hash(&self) -> SemanticHash {
        self.image_hash
    }

    pub const fn code_hash(&self) -> SemanticHash {
        self.code_hash
    }

    pub const fn outcome(&self) -> CoreVmGateAOutcome {
        self.outcome
    }

    pub fn effect_trace(&self) -> &[CoreVmGateAEffect] {
        &self.effect_trace
    }

    pub const fn record_hash(&self) -> SemanticHash {
        self.record_hash
    }

    pub const fn fallback(&self) -> bool {
        self.fallback
    }

    pub const fn teardown(&self) -> bool {
        self.teardown
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailEnvelopedCorrespondenceEvidence {
    pub(super) schema_version: (u16, u16, u16),
    pub(super) policy_version: (u16, u16, u16),
    pub(super) corpus_manifest_hash: SemanticHash,
    pub(super) branch_target_semantic_hash: SemanticHash,
    pub(super) branch_image_hash: SemanticHash,
    pub(super) branch_code_hash: SemanticHash,
    pub(super) bounds_target_semantic_hash: SemanticHash,
    pub(super) bounds_image_hash: SemanticHash,
    pub(super) bounds_code_hash: SemanticHash,
    pub(super) records: Vec<X64TailEnvelopedCorrespondenceRecord>,
    pub(super) results_hash: SemanticHash,
    pub(super) evidence_hash: SemanticHash,
}

impl X64TailEnvelopedCorrespondenceEvidence {
    pub const fn schema_version(&self) -> (u16, u16, u16) {
        self.schema_version
    }

    pub const fn policy_version(&self) -> (u16, u16, u16) {
        self.policy_version
    }

    pub const fn corpus_manifest_hash(&self) -> SemanticHash {
        self.corpus_manifest_hash
    }

    pub fn records(&self) -> &[X64TailEnvelopedCorrespondenceRecord] {
        &self.records
    }

    pub const fn results_hash(&self) -> SemanticHash {
        self.results_hash
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailEnvelopedCorrespondence<'evidence> {
    evidence: &'evidence X64TailEnvelopedCorrespondenceEvidence,
}

/// Opaque parent-side witness for complete structural and target-plan replay.
///
/// Unlike `VerifiedX64TailEnvelopedCorrespondence`, constructing this witness
/// never maps or invokes machine code. It is the exact authority consumed by
/// ADR-0069 after untrusted child bytes have passed the IPC decoder.
#[derive(Debug)]
pub struct VerifiedX64TailEnvelopedObservations<'evidence> {
    evidence: &'evidence X64TailEnvelopedCorrespondenceEvidence,
}

impl<'evidence> VerifiedX64TailEnvelopedObservations<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailEnvelopedCorrespondenceEvidence {
        self.evidence
    }
}

impl<'evidence> VerifiedX64TailEnvelopedCorrespondence<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailEnvelopedCorrespondenceEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedCorrespondenceError {
    Manifest(CoreVmGateAError),
    Pipeline {
        workload: CoreVmGateAWorkload,
        stage: &'static str,
        message: String,
    },
    Native(String),
    InvalidField {
        field: &'static str,
    },
    NonCanonicalOrdinal {
        expected: u32,
        actual: u32,
    },
    SemanticMismatch {
        case_ordinal: u32,
    },
    RecordHashMismatch {
        case_ordinal: u32,
    },
    ResultsHashMismatch,
    EvidenceHashMismatch,
    ReplayMismatch,
    MetricOverflow,
}

impl fmt::Display for X64TailEnvelopedCorrespondenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(formatter, "cannot regenerate Gate A: {error}"),
            Self::Pipeline {
                workload,
                stage,
                message,
            } => write!(formatter, "{workload:?} {stage} failed: {message}"),
            Self::Native(message) => {
                write!(formatter, "sovereign native execution failed: {message}")
            }
            Self::InvalidField { field } => write!(formatter, "invalid ADR-0068 {field}"),
            Self::NonCanonicalOrdinal { expected, actual } => write!(
                formatter,
                "ADR-0068 case ordinal is {actual}; canonical ordinal is {expected}"
            ),
            Self::SemanticMismatch { case_ordinal } => {
                write!(
                    formatter,
                    "ADR-0068 semantic mismatch at case {case_ordinal}"
                )
            }
            Self::RecordHashMismatch { case_ordinal } => {
                write!(
                    formatter,
                    "ADR-0068 record hash mismatch at case {case_ordinal}"
                )
            }
            Self::ResultsHashMismatch => formatter.write_str("ADR-0068 results hash mismatch"),
            Self::EvidenceHashMismatch => formatter.write_str("ADR-0068 evidence hash mismatch"),
            Self::ReplayMismatch => formatter.write_str("ADR-0068 independent replay mismatch"),
            Self::MetricOverflow => formatter.write_str("ADR-0068 metric overflow"),
        }
    }
}

impl std::error::Error for X64TailEnvelopedCorrespondenceError {}

impl From<CoreVmGateAError> for X64TailEnvelopedCorrespondenceError {
    fn from(value: CoreVmGateAError) -> Self {
        Self::Manifest(value)
    }
}

impl From<X64TailEnvelopedNativeRunnerError> for X64TailEnvelopedCorrespondenceError {
    fn from(value: X64TailEnvelopedNativeRunnerError) -> Self {
        Self::Native(value.to_string())
    }
}

struct SovereignPackage {
    workload: CoreVmGateAWorkload,
    specialization: CoreVmR1S4Specialization,
    ssa: CoreSsaArtifact,
    machine: MachineIrArtifact,
    target: X64TargetArtifact,
    logical: X64TailStatePlan,
    physical: X64TailPhysicalAllocation,
    templates: X64TailTemplateRealization,
    transition: X64TailCandidateCapsule,
    binding: X64TailSiteBindingProof,
    realization: X64TailBodyFrontierRealization,
    body: X64TailBodyFrontierCapsule,
    closed: X64TailClosedImage,
    abi: X64TailAbiEnvelopeCapsule,
    image: X64TailEnvelopedImage,
}

impl SovereignPackage {
    fn build(workload: CoreVmGateAWorkload) -> Result<Self, X64TailEnvelopedCorrespondenceError> {
        let (program, dynamic_types) = match workload {
            CoreVmGateAWorkload::BranchMix => (
                branch_mix_kernel_program(),
                vec![array_f64_type(), Type::I64],
            ),
            CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                (bounds_ordered_array_get_program(), vec![array_f64_type()])
            }
        };
        let specialization = specialize_program(workload, &program, dynamic_types)?;
        let residual = specialization.artifact();
        let ssa = lower_core_ssa_r1_s5(residual)
            .map_err(|error| pipeline(workload, "R1-S5 lowering", error))?;
        let machine = lower_machine_ir_r1_s6(&ssa, residual)
            .map_err(|error| pipeline(workload, "R1-S6 lowering", error))?;
        let target = lower_x64_target_r1_s7a(&machine, &ssa, residual)
            .map_err(|error| pipeline(workload, "R1-S7a lowering", error))?;
        verify_x64_target_source(&target, &machine, &ssa, residual)
            .map_err(|error| pipeline(workload, "R1-S7a source replay", error))?;

        let logical = emit_x64_tail_state_plan(&target)
            .map_err(|error| pipeline(workload, "ADR-0057 state plan", error))?;
        let physical = emit_x64_tail_physical_allocation(&target, &logical)
            .map_err(|error| pipeline(workload, "ADR-0058 allocation", error))?;
        let templates = emit_x64_tail_template_realization(&target, &logical, &physical)
            .map_err(|error| pipeline(workload, "ADR-0059 templates", error))?;
        let transition = emit_x64_tail_candidate_capsule(&target, &logical, &physical, &templates)
            .map_err(|error| pipeline(workload, "ADR-0060 capsule", error))?;
        let binding =
            emit_x64_tail_site_binding_proof(&target, &logical, &physical, &templates, &transition)
                .map_err(|error| pipeline(workload, "ADR-0061 binding", error))?;
        let realization = emit_x64_tail_body_frontier_realization(
            &target,
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
        )
        .map_err(|error| pipeline(workload, "ADR-0062 realization", error))?;
        let body = emit_x64_tail_body_frontier_capsule(
            &target,
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
            &realization,
        )
        .map_err(|error| pipeline(workload, "ADR-0064 body capsule", error))?;
        let closed = emit_x64_tail_closed_image(
            &target,
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
            &realization,
            &body,
        )
        .map_err(|error| pipeline(workload, "ADR-0065 closed image", error))?;
        let verified_closed = verify_x64_tail_closed_image(
            &closed,
            &body,
            &realization,
            &binding,
            &transition,
            &templates,
            &physical,
            &logical,
            &target,
        )
        .map_err(|error| pipeline(workload, "ADR-0065 closed replay", error))?;
        let abi = emit_x64_tail_abi_envelope_capsule(&target, &verified_closed)
            .map_err(|error| pipeline(workload, "ADR-0066 ABI capsule", error))?;
        let verified_abi = verify_x64_tail_abi_envelope_capsule(&abi, &target, &verified_closed)
            .map_err(|error| pipeline(workload, "ADR-0066 ABI replay", error))?;
        let image = emit_x64_tail_enveloped_image(&target, &verified_closed, &verified_abi)
            .map_err(|error| pipeline(workload, "ADR-0067 image", error))?;

        Ok(Self {
            workload,
            specialization,
            ssa,
            machine,
            target,
            logical,
            physical,
            templates,
            transition,
            binding,
            realization,
            body,
            closed,
            abi,
            image,
        })
    }

    fn verified_image(
        &self,
    ) -> Result<VerifiedX64TailEnvelopedImage<'_>, X64TailEnvelopedCorrespondenceError> {
        verify_x64_target_source(
            &self.target,
            &self.machine,
            &self.ssa,
            self.specialization.artifact(),
        )
        .map_err(|error| pipeline(self.workload, "R1-S7a source replay", error))?;
        let closed = verify_x64_tail_closed_image(
            &self.closed,
            &self.body,
            &self.realization,
            &self.binding,
            &self.transition,
            &self.templates,
            &self.physical,
            &self.logical,
            &self.target,
        )
        .map_err(|error| pipeline(self.workload, "ADR-0065 closed replay", error))?;
        let abi = verify_x64_tail_abi_envelope_capsule(&self.abi, &self.target, &closed)
            .map_err(|error| pipeline(self.workload, "ADR-0066 ABI replay", error))?;
        verify_x64_tail_enveloped_image(&self.image, &self.target, &closed, &abi)
            .map_err(|error| pipeline(self.workload, "ADR-0067 image replay", error))
    }
}

/// Emit the exact ordered 51-case sovereign native correspondence evidence.
pub fn emit_x64_tail_enveloped_correspondence(
) -> Result<X64TailEnvelopedCorrespondenceEvidence, X64TailEnvelopedCorrespondenceError> {
    let manifest = corevm0_gate_a_manifest()?;
    validate_manifest_size(manifest.total_cases, manifest.cases.len())?;
    let branch = SovereignPackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bounds = SovereignPackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?;
    let mut records = Vec::with_capacity(manifest.cases.len());
    for (index, case) in manifest.cases.iter().enumerate() {
        let expected = u32::try_from(index)
            .map_err(|_| X64TailEnvelopedCorrespondenceError::MetricOverflow)?;
        if case.ordinal != expected {
            return Err(X64TailEnvelopedCorrespondenceError::NonCanonicalOrdinal {
                expected,
                actual: case.ordinal,
            });
        }
        let package = package_for(case.workload, &branch, &bounds);
        records.push(execute_case(package, case)?);
    }
    let mut evidence = X64TailEnvelopedCorrespondenceEvidence {
        schema_version: X64_TAIL_ENVELOPED_CORRESPONDENCE_SCHEMA_VERSION,
        policy_version: X64_TAIL_ENVELOPED_CORRESPONDENCE_POLICY_VERSION,
        corpus_manifest_hash: manifest.manifest_hash,
        branch_target_semantic_hash: branch.target.semantic_hash,
        branch_image_hash: branch.image.image_hash(),
        branch_code_hash: branch.image.code_hash(),
        bounds_target_semantic_hash: bounds.target.semantic_hash,
        bounds_image_hash: bounds.image.image_hash(),
        bounds_code_hash: bounds.image.code_hash(),
        records,
        results_hash: SemanticHash::ZERO,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.results_hash = x64_tail_enveloped_correspondence_results_hash(&evidence)?;
    evidence.evidence_hash = x64_tail_enveloped_correspondence_evidence_hash(&evidence)?;
    Ok(evidence)
}

/// Verify the complete finite observation without executing machine code.
///
/// This is intentionally distinct from ADR-0068 native replay. It rebuilds
/// both sovereign source/image packages and regenerates every target-plan
/// oracle result, but treats the W^X observation as untrusted input. ADR-0069
/// uses it only after exact bounded IPC decoding.
pub fn verify_x64_tail_enveloped_observations<'evidence>(
    evidence: &'evidence X64TailEnvelopedCorrespondenceEvidence,
) -> Result<VerifiedX64TailEnvelopedObservations<'evidence>, X64TailEnvelopedCorrespondenceError> {
    let manifest = corevm0_gate_a_manifest()?;
    validate_manifest_size(manifest.total_cases, manifest.cases.len())?;
    validate_evidence_shape(evidence, manifest.manifest_hash, &manifest.cases)?;
    let branch = SovereignPackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bounds = SovereignPackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?;
    validate_package_identities(evidence, &branch, &bounds)?;

    for (case, record) in manifest.cases.iter().zip(&evidence.records) {
        let package = package_for(case.workload, &branch, &bounds);
        let expected = evaluate_x64_target_plan(
            &package.target,
            case_arguments(case),
            EvaluationBudget::new(
                COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
                COREVM0_GATE_A_CALL_DEPTH_LIMIT,
            ),
        )
        .map_err(|error| pipeline(case.workload, "target-plan oracle", error))?;
        let (outcome, effects) = canonical_observation(&expected)?;
        if record.outcome != outcome || record.effect_trace != effects {
            return Err(X64TailEnvelopedCorrespondenceError::SemanticMismatch {
                case_ordinal: case.ordinal,
            });
        }
    }

    Ok(VerifiedX64TailEnvelopedObservations { evidence })
}

/// Replay corpus identity, every record seal, both complete source/image
/// chains, the ordinary target-plan oracle, and all 51 sovereign executions.
pub fn verify_x64_tail_enveloped_correspondence<'evidence>(
    evidence: &'evidence X64TailEnvelopedCorrespondenceEvidence,
) -> Result<VerifiedX64TailEnvelopedCorrespondence<'evidence>, X64TailEnvelopedCorrespondenceError>
{
    let manifest = corevm0_gate_a_manifest()?;
    validate_manifest_size(manifest.total_cases, manifest.cases.len())?;
    validate_evidence_shape(evidence, manifest.manifest_hash, &manifest.cases)?;
    let branch = SovereignPackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bounds = SovereignPackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?;
    validate_package_identities(evidence, &branch, &bounds)?;

    for (case, record) in manifest.cases.iter().zip(&evidence.records) {
        let package = package_for(case.workload, &branch, &bounds);
        let replayed = execute_case(package, case)?;
        if !records_semantically_equal(record, &replayed) {
            return Err(X64TailEnvelopedCorrespondenceError::ReplayMismatch);
        }
    }
    Ok(VerifiedX64TailEnvelopedCorrespondence { evidence })
}

pub fn x64_tail_enveloped_correspondence_record_hash(
    record: &X64TailEnvelopedCorrespondenceRecord,
) -> Result<SemanticHash, X64TailEnvelopedCorrespondenceError> {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(RECORD_DOMAIN);
    put_u32(&mut bytes, record.case_ordinal);
    bytes.push(workload_tag(record.workload));
    put_hash(&mut bytes, record.input_hash);
    put_hash(&mut bytes, record.target_semantic_hash);
    put_hash(&mut bytes, record.target_plan_hash);
    put_hash(&mut bytes, record.image_hash);
    put_hash(&mut bytes, record.code_hash);
    put_u32(&mut bytes, record.entry_point);
    bytes.push(record.input_lanes);
    put_hash(&mut bytes, record.copied_rw_code_hash);
    put_hash(&mut bytes, record.readback_rx_code_hash);
    for state in record.mapping_trace {
        bytes.push(mapping_state_tag(state));
    }
    put_u32(&mut bytes, record.mxcsr_before);
    put_u32(&mut bytes, record.mxcsr_after);
    encode_outcome(&mut bytes, record.outcome);
    put_u32(
        &mut bytes,
        u32::try_from(record.effect_trace.len())
            .map_err(|_| X64TailEnvelopedCorrespondenceError::MetricOverflow)?,
    );
    for effect in &record.effect_trace {
        bytes.push(effect_tag(*effect));
    }
    bytes.push(u8::from(record.teardown));
    bytes.push(u8::from(record.fallback));
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn x64_tail_enveloped_correspondence_results_hash(
    evidence: &X64TailEnvelopedCorrespondenceEvidence,
) -> Result<SemanticHash, X64TailEnvelopedCorrespondenceError> {
    let mut bytes = Vec::with_capacity(RESULTS_DOMAIN.len() + evidence.records.len() * 32 + 4);
    bytes.extend_from_slice(RESULTS_DOMAIN);
    put_u32(
        &mut bytes,
        u32::try_from(evidence.records.len())
            .map_err(|_| X64TailEnvelopedCorrespondenceError::MetricOverflow)?,
    );
    for record in &evidence.records {
        put_hash(&mut bytes, record.record_hash);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn x64_tail_enveloped_correspondence_evidence_hash(
    evidence: &X64TailEnvelopedCorrespondenceEvidence,
) -> Result<SemanticHash, X64TailEnvelopedCorrespondenceError> {
    let mut bytes = Vec::with_capacity(EVIDENCE_DOMAIN.len() + 32 * 8 + 32);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.corpus_manifest_hash);
    put_hash(&mut bytes, evidence.branch_target_semantic_hash);
    put_hash(&mut bytes, evidence.branch_image_hash);
    put_hash(&mut bytes, evidence.branch_code_hash);
    put_hash(&mut bytes, evidence.bounds_target_semantic_hash);
    put_hash(&mut bytes, evidence.bounds_image_hash);
    put_hash(&mut bytes, evidence.bounds_code_hash);
    put_hash(&mut bytes, evidence.results_hash);
    Ok(SemanticHash(sha256(&bytes)))
}

fn execute_case(
    package: &SovereignPackage,
    case: &super::corevm0_gate_a::CoreVmGateACase,
) -> Result<X64TailEnvelopedCorrespondenceRecord, X64TailEnvelopedCorrespondenceError> {
    if package.workload != case.workload || corevm0_gate_a_case_input_hash(case)? != case.input_hash
    {
        return Err(X64TailEnvelopedCorrespondenceError::InvalidField {
            field: "canonical case binding",
        });
    }
    let arguments = case_arguments(case);
    let expected = evaluate_x64_target_plan(
        &package.target,
        arguments.clone(),
        EvaluationBudget::new(
            COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
            COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        ),
    )
    .map_err(|error| pipeline(case.workload, "target-plan oracle", error))?;
    let verified = package.verified_image()?;
    let native =
        execute_x64_tail_enveloped_native_canonical_mxcsr(&package.target, &verified, &arguments)?;
    let expected_observation = canonical_observation(&expected)?;
    let native_observation = canonical_native_observation(&native)?;
    if expected_observation != native_observation {
        return Err(X64TailEnvelopedCorrespondenceError::SemanticMismatch {
            case_ordinal: case.ordinal,
        });
    }
    if native.mxcsr_before() != package.target.program.abi.canonical_mxcsr
        || native.mxcsr_after() != native.mxcsr_before()
    {
        return Err(X64TailEnvelopedCorrespondenceError::InvalidField {
            field: "canonical MXCSR execution",
        });
    }

    let mut record = X64TailEnvelopedCorrespondenceRecord {
        case_ordinal: case.ordinal,
        workload: case.workload,
        input_hash: case.input_hash,
        target_semantic_hash: package.target.semantic_hash,
        target_plan_hash: package.target.program.plan_hash,
        image_hash: package.image.image_hash(),
        code_hash: package.image.code_hash(),
        entry_point: native.entry_point(),
        input_lanes: native.input_lanes(),
        copied_rw_code_hash: native.copied_rw_code_hash(),
        readback_rx_code_hash: native.readback_rx_code_hash(),
        mapping_trace: native.mapping_trace(),
        mxcsr_before: native.mxcsr_before(),
        mxcsr_after: native.mxcsr_after(),
        outcome: native_observation.0,
        effect_trace: native_observation.1,
        teardown: native.mapping_trace()[3] == X64TailEnvelopedNativeMappingState::Unmapped,
        fallback: native.fallback(),
        record_hash: SemanticHash::ZERO,
    };
    record.record_hash = x64_tail_enveloped_correspondence_record_hash(&record)?;
    Ok(record)
}

fn validate_evidence_shape(
    evidence: &X64TailEnvelopedCorrespondenceEvidence,
    manifest_hash: SemanticHash,
    cases: &[super::corevm0_gate_a::CoreVmGateACase],
) -> Result<(), X64TailEnvelopedCorrespondenceError> {
    if evidence.schema_version != X64_TAIL_ENVELOPED_CORRESPONDENCE_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_ENVELOPED_CORRESPONDENCE_POLICY_VERSION
        || evidence.corpus_manifest_hash != manifest_hash
        || evidence.records.len() != X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES as usize
        || evidence.records.len() > X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_RECORDS as usize
    {
        return Err(X64TailEnvelopedCorrespondenceError::InvalidField {
            field: "aggregate envelope",
        });
    }
    for (index, (case, record)) in cases.iter().zip(&evidence.records).enumerate() {
        let expected = u32::try_from(index)
            .map_err(|_| X64TailEnvelopedCorrespondenceError::MetricOverflow)?;
        if case.ordinal != expected || record.case_ordinal != expected {
            return Err(X64TailEnvelopedCorrespondenceError::NonCanonicalOrdinal {
                expected,
                actual: record.case_ordinal,
            });
        }
        if record.workload != case.workload
            || record.input_hash != case.input_hash
            || record.effect_trace.len()
                > X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_EFFECTS_PER_RECORD as usize
            || record.mapping_trace
                != [
                    X64TailEnvelopedNativeMappingState::Unmapped,
                    X64TailEnvelopedNativeMappingState::ReadWrite,
                    X64TailEnvelopedNativeMappingState::ReadExecute,
                    X64TailEnvelopedNativeMappingState::Unmapped,
                ]
            || !record.teardown
            || record.fallback
            || record.mxcsr_before != record.mxcsr_after
            || record.code_hash != record.copied_rw_code_hash
            || record.code_hash != record.readback_rx_code_hash
        {
            return Err(X64TailEnvelopedCorrespondenceError::InvalidField {
                field: "record envelope",
            });
        }
        if x64_tail_enveloped_correspondence_record_hash(record)? != record.record_hash {
            return Err(X64TailEnvelopedCorrespondenceError::RecordHashMismatch {
                case_ordinal: record.case_ordinal,
            });
        }
    }
    if x64_tail_enveloped_correspondence_results_hash(evidence)? != evidence.results_hash {
        return Err(X64TailEnvelopedCorrespondenceError::ResultsHashMismatch);
    }
    if x64_tail_enveloped_correspondence_evidence_hash(evidence)? != evidence.evidence_hash {
        return Err(X64TailEnvelopedCorrespondenceError::EvidenceHashMismatch);
    }
    Ok(())
}

fn validate_package_identities(
    evidence: &X64TailEnvelopedCorrespondenceEvidence,
    branch: &SovereignPackage,
    bounds: &SovereignPackage,
) -> Result<(), X64TailEnvelopedCorrespondenceError> {
    if evidence.branch_target_semantic_hash != branch.target.semantic_hash
        || evidence.branch_image_hash != branch.image.image_hash()
        || evidence.branch_code_hash != branch.image.code_hash()
        || evidence.bounds_target_semantic_hash != bounds.target.semantic_hash
        || evidence.bounds_image_hash != bounds.image.image_hash()
        || evidence.bounds_code_hash != bounds.image.code_hash()
    {
        return Err(X64TailEnvelopedCorrespondenceError::InvalidField {
            field: "source identities",
        });
    }
    for record in &evidence.records {
        let package = package_for(record.workload, branch, bounds);
        let input_lanes = u8::try_from(package.target.program.entry_abi.input_lanes.len())
            .map_err(|_| X64TailEnvelopedCorrespondenceError::MetricOverflow)?;
        if record.target_semantic_hash != package.target.semantic_hash
            || record.target_plan_hash != package.target.program.plan_hash
            || record.image_hash != package.image.image_hash()
            || record.code_hash != package.image.code_hash()
            || record.entry_point != package.image.entry_point()
            || record.input_lanes != input_lanes
            || record.mxcsr_before != package.target.program.abi.canonical_mxcsr
            || record.mxcsr_after != package.target.program.abi.canonical_mxcsr
        {
            return Err(X64TailEnvelopedCorrespondenceError::InvalidField {
                field: "record source identity",
            });
        }
    }
    Ok(())
}

fn records_semantically_equal(
    recorded: &X64TailEnvelopedCorrespondenceRecord,
    replayed: &X64TailEnvelopedCorrespondenceRecord,
) -> bool {
    recorded.case_ordinal == replayed.case_ordinal
        && recorded.workload == replayed.workload
        && recorded.input_hash == replayed.input_hash
        && recorded.target_semantic_hash == replayed.target_semantic_hash
        && recorded.target_plan_hash == replayed.target_plan_hash
        && recorded.image_hash == replayed.image_hash
        && recorded.code_hash == replayed.code_hash
        && recorded.entry_point == replayed.entry_point
        && recorded.input_lanes == replayed.input_lanes
        && recorded.copied_rw_code_hash == replayed.copied_rw_code_hash
        && recorded.readback_rx_code_hash == replayed.readback_rx_code_hash
        && recorded.mapping_trace == replayed.mapping_trace
        && recorded.mxcsr_before == replayed.mxcsr_before
        && recorded.mxcsr_after == replayed.mxcsr_after
        && recorded.outcome == replayed.outcome
        && recorded.effect_trace == replayed.effect_trace
        && recorded.teardown == replayed.teardown
        && recorded.fallback == replayed.fallback
        && recorded.record_hash == replayed.record_hash
}

fn canonical_native_observation(
    execution: &X64TailEnvelopedNativeExecution,
) -> Result<(CoreVmGateAOutcome, Vec<CoreVmGateAEffect>), X64TailEnvelopedCorrespondenceError> {
    canonical_outcome_and_effects(execution.outcome(), execution.effect_trace())
}

fn canonical_observation(
    evaluation: &Evaluation,
) -> Result<(CoreVmGateAOutcome, Vec<CoreVmGateAEffect>), X64TailEnvelopedCorrespondenceError> {
    canonical_outcome_and_effects(&evaluation.outcome, &evaluation.effect_trace)
}

fn canonical_outcome_and_effects(
    outcome: &EvaluationOutcome,
    effects: &[EffectEvent],
) -> Result<(CoreVmGateAOutcome, Vec<CoreVmGateAEffect>), X64TailEnvelopedCorrespondenceError> {
    let outcome = match outcome {
        EvaluationOutcome::Return(CoreValue::F64(value)) if value.is_nan() => {
            CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::CanonicalNaN)
        }
        EvaluationOutcome::Return(CoreValue::F64(value)) => {
            CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::ExactBits(value.to_bits()))
        }
        EvaluationOutcome::Error(ErrorKind::Bounds) => CoreVmGateAOutcome::Bounds,
        _ => {
            return Err(X64TailEnvelopedCorrespondenceError::InvalidField {
                field: "finite outcome",
            });
        }
    };
    let effects = effects
        .iter()
        .map(|effect| match effect {
            EffectEvent::Error(ErrorKind::Bounds) => Ok(CoreVmGateAEffect::Bounds),
            _ => Err(X64TailEnvelopedCorrespondenceError::InvalidField {
                field: "finite effect",
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((outcome, effects))
}

fn case_arguments(case: &super::corevm0_gate_a::CoreVmGateACase) -> Vec<CoreValue> {
    let values = case
        .input
        .array_f64_bits
        .iter()
        .copied()
        .map(f64::from_bits)
        .collect::<Vec<_>>();
    let mut arguments = vec![CoreValue::array_f64(values)];
    if case.workload == CoreVmGateAWorkload::BranchMix {
        arguments.push(CoreValue::I64(case.input.repetitions));
    }
    arguments
}

fn package_for<'package>(
    workload: CoreVmGateAWorkload,
    branch: &'package SovereignPackage,
    bounds: &'package SovereignPackage,
) -> &'package SovereignPackage {
    match workload {
        CoreVmGateAWorkload::BranchMix => branch,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => bounds,
    }
}

fn validate_manifest_size(
    declared: u32,
    actual: usize,
) -> Result<(), X64TailEnvelopedCorrespondenceError> {
    if COREVM0_GATE_A_TOTAL_CASES != X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES
        || declared != X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES
        || actual != X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES as usize
        || actual > X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_RECORDS as usize
    {
        return Err(X64TailEnvelopedCorrespondenceError::InvalidField {
            field: "fixed corpus size",
        });
    }
    Ok(())
}

fn specialize_program(
    workload: CoreVmGateAWorkload,
    program: &CoreVmProgram,
    dynamic_types: Vec<Type>,
) -> Result<CoreVmR1S4Specialization, X64TailEnvelopedCorrespondenceError> {
    let bound = build_definitional_corevm0(program)
        .map_err(|error| pipeline(workload, "CoreVM0 definitional build", error))?;
    let mut manifest = vec![BindingTime::Static];
    manifest.extend(std::iter::repeat_n(
        BindingTime::Dynamic,
        dynamic_types.len(),
    ));
    let binding = BindingTimeRequest::p1v0(
        bound.artifact(),
        manifest,
        BindingTimeBudget::new(1_000_000, 1_000_000, 10_000),
    )
    .map_err(|error| pipeline(workload, "B0 request", error))?;
    let validated_binding = validate_binding_time_b0_request(bound.artifact(), &binding)
        .map_err(|error| pipeline(workload, "B0 validation", error))?;
    let certificate = certify_binding_time_b0d(&validated_binding)
        .map_err(|error| pipeline(workload, "B0 certificate", error))?;
    let mut slots = vec![SpecializationSlot::Static(bound.program_image().clone())];
    slots.extend(dynamic_types.into_iter().map(SpecializationSlot::Dynamic));
    let request = SpecializationRequest::p1v0(
        bound.artifact(),
        &binding,
        &certificate,
        slots,
        SpecializationBudget::new(1_000_000, 1_000_000, 100_000_000, 1_000_000, 1_000_000_000),
    )
    .map_err(|error| pipeline(workload, "R0 request", error))?;
    let validated =
        validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
            .map_err(|error| pipeline(workload, "R0 validation", error))?;
    specialize_corevm0_r1_s4(&bound, &validated, fixed_s4_budget())
        .map_err(|error| pipeline(workload, "R1-S4 specialization", error))
}

fn array_f64_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn fixed_s4_budget() -> PolyvariantR1S4Budget {
    PolyvariantR1S4Budget::new(
        100_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000_000,
    )
}

fn pipeline(
    workload: CoreVmGateAWorkload,
    stage: &'static str,
    error: impl fmt::Display,
) -> X64TailEnvelopedCorrespondenceError {
    X64TailEnvelopedCorrespondenceError::Pipeline {
        workload,
        stage,
        message: error.to_string(),
    }
}

fn workload_tag(workload: CoreVmGateAWorkload) -> u8 {
    match workload {
        CoreVmGateAWorkload::BranchMix => 0,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => 1,
    }
}

fn mapping_state_tag(state: X64TailEnvelopedNativeMappingState) -> u8 {
    match state {
        X64TailEnvelopedNativeMappingState::Unmapped => 0,
        X64TailEnvelopedNativeMappingState::ReadWrite => 1,
        X64TailEnvelopedNativeMappingState::ReadExecute => 2,
    }
}

fn effect_tag(effect: CoreVmGateAEffect) -> u8 {
    match effect {
        CoreVmGateAEffect::Bounds => 0,
    }
}

fn encode_outcome(bytes: &mut Vec<u8>, outcome: CoreVmGateAOutcome) {
    match outcome {
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::ExactBits(bits)) => {
            bytes.push(0);
            put_u64(bytes, bits);
        }
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::CanonicalNaN) => bytes.push(1),
        CoreVmGateAOutcome::Bounds => bytes.push(2),
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    put_u16(bytes, version.0);
    put_u16(bytes, version.1);
    put_u16(bytes, version.2);
}

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn loop_carried_state_and_repetition_survive_the_ieee754_edge_case() {
        let package = SovereignPackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch sovereign package must build");
        let manifest = corevm0_gate_a_manifest().expect("canonical manifest must build");
        let case = &manifest.cases[6];
        let record = execute_case(&package, case).expect("case 6 must correspond");
        assert_eq!(
            record.outcome(),
            CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::ExactBits(0x8000_0000_0000_0004,))
        );
        assert!(record.effect_trace().is_empty());
    }

    #[test]
    fn exact_51_case_sovereign_correspondence_replays_without_fallback() {
        let evidence = emit_x64_tail_enveloped_correspondence()
            .expect("canonical sovereign correspondence must emit");
        let verified = verify_x64_tail_enveloped_correspondence(&evidence)
            .expect("canonical sovereign correspondence must replay");
        let observed = verify_x64_tail_enveloped_observations(&evidence)
            .expect("canonical observations must replay without native execution");
        assert_eq!(verified.evidence(), &evidence);
        assert_eq!(observed.evidence(), &evidence);
        assert_eq!(evidence.records().len(), 51);
        assert!(evidence.records().iter().all(|record| {
            record.teardown() && !record.fallback() && record.effect_trace().len() <= 1
        }));
        assert_eq!(
            evidence.evidence_hash().to_hex(),
            "defef43d36e6eb01d21ef5cb3a2f89d74b675fff42a819e940aec9cbbd29e3d2"
        );
    }

    #[test]
    fn resealed_semantic_mutation_fails_independent_replay() {
        let evidence = emit_x64_tail_enveloped_correspondence()
            .expect("canonical sovereign correspondence must emit");
        let mut mutated = evidence.clone();
        mutated.records[0].outcome = CoreVmGateAOutcome::Bounds;
        mutated.records[0].effect_trace = vec![CoreVmGateAEffect::Bounds];
        mutated.records[0].record_hash =
            x64_tail_enveloped_correspondence_record_hash(&mutated.records[0])
                .expect("mutated record must locally seal");
        mutated.results_hash = x64_tail_enveloped_correspondence_results_hash(&mutated)
            .expect("mutated result set must locally seal");
        mutated.evidence_hash = x64_tail_enveloped_correspondence_evidence_hash(&mutated)
            .expect("mutated evidence must locally seal");
        let frame = crate::core::encode_x64_tail_enveloped_ipc(&mutated)
            .expect("mutated child observation must encode canonically");
        let decoded = crate::core::decode_x64_tail_enveloped_ipc(&frame)
            .expect("mutated child observation must decode canonically");
        assert!(matches!(
            verify_x64_tail_enveloped_observations(&decoded),
            Err(X64TailEnvelopedCorrespondenceError::SemanticMismatch { case_ordinal: 0 })
        ));
        assert!(matches!(
            verify_x64_tail_enveloped_correspondence(&mutated),
            Err(X64TailEnvelopedCorrespondenceError::ReplayMismatch)
        ));
    }
}
