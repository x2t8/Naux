use super::corevm0::{
    corevm0_program_image_type, CoreVmProgram, COREVM0_INSTRUCTION_SLOT_SUM_NAME,
    COREVM0_INSTRUCTION_SUM_NAME, COREVM0_TYPE_SLOT_SUM_NAME,
};
use super::corevm0_definitional::{
    build_definitional_corevm0, DefinitionalCoreVmArtifact, DefinitionalCoreVmBuildError,
    COREVM0_BANK_UPDATE_SUM_NAME, COREVM0_RUNTIME_VALUE_SUM_NAME, COREVM0_VALUE_LOOKUP_SUM_NAME,
};
use super::encoding::{semantic_bytes, sha256, specialization_value_bytes, EncodeError};
use super::polyvariant_r1_s4::{
    specialize_polyvariant_r1_s4_with_control, PolyvariantR1S4Budget, PolyvariantR1S4Control,
    PolyvariantR1S4Error, PolyvariantR1S4Pattern, PolyvariantR1S4Report,
    PolyvariantR1S4Specialization, PolyvariantR1S4Usage,
};
use super::schema::{
    CoreArtifact, Function, FunctionId, RValue, SemanticHash, SumType, Term, Type,
};
use super::specialization::{
    validate_specialization_r0a_request, SpecializationRequest, SpecializationRequestErrors,
    SpecializationSlot, ValidatedSpecializationRequest,
};
use super::staging::{
    certify_binding_time_b0d, validate_binding_time_b0_request, BindingTimeCertificate,
    BindingTimeCertificateBuildError, BindingTimeRequest, BindingTimeRequestErrors,
};
use super::verify::verify;
use std::collections::BTreeSet;
use std::fmt;

pub const COREVM0_R1_S4_BINDING_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_R1_S4_ERASURE_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_R1_S4_EVIDENCE_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_R1_S4_REPLAY_VERSION: (u16, u16, u16) = (1, 0, 0);

const BINDING_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s4:binding:v1\0";
const ERASURE_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s4:erasure:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s4:evidence:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmR1S4ErasureReport {
    checker_version: (u16, u16, u16),
    erasure_hash: SemanticHash,
    residual_hash: SemanticHash,
    residual_functions: u64,
    loop_variants: u64,
    residual_nodes_scanned: u64,
    residual_calls: u64,
    residual_tail_calls: u64,
    residual_ifs: u64,
}

impl CoreVmR1S4ErasureReport {
    pub fn checker_version(&self) -> (u16, u16, u16) {
        self.checker_version
    }

    pub fn erasure_hash(&self) -> SemanticHash {
        self.erasure_hash
    }

    pub fn residual_hash(&self) -> SemanticHash {
        self.residual_hash
    }

    pub fn residual_functions(&self) -> u64 {
        self.residual_functions
    }

    pub fn loop_variants(&self) -> u64 {
        self.loop_variants
    }

    pub fn residual_nodes_scanned(&self) -> u64 {
        self.residual_nodes_scanned
    }

    pub fn residual_calls(&self) -> u64 {
        self.residual_calls
    }

    pub fn residual_tail_calls(&self) -> u64 {
        self.residual_tail_calls
    }

    pub fn residual_ifs(&self) -> u64 {
        self.residual_ifs
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreVmR1S4ErasureError {
    InvalidEntryVariant,
    MissingLoopVariant,
    UnexpectedSourceVariant {
        function: FunctionId,
    },
    DynamicControlAnchor {
        residual_function: FunctionId,
        parameter: u32,
    },
    ResidualEntryShape,
    InterpreterType {
        name: String,
    },
    ResidualDispatch {
        function: FunctionId,
    },
    ResidualHelperCall {
        function: FunctionId,
        target: FunctionId,
    },
    ProvenanceMismatch,
    MetricOverflow,
}

impl fmt::Display for CoreVmR1S4ErasureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntryVariant => {
                formatter.write_str("R1-S4 erasure found an invalid CoreVM0 entry variant")
            }
            Self::MissingLoopVariant => {
                formatter.write_str("R1-S4 erasure found no specialized CoreVM0 loop variant")
            }
            Self::UnexpectedSourceVariant { function } => write!(
                formatter,
                "R1-S4 erasure retained source helper function {}",
                function.0
            ),
            Self::DynamicControlAnchor {
                residual_function,
                parameter,
            } => write!(
                formatter,
                "R1-S4 residual function {} lost static control parameter {}",
                residual_function.0, parameter
            ),
            Self::ResidualEntryShape => {
                formatter.write_str("R1-S4 residual entry is not the exact dynamic CoreVM0 ABI")
            }
            Self::InterpreterType { name } => {
                write!(formatter, "R1-S4 residual retained interpreter type {name}")
            }
            Self::ResidualDispatch { function } => write!(
                formatter,
                "R1-S4 residual function {} retained a Case dispatch",
                function.0
            ),
            Self::ResidualHelperCall { function, target } => write!(
                formatter,
                "R1-S4 residual function {} calls non-erased helper {}",
                function.0, target.0
            ),
            Self::ProvenanceMismatch => {
                formatter.write_str("R1-S4 erasure input is not bound to the CoreVM0 artifact")
            }
            Self::MetricOverflow => formatter.write_str("R1-S4 erasure metrics overflowed U64"),
        }
    }
}

impl std::error::Error for CoreVmR1S4ErasureError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmR1S4Evidence {
    pub schema_version: (u16, u16, u16),
    pub replay_version: (u16, u16, u16),
    pub binding_version: (u16, u16, u16),
    pub construction_version: (u16, u16, u16),
    pub s4_policy_version: (u16, u16, u16),
    pub erasure_version: (u16, u16, u16),
    pub core_interpreter_semantics_hash: SemanticHash,
    pub artifact_hash: SemanticHash,
    pub program_hash: SemanticHash,
    pub program_image_hash: SemanticHash,
    pub binding_time_request_hash: SemanticHash,
    pub binding_time_certificate_hash: SemanticHash,
    pub upstream_request_hash: SemanticHash,
    pub s4_policy_hash: SemanticHash,
    pub s4_request_hash: SemanticHash,
    pub control_hash: SemanticHash,
    pub static_table_hash: SemanticHash,
    pub summary_table_hash: SemanticHash,
    pub variant_table_hash: SemanticHash,
    pub residual_hash: SemanticHash,
    pub binding_hash: SemanticHash,
    pub erasure_hash: SemanticHash,
    pub budget: PolyvariantR1S4Budget,
    pub usage: PolyvariantR1S4Usage,
    pub residual_nodes: u64,
    pub residual_bytes: u64,
    pub residual_functions: u64,
    pub loop_variants: u64,
    pub residual_nodes_scanned: u64,
    pub residual_calls: u64,
    pub residual_tail_calls: u64,
    pub residual_ifs: u64,
    pub evidence_hash: SemanticHash,
}

#[derive(Debug)]
pub enum CoreVmR1S4ReplayError {
    InvalidEvidenceHash,
    Build(DefinitionalCoreVmBuildError),
    Binding(BindingTimeRequestErrors),
    Certificate(BindingTimeCertificateBuildError),
    CertificateMismatch,
    Request(SpecializationRequestErrors),
    Specialization(CoreVmR1S4Error),
    ResidualMismatch,
    EvidenceMismatch,
}

impl fmt::Display for CoreVmR1S4ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvidenceHash => {
                formatter.write_str("R1-S4 evidence hash is not canonical")
            }
            Self::Build(error) => write!(formatter, "R1-S4 replay build failed: {error}"),
            Self::Binding(error) => write!(formatter, "R1-S4 replay B0 request failed: {error}"),
            Self::Certificate(error) => {
                write!(formatter, "R1-S4 replay B0 certificate failed: {error}")
            }
            Self::CertificateMismatch => {
                formatter.write_str("R1-S4 replay certificate differs from independent rebuild")
            }
            Self::Request(error) => write!(formatter, "R1-S4 replay R0 request failed: {error}"),
            Self::Specialization(error) => {
                write!(formatter, "R1-S4 replay specialization failed: {error}")
            }
            Self::ResidualMismatch => {
                formatter.write_str("R1-S4 replay regenerated a different residual")
            }
            Self::EvidenceMismatch => {
                formatter.write_str("R1-S4 replay regenerated different sealed evidence")
            }
        }
    }
}

impl std::error::Error for CoreVmR1S4ReplayError {}

impl From<DefinitionalCoreVmBuildError> for CoreVmR1S4ReplayError {
    fn from(error: DefinitionalCoreVmBuildError) -> Self {
        Self::Build(error)
    }
}

impl From<BindingTimeRequestErrors> for CoreVmR1S4ReplayError {
    fn from(error: BindingTimeRequestErrors) -> Self {
        Self::Binding(error)
    }
}

impl From<BindingTimeCertificateBuildError> for CoreVmR1S4ReplayError {
    fn from(error: BindingTimeCertificateBuildError) -> Self {
        Self::Certificate(error)
    }
}

impl From<SpecializationRequestErrors> for CoreVmR1S4ReplayError {
    fn from(error: SpecializationRequestErrors) -> Self {
        Self::Request(error)
    }
}

impl From<CoreVmR1S4Error> for CoreVmR1S4ReplayError {
    fn from(error: CoreVmR1S4Error) -> Self {
        Self::Specialization(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmR1S4Report {
    binding_version: (u16, u16, u16),
    binding_hash: SemanticHash,
    construction_version: (u16, u16, u16),
    core_interpreter_semantics_hash: SemanticHash,
    artifact_hash: SemanticHash,
    program_hash: SemanticHash,
    program_image_hash: SemanticHash,
    binding_time_request_hash: SemanticHash,
    binding_time_certificate_hash: SemanticHash,
    upstream_request_hash: SemanticHash,
    control_hash: SemanticHash,
    s4_policy_hash: SemanticHash,
    s4_request_hash: SemanticHash,
    static_table_hash: SemanticHash,
    summary_table_hash: SemanticHash,
    variant_table_hash: SemanticHash,
    residual_hash: SemanticHash,
    erasure: CoreVmR1S4ErasureReport,
}

impl CoreVmR1S4Report {
    pub fn binding_version(&self) -> (u16, u16, u16) {
        self.binding_version
    }

    pub fn binding_hash(&self) -> SemanticHash {
        self.binding_hash
    }

    pub fn construction_version(&self) -> (u16, u16, u16) {
        self.construction_version
    }

    pub fn core_interpreter_semantics_hash(&self) -> SemanticHash {
        self.core_interpreter_semantics_hash
    }

    pub fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }

    pub fn program_hash(&self) -> SemanticHash {
        self.program_hash
    }

    pub fn program_image_hash(&self) -> SemanticHash {
        self.program_image_hash
    }

    pub fn binding_time_request_hash(&self) -> SemanticHash {
        self.binding_time_request_hash
    }

    pub fn binding_time_certificate_hash(&self) -> SemanticHash {
        self.binding_time_certificate_hash
    }

    pub fn upstream_request_hash(&self) -> SemanticHash {
        self.upstream_request_hash
    }

    pub fn control_hash(&self) -> SemanticHash {
        self.control_hash
    }

    pub fn s4_policy_hash(&self) -> SemanticHash {
        self.s4_policy_hash
    }

    pub fn s4_request_hash(&self) -> SemanticHash {
        self.s4_request_hash
    }

    pub fn static_table_hash(&self) -> SemanticHash {
        self.static_table_hash
    }

    pub fn summary_table_hash(&self) -> SemanticHash {
        self.summary_table_hash
    }

    pub fn variant_table_hash(&self) -> SemanticHash {
        self.variant_table_hash
    }

    pub fn residual_hash(&self) -> SemanticHash {
        self.residual_hash
    }

    pub fn erasure(&self) -> &CoreVmR1S4ErasureReport {
        &self.erasure
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoreVmR1S4Specialization {
    specialization: PolyvariantR1S4Specialization,
    report: CoreVmR1S4Report,
}

impl CoreVmR1S4Specialization {
    pub fn specialization(&self) -> &PolyvariantR1S4Specialization {
        &self.specialization
    }

    pub fn artifact(&self) -> &CoreArtifact {
        self.specialization.artifact()
    }

    pub fn s4_report(&self) -> &PolyvariantR1S4Report {
        self.specialization.report()
    }

    pub fn report(&self) -> &CoreVmR1S4Report {
        &self.report
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CoreVmR1S4Error {
    ArtifactMismatch,
    EntryShapeMismatch,
    ProgramImageSlotMismatch,
    DynamicSlotMismatch { index: u32 },
    Encoding(EncodeError),
    Specialization(PolyvariantR1S4Error),
    Erasure(CoreVmR1S4ErasureError),
}

impl fmt::Display for CoreVmR1S4Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactMismatch => {
                formatter.write_str("R1-S4 CoreVM0 package does not match the validated artifact")
            }
            Self::EntryShapeMismatch => {
                formatter.write_str("R1-S4 CoreVM0 package has an invalid entry shape")
            }
            Self::ProgramImageSlotMismatch => formatter.write_str(
                "R1-S4 CoreVM0 slot zero is not the package's canonical full ProgramImage",
            ),
            Self::DynamicSlotMismatch { index } => write!(
                formatter,
                "R1-S4 CoreVM0 entry slot {index} is not the exact dynamic package type"
            ),
            Self::Encoding(error) => write!(
                formatter,
                "R1-S4 CoreVM0 ProgramImage identity encoding failed: {error}"
            ),
            Self::Specialization(error) => write!(formatter, "{error}"),
            Self::Erasure(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CoreVmR1S4Error {}

impl From<EncodeError> for CoreVmR1S4Error {
    fn from(error: EncodeError) -> Self {
        Self::Encoding(error)
    }
}

impl From<PolyvariantR1S4Error> for CoreVmR1S4Error {
    fn from(error: PolyvariantR1S4Error) -> Self {
        Self::Specialization(error)
    }
}

impl From<CoreVmR1S4ErasureError> for CoreVmR1S4Error {
    fn from(error: CoreVmR1S4ErasureError) -> Self {
        Self::Erasure(error)
    }
}

pub fn specialize_corevm0_r1_s4(
    bound: &DefinitionalCoreVmArtifact,
    validated: &ValidatedSpecializationRequest<'_, '_>,
    budget: PolyvariantR1S4Budget,
) -> Result<CoreVmR1S4Specialization, CoreVmR1S4Error> {
    if validated.artifact() != bound.artifact() {
        return Err(CoreVmR1S4Error::ArtifactMismatch);
    }

    let entry = bound
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == bound.artifact().program.entry)
        .ok_or(CoreVmR1S4Error::EntryShapeMismatch)?;
    let slots = &validated.request().entry_slots;
    if entry.parameters.len() != slots.len()
        || slots.len() != bound.argument_types().len().saturating_add(1)
    {
        return Err(CoreVmR1S4Error::EntryShapeMismatch);
    }

    let expected_image = specialization_value_bytes(bound.program_image())?;
    let Some(SpecializationSlot::Static(actual_image)) = slots.first() else {
        return Err(CoreVmR1S4Error::ProgramImageSlotMismatch);
    };
    if specialization_value_bytes(actual_image)? != expected_image {
        return Err(CoreVmR1S4Error::ProgramImageSlotMismatch);
    }

    for (index, (slot, parameter)) in slots.iter().zip(&entry.parameters).enumerate().skip(1) {
        if !matches!(slot, SpecializationSlot::Dynamic(ty) if *ty == parameter.ty) {
            return Err(CoreVmR1S4Error::DynamicSlotMismatch {
                index: index as u32,
            });
        }
    }

    let argument_count = u32::try_from(bound.argument_types().len())
        .map_err(|_| CoreVmR1S4Error::EntryShapeMismatch)?;
    let control = PolyvariantR1S4Control::from_pins([
        (FunctionId(1), 0),
        (FunctionId(1), 1),
        (FunctionId(1), 2 + argument_count),
        (FunctionId(1), 3 + argument_count),
    ]);
    let specialization = specialize_polyvariant_r1_s4_with_control(validated, budget, &control)?;
    let s4 = specialization.report();
    let expected_dynamic_types = entry
        .parameters
        .iter()
        .skip(1)
        .map(|parameter| parameter.ty.clone())
        .collect::<Vec<_>>();
    let erasure = verify_corevm0_r1_s4_erasure(bound, &specialization, &expected_dynamic_types)?;
    let binding_hash = binding_hash(
        bound,
        &BindingHashInputs {
            binding_time_request_hash: validated.request().binding_time_request_hash,
            binding_time_certificate_hash: validated.request().binding_time_certificate_hash,
            upstream_request_hash: validated.request_hash(),
            s4_policy_hash: s4.policy_hash(),
            s4_request_hash: s4.request_hash(),
            control_hash: s4.control_hash(),
            static_table_hash: s4.static_table_hash(),
            summary_table_hash: s4.summary_table_hash(),
            variant_table_hash: s4.variant_table_hash(),
            residual_hash: s4.residual_hash(),
            erasure_hash: erasure.erasure_hash(),
        },
    );
    let report = CoreVmR1S4Report {
        binding_version: COREVM0_R1_S4_BINDING_VERSION,
        binding_hash,
        construction_version: bound.construction_version(),
        core_interpreter_semantics_hash: bound.core_interpreter_semantics_hash(),
        artifact_hash: bound.artifact().semantic_hash,
        program_hash: bound.program_hash(),
        program_image_hash: bound.program_image_hash(),
        binding_time_request_hash: validated.request().binding_time_request_hash,
        binding_time_certificate_hash: validated.request().binding_time_certificate_hash,
        upstream_request_hash: validated.request_hash(),
        control_hash: s4.control_hash(),
        s4_policy_hash: s4.policy_hash(),
        s4_request_hash: s4.request_hash(),
        static_table_hash: s4.static_table_hash(),
        summary_table_hash: s4.summary_table_hash(),
        variant_table_hash: s4.variant_table_hash(),
        residual_hash: s4.residual_hash(),
        erasure,
    };
    Ok(CoreVmR1S4Specialization {
        specialization,
        report,
    })
}

pub fn emit_corevm0_r1_s4_evidence(
    specialization: &CoreVmR1S4Specialization,
) -> CoreVmR1S4Evidence {
    let binding = specialization.report();
    let s4 = specialization.s4_report();
    let erasure = binding.erasure();
    let mut evidence = CoreVmR1S4Evidence {
        schema_version: COREVM0_R1_S4_EVIDENCE_VERSION,
        replay_version: COREVM0_R1_S4_REPLAY_VERSION,
        binding_version: binding.binding_version(),
        construction_version: binding.construction_version(),
        s4_policy_version: s4.policy_version(),
        erasure_version: erasure.checker_version(),
        core_interpreter_semantics_hash: binding.core_interpreter_semantics_hash(),
        artifact_hash: binding.artifact_hash(),
        program_hash: binding.program_hash(),
        program_image_hash: binding.program_image_hash(),
        binding_time_request_hash: binding.binding_time_request_hash(),
        binding_time_certificate_hash: binding.binding_time_certificate_hash(),
        upstream_request_hash: binding.upstream_request_hash(),
        s4_policy_hash: binding.s4_policy_hash(),
        s4_request_hash: binding.s4_request_hash(),
        control_hash: binding.control_hash(),
        static_table_hash: binding.static_table_hash(),
        summary_table_hash: binding.summary_table_hash(),
        variant_table_hash: binding.variant_table_hash(),
        residual_hash: binding.residual_hash(),
        binding_hash: binding.binding_hash(),
        erasure_hash: erasure.erasure_hash(),
        budget: s4.budget(),
        usage: s4.usage(),
        residual_nodes: s4.residual_nodes(),
        residual_bytes: s4.residual_bytes(),
        residual_functions: erasure.residual_functions(),
        loop_variants: erasure.loop_variants(),
        residual_nodes_scanned: erasure.residual_nodes_scanned(),
        residual_calls: erasure.residual_calls(),
        residual_tail_calls: erasure.residual_tail_calls(),
        residual_ifs: erasure.residual_ifs(),
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = corevm0_r1_s4_evidence_hash(&evidence);
    evidence
}

pub fn corevm0_r1_s4_evidence_hash(evidence: &CoreVmR1S4Evidence) -> SemanticHash {
    let mut bytes = EVIDENCE_DOMAIN.to_vec();
    for version in [
        evidence.schema_version,
        evidence.replay_version,
        evidence.binding_version,
        evidence.construction_version,
        evidence.s4_policy_version,
        evidence.erasure_version,
    ] {
        for component in [version.0, version.1, version.2] {
            bytes.extend_from_slice(&component.to_be_bytes());
        }
    }
    for hash in [
        evidence.core_interpreter_semantics_hash,
        evidence.artifact_hash,
        evidence.program_hash,
        evidence.program_image_hash,
        evidence.binding_time_request_hash,
        evidence.binding_time_certificate_hash,
        evidence.upstream_request_hash,
        evidence.s4_policy_hash,
        evidence.s4_request_hash,
        evidence.control_hash,
        evidence.static_table_hash,
        evidence.summary_table_hash,
        evidence.variant_table_hash,
        evidence.residual_hash,
        evidence.binding_hash,
        evidence.erasure_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    for limit in [
        evidence.budget.max_work_units,
        evidence.budget.max_partial_value_nodes,
        evidence.budget.max_variants,
        evidence.budget.max_control_splits,
        evidence.budget.max_dynamic_parameters,
        evidence.budget.max_helper_unfolds,
        evidence.budget.max_residual_nodes,
        evidence.budget.max_residual_bytes,
    ] {
        bytes.extend_from_slice(&limit.to_be_bytes());
    }
    for usage in [
        evidence.usage.work_units,
        evidence.usage.partial_value_nodes,
        evidence.usage.variants,
        evidence.usage.control_splits,
        evidence.usage.dynamic_parameters,
        evidence.usage.helper_unfolds,
        evidence.usage.static_interns,
        evidence.usage.summary_entries,
        evidence.usage.summary_hits,
        evidence.usage.widened_values,
        evidence.residual_nodes,
        evidence.residual_bytes,
        evidence.residual_functions,
        evidence.loop_variants,
        evidence.residual_nodes_scanned,
        evidence.residual_calls,
        evidence.residual_tail_calls,
        evidence.residual_ifs,
    ] {
        bytes.extend_from_slice(&usage.to_be_bytes());
    }
    SemanticHash(sha256(&bytes))
}

pub fn verify_corevm0_r1_s4_evidence(
    program: &CoreVmProgram,
    binding_time_request: &BindingTimeRequest,
    binding_time_certificate: &BindingTimeCertificate,
    specialization_request: &SpecializationRequest,
    budget: PolyvariantR1S4Budget,
    claimed_residual: &CoreArtifact,
    evidence: &CoreVmR1S4Evidence,
) -> Result<CoreVmR1S4Specialization, CoreVmR1S4ReplayError> {
    if corevm0_r1_s4_evidence_hash(evidence) != evidence.evidence_hash {
        return Err(CoreVmR1S4ReplayError::InvalidEvidenceHash);
    }
    if evidence.schema_version != COREVM0_R1_S4_EVIDENCE_VERSION
        || evidence.replay_version != COREVM0_R1_S4_REPLAY_VERSION
        || evidence.binding_version != COREVM0_R1_S4_BINDING_VERSION
        || evidence.erasure_version != COREVM0_R1_S4_ERASURE_VERSION
        || evidence.budget != budget
    {
        return Err(CoreVmR1S4ReplayError::EvidenceMismatch);
    }
    if verify(claimed_residual).is_err() || claimed_residual.semantic_hash != evidence.residual_hash
    {
        return Err(CoreVmR1S4ReplayError::ResidualMismatch);
    }
    let bound = build_definitional_corevm0(program)?;
    if evidence.construction_version != bound.construction_version()
        || evidence.core_interpreter_semantics_hash != bound.core_interpreter_semantics_hash()
        || evidence.artifact_hash != bound.artifact().semantic_hash
        || evidence.program_hash != bound.program_hash()
        || evidence.program_image_hash != bound.program_image_hash()
    {
        return Err(CoreVmR1S4ReplayError::EvidenceMismatch);
    }
    let validated_binding =
        validate_binding_time_b0_request(bound.artifact(), binding_time_request)?;
    let replayed_certificate = certify_binding_time_b0d(&validated_binding)?;
    if replayed_certificate != *binding_time_certificate {
        return Err(CoreVmR1S4ReplayError::CertificateMismatch);
    }
    if evidence.binding_time_request_hash != specialization_request.binding_time_request_hash
        || evidence.binding_time_certificate_hash
            != specialization_request.binding_time_certificate_hash
    {
        return Err(CoreVmR1S4ReplayError::EvidenceMismatch);
    }
    let validated = validate_specialization_r0a_request(
        bound.artifact(),
        binding_time_request,
        binding_time_certificate,
        specialization_request,
    )?;
    if evidence.upstream_request_hash != validated.request_hash() {
        return Err(CoreVmR1S4ReplayError::EvidenceMismatch);
    }
    let specialization = specialize_corevm0_r1_s4(&bound, &validated, budget)?;
    if !artifacts_canonically_equal(specialization.artifact(), claimed_residual) {
        return Err(CoreVmR1S4ReplayError::ResidualMismatch);
    }
    let replayed_evidence = emit_corevm0_r1_s4_evidence(&specialization);
    if replayed_evidence != *evidence {
        return Err(CoreVmR1S4ReplayError::EvidenceMismatch);
    }
    Ok(specialization)
}

#[derive(Default)]
struct ErasureMetrics {
    nodes: u64,
    calls: u64,
    tail_calls: u64,
    ifs: u64,
}

fn verify_corevm0_r1_s4_erasure(
    bound: &DefinitionalCoreVmArtifact,
    specialization: &PolyvariantR1S4Specialization,
    expected_dynamic_types: &[Type],
) -> Result<CoreVmR1S4ErasureReport, CoreVmR1S4ErasureError> {
    let report = specialization.report();
    let artifact = specialization.artifact();
    if specialization.residual().source_hash != bound.artifact().semantic_hash {
        return Err(CoreVmR1S4ErasureError::ProvenanceMismatch);
    }
    let mut allowed_functions = BTreeSet::new();
    let mut entry_variant = None;
    let mut loop_variants = 0_u64;
    let argument_count = expected_dynamic_types.len();
    let pc_parameter = argument_count
        .checked_add(2)
        .ok_or(CoreVmR1S4ErasureError::MetricOverflow)?;
    let sp_parameter = argument_count
        .checked_add(3)
        .ok_or(CoreVmR1S4ErasureError::MetricOverflow)?;

    for variant in report.variants() {
        allowed_functions.insert(variant.residual_function());
        match variant.source_function() {
            FunctionId(0) => {
                if entry_variant.replace(variant.residual_function()).is_some()
                    || variant.patterns().len() != argument_count.saturating_add(1)
                    || !matches!(
                        variant.patterns().first(),
                        Some(PolyvariantR1S4Pattern::SharedStatic { .. })
                    )
                    || !variant
                        .patterns()
                        .iter()
                        .skip(1)
                        .zip(expected_dynamic_types)
                        .all(|(pattern, expected)| {
                            matches!(
                                pattern,
                                PolyvariantR1S4Pattern::Hole { ty, .. } if ty == expected
                            )
                        })
                {
                    return Err(CoreVmR1S4ErasureError::InvalidEntryVariant);
                }
            }
            FunctionId(1) => {
                loop_variants = loop_variants
                    .checked_add(1)
                    .ok_or(CoreVmR1S4ErasureError::MetricOverflow)?;
                let patterns = variant.patterns();
                if !matches!(
                    patterns.first(),
                    Some(PolyvariantR1S4Pattern::SharedStatic { .. })
                ) || !matches!(patterns.get(1), Some(PolyvariantR1S4Pattern::KnownI64(_)))
                {
                    return Err(CoreVmR1S4ErasureError::DynamicControlAnchor {
                        residual_function: variant.residual_function(),
                        parameter: 0,
                    });
                }
                for parameter in [pc_parameter, sp_parameter] {
                    if !matches!(
                        patterns.get(parameter),
                        Some(PolyvariantR1S4Pattern::KnownI64(_))
                    ) {
                        return Err(CoreVmR1S4ErasureError::DynamicControlAnchor {
                            residual_function: variant.residual_function(),
                            parameter: u32::try_from(parameter)
                                .map_err(|_| CoreVmR1S4ErasureError::MetricOverflow)?,
                        });
                    }
                }
            }
            function => {
                return Err(CoreVmR1S4ErasureError::UnexpectedSourceVariant { function });
            }
        }
    }

    let entry_variant = entry_variant.ok_or(CoreVmR1S4ErasureError::InvalidEntryVariant)?;
    if loop_variants == 0 {
        return Err(CoreVmR1S4ErasureError::MissingLoopVariant);
    }
    if artifact.program.entry != entry_variant
        || artifact.program.functions.len() != allowed_functions.len()
    {
        return Err(CoreVmR1S4ErasureError::ResidualEntryShape);
    }
    let entry = artifact
        .program
        .functions
        .iter()
        .find(|function| function.id == artifact.program.entry)
        .ok_or(CoreVmR1S4ErasureError::ResidualEntryShape)?;
    if entry
        .parameters
        .iter()
        .map(|parameter| &parameter.ty)
        .ne(expected_dynamic_types.iter())
    {
        return Err(CoreVmR1S4ErasureError::ResidualEntryShape);
    }

    let mut metrics = ErasureMetrics::default();
    for function in &artifact.program.functions {
        if !allowed_functions.contains(&function.id) {
            return Err(CoreVmR1S4ErasureError::ResidualHelperCall {
                function: function.id,
                target: function.id,
            });
        }
        scan_function(function, &allowed_functions, &mut metrics)?;
    }
    let residual_functions = u64::try_from(artifact.program.functions.len())
        .map_err(|_| CoreVmR1S4ErasureError::MetricOverflow)?;
    let residual_hash = report.residual_hash();
    let mut bytes = ERASURE_DOMAIN.to_vec();
    for component in [
        COREVM0_R1_S4_ERASURE_VERSION.0,
        COREVM0_R1_S4_ERASURE_VERSION.1,
        COREVM0_R1_S4_ERASURE_VERSION.2,
    ] {
        bytes.extend_from_slice(&component.to_be_bytes());
    }
    for component in [
        bound.construction_version().0,
        bound.construction_version().1,
        bound.construction_version().2,
    ] {
        bytes.extend_from_slice(&component.to_be_bytes());
    }
    for hash in [
        bound.artifact().semantic_hash,
        bound.program_hash(),
        bound.program_image_hash(),
        bound.core_interpreter_semantics_hash(),
        specialization.residual().source_hash,
        specialization.residual().request_hash,
        report.policy_hash(),
        report.request_hash(),
        report.upstream_request_hash(),
        report.control_hash(),
        report.static_table_hash(),
        report.summary_table_hash(),
        report.variant_table_hash(),
        residual_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    for value in [
        residual_functions,
        loop_variants,
        metrics.nodes,
        metrics.calls,
        metrics.tail_calls,
        metrics.ifs,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    let erasure_hash = SemanticHash(sha256(&bytes));
    Ok(CoreVmR1S4ErasureReport {
        checker_version: COREVM0_R1_S4_ERASURE_VERSION,
        erasure_hash,
        residual_hash,
        residual_functions,
        loop_variants,
        residual_nodes_scanned: metrics.nodes,
        residual_calls: metrics.calls,
        residual_tail_calls: metrics.tail_calls,
        residual_ifs: metrics.ifs,
    })
}

fn artifacts_canonically_equal(expected: &CoreArtifact, claimed: &CoreArtifact) -> bool {
    if expected.semantic_hash != claimed.semantic_hash {
        return false;
    }
    match (
        semantic_bytes(&expected.program),
        semantic_bytes(&claimed.program),
    ) {
        (Ok(expected), Ok(claimed)) => expected == claimed,
        _ => false,
    }
}

fn scan_function(
    function: &Function,
    allowed_functions: &BTreeSet<FunctionId>,
    metrics: &mut ErasureMetrics,
) -> Result<(), CoreVmR1S4ErasureError> {
    for parameter in &function.parameters {
        scan_type(&parameter.ty)?;
    }
    scan_type(&function.result)?;
    scan_term(function.id, &function.body, allowed_functions, metrics)
}

fn scan_term(
    function: FunctionId,
    term: &Term,
    allowed_functions: &BTreeSet<FunctionId>,
    metrics: &mut ErasureMetrics,
) -> Result<(), CoreVmR1S4ErasureError> {
    metrics.nodes = metrics
        .nodes
        .checked_add(1)
        .ok_or(CoreVmR1S4ErasureError::MetricOverflow)?;
    match term {
        Term::Let {
            ty, value, next, ..
        } => {
            scan_type(ty)?;
            scan_rvalue(function, value, allowed_functions, metrics)?;
            scan_term(function, next, allowed_functions, metrics)
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            metrics.ifs = metrics
                .ifs
                .checked_add(1)
                .ok_or(CoreVmR1S4ErasureError::MetricOverflow)?;
            scan_term(function, then_term, allowed_functions, metrics)?;
            scan_term(function, else_term, allowed_functions, metrics)
        }
        Term::Case { .. } => Err(CoreVmR1S4ErasureError::ResidualDispatch { function }),
        Term::TailCall {
            function: target, ..
        } => {
            metrics.tail_calls = metrics
                .tail_calls
                .checked_add(1)
                .ok_or(CoreVmR1S4ErasureError::MetricOverflow)?;
            require_allowed_call(function, *target, allowed_functions)
        }
        Term::Return(_) => Ok(()),
        Term::Region { body, .. } => scan_term(function, body, allowed_functions, metrics),
        Term::Handle {
            capture_parameters,
            clauses,
            body,
            ..
        } => {
            for parameter in capture_parameters {
                scan_type(&parameter.ty)?;
            }
            for clause in clauses {
                for parameter in &clause.operation.parameters {
                    scan_type(parameter)?;
                }
                scan_type(&clause.operation.result)?;
                scan_term(function, &clause.body, allowed_functions, metrics)?;
            }
            scan_term(function, body, allowed_functions, metrics)
        }
    }
}

fn scan_rvalue(
    function: FunctionId,
    value: &RValue,
    allowed_functions: &BTreeSet<FunctionId>,
    metrics: &mut ErasureMetrics,
) -> Result<(), CoreVmR1S4ErasureError> {
    metrics.nodes = metrics
        .nodes
        .checked_add(1)
        .ok_or(CoreVmR1S4ErasureError::MetricOverflow)?;
    match value {
        RValue::Construct { sum, .. } => scan_sum(sum),
        RValue::Call {
            function: target, ..
        } => {
            metrics.calls = metrics
                .calls
                .checked_add(1)
                .ok_or(CoreVmR1S4ErasureError::MetricOverflow)?;
            require_allowed_call(function, *target, allowed_functions)
        }
        RValue::PackClosure {
            function: target, ..
        } => require_allowed_call(function, *target, allowed_functions),
        RValue::Perform { operation, .. } => {
            for parameter in &operation.parameters {
                scan_type(parameter)?;
            }
            scan_type(&operation.result)
        }
        RValue::Use(_)
        | RValue::Tuple(_)
        | RValue::Project { .. }
        | RValue::Primitive { .. }
        | RValue::RefAlloc { .. }
        | RValue::RefLoad { .. }
        | RValue::RefStore { .. }
        | RValue::CallClosure { .. } => Ok(()),
    }
}

fn require_allowed_call(
    function: FunctionId,
    target: FunctionId,
    allowed_functions: &BTreeSet<FunctionId>,
) -> Result<(), CoreVmR1S4ErasureError> {
    if allowed_functions.contains(&target) {
        Ok(())
    } else {
        Err(CoreVmR1S4ErasureError::ResidualHelperCall { function, target })
    }
}

fn scan_type(ty: &Type) -> Result<(), CoreVmR1S4ErasureError> {
    if *ty == corevm0_program_image_type() {
        return Err(CoreVmR1S4ErasureError::InterpreterType {
            name: "CoreVM0.ProgramImage.v1".to_owned(),
        });
    }
    match ty {
        Type::Tuple(fields) => {
            for field in fields {
                scan_type(field)?;
            }
            Ok(())
        }
        Type::Sum(sum) => scan_sum(sum),
        Type::Array { element, .. } | Type::Ref { element, .. } => scan_type(element),
        Type::Function {
            parameters, result, ..
        }
        | Type::Closure {
            parameters, result, ..
        } => {
            for parameter in parameters {
                scan_type(parameter)?;
            }
            scan_type(result)
        }
        Type::Unit | Type::Bool | Type::I64 | Type::F64 | Type::Text | Type::Bytes => Ok(()),
    }
}

fn scan_sum(sum: &SumType) -> Result<(), CoreVmR1S4ErasureError> {
    if [
        COREVM0_TYPE_SLOT_SUM_NAME,
        COREVM0_INSTRUCTION_SLOT_SUM_NAME,
        COREVM0_INSTRUCTION_SUM_NAME,
        COREVM0_RUNTIME_VALUE_SUM_NAME,
        COREVM0_VALUE_LOOKUP_SUM_NAME,
        COREVM0_BANK_UPDATE_SUM_NAME,
    ]
    .contains(&sum.name.as_str())
    {
        return Err(CoreVmR1S4ErasureError::InterpreterType {
            name: sum.name.clone(),
        });
    }
    for constructor in &sum.constructors {
        for field in &constructor.fields {
            scan_type(field)?;
        }
    }
    Ok(())
}

struct BindingHashInputs {
    binding_time_request_hash: SemanticHash,
    binding_time_certificate_hash: SemanticHash,
    upstream_request_hash: SemanticHash,
    s4_policy_hash: SemanticHash,
    s4_request_hash: SemanticHash,
    control_hash: SemanticHash,
    static_table_hash: SemanticHash,
    summary_table_hash: SemanticHash,
    variant_table_hash: SemanticHash,
    residual_hash: SemanticHash,
    erasure_hash: SemanticHash,
}

fn binding_hash(bound: &DefinitionalCoreVmArtifact, inputs: &BindingHashInputs) -> SemanticHash {
    let mut bytes = BINDING_DOMAIN.to_vec();
    for component in [
        COREVM0_R1_S4_BINDING_VERSION.0,
        COREVM0_R1_S4_BINDING_VERSION.1,
        COREVM0_R1_S4_BINDING_VERSION.2,
        bound.construction_version().0,
        bound.construction_version().1,
        bound.construction_version().2,
    ] {
        bytes.extend_from_slice(&component.to_be_bytes());
    }
    for hash in [
        bound.artifact().semantic_hash,
        bound.program_hash(),
        bound.program_image_hash(),
        bound.core_interpreter_semantics_hash(),
        inputs.binding_time_request_hash,
        inputs.binding_time_certificate_hash,
        inputs.upstream_request_hash,
        inputs.s4_policy_hash,
        inputs.s4_request_hash,
        inputs.control_hash,
        inputs.static_table_hash,
        inputs.summary_table_hash,
        inputs.variant_table_hash,
        inputs.residual_hash,
        inputs.erasure_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    SemanticHash(sha256(&bytes))
}
