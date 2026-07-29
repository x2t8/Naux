use super::encoding::{
    binding_time_certificate_hash, binding_time_node_bytes, binding_time_request_hash,
    semantic_bytes, sha256, specialization_request_hash, specialization_value_bytes, EncodeError,
};
use super::residual::{count_program_nodes, ResidualCore, ResidualGenerationError};
use super::residual_r0c2::generate_residual_r0c2;
use super::schema::{CoreArtifact, SemanticHash};
use super::specialization::{
    validate_specialization_r0a_request, SpecializationRequest, ValidatedSpecializationRequest,
};
use super::staging::{BindingTimeCertificate, BindingTimeNodeId, BindingTimeRequest};
use super::static_evaluate::{StaticEvaluationError, StaticResidualReason};
use super::static_evaluate_r0b2::{
    evaluate_static_r0b2, MixedStaticEvaluation, MixedStaticOutcome,
};
use super::verify::{verify, VerificationErrors};
use std::fmt;

const MIXED_STATIC_EVALUATION_DOMAIN: &[u8] = b"NAUX:core-n0:mixed-static-evaluation:r0b2:v1\0";
const RESIDUAL_EVIDENCE_DOMAIN: &[u8] = b"NAUX:core-n0:residual-evidence:r0d:v1\0";

pub const R0D_EVIDENCE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const R0D_REPLAY_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidualEvidence {
    pub schema_version: (u16, u16, u16),
    pub replay_policy_version: (u16, u16, u16),
    pub source_program_hash: SemanticHash,
    pub interpreter_semantics_hash: SemanticHash,
    pub binding_time_request_hash: SemanticHash,
    pub binding_time_certificate_hash: SemanticHash,
    pub specialization_request_hash: SemanticHash,
    pub evaluation_hash: SemanticHash,
    pub evaluation_steps: u64,
    pub residual_program_hash: SemanticHash,
    pub residual_nodes: u64,
    pub residual_bytes: u64,
    pub evidence_hash: SemanticHash,
}

#[derive(Debug)]
pub enum ResidualEvidenceBuildError {
    EvaluationRecordMismatch {
        expected: SemanticHash,
        actual: SemanticHash,
    },
    ResidualProvenanceMismatch,
    ResidualRejected(VerificationErrors),
    ResidualMetricMismatch,
    ResidualCorrespondenceMismatch,
    ResidualGeneration(ResidualGenerationError),
    Encoding(EncodeError),
}

impl fmt::Display for ResidualEvidenceBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EvaluationRecordMismatch { expected, actual } => write!(
                formatter,
                "R0-D evaluation record binds request {actual}, expected {expected}"
            ),
            Self::ResidualProvenanceMismatch => {
                write!(
                    formatter,
                    "R0-D residual provenance does not match the request"
                )
            }
            Self::ResidualRejected(errors) => {
                write!(
                    formatter,
                    "R0-D residual artifact is not verified: {errors}"
                )
            }
            Self::ResidualMetricMismatch => {
                write!(formatter, "R0-D residual wrapper metrics are not canonical")
            }
            Self::ResidualCorrespondenceMismatch => write!(
                formatter,
                "R0-D residual artifact differs from deterministic R0-C2 regeneration"
            ),
            Self::ResidualGeneration(error) => {
                write!(formatter, "R0-D residual regeneration failed: {error}")
            }
            Self::Encoding(error) => write!(formatter, "R0-D evidence encoding failed: {error}"),
        }
    }
}

impl std::error::Error for ResidualEvidenceBuildError {}

impl From<EncodeError> for ResidualEvidenceBuildError {
    fn from(error: EncodeError) -> Self {
        Self::Encoding(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidualEvidenceCode {
    InvalidRequest,
    UnsupportedEvidenceSchema,
    UnsupportedReplayPolicy,
    SourceProgramHashMismatch,
    InterpreterSemanticsHashMismatch,
    BindingTimeRequestHashMismatch,
    BindingTimeCertificateHashMismatch,
    SpecializationRequestHashMismatch,
    EvidenceHashMismatch,
    ResidualRejected,
    ResidualProgramHashMismatch,
    ResidualNodeCountMismatch,
    ResidualByteCountMismatch,
    IndependentReplayFailure,
    EvaluationHashMismatch,
    EvaluationStepMismatch,
    ResidualStructureMismatch,
    EncodingFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidualEvidenceError {
    pub code: ResidualEvidenceCode,
    pub path: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidualEvidenceErrors(pub Vec<ResidualEvidenceError>);

impl fmt::Display for ResidualEvidenceErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} residual R0-D evidence error(s)",
            self.0.len()
        )?;
        for error in &self.0 {
            write!(
                formatter,
                "\n- {:?} at {}: {}",
                error.code, error.path, error.message
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ResidualEvidenceErrors {}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedResidualEvidence<'evidence> {
    evidence: &'evidence ResidualEvidence,
}

impl<'evidence> VerifiedResidualEvidence<'evidence> {
    pub fn evidence(&self) -> &'evidence ResidualEvidence {
        self.evidence
    }
}

/// Seal R0-D evidence after checking that the supplied R0-B2 and R0-C2
/// products exactly correspond to the validated request.
pub fn emit_residual_evidence_r0d(
    validated: &ValidatedSpecializationRequest<'_, '_>,
    evaluation: &MixedStaticEvaluation,
    residual: &ResidualCore,
) -> Result<ResidualEvidence, ResidualEvidenceBuildError> {
    if evaluation.request_hash() != validated.request_hash() {
        return Err(ResidualEvidenceBuildError::EvaluationRecordMismatch {
            expected: validated.request_hash(),
            actual: evaluation.request_hash(),
        });
    }
    if residual.source_hash != validated.artifact().semantic_hash
        || residual.request_hash != validated.request_hash()
    {
        return Err(ResidualEvidenceBuildError::ResidualProvenanceMismatch);
    }
    verify(&residual.artifact).map_err(ResidualEvidenceBuildError::ResidualRejected)?;
    let canonical_nodes = count_program_nodes(&residual.artifact.program);
    let canonical_bytes = semantic_bytes(&residual.artifact.program)?.len() as u64;
    if residual.residual_nodes != canonical_nodes || residual.residual_bytes != canonical_bytes {
        return Err(ResidualEvidenceBuildError::ResidualMetricMismatch);
    }

    let expected = generate_residual_r0c2(validated, evaluation)
        .map_err(ResidualEvidenceBuildError::ResidualGeneration)?;
    if expected != *residual {
        return Err(ResidualEvidenceBuildError::ResidualCorrespondenceMismatch);
    }

    let request = validated.request();
    let certificate = validated.certificate().certificate();
    let mut evidence = ResidualEvidence {
        schema_version: R0D_EVIDENCE_SCHEMA_VERSION,
        replay_policy_version: R0D_REPLAY_POLICY_VERSION,
        source_program_hash: validated.artifact().semantic_hash,
        interpreter_semantics_hash: request.interpreter_semantics_hash,
        binding_time_request_hash: request.binding_time_request_hash,
        binding_time_certificate_hash: certificate.certificate_hash,
        specialization_request_hash: validated.request_hash(),
        evaluation_hash: mixed_static_evaluation_hash(evaluation)?,
        evaluation_steps: evaluation.steps(),
        residual_program_hash: residual.artifact.semantic_hash,
        residual_nodes: canonical_nodes,
        residual_bytes: canonical_bytes,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = residual_evidence_hash(&evidence)?;
    Ok(evidence)
}

/// Verify R0-D evidence from raw public inputs.
///
/// The admission boundary reconstructs the validated request, replays R0-B2,
/// and regenerates R0-C2. It never accepts the emitter's evaluation record or
/// `ResidualCore` wrapper as input.
pub fn verify_residual_evidence_r0d<'evidence>(
    source: &CoreArtifact,
    binding_time_request: &BindingTimeRequest,
    binding_time_certificate: &BindingTimeCertificate,
    specialization_request: &SpecializationRequest,
    residual: &CoreArtifact,
    evidence: &'evidence ResidualEvidence,
) -> Result<VerifiedResidualEvidence<'evidence>, ResidualEvidenceErrors> {
    let validated = validate_specialization_r0a_request(
        source,
        binding_time_request,
        binding_time_certificate,
        specialization_request,
    )
    .map_err(|errors| {
        ResidualEvidenceErrors(vec![ResidualEvidenceError {
            code: ResidualEvidenceCode::InvalidRequest,
            path: "evidence.request",
            message: errors.to_string(),
        }])
    })?;

    let mut errors = Vec::new();
    if evidence.schema_version != R0D_EVIDENCE_SCHEMA_VERSION {
        push_error(
            &mut errors,
            ResidualEvidenceCode::UnsupportedEvidenceSchema,
            "evidence.schema_version",
            format!(
                "expected {:?}, found {:?}",
                R0D_EVIDENCE_SCHEMA_VERSION, evidence.schema_version
            ),
        );
    }
    if evidence.replay_policy_version != R0D_REPLAY_POLICY_VERSION {
        push_error(
            &mut errors,
            ResidualEvidenceCode::UnsupportedReplayPolicy,
            "evidence.replay_policy_version",
            format!(
                "expected {:?}, found {:?}",
                R0D_REPLAY_POLICY_VERSION, evidence.replay_policy_version
            ),
        );
    }
    compare_hash(
        &mut errors,
        ResidualEvidenceCode::SourceProgramHashMismatch,
        "evidence.source_program_hash",
        source.semantic_hash,
        evidence.source_program_hash,
    );
    compare_hash(
        &mut errors,
        ResidualEvidenceCode::InterpreterSemanticsHashMismatch,
        "evidence.interpreter_semantics_hash",
        specialization_request.interpreter_semantics_hash,
        evidence.interpreter_semantics_hash,
    );
    match binding_time_request_hash(binding_time_request) {
        Ok(expected) => compare_hash(
            &mut errors,
            ResidualEvidenceCode::BindingTimeRequestHashMismatch,
            "evidence.binding_time_request_hash",
            expected,
            evidence.binding_time_request_hash,
        ),
        Err(error) => encoding_error(&mut errors, "evidence.binding_time_request_hash", error),
    }
    match binding_time_certificate_hash(binding_time_certificate) {
        Ok(expected) => compare_hash(
            &mut errors,
            ResidualEvidenceCode::BindingTimeCertificateHashMismatch,
            "evidence.binding_time_certificate_hash",
            expected,
            evidence.binding_time_certificate_hash,
        ),
        Err(error) => encoding_error(&mut errors, "evidence.binding_time_certificate_hash", error),
    }
    match specialization_request_hash(specialization_request) {
        Ok(expected) => compare_hash(
            &mut errors,
            ResidualEvidenceCode::SpecializationRequestHashMismatch,
            "evidence.specialization_request_hash",
            expected,
            evidence.specialization_request_hash,
        ),
        Err(error) => encoding_error(&mut errors, "evidence.specialization_request_hash", error),
    }
    match residual_evidence_hash(evidence) {
        Ok(expected) => compare_hash(
            &mut errors,
            ResidualEvidenceCode::EvidenceHashMismatch,
            "evidence.evidence_hash",
            expected,
            evidence.evidence_hash,
        ),
        Err(error) => encoding_error(&mut errors, "evidence.evidence_hash", error),
    }

    if let Err(rejections) = verify(residual) {
        push_error(
            &mut errors,
            ResidualEvidenceCode::ResidualRejected,
            "evidence.residual",
            rejections.to_string(),
        );
    } else {
        compare_hash(
            &mut errors,
            ResidualEvidenceCode::ResidualProgramHashMismatch,
            "evidence.residual_program_hash",
            residual.semantic_hash,
            evidence.residual_program_hash,
        );
        let nodes = count_program_nodes(&residual.program);
        if evidence.residual_nodes != nodes {
            push_error(
                &mut errors,
                ResidualEvidenceCode::ResidualNodeCountMismatch,
                "evidence.residual_nodes",
                format!(
                    "declared {} residual nodes, canonical residual has {nodes}",
                    evidence.residual_nodes
                ),
            );
        }
        match semantic_bytes(&residual.program) {
            Ok(bytes) => {
                let byte_count = bytes.len() as u64;
                if evidence.residual_bytes != byte_count {
                    push_error(
                        &mut errors,
                        ResidualEvidenceCode::ResidualByteCountMismatch,
                        "evidence.residual_bytes",
                        format!(
                            "declared {} residual bytes, canonical residual has {byte_count}",
                            evidence.residual_bytes
                        ),
                    );
                }
            }
            Err(error) => encoding_error(&mut errors, "evidence.residual_bytes", error),
        }
    }

    if !errors.is_empty() {
        return Err(ResidualEvidenceErrors(errors));
    }

    let replayed = evaluate_static_r0b2(&validated)
        .map_err(|error| independent_replay_error("evidence.evaluation", error))?;
    let replayed_hash = mixed_static_evaluation_hash(&replayed)
        .map_err(|error| encoding_error_result("evidence.evaluation_hash", error))?;
    if evidence.evaluation_hash != replayed_hash {
        push_error(
            &mut errors,
            ResidualEvidenceCode::EvaluationHashMismatch,
            "evidence.evaluation_hash",
            "declared evaluation differs from independent R0-B2 replay".to_owned(),
        );
    }
    if evidence.evaluation_steps != replayed.steps() {
        push_error(
            &mut errors,
            ResidualEvidenceCode::EvaluationStepMismatch,
            "evidence.evaluation_steps",
            format!(
                "declared {} steps, independent replay used {}",
                evidence.evaluation_steps,
                replayed.steps()
            ),
        );
    }
    if !errors.is_empty() {
        return Err(ResidualEvidenceErrors(errors));
    }

    let regenerated = generate_residual_r0c2(&validated, &replayed).map_err(|error| {
        ResidualEvidenceErrors(vec![ResidualEvidenceError {
            code: ResidualEvidenceCode::IndependentReplayFailure,
            path: "evidence.residual",
            message: error.to_string(),
        }])
    })?;
    if regenerated.artifact.program != residual.program
        || regenerated.artifact.semantic_hash != residual.semantic_hash
        || regenerated.residual_nodes != evidence.residual_nodes
        || regenerated.residual_bytes != evidence.residual_bytes
    {
        push_error(
            &mut errors,
            ResidualEvidenceCode::ResidualStructureMismatch,
            "evidence.residual",
            "supplied residual differs from deterministic R0-C2 regeneration".to_owned(),
        );
    }

    if errors.is_empty() {
        Ok(VerifiedResidualEvidence { evidence })
    } else {
        Err(ResidualEvidenceErrors(errors))
    }
}

pub fn mixed_static_evaluation_bytes(
    evaluation: &MixedStaticEvaluation,
) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = EvidenceEncoder::new(MIXED_STATIC_EVALUATION_DOMAIN);
    encoder.hash(evaluation.request_hash());
    match evaluation.outcome() {
        MixedStaticOutcome::Complete(value) => {
            encoder.tag(0);
            encoder.nested(
                "residual.evaluation.complete",
                &specialization_value_bytes(value)?,
            )?;
        }
        MixedStaticOutcome::MixedFrontier { halt, static_facts } => {
            encoder.tag(1);
            encoder.node("residual.evaluation.halt.node", &halt.node)?;
            encode_residual_reason(&mut encoder, halt.reason);
            encoder.length("residual.evaluation.static_facts", static_facts.len())?;
            for fact in static_facts {
                encoder.u32(fact.local.0);
                encoder.nested(
                    "residual.evaluation.static_fact.value",
                    &specialization_value_bytes(&fact.value)?,
                )?;
            }
        }
    }
    encoder.u64(evaluation.steps());
    encoder.length(
        "residual.evaluation.executed_nodes",
        evaluation.executed_nodes().len(),
    )?;
    for node in evaluation.executed_nodes() {
        encoder.node("residual.evaluation.executed_node", node)?;
    }
    encoder.length(
        "residual.evaluation.skipped_nodes",
        evaluation.skipped_nodes().len(),
    )?;
    for skipped in evaluation.skipped_nodes() {
        encoder.node("residual.evaluation.skipped_node", &skipped.node)?;
        encode_residual_reason(&mut encoder, skipped.reason);
    }
    Ok(encoder.finish())
}

pub fn mixed_static_evaluation_hash(
    evaluation: &MixedStaticEvaluation,
) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&mixed_static_evaluation_bytes(
        evaluation,
    )?)))
}

pub fn residual_evidence_bytes(evidence: &ResidualEvidence) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = EvidenceEncoder::new(RESIDUAL_EVIDENCE_DOMAIN);
    encoder.version(evidence.schema_version);
    encoder.version(evidence.replay_policy_version);
    encoder.hash(evidence.source_program_hash);
    encoder.hash(evidence.interpreter_semantics_hash);
    encoder.hash(evidence.binding_time_request_hash);
    encoder.hash(evidence.binding_time_certificate_hash);
    encoder.hash(evidence.specialization_request_hash);
    encoder.hash(evidence.evaluation_hash);
    encoder.u64(evidence.evaluation_steps);
    encoder.hash(evidence.residual_program_hash);
    encoder.u64(evidence.residual_nodes);
    encoder.u64(evidence.residual_bytes);
    Ok(encoder.finish())
}

pub fn residual_evidence_hash(evidence: &ResidualEvidence) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&residual_evidence_bytes(evidence)?)))
}

fn encode_residual_reason(encoder: &mut EvidenceEncoder, reason: StaticResidualReason) {
    encoder.tag(match reason {
        StaticResidualReason::DynamicDependency => 0,
        StaticResidualReason::DeniedByCertificate => 1,
        StaticResidualReason::InterproceduralDeferred => 2,
        StaticResidualReason::UnavailableStaticValue => 3,
    });
}

fn compare_hash(
    errors: &mut Vec<ResidualEvidenceError>,
    code: ResidualEvidenceCode,
    path: &'static str,
    expected: SemanticHash,
    actual: SemanticHash,
) {
    if expected != actual {
        push_error(
            errors,
            code,
            path,
            format!("expected {expected}, found {actual}"),
        );
    }
}

fn push_error(
    errors: &mut Vec<ResidualEvidenceError>,
    code: ResidualEvidenceCode,
    path: &'static str,
    message: String,
) {
    errors.push(ResidualEvidenceError {
        code,
        path,
        message,
    });
}

fn encoding_error(errors: &mut Vec<ResidualEvidenceError>, path: &'static str, error: EncodeError) {
    push_error(
        errors,
        ResidualEvidenceCode::EncodingFailure,
        path,
        error.to_string(),
    );
}

fn encoding_error_result(path: &'static str, error: EncodeError) -> ResidualEvidenceErrors {
    ResidualEvidenceErrors(vec![ResidualEvidenceError {
        code: ResidualEvidenceCode::EncodingFailure,
        path,
        message: error.to_string(),
    }])
}

fn independent_replay_error(
    path: &'static str,
    error: StaticEvaluationError,
) -> ResidualEvidenceErrors {
    ResidualEvidenceErrors(vec![ResidualEvidenceError {
        code: ResidualEvidenceCode::IndependentReplayFailure,
        path,
        message: error.to_string(),
    }])
}

struct EvidenceEncoder {
    bytes: Vec<u8>,
}

impl EvidenceEncoder {
    fn new(domain: &[u8]) -> Self {
        Self {
            bytes: domain.to_vec(),
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn tag(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn hash(&mut self, value: SemanticHash) {
        self.bytes.extend_from_slice(&value.0);
    }

    fn version(&mut self, version: (u16, u16, u16)) {
        self.u16(version.0);
        self.u16(version.1);
        self.u16(version.2);
    }

    fn length(&mut self, field: &'static str, length: usize) -> Result<(), EncodeError> {
        let length =
            u32::try_from(length).map_err(|_| EncodeError::LengthOverflow { field, length })?;
        self.u32(length);
        Ok(())
    }

    fn nested(&mut self, field: &'static str, bytes: &[u8]) -> Result<(), EncodeError> {
        self.length(field, bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn node(&mut self, field: &'static str, node: &BindingTimeNodeId) -> Result<(), EncodeError> {
        self.nested(field, &binding_time_node_bytes(node)?)
    }
}
