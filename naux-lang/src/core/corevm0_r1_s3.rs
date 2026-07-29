use super::corevm0_definitional::DefinitionalCoreVmArtifact;
use super::encoding::{sha256, specialization_value_bytes, EncodeError};
use super::polyvariant_r1_s3::{
    specialize_polyvariant_r1_s3, PolyvariantR1S3Budget, PolyvariantR1S3Error,
    PolyvariantR1S3Report, PolyvariantR1S3Specialization,
};
use super::schema::{CoreArtifact, SemanticHash};
use super::specialization::{SpecializationSlot, ValidatedSpecializationRequest};
use std::fmt;

pub const COREVM0_R1_S3_BINDING_VERSION: (u16, u16, u16) = (1, 0, 0);

const BINDING_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s3:binding:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmR1S3Report {
    binding_version: (u16, u16, u16),
    binding_hash: SemanticHash,
    construction_version: (u16, u16, u16),
    core_interpreter_semantics_hash: SemanticHash,
    artifact_hash: SemanticHash,
    program_hash: SemanticHash,
    program_image_hash: SemanticHash,
    upstream_request_hash: SemanticHash,
    s3_policy_hash: SemanticHash,
    s3_request_hash: SemanticHash,
    residual_hash: SemanticHash,
}

impl CoreVmR1S3Report {
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

    pub fn upstream_request_hash(&self) -> SemanticHash {
        self.upstream_request_hash
    }

    pub fn s3_policy_hash(&self) -> SemanticHash {
        self.s3_policy_hash
    }

    pub fn s3_request_hash(&self) -> SemanticHash {
        self.s3_request_hash
    }

    pub fn residual_hash(&self) -> SemanticHash {
        self.residual_hash
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoreVmR1S3Specialization {
    specialization: PolyvariantR1S3Specialization,
    report: CoreVmR1S3Report,
}

impl CoreVmR1S3Specialization {
    pub fn specialization(&self) -> &PolyvariantR1S3Specialization {
        &self.specialization
    }

    pub fn artifact(&self) -> &CoreArtifact {
        self.specialization.artifact()
    }

    pub fn s3_report(&self) -> &PolyvariantR1S3Report {
        self.specialization.report()
    }

    pub fn report(&self) -> &CoreVmR1S3Report {
        &self.report
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CoreVmR1S3Error {
    ArtifactMismatch,
    EntryShapeMismatch,
    ProgramImageSlotMismatch,
    DynamicSlotMismatch { index: u32 },
    Encoding(EncodeError),
    Specialization(PolyvariantR1S3Error),
}

impl fmt::Display for CoreVmR1S3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactMismatch => {
                formatter.write_str("R1-S3 CoreVM0 package does not match the validated artifact")
            }
            Self::EntryShapeMismatch => {
                formatter.write_str("R1-S3 CoreVM0 package has an invalid entry shape")
            }
            Self::ProgramImageSlotMismatch => formatter.write_str(
                "R1-S3 CoreVM0 slot zero is not the package's canonical full ProgramImage",
            ),
            Self::DynamicSlotMismatch { index } => write!(
                formatter,
                "R1-S3 CoreVM0 entry slot {index} is not the exact dynamic package type"
            ),
            Self::Encoding(error) => write!(
                formatter,
                "R1-S3 CoreVM0 ProgramImage identity encoding failed: {error}"
            ),
            Self::Specialization(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CoreVmR1S3Error {}

impl From<EncodeError> for CoreVmR1S3Error {
    fn from(error: EncodeError) -> Self {
        Self::Encoding(error)
    }
}

impl From<PolyvariantR1S3Error> for CoreVmR1S3Error {
    fn from(error: PolyvariantR1S3Error) -> Self {
        Self::Specialization(error)
    }
}

pub fn specialize_corevm0_r1_s3(
    bound: &DefinitionalCoreVmArtifact,
    validated: &ValidatedSpecializationRequest<'_, '_>,
    budget: PolyvariantR1S3Budget,
) -> Result<CoreVmR1S3Specialization, CoreVmR1S3Error> {
    if validated.artifact() != bound.artifact() {
        return Err(CoreVmR1S3Error::ArtifactMismatch);
    }

    let entry = bound
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == bound.artifact().program.entry)
        .ok_or(CoreVmR1S3Error::EntryShapeMismatch)?;
    let slots = &validated.request().entry_slots;
    if entry.parameters.len() != slots.len()
        || slots.len() != bound.argument_types().len().saturating_add(1)
    {
        return Err(CoreVmR1S3Error::EntryShapeMismatch);
    }

    let expected_image = specialization_value_bytes(bound.program_image())?;
    let Some(SpecializationSlot::Static(actual_image)) = slots.first() else {
        return Err(CoreVmR1S3Error::ProgramImageSlotMismatch);
    };
    if specialization_value_bytes(actual_image)? != expected_image {
        return Err(CoreVmR1S3Error::ProgramImageSlotMismatch);
    }

    for (index, (slot, parameter)) in slots.iter().zip(&entry.parameters).enumerate().skip(1) {
        if !matches!(slot, SpecializationSlot::Dynamic(ty) if *ty == parameter.ty) {
            return Err(CoreVmR1S3Error::DynamicSlotMismatch {
                index: index as u32,
            });
        }
    }

    let specialization = specialize_polyvariant_r1_s3(validated, budget)?;
    let s3 = specialization.report();
    let binding_hash = binding_hash(
        bound,
        validated.request_hash(),
        s3.policy_hash(),
        s3.request_hash(),
        s3.residual_hash(),
    );
    let report = CoreVmR1S3Report {
        binding_version: COREVM0_R1_S3_BINDING_VERSION,
        binding_hash,
        construction_version: bound.construction_version(),
        core_interpreter_semantics_hash: bound.core_interpreter_semantics_hash(),
        artifact_hash: bound.artifact().semantic_hash,
        program_hash: bound.program_hash(),
        program_image_hash: bound.program_image_hash(),
        upstream_request_hash: validated.request_hash(),
        s3_policy_hash: s3.policy_hash(),
        s3_request_hash: s3.request_hash(),
        residual_hash: s3.residual_hash(),
    };
    Ok(CoreVmR1S3Specialization {
        specialization,
        report,
    })
}

fn binding_hash(
    bound: &DefinitionalCoreVmArtifact,
    upstream_request_hash: SemanticHash,
    s3_policy_hash: SemanticHash,
    s3_request_hash: SemanticHash,
    residual_hash: SemanticHash,
) -> SemanticHash {
    let mut bytes = BINDING_DOMAIN.to_vec();
    for component in [
        COREVM0_R1_S3_BINDING_VERSION.0,
        COREVM0_R1_S3_BINDING_VERSION.1,
        COREVM0_R1_S3_BINDING_VERSION.2,
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
        upstream_request_hash,
        s3_policy_hash,
        s3_request_hash,
        residual_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    SemanticHash(sha256(&bytes))
}
