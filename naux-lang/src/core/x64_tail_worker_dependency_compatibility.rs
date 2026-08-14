//! ADR-0078 proof-only GNU version requirement-to-definition compatibility.
//!
//! This boundary joins only independently verified ADR-0076 requirements to
//! independently verified ADR-0077 primary definitions. It never inventories
//! or resolves a dynamic symbol, version-symbol entry, or relocation.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
};
use super::x64_tail_worker_dependency_closure::{
    X64TailWorkerDependencyClosureEvidence, X64TailWorkerDependencyClosureExpectation,
};
use super::x64_tail_worker_dependency_definitions::{
    verify_x64_tail_worker_dependency_definition_evidence, X64TailWorkerDependencyDefinitionError,
    X64TailWorkerDependencyDefinitionEvidence, X64TailWorkerDependencyDefinitionRecordEvidence,
    X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_dynamic::X64TailWorkerDependencyDynamicEvidence;
use super::x64_tail_worker_dependency_objects::{
    X64TailWorkerDependencyObjectManifest, X64TailWorkerDependencyObjectSet,
};
use super::x64_tail_worker_dependency_versions::{
    X64TailWorkerDependencyVersionAuxEvidence, X64TailWorkerDependencyVersionEvidence,
    X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT,
};
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use std::fmt;

pub const X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_PROVIDERS: u16 = 65;
pub const X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_REQUIREMENTS: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_BINDINGS: u16 = 4_096;
pub const X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_ROOT: SemanticHash = SemanticHash([
    0x01, 0x78, 0x32, 0xc1, 0x9b, 0x76, 0xfc, 0x99, 0x4f, 0x28, 0x40, 0x42, 0x3f, 0xde, 0xe0, 0x41,
    0x18, 0x93, 0xa5, 0xc9, 0xc2, 0x1e, 0x80, 0x8f, 0x1e, 0xe5, 0x97, 0x9e, 0x39, 0xf7, 0xc8, 0x4e,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-compatibility-policy:v1\0";
const BINDING_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-compatibility-binding:v1\0";
const OBJECT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-compatibility-object:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-compatibility-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "full-adr0076-requirement-replay-v1",
    "full-adr0077-definition-replay-v1",
    "exact-requester-requirement-auxiliary-order-v1",
    "exact-admitted-provider-only-selection-v1",
    "strong-requirement-only-v1",
    "unique-primary-name-and-elf-hash-join-v1",
    "source-and-target-evidence-hash-binding-v1",
    "domain-separated-binding-object-aggregate-replay-v1",
    "proof-only-no-symbol-versym-relocation-or-execution-v1",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyCompatibilityBindingEvidence {
    ordinal: u16,
    requester_provider_ordinal: u16,
    requester_object_evidence_hash: SemanticHash,
    requirement_ordinal: u16,
    requirement_evidence_hash: SemanticHash,
    auxiliary_ordinal: u16,
    requirement_auxiliary_evidence_hash: SemanticHash,
    requirement_name: String,
    requirement_name_hash: u32,
    requirement_version_index: u16,
    provider_ordinal: u16,
    provider_definition_object_evidence_hash: SemanticHash,
    definition_ordinal: u16,
    definition_evidence_hash: SemanticHash,
    definition_name: String,
    definition_name_hash: u32,
    definition_version_index: u16,
    definition_flags: u16,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyCompatibilityBindingEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn requester_provider_ordinal(&self) -> u16 {
        self.requester_provider_ordinal
    }

    pub const fn requirement_ordinal(&self) -> u16 {
        self.requirement_ordinal
    }

    pub const fn auxiliary_ordinal(&self) -> u16 {
        self.auxiliary_ordinal
    }

    pub fn requirement_name(&self) -> &str {
        &self.requirement_name
    }

    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub const fn definition_ordinal(&self) -> u16 {
        self.definition_ordinal
    }

    pub const fn definition_version_index(&self) -> u16 {
        self.definition_version_index
    }

    pub const fn definition_flags(&self) -> u16 {
        self.definition_flags
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyCompatibilityObjectEvidence {
    requester_provider_ordinal: u16,
    version_object_evidence_hash: SemanticHash,
    binding_count: u16,
    bindings: Vec<X64TailWorkerDependencyCompatibilityBindingEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyCompatibilityObjectEvidence {
    pub const fn requester_provider_ordinal(&self) -> u16 {
        self.requester_provider_ordinal
    }

    pub const fn binding_count(&self) -> u16 {
        self.binding_count
    }

    pub fn bindings(&self) -> &[X64TailWorkerDependencyCompatibilityBindingEvidence] {
        &self.bindings
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyCompatibilityEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    version_policy_hash: SemanticHash,
    version_evidence_hash: SemanticHash,
    definition_policy_hash: SemanticHash,
    definition_evidence_hash: SemanticHash,
    provider_count: u16,
    total_bindings: u16,
    objects: Vec<X64TailWorkerDependencyCompatibilityObjectEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyCompatibilityEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn version_evidence_hash(&self) -> SemanticHash {
        self.version_evidence_hash
    }

    pub const fn definition_evidence_hash(&self) -> SemanticHash {
        self.definition_evidence_hash
    }

    pub const fn provider_count(&self) -> u16 {
        self.provider_count
    }

    pub const fn total_bindings(&self) -> u16 {
        self.total_bindings
    }

    pub fn objects(&self) -> &[X64TailWorkerDependencyCompatibilityObjectEvidence] {
        &self.objects
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerDependencyCompatibility<'evidence> {
    evidence: &'evidence X64TailWorkerDependencyCompatibilityEvidence,
}

impl<'evidence> VerifiedX64TailWorkerDependencyCompatibility<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerDependencyCompatibilityEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerDependencyCompatibilityError {
    Definitions(X64TailWorkerDependencyDefinitionError),
    Invalid(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerDependencyCompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Definitions(error) => write!(formatter, "ADR-0078 definitions failed: {error}"),
            Self::Invalid(field) => write!(formatter, "invalid ADR-0078 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0078 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0078 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0078 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerDependencyCompatibilityError {}

impl From<X64TailWorkerDependencyDefinitionError> for X64TailWorkerDependencyCompatibilityError {
    fn from(value: X64TailWorkerDependencyDefinitionError) -> Self {
        Self::Definitions(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn admit_x64_tail_worker_dependency_compatibility(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
) -> Result<X64TailWorkerDependencyCompatibilityEvidence, X64TailWorkerDependencyCompatibilityError>
{
    if x64_tail_worker_dependency_compatibility_policy_hash()
        != X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_ROOT
    {
        return Err(X64TailWorkerDependencyCompatibilityError::Invalid(
            "policy root",
        ));
    }
    verify_x64_tail_worker_dependency_definition_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        version_evidence,
        definition_evidence,
    )?;
    build_compatibility_evidence(version_evidence, definition_evidence)
}

fn build_compatibility_evidence(
    versions: &X64TailWorkerDependencyVersionEvidence,
    definitions: &X64TailWorkerDependencyDefinitionEvidence,
) -> Result<X64TailWorkerDependencyCompatibilityEvidence, X64TailWorkerDependencyCompatibilityError>
{
    if versions.policy_hash() != X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT
        || definitions.policy_hash() != X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT
        || versions.provider_count() != definitions.provider_count()
        || versions.objects().len() != definitions.objects().len()
        || versions.objects().len()
            > usize::from(X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_PROVIDERS)
    {
        return Err(X64TailWorkerDependencyCompatibilityError::EvidenceMismatch);
    }
    let mut objects = Vec::with_capacity(versions.objects().len());
    let mut total_bindings = 0u16;
    for version_object in versions.objects() {
        if version_object.requirement_count()
            > X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_REQUIREMENTS
        {
            return Err(X64TailWorkerDependencyCompatibilityError::Limit {
                field: "requirements",
                limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_REQUIREMENTS),
                actual: u64::from(version_object.requirement_count()),
            });
        }
        let mut bindings = Vec::with_capacity(usize::from(version_object.auxiliary_count()));
        for requirement in version_object.requirements() {
            if requirement.auxiliaries().len()
                > usize::from(X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT)
            {
                return Err(X64TailWorkerDependencyCompatibilityError::Limit {
                    field: "requirement auxiliaries",
                    limit: u64::from(
                        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT,
                    ),
                    actual: u64::try_from(requirement.auxiliaries().len()).unwrap_or(u64::MAX),
                });
            }
            let provider = definitions
                .objects()
                .get(usize::from(requirement.provider_ordinal()))
                .ok_or(X64TailWorkerDependencyCompatibilityError::Invalid(
                    "requirement provider ordinal",
                ))?;
            if provider.provider_ordinal() != requirement.provider_ordinal()
                || provider.soname() != requirement.file_name()
            {
                return Err(X64TailWorkerDependencyCompatibilityError::Invalid(
                    "requirement provider identity",
                ));
            }
            for auxiliary in requirement.auxiliaries() {
                require_strong(auxiliary)?;
                let definition = select_definition(
                    provider.definitions(),
                    auxiliary.name(),
                    auxiliary.name_hash(),
                )?;
                total_bindings = total_bindings.checked_add(1).ok_or(
                    X64TailWorkerDependencyCompatibilityError::Overflow("total bindings"),
                )?;
                if total_bindings > X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_BINDINGS {
                    return Err(X64TailWorkerDependencyCompatibilityError::Limit {
                        field: "bindings",
                        limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_BINDINGS),
                        actual: u64::from(total_bindings),
                    });
                }
                let mut binding = X64TailWorkerDependencyCompatibilityBindingEvidence {
                    ordinal: u16::try_from(bindings.len()).map_err(|_| {
                        X64TailWorkerDependencyCompatibilityError::Overflow("binding ordinal")
                    })?,
                    requester_provider_ordinal: version_object.provider_ordinal(),
                    requester_object_evidence_hash: version_object.evidence_hash(),
                    requirement_ordinal: requirement.ordinal(),
                    requirement_evidence_hash: requirement.evidence_hash(),
                    auxiliary_ordinal: auxiliary.ordinal(),
                    requirement_auxiliary_evidence_hash: auxiliary.evidence_hash(),
                    requirement_name: auxiliary.name().to_owned(),
                    requirement_name_hash: auxiliary.name_hash(),
                    requirement_version_index: auxiliary.version_index(),
                    provider_ordinal: provider.provider_ordinal(),
                    provider_definition_object_evidence_hash: provider.evidence_hash(),
                    definition_ordinal: definition.ordinal(),
                    definition_evidence_hash: definition.evidence_hash(),
                    definition_name: definition.primary_name().to_owned(),
                    definition_name_hash: definition.name_hash(),
                    definition_version_index: definition.version_index(),
                    definition_flags: definition.flags(),
                    evidence_hash: SemanticHash::ZERO,
                };
                binding.evidence_hash = compatibility_binding_evidence_hash(&binding);
                bindings.push(binding);
            }
        }
        let mut object = X64TailWorkerDependencyCompatibilityObjectEvidence {
            requester_provider_ordinal: version_object.provider_ordinal(),
            version_object_evidence_hash: version_object.evidence_hash(),
            binding_count: u16::try_from(bindings.len()).map_err(|_| {
                X64TailWorkerDependencyCompatibilityError::Overflow("object bindings")
            })?,
            bindings,
            evidence_hash: SemanticHash::ZERO,
        };
        object.evidence_hash = compatibility_object_evidence_hash(&object);
        objects.push(object);
    }
    let mut evidence = X64TailWorkerDependencyCompatibilityEvidence {
        schema_version: X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_VERSION,
        policy_hash: x64_tail_worker_dependency_compatibility_policy_hash(),
        version_policy_hash: X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT,
        version_evidence_hash: versions.evidence_hash(),
        definition_policy_hash: X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT,
        definition_evidence_hash: definitions.evidence_hash(),
        provider_count: versions.provider_count(),
        total_bindings,
        objects,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_dependency_compatibility_evidence_hash(&evidence);
    Ok(evidence)
}

fn require_strong(
    auxiliary: &X64TailWorkerDependencyVersionAuxEvidence,
) -> Result<(), X64TailWorkerDependencyCompatibilityError> {
    require_strong_flags(auxiliary.flags())
}

fn require_strong_flags(flags: u16) -> Result<(), X64TailWorkerDependencyCompatibilityError> {
    if flags == 0 {
        Ok(())
    } else {
        Err(X64TailWorkerDependencyCompatibilityError::Invalid(
            "weak version requirement",
        ))
    }
}

fn select_definition<'definitions>(
    definitions: &'definitions [X64TailWorkerDependencyDefinitionRecordEvidence],
    name: &str,
    name_hash: u32,
) -> Result<
    &'definitions X64TailWorkerDependencyDefinitionRecordEvidence,
    X64TailWorkerDependencyCompatibilityError,
> {
    let mut matches = definitions.iter().filter(|definition| {
        definition.primary_name() == name && definition.name_hash() == name_hash
    });
    let selected = matches
        .next()
        .ok_or(X64TailWorkerDependencyCompatibilityError::Invalid(
            "missing strong version definition",
        ))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerDependencyCompatibilityError::Invalid(
            "ambiguous strong version definition",
        ));
    }
    Ok(selected)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_dependency_compatibility<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
    evidence: &'evidence X64TailWorkerDependencyCompatibilityEvidence,
) -> Result<
    VerifiedX64TailWorkerDependencyCompatibility<'evidence>,
    X64TailWorkerDependencyCompatibilityError,
> {
    preflight_compatibility_evidence(version_evidence, definition_evidence, evidence)?;
    let expected = admit_x64_tail_worker_dependency_compatibility(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        version_evidence,
        definition_evidence,
    )?;
    if &expected != evidence
        || x64_tail_worker_dependency_compatibility_evidence_hash(evidence)
            != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyCompatibilityError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerDependencyCompatibility { evidence })
}

fn preflight_compatibility_evidence(
    versions: &X64TailWorkerDependencyVersionEvidence,
    definitions: &X64TailWorkerDependencyDefinitionEvidence,
    evidence: &X64TailWorkerDependencyCompatibilityEvidence,
) -> Result<(), X64TailWorkerDependencyCompatibilityError> {
    if evidence.schema_version != X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_ROOT
        || evidence.policy_hash != x64_tail_worker_dependency_compatibility_policy_hash()
        || evidence.version_policy_hash != X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT
        || evidence.version_evidence_hash != versions.evidence_hash()
        || evidence.definition_policy_hash != X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT
        || evidence.definition_evidence_hash != definitions.evidence_hash()
        || evidence.provider_count != versions.provider_count()
        || evidence.provider_count != definitions.provider_count()
        || evidence.objects.len() != versions.objects().len()
        || evidence.total_bindings > X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_BINDINGS
        || x64_tail_worker_dependency_compatibility_evidence_hash(evidence)
            != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyCompatibilityError::EvidenceMismatch);
    }
    let mut total_bindings = 0u16;
    for (object_ordinal, ((object, version_object), _definition_object)) in evidence
        .objects
        .iter()
        .zip(versions.objects())
        .zip(definitions.objects())
        .enumerate()
    {
        let expected_binding_count = version_object
            .requirements()
            .iter()
            .map(|requirement| requirement.auxiliaries().len())
            .sum::<usize>();
        if object.requester_provider_ordinal != u16::try_from(object_ordinal).unwrap_or(u16::MAX)
            || object.requester_provider_ordinal != version_object.provider_ordinal()
            || object.version_object_evidence_hash != version_object.evidence_hash()
            || usize::from(object.binding_count) != expected_binding_count
            || object.bindings.len() != expected_binding_count
            || compatibility_object_evidence_hash(object) != object.evidence_hash
        {
            return Err(X64TailWorkerDependencyCompatibilityError::EvidenceMismatch);
        }
        let mut binding_ordinal = 0usize;
        for requirement in version_object.requirements() {
            let provider = definitions
                .objects()
                .get(usize::from(requirement.provider_ordinal()))
                .ok_or(X64TailWorkerDependencyCompatibilityError::EvidenceMismatch)?;
            for auxiliary in requirement.auxiliaries() {
                require_strong(auxiliary)?;
                let definition = select_definition(
                    provider.definitions(),
                    auxiliary.name(),
                    auxiliary.name_hash(),
                )?;
                let binding = object
                    .bindings
                    .get(binding_ordinal)
                    .ok_or(X64TailWorkerDependencyCompatibilityError::EvidenceMismatch)?;
                if binding.ordinal != u16::try_from(binding_ordinal).unwrap_or(u16::MAX)
                    || binding.requester_provider_ordinal != version_object.provider_ordinal()
                    || binding.requester_object_evidence_hash != version_object.evidence_hash()
                    || binding.requirement_ordinal != requirement.ordinal()
                    || binding.requirement_evidence_hash != requirement.evidence_hash()
                    || binding.auxiliary_ordinal != auxiliary.ordinal()
                    || binding.requirement_auxiliary_evidence_hash != auxiliary.evidence_hash()
                    || binding.requirement_name != auxiliary.name()
                    || binding.requirement_name_hash != auxiliary.name_hash()
                    || binding.requirement_version_index != auxiliary.version_index()
                    || binding.provider_ordinal != provider.provider_ordinal()
                    || binding.provider_definition_object_evidence_hash != provider.evidence_hash()
                    || binding.definition_ordinal != definition.ordinal()
                    || binding.definition_evidence_hash != definition.evidence_hash()
                    || binding.definition_name != definition.primary_name()
                    || binding.definition_name_hash != definition.name_hash()
                    || binding.definition_version_index != definition.version_index()
                    || binding.definition_flags != definition.flags()
                    || compatibility_binding_evidence_hash(binding) != binding.evidence_hash
                {
                    return Err(X64TailWorkerDependencyCompatibilityError::EvidenceMismatch);
                }
                binding_ordinal += 1;
            }
        }
        total_bindings = total_bindings.checked_add(object.binding_count).ok_or(
            X64TailWorkerDependencyCompatibilityError::Overflow("evidence bindings"),
        )?;
    }
    if total_bindings != evidence.total_bindings {
        return Err(X64TailWorkerDependencyCompatibilityError::EvidenceMismatch);
    }
    Ok(())
}

pub fn x64_tail_worker_dependency_compatibility_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_SCHEMA_VERSION,
    );
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_VERSION,
    );
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT);
    put_hash(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_PROVIDERS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_REQUIREMENTS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_BINDINGS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_MAX_NAME_BYTES,
    );
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn compatibility_binding_evidence_hash(
    evidence: &X64TailWorkerDependencyCompatibilityBindingEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(BINDING_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u16(&mut bytes, evidence.requester_provider_ordinal);
    put_hash(&mut bytes, evidence.requester_object_evidence_hash);
    put_u16(&mut bytes, evidence.requirement_ordinal);
    put_hash(&mut bytes, evidence.requirement_evidence_hash);
    put_u16(&mut bytes, evidence.auxiliary_ordinal);
    put_hash(&mut bytes, evidence.requirement_auxiliary_evidence_hash);
    put_string(&mut bytes, &evidence.requirement_name);
    put_u32(&mut bytes, evidence.requirement_name_hash);
    put_u16(&mut bytes, evidence.requirement_version_index);
    put_u16(&mut bytes, evidence.provider_ordinal);
    put_hash(
        &mut bytes,
        evidence.provider_definition_object_evidence_hash,
    );
    put_u16(&mut bytes, evidence.definition_ordinal);
    put_hash(&mut bytes, evidence.definition_evidence_hash);
    put_string(&mut bytes, &evidence.definition_name);
    put_u32(&mut bytes, evidence.definition_name_hash);
    put_u16(&mut bytes, evidence.definition_version_index);
    put_u16(&mut bytes, evidence.definition_flags);
    SemanticHash(sha256(&bytes))
}

fn compatibility_object_evidence_hash(
    evidence: &X64TailWorkerDependencyCompatibilityObjectEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(OBJECT_DOMAIN);
    put_u16(&mut bytes, evidence.requester_provider_ordinal);
    put_hash(&mut bytes, evidence.version_object_evidence_hash);
    put_u16(&mut bytes, evidence.binding_count);
    for binding in &evidence.bindings {
        put_hash(&mut bytes, binding.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_dependency_compatibility_evidence_hash(
    evidence: &X64TailWorkerDependencyCompatibilityEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.version_policy_hash);
    put_hash(&mut bytes, evidence.version_evidence_hash);
    put_hash(&mut bytes, evidence.definition_policy_hash);
    put_hash(&mut bytes, evidence.definition_evidence_hash);
    put_u16(&mut bytes, evidence.provider_count);
    put_u16(&mut bytes, evidence.total_bindings);
    for object in &evidence.objects {
        put_hash(&mut bytes, object.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    put_u16(bytes, version.0);
    put_u16(bytes, version.1);
    put_u16(bytes, version.2);
}

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u16(bytes, u16::try_from(value.len()).unwrap_or(u16::MAX));
    bytes.extend_from_slice(value.as_bytes());
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_dependency_compatibility_join_edges(
    versions: &X64TailWorkerDependencyVersionEvidence,
    definitions: &X64TailWorkerDependencyDefinitionEvidence,
) -> bool {
    let Some(auxiliary) = versions
        .objects()
        .iter()
        .flat_map(|object| object.requirements())
        .flat_map(|requirement| requirement.auxiliaries())
        .next()
    else {
        return false;
    };
    let Some(provider) = definitions.objects().iter().find(|provider| {
        provider
            .definitions()
            .iter()
            .any(|definition| definition.primary_name() == auxiliary.name())
    }) else {
        return false;
    };
    let mut duplicate_definitions = provider.definitions().to_vec();
    let Some(exact) = duplicate_definitions
        .iter()
        .find(|definition| definition.primary_name() == auxiliary.name())
        .cloned()
    else {
        return false;
    };
    duplicate_definitions.push(exact);
    let wrong_provider_collision_is_visible = definitions
        .objects()
        .iter()
        .filter(|candidate| candidate.provider_ordinal() != provider.provider_ordinal())
        .any(|candidate| {
            select_definition(
                candidate.definitions(),
                auxiliary.name(),
                auxiliary.name_hash(),
            )
            .is_err()
        });
    require_strong_flags(2).is_err()
        && select_definition(
            provider.definitions(),
            "NAUX_MISSING_VERSION",
            auxiliary.name_hash(),
        )
        .is_err()
        && select_definition(
            provider.definitions(),
            auxiliary.name(),
            auxiliary.name_hash() ^ 1,
        )
        .is_err()
        && select_definition(
            &duplicate_definitions,
            auxiliary.name(),
            auxiliary.name_hash(),
        )
        .is_err()
        && wrong_provider_collision_is_visible
}

#[cfg(debug_assertions)]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn probe_x64_tail_worker_dependency_compatibility_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
    evidence: &X64TailWorkerDependencyCompatibilityEvidence,
) -> bool {
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_versions = evidence.clone();
    stale_versions.version_evidence_hash.0[0] ^= 1;
    let mut stale_definitions = evidence.clone();
    stale_definitions.definition_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.total_bindings = stale_count.total_bindings.saturating_add(1);
    let mut stale_object = evidence.clone();
    stale_object.objects[0].requester_provider_ordinal ^= 1;
    let mut stale_binding = evidence.clone();
    let Some(binding) = stale_binding
        .objects
        .iter_mut()
        .flat_map(|object| object.bindings.iter_mut())
        .next()
    else {
        return false;
    };
    binding.definition_version_index ^= 1;
    let mut reordered = evidence.clone();
    let Some(object) = reordered
        .objects
        .iter_mut()
        .find(|object| object.bindings.len() >= 2)
    else {
        return false;
    };
    object.bindings.swap(0, 1);

    let shallow_rejected = [
        stale_policy,
        stale_versions,
        stale_definitions,
        stale_count,
        stale_object,
        stale_binding,
        reordered,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_dependency_compatibility(
            artifact,
            inventory,
            declaration_expectation,
            declaration_evidence,
            manifest,
            object_set,
            dynamic_evidence,
            closure_expectation,
            closure_evidence,
            version_evidence,
            definition_evidence,
            mutation,
        )
        .is_err()
    });

    let mut resealed = evidence.clone();
    let Some((object_ordinal, binding_ordinal)) =
        resealed
            .objects
            .iter()
            .enumerate()
            .find_map(|(object_ordinal, object)| {
                (!object.bindings.is_empty()).then_some((object_ordinal, 0usize))
            })
    else {
        return false;
    };
    let binding = &mut resealed.objects[object_ordinal].bindings[binding_ordinal];
    let Some(alternative) = definition_evidence
        .objects()
        .get(usize::from(binding.provider_ordinal))
        .and_then(|provider| {
            provider
                .definitions()
                .iter()
                .find(|definition| definition.ordinal() != binding.definition_ordinal)
        })
    else {
        return false;
    };
    binding.definition_ordinal = alternative.ordinal();
    binding.definition_evidence_hash = alternative.evidence_hash();
    binding.definition_name = alternative.primary_name().to_owned();
    binding.definition_name_hash = alternative.name_hash();
    binding.definition_version_index = alternative.version_index();
    binding.definition_flags = alternative.flags();
    binding.evidence_hash = compatibility_binding_evidence_hash(binding);
    let object = &mut resealed.objects[object_ordinal];
    object.evidence_hash = compatibility_object_evidence_hash(object);
    resealed.evidence_hash = x64_tail_worker_dependency_compatibility_evidence_hash(&resealed);
    let resealed_rejected = verify_x64_tail_worker_dependency_compatibility(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        version_evidence,
        definition_evidence,
        &resealed,
    )
    .is_err();

    shallow_rejected
        && resealed_rejected
        && probe_x64_tail_worker_dependency_compatibility_join_edges(
            version_evidence,
            definition_evidence,
        )
}
