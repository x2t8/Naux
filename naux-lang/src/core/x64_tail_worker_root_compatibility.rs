//! ADR-0081 proof-only root GNU version compatibility admission.
//!
//! This boundary joins the independently verified ADR-0080 root requirements
//! to independently verified ADR-0077 provider definitions. It grants no
//! root symbol inventory, lookup, mapping, or execution authority.

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
use super::x64_tail_worker_dependency_versions::X64TailWorkerDependencyVersionEvidence;
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use super::x64_tail_worker_root_versions::{
    verify_x64_tail_worker_root_version_evidence, X64TailWorkerRootVersionError,
    X64TailWorkerRootVersionEvidence, X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT,
};
use std::fmt;

pub const X64_TAIL_WORKER_ROOT_COMPATIBILITY_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_PROVIDERS: u16 = 65;
pub const X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_REQUIREMENTS: u16 = 64;
pub const X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT: u16 = 64;
pub const X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_BINDINGS: u16 = 4_096;
pub const X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT: SemanticHash = SemanticHash([
    0xdb, 0x6e, 0x8c, 0x46, 0x40, 0xa1, 0x9a, 0x7a, 0x7c, 0x79, 0x25, 0xd9, 0x7c, 0x64, 0x92, 0x3c,
    0xcb, 0xd4, 0xe5, 0xba, 0xf9, 0xc3, 0xa2, 0x93, 0x78, 0x6f, 0x96, 0x2b, 0x13, 0xa1, 0xdf, 0x0e,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-compatibility-policy:v1\0";
const BINDING_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-compatibility-binding:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-compatibility-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "full-adr0080-root-requirement-replay-v1",
    "full-adr0077-provider-definition-replay-v1",
    "exact-root-requirement-auxiliary-order-v1",
    "exact-root-bound-provider-only-selection-v1",
    "strong-requirement-and-definition-only-v1",
    "unique-primary-name-and-elf-hash-join-v1",
    "source-and-target-evidence-hash-binding-v1",
    "domain-separated-binding-and-aggregate-replay-v1",
    "proof-only-no-root-symbol-lookup-mapping-or-execution-v1",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootCompatibilityBindingEvidence {
    ordinal: u16,
    root_requirement_ordinal: u16,
    root_requirement_evidence_hash: SemanticHash,
    root_auxiliary_ordinal: u16,
    root_auxiliary_evidence_hash: SemanticHash,
    requirement_file_name: String,
    declaration_ordinal: u16,
    requirement_name: String,
    requirement_name_hash: u32,
    requirement_flags: u16,
    requirement_version_index: u16,
    provider_ordinal: u16,
    root_provider_evidence_hash: SemanticHash,
    provider_definition_object_evidence_hash: SemanticHash,
    definition_ordinal: u16,
    definition_evidence_hash: SemanticHash,
    definition_name: String,
    definition_name_hash: u32,
    definition_version_index: u16,
    definition_flags: u16,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootCompatibilityBindingEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn root_requirement_ordinal(&self) -> u16 {
        self.root_requirement_ordinal
    }

    pub const fn root_requirement_evidence_hash(&self) -> SemanticHash {
        self.root_requirement_evidence_hash
    }

    pub const fn root_auxiliary_ordinal(&self) -> u16 {
        self.root_auxiliary_ordinal
    }

    pub const fn root_auxiliary_evidence_hash(&self) -> SemanticHash {
        self.root_auxiliary_evidence_hash
    }

    pub fn requirement_file_name(&self) -> &str {
        &self.requirement_file_name
    }

    pub const fn declaration_ordinal(&self) -> u16 {
        self.declaration_ordinal
    }

    pub fn requirement_name(&self) -> &str {
        &self.requirement_name
    }

    pub const fn requirement_name_hash(&self) -> u32 {
        self.requirement_name_hash
    }

    pub const fn requirement_flags(&self) -> u16 {
        self.requirement_flags
    }

    pub const fn requirement_version_index(&self) -> u16 {
        self.requirement_version_index
    }

    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub const fn root_provider_evidence_hash(&self) -> SemanticHash {
        self.root_provider_evidence_hash
    }

    pub const fn provider_definition_object_evidence_hash(&self) -> SemanticHash {
        self.provider_definition_object_evidence_hash
    }

    pub const fn definition_ordinal(&self) -> u16 {
        self.definition_ordinal
    }

    pub const fn definition_evidence_hash(&self) -> SemanticHash {
        self.definition_evidence_hash
    }

    pub fn definition_name(&self) -> &str {
        &self.definition_name
    }

    pub const fn definition_name_hash(&self) -> u32 {
        self.definition_name_hash
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
pub struct X64TailWorkerRootCompatibilityEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    root_version_policy_hash: SemanticHash,
    root_version_evidence_hash: SemanticHash,
    definition_policy_hash: SemanticHash,
    definition_evidence_hash: SemanticHash,
    provider_count: u16,
    requirement_count: u16,
    binding_count: u16,
    bindings: Vec<X64TailWorkerRootCompatibilityBindingEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootCompatibilityEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn root_version_evidence_hash(&self) -> SemanticHash {
        self.root_version_evidence_hash
    }

    pub const fn definition_evidence_hash(&self) -> SemanticHash {
        self.definition_evidence_hash
    }

    pub const fn provider_count(&self) -> u16 {
        self.provider_count
    }

    pub const fn requirement_count(&self) -> u16 {
        self.requirement_count
    }

    pub const fn binding_count(&self) -> u16 {
        self.binding_count
    }

    pub fn bindings(&self) -> &[X64TailWorkerRootCompatibilityBindingEvidence] {
        &self.bindings
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerRootCompatibility<'evidence> {
    evidence: &'evidence X64TailWorkerRootCompatibilityEvidence,
}

impl<'evidence> VerifiedX64TailWorkerRootCompatibility<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerRootCompatibilityEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerRootCompatibilityError {
    RootVersions(X64TailWorkerRootVersionError),
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

impl fmt::Display for X64TailWorkerRootCompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootVersions(error) => {
                write!(formatter, "ADR-0081 root versions failed: {error}")
            }
            Self::Definitions(error) => write!(formatter, "ADR-0081 definitions failed: {error}"),
            Self::Invalid(field) => write!(formatter, "invalid ADR-0081 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0081 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0081 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0081 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerRootCompatibilityError {}

impl From<X64TailWorkerRootVersionError> for X64TailWorkerRootCompatibilityError {
    fn from(value: X64TailWorkerRootVersionError) -> Self {
        Self::RootVersions(value)
    }
}

impl From<X64TailWorkerDependencyDefinitionError> for X64TailWorkerRootCompatibilityError {
    fn from(value: X64TailWorkerDependencyDefinitionError) -> Self {
        Self::Definitions(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn admit_x64_tail_worker_root_compatibility(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    dependency_version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
) -> Result<X64TailWorkerRootCompatibilityEvidence, X64TailWorkerRootCompatibilityError> {
    if x64_tail_worker_root_compatibility_policy_hash()
        != X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT
    {
        return Err(X64TailWorkerRootCompatibilityError::Invalid("policy root"));
    }
    verify_x64_tail_worker_root_version_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        root_version_evidence,
    )?;
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
        dependency_version_evidence,
        definition_evidence,
    )?;
    build_root_compatibility_evidence(root_version_evidence, definition_evidence)
}

fn build_root_compatibility_evidence(
    root_versions: &X64TailWorkerRootVersionEvidence,
    definitions: &X64TailWorkerDependencyDefinitionEvidence,
) -> Result<X64TailWorkerRootCompatibilityEvidence, X64TailWorkerRootCompatibilityError> {
    if root_versions.policy_hash() != X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT
        || definitions.policy_hash() != X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT
        || definitions.objects().len()
            > usize::from(X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_PROVIDERS)
        || root_versions.requirement_count() > X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_REQUIREMENTS
        || root_versions.requirements().len() != usize::from(root_versions.requirement_count())
    {
        return Err(X64TailWorkerRootCompatibilityError::EvidenceMismatch);
    }
    let mut bindings = Vec::with_capacity(usize::from(root_versions.auxiliary_count()));
    for requirement in root_versions.requirements() {
        if requirement.auxiliaries().len()
            > usize::from(X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT)
        {
            return Err(X64TailWorkerRootCompatibilityError::Limit {
                field: "requirement auxiliaries",
                limit: u64::from(X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT),
                actual: u64::try_from(requirement.auxiliaries().len()).unwrap_or(u64::MAX),
            });
        }
        require_name(requirement.file_name())?;
        let provider = definitions
            .objects()
            .get(usize::from(requirement.provider_ordinal()))
            .ok_or(X64TailWorkerRootCompatibilityError::Invalid(
                "root requirement provider ordinal",
            ))?;
        if provider.provider_ordinal() != requirement.provider_ordinal()
            || provider.soname() != requirement.file_name()
        {
            return Err(X64TailWorkerRootCompatibilityError::Invalid(
                "root requirement provider identity",
            ));
        }
        for auxiliary in requirement.auxiliaries() {
            require_strong_flags(auxiliary.flags(), "weak root version requirement")?;
            require_name(auxiliary.name())?;
            let definition = select_strong_definition(
                provider.definitions(),
                auxiliary.name(),
                auxiliary.name_hash(),
            )?;
            require_name(definition.primary_name())?;
            let ordinal = u16::try_from(bindings.len())
                .map_err(|_| X64TailWorkerRootCompatibilityError::Overflow("binding ordinal"))?;
            if ordinal >= X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_BINDINGS {
                return Err(X64TailWorkerRootCompatibilityError::Limit {
                    field: "bindings",
                    limit: u64::from(X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_BINDINGS),
                    actual: u64::try_from(bindings.len().saturating_add(1)).unwrap_or(u64::MAX),
                });
            }
            let mut binding = X64TailWorkerRootCompatibilityBindingEvidence {
                ordinal,
                root_requirement_ordinal: requirement.ordinal(),
                root_requirement_evidence_hash: requirement.evidence_hash(),
                root_auxiliary_ordinal: auxiliary.ordinal(),
                root_auxiliary_evidence_hash: auxiliary.evidence_hash(),
                requirement_file_name: requirement.file_name().to_owned(),
                declaration_ordinal: requirement.declaration_ordinal(),
                requirement_name: auxiliary.name().to_owned(),
                requirement_name_hash: auxiliary.name_hash(),
                requirement_flags: auxiliary.flags(),
                requirement_version_index: auxiliary.version_index(),
                provider_ordinal: provider.provider_ordinal(),
                root_provider_evidence_hash: requirement.provider_evidence_hash(),
                provider_definition_object_evidence_hash: provider.evidence_hash(),
                definition_ordinal: definition.ordinal(),
                definition_evidence_hash: definition.evidence_hash(),
                definition_name: definition.primary_name().to_owned(),
                definition_name_hash: definition.name_hash(),
                definition_version_index: definition.version_index(),
                definition_flags: definition.flags(),
                evidence_hash: SemanticHash::ZERO,
            };
            binding.evidence_hash = root_compatibility_binding_evidence_hash(&binding);
            bindings.push(binding);
        }
    }
    let binding_count = u16::try_from(bindings.len())
        .map_err(|_| X64TailWorkerRootCompatibilityError::Overflow("binding count"))?;
    if binding_count != root_versions.auxiliary_count() {
        return Err(X64TailWorkerRootCompatibilityError::EvidenceMismatch);
    }
    let mut evidence = X64TailWorkerRootCompatibilityEvidence {
        schema_version: X64_TAIL_WORKER_ROOT_COMPATIBILITY_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_VERSION,
        policy_hash: x64_tail_worker_root_compatibility_policy_hash(),
        root_version_policy_hash: X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT,
        root_version_evidence_hash: root_versions.evidence_hash(),
        definition_policy_hash: X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT,
        definition_evidence_hash: definitions.evidence_hash(),
        provider_count: definitions.provider_count(),
        requirement_count: root_versions.requirement_count(),
        binding_count,
        bindings,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_root_compatibility_evidence_hash(&evidence);
    Ok(evidence)
}

fn require_name(name: &str) -> Result<(), X64TailWorkerRootCompatibilityError> {
    if name.is_empty()
        || name.len() > usize::from(X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_NAME_BYTES)
    {
        Err(X64TailWorkerRootCompatibilityError::Invalid("name"))
    } else {
        Ok(())
    }
}

fn require_strong_flags(
    flags: u16,
    field: &'static str,
) -> Result<(), X64TailWorkerRootCompatibilityError> {
    if flags == 0 {
        Ok(())
    } else {
        Err(X64TailWorkerRootCompatibilityError::Invalid(field))
    }
}

fn select_strong_definition<'definitions>(
    definitions: &'definitions [X64TailWorkerDependencyDefinitionRecordEvidence],
    name: &str,
    name_hash: u32,
) -> Result<
    &'definitions X64TailWorkerDependencyDefinitionRecordEvidence,
    X64TailWorkerRootCompatibilityError,
> {
    let mut matches = definitions.iter().filter(|definition| {
        definition.primary_name() == name && definition.name_hash() == name_hash
    });
    let selected = matches
        .next()
        .ok_or(X64TailWorkerRootCompatibilityError::Invalid(
            "missing strong version definition",
        ))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerRootCompatibilityError::Invalid(
            "ambiguous strong version definition",
        ));
    }
    require_strong_flags(selected.flags(), "weak or base version definition")?;
    Ok(selected)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_root_compatibility<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    dependency_version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
    evidence: &'evidence X64TailWorkerRootCompatibilityEvidence,
) -> Result<VerifiedX64TailWorkerRootCompatibility<'evidence>, X64TailWorkerRootCompatibilityError>
{
    preflight_root_compatibility_evidence(root_version_evidence, definition_evidence, evidence)?;
    let expected = admit_x64_tail_worker_root_compatibility(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        dependency_version_evidence,
        definition_evidence,
        root_version_evidence,
    )?;
    if &expected != evidence
        || x64_tail_worker_root_compatibility_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootCompatibilityError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerRootCompatibility { evidence })
}

fn preflight_root_compatibility_evidence(
    root_versions: &X64TailWorkerRootVersionEvidence,
    definitions: &X64TailWorkerDependencyDefinitionEvidence,
    evidence: &X64TailWorkerRootCompatibilityEvidence,
) -> Result<(), X64TailWorkerRootCompatibilityError> {
    if evidence.schema_version != X64_TAIL_WORKER_ROOT_COMPATIBILITY_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT
        || evidence.policy_hash != x64_tail_worker_root_compatibility_policy_hash()
        || evidence.root_version_policy_hash != X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT
        || evidence.root_version_evidence_hash != root_versions.evidence_hash()
        || evidence.definition_policy_hash != X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT
        || evidence.definition_evidence_hash != definitions.evidence_hash()
        || evidence.provider_count != definitions.provider_count()
        || evidence.requirement_count != root_versions.requirement_count()
        || evidence.binding_count != root_versions.auxiliary_count()
        || evidence.bindings.len() != usize::from(evidence.binding_count)
        || evidence.provider_count > X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_PROVIDERS
        || evidence.requirement_count > X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_REQUIREMENTS
        || evidence.binding_count > X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_BINDINGS
        || x64_tail_worker_root_compatibility_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootCompatibilityError::EvidenceMismatch);
    }
    let mut binding_ordinal = 0usize;
    for requirement in root_versions.requirements() {
        if requirement.auxiliaries().len()
            > usize::from(X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT)
        {
            return Err(X64TailWorkerRootCompatibilityError::EvidenceMismatch);
        }
        let provider = definitions
            .objects()
            .get(usize::from(requirement.provider_ordinal()))
            .ok_or(X64TailWorkerRootCompatibilityError::EvidenceMismatch)?;
        if provider.provider_ordinal() != requirement.provider_ordinal()
            || provider.soname() != requirement.file_name()
        {
            return Err(X64TailWorkerRootCompatibilityError::EvidenceMismatch);
        }
        for auxiliary in requirement.auxiliaries() {
            require_strong_flags(auxiliary.flags(), "weak root version requirement")?;
            let definition = select_strong_definition(
                provider.definitions(),
                auxiliary.name(),
                auxiliary.name_hash(),
            )?;
            let binding = evidence
                .bindings
                .get(binding_ordinal)
                .ok_or(X64TailWorkerRootCompatibilityError::EvidenceMismatch)?;
            if binding.ordinal != u16::try_from(binding_ordinal).unwrap_or(u16::MAX)
                || binding.root_requirement_ordinal != requirement.ordinal()
                || binding.root_requirement_evidence_hash != requirement.evidence_hash()
                || binding.root_auxiliary_ordinal != auxiliary.ordinal()
                || binding.root_auxiliary_evidence_hash != auxiliary.evidence_hash()
                || binding.requirement_file_name != requirement.file_name()
                || binding.declaration_ordinal != requirement.declaration_ordinal()
                || binding.requirement_name != auxiliary.name()
                || binding.requirement_name_hash != auxiliary.name_hash()
                || binding.requirement_flags != auxiliary.flags()
                || binding.requirement_version_index != auxiliary.version_index()
                || binding.provider_ordinal != provider.provider_ordinal()
                || binding.root_provider_evidence_hash != requirement.provider_evidence_hash()
                || binding.provider_definition_object_evidence_hash != provider.evidence_hash()
                || binding.definition_ordinal != definition.ordinal()
                || binding.definition_evidence_hash != definition.evidence_hash()
                || binding.definition_name != definition.primary_name()
                || binding.definition_name_hash != definition.name_hash()
                || binding.definition_version_index != definition.version_index()
                || binding.definition_flags != definition.flags()
                || root_compatibility_binding_evidence_hash(binding) != binding.evidence_hash
            {
                return Err(X64TailWorkerRootCompatibilityError::EvidenceMismatch);
            }
            binding_ordinal += 1;
        }
    }
    if binding_ordinal != evidence.bindings.len() {
        return Err(X64TailWorkerRootCompatibilityError::EvidenceMismatch);
    }
    Ok(())
}

pub fn x64_tail_worker_root_compatibility_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_ROOT_COMPATIBILITY_SCHEMA_VERSION,
    );
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_VERSION,
    );
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT);
    put_hash(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT,
    );
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_PROVIDERS);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_REQUIREMENTS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_AUX_PER_REQUIREMENT,
    );
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_BINDINGS);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_ROOT_COMPATIBILITY_MAX_NAME_BYTES,
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

fn root_compatibility_binding_evidence_hash(
    evidence: &X64TailWorkerRootCompatibilityBindingEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(640);
    bytes.extend_from_slice(BINDING_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u16(&mut bytes, evidence.root_requirement_ordinal);
    put_hash(&mut bytes, evidence.root_requirement_evidence_hash);
    put_u16(&mut bytes, evidence.root_auxiliary_ordinal);
    put_hash(&mut bytes, evidence.root_auxiliary_evidence_hash);
    put_string(&mut bytes, &evidence.requirement_file_name);
    put_u16(&mut bytes, evidence.declaration_ordinal);
    put_string(&mut bytes, &evidence.requirement_name);
    put_u32(&mut bytes, evidence.requirement_name_hash);
    put_u16(&mut bytes, evidence.requirement_flags);
    put_u16(&mut bytes, evidence.requirement_version_index);
    put_u16(&mut bytes, evidence.provider_ordinal);
    put_hash(&mut bytes, evidence.root_provider_evidence_hash);
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

pub fn x64_tail_worker_root_compatibility_evidence_hash(
    evidence: &X64TailWorkerRootCompatibilityEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.root_version_policy_hash);
    put_hash(&mut bytes, evidence.root_version_evidence_hash);
    put_hash(&mut bytes, evidence.definition_policy_hash);
    put_hash(&mut bytes, evidence.definition_evidence_hash);
    put_u16(&mut bytes, evidence.provider_count);
    put_u16(&mut bytes, evidence.requirement_count);
    put_u16(&mut bytes, evidence.binding_count);
    for binding in &evidence.bindings {
        put_hash(&mut bytes, binding.evidence_hash);
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
pub fn probe_x64_tail_worker_root_compatibility_join_edges(
    root_versions: &X64TailWorkerRootVersionEvidence,
    definitions: &X64TailWorkerDependencyDefinitionEvidence,
) -> bool {
    let glibc_23 = root_versions
        .requirements()
        .iter()
        .flat_map(|requirement| {
            requirement
                .auxiliaries()
                .iter()
                .filter(|auxiliary| auxiliary.name() == "GLIBC_2.3")
                .map(move |auxiliary| (requirement, auxiliary))
        })
        .collect::<Vec<_>>();
    if glibc_23.len() != 2 || glibc_23[0].0.provider_ordinal() == glibc_23[1].0.provider_ordinal() {
        return false;
    }
    let exact_selection = glibc_23.iter().all(|(requirement, auxiliary)| {
        definitions
            .objects()
            .get(usize::from(requirement.provider_ordinal()))
            .is_some_and(|provider| {
                provider.soname() == requirement.file_name()
                    && select_strong_definition(
                        provider.definitions(),
                        auxiliary.name(),
                        auxiliary.name_hash(),
                    )
                    .is_ok()
            })
    });
    let first_auxiliary = glibc_23[0].1;
    let cross_provider_collision_exists = definitions.objects().iter().any(|provider| {
        provider.provider_ordinal() != glibc_23[0].0.provider_ordinal()
            && select_strong_definition(
                provider.definitions(),
                first_auxiliary.name(),
                first_auxiliary.name_hash(),
            )
            .is_ok()
    });
    let provider = &definitions.objects()[usize::from(glibc_23[0].0.provider_ordinal())];
    let mut duplicate_definitions = provider.definitions().to_vec();
    let Some(exact) = duplicate_definitions
        .iter()
        .find(|definition| definition.primary_name() == first_auxiliary.name())
        .cloned()
    else {
        return false;
    };
    duplicate_definitions.push(exact);
    exact_selection
        && cross_provider_collision_exists
        && require_strong_flags(2, "weak").is_err()
        && select_strong_definition(
            provider.definitions(),
            "NAUX_MISSING_VERSION",
            first_auxiliary.name_hash(),
        )
        .is_err()
        && select_strong_definition(
            provider.definitions(),
            first_auxiliary.name(),
            first_auxiliary.name_hash() ^ 1,
        )
        .is_err()
        && select_strong_definition(
            &duplicate_definitions,
            first_auxiliary.name(),
            first_auxiliary.name_hash(),
        )
        .is_err()
}

#[cfg(debug_assertions)]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn probe_x64_tail_worker_root_compatibility_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    dependency_version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
    evidence: &X64TailWorkerRootCompatibilityEvidence,
) -> bool {
    if evidence.bindings.len() < 2 {
        return false;
    }
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_root = evidence.clone();
    stale_root.root_version_evidence_hash.0[0] ^= 1;
    let mut stale_definitions = evidence.clone();
    stale_definitions.definition_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.binding_count = stale_count.binding_count.saturating_add(1);
    let mut stale_binding = evidence.clone();
    stale_binding.bindings[0].requirement_name.push('X');
    let mut reordered = evidence.clone();
    reordered.bindings.swap(0, 1);
    let shallow_rejected = [
        stale_policy,
        stale_root,
        stale_definitions,
        stale_count,
        stale_binding,
        reordered,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_root_compatibility(
            artifact,
            inventory,
            declaration_expectation,
            declaration_evidence,
            manifest,
            object_set,
            dynamic_evidence,
            closure_expectation,
            closure_evidence,
            dependency_version_evidence,
            definition_evidence,
            root_version_evidence,
            mutation,
        )
        .is_err()
    });

    let Some((target_binding_ordinal, target_provider_ordinal)) = evidence
        .bindings
        .iter()
        .enumerate()
        .find(|(_, binding)| binding.requirement_name == "GLIBC_2.3")
        .map(|(ordinal, binding)| (ordinal, binding.provider_ordinal))
    else {
        return false;
    };
    let Some((alternate_requirement, alternate_auxiliary)) = root_version_evidence
        .requirements()
        .iter()
        .find_map(|requirement| {
            (requirement.provider_ordinal() != target_provider_ordinal).then(|| {
                requirement
                    .auxiliaries()
                    .iter()
                    .find(|auxiliary| auxiliary.name() == "GLIBC_2.3")
                    .map(|auxiliary| (requirement, auxiliary))
            })?
        })
    else {
        return false;
    };
    let Some(alternate_provider) = definition_evidence
        .objects()
        .get(usize::from(alternate_requirement.provider_ordinal()))
    else {
        return false;
    };
    let Ok(alternate_definition) = select_strong_definition(
        alternate_provider.definitions(),
        alternate_auxiliary.name(),
        alternate_auxiliary.name_hash(),
    ) else {
        return false;
    };
    let mut resealed = evidence.clone();
    let binding = &mut resealed.bindings[target_binding_ordinal];
    binding.root_requirement_ordinal = alternate_requirement.ordinal();
    binding.root_requirement_evidence_hash = alternate_requirement.evidence_hash();
    binding.root_auxiliary_ordinal = alternate_auxiliary.ordinal();
    binding.root_auxiliary_evidence_hash = alternate_auxiliary.evidence_hash();
    binding.requirement_file_name = alternate_requirement.file_name().to_owned();
    binding.declaration_ordinal = alternate_requirement.declaration_ordinal();
    binding.requirement_name = alternate_auxiliary.name().to_owned();
    binding.requirement_name_hash = alternate_auxiliary.name_hash();
    binding.requirement_flags = alternate_auxiliary.flags();
    binding.requirement_version_index = alternate_auxiliary.version_index();
    binding.provider_ordinal = alternate_provider.provider_ordinal();
    binding.root_provider_evidence_hash = alternate_requirement.provider_evidence_hash();
    binding.provider_definition_object_evidence_hash = alternate_provider.evidence_hash();
    binding.definition_ordinal = alternate_definition.ordinal();
    binding.definition_evidence_hash = alternate_definition.evidence_hash();
    binding.definition_name = alternate_definition.primary_name().to_owned();
    binding.definition_name_hash = alternate_definition.name_hash();
    binding.definition_version_index = alternate_definition.version_index();
    binding.definition_flags = alternate_definition.flags();
    binding.evidence_hash = root_compatibility_binding_evidence_hash(binding);
    resealed.evidence_hash = x64_tail_worker_root_compatibility_evidence_hash(&resealed);
    let resealed_rejected = verify_x64_tail_worker_root_compatibility(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        dependency_version_evidence,
        definition_evidence,
        root_version_evidence,
        &resealed,
    )
    .is_err();

    shallow_rejected
        && resealed_rejected
        && probe_x64_tail_worker_root_compatibility_join_edges(
            root_version_evidence,
            definition_evidence,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_compatibility_policy_root_is_frozen() {
        let actual = x64_tail_worker_root_compatibility_policy_hash();
        assert_eq!(
            actual, X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT,
            "{actual}"
        );
    }

    #[test]
    fn production_module_has_no_forbidden_authority() {
        let source = include_str!("x64_tail_worker_root_compatibility.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let imports = production
            .lines()
            .filter(|line| line.trim_start().starts_with("use "))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "std::fs",
            "std::path",
            "std::process",
            "object::",
            "goblin",
            "libloading",
            "dependency_symbols::",
            "x64_tail_enveloped_native",
            "x64_native_process",
            "x64_standalone",
            "x64_target::raw",
        ] {
            assert!(
                !imports.contains(forbidden),
                "forbidden authority: {forbidden}"
            );
        }
    }
}
