//! ADR-0083 proof-only reviewed root dynamic-symbol lookup-scope admission.
//!
//! This boundary admits only an ordered list of already sealed providers. It
//! never looks up a name, selects a definition, relocates, maps, or executes.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
};
use super::x64_tail_worker_dependency_closure::{
    X64TailWorkerDependencyClosureEvidence, X64TailWorkerDependencyClosureExpectation,
    X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_compatibility::X64TailWorkerDependencyCompatibilityEvidence;
use super::x64_tail_worker_dependency_definitions::X64TailWorkerDependencyDefinitionEvidence;
use super::x64_tail_worker_dependency_dynamic::X64TailWorkerDependencyDynamicEvidence;
use super::x64_tail_worker_dependency_objects::{
    X64TailWorkerDependencyObjectManifest, X64TailWorkerDependencyObjectSet,
};
use super::x64_tail_worker_dependency_symbols::{
    verify_x64_tail_worker_dependency_symbol_evidence, X64TailWorkerDependencySymbolError,
    X64TailWorkerDependencySymbolEvidence, X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_versions::X64TailWorkerDependencyVersionEvidence;
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use super::x64_tail_worker_root_compatibility::X64TailWorkerRootCompatibilityEvidence;
use super::x64_tail_worker_root_symbols::{
    verify_x64_tail_worker_root_symbol_evidence, X64TailWorkerRootSymbolError,
    X64TailWorkerRootSymbolEvidence, X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT,
};
use super::x64_tail_worker_root_versions::X64TailWorkerRootVersionEvidence;
use std::fmt;

pub const X64_TAIL_WORKER_ROOT_SCOPE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_SCOPE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_SCOPE_MAX_PROVIDERS: u16 = 65;
pub const X64_TAIL_WORKER_ROOT_SCOPE_MAX_ENTRIES: u16 = 65;
pub const X64_TAIL_WORKER_ROOT_SCOPE_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT: SemanticHash = SemanticHash([
    75, 145, 63, 162, 114, 138, 149, 48, 35, 105, 18, 32, 180, 142, 144, 92, 202, 220, 20, 161, 76,
    188, 201, 143, 52, 45, 74, 103, 29, 41, 118, 90,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-scope-policy:v1\0";
const ENTRY_EXPECTATION_DOMAIN: &[u8] =
    b"NAUX:x86-64:tail-worker-root-scope-entry-expectation:v1\0";
const EXPECTATION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-scope-expectation:v1\0";
const ENTRY_EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-scope-entry-evidence:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-scope-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "externally-reviewed-complete-ordered-provider-scope-v1",
    "full-adr0079-provider-symbol-replay-v1",
    "full-adr0082-root-requester-replay-v1",
    "provider-order-independent-of-canonical-provider-ordinal-v1",
    "exact-soname-object-closure-and-symbol-identity-binding-v1",
    "complete-provider-membership-exactly-once-v1",
    "domain-separated-expectation-entry-and-aggregate-replay-v1",
    "proof-only-no-name-lookup-selection-relocation-or-execution-v1",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootScopeEntryExpectation {
    schema_version: (u16, u16, u16),
    provider_ordinal: u16,
    soname: String,
    object_hash: SemanticHash,
    closure_provider_evidence_hash: SemanticHash,
    provider_symbol_object_evidence_hash: SemanticHash,
    expectation_hash: SemanticHash,
}

impl X64TailWorkerRootScopeEntryExpectation {
    pub fn new(
        provider_ordinal: u16,
        soname: String,
        object_hash: SemanticHash,
        closure_provider_evidence_hash: SemanticHash,
        provider_symbol_object_evidence_hash: SemanticHash,
    ) -> Result<Self, X64TailWorkerRootScopeError> {
        let mut expectation = Self {
            schema_version: X64_TAIL_WORKER_ROOT_SCOPE_SCHEMA_VERSION,
            provider_ordinal,
            soname,
            object_hash,
            closure_provider_evidence_hash,
            provider_symbol_object_evidence_hash,
            expectation_hash: SemanticHash::ZERO,
        };
        validate_entry_expectation_shape(&expectation)?;
        expectation.expectation_hash = root_scope_entry_expectation_hash(&expectation);
        Ok(expectation)
    }

    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub fn soname(&self) -> &str {
        &self.soname
    }

    pub const fn object_hash(&self) -> SemanticHash {
        self.object_hash
    }

    pub const fn closure_provider_evidence_hash(&self) -> SemanticHash {
        self.closure_provider_evidence_hash
    }

    pub const fn provider_symbol_object_evidence_hash(&self) -> SemanticHash {
        self.provider_symbol_object_evidence_hash
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootScopeExpectation {
    schema_version: (u16, u16, u16),
    dependency_symbol_evidence_hash: SemanticHash,
    root_symbol_evidence_hash: SemanticHash,
    entries: Vec<X64TailWorkerRootScopeEntryExpectation>,
    expectation_hash: SemanticHash,
}

impl X64TailWorkerRootScopeExpectation {
    pub fn new(
        dependency_symbol_evidence_hash: SemanticHash,
        root_symbol_evidence_hash: SemanticHash,
        entries: Vec<X64TailWorkerRootScopeEntryExpectation>,
    ) -> Result<Self, X64TailWorkerRootScopeError> {
        let mut expectation = Self {
            schema_version: X64_TAIL_WORKER_ROOT_SCOPE_SCHEMA_VERSION,
            dependency_symbol_evidence_hash,
            root_symbol_evidence_hash,
            entries,
            expectation_hash: SemanticHash::ZERO,
        };
        validate_scope_expectation_shape(&expectation)?;
        expectation.expectation_hash = x64_tail_worker_root_scope_expectation_hash(&expectation);
        Ok(expectation)
    }

    pub fn entries(&self) -> &[X64TailWorkerRootScopeEntryExpectation] {
        &self.entries
    }

    pub const fn dependency_symbol_evidence_hash(&self) -> SemanticHash {
        self.dependency_symbol_evidence_hash
    }

    pub const fn root_symbol_evidence_hash(&self) -> SemanticHash {
        self.root_symbol_evidence_hash
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootScopeEntryEvidence {
    ordinal: u16,
    expectation_hash: SemanticHash,
    provider_ordinal: u16,
    soname: String,
    object_hash: SemanticHash,
    closure_provider_evidence_hash: SemanticHash,
    provider_symbol_object_evidence_hash: SemanticHash,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootScopeEntryEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub fn soname(&self) -> &str {
        &self.soname
    }

    pub const fn object_hash(&self) -> SemanticHash {
        self.object_hash
    }

    pub const fn closure_provider_evidence_hash(&self) -> SemanticHash {
        self.closure_provider_evidence_hash
    }

    pub const fn provider_symbol_object_evidence_hash(&self) -> SemanticHash {
        self.provider_symbol_object_evidence_hash
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootScopeEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    closure_policy_hash: SemanticHash,
    closure_evidence_hash: SemanticHash,
    dependency_symbol_policy_hash: SemanticHash,
    dependency_symbol_evidence_hash: SemanticHash,
    root_symbol_policy_hash: SemanticHash,
    root_symbol_evidence_hash: SemanticHash,
    expectation_hash: SemanticHash,
    scope_count: u16,
    entries: Vec<X64TailWorkerRootScopeEntryEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootScopeEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn scope_count(&self) -> u16 {
        self.scope_count
    }

    pub fn entries(&self) -> &[X64TailWorkerRootScopeEntryEvidence] {
        &self.entries
    }

    pub const fn dependency_symbol_evidence_hash(&self) -> SemanticHash {
        self.dependency_symbol_evidence_hash
    }

    pub const fn root_symbol_evidence_hash(&self) -> SemanticHash {
        self.root_symbol_evidence_hash
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerRootScope<'evidence> {
    evidence: &'evidence X64TailWorkerRootScopeEvidence,
}

impl<'evidence> VerifiedX64TailWorkerRootScope<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerRootScopeEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerRootScopeError {
    DependencySymbols(X64TailWorkerDependencySymbolError),
    RootSymbols(X64TailWorkerRootSymbolError),
    InvalidExpectation(&'static str),
    Invalid(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    ExpectationMismatch,
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerRootScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DependencySymbols(error) => {
                write!(formatter, "ADR-0083 provider symbols failed: {error}")
            }
            Self::RootSymbols(error) => write!(formatter, "ADR-0083 root symbols failed: {error}"),
            Self::InvalidExpectation(field) => {
                write!(formatter, "invalid ADR-0083 expectation {field}")
            }
            Self::Invalid(field) => write!(formatter, "invalid ADR-0083 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0083 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0083 {field} overflow"),
            Self::ExpectationMismatch => formatter.write_str("ADR-0083 expectation mismatch"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0083 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerRootScopeError {}

impl From<X64TailWorkerDependencySymbolError> for X64TailWorkerRootScopeError {
    fn from(value: X64TailWorkerDependencySymbolError) -> Self {
        Self::DependencySymbols(value)
    }
}

impl From<X64TailWorkerRootSymbolError> for X64TailWorkerRootScopeError {
    fn from(value: X64TailWorkerRootSymbolError) -> Self {
        Self::RootSymbols(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn admit_x64_tail_worker_root_scope(
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
    dependency_compatibility_evidence: &X64TailWorkerDependencyCompatibilityEvidence,
    dependency_symbol_evidence: &X64TailWorkerDependencySymbolEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
    root_compatibility_evidence: &X64TailWorkerRootCompatibilityEvidence,
    root_symbol_evidence: &X64TailWorkerRootSymbolEvidence,
    expectation: &X64TailWorkerRootScopeExpectation,
) -> Result<X64TailWorkerRootScopeEvidence, X64TailWorkerRootScopeError> {
    if x64_tail_worker_root_scope_policy_hash() != X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT {
        return Err(X64TailWorkerRootScopeError::Invalid("policy root"));
    }
    validate_scope_expectation(expectation)?;
    verify_x64_tail_worker_dependency_symbol_evidence(
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
        dependency_compatibility_evidence,
        dependency_symbol_evidence,
    )?;
    verify_x64_tail_worker_root_symbol_evidence(
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
        root_version_evidence,
        root_compatibility_evidence,
        root_symbol_evidence,
    )?;
    if expectation.dependency_symbol_evidence_hash != dependency_symbol_evidence.evidence_hash()
        || expectation.root_symbol_evidence_hash != root_symbol_evidence.evidence_hash()
        || closure_evidence.provider_count() != dependency_symbol_evidence.provider_count()
        || expectation.entries.len() != usize::from(closure_evidence.provider_count())
    {
        return Err(X64TailWorkerRootScopeError::ExpectationMismatch);
    }

    let mut seen = vec![false; closure_evidence.providers().len()];
    let mut entries = Vec::with_capacity(expectation.entries.len());
    for (ordinal, reviewed) in expectation.entries.iter().enumerate() {
        let provider_index = usize::from(reviewed.provider_ordinal);
        let provider = closure_evidence
            .providers()
            .get(provider_index)
            .ok_or(X64TailWorkerRootScopeError::ExpectationMismatch)?;
        let symbol_object = dependency_symbol_evidence
            .objects()
            .get(provider_index)
            .ok_or(X64TailWorkerRootScopeError::ExpectationMismatch)?;
        if seen[provider_index]
            || provider.ordinal() != reviewed.provider_ordinal
            || symbol_object.provider_ordinal() != reviewed.provider_ordinal
            || reviewed.soname != provider.soname()
            || reviewed.soname != symbol_object.soname()
            || reviewed.object_hash != provider.object_hash()
            || reviewed.object_hash != symbol_object.object_hash()
            || reviewed.closure_provider_evidence_hash != provider.evidence_hash()
            || reviewed.closure_provider_evidence_hash
                != symbol_object.closure_provider_evidence_hash()
            || reviewed.provider_symbol_object_evidence_hash != symbol_object.evidence_hash()
        {
            return Err(X64TailWorkerRootScopeError::ExpectationMismatch);
        }
        seen[provider_index] = true;
        let mut entry = X64TailWorkerRootScopeEntryEvidence {
            ordinal: u16::try_from(ordinal)
                .map_err(|_| X64TailWorkerRootScopeError::Overflow("scope ordinal"))?,
            expectation_hash: reviewed.expectation_hash,
            provider_ordinal: reviewed.provider_ordinal,
            soname: reviewed.soname.clone(),
            object_hash: reviewed.object_hash,
            closure_provider_evidence_hash: reviewed.closure_provider_evidence_hash,
            provider_symbol_object_evidence_hash: reviewed.provider_symbol_object_evidence_hash,
            evidence_hash: SemanticHash::ZERO,
        };
        entry.evidence_hash = root_scope_entry_evidence_hash(&entry);
        entries.push(entry);
    }
    if seen.iter().any(|present| !present) {
        return Err(X64TailWorkerRootScopeError::ExpectationMismatch);
    }

    let mut evidence = X64TailWorkerRootScopeEvidence {
        schema_version: X64_TAIL_WORKER_ROOT_SCOPE_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ROOT_SCOPE_POLICY_VERSION,
        policy_hash: x64_tail_worker_root_scope_policy_hash(),
        closure_policy_hash: X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
        closure_evidence_hash: closure_evidence.evidence_hash(),
        dependency_symbol_policy_hash: X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT,
        dependency_symbol_evidence_hash: dependency_symbol_evidence.evidence_hash(),
        root_symbol_policy_hash: X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT,
        root_symbol_evidence_hash: root_symbol_evidence.evidence_hash(),
        expectation_hash: expectation.expectation_hash,
        scope_count: u16::try_from(entries.len())
            .map_err(|_| X64TailWorkerRootScopeError::Overflow("scope count"))?,
        entries,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_root_scope_evidence_hash(&evidence);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_root_scope<'evidence>(
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
    dependency_compatibility_evidence: &X64TailWorkerDependencyCompatibilityEvidence,
    dependency_symbol_evidence: &X64TailWorkerDependencySymbolEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
    root_compatibility_evidence: &X64TailWorkerRootCompatibilityEvidence,
    root_symbol_evidence: &X64TailWorkerRootSymbolEvidence,
    expectation: &X64TailWorkerRootScopeExpectation,
    evidence: &'evidence X64TailWorkerRootScopeEvidence,
) -> Result<VerifiedX64TailWorkerRootScope<'evidence>, X64TailWorkerRootScopeError> {
    preflight_scope_evidence(
        closure_evidence,
        dependency_symbol_evidence,
        root_symbol_evidence,
        expectation,
        evidence,
    )?;
    let expected = admit_x64_tail_worker_root_scope(
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
        dependency_compatibility_evidence,
        dependency_symbol_evidence,
        root_version_evidence,
        root_compatibility_evidence,
        root_symbol_evidence,
        expectation,
    )?;
    if &expected != evidence
        || x64_tail_worker_root_scope_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootScopeError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerRootScope { evidence })
}

fn validate_entry_expectation_shape(
    expectation: &X64TailWorkerRootScopeEntryExpectation,
) -> Result<(), X64TailWorkerRootScopeError> {
    if expectation.schema_version != X64_TAIL_WORKER_ROOT_SCOPE_SCHEMA_VERSION {
        return Err(X64TailWorkerRootScopeError::InvalidExpectation(
            "entry schema",
        ));
    }
    validate_name(&expectation.soname)?;
    if expectation.provider_ordinal >= X64_TAIL_WORKER_ROOT_SCOPE_MAX_PROVIDERS
        || expectation.object_hash == SemanticHash::ZERO
        || expectation.closure_provider_evidence_hash == SemanticHash::ZERO
        || expectation.provider_symbol_object_evidence_hash == SemanticHash::ZERO
    {
        return Err(X64TailWorkerRootScopeError::InvalidExpectation(
            "entry identity",
        ));
    }
    Ok(())
}

fn validate_scope_expectation_shape(
    expectation: &X64TailWorkerRootScopeExpectation,
) -> Result<(), X64TailWorkerRootScopeError> {
    if expectation.schema_version != X64_TAIL_WORKER_ROOT_SCOPE_SCHEMA_VERSION {
        return Err(X64TailWorkerRootScopeError::InvalidExpectation(
            "scope schema",
        ));
    }
    if expectation.entries.is_empty()
        || expectation.entries.len() > usize::from(X64_TAIL_WORKER_ROOT_SCOPE_MAX_ENTRIES)
    {
        return Err(X64TailWorkerRootScopeError::Limit {
            field: "scope entries",
            limit: u64::from(X64_TAIL_WORKER_ROOT_SCOPE_MAX_ENTRIES),
            actual: u64::try_from(expectation.entries.len()).unwrap_or(u64::MAX),
        });
    }
    if expectation.dependency_symbol_evidence_hash == SemanticHash::ZERO
        || expectation.root_symbol_evidence_hash == SemanticHash::ZERO
    {
        return Err(X64TailWorkerRootScopeError::InvalidExpectation(
            "predecessor identity",
        ));
    }
    for (ordinal, entry) in expectation.entries.iter().enumerate() {
        validate_entry_expectation_shape(entry)?;
        if expectation.entries[..ordinal]
            .iter()
            .any(|existing| existing.provider_ordinal == entry.provider_ordinal)
        {
            return Err(X64TailWorkerRootScopeError::InvalidExpectation(
                "duplicate provider",
            ));
        }
    }
    Ok(())
}

fn validate_scope_expectation(
    expectation: &X64TailWorkerRootScopeExpectation,
) -> Result<(), X64TailWorkerRootScopeError> {
    validate_scope_expectation_shape(expectation)?;
    if expectation
        .entries
        .iter()
        .any(|entry| root_scope_entry_expectation_hash(entry) != entry.expectation_hash)
        || x64_tail_worker_root_scope_expectation_hash(expectation) != expectation.expectation_hash
    {
        return Err(X64TailWorkerRootScopeError::InvalidExpectation(
            "expectation hash",
        ));
    }
    Ok(())
}

fn preflight_scope_evidence(
    closure: &X64TailWorkerDependencyClosureEvidence,
    dependency_symbols: &X64TailWorkerDependencySymbolEvidence,
    root_symbols: &X64TailWorkerRootSymbolEvidence,
    expectation: &X64TailWorkerRootScopeExpectation,
    evidence: &X64TailWorkerRootScopeEvidence,
) -> Result<(), X64TailWorkerRootScopeError> {
    validate_scope_expectation(expectation)?;
    if evidence.schema_version != X64_TAIL_WORKER_ROOT_SCOPE_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_ROOT_SCOPE_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT
        || evidence.closure_policy_hash != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT
        || evidence.closure_evidence_hash != closure.evidence_hash()
        || evidence.dependency_symbol_policy_hash != X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT
        || evidence.dependency_symbol_evidence_hash != dependency_symbols.evidence_hash()
        || evidence.root_symbol_policy_hash != X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT
        || evidence.root_symbol_evidence_hash != root_symbols.evidence_hash()
        || evidence.expectation_hash != expectation.expectation_hash
        || usize::from(evidence.scope_count) != evidence.entries.len()
        || evidence.entries.len() != expectation.entries.len()
        || evidence.entries.len() != closure.providers().len()
        || evidence.entries.len() != dependency_symbols.objects().len()
        || x64_tail_worker_root_scope_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootScopeError::EvidenceMismatch);
    }
    let mut seen_providers = vec![false; closure.providers().len()];
    let mut seen_expectations = vec![false; expectation.entries.len()];
    for (ordinal, entry) in evidence.entries.iter().enumerate() {
        if entry.ordinal != u16::try_from(ordinal).unwrap_or(u16::MAX)
            || root_scope_entry_evidence_hash(entry) != entry.evidence_hash
        {
            return Err(X64TailWorkerRootScopeError::EvidenceMismatch);
        }
        validate_name(&entry.soname)?;
        let provider_index = usize::from(entry.provider_ordinal);
        let Some(provider_seen) = seen_providers.get_mut(provider_index) else {
            return Err(X64TailWorkerRootScopeError::EvidenceMismatch);
        };
        if *provider_seen {
            return Err(X64TailWorkerRootScopeError::EvidenceMismatch);
        }
        *provider_seen = true;
        let Some(expectation_index) = expectation
            .entries
            .iter()
            .position(|reviewed| reviewed.expectation_hash == entry.expectation_hash)
        else {
            return Err(X64TailWorkerRootScopeError::EvidenceMismatch);
        };
        if seen_expectations[expectation_index] {
            return Err(X64TailWorkerRootScopeError::EvidenceMismatch);
        }
        seen_expectations[expectation_index] = true;
    }
    if seen_providers.iter().any(|seen| !seen) || seen_expectations.iter().any(|seen| !seen) {
        return Err(X64TailWorkerRootScopeError::EvidenceMismatch);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), X64TailWorkerRootScopeError> {
    if name.is_empty()
        || name.len() > usize::from(X64_TAIL_WORKER_ROOT_SCOPE_MAX_NAME_BYTES)
        || name
            .as_bytes()
            .iter()
            .any(|byte| !(0x21..=0x7e).contains(byte) || *byte == b'/' || *byte == b'\\')
    {
        return Err(X64TailWorkerRootScopeError::InvalidExpectation(
            "provider SONAME",
        ));
    }
    Ok(())
}

pub fn x64_tail_worker_root_scope_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_SCOPE_SCHEMA_VERSION);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_SCOPE_POLICY_VERSION);
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SCOPE_MAX_PROVIDERS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SCOPE_MAX_ENTRIES);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SCOPE_MAX_NAME_BYTES);
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn root_scope_entry_expectation_hash(
    expectation: &X64TailWorkerRootScopeEntryExpectation,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(ENTRY_EXPECTATION_DOMAIN);
    put_version(&mut bytes, expectation.schema_version);
    put_u16(&mut bytes, expectation.provider_ordinal);
    put_string(&mut bytes, &expectation.soname);
    put_hash(&mut bytes, expectation.object_hash);
    put_hash(&mut bytes, expectation.closure_provider_evidence_hash);
    put_hash(&mut bytes, expectation.provider_symbol_object_evidence_hash);
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_root_scope_expectation_hash(
    expectation: &X64TailWorkerRootScopeExpectation,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EXPECTATION_DOMAIN);
    put_version(&mut bytes, expectation.schema_version);
    put_hash(&mut bytes, expectation.dependency_symbol_evidence_hash);
    put_hash(&mut bytes, expectation.root_symbol_evidence_hash);
    put_u16(
        &mut bytes,
        u16::try_from(expectation.entries.len()).unwrap_or(u16::MAX),
    );
    for entry in &expectation.entries {
        put_hash(&mut bytes, entry.expectation_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn root_scope_entry_evidence_hash(evidence: &X64TailWorkerRootScopeEntryEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(ENTRY_EVIDENCE_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_hash(&mut bytes, evidence.expectation_hash);
    put_u16(&mut bytes, evidence.provider_ordinal);
    put_string(&mut bytes, &evidence.soname);
    put_hash(&mut bytes, evidence.object_hash);
    put_hash(&mut bytes, evidence.closure_provider_evidence_hash);
    put_hash(&mut bytes, evidence.provider_symbol_object_evidence_hash);
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_root_scope_evidence_hash(
    evidence: &X64TailWorkerRootScopeEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.closure_policy_hash);
    put_hash(&mut bytes, evidence.closure_evidence_hash);
    put_hash(&mut bytes, evidence.dependency_symbol_policy_hash);
    put_hash(&mut bytes, evidence.dependency_symbol_evidence_hash);
    put_hash(&mut bytes, evidence.root_symbol_policy_hash);
    put_hash(&mut bytes, evidence.root_symbol_evidence_hash);
    put_hash(&mut bytes, evidence.expectation_hash);
    put_u16(&mut bytes, evidence.scope_count);
    for entry in &evidence.entries {
        put_hash(&mut bytes, entry.evidence_hash);
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

#[cfg(debug_assertions)]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn probe_x64_tail_worker_root_scope_mutations(
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
    dependency_compatibility_evidence: &X64TailWorkerDependencyCompatibilityEvidence,
    dependency_symbol_evidence: &X64TailWorkerDependencySymbolEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
    root_compatibility_evidence: &X64TailWorkerRootCompatibilityEvidence,
    root_symbol_evidence: &X64TailWorkerRootSymbolEvidence,
    expectation: &X64TailWorkerRootScopeExpectation,
    evidence: &X64TailWorkerRootScopeEvidence,
) -> bool {
    if evidence.entries.len() < 2 {
        return false;
    }
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_provider_symbols = evidence.clone();
    stale_provider_symbols.dependency_symbol_evidence_hash.0[0] ^= 1;
    let mut stale_root_symbols = evidence.clone();
    stale_root_symbols.root_symbol_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.scope_count = stale_count.scope_count.saturating_add(1);
    let mut stale_entry = evidence.clone();
    stale_entry.entries[0].soname.push('x');
    let shallow_rejected = [
        stale_policy,
        stale_provider_symbols,
        stale_root_symbols,
        stale_count,
        stale_entry,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_root_scope(
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
            dependency_compatibility_evidence,
            dependency_symbol_evidence,
            root_version_evidence,
            root_compatibility_evidence,
            root_symbol_evidence,
            expectation,
            mutation,
        )
        .is_err()
    });

    let mut reordered = evidence.clone();
    reordered.entries.swap(0, 1);
    for (ordinal, entry) in reordered.entries.iter_mut().enumerate() {
        entry.ordinal = u16::try_from(ordinal).unwrap_or(u16::MAX);
        entry.evidence_hash = root_scope_entry_evidence_hash(entry);
    }
    reordered.evidence_hash = x64_tail_worker_root_scope_evidence_hash(&reordered);
    let coherent_reorder_rejected = verify_x64_tail_worker_root_scope(
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
        dependency_compatibility_evidence,
        dependency_symbol_evidence,
        root_version_evidence,
        root_compatibility_evidence,
        root_symbol_evidence,
        expectation,
        &reordered,
    )
    .is_err();

    shallow_rejected && coherent_reorder_rejected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_scope_policy_root_is_frozen() {
        assert_eq!(
            x64_tail_worker_root_scope_policy_hash(),
            X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT
        );
    }

    #[test]
    fn production_module_has_no_forbidden_authority() {
        let source = include_str!("x64_tail_worker_root_scope.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in [
            "std::fs",
            "std::path",
            "std::process",
            "x64_tail_worker_dependency_object_bytes",
            "readelf",
            "object::",
            "goblin",
            "libloading",
            "x64_tail_enveloped_native",
            "x64_native_process",
            "x64_standalone",
            "x64_target::raw",
        ] {
            assert!(
                !production.contains(forbidden),
                "production scope admission contains forbidden authority {forbidden}"
            );
        }
    }
}
