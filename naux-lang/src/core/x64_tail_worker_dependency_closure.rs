//! ADR-0075 proof-only reviewed transitive-declaration closure admission.
//!
//! This boundary compares an externally reviewed canonical SONAME/digest/edge
//! graph with the independently reconstructed ADR-0074 inventory. It proves
//! only closure inside the immutable ADR-0073 object set. It never searches a
//! path, consults the host loader, maps an object, or executes code.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
};
use super::x64_tail_worker_dependency_dynamic::{
    verify_x64_tail_worker_dependency_dynamic_evidence, X64TailWorkerDependencyDynamicError,
    X64TailWorkerDependencyDynamicEvidence, X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_objects::{
    X64TailWorkerDependencyObjectManifest, X64TailWorkerDependencyObjectSet,
};
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use std::fmt;

pub const X64_TAIL_WORKER_DEPENDENCY_CLOSURE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_PROVIDERS: u16 = 65;
pub const X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_APPEARANCES: u16 = 65;
pub const X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_EDGES: u16 = 4_096;
pub const X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT: SemanticHash = SemanticHash([
    0x68, 0x35, 0xb6, 0x5f, 0x73, 0xbe, 0x7d, 0x21, 0x4d, 0xa2, 0x3b, 0x20, 0xc9, 0x2b, 0x93, 0x01,
    0x3a, 0xc0, 0x2c, 0x5f, 0x3b, 0x96, 0xc4, 0xab, 0xf7, 0x43, 0xcd, 0x50, 0x37, 0x61, 0xbd, 0x56,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-closure-policy:v1\0";
const PROVIDER_EXPECTATION_DOMAIN: &[u8] =
    b"NAUX:x86-64:tail-worker-dependency-closure-provider-expectation:v1\0";
const EXPECTATION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-closure-expectation:v1\0";
const PROVIDER_EVIDENCE_DOMAIN: &[u8] =
    b"NAUX:x86-64:tail-worker-dependency-closure-provider-evidence:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-closure-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "externally-reviewed-canonical-soname-digest-edge-graph-v1",
    "full-adr0074-predecessor-replay-v1",
    "canonical-first-appearance-provider-order-v1",
    "exact-provider-object-digest-binding-v1",
    "ordered-needed-edge-binding-v1",
    "unique-in-set-provider-resolution-v1",
    "duplicate-soname-exact-digest-and-facts-collapse-v1",
    "reject-missing-extra-duplicate-ambiguous-provider-v1",
    "domain-separated-expectation-and-evidence-replay-v1",
    "proof-only-no-host-loader-resolution-map-or-execute-v1",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyClosureProviderExpectation {
    schema_version: (u16, u16, u16),
    soname: String,
    object_hash: SemanticHash,
    needed: Vec<String>,
    expectation_hash: SemanticHash,
}

impl X64TailWorkerDependencyClosureProviderExpectation {
    pub fn new(
        soname: String,
        object_hash: SemanticHash,
        needed: Vec<String>,
    ) -> Result<Self, X64TailWorkerDependencyClosureError> {
        let mut expectation = Self {
            schema_version: X64_TAIL_WORKER_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
            soname,
            object_hash,
            needed,
            expectation_hash: SemanticHash::ZERO,
        };
        validate_provider_expectation_shape(&expectation)?;
        expectation.expectation_hash = closure_provider_expectation_hash(&expectation);
        Ok(expectation)
    }

    pub fn soname(&self) -> &str {
        &self.soname
    }

    pub const fn object_hash(&self) -> SemanticHash {
        self.object_hash
    }

    pub fn needed(&self) -> &[String] {
        &self.needed
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyClosureExpectation {
    schema_version: (u16, u16, u16),
    providers: Vec<X64TailWorkerDependencyClosureProviderExpectation>,
    expectation_hash: SemanticHash,
}

impl X64TailWorkerDependencyClosureExpectation {
    pub fn new(
        providers: Vec<X64TailWorkerDependencyClosureProviderExpectation>,
    ) -> Result<Self, X64TailWorkerDependencyClosureError> {
        let mut expectation = Self {
            schema_version: X64_TAIL_WORKER_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
            providers,
            expectation_hash: SemanticHash::ZERO,
        };
        validate_closure_expectation_shape(&expectation)?;
        expectation.expectation_hash =
            x64_tail_worker_dependency_closure_expectation_hash(&expectation);
        Ok(expectation)
    }

    pub fn providers(&self) -> &[X64TailWorkerDependencyClosureProviderExpectation] {
        &self.providers
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyClosureProviderEvidence {
    ordinal: u16,
    expectation_hash: SemanticHash,
    first_object_ordinal: u16,
    source_object_ordinals: Vec<u16>,
    first_dynamic_evidence_hash: SemanticHash,
    soname: String,
    object_hash: SemanticHash,
    needed: Vec<String>,
    edge_provider_ordinals: Vec<u16>,
    dynamic_flags: u64,
    dynamic_flags_1: u64,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyClosureProviderEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub fn soname(&self) -> &str {
        &self.soname
    }

    pub const fn object_hash(&self) -> SemanticHash {
        self.object_hash
    }

    pub fn needed(&self) -> &[String] {
        &self.needed
    }

    pub fn edge_provider_ordinals(&self) -> &[u16] {
        &self.edge_provider_ordinals
    }

    pub fn source_object_ordinals(&self) -> &[u16] {
        &self.source_object_ordinals
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyClosureEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    dynamic_policy_hash: SemanticHash,
    dynamic_evidence_hash: SemanticHash,
    object_set_evidence_hash: SemanticHash,
    expectation_hash: SemanticHash,
    provider_count: u16,
    appearance_count: u16,
    edge_count: u16,
    providers: Vec<X64TailWorkerDependencyClosureProviderEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyClosureEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn dynamic_evidence_hash(&self) -> SemanticHash {
        self.dynamic_evidence_hash
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }

    pub const fn provider_count(&self) -> u16 {
        self.provider_count
    }

    pub const fn appearance_count(&self) -> u16 {
        self.appearance_count
    }

    pub const fn edge_count(&self) -> u16 {
        self.edge_count
    }

    pub fn providers(&self) -> &[X64TailWorkerDependencyClosureProviderEvidence] {
        &self.providers
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerDependencyClosure<'evidence> {
    evidence: &'evidence X64TailWorkerDependencyClosureEvidence,
}

impl<'evidence> VerifiedX64TailWorkerDependencyClosure<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerDependencyClosureEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerDependencyClosureError {
    Dynamic(X64TailWorkerDependencyDynamicError),
    InvalidExpectation(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    MissingProvider(String),
    ConflictingProvider(String),
    ExpectationMismatch,
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerDependencyClosureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dynamic(error) => write!(formatter, "ADR-0075 predecessor failed: {error}"),
            Self::InvalidExpectation(field) => {
                write!(formatter, "invalid ADR-0075 expectation {field}")
            }
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0075 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0075 {field} overflow"),
            Self::MissingProvider(name) => {
                write!(formatter, "ADR-0075 has no reviewed provider for {name}")
            }
            Self::ConflictingProvider(name) => {
                write!(formatter, "ADR-0075 has conflicting providers for {name}")
            }
            Self::ExpectationMismatch => formatter.write_str("ADR-0075 expectation mismatch"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0075 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerDependencyClosureError {}

impl From<X64TailWorkerDependencyDynamicError> for X64TailWorkerDependencyClosureError {
    fn from(value: X64TailWorkerDependencyDynamicError) -> Self {
        Self::Dynamic(value)
    }
}

#[derive(Clone)]
struct CanonicalProvider {
    first_object_ordinal: u16,
    source_object_ordinals: Vec<u16>,
    first_dynamic_evidence_hash: SemanticHash,
    soname: String,
    object_hash: SemanticHash,
    needed: Vec<String>,
    dynamic_flags: u64,
    dynamic_flags_1: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn admit_x64_tail_worker_dependency_closure(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    expectation: &X64TailWorkerDependencyClosureExpectation,
) -> Result<X64TailWorkerDependencyClosureEvidence, X64TailWorkerDependencyClosureError> {
    if x64_tail_worker_dependency_closure_policy_hash()
        != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT
    {
        return Err(X64TailWorkerDependencyClosureError::InvalidExpectation(
            "policy root",
        ));
    }
    validate_closure_expectation(expectation)?;
    verify_x64_tail_worker_dependency_dynamic_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
    )?;

    let canonical = derive_canonical_providers(object_set, dynamic_evidence)?;
    compare_reviewed_graph(expectation, &canonical)?;
    let appearance_count = canonical.iter().try_fold(0u16, |total, provider| {
        total
            .checked_add(
                u16::try_from(provider.source_object_ordinals.len()).map_err(|_| {
                    X64TailWorkerDependencyClosureError::Overflow("appearance count")
                })?,
            )
            .ok_or(X64TailWorkerDependencyClosureError::Overflow(
                "appearance count",
            ))
    })?;
    let edge_count = canonical.iter().try_fold(0u16, |total, provider| {
        total
            .checked_add(
                u16::try_from(provider.needed.len())
                    .map_err(|_| X64TailWorkerDependencyClosureError::Overflow("edge count"))?,
            )
            .ok_or(X64TailWorkerDependencyClosureError::Overflow("edge count"))
    })?;
    enforce_aggregate_limits(canonical.len(), appearance_count, edge_count)?;

    let mut providers = Vec::with_capacity(canonical.len());
    for (ordinal, (provider, reviewed)) in canonical
        .iter()
        .zip(expectation.providers.iter())
        .enumerate()
    {
        let mut edge_provider_ordinals = Vec::with_capacity(provider.needed.len());
        for needed in &provider.needed {
            let resolved = canonical
                .iter()
                .position(|candidate| candidate.soname == *needed)
                .ok_or_else(|| {
                    X64TailWorkerDependencyClosureError::MissingProvider(needed.clone())
                })?;
            edge_provider_ordinals.push(u16::try_from(resolved).map_err(|_| {
                X64TailWorkerDependencyClosureError::Overflow("edge provider ordinal")
            })?);
        }
        let mut evidence = X64TailWorkerDependencyClosureProviderEvidence {
            ordinal: u16::try_from(ordinal)
                .map_err(|_| X64TailWorkerDependencyClosureError::Overflow("provider ordinal"))?,
            expectation_hash: reviewed.expectation_hash,
            first_object_ordinal: provider.first_object_ordinal,
            source_object_ordinals: provider.source_object_ordinals.clone(),
            first_dynamic_evidence_hash: provider.first_dynamic_evidence_hash,
            soname: provider.soname.clone(),
            object_hash: provider.object_hash,
            needed: provider.needed.clone(),
            edge_provider_ordinals,
            dynamic_flags: provider.dynamic_flags,
            dynamic_flags_1: provider.dynamic_flags_1,
            evidence_hash: SemanticHash::ZERO,
        };
        evidence.evidence_hash = closure_provider_evidence_hash(&evidence);
        providers.push(evidence);
    }
    let mut evidence = X64TailWorkerDependencyClosureEvidence {
        schema_version: X64_TAIL_WORKER_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_VERSION,
        policy_hash: x64_tail_worker_dependency_closure_policy_hash(),
        dynamic_policy_hash: X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT,
        dynamic_evidence_hash: dynamic_evidence.evidence_hash(),
        object_set_evidence_hash: object_set.evidence().evidence_hash(),
        expectation_hash: expectation.expectation_hash,
        provider_count: u16::try_from(providers.len())
            .map_err(|_| X64TailWorkerDependencyClosureError::Overflow("provider count"))?,
        appearance_count,
        edge_count,
        providers,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_dependency_closure_evidence_hash(&evidence);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_dependency_closure<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    expectation: &X64TailWorkerDependencyClosureExpectation,
    evidence: &'evidence X64TailWorkerDependencyClosureEvidence,
) -> Result<VerifiedX64TailWorkerDependencyClosure<'evidence>, X64TailWorkerDependencyClosureError>
{
    preflight_closure_evidence(object_set, dynamic_evidence, expectation, evidence)?;
    let expected = admit_x64_tail_worker_dependency_closure(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        expectation,
    )?;
    if &expected != evidence
        || x64_tail_worker_dependency_closure_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyClosureError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerDependencyClosure { evidence })
}

fn derive_canonical_providers(
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
) -> Result<Vec<CanonicalProvider>, X64TailWorkerDependencyClosureError> {
    if object_set.object_count() != dynamic_evidence.objects().len() {
        return Err(X64TailWorkerDependencyClosureError::EvidenceMismatch);
    }
    let mut providers: Vec<CanonicalProvider> = Vec::new();
    for (ordinal, (dynamic, object)) in dynamic_evidence
        .objects()
        .iter()
        .zip(object_set.evidence().objects())
        .enumerate()
    {
        let ordinal = u16::try_from(ordinal)
            .map_err(|_| X64TailWorkerDependencyClosureError::Overflow("object ordinal"))?;
        let needed = dynamic
            .needed()
            .iter()
            .map(|name| name.name().to_owned())
            .collect::<Vec<_>>();
        if let Some(existing) = providers
            .iter_mut()
            .find(|provider| provider.soname == dynamic.soname())
        {
            if existing.object_hash != object.object_hash()
                || existing.needed != needed
                || existing.dynamic_flags != dynamic.dynamic_flags()
                || existing.dynamic_flags_1 != dynamic.dynamic_flags_1()
            {
                return Err(X64TailWorkerDependencyClosureError::ConflictingProvider(
                    dynamic.soname().to_owned(),
                ));
            }
            existing.source_object_ordinals.push(ordinal);
        } else {
            providers.push(CanonicalProvider {
                first_object_ordinal: ordinal,
                source_object_ordinals: vec![ordinal],
                first_dynamic_evidence_hash: dynamic.evidence_hash(),
                soname: dynamic.soname().to_owned(),
                object_hash: object.object_hash(),
                needed,
                dynamic_flags: dynamic.dynamic_flags(),
                dynamic_flags_1: dynamic.dynamic_flags_1(),
            });
        }
    }
    Ok(providers)
}

fn compare_reviewed_graph(
    expectation: &X64TailWorkerDependencyClosureExpectation,
    canonical: &[CanonicalProvider],
) -> Result<(), X64TailWorkerDependencyClosureError> {
    if expectation.providers.len() != canonical.len() {
        return Err(X64TailWorkerDependencyClosureError::ExpectationMismatch);
    }
    for (reviewed, actual) in expectation.providers.iter().zip(canonical) {
        if reviewed.soname != actual.soname
            || reviewed.object_hash != actual.object_hash
            || reviewed.needed != actual.needed
        {
            return Err(X64TailWorkerDependencyClosureError::ExpectationMismatch);
        }
    }
    for provider in canonical {
        for needed in &provider.needed {
            let provider_count = canonical
                .iter()
                .filter(|candidate| candidate.soname == *needed)
                .count();
            if provider_count == 0 {
                return Err(X64TailWorkerDependencyClosureError::MissingProvider(
                    needed.clone(),
                ));
            }
            if provider_count != 1 {
                return Err(X64TailWorkerDependencyClosureError::ConflictingProvider(
                    needed.clone(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_provider_expectation_shape(
    expectation: &X64TailWorkerDependencyClosureProviderExpectation,
) -> Result<(), X64TailWorkerDependencyClosureError> {
    if expectation.schema_version != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_SCHEMA_VERSION {
        return Err(X64TailWorkerDependencyClosureError::InvalidExpectation(
            "provider schema",
        ));
    }
    validate_name(&expectation.soname, "provider SONAME")?;
    if expectation.needed.len() > usize::from(X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_EDGES) {
        return Err(X64TailWorkerDependencyClosureError::Limit {
            field: "provider edges",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_EDGES),
            actual: u64::try_from(expectation.needed.len()).unwrap_or(u64::MAX),
        });
    }
    for (ordinal, needed) in expectation.needed.iter().enumerate() {
        validate_name(needed, "needed SONAME")?;
        if expectation.needed[..ordinal].contains(needed) {
            return Err(X64TailWorkerDependencyClosureError::InvalidExpectation(
                "duplicate provider edge",
            ));
        }
    }
    Ok(())
}

fn validate_closure_expectation_shape(
    expectation: &X64TailWorkerDependencyClosureExpectation,
) -> Result<(), X64TailWorkerDependencyClosureError> {
    if expectation.schema_version != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_SCHEMA_VERSION {
        return Err(X64TailWorkerDependencyClosureError::InvalidExpectation(
            "closure schema",
        ));
    }
    if expectation.providers.is_empty()
        || expectation.providers.len()
            > usize::from(X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_PROVIDERS)
    {
        return Err(X64TailWorkerDependencyClosureError::Limit {
            field: "providers",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_PROVIDERS),
            actual: u64::try_from(expectation.providers.len()).unwrap_or(u64::MAX),
        });
    }
    let mut total_edges = 0usize;
    for (ordinal, provider) in expectation.providers.iter().enumerate() {
        validate_provider_expectation_shape(provider)?;
        if expectation.providers[..ordinal]
            .iter()
            .any(|existing| existing.soname == provider.soname)
        {
            return Err(X64TailWorkerDependencyClosureError::InvalidExpectation(
                "duplicate provider SONAME",
            ));
        }
        total_edges = total_edges.checked_add(provider.needed.len()).ok_or(
            X64TailWorkerDependencyClosureError::Overflow("expectation edges"),
        )?;
    }
    if total_edges > usize::from(X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_EDGES) {
        return Err(X64TailWorkerDependencyClosureError::Limit {
            field: "expectation edges",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_EDGES),
            actual: u64::try_from(total_edges).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

fn validate_closure_expectation(
    expectation: &X64TailWorkerDependencyClosureExpectation,
) -> Result<(), X64TailWorkerDependencyClosureError> {
    validate_closure_expectation_shape(expectation)?;
    if expectation
        .providers
        .iter()
        .any(|provider| closure_provider_expectation_hash(provider) != provider.expectation_hash)
        || x64_tail_worker_dependency_closure_expectation_hash(expectation)
            != expectation.expectation_hash
    {
        return Err(X64TailWorkerDependencyClosureError::InvalidExpectation(
            "expectation hash",
        ));
    }
    Ok(())
}

fn validate_name(
    name: &str,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyClosureError> {
    if name.is_empty()
        || name.len() > usize::from(X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_NAME_BYTES)
        || name
            .as_bytes()
            .iter()
            .any(|byte| !(0x21..=0x7e).contains(byte) || *byte == b'/' || *byte == b'\\')
    {
        return Err(X64TailWorkerDependencyClosureError::InvalidExpectation(
            field,
        ));
    }
    Ok(())
}

fn enforce_aggregate_limits(
    provider_count: usize,
    appearance_count: u16,
    edge_count: u16,
) -> Result<(), X64TailWorkerDependencyClosureError> {
    for (field, limit, actual) in [
        (
            "providers",
            X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_PROVIDERS,
            u16::try_from(provider_count).unwrap_or(u16::MAX),
        ),
        (
            "appearances",
            X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_APPEARANCES,
            appearance_count,
        ),
        (
            "edges",
            X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_EDGES,
            edge_count,
        ),
    ] {
        if actual > limit {
            return Err(X64TailWorkerDependencyClosureError::Limit {
                field,
                limit: u64::from(limit),
                actual: u64::from(actual),
            });
        }
    }
    Ok(())
}

fn preflight_closure_evidence(
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    expectation: &X64TailWorkerDependencyClosureExpectation,
    evidence: &X64TailWorkerDependencyClosureEvidence,
) -> Result<(), X64TailWorkerDependencyClosureError> {
    validate_closure_expectation(expectation)?;
    if evidence.schema_version != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT
        || evidence.policy_hash != x64_tail_worker_dependency_closure_policy_hash()
        || evidence.dynamic_policy_hash != X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT
        || evidence.dynamic_evidence_hash != dynamic_evidence.evidence_hash()
        || evidence.object_set_evidence_hash != object_set.evidence().evidence_hash()
        || evidence.expectation_hash != expectation.expectation_hash
        || usize::from(evidence.provider_count) != evidence.providers.len()
        || x64_tail_worker_dependency_closure_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyClosureError::EvidenceMismatch);
    }
    enforce_aggregate_limits(
        evidence.providers.len(),
        evidence.appearance_count,
        evidence.edge_count,
    )?;
    let mut appearances = 0u16;
    let mut edges = 0u16;
    for (ordinal, (provider, reviewed)) in evidence
        .providers
        .iter()
        .zip(expectation.providers.iter())
        .enumerate()
    {
        appearances = appearances
            .checked_add(
                u16::try_from(provider.source_object_ordinals.len()).map_err(|_| {
                    X64TailWorkerDependencyClosureError::Overflow("evidence appearances")
                })?,
            )
            .ok_or(X64TailWorkerDependencyClosureError::Overflow(
                "evidence appearances",
            ))?;
        edges = edges
            .checked_add(
                u16::try_from(provider.needed.len())
                    .map_err(|_| X64TailWorkerDependencyClosureError::Overflow("evidence edges"))?,
            )
            .ok_or(X64TailWorkerDependencyClosureError::Overflow(
                "evidence edges",
            ))?;
        if provider.ordinal != u16::try_from(ordinal).unwrap_or(u16::MAX)
            || provider.expectation_hash != reviewed.expectation_hash
            || provider.soname != reviewed.soname
            || provider.object_hash != reviewed.object_hash
            || provider.needed != reviewed.needed
            || provider.source_object_ordinals.first().copied()
                != Some(provider.first_object_ordinal)
            || provider
                .source_object_ordinals
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || provider.edge_provider_ordinals.len() != provider.needed.len()
            || provider
                .edge_provider_ordinals
                .iter()
                .any(|edge| usize::from(*edge) >= evidence.providers.len())
            || closure_provider_evidence_hash(provider) != provider.evidence_hash
        {
            return Err(X64TailWorkerDependencyClosureError::EvidenceMismatch);
        }
    }
    if appearances != evidence.appearance_count || edges != evidence.edge_count {
        return Err(X64TailWorkerDependencyClosureError::EvidenceMismatch);
    }
    Ok(())
}

pub fn x64_tail_worker_dependency_closure_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
    );
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_VERSION,
    );
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT);
    put_u16(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_PROVIDERS);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_APPEARANCES,
    );
    put_u16(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_EDGES);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_CLOSURE_MAX_NAME_BYTES,
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

fn closure_provider_expectation_hash(
    expectation: &X64TailWorkerDependencyClosureProviderExpectation,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(320);
    bytes.extend_from_slice(PROVIDER_EXPECTATION_DOMAIN);
    put_version(&mut bytes, expectation.schema_version);
    put_hash(&mut bytes, x64_tail_worker_dependency_closure_policy_hash());
    put_string(&mut bytes, &expectation.soname);
    put_hash(&mut bytes, expectation.object_hash);
    put_strings(&mut bytes, &expectation.needed);
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_dependency_closure_expectation_hash(
    expectation: &X64TailWorkerDependencyClosureExpectation,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(EXPECTATION_DOMAIN);
    put_version(&mut bytes, expectation.schema_version);
    put_hash(&mut bytes, x64_tail_worker_dependency_closure_policy_hash());
    put_u16(
        &mut bytes,
        u16::try_from(expectation.providers.len()).unwrap_or(u16::MAX),
    );
    for provider in &expectation.providers {
        put_hash(&mut bytes, provider.expectation_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn closure_provider_evidence_hash(
    evidence: &X64TailWorkerDependencyClosureProviderEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(PROVIDER_EVIDENCE_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_hash(&mut bytes, evidence.expectation_hash);
    put_u16(&mut bytes, evidence.first_object_ordinal);
    put_u16(
        &mut bytes,
        u16::try_from(evidence.source_object_ordinals.len()).unwrap_or(u16::MAX),
    );
    for ordinal in &evidence.source_object_ordinals {
        put_u16(&mut bytes, *ordinal);
    }
    put_hash(&mut bytes, evidence.first_dynamic_evidence_hash);
    put_string(&mut bytes, &evidence.soname);
    put_hash(&mut bytes, evidence.object_hash);
    put_strings(&mut bytes, &evidence.needed);
    put_u16(
        &mut bytes,
        u16::try_from(evidence.edge_provider_ordinals.len()).unwrap_or(u16::MAX),
    );
    for ordinal in &evidence.edge_provider_ordinals {
        put_u16(&mut bytes, *ordinal);
    }
    put_u64(&mut bytes, evidence.dynamic_flags);
    put_u64(&mut bytes, evidence.dynamic_flags_1);
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_dependency_closure_evidence_hash(
    evidence: &X64TailWorkerDependencyClosureEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.dynamic_policy_hash);
    put_hash(&mut bytes, evidence.dynamic_evidence_hash);
    put_hash(&mut bytes, evidence.object_set_evidence_hash);
    put_hash(&mut bytes, evidence.expectation_hash);
    put_u16(&mut bytes, evidence.provider_count);
    put_u16(&mut bytes, evidence.appearance_count);
    put_u16(&mut bytes, evidence.edge_count);
    for provider in &evidence.providers {
        put_hash(&mut bytes, provider.evidence_hash);
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

fn put_strings(bytes: &mut Vec<u8>, values: &[String]) {
    put_u16(bytes, u16::try_from(values.len()).unwrap_or(u16::MAX));
    for value in values {
        put_string(bytes, value);
    }
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u16(bytes, u16::try_from(value.len()).unwrap_or(u16::MAX));
    bytes.extend_from_slice(value.as_bytes());
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(debug_assertions)]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn probe_x64_tail_worker_dependency_closure_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    expectation: &X64TailWorkerDependencyClosureExpectation,
    evidence: &X64TailWorkerDependencyClosureEvidence,
) -> bool {
    let mut missing = expectation.clone();
    missing.providers.pop();
    missing.expectation_hash = x64_tail_worker_dependency_closure_expectation_hash(&missing);

    let mut extra = expectation.clone();
    let Ok(extra_provider) = X64TailWorkerDependencyClosureProviderExpectation::new(
        "not-reviewed.so".to_owned(),
        SemanticHash([0x44; 32]),
        Vec::new(),
    ) else {
        return false;
    };
    extra.providers.push(extra_provider);
    extra.expectation_hash = x64_tail_worker_dependency_closure_expectation_hash(&extra);

    let mut reordered = expectation.clone();
    if reordered.providers.len() < 2 {
        return false;
    }
    reordered.providers.swap(0, 1);
    reordered.expectation_hash = x64_tail_worker_dependency_closure_expectation_hash(&reordered);

    let mut wrong_digest = expectation.clone();
    wrong_digest.providers[0].object_hash.0[0] ^= 1;
    wrong_digest.providers[0].expectation_hash =
        closure_provider_expectation_hash(&wrong_digest.providers[0]);
    wrong_digest.expectation_hash =
        x64_tail_worker_dependency_closure_expectation_hash(&wrong_digest);

    let mut wrong_edge = expectation.clone();
    let Some(edge_provider) = wrong_edge
        .providers
        .iter_mut()
        .find(|provider| !provider.needed.is_empty())
    else {
        return false;
    };
    edge_provider.needed[0] = "missing-provider.so".to_owned();
    edge_provider.expectation_hash = closure_provider_expectation_hash(edge_provider);
    wrong_edge.expectation_hash = x64_tail_worker_dependency_closure_expectation_hash(&wrong_edge);

    let expectations_rejected = [missing, extra, reordered, wrong_digest, wrong_edge]
        .iter()
        .all(|mutation| {
            admit_x64_tail_worker_dependency_closure(
                artifact,
                inventory,
                declaration_expectation,
                declaration_evidence,
                manifest,
                object_set,
                dynamic_evidence,
                mutation,
            )
            .is_err()
        });

    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_dynamic = evidence.clone();
    stale_dynamic.dynamic_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.edge_count = stale_count.edge_count.saturating_add(1);
    let mut stale_provider = evidence.clone();
    stale_provider.providers[0].soname.push('x');
    let mut resealed = evidence.clone();
    resealed.providers[0].soname.push('x');
    resealed.providers[0].evidence_hash = closure_provider_evidence_hash(&resealed.providers[0]);
    resealed.evidence_hash = x64_tail_worker_dependency_closure_evidence_hash(&resealed);

    let evidence_rejected = [
        stale_policy,
        stale_dynamic,
        stale_count,
        stale_provider,
        resealed,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_dependency_closure(
            artifact,
            inventory,
            declaration_expectation,
            declaration_evidence,
            manifest,
            object_set,
            dynamic_evidence,
            expectation,
            mutation,
        )
        .is_err()
    });

    let duplicate_review = X64TailWorkerDependencyClosureExpectation::new(vec![
        expectation.providers[0].clone(),
        expectation.providers[0].clone(),
    ])
    .is_err();
    expectations_rejected && evidence_rejected && duplicate_review
}
