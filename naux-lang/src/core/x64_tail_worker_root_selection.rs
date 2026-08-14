//! ADR-0084 proof-only exact strong versioned root-symbol candidate selection.
//!
//! This boundary replays only already sealed symbol and hash-table evidence.
//! It returns selected/refused identities, never addresses, relocations,
//! mappings, or executable authority.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
};
use super::x64_tail_worker_dependency_closure::{
    X64TailWorkerDependencyClosureEvidence, X64TailWorkerDependencyClosureExpectation,
};
use super::x64_tail_worker_dependency_compatibility::X64TailWorkerDependencyCompatibilityEvidence;
use super::x64_tail_worker_dependency_definitions::X64TailWorkerDependencyDefinitionEvidence;
use super::x64_tail_worker_dependency_dynamic::X64TailWorkerDependencyDynamicEvidence;
use super::x64_tail_worker_dependency_objects::{
    X64TailWorkerDependencyObjectManifest, X64TailWorkerDependencyObjectSet,
};
use super::x64_tail_worker_dependency_symbols::{
    X64TailWorkerDependencySymbolEvidence, X64TailWorkerDependencySymbolNamespaceKind,
    X64TailWorkerDependencySymbolObjectEvidence, X64_TAIL_WORKER_DEPENDENCY_SYMBOL_MAX_SYMBOLS,
    X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_versions::X64TailWorkerDependencyVersionEvidence;
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use super::x64_tail_worker_root_compatibility::{
    X64TailWorkerRootCompatibilityBindingEvidence, X64TailWorkerRootCompatibilityEvidence,
    X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT,
};
use super::x64_tail_worker_root_scope::{
    verify_x64_tail_worker_root_scope, X64TailWorkerRootScopeError, X64TailWorkerRootScopeEvidence,
    X64TailWorkerRootScopeExpectation, X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT,
};
use super::x64_tail_worker_root_symbols::{
    X64TailWorkerRootSymbolEvidence, X64TailWorkerRootSymbolNamespaceKind,
    X64TailWorkerRootSymbolRecordEvidence, X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT,
};
use super::x64_tail_worker_root_versions::X64TailWorkerRootVersionEvidence;
use std::fmt;

pub const X64_TAIL_WORKER_ROOT_SELECTION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_SELECTION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_SELECTION_MAX_REQUESTS: u16 = 108;
pub const X64_TAIL_WORKER_ROOT_SELECTION_MAX_SCOPE_PROBES: u16 = 65;
pub const X64_TAIL_WORKER_ROOT_SELECTION_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_ROOT_SYMBOLS: u16 = 108;
pub const X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_REQUESTS: u16 = 96;
pub const X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_SELECTED: u16 = 90;
pub const X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_IFUNC_REFUSALS: u16 = 6;
pub const X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT: SemanticHash = SemanticHash([
    38, 20, 149, 219, 71, 203, 93, 76, 86, 142, 184, 134, 51, 233, 182, 7, 57, 248, 97, 19, 194,
    12, 14, 30, 34, 79, 74, 240, 7, 1, 124, 33,
]);
pub const X64_TAIL_WORKER_ROOT_SELECTION_TOPOLOGY_ROOT: SemanticHash = SemanticHash([
    30, 157, 65, 216, 73, 123, 184, 163, 14, 130, 233, 44, 228, 36, 238, 2, 179, 250, 17, 127, 230,
    54, 53, 64, 93, 138, 49, 54, 212, 88, 99, 30,
]);

const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STV_DEFAULT: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-selection-policy:v1\0";
const PROBE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-selection-probe:v1\0";
const DECISION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-selection-decision:v1\0";
const TOPOLOGY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-selection-topology:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-selection-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "full-adr0083-reviewed-scope-replay-v1",
    "complete-strong-versioned-request-coverage-v1",
    "independent-system-v-hash-probe-replay-v1",
    "independent-gnu-bloom-bucket-chain-probe-replay-v1",
    "dual-hash-name-candidate-agreement-v1",
    "exact-adr0081-definition-namespace-binding-v1",
    "explicit-global-or-weak-provider-definition-binding-v1",
    "exact-func-object-compatibility-v1",
    "explicit-gnu-ifunc-refusal-v1",
    "ordered-earlier-provider-probe-preservation-v1",
    "proof-only-no-address-relocation-mapping-or-execution-v1",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X64TailWorkerRootSelectionDecisionKind {
    Selected = 0,
    RefusedIfunc = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootSelectionProbeEvidence {
    ordinal: u16,
    scope_ordinal: u16,
    provider_ordinal: u16,
    provider_symbol_object_evidence_hash: SemanticHash,
    sysv_bucket_ordinal: Option<u16>,
    sysv_chain_ordinals: Vec<u16>,
    sysv_name_matches: Vec<u16>,
    gnu_bloom_word_ordinal: Option<u16>,
    gnu_bloom_mask: u64,
    gnu_bloom_passed: bool,
    gnu_bucket_ordinal: Option<u16>,
    gnu_chain_ordinals: Vec<u16>,
    gnu_name_matches: Vec<u16>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootSelectionProbeEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn scope_ordinal(&self) -> u16 {
        self.scope_ordinal
    }

    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub const fn provider_symbol_object_evidence_hash(&self) -> SemanticHash {
        self.provider_symbol_object_evidence_hash
    }

    pub const fn sysv_bucket_ordinal(&self) -> Option<u16> {
        self.sysv_bucket_ordinal
    }

    pub fn sysv_chain_ordinals(&self) -> &[u16] {
        &self.sysv_chain_ordinals
    }

    pub fn sysv_name_matches(&self) -> &[u16] {
        &self.sysv_name_matches
    }

    pub const fn gnu_bloom_word_ordinal(&self) -> Option<u16> {
        self.gnu_bloom_word_ordinal
    }

    pub const fn gnu_bloom_mask(&self) -> u64 {
        self.gnu_bloom_mask
    }

    pub const fn gnu_bloom_passed(&self) -> bool {
        self.gnu_bloom_passed
    }

    pub const fn gnu_bucket_ordinal(&self) -> Option<u16> {
        self.gnu_bucket_ordinal
    }

    pub fn gnu_chain_ordinals(&self) -> &[u16] {
        &self.gnu_chain_ordinals
    }

    pub fn gnu_name_matches(&self) -> &[u16] {
        &self.gnu_name_matches
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootSelectionDecisionEvidence {
    ordinal: u16,
    requester_symbol_ordinal: u16,
    requester_symbol_evidence_hash: SemanticHash,
    name: String,
    sysv_name_hash: u32,
    gnu_name_hash: u32,
    requester_binding: u8,
    requester_symbol_type: u8,
    requester_visibility: u8,
    requester_version_index: u16,
    requester_version_hidden: bool,
    requester_namespace_evidence_hash: SemanticHash,
    compatibility_binding_evidence_hash: SemanticHash,
    requirement_name: String,
    definition_evidence_hash: SemanticHash,
    decision_kind: X64TailWorkerRootSelectionDecisionKind,
    selected_scope_ordinal: u16,
    selected_provider_ordinal: u16,
    selected_symbol_ordinal: u16,
    selected_symbol_evidence_hash: SemanticHash,
    selected_binding: u8,
    selected_symbol_type: u8,
    selected_visibility: u8,
    selected_version_index: u16,
    selected_version_hidden: bool,
    probes: Vec<X64TailWorkerRootSelectionProbeEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootSelectionDecisionEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn requester_symbol_ordinal(&self) -> u16 {
        self.requester_symbol_ordinal
    }

    pub const fn requester_symbol_evidence_hash(&self) -> SemanticHash {
        self.requester_symbol_evidence_hash
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn decision_kind(&self) -> X64TailWorkerRootSelectionDecisionKind {
        self.decision_kind
    }

    pub const fn selected_scope_ordinal(&self) -> u16 {
        self.selected_scope_ordinal
    }

    pub const fn selected_provider_ordinal(&self) -> u16 {
        self.selected_provider_ordinal
    }

    pub const fn selected_symbol_ordinal(&self) -> u16 {
        self.selected_symbol_ordinal
    }

    pub const fn selected_binding(&self) -> u8 {
        self.selected_binding
    }

    pub const fn selected_symbol_type(&self) -> u8 {
        self.selected_symbol_type
    }

    pub fn probes(&self) -> &[X64TailWorkerRootSelectionProbeEvidence] {
        &self.probes
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootSelectionEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    dependency_symbol_policy_hash: SemanticHash,
    dependency_symbol_evidence_hash: SemanticHash,
    root_compatibility_policy_hash: SemanticHash,
    root_compatibility_evidence_hash: SemanticHash,
    root_symbol_policy_hash: SemanticHash,
    root_symbol_evidence_hash: SemanticHash,
    root_scope_policy_hash: SemanticHash,
    root_scope_evidence_hash: SemanticHash,
    root_scope_expectation_hash: SemanticHash,
    root_symbol_count: u16,
    request_count: u16,
    selected_count: u16,
    ifunc_refusal_count: u16,
    decisions: Vec<X64TailWorkerRootSelectionDecisionEvidence>,
    topology_hash: SemanticHash,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootSelectionEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn root_symbol_evidence_hash(&self) -> SemanticHash {
        self.root_symbol_evidence_hash
    }

    pub const fn root_symbol_count(&self) -> u16 {
        self.root_symbol_count
    }

    pub const fn request_count(&self) -> u16 {
        self.request_count
    }

    pub const fn selected_count(&self) -> u16 {
        self.selected_count
    }

    pub const fn ifunc_refusal_count(&self) -> u16 {
        self.ifunc_refusal_count
    }

    pub fn decisions(&self) -> &[X64TailWorkerRootSelectionDecisionEvidence] {
        &self.decisions
    }

    pub const fn topology_hash(&self) -> SemanticHash {
        self.topology_hash
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerRootSelection<'evidence> {
    evidence: &'evidence X64TailWorkerRootSelectionEvidence,
}

impl<'evidence> VerifiedX64TailWorkerRootSelection<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerRootSelectionEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerRootSelectionError {
    Scope(X64TailWorkerRootScopeError),
    Invalid(&'static str),
    Unsupported {
        requester_ordinal: u16,
        reason: &'static str,
    },
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerRootSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scope(error) => write!(formatter, "root scope: {error}"),
            Self::Invalid(field) => write!(formatter, "invalid root selection {field}"),
            Self::Unsupported {
                requester_ordinal,
                reason,
            } => write!(
                formatter,
                "unsupported root requester {requester_ordinal}: {reason}"
            ),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "root selection {field} limit {limit} exceeded by {actual}"
            ),
            Self::Overflow(field) => write!(formatter, "root selection {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("root selection evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerRootSelectionError {}

impl From<X64TailWorkerRootScopeError> for X64TailWorkerRootSelectionError {
    fn from(value: X64TailWorkerRootScopeError) -> Self {
        Self::Scope(value)
    }
}

struct HashLookupResult {
    sysv_bucket_ordinal: Option<u16>,
    sysv_chain_ordinals: Vec<u16>,
    sysv_name_matches: Vec<u16>,
    gnu_bloom_word_ordinal: Option<u16>,
    gnu_bloom_mask: u64,
    gnu_bloom_passed: bool,
    gnu_bucket_ordinal: Option<u16>,
    gnu_chain_ordinals: Vec<u16>,
    gnu_name_matches: Vec<u16>,
    canonical_name_matches: Vec<u16>,
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_worker_root_selection_evidence(
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
    scope_expectation: &X64TailWorkerRootScopeExpectation,
    scope_evidence: &X64TailWorkerRootScopeEvidence,
) -> Result<X64TailWorkerRootSelectionEvidence, X64TailWorkerRootSelectionError> {
    if x64_tail_worker_root_selection_policy_hash() != X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT {
        return Err(X64TailWorkerRootSelectionError::Invalid("policy root"));
    }
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
        scope_expectation,
        scope_evidence,
    )?;
    if root_symbol_evidence.symbol_count() != X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_ROOT_SYMBOLS {
        return Err(X64TailWorkerRootSelectionError::Invalid(
            "frozen root symbol count",
        ));
    }

    let mut decisions =
        Vec::with_capacity(usize::from(X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_REQUESTS));
    let mut selected_count = 0u16;
    let mut ifunc_refusal_count = 0u16;
    for requester in root_symbol_evidence.object().symbols() {
        if !is_strong_versioned_requester(requester) {
            continue;
        }
        let compatibility = unique_compatibility_binding(root_compatibility_evidence, requester)?;
        let mut probes = Vec::new();
        let mut selected = None;
        for (scope_index, scope_entry) in scope_evidence.entries().iter().enumerate() {
            let provider_index = usize::from(scope_entry.provider_ordinal());
            let provider = dependency_symbol_evidence
                .objects()
                .get(provider_index)
                .ok_or(X64TailWorkerRootSelectionError::Invalid(
                    "scope provider ordinal",
                ))?;
            if provider.provider_ordinal() != scope_entry.provider_ordinal()
                || provider.evidence_hash() != scope_entry.provider_symbol_object_evidence_hash()
            {
                return Err(X64TailWorkerRootSelectionError::Invalid(
                    "scope provider identity",
                ));
            }
            let lookup = replay_provider_hash_lookup(provider, requester)?;
            let probe_ordinal = u16::try_from(probes.len())
                .map_err(|_| X64TailWorkerRootSelectionError::Overflow("probe ordinal"))?;
            let scope_ordinal = u16::try_from(scope_index)
                .map_err(|_| X64TailWorkerRootSelectionError::Overflow("scope ordinal"))?;
            let mut probe = X64TailWorkerRootSelectionProbeEvidence {
                ordinal: probe_ordinal,
                scope_ordinal,
                provider_ordinal: provider.provider_ordinal(),
                provider_symbol_object_evidence_hash: provider.evidence_hash(),
                sysv_bucket_ordinal: lookup.sysv_bucket_ordinal,
                sysv_chain_ordinals: lookup.sysv_chain_ordinals,
                sysv_name_matches: lookup.sysv_name_matches,
                gnu_bloom_word_ordinal: lookup.gnu_bloom_word_ordinal,
                gnu_bloom_mask: lookup.gnu_bloom_mask,
                gnu_bloom_passed: lookup.gnu_bloom_passed,
                gnu_bucket_ordinal: lookup.gnu_bucket_ordinal,
                gnu_chain_ordinals: lookup.gnu_chain_ordinals,
                gnu_name_matches: lookup.gnu_name_matches,
                evidence_hash: SemanticHash::ZERO,
            };
            probe.evidence_hash = root_selection_probe_evidence_hash(&probe);
            probes.push(probe);

            if provider.provider_ordinal() == compatibility.provider_ordinal() {
                selected = Some(select_exact_candidate(
                    provider,
                    requester,
                    compatibility,
                    &lookup.canonical_name_matches,
                    scope_ordinal,
                )?);
                break;
            }
        }
        let selected = selected.ok_or(X64TailWorkerRootSelectionError::Unsupported {
            requester_ordinal: requester.ordinal(),
            reason: "compatible provider absent from scope",
        })?;
        match selected.0 {
            X64TailWorkerRootSelectionDecisionKind::Selected => {
                selected_count = selected_count
                    .checked_add(1)
                    .ok_or(X64TailWorkerRootSelectionError::Overflow("selected count"))?;
            }
            X64TailWorkerRootSelectionDecisionKind::RefusedIfunc => {
                ifunc_refusal_count = ifunc_refusal_count.checked_add(1).ok_or(
                    X64TailWorkerRootSelectionError::Overflow("IFUNC refusal count"),
                )?;
            }
        }
        let candidate = selected.1;
        let mut decision = X64TailWorkerRootSelectionDecisionEvidence {
            ordinal: u16::try_from(decisions.len())
                .map_err(|_| X64TailWorkerRootSelectionError::Overflow("decision ordinal"))?,
            requester_symbol_ordinal: requester.ordinal(),
            requester_symbol_evidence_hash: requester.evidence_hash(),
            name: requester.name().to_owned(),
            sysv_name_hash: requester.sysv_name_hash(),
            gnu_name_hash: requester.gnu_name_hash(),
            requester_binding: requester.binding(),
            requester_symbol_type: requester.symbol_type(),
            requester_visibility: requester.visibility(),
            requester_version_index: requester.version_index(),
            requester_version_hidden: requester.version_hidden(),
            requester_namespace_evidence_hash: requester.namespace_evidence_hash(),
            compatibility_binding_evidence_hash: compatibility.evidence_hash(),
            requirement_name: compatibility.requirement_name().to_owned(),
            definition_evidence_hash: compatibility.definition_evidence_hash(),
            decision_kind: selected.0,
            selected_scope_ordinal: selected.2,
            selected_provider_ordinal: compatibility.provider_ordinal(),
            selected_symbol_ordinal: candidate.ordinal(),
            selected_symbol_evidence_hash: candidate.evidence_hash(),
            selected_binding: candidate.binding(),
            selected_symbol_type: candidate.symbol_type(),
            selected_visibility: candidate.visibility(),
            selected_version_index: candidate.version_index(),
            selected_version_hidden: candidate.version_hidden(),
            probes,
            evidence_hash: SemanticHash::ZERO,
        };
        decision.evidence_hash = root_selection_decision_evidence_hash(&decision);
        decisions.push(decision);
    }

    let request_count = u16::try_from(decisions.len())
        .map_err(|_| X64TailWorkerRootSelectionError::Overflow("request count"))?;
    if request_count != X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_REQUESTS
        || selected_count != X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_SELECTED
        || ifunc_refusal_count != X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_IFUNC_REFUSALS
    {
        return Err(X64TailWorkerRootSelectionError::Invalid(
            "frozen decision partition",
        ));
    }

    let topology_hash = root_selection_topology_hash(&decisions);
    let mut evidence = X64TailWorkerRootSelectionEvidence {
        schema_version: X64_TAIL_WORKER_ROOT_SELECTION_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ROOT_SELECTION_POLICY_VERSION,
        policy_hash: x64_tail_worker_root_selection_policy_hash(),
        dependency_symbol_policy_hash: X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT,
        dependency_symbol_evidence_hash: dependency_symbol_evidence.evidence_hash(),
        root_compatibility_policy_hash: X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT,
        root_compatibility_evidence_hash: root_compatibility_evidence.evidence_hash(),
        root_symbol_policy_hash: X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT,
        root_symbol_evidence_hash: root_symbol_evidence.evidence_hash(),
        root_scope_policy_hash: X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT,
        root_scope_evidence_hash: scope_evidence.evidence_hash(),
        root_scope_expectation_hash: scope_evidence.expectation_hash(),
        root_symbol_count: root_symbol_evidence.symbol_count(),
        request_count,
        selected_count,
        ifunc_refusal_count,
        decisions,
        topology_hash,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_root_selection_evidence_hash(&evidence);
    Ok(evidence)
}

fn is_strong_versioned_requester(requester: &X64TailWorkerRootSymbolRecordEvidence) -> bool {
    !requester.is_defined()
        && requester.binding() == STB_GLOBAL
        && requester.visibility() == STV_DEFAULT
        && requester.namespace_kind() == X64TailWorkerRootSymbolNamespaceKind::Requirement
}

fn unique_compatibility_binding<'evidence>(
    compatibility: &'evidence X64TailWorkerRootCompatibilityEvidence,
    requester: &X64TailWorkerRootSymbolRecordEvidence,
) -> Result<&'evidence X64TailWorkerRootCompatibilityBindingEvidence, X64TailWorkerRootSelectionError>
{
    let mut matches = compatibility.bindings().iter().filter(|binding| {
        binding.evidence_hash() == requester.compatibility_binding_evidence_hash()
    });
    let binding = matches
        .next()
        .ok_or(X64TailWorkerRootSelectionError::Invalid(
            "requester compatibility binding",
        ))?;
    if matches.next().is_some()
        || requester.namespace_provider_ordinal() != binding.provider_ordinal()
        || requester.namespace_record_ordinal() != binding.root_requirement_ordinal()
        || requester.namespace_auxiliary_ordinal() != binding.root_auxiliary_ordinal()
        || requester.namespace_evidence_hash() != binding.root_auxiliary_evidence_hash()
        || requester.version_index() != binding.requirement_version_index()
    {
        return Err(X64TailWorkerRootSelectionError::Invalid(
            "requester compatibility join",
        ));
    }
    Ok(binding)
}

fn select_exact_candidate<'evidence>(
    provider: &'evidence X64TailWorkerDependencySymbolObjectEvidence,
    requester: &X64TailWorkerRootSymbolRecordEvidence,
    compatibility: &X64TailWorkerRootCompatibilityBindingEvidence,
    name_matches: &[u16],
    scope_ordinal: u16,
) -> Result<
    (
        X64TailWorkerRootSelectionDecisionKind,
        &'evidence super::x64_tail_worker_dependency_symbols::X64TailWorkerDependencySymbolRecordEvidence,
        u16,
    ),
    X64TailWorkerRootSelectionError,
>{
    let mut candidates = name_matches.iter().filter_map(|ordinal| {
        let candidate = provider.symbols().get(usize::from(*ordinal))?;
        (candidate.ordinal() == *ordinal
            && candidate.is_defined()
            && matches!(candidate.binding(), STB_GLOBAL | STB_WEAK)
            && candidate.visibility() == STV_DEFAULT
            && candidate.namespace_kind() == X64TailWorkerDependencySymbolNamespaceKind::Definition
            && candidate.namespace_provider_ordinal() == compatibility.provider_ordinal()
            && candidate.namespace_evidence_hash() == compatibility.definition_evidence_hash()
            && candidate.version_index() == compatibility.definition_version_index())
        .then_some(candidate)
    });
    let candidate = candidates
        .next()
        .ok_or(X64TailWorkerRootSelectionError::Unsupported {
            requester_ordinal: requester.ordinal(),
            reason: "no exact versioned candidate",
        })?;
    if candidates.next().is_some() {
        return Err(X64TailWorkerRootSelectionError::Unsupported {
            requester_ordinal: requester.ordinal(),
            reason: "ambiguous exact versioned candidate",
        });
    }
    let decision_kind = match (requester.symbol_type(), candidate.symbol_type()) {
        (STT_FUNC, STT_FUNC) | (STT_OBJECT, STT_OBJECT) => {
            X64TailWorkerRootSelectionDecisionKind::Selected
        }
        (STT_FUNC, STT_GNU_IFUNC) => X64TailWorkerRootSelectionDecisionKind::RefusedIfunc,
        _ => {
            return Err(X64TailWorkerRootSelectionError::Unsupported {
                requester_ordinal: requester.ordinal(),
                reason: "unsupported type compatibility",
            });
        }
    };
    Ok((decision_kind, candidate, scope_ordinal))
}

fn replay_provider_hash_lookup(
    provider: &X64TailWorkerDependencySymbolObjectEvidence,
    requester: &X64TailWorkerRootSymbolRecordEvidence,
) -> Result<HashLookupResult, X64TailWorkerRootSelectionError> {
    validate_name(requester.name())?;
    if elf_hash(requester.name().as_bytes()) != requester.sysv_name_hash()
        || gnu_hash(requester.name().as_bytes()) != requester.gnu_name_hash()
    {
        return Err(X64TailWorkerRootSelectionError::Invalid(
            "requester name hash",
        ));
    }
    let sysv_present = !provider.sysv_buckets().is_empty();
    if sysv_present == provider.sysv_chains().is_empty() {
        return Err(X64TailWorkerRootSelectionError::Invalid(
            "System V table presence",
        ));
    }
    let gnu_present = !provider.gnu_bloom().is_empty() || !provider.gnu_buckets().is_empty();
    if provider.gnu_bloom().is_empty() != provider.gnu_buckets().is_empty()
        || (!gnu_present && !provider.gnu_chains().is_empty())
        || (!sysv_present && !gnu_present)
    {
        return Err(X64TailWorkerRootSelectionError::Invalid(
            "GNU table presence",
        ));
    }

    let (sysv_bucket_ordinal, sysv_chain_ordinals, sysv_name_matches) = if sysv_present {
        replay_sysv_lookup(provider, requester)?
    } else {
        (None, Vec::new(), Vec::new())
    };
    let (
        gnu_bloom_word_ordinal,
        gnu_bloom_mask,
        gnu_bloom_passed,
        gnu_bucket_ordinal,
        gnu_chain_ordinals,
        gnu_name_matches,
    ) = if gnu_present {
        replay_gnu_lookup(provider, requester)?
    } else {
        (None, 0, false, None, Vec::new(), Vec::new())
    };
    if sysv_present && gnu_present && sysv_name_matches != gnu_name_matches {
        return Err(X64TailWorkerRootSelectionError::Invalid(
            "dual hash candidate agreement",
        ));
    }
    let canonical_name_matches = if gnu_present {
        gnu_name_matches.clone()
    } else {
        sysv_name_matches.clone()
    };
    Ok(HashLookupResult {
        sysv_bucket_ordinal,
        sysv_chain_ordinals,
        sysv_name_matches,
        gnu_bloom_word_ordinal,
        gnu_bloom_mask,
        gnu_bloom_passed,
        gnu_bucket_ordinal,
        gnu_chain_ordinals,
        gnu_name_matches,
        canonical_name_matches,
    })
}

#[allow(clippy::type_complexity)]
fn replay_sysv_lookup(
    provider: &X64TailWorkerDependencySymbolObjectEvidence,
    requester: &X64TailWorkerRootSymbolRecordEvidence,
) -> Result<(Option<u16>, Vec<u16>, Vec<u16>), X64TailWorkerRootSelectionError> {
    let bucket_index = usize::try_from(requester.sysv_name_hash()).unwrap_or(usize::MAX)
        % provider.sysv_buckets().len();
    let mut symbol_index = usize::try_from(provider.sysv_buckets()[bucket_index])
        .map_err(|_| X64TailWorkerRootSelectionError::Overflow("System V symbol ordinal"))?;
    let mut seen = vec![false; provider.symbols().len()];
    let mut chain = Vec::new();
    let mut matches = Vec::new();
    while symbol_index != 0 {
        if symbol_index >= provider.symbols().len()
            || symbol_index >= provider.sysv_chains().len()
            || seen[symbol_index]
            || chain.len() >= provider.symbols().len()
        {
            return Err(X64TailWorkerRootSelectionError::Invalid("System V chain"));
        }
        seen[symbol_index] = true;
        let ordinal = u16::try_from(symbol_index)
            .map_err(|_| X64TailWorkerRootSelectionError::Overflow("System V chain ordinal"))?;
        chain.push(ordinal);
        let symbol = &provider.symbols()[symbol_index];
        if symbol.sysv_name_hash() == requester.sysv_name_hash()
            && symbol.name() == requester.name()
        {
            validate_provider_symbol_name_hashes(symbol)?;
            matches.push(ordinal);
        }
        symbol_index = usize::try_from(provider.sysv_chains()[symbol_index])
            .map_err(|_| X64TailWorkerRootSelectionError::Overflow("System V next ordinal"))?;
    }
    Ok((
        Some(
            u16::try_from(bucket_index)
                .map_err(|_| X64TailWorkerRootSelectionError::Overflow("System V bucket"))?,
        ),
        chain,
        matches,
    ))
}

#[allow(clippy::type_complexity)]
fn replay_gnu_lookup(
    provider: &X64TailWorkerDependencySymbolObjectEvidence,
    requester: &X64TailWorkerRootSymbolRecordEvidence,
) -> Result<
    (Option<u16>, u64, bool, Option<u16>, Vec<u16>, Vec<u16>),
    X64TailWorkerRootSelectionError,
> {
    let hash = requester.gnu_name_hash();
    let word_index = usize::try_from(hash / 64).unwrap_or(usize::MAX) % provider.gnu_bloom().len();
    let first_bit = hash % 64;
    let second_bit = (hash >> provider.gnu_bloom_shift()) % 64;
    let mask = (1u64 << first_bit) | (1u64 << second_bit);
    let bloom_passed = provider.gnu_bloom()[word_index] & mask == mask;
    let word_ordinal = Some(
        u16::try_from(word_index)
            .map_err(|_| X64TailWorkerRootSelectionError::Overflow("GNU bloom ordinal"))?,
    );
    if !bloom_passed {
        return Ok((word_ordinal, mask, false, None, Vec::new(), Vec::new()));
    }

    let bucket_index = usize::try_from(hash).unwrap_or(usize::MAX) % provider.gnu_buckets().len();
    let bucket_ordinal = Some(
        u16::try_from(bucket_index)
            .map_err(|_| X64TailWorkerRootSelectionError::Overflow("GNU bucket ordinal"))?,
    );
    let symbol_offset = usize::try_from(provider.gnu_symbol_offset())
        .map_err(|_| X64TailWorkerRootSelectionError::Overflow("GNU symbol offset"))?;
    let mut symbol_index = usize::try_from(provider.gnu_buckets()[bucket_index])
        .map_err(|_| X64TailWorkerRootSelectionError::Overflow("GNU symbol ordinal"))?;
    if symbol_index < symbol_offset {
        return Ok((
            word_ordinal,
            mask,
            true,
            bucket_ordinal,
            Vec::new(),
            Vec::new(),
        ));
    }
    let mut chain = Vec::new();
    let mut matches = Vec::new();
    loop {
        let chain_index = symbol_index
            .checked_sub(symbol_offset)
            .ok_or(X64TailWorkerRootSelectionError::Invalid("GNU chain index"))?;
        let chain_hash = *provider
            .gnu_chains()
            .get(chain_index)
            .ok_or(X64TailWorkerRootSelectionError::Invalid("GNU chain"))?;
        let symbol = provider
            .symbols()
            .get(symbol_index)
            .ok_or(X64TailWorkerRootSelectionError::Invalid("GNU symbol"))?;
        if chain.len() >= provider.symbols().len() {
            return Err(X64TailWorkerRootSelectionError::Invalid("GNU chain budget"));
        }
        let ordinal = u16::try_from(symbol_index)
            .map_err(|_| X64TailWorkerRootSelectionError::Overflow("GNU chain ordinal"))?;
        chain.push(ordinal);
        if chain_hash | 1 == hash | 1 && symbol.name() == requester.name() {
            validate_provider_symbol_name_hashes(symbol)?;
            matches.push(ordinal);
        }
        if chain_hash & 1 != 0 {
            break;
        }
        symbol_index = symbol_index
            .checked_add(1)
            .ok_or(X64TailWorkerRootSelectionError::Overflow("GNU next symbol"))?;
    }
    Ok((word_ordinal, mask, true, bucket_ordinal, chain, matches))
}

fn validate_provider_symbol_name_hashes(
    symbol: &super::x64_tail_worker_dependency_symbols::X64TailWorkerDependencySymbolRecordEvidence,
) -> Result<(), X64TailWorkerRootSelectionError> {
    validate_name(symbol.name())?;
    if elf_hash(symbol.name().as_bytes()) != symbol.sysv_name_hash()
        || gnu_hash(symbol.name().as_bytes()) != symbol.gnu_name_hash()
    {
        return Err(X64TailWorkerRootSelectionError::Invalid(
            "provider symbol name hash",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_root_selection_evidence<'evidence>(
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
    scope_expectation: &X64TailWorkerRootScopeExpectation,
    scope_evidence: &X64TailWorkerRootScopeEvidence,
    evidence: &'evidence X64TailWorkerRootSelectionEvidence,
) -> Result<VerifiedX64TailWorkerRootSelection<'evidence>, X64TailWorkerRootSelectionError> {
    preflight_root_selection_evidence(
        dependency_symbol_evidence,
        root_compatibility_evidence,
        root_symbol_evidence,
        scope_evidence,
        evidence,
    )?;
    let expected = emit_x64_tail_worker_root_selection_evidence(
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
        scope_expectation,
        scope_evidence,
    )?;
    if &expected != evidence
        || x64_tail_worker_root_selection_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootSelectionError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerRootSelection { evidence })
}

fn preflight_root_selection_evidence(
    dependency_symbols: &X64TailWorkerDependencySymbolEvidence,
    root_compatibility: &X64TailWorkerRootCompatibilityEvidence,
    root_symbols: &X64TailWorkerRootSymbolEvidence,
    scope: &X64TailWorkerRootScopeEvidence,
    evidence: &X64TailWorkerRootSelectionEvidence,
) -> Result<(), X64TailWorkerRootSelectionError> {
    if evidence.schema_version != X64_TAIL_WORKER_ROOT_SELECTION_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_ROOT_SELECTION_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT
        || evidence.dependency_symbol_policy_hash != X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT
        || evidence.dependency_symbol_evidence_hash != dependency_symbols.evidence_hash()
        || evidence.root_compatibility_policy_hash != X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT
        || evidence.root_compatibility_evidence_hash != root_compatibility.evidence_hash()
        || evidence.root_symbol_policy_hash != X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT
        || evidence.root_symbol_evidence_hash != root_symbols.evidence_hash()
        || evidence.root_scope_policy_hash != X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT
        || evidence.root_scope_evidence_hash != scope.evidence_hash()
        || evidence.root_scope_expectation_hash != scope.expectation_hash()
        || evidence.root_symbol_count != X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_ROOT_SYMBOLS
        || evidence.root_symbol_count != root_symbols.symbol_count()
        || evidence.request_count != X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_REQUESTS
        || evidence.selected_count != X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_SELECTED
        || evidence.ifunc_refusal_count != X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_IFUNC_REFUSALS
        || usize::from(evidence.request_count) != evidence.decisions.len()
        || evidence.topology_hash != X64_TAIL_WORKER_ROOT_SELECTION_TOPOLOGY_ROOT
        || root_selection_topology_hash(&evidence.decisions) != evidence.topology_hash
        || x64_tail_worker_root_selection_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootSelectionError::EvidenceMismatch);
    }
    let mut selected_count = 0u16;
    let mut refused_count = 0u16;
    let mut previous_requester = None;
    for (ordinal, decision) in evidence.decisions.iter().enumerate() {
        if decision.ordinal != u16::try_from(ordinal).unwrap_or(u16::MAX)
            || previous_requester
                .is_some_and(|previous| previous >= decision.requester_symbol_ordinal)
            || decision.requester_symbol_ordinal >= evidence.root_symbol_count
            || decision.requester_symbol_evidence_hash == SemanticHash::ZERO
            || decision.compatibility_binding_evidence_hash == SemanticHash::ZERO
            || decision.definition_evidence_hash == SemanticHash::ZERO
            || decision.selected_symbol_evidence_hash == SemanticHash::ZERO
            || !matches!(decision.selected_binding, STB_GLOBAL | STB_WEAK)
            || decision.selected_visibility != STV_DEFAULT
            || decision.probes.is_empty()
            || decision.probes.len() > usize::from(X64_TAIL_WORKER_ROOT_SELECTION_MAX_SCOPE_PROBES)
            || decision.selected_scope_ordinal
                != u16::try_from(decision.probes.len() - 1).unwrap_or(u16::MAX)
            || decision
                .probes
                .last()
                .is_none_or(|probe| probe.provider_ordinal != decision.selected_provider_ordinal)
            || root_selection_decision_evidence_hash(decision) != decision.evidence_hash
        {
            return Err(X64TailWorkerRootSelectionError::EvidenceMismatch);
        }
        validate_name(&decision.name)?;
        validate_name(&decision.requirement_name)?;
        for (probe_ordinal, probe) in decision.probes.iter().enumerate() {
            if probe.ordinal != u16::try_from(probe_ordinal).unwrap_or(u16::MAX)
                || probe.scope_ordinal != probe.ordinal
                || probe.provider_symbol_object_evidence_hash == SemanticHash::ZERO
                || probe.sysv_chain_ordinals.len()
                    > usize::from(X64_TAIL_WORKER_DEPENDENCY_SYMBOL_MAX_SYMBOLS)
                || probe.gnu_chain_ordinals.len()
                    > usize::from(X64_TAIL_WORKER_DEPENDENCY_SYMBOL_MAX_SYMBOLS)
                || root_selection_probe_evidence_hash(probe) != probe.evidence_hash
            {
                return Err(X64TailWorkerRootSelectionError::EvidenceMismatch);
            }
        }
        match decision.decision_kind {
            X64TailWorkerRootSelectionDecisionKind::Selected => {
                if !matches!(
                    (
                        decision.requester_symbol_type,
                        decision.selected_symbol_type
                    ),
                    (STT_FUNC, STT_FUNC) | (STT_OBJECT, STT_OBJECT)
                ) {
                    return Err(X64TailWorkerRootSelectionError::EvidenceMismatch);
                }
                selected_count = selected_count.checked_add(1).ok_or(
                    X64TailWorkerRootSelectionError::Overflow("preflight selected"),
                )?;
            }
            X64TailWorkerRootSelectionDecisionKind::RefusedIfunc => {
                if decision.requester_symbol_type != STT_FUNC
                    || decision.selected_symbol_type != STT_GNU_IFUNC
                {
                    return Err(X64TailWorkerRootSelectionError::EvidenceMismatch);
                }
                refused_count = refused_count.checked_add(1).ok_or(
                    X64TailWorkerRootSelectionError::Overflow("preflight refused"),
                )?;
            }
        }
        previous_requester = Some(decision.requester_symbol_ordinal);
    }
    if selected_count != evidence.selected_count || refused_count != evidence.ifunc_refusal_count {
        return Err(X64TailWorkerRootSelectionError::EvidenceMismatch);
    }
    Ok(())
}

pub fn x64_tail_worker_root_selection_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_SELECTION_SCHEMA_VERSION);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_SELECTION_POLICY_VERSION);
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT);
    for value in [
        X64_TAIL_WORKER_ROOT_SELECTION_MAX_REQUESTS,
        X64_TAIL_WORKER_ROOT_SELECTION_MAX_SCOPE_PROBES,
        X64_TAIL_WORKER_ROOT_SELECTION_MAX_NAME_BYTES,
        X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_ROOT_SYMBOLS,
        X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_REQUESTS,
        X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_SELECTED,
        X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_IFUNC_REFUSALS,
    ] {
        put_u16(&mut bytes, value);
    }
    for value in [
        STB_GLOBAL,
        STB_WEAK,
        STV_DEFAULT,
        STT_OBJECT,
        STT_FUNC,
        STT_GNU_IFUNC,
    ] {
        put_u8(&mut bytes, value);
    }
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn root_selection_probe_evidence_hash(
    evidence: &X64TailWorkerRootSelectionProbeEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(PROBE_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u16(&mut bytes, evidence.scope_ordinal);
    put_u16(&mut bytes, evidence.provider_ordinal);
    put_hash(&mut bytes, evidence.provider_symbol_object_evidence_hash);
    put_option_u16(&mut bytes, evidence.sysv_bucket_ordinal);
    put_u16_vector(&mut bytes, &evidence.sysv_chain_ordinals);
    put_u16_vector(&mut bytes, &evidence.sysv_name_matches);
    put_option_u16(&mut bytes, evidence.gnu_bloom_word_ordinal);
    put_u64(&mut bytes, evidence.gnu_bloom_mask);
    put_bool(&mut bytes, evidence.gnu_bloom_passed);
    put_option_u16(&mut bytes, evidence.gnu_bucket_ordinal);
    put_u16_vector(&mut bytes, &evidence.gnu_chain_ordinals);
    put_u16_vector(&mut bytes, &evidence.gnu_name_matches);
    SemanticHash(sha256(&bytes))
}

fn root_selection_decision_evidence_hash(
    evidence: &X64TailWorkerRootSelectionDecisionEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(DECISION_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u16(&mut bytes, evidence.requester_symbol_ordinal);
    put_hash(&mut bytes, evidence.requester_symbol_evidence_hash);
    put_string(&mut bytes, &evidence.name);
    put_u32(&mut bytes, evidence.sysv_name_hash);
    put_u32(&mut bytes, evidence.gnu_name_hash);
    put_u8(&mut bytes, evidence.requester_binding);
    put_u8(&mut bytes, evidence.requester_symbol_type);
    put_u8(&mut bytes, evidence.requester_visibility);
    put_u16(&mut bytes, evidence.requester_version_index);
    put_bool(&mut bytes, evidence.requester_version_hidden);
    put_hash(&mut bytes, evidence.requester_namespace_evidence_hash);
    put_hash(&mut bytes, evidence.compatibility_binding_evidence_hash);
    put_string(&mut bytes, &evidence.requirement_name);
    put_hash(&mut bytes, evidence.definition_evidence_hash);
    put_u8(&mut bytes, evidence.decision_kind as u8);
    put_u16(&mut bytes, evidence.selected_scope_ordinal);
    put_u16(&mut bytes, evidence.selected_provider_ordinal);
    put_u16(&mut bytes, evidence.selected_symbol_ordinal);
    put_hash(&mut bytes, evidence.selected_symbol_evidence_hash);
    put_u8(&mut bytes, evidence.selected_binding);
    put_u8(&mut bytes, evidence.selected_symbol_type);
    put_u8(&mut bytes, evidence.selected_visibility);
    put_u16(&mut bytes, evidence.selected_version_index);
    put_bool(&mut bytes, evidence.selected_version_hidden);
    put_u16(
        &mut bytes,
        u16::try_from(evidence.probes.len()).unwrap_or(u16::MAX),
    );
    for probe in &evidence.probes {
        put_hash(&mut bytes, probe.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn root_selection_topology_hash(
    decisions: &[X64TailWorkerRootSelectionDecisionEvidence],
) -> SemanticHash {
    let mut ordered = decisions.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.requirement_name.cmp(&right.requirement_name))
            .then_with(|| {
                left.selected_provider_ordinal
                    .cmp(&right.selected_provider_ordinal)
            })
            .then_with(|| {
                left.selected_symbol_ordinal
                    .cmp(&right.selected_symbol_ordinal)
            })
    });

    let mut bytes = Vec::with_capacity(16 * 1024);
    bytes.extend_from_slice(TOPOLOGY_DOMAIN);
    put_u16(&mut bytes, u16::try_from(ordered.len()).unwrap_or(u16::MAX));
    for decision in ordered {
        put_string(&mut bytes, &decision.name);
        put_u32(&mut bytes, decision.sysv_name_hash);
        put_u32(&mut bytes, decision.gnu_name_hash);
        put_u8(&mut bytes, decision.requester_binding);
        put_u8(&mut bytes, decision.requester_symbol_type);
        put_u8(&mut bytes, decision.requester_visibility);
        put_bool(&mut bytes, decision.requester_version_hidden);
        put_string(&mut bytes, &decision.requirement_name);
        put_u8(&mut bytes, decision.decision_kind as u8);
        put_u16(&mut bytes, decision.selected_scope_ordinal);
        put_u16(&mut bytes, decision.selected_provider_ordinal);
        put_u16(&mut bytes, decision.selected_symbol_ordinal);
        put_u8(&mut bytes, decision.selected_binding);
        put_u8(&mut bytes, decision.selected_symbol_type);
        put_u8(&mut bytes, decision.selected_visibility);
        put_u16(&mut bytes, decision.selected_version_index);
        put_bool(&mut bytes, decision.selected_version_hidden);
        put_u16(
            &mut bytes,
            u16::try_from(decision.probes.len()).unwrap_or(u16::MAX),
        );
        for probe in &decision.probes {
            put_u16(&mut bytes, probe.ordinal);
            put_u16(&mut bytes, probe.scope_ordinal);
            put_u16(&mut bytes, probe.provider_ordinal);
            put_option_u16(&mut bytes, probe.sysv_bucket_ordinal);
            put_u16_vector(&mut bytes, &probe.sysv_chain_ordinals);
            put_u16_vector(&mut bytes, &probe.sysv_name_matches);
            put_option_u16(&mut bytes, probe.gnu_bloom_word_ordinal);
            put_u64(&mut bytes, probe.gnu_bloom_mask);
            put_bool(&mut bytes, probe.gnu_bloom_passed);
            put_option_u16(&mut bytes, probe.gnu_bucket_ordinal);
            put_u16_vector(&mut bytes, &probe.gnu_chain_ordinals);
            put_u16_vector(&mut bytes, &probe.gnu_name_matches);
        }
    }
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_root_selection_evidence_hash(
    evidence: &X64TailWorkerRootSelectionEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.dependency_symbol_policy_hash);
    put_hash(&mut bytes, evidence.dependency_symbol_evidence_hash);
    put_hash(&mut bytes, evidence.root_compatibility_policy_hash);
    put_hash(&mut bytes, evidence.root_compatibility_evidence_hash);
    put_hash(&mut bytes, evidence.root_symbol_policy_hash);
    put_hash(&mut bytes, evidence.root_symbol_evidence_hash);
    put_hash(&mut bytes, evidence.root_scope_policy_hash);
    put_hash(&mut bytes, evidence.root_scope_evidence_hash);
    put_hash(&mut bytes, evidence.root_scope_expectation_hash);
    put_u16(&mut bytes, evidence.root_symbol_count);
    put_u16(&mut bytes, evidence.request_count);
    put_u16(&mut bytes, evidence.selected_count);
    put_u16(&mut bytes, evidence.ifunc_refusal_count);
    for decision in &evidence.decisions {
        put_hash(&mut bytes, decision.evidence_hash);
    }
    put_hash(&mut bytes, evidence.topology_hash);
    SemanticHash(sha256(&bytes))
}

fn validate_name(name: &str) -> Result<(), X64TailWorkerRootSelectionError> {
    if name.is_empty()
        || name.len() > usize::from(X64_TAIL_WORKER_ROOT_SELECTION_MAX_NAME_BYTES)
        || name.as_bytes().contains(&0)
    {
        return Err(X64TailWorkerRootSelectionError::Invalid("symbol name"));
    }
    Ok(())
}

fn elf_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(u32::from(*byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(*byte))
    })
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

fn put_bool(bytes: &mut Vec<u8>, value: bool) {
    put_u8(bytes, u8::from(value));
}

fn put_option_u16(bytes: &mut Vec<u8>, value: Option<u16>) {
    put_bool(bytes, value.is_some());
    put_u16(bytes, value.unwrap_or_default());
}

fn put_u16_vector(bytes: &mut Vec<u8>, values: &[u16]) {
    put_u16(bytes, u16::try_from(values.len()).unwrap_or(u16::MAX));
    for value in values {
        put_u16(bytes, *value);
    }
}

fn put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
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

#[cfg(debug_assertions)]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn probe_x64_tail_worker_root_selection_mutations(
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
    scope_expectation: &X64TailWorkerRootScopeExpectation,
    scope_evidence: &X64TailWorkerRootScopeEvidence,
    evidence: &X64TailWorkerRootSelectionEvidence,
) -> bool {
    if evidence.decisions.is_empty() {
        return false;
    }
    let verify_full = |candidate: &X64TailWorkerRootSelectionEvidence| {
        verify_x64_tail_worker_root_selection_evidence(
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
            scope_expectation,
            scope_evidence,
            candidate,
        )
        .is_err()
    };

    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_root = evidence.clone();
    stale_root.root_symbol_evidence_hash.0[0] ^= 1;
    let mut stale_scope = evidence.clone();
    stale_scope.root_scope_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.request_count = stale_count.request_count.saturating_add(1);
    let mut shallow_entry = evidence.clone();
    shallow_entry.decisions[0].name.push('x');
    let shallow_rejected = [
        stale_policy,
        stale_root,
        stale_scope,
        stale_count,
        shallow_entry,
    ]
    .iter()
    .all(|candidate| {
        preflight_root_selection_evidence(
            dependency_symbol_evidence,
            root_compatibility_evidence,
            root_symbol_evidence,
            scope_evidence,
            candidate,
        )
        .is_err()
    });

    let mut coherent_candidate = evidence.clone();
    let decision = &mut coherent_candidate.decisions[0];
    decision.selected_symbol_ordinal = decision.selected_symbol_ordinal.saturating_add(1);
    decision.selected_symbol_evidence_hash.0[0] ^= 1;
    decision.evidence_hash = root_selection_decision_evidence_hash(decision);
    coherent_candidate.topology_hash = root_selection_topology_hash(&coherent_candidate.decisions);
    coherent_candidate.evidence_hash =
        x64_tail_worker_root_selection_evidence_hash(&coherent_candidate);

    let mut coherent_probe = evidence.clone();
    let probe_decision = coherent_probe.decisions.iter_mut().find(|decision| {
        decision.probes.iter().any(|probe| {
            !probe.gnu_chain_ordinals.is_empty() || !probe.sysv_chain_ordinals.is_empty()
        })
    });
    let Some(probe_decision) = probe_decision else {
        return false;
    };
    let probe = probe_decision
        .probes
        .iter_mut()
        .find(|probe| !probe.gnu_chain_ordinals.is_empty() || !probe.sysv_chain_ordinals.is_empty())
        .expect("probe path was selected above");
    if let Some(first) = probe.gnu_chain_ordinals.first_mut() {
        *first = first.saturating_add(1);
    } else if let Some(first) = probe.sysv_chain_ordinals.first_mut() {
        *first = first.saturating_add(1);
    }
    probe.evidence_hash = root_selection_probe_evidence_hash(probe);
    probe_decision.evidence_hash = root_selection_decision_evidence_hash(probe_decision);
    coherent_probe.topology_hash = root_selection_topology_hash(&coherent_probe.decisions);
    coherent_probe.evidence_hash = x64_tail_worker_root_selection_evidence_hash(&coherent_probe);

    shallow_rejected && verify_full(&coherent_candidate) && verify_full(&coherent_probe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_selection_policy_root_is_frozen() {
        assert_eq!(
            x64_tail_worker_root_selection_policy_hash(),
            X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT
        );
    }

    #[test]
    fn production_module_has_no_forbidden_authority() {
        let source = include_str!("x64_tail_worker_root_selection.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in [
            "std::fs",
            "std::path",
            "std::process",
            "x64_tail_worker_dependency_object_bytes",
            "decode_x64_tail_worker",
            "readelf",
            "dlsym",
            "libloading",
            "x64_tail_enveloped_native",
            "x64_native_process",
            "x64_standalone",
            "x64_target::raw",
            "Instant",
            "SystemTime",
        ] {
            assert!(
                !production.contains(forbidden),
                "production root selection contains forbidden authority {forbidden}"
            );
        }
    }
}
