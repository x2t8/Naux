use super::encoding::{canonical_f64_bits, sha256, specialization_value_bytes};
use super::residual::{finalize_residual_with_limits, ResidualCore, ResidualGenerationError};
use super::schema::{
    CaseArm, CoreProfile, Effect, EffectRow, ErrorKind, Function, FunctionId, LocalId, Mutability,
    NumericMode, Operand, Parameter, Primitive, Program, RValue, RegionId, SemanticHash, SumType,
    Term, Type,
};
use super::specialization::{
    SpecializationSlot, SpecializationValue, ValidatedSpecializationRequest,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

pub const POLYVARIANT_R1_S4_VERSION: (u16, u16, u16) = (1, 3, 0);
pub const R1_S4_MAX_WORK_UNITS_HARD_CAP: u64 = 100_000_000;
pub const R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP: u64 = 1_000_000;
pub const R1_S4_MAX_VARIANTS_HARD_CAP: u64 = 1_000_000;
pub const R1_S4_MAX_CONTROL_SPLITS_HARD_CAP: u64 = 1_000_000;
pub const R1_S4_MAX_DYNAMIC_PARAMETERS_HARD_CAP: u64 = 1_000_000;
pub const R1_S4_MAX_HELPER_UNFOLDS_HARD_CAP: u64 = 1_000_000;
pub const R1_S4_MAX_HELPER_DEPTH: usize = 256;
pub const R1_S4_MAX_RESIDUAL_NODES_HARD_CAP: u64 = 1_000_000;
pub const R1_S4_MAX_RESIDUAL_BYTES_HARD_CAP: u64 = 1_073_741_824;

const POLICY_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-policy:r1-s4:v1\0";
const REQUEST_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-request:r1-s4:v1\0";
const VERSION_KEY_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-version-key:r1-s4:v1\0";
const CONTROL_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-control:r1-s4:v1\0";
const STATIC_TABLE_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-static-table:r1-s4:v1\0";
const SUMMARY_TABLE_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-summary-table:r1-s4:v1\0";
const VARIANT_TABLE_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-variant-table:r1-s4:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyvariantR1S4Budget {
    pub max_work_units: u64,
    pub max_partial_value_nodes: u64,
    pub max_variants: u64,
    pub max_control_splits: u64,
    pub max_dynamic_parameters: u64,
    pub max_helper_unfolds: u64,
    pub max_residual_nodes: u64,
    pub max_residual_bytes: u64,
}

impl PolyvariantR1S4Budget {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        max_work_units: u64,
        max_partial_value_nodes: u64,
        max_variants: u64,
        max_control_splits: u64,
        max_dynamic_parameters: u64,
        max_helper_unfolds: u64,
        max_residual_nodes: u64,
        max_residual_bytes: u64,
    ) -> Self {
        Self {
            max_work_units,
            max_partial_value_nodes,
            max_variants,
            max_control_splits,
            max_dynamic_parameters,
            max_helper_unfolds,
            max_residual_nodes,
            max_residual_bytes,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolyvariantR1S4Control {
    recursive_static_pins: BTreeMap<FunctionId, BTreeSet<u32>>,
}

impl PolyvariantR1S4Control {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn from_pins(pins: impl IntoIterator<Item = (FunctionId, u32)>) -> Self {
        let mut recursive_static_pins = BTreeMap::<FunctionId, BTreeSet<u32>>::new();
        for (function, parameter) in pins {
            recursive_static_pins
                .entry(function)
                .or_default()
                .insert(parameter);
        }
        Self {
            recursive_static_pins,
        }
    }

    pub fn pinned_parameters(&self, function: FunctionId) -> Option<&BTreeSet<u32>> {
        self.recursive_static_pins.get(&function)
    }

    pub fn control_hash(&self) -> SemanticHash {
        let mut bytes = CONTROL_DOMAIN.to_vec();
        bytes.extend_from_slice(&(self.recursive_static_pins.len() as u32).to_be_bytes());
        for (function, parameters) in &self.recursive_static_pins {
            bytes.extend_from_slice(&function.0.to_be_bytes());
            bytes.extend_from_slice(&(parameters.len() as u32).to_be_bytes());
            for parameter in parameters {
                bytes.extend_from_slice(&parameter.to_be_bytes());
            }
        }
        SemanticHash(sha256(&bytes))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolyvariantR1S4Usage {
    pub work_units: u64,
    pub partial_value_nodes: u64,
    pub variants: u64,
    pub control_splits: u64,
    pub dynamic_parameters: u64,
    pub helper_unfolds: u64,
    pub static_interns: u64,
    pub summary_entries: u64,
    pub summary_hits: u64,
    pub widened_values: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolyvariantR1S4Pattern {
    KnownUnit,
    KnownBool(bool),
    KnownI64(i64),
    KnownF64(u64),
    KnownTuple(Vec<PolyvariantR1S4Pattern>),
    Hole {
        ty: Type,
        alias: u32,
    },
    Tuple(Vec<PolyvariantR1S4Pattern>),
    KnownSum {
        sum: SumType,
        constructor: u32,
        fields: Vec<PolyvariantR1S4Pattern>,
    },
    UnknownSum {
        sum: SumType,
        alias: u32,
    },
    SharedStatic {
        hash: SemanticHash,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyvariantR1S4Variant {
    source_function: FunctionId,
    residual_function: FunctionId,
    patterns: Vec<PolyvariantR1S4Pattern>,
}

impl PolyvariantR1S4Variant {
    pub fn source_function(&self) -> FunctionId {
        self.source_function
    }

    pub fn residual_function(&self) -> FunctionId {
        self.residual_function
    }

    pub fn patterns(&self) -> &[PolyvariantR1S4Pattern] {
        &self.patterns
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyvariantR1S4Report {
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    request_hash: SemanticHash,
    upstream_request_hash: SemanticHash,
    control_hash: SemanticHash,
    static_table_hash: SemanticHash,
    summary_table_hash: SemanticHash,
    variant_table_hash: SemanticHash,
    budget: PolyvariantR1S4Budget,
    usage: PolyvariantR1S4Usage,
    variants: Vec<PolyvariantR1S4Variant>,
    residual_hash: SemanticHash,
    residual_nodes: u64,
    residual_bytes: u64,
}

impl PolyvariantR1S4Report {
    pub fn policy_version(&self) -> (u16, u16, u16) {
        self.policy_version
    }

    pub fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub fn request_hash(&self) -> SemanticHash {
        self.request_hash
    }

    pub fn upstream_request_hash(&self) -> SemanticHash {
        self.upstream_request_hash
    }

    pub fn control_hash(&self) -> SemanticHash {
        self.control_hash
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

    pub fn budget(&self) -> PolyvariantR1S4Budget {
        self.budget
    }

    pub fn usage(&self) -> PolyvariantR1S4Usage {
        self.usage
    }

    pub fn variants(&self) -> &[PolyvariantR1S4Variant] {
        &self.variants
    }

    pub fn residual_hash(&self) -> SemanticHash {
        self.residual_hash
    }

    pub fn residual_nodes(&self) -> u64 {
        self.residual_nodes
    }

    pub fn residual_bytes(&self) -> u64 {
        self.residual_bytes
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolyvariantR1S4Specialization {
    residual: ResidualCore,
    report: PolyvariantR1S4Report,
}

impl PolyvariantR1S4Specialization {
    pub fn residual(&self) -> &ResidualCore {
        &self.residual
    }

    pub fn artifact(&self) -> &super::schema::CoreArtifact {
        &self.residual.artifact
    }

    pub fn report(&self) -> &PolyvariantR1S4Report {
        &self.report
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PolyvariantR1S4Error {
    ZeroBudget {
        field: &'static str,
    },
    BudgetHardCapExceeded {
        field: &'static str,
        limit: u64,
        hard_cap: u64,
    },
    UnsupportedProfile(CoreProfile),
    UnsupportedType {
        function: FunctionId,
        context: &'static str,
        ty: Type,
    },
    UnsupportedEffects {
        function: FunctionId,
    },
    UnsupportedRegionParameters {
        function: FunctionId,
    },
    UnsupportedNode {
        function: FunctionId,
        node: &'static str,
    },
    UnsupportedPrimitive {
        function: FunctionId,
        primitive: Primitive,
    },
    MissingFunction(FunctionId),
    MissingLocal {
        function: FunctionId,
        local: LocalId,
    },
    ArityMismatch {
        function: FunctionId,
        expected: usize,
        actual: usize,
    },
    InvalidEntrySlot {
        parameter: LocalId,
    },
    InvalidControlPin {
        function: FunctionId,
        parameter: u32,
    },
    MultipleRecursiveComponents {
        count: usize,
    },
    ExpectedBool {
        function: FunctionId,
    },
    ExpectedTuple {
        function: FunctionId,
    },
    ExpectedSum {
        function: FunctionId,
    },
    WorkBudgetExceeded {
        limit: u64,
    },
    PartialValueBudgetExceeded {
        limit: u64,
    },
    VariantBudgetExceeded {
        limit: u64,
    },
    ControlBudgetExceeded {
        limit: u64,
    },
    DynamicParameterBudgetExceeded {
        limit: u64,
    },
    HelperBudgetExceeded {
        limit: u64,
    },
    FunctionIdExhausted,
    LocalIdExhausted,
    AtomIdExhausted,
    StaticIdentityCollision {
        hash: SemanticHash,
    },
    UnresolvedVariant,
    Residual(ResidualGenerationError),
    InternalInvariant {
        message: String,
    },
}

impl fmt::Display for PolyvariantR1S4Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBudget { field } => write!(formatter, "R1-S4 budget {field} is zero"),
            Self::BudgetHardCapExceeded {
                field,
                limit,
                hard_cap,
            } => write!(
                formatter,
                "R1-S4 budget {field}={limit} exceeds hard cap {hard_cap}"
            ),
            Self::UnsupportedProfile(profile) => {
                write!(formatter, "R1-S4 admits P1V0, found {profile:?}")
            }
            Self::UnsupportedType {
                function,
                context,
                ty,
            } => write!(
                formatter,
                "R1-S4 function {} has unsupported {context} type {ty:?}",
                function.0
            ),
            Self::UnsupportedEffects { function } => write!(
                formatter,
                "R1-S4 function {} has effects outside empty or Error<Bounds>",
                function.0
            ),
            Self::UnsupportedRegionParameters { function } => write!(
                formatter,
                "R1-S4 function {} has region parameters outside [] or [RegionId(0)]",
                function.0
            ),
            Self::UnsupportedNode { function, node } => write!(
                formatter,
                "R1-S4 function {} contains unsupported {node}",
                function.0
            ),
            Self::UnsupportedPrimitive {
                function,
                primitive,
            } => write!(
                formatter,
                "R1-S4 function {} contains unsupported primitive {primitive:?}",
                function.0
            ),
            Self::MissingFunction(function) => {
                write!(formatter, "R1-S4 cannot find function {}", function.0)
            }
            Self::MissingLocal { function, local } => write!(
                formatter,
                "R1-S4 function {} cannot resolve local {}",
                function.0, local.0
            ),
            Self::ArityMismatch {
                function,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S4 call to function {} has {actual} argument(s), expected {expected}",
                function.0
            ),
            Self::InvalidEntrySlot { parameter } => write!(
                formatter,
                "R1-S4 entry parameter {} is not an admitted structural slot",
                parameter.0
            ),
            Self::InvalidControlPin {
                function,
                parameter,
            } => write!(
                formatter,
                "R1-S4 control pins non-recursive or missing parameter {} of function {}",
                parameter, function.0
            ),
            Self::MultipleRecursiveComponents { count } => write!(
                formatter,
                "R1-S4 reachable graph has {count} recursive components; at most two are admitted"
            ),
            Self::ExpectedBool { function } => write!(
                formatter,
                "R1-S4 function {} reached a non-Bool If condition",
                function.0
            ),
            Self::ExpectedTuple { function } => write!(
                formatter,
                "R1-S4 function {} reached a non-Tuple projection",
                function.0
            ),
            Self::ExpectedSum { function } => write!(
                formatter,
                "R1-S4 function {} reached a non-Sum Case",
                function.0
            ),
            Self::WorkBudgetExceeded { limit } => {
                write!(formatter, "R1-S4 exceeded max_work_units {limit}")
            }
            Self::PartialValueBudgetExceeded { limit } => {
                write!(formatter, "R1-S4 exceeded max_partial_value_nodes {limit}")
            }
            Self::VariantBudgetExceeded { limit } => {
                write!(formatter, "R1-S4 exceeded max_variants {limit}")
            }
            Self::ControlBudgetExceeded { limit } => {
                write!(formatter, "R1-S4 exceeded max_control_splits {limit}")
            }
            Self::DynamicParameterBudgetExceeded { limit } => {
                write!(formatter, "R1-S4 exceeded max_dynamic_parameters {limit}")
            }
            Self::HelperBudgetExceeded { limit } => {
                write!(formatter, "R1-S4 exceeded max_helper_unfolds {limit}")
            }
            Self::FunctionIdExhausted => {
                formatter.write_str("R1-S4 exhausted the FunctionId namespace")
            }
            Self::LocalIdExhausted => {
                formatter.write_str("R1-S4 exhausted a residual LocalId namespace")
            }
            Self::AtomIdExhausted => formatter.write_str("R1-S4 exhausted internal AtomId"),
            Self::StaticIdentityCollision { hash } => write!(
                formatter,
                "R1-S4 static interner found conflicting canonical values for {}",
                hash.to_hex()
            ),
            Self::UnresolvedVariant => {
                formatter.write_str("R1-S4 finished with an unresolved variant")
            }
            Self::Residual(error) => write!(formatter, "R1-S4 residual failed: {error}"),
            Self::InternalInvariant { message } => {
                write!(formatter, "R1-S4 invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for PolyvariantR1S4Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AtomId(u64);

#[derive(Clone, Debug)]
struct Atom {
    id: AtomId,
    ty: Type,
    operand: Operand,
}

type Partial = Arc<PartialValue>;

#[derive(Clone, Debug)]
enum PartialValue {
    Known(Arc<SpecializationValue>),
    SharedStatic(Arc<SharedStatic>),
    Hole(Atom),
    Tuple(Vec<Partial>),
    KnownSum {
        sum: SumType,
        constructor: u32,
        fields: Vec<Partial>,
    },
    UnknownSum {
        sum: SumType,
        atom: Atom,
    },
}

#[derive(Clone, Debug)]
struct SharedStatic {
    hash: SemanticHash,
    canonical: Arc<[u8]>,
    value: Arc<SpecializationValue>,
    ty: Type,
    shape: SharedStaticShape,
}

#[derive(Clone, Debug)]
enum SharedStaticShape {
    Tuple(Vec<Partial>),
    Sum {
        sum: SumType,
        constructor: u32,
        fields: Vec<Partial>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VersionKey {
    source_function: FunctionId,
    patterns: Vec<PolyvariantR1S4Pattern>,
}

#[derive(Clone)]
struct ReservedVersion {
    temporary_id: FunctionId,
    built: bool,
}

struct BuiltVersion {
    key: VersionKey,
    temporary_id: FunctionId,
    function: Function,
}

#[derive(Clone)]
struct MaterializedBinding {
    binder: LocalId,
    ty: Type,
    value: RValue,
}

struct HelperFrame {
    function: FunctionId,
    environment: BTreeMap<LocalId, Partial>,
    cursor: Term,
    return_to: Option<LocalId>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SummaryKey {
    function: FunctionId,
    patterns: Vec<PolyvariantR1S4Pattern>,
}

#[derive(Clone, Debug)]
enum SummaryEntry {
    Result(PolyvariantR1S4Pattern),
}

struct FreshLocals {
    next: Option<u32>,
}

impl FreshLocals {
    fn for_function(function: &Function) -> Self {
        let mut maximum = function
            .parameters
            .iter()
            .map(|parameter| parameter.local.0)
            .max();
        scan_term_locals(&function.body, &mut maximum);
        Self {
            next: match maximum {
                Some(maximum) => maximum.checked_add(1),
                None => Some(0),
            },
        }
    }

    fn allocate(&mut self) -> Result<LocalId, PolyvariantR1S4Error> {
        let local = self.next.ok_or(PolyvariantR1S4Error::LocalIdExhausted)?;
        self.next = local.checked_add(1);
        Ok(LocalId(local))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AtomDerivation {
    TupleField(u32),
    SumField { constructor: u32, field: u32 },
}

struct Machine {
    functions: BTreeMap<FunctionId, Function>,
    recursive_functions: BTreeSet<FunctionId>,
    budget: PolyvariantR1S4Budget,
    control: PolyvariantR1S4Control,
    usage: PolyvariantR1S4Usage,
    next_atom: Option<u64>,
    derived_atoms: BTreeMap<(AtomId, AtomDerivation), AtomId>,
    static_values: BTreeMap<SemanticHash, Partial>,
    summaries: BTreeMap<SummaryKey, SummaryEntry>,
    reserved: BTreeMap<VersionKey, ReservedVersion>,
    worklist: VecDeque<VersionKey>,
    built: Vec<BuiltVersion>,
}

pub fn polyvariant_r1_s4_policy_hash() -> SemanticHash {
    let mut bytes = POLICY_DOMAIN.to_vec();
    put_version(&mut bytes, POLYVARIANT_R1_S4_VERSION);
    put_bytes(&mut bytes, VERSION_KEY_DOMAIN);
    put_bytes(&mut bytes, STATIC_TABLE_DOMAIN);
    put_bytes(&mut bytes, SUMMARY_TABLE_DOMAIN);
    put_bytes(&mut bytes, VARIANT_TABLE_DOMAIN);
    for cap in [
        R1_S4_MAX_WORK_UNITS_HARD_CAP,
        R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
        R1_S4_MAX_VARIANTS_HARD_CAP,
        R1_S4_MAX_CONTROL_SPLITS_HARD_CAP,
        R1_S4_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
        R1_S4_MAX_HELPER_UNFOLDS_HARD_CAP,
        R1_S4_MAX_HELPER_DEPTH as u64,
        R1_S4_MAX_RESIDUAL_NODES_HARD_CAP,
        R1_S4_MAX_RESIDUAL_BYTES_HARD_CAP,
    ] {
        bytes.extend_from_slice(&cap.to_be_bytes());
    }
    for capability in [
        b"structural-partial-values-v1".as_slice(),
        b"known-unknown-sum-v1".as_slice(),
        b"entry-static-aggregate-structuralization-v1".as_slice(),
        b"hash-checked-shared-static-aggregate-interning-v1".as_slice(),
        b"compact-shared-static-version-keys-v1".as_slice(),
        b"alpha-hole-aliases-v1".as_slice(),
        b"flattened-signatures-v1".as_slice(),
        b"derived-aggregate-atoms-v1".as_slice(),
        b"atom-equivalence-current-operand-v1".as_slice(),
        b"zero-residual-acyclic-helper-unfold-v1".as_slice(),
        b"known-if-case-helper-unfold-v1".as_slice(),
        b"cross-version-pure-result-summary-templates-v1".as_slice(),
        b"summary-alias-rebinding-v1".as_slice(),
        b"machine-work-event-schedule-v1".as_slice(),
        b"partial-node-cumulative-including-refused-helper-work-v1".as_slice(),
        b"control-if-one-case-arms-minus-one-v1".as_slice(),
        b"helper-attempts-eligible-entries-v1".as_slice(),
        b"helper-depth-256-conservative-refusal-v1".as_slice(),
        b"read-only-array-f64-hole-v1".as_slice(),
        b"bounds-effect-row-preservation-v1".as_slice(),
        b"array-len-never-statically-erased-v1".as_slice(),
        b"array-get-never-statically-erased-v1".as_slice(),
        b"region-parameters-empty-or-zero-v1".as_slice(),
        b"at-most-two-recursive-components-v1".as_slice(),
        b"recursive-boundary-monotone-payload-widening-v1".as_slice(),
        b"request-bound-static-control-pins-v1".as_slice(),
        b"static-array-live-use-refused-v1".as_slice(),
        b"residual-cap-min-s4-upstream-v1".as_slice(),
        b"canonical-key-byte-function-id-order-v1".as_slice(),
        b"exact-independent-budgets-v1".as_slice(),
        b"verified-residual-only-v1".as_slice(),
    ] {
        put_bytes(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

pub fn specialize_polyvariant_r1_s4(
    validated: &ValidatedSpecializationRequest<'_, '_>,
    budget: PolyvariantR1S4Budget,
) -> Result<PolyvariantR1S4Specialization, PolyvariantR1S4Error> {
    specialize_polyvariant_r1_s4_with_control(validated, budget, &PolyvariantR1S4Control::none())
}

pub fn specialize_polyvariant_r1_s4_with_control(
    validated: &ValidatedSpecializationRequest<'_, '_>,
    budget: PolyvariantR1S4Budget,
    control: &PolyvariantR1S4Control,
) -> Result<PolyvariantR1S4Specialization, PolyvariantR1S4Error> {
    validate_budget(budget)?;
    let source = &validated.artifact().program;
    if source.profile != CoreProfile::P1V0 {
        return Err(PolyvariantR1S4Error::UnsupportedProfile(source.profile));
    }

    let functions = source
        .functions
        .iter()
        .cloned()
        .map(|function| (function.id, function))
        .collect::<BTreeMap<_, _>>();
    let mut machine = Machine {
        functions,
        recursive_functions: BTreeSet::new(),
        budget,
        control: control.clone(),
        usage: PolyvariantR1S4Usage::default(),
        next_atom: Some(0),
        derived_atoms: BTreeMap::new(),
        static_values: BTreeMap::new(),
        summaries: BTreeMap::new(),
        reserved: BTreeMap::new(),
        worklist: VecDeque::new(),
        built: Vec::new(),
    };
    let graph = machine.admit_reachable_subset(source.entry)?;
    let graph_edges = graph.values().try_fold(0_u64, |total, edges| {
        total
            .checked_add(edges.len() as u64)
            .ok_or(PolyvariantR1S4Error::WorkBudgetExceeded {
                limit: budget.max_work_units,
            })
    })?;
    machine.consume_work(graph.len() as u64 + graph_edges)?;
    let recursive_components = recursive_components(&graph);
    if recursive_components.len() > 2 {
        return Err(PolyvariantR1S4Error::MultipleRecursiveComponents {
            count: recursive_components.len(),
        });
    }
    machine.recursive_functions = recursive_components
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>();
    machine.validate_control()?;

    let entry = machine
        .functions
        .get(&source.entry)
        .cloned()
        .ok_or(PolyvariantR1S4Error::MissingFunction(source.entry))?;
    if entry.parameters.len() != validated.request().entry_slots.len() {
        return Err(PolyvariantR1S4Error::ArityMismatch {
            function: source.entry,
            expected: entry.parameters.len(),
            actual: validated.request().entry_slots.len(),
        });
    }
    let mut entry_values = Vec::with_capacity(entry.parameters.len());
    for (parameter, slot) in entry
        .parameters
        .iter()
        .zip(&validated.request().entry_slots)
    {
        entry_values.push(machine.entry_partial(parameter, slot)?);
    }
    let (entry_patterns, _) = machine.patterns_and_operands(&entry_values)?;
    let entry_key = VersionKey {
        source_function: source.entry,
        patterns: entry_patterns,
    };

    let policy_hash = polyvariant_r1_s4_policy_hash();
    let control_hash = control.control_hash();
    let request_hash = polyvariant_request_hash(
        validated.artifact().semantic_hash,
        validated.request_hash(),
        source.entry,
        budget,
        policy_hash,
        control,
    );
    let entry_temporary = machine.reserve(entry_key)?;
    while let Some(key) = machine.worklist.pop_front() {
        machine.build_version(key)?;
    }
    if machine.reserved.values().any(|version| !version.built) {
        return Err(PolyvariantR1S4Error::UnresolvedVariant);
    }

    let (static_table_hash, summary_table_hash) = machine.evidence_table_hashes()?;
    let (program, variants, usage) =
        machine.lower_program(entry_temporary, &source.schema, source.profile)?;
    let variant_table_hash = variant_table_hash(&variants)?;
    let upstream = validated.request().budget;
    let residual = finalize_residual_with_limits(
        validated.artifact().semantic_hash,
        request_hash,
        program,
        budget.max_residual_nodes.min(upstream.max_residual_nodes),
        budget.max_residual_bytes.min(upstream.max_residual_bytes),
    )
    .map_err(PolyvariantR1S4Error::Residual)?;
    let report = PolyvariantR1S4Report {
        policy_version: POLYVARIANT_R1_S4_VERSION,
        policy_hash,
        request_hash,
        upstream_request_hash: validated.request_hash(),
        control_hash,
        static_table_hash,
        summary_table_hash,
        variant_table_hash,
        budget,
        usage,
        variants,
        residual_hash: residual.artifact.semantic_hash,
        residual_nodes: residual.residual_nodes,
        residual_bytes: residual.residual_bytes,
    };
    Ok(PolyvariantR1S4Specialization { residual, report })
}

impl Machine {
    fn validate_control(&self) -> Result<(), PolyvariantR1S4Error> {
        for (function, parameters) in &self.control.recursive_static_pins {
            let Some(source) = self.functions.get(function) else {
                return Err(PolyvariantR1S4Error::InvalidControlPin {
                    function: *function,
                    parameter: parameters.iter().next().copied().unwrap_or(0),
                });
            };
            for parameter in parameters {
                if !self.recursive_functions.contains(function)
                    || (*parameter as usize) >= source.parameters.len()
                {
                    return Err(PolyvariantR1S4Error::InvalidControlPin {
                        function: *function,
                        parameter: *parameter,
                    });
                }
            }
        }
        Ok(())
    }

    fn consume_work(&mut self, units: u64) -> Result<(), PolyvariantR1S4Error> {
        let next = self.usage.work_units.checked_add(units).ok_or(
            PolyvariantR1S4Error::WorkBudgetExceeded {
                limit: self.budget.max_work_units,
            },
        )?;
        if next > self.budget.max_work_units {
            return Err(PolyvariantR1S4Error::WorkBudgetExceeded {
                limit: self.budget.max_work_units,
            });
        }
        self.usage.work_units = next;
        Ok(())
    }

    fn consume_partial_nodes(&mut self, nodes: u64) -> Result<(), PolyvariantR1S4Error> {
        self.consume_work(nodes)?;
        let next = self.usage.partial_value_nodes.checked_add(nodes).ok_or(
            PolyvariantR1S4Error::PartialValueBudgetExceeded {
                limit: self.budget.max_partial_value_nodes,
            },
        )?;
        if next > self.budget.max_partial_value_nodes {
            return Err(PolyvariantR1S4Error::PartialValueBudgetExceeded {
                limit: self.budget.max_partial_value_nodes,
            });
        }
        self.usage.partial_value_nodes = next;
        Ok(())
    }

    fn consume_control(&mut self, splits: u64) -> Result<(), PolyvariantR1S4Error> {
        let next = self.usage.control_splits.checked_add(splits).ok_or(
            PolyvariantR1S4Error::ControlBudgetExceeded {
                limit: self.budget.max_control_splits,
            },
        )?;
        if next > self.budget.max_control_splits {
            return Err(PolyvariantR1S4Error::ControlBudgetExceeded {
                limit: self.budget.max_control_splits,
            });
        }
        self.usage.control_splits = next;
        Ok(())
    }

    fn consume_helper(&mut self) -> Result<(), PolyvariantR1S4Error> {
        if self.usage.helper_unfolds == self.budget.max_helper_unfolds {
            return Err(PolyvariantR1S4Error::HelperBudgetExceeded {
                limit: self.budget.max_helper_unfolds,
            });
        }
        self.usage.helper_unfolds += 1;
        Ok(())
    }

    fn allocate_atom(&mut self) -> Result<AtomId, PolyvariantR1S4Error> {
        let raw = self
            .next_atom
            .ok_or(PolyvariantR1S4Error::AtomIdExhausted)?;
        self.next_atom = raw.checked_add(1);
        Ok(AtomId(raw))
    }

    fn widen_recursive_arguments(
        &mut self,
        function: FunctionId,
        arguments: &[Partial],
    ) -> Result<Vec<Partial>, PolyvariantR1S4Error> {
        if !self.recursive_functions.contains(&function) {
            return Ok(arguments.to_vec());
        }
        let pins = self
            .control
            .pinned_parameters(function)
            .cloned()
            .unwrap_or_default();
        let mut widened = Vec::with_capacity(arguments.len());
        for (index, argument) in arguments.iter().enumerate() {
            let index =
                u32::try_from(index).map_err(|_| PolyvariantR1S4Error::InternalInvariant {
                    message: "R1-S4 recursive argument index exceeds U32".to_owned(),
                })?;
            if pins.contains(&index) {
                widened.push(argument.clone());
            } else {
                widened.push(self.widen_partial(argument)?);
            }
        }
        Ok(widened)
    }

    fn widen_partial(&mut self, value: &Partial) -> Result<Partial, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match value.as_ref() {
            PartialValue::Known(value) => {
                if matches!(
                    value.as_ref(),
                    SpecializationValue::Tuple(_) | SpecializationValue::Sum { .. }
                ) {
                    let shared = self.make_known(value.as_ref().clone())?;
                    return self.widen_partial(&shared);
                }
                let ty = specialization_value_type(value)?;
                let operand = literal_from_value(value).ok_or_else(|| {
                    PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 could not residualize a widened scalar".to_owned(),
                    }
                })?;
                let atom = self.allocate_atom()?;
                self.usage.widened_values = self.usage.widened_values.checked_add(1).ok_or(
                    PolyvariantR1S4Error::PartialValueBudgetExceeded {
                        limit: self.budget.max_partial_value_nodes,
                    },
                )?;
                self.make_dynamic(ty, atom, operand)
            }
            PartialValue::SharedStatic(shared) => match &shared.shape {
                SharedStaticShape::Tuple(original) => {
                    let widened = self.widen_fields(original)?;
                    if widened
                        .iter()
                        .zip(original)
                        .all(|(widened, original)| Arc::ptr_eq(widened, original))
                    {
                        return Ok(value.clone());
                    }
                    self.consume_partial_nodes(1)?;
                    Ok(Arc::new(PartialValue::Tuple(widened)))
                }
                SharedStaticShape::Sum {
                    sum,
                    constructor,
                    fields,
                } => {
                    let widened = self.widen_fields(fields)?;
                    if widened
                        .iter()
                        .zip(fields)
                        .all(|(widened, original)| Arc::ptr_eq(widened, original))
                    {
                        return Ok(value.clone());
                    }
                    self.consume_partial_nodes(1)?;
                    Ok(Arc::new(PartialValue::KnownSum {
                        sum: sum.clone(),
                        constructor: *constructor,
                        fields: widened,
                    }))
                }
            },
            PartialValue::Tuple(fields) => {
                let widened = self.widen_fields(fields)?;
                if widened
                    .iter()
                    .zip(fields)
                    .all(|(widened, original)| Arc::ptr_eq(widened, original))
                {
                    return Ok(value.clone());
                }
                self.consume_partial_nodes(1)?;
                Ok(Arc::new(PartialValue::Tuple(widened)))
            }
            PartialValue::KnownSum {
                sum,
                constructor,
                fields,
            } => {
                let widened = self.widen_fields(fields)?;
                if widened
                    .iter()
                    .zip(fields)
                    .all(|(widened, original)| Arc::ptr_eq(widened, original))
                {
                    return Ok(value.clone());
                }
                self.consume_partial_nodes(1)?;
                Ok(Arc::new(PartialValue::KnownSum {
                    sum: sum.clone(),
                    constructor: *constructor,
                    fields: widened,
                }))
            }
            PartialValue::Hole(atom) => {
                let id = self.allocate_atom()?;
                self.usage.widened_values = self.usage.widened_values.checked_add(1).ok_or(
                    PolyvariantR1S4Error::PartialValueBudgetExceeded {
                        limit: self.budget.max_partial_value_nodes,
                    },
                )?;
                self.make_dynamic(atom.ty.clone(), id, atom.operand.clone())
            }
            PartialValue::UnknownSum { sum, atom } => {
                let id = self.allocate_atom()?;
                self.usage.widened_values = self.usage.widened_values.checked_add(1).ok_or(
                    PolyvariantR1S4Error::PartialValueBudgetExceeded {
                        limit: self.budget.max_partial_value_nodes,
                    },
                )?;
                self.make_dynamic(Type::Sum(sum.clone()), id, atom.operand.clone())
            }
        }
    }

    fn widen_fields(&mut self, fields: &[Partial]) -> Result<Vec<Partial>, PolyvariantR1S4Error> {
        fields
            .iter()
            .map(|field| self.widen_partial(field))
            .collect()
    }

    fn derived_atom(
        &mut self,
        parent: AtomId,
        derivation: AtomDerivation,
    ) -> Result<AtomId, PolyvariantR1S4Error> {
        if let Some(atom) = self.derived_atoms.get(&(parent, derivation.clone())) {
            return Ok(*atom);
        }
        let atom = self.allocate_atom()?;
        self.derived_atoms.insert((parent, derivation), atom);
        Ok(atom)
    }

    fn make_known(&mut self, value: SpecializationValue) -> Result<Partial, PolyvariantR1S4Error> {
        let value = canonical_static_value(&value)?;
        match value {
            SpecializationValue::Tuple(_) | SpecializationValue::Sum { .. } => {
                self.intern_static(value)
            }
            SpecializationValue::Unit
            | SpecializationValue::Bool(_)
            | SpecializationValue::I64(_)
            | SpecializationValue::F64(_) => {
                self.consume_partial_nodes(1)?;
                Ok(Arc::new(PartialValue::Known(Arc::new(value))))
            }
            SpecializationValue::ArrayF64(_) => Err(PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 received an excluded static array".to_owned(),
            }),
        }
    }

    fn intern_static(
        &mut self,
        value: SpecializationValue,
    ) -> Result<Partial, PolyvariantR1S4Error> {
        let canonical = specialization_value_bytes(&value).map_err(|error| {
            PolyvariantR1S4Error::InternalInvariant {
                message: format!("R1-S4 could not encode a shared static value: {error}"),
            }
        })?;
        let hash = SemanticHash(sha256(&canonical));
        if let Some(stored) = self.static_values.get(&hash) {
            let PartialValue::SharedStatic(existing) = stored.as_ref() else {
                return Err(PolyvariantR1S4Error::InternalInvariant {
                    message: "R1-S4 static interner stored a non-shared value".to_owned(),
                });
            };
            if existing.canonical.as_ref() != canonical.as_slice() {
                return Err(PolyvariantR1S4Error::StaticIdentityCollision { hash });
            }
            return Ok(stored.clone());
        }

        let ty = specialization_value_type(&value)?;
        let shape = match &value {
            SpecializationValue::Tuple(fields) => {
                let mut partials = Vec::with_capacity(fields.len());
                for field in fields {
                    partials.push(self.make_known(field.clone())?);
                }
                SharedStaticShape::Tuple(partials)
            }
            SpecializationValue::Sum {
                ty,
                constructor,
                fields,
            } => {
                let expected = ty.constructors.get(*constructor as usize).ok_or_else(|| {
                    PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 shared Sum constructor is absent".to_owned(),
                    }
                })?;
                if expected.fields.len() != fields.len() {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 shared Sum arity changed".to_owned(),
                    });
                }
                let mut partials = Vec::with_capacity(fields.len());
                for field in fields {
                    partials.push(self.make_known(field.clone())?);
                }
                SharedStaticShape::Sum {
                    sum: ty.clone(),
                    constructor: *constructor,
                    fields: partials,
                }
            }
            _ => {
                return Err(PolyvariantR1S4Error::InternalInvariant {
                    message: "R1-S4 attempted to intern a scalar static value".to_owned(),
                });
            }
        };
        self.consume_partial_nodes(1)?;
        self.usage.static_interns = self.usage.static_interns.checked_add(1).ok_or(
            PolyvariantR1S4Error::PartialValueBudgetExceeded {
                limit: self.budget.max_partial_value_nodes,
            },
        )?;
        let shared = Arc::new(PartialValue::SharedStatic(Arc::new(SharedStatic {
            hash,
            canonical: Arc::from(canonical),
            value: Arc::new(value),
            ty,
            shape,
        })));
        self.static_values.insert(hash, shared.clone());
        Ok(shared)
    }

    fn make_entry_static(
        &mut self,
        value: &SpecializationValue,
    ) -> Result<Partial, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        self.make_known(value.clone())
    }

    fn make_dynamic(
        &mut self,
        ty: Type,
        id: AtomId,
        operand: Operand,
    ) -> Result<Partial, PolyvariantR1S4Error> {
        self.consume_partial_nodes(1)?;
        Ok(match ty {
            Type::Sum(sum) => Arc::new(PartialValue::UnknownSum {
                sum: sum.clone(),
                atom: Atom {
                    id,
                    ty: Type::Sum(sum),
                    operand,
                },
            }),
            ty => Arc::new(PartialValue::Hole(Atom { id, ty, operand })),
        })
    }

    fn make_tuple(&mut self, fields: Vec<Partial>) -> Result<Partial, PolyvariantR1S4Error> {
        self.consume_work(fields.len() as u64)?;
        if let Some(values) = all_static(&fields) {
            return self.intern_static(SpecializationValue::Tuple(values));
        }
        self.consume_partial_nodes(1)?;
        Ok(Arc::new(PartialValue::Tuple(fields)))
    }

    fn make_known_sum(
        &mut self,
        sum: SumType,
        constructor: u32,
        fields: Vec<Partial>,
    ) -> Result<Partial, PolyvariantR1S4Error> {
        self.consume_work(fields.len() as u64)?;
        let expected = sum.constructors.get(constructor as usize).ok_or_else(|| {
            PolyvariantR1S4Error::InternalInvariant {
                message: "verified Sum constructor is absent".to_owned(),
            }
        })?;
        if expected.fields.len() != fields.len() {
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: "verified Sum field arity changed during specialization".to_owned(),
            });
        }
        if let Some(values) = all_static(&fields) {
            return self.intern_static(SpecializationValue::Sum {
                ty: sum,
                constructor,
                fields: values,
            });
        }
        self.consume_partial_nodes(1)?;
        Ok(Arc::new(PartialValue::KnownSum {
            sum,
            constructor,
            fields,
        }))
    }

    fn entry_partial(
        &mut self,
        parameter: &Parameter,
        slot: &SpecializationSlot,
    ) -> Result<Partial, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match slot {
            SpecializationSlot::Static(value)
                if specialization_value_matches_type(value, &parameter.ty) =>
            {
                self.make_entry_static(value)
            }
            SpecializationSlot::Dynamic(ty) if is_admitted_type(ty) && *ty == parameter.ty => {
                let atom = self.allocate_atom()?;
                self.make_dynamic(ty.clone(), atom, Operand::Local(parameter.local))
            }
            _ => Err(PolyvariantR1S4Error::InvalidEntrySlot {
                parameter: parameter.local,
            }),
        }
    }

    fn admit_reachable_subset(
        &mut self,
        entry: FunctionId,
    ) -> Result<BTreeMap<FunctionId, Vec<FunctionId>>, PolyvariantR1S4Error> {
        let mut graph = BTreeMap::new();
        let mut pending = vec![entry];
        let mut visited = BTreeSet::new();
        while let Some(function_id) = pending.pop() {
            self.consume_work(1)?;
            if !visited.insert(function_id) {
                continue;
            }
            let function = self
                .functions
                .get(&function_id)
                .cloned()
                .ok_or(PolyvariantR1S4Error::MissingFunction(function_id))?;
            self.admit_function(&function)?;
            let mut callees = Vec::new();
            collect_calls(&function.body, &mut callees);
            self.consume_work(callees.len() as u64)?;
            callees.sort();
            callees.dedup();
            for callee in callees.iter().rev() {
                if !self.functions.contains_key(callee) {
                    return Err(PolyvariantR1S4Error::MissingFunction(*callee));
                }
                pending.push(*callee);
            }
            graph.insert(function_id, callees);
        }
        Ok(graph)
    }

    fn admit_function(&mut self, function: &Function) -> Result<(), PolyvariantR1S4Error> {
        self.consume_work(1)?;
        if !matches!(function.region_parameters.as_slice(), [] | [RegionId(0)]) {
            return Err(PolyvariantR1S4Error::UnsupportedRegionParameters {
                function: function.id,
            });
        }
        if !is_admitted_effect_row(&function.effects) {
            return Err(PolyvariantR1S4Error::UnsupportedEffects {
                function: function.id,
            });
        }
        for parameter in &function.parameters {
            self.admit_type(function.id, "parameter", &parameter.ty)?;
        }
        self.admit_type(function.id, "result", &function.result)?;
        self.admit_term(function.id, &function.body)
    }

    fn admit_type(
        &mut self,
        function: FunctionId,
        context: &'static str,
        ty: &Type,
    ) -> Result<(), PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match ty {
            Type::Unit | Type::Bool | Type::I64 | Type::F64 => Ok(()),
            Type::Tuple(fields) => {
                for field in fields {
                    self.admit_type(function, context, field)?;
                }
                Ok(())
            }
            Type::Sum(sum) => {
                self.consume_work(1)?;
                for constructor in &sum.constructors {
                    self.consume_work(1)?;
                    for field in &constructor.fields {
                        self.admit_type(function, context, field)?;
                    }
                }
                Ok(())
            }
            Type::Array {
                mutability,
                element,
                ..
            } if *mutability == Mutability::Read && element.as_ref() == &Type::F64 => Ok(()),
            _ => Err(PolyvariantR1S4Error::UnsupportedType {
                function,
                context,
                ty: ty.clone(),
            }),
        }
    }

    fn admit_term(
        &mut self,
        function: FunctionId,
        term: &Term,
    ) -> Result<(), PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match term {
            Term::Let {
                ty, value, next, ..
            } => {
                self.admit_type(function, "local", ty)?;
                self.admit_rvalue(function, value)?;
                self.admit_term(function, next)
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => {
                self.admit_operand(condition)?;
                self.admit_term(function, then_term)?;
                self.admit_term(function, else_term)
            }
            Term::Case { scrutinee, arms } => {
                self.admit_operand(scrutinee)?;
                self.consume_work(arms.len() as u64)?;
                for arm in arms {
                    self.admit_term(function, &arm.body)?;
                }
                Ok(())
            }
            Term::TailCall { arguments, .. } => self.admit_operands(arguments),
            Term::Return(operand) => self.admit_operand(operand),
            Term::Region { .. } => Err(PolyvariantR1S4Error::UnsupportedNode {
                function,
                node: "Region",
            }),
            Term::Handle { .. } => Err(PolyvariantR1S4Error::UnsupportedNode {
                function,
                node: "Handle",
            }),
        }
    }

    fn admit_rvalue(
        &mut self,
        function: FunctionId,
        value: &RValue,
    ) -> Result<(), PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match value {
            RValue::Use(operand) | RValue::Project { tuple: operand, .. } => {
                self.admit_operand(operand)
            }
            RValue::Tuple(operands)
            | RValue::Construct {
                fields: operands, ..
            }
            | RValue::Call {
                arguments: operands,
                ..
            } => self.admit_operands(operands),
            RValue::Primitive {
                operation,
                arguments,
            } => {
                self.admit_operands(arguments)?;
                match operation {
                    Primitive::I64Add(NumericMode::Wrapping | NumericMode::Saturating)
                    | Primitive::I64Sub(NumericMode::Wrapping | NumericMode::Saturating)
                    | Primitive::I64Mul(NumericMode::Wrapping | NumericMode::Saturating)
                    | Primitive::F64Add
                    | Primitive::F64Sub
                    | Primitive::I64CmpLt
                    | Primitive::I64CmpGe
                    | Primitive::ArrayLenF64
                    | Primitive::ArrayGetF64 => Ok(()),
                    _ => Err(PolyvariantR1S4Error::UnsupportedPrimitive {
                        function,
                        primitive: operation.clone(),
                    }),
                }
            }
            RValue::RefAlloc { .. }
            | RValue::RefLoad { .. }
            | RValue::RefStore { .. }
            | RValue::PackClosure { .. }
            | RValue::CallClosure { .. }
            | RValue::Perform { .. } => Err(PolyvariantR1S4Error::UnsupportedNode {
                function,
                node: "effectful or higher-order rvalue",
            }),
        }
    }

    fn admit_operand(&mut self, _operand: &Operand) -> Result<(), PolyvariantR1S4Error> {
        self.consume_work(1)
    }

    fn admit_operands(&mut self, operands: &[Operand]) -> Result<(), PolyvariantR1S4Error> {
        for operand in operands {
            self.admit_operand(operand)?;
        }
        Ok(())
    }

    fn patterns_and_operands(
        &mut self,
        values: &[Partial],
    ) -> Result<(Vec<PolyvariantR1S4Pattern>, Vec<Operand>), PolyvariantR1S4Error> {
        let mut aliases = BTreeMap::<AtomId, (u32, Type, Operand)>::new();
        let mut operands = Vec::new();
        let mut patterns = Vec::with_capacity(values.len());
        for value in values {
            patterns.push(self.pattern_for(value, &mut aliases, &mut operands)?);
        }
        Ok((patterns, operands))
    }

    fn pattern_for(
        &mut self,
        value: &Partial,
        aliases: &mut BTreeMap<AtomId, (u32, Type, Operand)>,
        operands: &mut Vec<Operand>,
    ) -> Result<PolyvariantR1S4Pattern, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        Ok(match value.as_ref() {
            PartialValue::Known(value) => {
                self.consume_work(specialization_value_nodes(value)?)?;
                known_pattern(value)?
            }
            PartialValue::SharedStatic(shared) => {
                PolyvariantR1S4Pattern::SharedStatic { hash: shared.hash }
            }
            PartialValue::Hole(atom) => {
                let alias = self.alias_for(atom, aliases, operands)?;
                PolyvariantR1S4Pattern::Hole {
                    ty: atom.ty.clone(),
                    alias,
                }
            }
            PartialValue::Tuple(fields) => {
                let mut patterns = Vec::with_capacity(fields.len());
                for field in fields {
                    patterns.push(self.pattern_for(field, aliases, operands)?);
                }
                PolyvariantR1S4Pattern::Tuple(patterns)
            }
            PartialValue::KnownSum {
                sum,
                constructor,
                fields,
            } => {
                let mut patterns = Vec::with_capacity(fields.len());
                for field in fields {
                    patterns.push(self.pattern_for(field, aliases, operands)?);
                }
                PolyvariantR1S4Pattern::KnownSum {
                    sum: sum.clone(),
                    constructor: *constructor,
                    fields: patterns,
                }
            }
            PartialValue::UnknownSum { sum, atom } => {
                let alias = self.alias_for(atom, aliases, operands)?;
                PolyvariantR1S4Pattern::UnknownSum {
                    sum: sum.clone(),
                    alias,
                }
            }
        })
    }

    fn alias_for(
        &mut self,
        atom: &Atom,
        aliases: &mut BTreeMap<AtomId, (u32, Type, Operand)>,
        operands: &mut Vec<Operand>,
    ) -> Result<u32, PolyvariantR1S4Error> {
        if let Some((alias, ty, _)) = aliases.get(&atom.id) {
            if *ty != atom.ty {
                return Err(PolyvariantR1S4Error::InternalInvariant {
                    message: "one R1-S4 atom acquired two types".to_owned(),
                });
            }
            return Ok(*alias);
        }
        let alias = u32::try_from(aliases.len()).map_err(|_| {
            PolyvariantR1S4Error::DynamicParameterBudgetExceeded {
                limit: self.budget.max_dynamic_parameters,
            }
        })?;
        aliases.insert(atom.id, (alias, atom.ty.clone(), atom.operand.clone()));
        operands.push(atom.operand.clone());
        Ok(alias)
    }

    fn reserve(&mut self, key: VersionKey) -> Result<FunctionId, PolyvariantR1S4Error> {
        self.consume_work(1 + pattern_nodes(&key.patterns)?)?;
        if let Some(version) = self.reserved.get(&key) {
            return Ok(version.temporary_id);
        }
        if self.usage.variants == self.budget.max_variants {
            return Err(PolyvariantR1S4Error::VariantBudgetExceeded {
                limit: self.budget.max_variants,
            });
        }
        let aliases = collect_pattern_aliases(&key.patterns)?;
        let dynamic_parameters = aliases.len() as u64;
        let next_dynamic = self
            .usage
            .dynamic_parameters
            .checked_add(dynamic_parameters)
            .ok_or(PolyvariantR1S4Error::DynamicParameterBudgetExceeded {
                limit: self.budget.max_dynamic_parameters,
            })?;
        if next_dynamic > self.budget.max_dynamic_parameters {
            return Err(PolyvariantR1S4Error::DynamicParameterBudgetExceeded {
                limit: self.budget.max_dynamic_parameters,
            });
        }
        let temporary_id = u32::try_from(self.usage.variants)
            .map(FunctionId)
            .map_err(|_| PolyvariantR1S4Error::FunctionIdExhausted)?;
        self.usage.variants += 1;
        self.usage.dynamic_parameters = next_dynamic;
        self.reserved.insert(
            key.clone(),
            ReservedVersion {
                temporary_id,
                built: false,
            },
        );
        self.worklist.push_back(key);
        Ok(temporary_id)
    }

    fn build_version(&mut self, key: VersionKey) -> Result<(), PolyvariantR1S4Error> {
        self.consume_work(1)?;
        let reserved = self
            .reserved
            .get(&key)
            .cloned()
            .ok_or(PolyvariantR1S4Error::UnresolvedVariant)?;
        if reserved.built {
            return Ok(());
        }
        let source = self
            .functions
            .get(&key.source_function)
            .cloned()
            .ok_or(PolyvariantR1S4Error::MissingFunction(key.source_function))?;
        if source.parameters.len() != key.patterns.len() {
            return Err(PolyvariantR1S4Error::ArityMismatch {
                function: source.id,
                expected: source.parameters.len(),
                actual: key.patterns.len(),
            });
        }

        self.consume_work(pattern_nodes(&key.patterns)?)?;
        let aliases = collect_pattern_aliases(&key.patterns)?;
        let mut fresh = FreshLocals::for_function(&source);
        self.consume_work(term_node_count(&source.body)?)?;
        let mut alias_atoms = BTreeMap::new();
        let mut residual_parameters = Vec::with_capacity(aliases.len());
        for (expected_alias, (alias, ty)) in aliases.into_iter().enumerate() {
            if alias as usize != expected_alias {
                return Err(PolyvariantR1S4Error::InternalInvariant {
                    message: "R1-S4 pattern aliases are not contiguous".to_owned(),
                });
            }
            let local = fresh.allocate()?;
            let atom = Atom {
                id: self.allocate_atom()?,
                ty: ty.clone(),
                operand: Operand::Local(local),
            };
            alias_atoms.insert(alias, atom);
            residual_parameters.push(Parameter { local, ty });
        }

        let mut environment = BTreeMap::new();
        for ((parameter, pattern), expected_type) in source
            .parameters
            .iter()
            .zip(&key.patterns)
            .zip(source.parameters.iter().map(|parameter| &parameter.ty))
        {
            let value = self.partial_from_pattern(pattern, &alias_atoms)?;
            if partial_type(&value)? != *expected_type {
                return Err(PolyvariantR1S4Error::InternalInvariant {
                    message: format!(
                        "R1-S4 pattern type does not match source parameter {}",
                        parameter.local.0
                    ),
                });
            }
            environment.insert(parameter.local, value);
        }
        let body = self.specialize_term(source.id, &source.body, &environment, &mut fresh)?;
        let function = Function {
            id: reserved.temporary_id,
            region_parameters: source.region_parameters,
            parameters: residual_parameters,
            effects: source.effects,
            result: source.result,
            body,
        };
        self.built.push(BuiltVersion {
            key: key.clone(),
            temporary_id: reserved.temporary_id,
            function,
        });
        self.reserved
            .get_mut(&key)
            .ok_or(PolyvariantR1S4Error::UnresolvedVariant)?
            .built = true;
        Ok(())
    }

    fn partial_from_pattern(
        &mut self,
        pattern: &PolyvariantR1S4Pattern,
        aliases: &BTreeMap<u32, Atom>,
    ) -> Result<Partial, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match pattern {
            PolyvariantR1S4Pattern::KnownUnit => self.make_known(SpecializationValue::Unit),
            PolyvariantR1S4Pattern::KnownBool(value) => {
                self.make_known(SpecializationValue::Bool(*value))
            }
            PolyvariantR1S4Pattern::KnownI64(value) => {
                self.make_known(SpecializationValue::I64(*value))
            }
            PolyvariantR1S4Pattern::KnownF64(bits) => {
                self.make_known(SpecializationValue::F64(f64::from_bits(*bits)))
            }
            PolyvariantR1S4Pattern::KnownTuple(fields) => {
                let mut values = Vec::with_capacity(fields.len());
                for field in fields {
                    let partial = self.partial_from_pattern(field, aliases)?;
                    let Some(value) = static_value(&partial) else {
                        return Err(PolyvariantR1S4Error::InternalInvariant {
                            message: "KnownTuple pattern contains a dynamic field".to_owned(),
                        });
                    };
                    values.push(value);
                }
                self.make_known(SpecializationValue::Tuple(values))
            }
            PolyvariantR1S4Pattern::Hole { ty, alias } => {
                let atom = aliases.get(alias).cloned().ok_or_else(|| {
                    PolyvariantR1S4Error::InternalInvariant {
                        message: format!("R1-S4 pattern references missing alias {alias}"),
                    }
                })?;
                if atom.ty != *ty || matches!(ty, Type::Sum(_)) {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 Hole pattern has an invalid alias type".to_owned(),
                    });
                }
                self.make_dynamic(ty.clone(), atom.id, atom.operand)
            }
            PolyvariantR1S4Pattern::Tuple(fields) => {
                let mut partials = Vec::with_capacity(fields.len());
                for field in fields {
                    partials.push(self.partial_from_pattern(field, aliases)?);
                }
                self.consume_work(partials.len() as u64)?;
                self.consume_partial_nodes(1)?;
                Ok(Arc::new(PartialValue::Tuple(partials)))
            }
            PolyvariantR1S4Pattern::KnownSum {
                sum,
                constructor,
                fields,
            } => {
                let expected = sum.constructors.get(*constructor as usize).ok_or_else(|| {
                    PolyvariantR1S4Error::InternalInvariant {
                        message: "KnownSum pattern constructor is absent".to_owned(),
                    }
                })?;
                let mut partials = Vec::with_capacity(fields.len());
                for field in fields {
                    partials.push(self.partial_from_pattern(field, aliases)?);
                }
                if expected.fields.len() != partials.len() {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "KnownSum pattern arity changed".to_owned(),
                    });
                }
                self.consume_work(partials.len() as u64)?;
                self.consume_partial_nodes(1)?;
                Ok(Arc::new(PartialValue::KnownSum {
                    sum: sum.clone(),
                    constructor: *constructor,
                    fields: partials,
                }))
            }
            PolyvariantR1S4Pattern::UnknownSum { sum, alias } => {
                let atom = aliases.get(alias).cloned().ok_or_else(|| {
                    PolyvariantR1S4Error::InternalInvariant {
                        message: format!("R1-S4 pattern references missing alias {alias}"),
                    }
                })?;
                if atom.ty != Type::Sum(sum.clone()) {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 UnknownSum alias type changed".to_owned(),
                    });
                }
                self.make_dynamic(atom.ty.clone(), atom.id, atom.operand)
            }
            PolyvariantR1S4Pattern::SharedStatic { hash } => {
                self.static_values.get(hash).cloned().ok_or_else(|| {
                    PolyvariantR1S4Error::InternalInvariant {
                        message: format!(
                            "R1-S4 pattern references missing shared static {}",
                            hash.to_hex()
                        ),
                    }
                })
            }
        }
    }

    fn specialize_term(
        &mut self,
        function: FunctionId,
        term: &Term,
        environment: &BTreeMap<LocalId, Partial>,
        fresh: &mut FreshLocals,
    ) -> Result<Term, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match term {
            Term::Let {
                binder,
                ty,
                value,
                next,
            } => {
                let specialized =
                    self.specialize_rvalue(function, *binder, ty, value, environment)?;
                let mut next_environment = environment.clone();
                match specialized {
                    SpecializedRValue::Elided(value) => {
                        next_environment.insert(*binder, value);
                        self.specialize_term(function, next, &next_environment, fresh)
                    }
                    SpecializedRValue::Residual { rvalue, result } => {
                        next_environment.insert(*binder, result);
                        let next =
                            self.specialize_term(function, next, &next_environment, fresh)?;
                        Ok(Term::Let {
                            binder: *binder,
                            ty: ty.clone(),
                            value: rvalue,
                            next: Box::new(next),
                        })
                    }
                }
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => {
                let condition = self.resolve_operand(function, condition, environment)?;
                match condition.as_ref() {
                    PartialValue::Known(value) => match value.as_ref() {
                        SpecializationValue::Bool(true) => {
                            self.specialize_term(function, then_term, environment, fresh)
                        }
                        SpecializationValue::Bool(false) => {
                            self.specialize_term(function, else_term, environment, fresh)
                        }
                        _ => Err(PolyvariantR1S4Error::ExpectedBool { function }),
                    },
                    PartialValue::Hole(atom) if atom.ty == Type::Bool => {
                        self.consume_control(1)?;
                        let then_term =
                            self.specialize_term(function, then_term, environment, fresh)?;
                        let else_term =
                            self.specialize_term(function, else_term, environment, fresh)?;
                        Ok(Term::If {
                            condition: atom.operand.clone(),
                            then_term: Box::new(then_term),
                            else_term: Box::new(else_term),
                        })
                    }
                    _ => Err(PolyvariantR1S4Error::ExpectedBool { function }),
                }
            }
            Term::Case { scrutinee, arms } => {
                let scrutinee = self.resolve_operand(function, scrutinee, environment)?;
                self.specialize_case(function, &scrutinee, arms, environment, fresh)
            }
            Term::TailCall {
                function: callee,
                arguments,
            } => {
                let arguments = self.resolve_operands(function, arguments, environment)?;
                let (target, arguments) = self.reserve_call(*callee, &arguments)?;
                Ok(Term::TailCall {
                    function: target,
                    arguments,
                })
            }
            Term::Return(operand) => {
                let value = self.resolve_operand(function, operand, environment)?;
                let mut bindings = Vec::new();
                let operand =
                    self.materialize(&value, &partial_type(&value)?, fresh, &mut bindings)?;
                Ok(wrap_bindings(bindings, Term::Return(operand)))
            }
            Term::Region { .. } => Err(PolyvariantR1S4Error::UnsupportedNode {
                function,
                node: "Region",
            }),
            Term::Handle { .. } => Err(PolyvariantR1S4Error::UnsupportedNode {
                function,
                node: "Handle",
            }),
        }
    }

    fn specialize_case(
        &mut self,
        function: FunctionId,
        scrutinee: &Partial,
        arms: &[CaseArm],
        environment: &BTreeMap<LocalId, Partial>,
        fresh: &mut FreshLocals,
    ) -> Result<Term, PolyvariantR1S4Error> {
        if let Some((sum, constructor, fields)) = self.known_sum_parts(scrutinee)? {
            let arm = arms
                .get(constructor as usize)
                .ok_or(PolyvariantR1S4Error::ExpectedSum { function })?;
            let constructor_type = sum
                .constructors
                .get(constructor as usize)
                .ok_or(PolyvariantR1S4Error::ExpectedSum { function })?;
            if arm.bindings.len() != fields.len() || constructor_type.fields.len() != fields.len() {
                return Err(PolyvariantR1S4Error::ExpectedSum { function });
            }
            let mut arm_environment = environment.clone();
            for (binding, field) in arm.bindings.iter().zip(fields) {
                arm_environment.insert(*binding, field);
            }
            return self.specialize_term(function, &arm.body, &arm_environment, fresh);
        }

        let PartialValue::UnknownSum { sum, atom } = scrutinee.as_ref() else {
            return Err(PolyvariantR1S4Error::ExpectedSum { function });
        };
        let splits = u64::try_from(arms.len().saturating_sub(1)).map_err(|_| {
            PolyvariantR1S4Error::ControlBudgetExceeded {
                limit: self.budget.max_control_splits,
            }
        })?;
        self.consume_control(splits)?;
        let mut residual_arms = Vec::with_capacity(arms.len());
        for arm in arms {
            self.consume_work(1)?;
            let constructor = sum
                .constructors
                .get(arm.constructor as usize)
                .ok_or(PolyvariantR1S4Error::ExpectedSum { function })?;
            if constructor.fields.len() != arm.bindings.len() {
                return Err(PolyvariantR1S4Error::ExpectedSum { function });
            }
            let mut arm_environment = environment.clone();
            for (index, (binding, ty)) in arm.bindings.iter().zip(&constructor.fields).enumerate() {
                let field =
                    u32::try_from(index).map_err(|_| PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 Case field index exceeds U32".to_owned(),
                    })?;
                let id = self.derived_atom(
                    atom.id,
                    AtomDerivation::SumField {
                        constructor: arm.constructor,
                        field,
                    },
                )?;
                let value = self.make_dynamic(ty.clone(), id, Operand::Local(*binding))?;
                arm_environment.insert(*binding, value);
            }
            let body = self.specialize_term(function, &arm.body, &arm_environment, fresh)?;
            residual_arms.push(CaseArm {
                constructor: arm.constructor,
                bindings: arm.bindings.clone(),
                body,
            });
        }
        Ok(Term::Case {
            scrutinee: atom.operand.clone(),
            arms: residual_arms,
        })
    }

    fn known_sum_parts(
        &mut self,
        value: &Partial,
    ) -> Result<Option<(SumType, u32, Vec<Partial>)>, PolyvariantR1S4Error> {
        match value.as_ref() {
            PartialValue::Known(value) => {
                let SpecializationValue::Sum {
                    ty,
                    constructor,
                    fields,
                } = value.as_ref()
                else {
                    return Ok(None);
                };
                let mut partials = Vec::with_capacity(fields.len());
                for field in fields {
                    partials.push(self.make_known(field.clone())?);
                }
                Ok(Some((ty.clone(), *constructor, partials)))
            }
            PartialValue::SharedStatic(shared) => match &shared.shape {
                SharedStaticShape::Sum {
                    sum,
                    constructor,
                    fields,
                } => Ok(Some((sum.clone(), *constructor, fields.clone()))),
                SharedStaticShape::Tuple(_) => Ok(None),
            },
            PartialValue::KnownSum {
                sum,
                constructor,
                fields,
            } => Ok(Some((sum.clone(), *constructor, fields.clone()))),
            _ => Ok(None),
        }
    }

    fn specialize_rvalue(
        &mut self,
        function: FunctionId,
        binder: LocalId,
        ty: &Type,
        value: &RValue,
        environment: &BTreeMap<LocalId, Partial>,
    ) -> Result<SpecializedRValue, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match value {
            RValue::Use(operand) => Ok(SpecializedRValue::Elided(self.resolve_operand(
                function,
                operand,
                environment,
            )?)),
            RValue::Tuple(fields) => {
                let fields = self.resolve_operands(function, fields, environment)?;
                Ok(SpecializedRValue::Elided(self.make_tuple(fields)?))
            }
            RValue::Project { tuple, index } => {
                let tuple = self.resolve_operand(function, tuple, environment)?;
                match tuple.as_ref() {
                    PartialValue::Known(value) => {
                        let SpecializationValue::Tuple(fields) = value.as_ref() else {
                            return Err(PolyvariantR1S4Error::ExpectedTuple { function });
                        };
                        let field = fields
                            .get(*index as usize)
                            .ok_or(PolyvariantR1S4Error::ExpectedTuple { function })?;
                        Ok(SpecializedRValue::Elided(self.make_known(field.clone())?))
                    }
                    PartialValue::SharedStatic(shared) => {
                        let SharedStaticShape::Tuple(fields) = &shared.shape else {
                            return Err(PolyvariantR1S4Error::ExpectedTuple { function });
                        };
                        let field = fields
                            .get(*index as usize)
                            .cloned()
                            .ok_or(PolyvariantR1S4Error::ExpectedTuple { function })?;
                        Ok(SpecializedRValue::Elided(field))
                    }
                    PartialValue::Tuple(fields) => {
                        let field = fields
                            .get(*index as usize)
                            .cloned()
                            .ok_or(PolyvariantR1S4Error::ExpectedTuple { function })?;
                        Ok(SpecializedRValue::Elided(field))
                    }
                    PartialValue::Hole(atom) if matches!(atom.ty, Type::Tuple(_)) => {
                        let id = self.derived_atom(atom.id, AtomDerivation::TupleField(*index))?;
                        let result = self.make_dynamic(ty.clone(), id, Operand::Local(binder))?;
                        Ok(SpecializedRValue::Residual {
                            rvalue: RValue::Project {
                                tuple: atom.operand.clone(),
                                index: *index,
                            },
                            result,
                        })
                    }
                    _ => Err(PolyvariantR1S4Error::ExpectedTuple { function }),
                }
            }
            RValue::Construct {
                sum,
                constructor,
                fields,
            } => {
                let fields = self.resolve_operands(function, fields, environment)?;
                Ok(SpecializedRValue::Elided(self.make_known_sum(
                    sum.clone(),
                    *constructor,
                    fields,
                )?))
            }
            RValue::Primitive {
                operation,
                arguments,
            } => {
                let arguments = self.resolve_operands(function, arguments, environment)?;
                match operation {
                    Primitive::ArrayLenF64 => {
                        let [array] = arguments.as_slice() else {
                            return Err(PolyvariantR1S4Error::InternalInvariant {
                                message: "verified ArrayLenF64 arity changed".to_owned(),
                            });
                        };
                        let residual_arguments = vec![array_operand(array)?];
                        let atom = self.allocate_atom()?;
                        let result = self.make_dynamic(ty.clone(), atom, Operand::Local(binder))?;
                        Ok(SpecializedRValue::Residual {
                            rvalue: RValue::Primitive {
                                operation: operation.clone(),
                                arguments: residual_arguments,
                            },
                            result,
                        })
                    }
                    Primitive::ArrayGetF64 => {
                        let [array, index] = arguments.as_slice() else {
                            return Err(PolyvariantR1S4Error::InternalInvariant {
                                message: "verified ArrayGetF64 arity changed".to_owned(),
                            });
                        };
                        let residual_arguments =
                            vec![array_operand(array)?, scalar_operand(index)?];
                        let atom = self.allocate_atom()?;
                        let result = self.make_dynamic(ty.clone(), atom, Operand::Local(binder))?;
                        Ok(SpecializedRValue::Residual {
                            rvalue: RValue::Primitive {
                                operation: operation.clone(),
                                arguments: residual_arguments,
                            },
                            result,
                        })
                    }
                    _ => {
                        if let Some(values) = all_static(&arguments) {
                            return Ok(SpecializedRValue::Elided(
                                self.make_known(evaluate_primitive(operation, &values)?)?,
                            ));
                        }
                        let mut residual_arguments = Vec::with_capacity(arguments.len());
                        for argument in &arguments {
                            residual_arguments.push(scalar_operand(argument)?);
                        }
                        let atom = self.allocate_atom()?;
                        let result = self.make_dynamic(ty.clone(), atom, Operand::Local(binder))?;
                        Ok(SpecializedRValue::Residual {
                            rvalue: RValue::Primitive {
                                operation: operation.clone(),
                                arguments: residual_arguments,
                            },
                            result,
                        })
                    }
                }
            }
            RValue::Call {
                function: callee,
                arguments,
            } => {
                let arguments = self.resolve_operands(function, arguments, environment)?;
                if let Some(result) = self.try_unfold_helper(*callee, &arguments)? {
                    return Ok(SpecializedRValue::Elided(result));
                }
                let (target, arguments) = self.reserve_call(*callee, &arguments)?;
                let atom = self.allocate_atom()?;
                let result = self.make_dynamic(ty.clone(), atom, Operand::Local(binder))?;
                Ok(SpecializedRValue::Residual {
                    rvalue: RValue::Call {
                        function: target,
                        arguments,
                    },
                    result,
                })
            }
            RValue::RefAlloc { .. }
            | RValue::RefLoad { .. }
            | RValue::RefStore { .. }
            | RValue::PackClosure { .. }
            | RValue::CallClosure { .. }
            | RValue::Perform { .. } => Err(PolyvariantR1S4Error::UnsupportedNode {
                function,
                node: "effectful or higher-order rvalue",
            }),
        }
    }

    fn resolve_operand(
        &mut self,
        function: FunctionId,
        operand: &Operand,
        environment: &BTreeMap<LocalId, Partial>,
    ) -> Result<Partial, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match operand {
            Operand::Unit => self.make_known(SpecializationValue::Unit),
            Operand::Bool(value) => self.make_known(SpecializationValue::Bool(*value)),
            Operand::I64(value) => self.make_known(SpecializationValue::I64(*value)),
            Operand::F64(value) => self.make_known(SpecializationValue::F64(f64::from_bits(
                canonical_f64_bits(*value),
            ))),
            Operand::Local(local) => {
                environment
                    .get(local)
                    .cloned()
                    .ok_or(PolyvariantR1S4Error::MissingLocal {
                        function,
                        local: *local,
                    })
            }
        }
    }

    fn resolve_operands(
        &mut self,
        function: FunctionId,
        operands: &[Operand],
        environment: &BTreeMap<LocalId, Partial>,
    ) -> Result<Vec<Partial>, PolyvariantR1S4Error> {
        operands
            .iter()
            .map(|operand| self.resolve_operand(function, operand, environment))
            .collect()
    }

    fn reserve_call(
        &mut self,
        function: FunctionId,
        arguments: &[Partial],
    ) -> Result<(FunctionId, Vec<Operand>), PolyvariantR1S4Error> {
        let callee = self
            .functions
            .get(&function)
            .ok_or(PolyvariantR1S4Error::MissingFunction(function))?;
        if callee.parameters.len() != arguments.len() {
            return Err(PolyvariantR1S4Error::ArityMismatch {
                function,
                expected: callee.parameters.len(),
                actual: arguments.len(),
            });
        }
        let arguments = self.widen_recursive_arguments(function, arguments)?;
        let (patterns, operands) = self.patterns_and_operands(&arguments)?;
        let target = self.reserve(VersionKey {
            source_function: function,
            patterns,
        })?;
        Ok((target, operands))
    }

    fn try_unfold_helper(
        &mut self,
        function: FunctionId,
        arguments: &[Partial],
    ) -> Result<Option<Partial>, PolyvariantR1S4Error> {
        let (key, aliases) = self.summary_context(function, arguments)?;
        if let Some(SummaryEntry::Result(template)) = self.summaries.get(&key).cloned() {
            self.consume_work(1 + pattern_node_count(&template)?)?;
            self.usage.summary_hits = self.usage.summary_hits.checked_add(1).ok_or(
                PolyvariantR1S4Error::WorkBudgetExceeded {
                    limit: self.budget.max_work_units,
                },
            )?;
            return self.partial_from_pattern(&template, &aliases).map(Some);
        }

        let result = self.unfold_helper_once(function, arguments)?;
        if let Some(result) = &result {
            if let Some(template) = self.summary_template(result, &aliases)? {
                if self.summaries.len() as u64 == self.budget.max_helper_unfolds {
                    return Err(PolyvariantR1S4Error::HelperBudgetExceeded {
                        limit: self.budget.max_helper_unfolds,
                    });
                }
                self.consume_work(1 + pattern_node_count(&template)?)?;
                self.summaries.insert(key, SummaryEntry::Result(template));
                self.usage.summary_entries = self.usage.summary_entries.checked_add(1).ok_or(
                    PolyvariantR1S4Error::HelperBudgetExceeded {
                        limit: self.budget.max_helper_unfolds,
                    },
                )?;
            }
        }
        Ok(result)
    }

    fn summary_context(
        &mut self,
        function: FunctionId,
        arguments: &[Partial],
    ) -> Result<(SummaryKey, BTreeMap<u32, Atom>), PolyvariantR1S4Error> {
        let mut raw_aliases = BTreeMap::<AtomId, (u32, Type, Operand)>::new();
        let mut ignored_operands = Vec::new();
        let mut patterns = Vec::with_capacity(arguments.len());
        for argument in arguments {
            patterns.push(self.pattern_for(argument, &mut raw_aliases, &mut ignored_operands)?);
        }
        let aliases = raw_aliases
            .into_iter()
            .map(|(id, (alias, ty, operand))| (alias, Atom { id, ty, operand }))
            .collect();
        Ok((SummaryKey { function, patterns }, aliases))
    }

    fn summary_template(
        &mut self,
        result: &Partial,
        aliases: &BTreeMap<u32, Atom>,
    ) -> Result<Option<PolyvariantR1S4Pattern>, PolyvariantR1S4Error> {
        let mut raw_aliases = aliases
            .iter()
            .map(|(alias, atom)| (atom.id, (*alias, atom.ty.clone(), atom.operand.clone())))
            .collect::<BTreeMap<_, _>>();
        let expected_aliases = raw_aliases.len();
        let mut ignored_operands = Vec::new();
        let template = self.pattern_for(result, &mut raw_aliases, &mut ignored_operands)?;
        if raw_aliases.len() != expected_aliases {
            return Ok(None);
        }
        Ok(Some(template))
    }

    fn unfold_helper_once(
        &mut self,
        function: FunctionId,
        arguments: &[Partial],
    ) -> Result<Option<Partial>, PolyvariantR1S4Error> {
        let mut frames = Vec::new();
        let mut active = BTreeSet::new();
        let Some(entry) =
            self.make_helper_frame(function, arguments, None, &mut active, frames.len())?
        else {
            return Ok(None);
        };
        frames.push(entry);

        loop {
            self.consume_work(1)?;
            let cursor = frames
                .last()
                .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                    message: "R1-S4 helper machine lost its entry frame".to_owned(),
                })?
                .cursor
                .clone();
            match cursor {
                Term::Let {
                    binder,
                    value,
                    next,
                    ..
                } => {
                    let current_function = frames
                        .last()
                        .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                            message: "R1-S4 helper machine lost its current frame".to_owned(),
                        })?
                        .function;
                    let environment = frames
                        .last()
                        .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                            message: "R1-S4 helper machine lost its environment".to_owned(),
                        })?
                        .environment
                        .clone();
                    if let RValue::Call {
                        function: callee,
                        arguments,
                    } = value
                    {
                        let arguments =
                            self.resolve_operands(current_function, &arguments, &environment)?;
                        let Some(frame) = self.make_helper_frame(
                            callee,
                            &arguments,
                            Some(binder),
                            &mut active,
                            frames.len(),
                        )?
                        else {
                            return Ok(None);
                        };
                        frames
                            .last_mut()
                            .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                                message: "R1-S4 helper machine lost its caller frame".to_owned(),
                            })?
                            .cursor = *next;
                        frames.push(frame);
                        continue;
                    }

                    let Some(value) =
                        self.summarize_helper_local_rvalue(current_function, &value, &environment)?
                    else {
                        return Ok(None);
                    };
                    let frame = frames.last_mut().ok_or_else(|| {
                        PolyvariantR1S4Error::InternalInvariant {
                            message: "R1-S4 helper machine lost its binding frame".to_owned(),
                        }
                    })?;
                    frame.environment.insert(binder, value);
                    frame.cursor = *next;
                }
                Term::Return(operand) => {
                    let frame =
                        frames
                            .last()
                            .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                                message: "R1-S4 helper machine lost its return frame".to_owned(),
                            })?;
                    let result =
                        self.resolve_operand(frame.function, &operand, &frame.environment)?;
                    let completed =
                        frames
                            .pop()
                            .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                                message: "R1-S4 helper machine could not pop its return frame"
                                    .to_owned(),
                            })?;
                    active.remove(&completed.function);
                    if let Some(binder) = completed.return_to {
                        let caller = frames.last_mut().ok_or_else(|| {
                            PolyvariantR1S4Error::InternalInvariant {
                                message: "R1-S4 helper return has no caller frame".to_owned(),
                            }
                        })?;
                        caller.environment.insert(binder, result);
                    } else {
                        if !frames.is_empty() {
                            return Err(PolyvariantR1S4Error::InternalInvariant {
                                message: "R1-S4 helper entry returned with live frames".to_owned(),
                            });
                        }
                        return Ok(Some(result));
                    }
                }
                Term::If {
                    condition,
                    then_term,
                    else_term,
                } => {
                    let frame =
                        frames
                            .last()
                            .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                                message: "R1-S4 helper machine lost its If frame".to_owned(),
                            })?;
                    let condition =
                        self.resolve_operand(frame.function, &condition, &frame.environment)?;
                    let selected = match condition.as_ref() {
                        PartialValue::Known(value) => match value.as_ref() {
                            SpecializationValue::Bool(true) => *then_term,
                            SpecializationValue::Bool(false) => *else_term,
                            _ => return Ok(None),
                        },
                        _ => return Ok(None),
                    };
                    frames
                        .last_mut()
                        .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                            message: "R1-S4 helper machine lost its selected If frame".to_owned(),
                        })?
                        .cursor = selected;
                }
                Term::Case { scrutinee, arms } => {
                    let frame =
                        frames
                            .last()
                            .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                                message: "R1-S4 helper machine lost its Case frame".to_owned(),
                            })?;
                    let scrutinee =
                        self.resolve_operand(frame.function, &scrutinee, &frame.environment)?;
                    let Some((sum, constructor, fields)) = self.known_sum_parts(&scrutinee)? else {
                        return Ok(None);
                    };
                    let Some(arm) = arms.into_iter().find(|arm| arm.constructor == constructor)
                    else {
                        return Ok(None);
                    };
                    let Some(constructor_type) = sum.constructors.get(constructor as usize) else {
                        return Ok(None);
                    };
                    if arm.bindings.len() != fields.len()
                        || constructor_type.fields.len() != fields.len()
                    {
                        return Ok(None);
                    }
                    let frame = frames.last_mut().ok_or_else(|| {
                        PolyvariantR1S4Error::InternalInvariant {
                            message: "R1-S4 helper machine lost its selected Case frame".to_owned(),
                        }
                    })?;
                    for (binding, field) in arm.bindings.iter().zip(fields) {
                        frame.environment.insert(*binding, field);
                    }
                    frame.cursor = arm.body;
                }
                Term::TailCall { .. } | Term::Region { .. } | Term::Handle { .. } => {
                    return Ok(None);
                }
            }
        }
    }

    fn make_helper_frame(
        &mut self,
        function: FunctionId,
        arguments: &[Partial],
        return_to: Option<LocalId>,
        active: &mut BTreeSet<FunctionId>,
        depth: usize,
    ) -> Result<Option<HelperFrame>, PolyvariantR1S4Error> {
        if self.recursive_functions.contains(&function)
            || depth == R1_S4_MAX_HELPER_DEPTH
            || active.contains(&function)
        {
            return Ok(None);
        }
        let helper = self
            .functions
            .get(&function)
            .cloned()
            .ok_or(PolyvariantR1S4Error::MissingFunction(function))?;
        if helper.parameters.len() != arguments.len() {
            return Err(PolyvariantR1S4Error::ArityMismatch {
                function,
                expected: helper.parameters.len(),
                actual: arguments.len(),
            });
        }
        if !helper.effects.effects.is_empty() {
            return Ok(None);
        }
        if !self.is_bounded_helper_metered(&helper.body)? {
            return Ok(None);
        }
        self.consume_helper()?;
        active.insert(function);
        Ok(Some(HelperFrame {
            function,
            environment: helper
                .parameters
                .iter()
                .zip(arguments)
                .map(|(parameter, argument)| (parameter.local, argument.clone()))
                .collect(),
            cursor: helper.body,
            return_to,
        }))
    }

    fn summarize_helper_local_rvalue(
        &mut self,
        function: FunctionId,
        value: &RValue,
        environment: &BTreeMap<LocalId, Partial>,
    ) -> Result<Option<Partial>, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match value {
            RValue::Use(operand) => self
                .resolve_operand(function, operand, environment)
                .map(Some),
            RValue::Tuple(fields) => {
                let fields = self.resolve_operands(function, fields, environment)?;
                self.make_tuple(fields).map(Some)
            }
            RValue::Project { tuple, index } => {
                let tuple = self.resolve_operand(function, tuple, environment)?;
                match tuple.as_ref() {
                    PartialValue::Known(value) => {
                        let SpecializationValue::Tuple(fields) = value.as_ref() else {
                            return Ok(None);
                        };
                        let Some(field) = fields.get(*index as usize) else {
                            return Ok(None);
                        };
                        self.make_known(field.clone()).map(Some)
                    }
                    PartialValue::SharedStatic(shared) => {
                        let SharedStaticShape::Tuple(fields) = &shared.shape else {
                            return Ok(None);
                        };
                        Ok(fields.get(*index as usize).cloned())
                    }
                    PartialValue::Tuple(fields) => Ok(fields.get(*index as usize).cloned()),
                    PartialValue::Hole(_)
                    | PartialValue::KnownSum { .. }
                    | PartialValue::UnknownSum { .. } => Ok(None),
                }
            }
            RValue::Construct {
                sum,
                constructor,
                fields,
            } => {
                let fields = self.resolve_operands(function, fields, environment)?;
                self.make_known_sum(sum.clone(), *constructor, fields)
                    .map(Some)
            }
            RValue::Primitive {
                operation,
                arguments,
            } => {
                let arguments = self.resolve_operands(function, arguments, environment)?;
                let Some(values) = all_static(&arguments) else {
                    return Ok(None);
                };
                self.make_known(evaluate_primitive(operation, &values)?)
                    .map(Some)
            }
            RValue::Call { .. } => Ok(None),
            RValue::RefAlloc { .. }
            | RValue::RefLoad { .. }
            | RValue::RefStore { .. }
            | RValue::PackClosure { .. }
            | RValue::CallClosure { .. }
            | RValue::Perform { .. } => Ok(None),
        }
    }

    fn is_bounded_helper_metered(&mut self, term: &Term) -> Result<bool, PolyvariantR1S4Error> {
        self.consume_work(term_node_count(term)?)?;
        Ok(is_bounded_helper(term))
    }

    fn materialize(
        &mut self,
        value: &Partial,
        expected: &Type,
        fresh: &mut FreshLocals,
        bindings: &mut Vec<MaterializedBinding>,
    ) -> Result<Operand, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match value.as_ref() {
            PartialValue::Known(value) => self.materialize_known(value, expected, fresh, bindings),
            PartialValue::SharedStatic(shared) => {
                self.materialize_known(&shared.value, expected, fresh, bindings)
            }
            PartialValue::Hole(atom) => {
                if atom.ty != *expected {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 Hole materialization type mismatch".to_owned(),
                    });
                }
                Ok(atom.operand.clone())
            }
            PartialValue::Tuple(fields) => {
                let Type::Tuple(types) = expected else {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 Tuple materialized at non-Tuple type".to_owned(),
                    });
                };
                if fields.len() != types.len() {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 Tuple materialization arity mismatch".to_owned(),
                    });
                }
                let mut operands = Vec::with_capacity(fields.len());
                for (field, ty) in fields.iter().zip(types) {
                    operands.push(self.materialize(field, ty, fresh, bindings)?);
                }
                let binder = fresh.allocate()?;
                bindings.push(MaterializedBinding {
                    binder,
                    ty: expected.clone(),
                    value: RValue::Tuple(operands),
                });
                Ok(Operand::Local(binder))
            }
            PartialValue::KnownSum {
                sum,
                constructor,
                fields,
            } => {
                if *expected != Type::Sum(sum.clone()) {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 KnownSum materialization type mismatch".to_owned(),
                    });
                }
                let constructor_type =
                    sum.constructors.get(*constructor as usize).ok_or_else(|| {
                        PolyvariantR1S4Error::InternalInvariant {
                            message: "R1-S4 KnownSum constructor is absent".to_owned(),
                        }
                    })?;
                if fields.len() != constructor_type.fields.len() {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 KnownSum materialization arity mismatch".to_owned(),
                    });
                }
                let mut operands = Vec::with_capacity(fields.len());
                for (field, ty) in fields.iter().zip(&constructor_type.fields) {
                    operands.push(self.materialize(field, ty, fresh, bindings)?);
                }
                let binder = fresh.allocate()?;
                bindings.push(MaterializedBinding {
                    binder,
                    ty: expected.clone(),
                    value: RValue::Construct {
                        sum: sum.clone(),
                        constructor: *constructor,
                        fields: operands,
                    },
                });
                Ok(Operand::Local(binder))
            }
            PartialValue::UnknownSum { sum, atom } => {
                if *expected != Type::Sum(sum.clone()) || atom.ty != *expected {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 UnknownSum materialization type mismatch".to_owned(),
                    });
                }
                Ok(atom.operand.clone())
            }
        }
    }

    fn materialize_known(
        &mut self,
        value: &SpecializationValue,
        expected: &Type,
        fresh: &mut FreshLocals,
        bindings: &mut Vec<MaterializedBinding>,
    ) -> Result<Operand, PolyvariantR1S4Error> {
        self.consume_work(1)?;
        if let Some(literal) = literal_from_value(value) {
            if specialization_value_matches_type(value, expected) {
                return Ok(literal);
            }
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 known scalar materialization type mismatch".to_owned(),
            });
        }
        match (value, expected) {
            (SpecializationValue::Tuple(values), Type::Tuple(types))
                if values.len() == types.len() =>
            {
                let mut operands = Vec::with_capacity(values.len());
                for (value, ty) in values.iter().zip(types) {
                    operands.push(self.materialize_known(value, ty, fresh, bindings)?);
                }
                let binder = fresh.allocate()?;
                bindings.push(MaterializedBinding {
                    binder,
                    ty: expected.clone(),
                    value: RValue::Tuple(operands),
                });
                Ok(Operand::Local(binder))
            }
            (
                SpecializationValue::Sum {
                    ty,
                    constructor,
                    fields,
                },
                Type::Sum(expected_sum),
            ) if ty == expected_sum => {
                let constructor_type = expected_sum
                    .constructors
                    .get(*constructor as usize)
                    .ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 known Sum constructor is absent".to_owned(),
                    })?;
                if fields.len() != constructor_type.fields.len() {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 known Sum materialization arity mismatch".to_owned(),
                    });
                }
                let mut operands = Vec::with_capacity(fields.len());
                for (field, ty) in fields.iter().zip(&constructor_type.fields) {
                    operands.push(self.materialize_known(field, ty, fresh, bindings)?);
                }
                let binder = fresh.allocate()?;
                bindings.push(MaterializedBinding {
                    binder,
                    ty: expected.clone(),
                    value: RValue::Construct {
                        sum: expected_sum.clone(),
                        constructor: *constructor,
                        fields: operands,
                    },
                });
                Ok(Operand::Local(binder))
            }
            _ => Err(PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 cannot materialize the known value at its result type".to_owned(),
            }),
        }
    }

    fn evidence_table_hashes(
        &mut self,
    ) -> Result<(SemanticHash, SemanticHash), PolyvariantR1S4Error> {
        let statics = self
            .static_values
            .iter()
            .map(|(hash, value)| {
                let PartialValue::SharedStatic(shared) = value.as_ref() else {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 static table contains a non-shared value".to_owned(),
                    });
                };
                if shared.hash != *hash {
                    return Err(PolyvariantR1S4Error::InternalInvariant {
                        message: "R1-S4 static table key disagrees with its value".to_owned(),
                    });
                }
                Ok((*hash, shared.canonical.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.consume_work(statics.len() as u64)?;
        let mut static_bytes = STATIC_TABLE_DOMAIN.to_vec();
        put_len(
            &mut static_bytes,
            statics.len(),
            "shared static table count",
        )?;
        for (hash, canonical) in statics {
            static_bytes.extend_from_slice(&hash.0);
            put_len(
                &mut static_bytes,
                canonical.len(),
                "shared static canonical byte count",
            )?;
            static_bytes.extend_from_slice(&canonical);
        }

        let summaries = self
            .summaries
            .iter()
            .map(|(key, entry)| match entry {
                SummaryEntry::Result(template) => (key.clone(), template.clone()),
            })
            .collect::<Vec<_>>();
        let mut summary_bytes = SUMMARY_TABLE_DOMAIN.to_vec();
        put_len(
            &mut summary_bytes,
            summaries.len(),
            "pure result summary count",
        )?;
        for (key, template) in summaries {
            self.consume_work(1 + pattern_nodes(&key.patterns)? + pattern_node_count(&template)?)?;
            summary_bytes.extend_from_slice(&key.function.0.to_be_bytes());
            put_len(
                &mut summary_bytes,
                key.patterns.len(),
                "summary input pattern count",
            )?;
            for pattern in &key.patterns {
                encode_pattern(&mut summary_bytes, pattern)?;
            }
            encode_pattern(&mut summary_bytes, &template)?;
        }
        Ok((
            SemanticHash(sha256(&static_bytes)),
            SemanticHash(sha256(&summary_bytes)),
        ))
    }

    fn lower_program(
        mut self,
        entry_temporary: FunctionId,
        schema: &super::schema::SchemaVersion,
        profile: CoreProfile,
    ) -> Result<(Program, Vec<PolyvariantR1S4Variant>, PolyvariantR1S4Usage), PolyvariantR1S4Error>
    {
        self.consume_work(self.built.len() as u64)?;
        let built = std::mem::take(&mut self.built);
        let mut keyed_versions = Vec::with_capacity(built.len());
        for version in built {
            self.consume_work(1 + pattern_nodes(&version.key.patterns)?)?;
            keyed_versions.push((version_key_bytes(&version.key)?, version));
        }
        keyed_versions.sort_by(|left, right| left.0.cmp(&right.0));
        for pair in keyed_versions.windows(2) {
            if pair[0].0 == pair[1].0 && pair[0].1.key != pair[1].1.key {
                return Err(PolyvariantR1S4Error::InternalInvariant {
                    message: "two distinct R1-S4 version keys have identical bytes".to_owned(),
                });
            }
        }
        self.built = keyed_versions
            .into_iter()
            .map(|(_, version)| version)
            .collect();

        let mut remap = BTreeMap::new();
        for (index, version) in self.built.iter().enumerate() {
            let final_id = u32::try_from(index)
                .map(FunctionId)
                .map_err(|_| PolyvariantR1S4Error::FunctionIdExhausted)?;
            remap.insert(version.temporary_id, final_id);
        }
        let entry = remap
            .get(&entry_temporary)
            .copied()
            .ok_or(PolyvariantR1S4Error::UnresolvedVariant)?;
        let built = std::mem::take(&mut self.built);
        let mut variants = Vec::with_capacity(built.len());
        let mut functions = Vec::with_capacity(built.len());
        for mut version in built {
            self.consume_work(1)?;
            let residual_function = remap
                .get(&version.temporary_id)
                .copied()
                .ok_or(PolyvariantR1S4Error::UnresolvedVariant)?;
            version.function.id = residual_function;
            self.rewrite_targets(&mut version.function.body, &remap)?;
            variants.push(PolyvariantR1S4Variant {
                source_function: version.key.source_function,
                residual_function,
                patterns: version.key.patterns,
            });
            functions.push(version.function);
        }
        let usage = self.usage;
        Ok((
            Program {
                schema: schema.clone(),
                profile,
                entry,
                functions,
            },
            variants,
            usage,
        ))
    }

    fn rewrite_targets(
        &mut self,
        term: &mut Term,
        remap: &BTreeMap<FunctionId, FunctionId>,
    ) -> Result<(), PolyvariantR1S4Error> {
        self.consume_work(1)?;
        match term {
            Term::Let { value, next, .. } => {
                if let RValue::Call { function, .. } = value {
                    *function = remap
                        .get(function)
                        .copied()
                        .ok_or(PolyvariantR1S4Error::UnresolvedVariant)?;
                }
                self.rewrite_targets(next, remap)
            }
            Term::If {
                then_term,
                else_term,
                ..
            } => {
                self.rewrite_targets(then_term, remap)?;
                self.rewrite_targets(else_term, remap)
            }
            Term::Case { arms, .. } => {
                for arm in arms {
                    self.rewrite_targets(&mut arm.body, remap)?;
                }
                Ok(())
            }
            Term::TailCall { function, .. } => {
                *function = remap
                    .get(function)
                    .copied()
                    .ok_or(PolyvariantR1S4Error::UnresolvedVariant)?;
                Ok(())
            }
            Term::Return(_) => Ok(()),
            Term::Region { body, .. } => self.rewrite_targets(body, remap),
            Term::Handle { clauses, body, .. } => {
                for clause in clauses {
                    self.rewrite_targets(&mut clause.body, remap)?;
                }
                self.rewrite_targets(body, remap)
            }
        }
    }
}

enum SpecializedRValue {
    Elided(Partial),
    Residual { rvalue: RValue, result: Partial },
}

fn validate_budget(budget: PolyvariantR1S4Budget) -> Result<(), PolyvariantR1S4Error> {
    for (field, limit, hard_cap) in [
        (
            "max_work_units",
            budget.max_work_units,
            R1_S4_MAX_WORK_UNITS_HARD_CAP,
        ),
        (
            "max_partial_value_nodes",
            budget.max_partial_value_nodes,
            R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
        ),
        (
            "max_variants",
            budget.max_variants,
            R1_S4_MAX_VARIANTS_HARD_CAP,
        ),
        (
            "max_control_splits",
            budget.max_control_splits,
            R1_S4_MAX_CONTROL_SPLITS_HARD_CAP,
        ),
        (
            "max_dynamic_parameters",
            budget.max_dynamic_parameters,
            R1_S4_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
        ),
        (
            "max_helper_unfolds",
            budget.max_helper_unfolds,
            R1_S4_MAX_HELPER_UNFOLDS_HARD_CAP,
        ),
        (
            "max_residual_nodes",
            budget.max_residual_nodes,
            R1_S4_MAX_RESIDUAL_NODES_HARD_CAP,
        ),
        (
            "max_residual_bytes",
            budget.max_residual_bytes,
            R1_S4_MAX_RESIDUAL_BYTES_HARD_CAP,
        ),
    ] {
        if limit == 0 {
            return Err(PolyvariantR1S4Error::ZeroBudget { field });
        }
        if limit > hard_cap {
            return Err(PolyvariantR1S4Error::BudgetHardCapExceeded {
                field,
                limit,
                hard_cap,
            });
        }
    }
    Ok(())
}

fn is_admitted_effect_row(effects: &EffectRow) -> bool {
    effects.effects.is_empty() || effects.effects.as_slice() == [Effect::Error(ErrorKind::Bounds)]
}

fn is_admitted_type(ty: &Type) -> bool {
    match ty {
        Type::Unit | Type::Bool | Type::I64 | Type::F64 => true,
        Type::Tuple(fields) => fields.iter().all(is_admitted_type),
        Type::Sum(sum) => sum
            .constructors
            .iter()
            .all(|constructor| constructor.fields.iter().all(is_admitted_type)),
        Type::Array {
            mutability,
            element,
            ..
        } => *mutability == Mutability::Read && element.as_ref() == &Type::F64,
        _ => false,
    }
}

fn specialization_value_matches_type(value: &SpecializationValue, ty: &Type) -> bool {
    match (value, ty) {
        (SpecializationValue::Unit, Type::Unit)
        | (SpecializationValue::Bool(_), Type::Bool)
        | (SpecializationValue::I64(_), Type::I64)
        | (SpecializationValue::F64(_), Type::F64) => true,
        (SpecializationValue::Tuple(values), Type::Tuple(types)) => {
            values.len() == types.len()
                && values
                    .iter()
                    .zip(types)
                    .all(|(value, ty)| specialization_value_matches_type(value, ty))
        }
        (
            SpecializationValue::Sum {
                ty: actual,
                constructor,
                fields,
            },
            Type::Sum(expected),
        ) if actual == expected => expected
            .constructors
            .get(*constructor as usize)
            .is_some_and(|constructor| {
                fields.len() == constructor.fields.len()
                    && fields
                        .iter()
                        .zip(&constructor.fields)
                        .all(|(value, ty)| specialization_value_matches_type(value, ty))
            }),
        _ => false,
    }
}

fn specialization_value_nodes(value: &SpecializationValue) -> Result<u64, PolyvariantR1S4Error> {
    let children = match value {
        SpecializationValue::Tuple(fields) => fields,
        SpecializationValue::Sum { fields, .. } => fields,
        SpecializationValue::Unit
        | SpecializationValue::Bool(_)
        | SpecializationValue::I64(_)
        | SpecializationValue::F64(_) => return Ok(1),
        SpecializationValue::ArrayF64(_) => {
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 counted an excluded static array".to_owned(),
            });
        }
    };
    let mut nodes = 1_u64;
    for child in children {
        nodes = nodes
            .checked_add(specialization_value_nodes(child)?)
            .ok_or(PolyvariantR1S4Error::PartialValueBudgetExceeded {
                limit: R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
            })?;
    }
    Ok(nodes)
}

fn canonical_static_value(
    value: &SpecializationValue,
) -> Result<SpecializationValue, PolyvariantR1S4Error> {
    Ok(match value {
        SpecializationValue::Unit => SpecializationValue::Unit,
        SpecializationValue::Bool(value) => SpecializationValue::Bool(*value),
        SpecializationValue::I64(value) => SpecializationValue::I64(*value),
        SpecializationValue::F64(value) => {
            SpecializationValue::F64(f64::from_bits(canonical_f64_bits(*value)))
        }
        SpecializationValue::Tuple(fields) => SpecializationValue::Tuple(
            fields
                .iter()
                .map(canonical_static_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        SpecializationValue::Sum {
            ty,
            constructor,
            fields,
        } => SpecializationValue::Sum {
            ty: ty.clone(),
            constructor: *constructor,
            fields: fields
                .iter()
                .map(canonical_static_value)
                .collect::<Result<Vec<_>, _>>()?,
        },
        SpecializationValue::ArrayF64(_) => {
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 canonicalized an excluded static array".to_owned(),
            });
        }
    })
}

fn specialization_value_type(value: &SpecializationValue) -> Result<Type, PolyvariantR1S4Error> {
    Ok(match value {
        SpecializationValue::Unit => Type::Unit,
        SpecializationValue::Bool(_) => Type::Bool,
        SpecializationValue::I64(_) => Type::I64,
        SpecializationValue::F64(_) => Type::F64,
        SpecializationValue::Tuple(fields) => Type::Tuple(
            fields
                .iter()
                .map(specialization_value_type)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        SpecializationValue::Sum { ty, .. } => Type::Sum(ty.clone()),
        SpecializationValue::ArrayF64(_) => {
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 inferred the type of an excluded static array".to_owned(),
            });
        }
    })
}

fn static_value(value: &Partial) -> Option<SpecializationValue> {
    match value.as_ref() {
        PartialValue::Known(value) => Some(value.as_ref().clone()),
        PartialValue::SharedStatic(shared) => Some(shared.value.as_ref().clone()),
        PartialValue::Tuple(fields) => {
            let values = fields
                .iter()
                .map(static_value)
                .collect::<Option<Vec<_>>>()?;
            Some(SpecializationValue::Tuple(values))
        }
        PartialValue::KnownSum {
            sum,
            constructor,
            fields,
        } => {
            let values = fields
                .iter()
                .map(static_value)
                .collect::<Option<Vec<_>>>()?;
            Some(SpecializationValue::Sum {
                ty: sum.clone(),
                constructor: *constructor,
                fields: values,
            })
        }
        PartialValue::Hole(_) | PartialValue::UnknownSum { .. } => None,
    }
}

fn all_static(values: &[Partial]) -> Option<Vec<SpecializationValue>> {
    values.iter().map(static_value).collect()
}

fn partial_type(value: &Partial) -> Result<Type, PolyvariantR1S4Error> {
    match value.as_ref() {
        PartialValue::Known(value) => specialization_value_type(value),
        PartialValue::SharedStatic(shared) => Ok(shared.ty.clone()),
        PartialValue::Hole(atom) => Ok(atom.ty.clone()),
        PartialValue::Tuple(fields) => Ok(Type::Tuple(
            fields
                .iter()
                .map(partial_type)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        PartialValue::KnownSum { sum, .. } | PartialValue::UnknownSum { sum, .. } => {
            Ok(Type::Sum(sum.clone()))
        }
    }
}

fn known_pattern(
    value: &SpecializationValue,
) -> Result<PolyvariantR1S4Pattern, PolyvariantR1S4Error> {
    Ok(match value {
        SpecializationValue::Unit => PolyvariantR1S4Pattern::KnownUnit,
        SpecializationValue::Bool(value) => PolyvariantR1S4Pattern::KnownBool(*value),
        SpecializationValue::I64(value) => PolyvariantR1S4Pattern::KnownI64(*value),
        SpecializationValue::F64(value) => {
            PolyvariantR1S4Pattern::KnownF64(canonical_f64_bits(*value))
        }
        SpecializationValue::Tuple(fields) => PolyvariantR1S4Pattern::KnownTuple(
            fields
                .iter()
                .map(known_pattern)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        SpecializationValue::Sum {
            ty,
            constructor,
            fields,
        } => PolyvariantR1S4Pattern::KnownSum {
            sum: ty.clone(),
            constructor: *constructor,
            fields: fields
                .iter()
                .map(known_pattern)
                .collect::<Result<Vec<_>, _>>()?,
        },
        SpecializationValue::ArrayF64(_) => {
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 encoded an excluded static array pattern".to_owned(),
            });
        }
    })
}

fn scalar_operand(value: &Partial) -> Result<Operand, PolyvariantR1S4Error> {
    match value.as_ref() {
        PartialValue::Known(value) => {
            literal_from_value(value).ok_or_else(|| PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 primitive received a known aggregate".to_owned(),
            })
        }
        PartialValue::Hole(atom)
            if matches!(atom.ty, Type::Unit | Type::Bool | Type::I64 | Type::F64) =>
        {
            Ok(atom.operand.clone())
        }
        _ => Err(PolyvariantR1S4Error::InternalInvariant {
            message: "R1-S4 primitive received a structural value".to_owned(),
        }),
    }
}

fn array_operand(value: &Partial) -> Result<Operand, PolyvariantR1S4Error> {
    match value.as_ref() {
        PartialValue::Hole(atom)
            if matches!(
                atom.ty,
                Type::Array {
                    mutability: Mutability::Read,
                    ref element,
                    ..
                } if element.as_ref() == &Type::F64
            ) =>
        {
            Ok(atom.operand.clone())
        }
        PartialValue::Known(value)
            if matches!(value.as_ref(), SpecializationValue::ArrayF64(_)) =>
        {
            Err(PolyvariantR1S4Error::InternalInvariant {
                message: "R1-S4 cannot materialize a static array literal".to_owned(),
            })
        }
        _ => Err(PolyvariantR1S4Error::InternalInvariant {
            message: "R1-S4 array primitive received a non-array value".to_owned(),
        }),
    }
}

fn literal_from_value(value: &SpecializationValue) -> Option<Operand> {
    match value {
        SpecializationValue::Unit => Some(Operand::Unit),
        SpecializationValue::Bool(value) => Some(Operand::Bool(*value)),
        SpecializationValue::I64(value) => Some(Operand::I64(*value)),
        SpecializationValue::F64(value) => {
            Some(Operand::F64(f64::from_bits(canonical_f64_bits(*value))))
        }
        SpecializationValue::Tuple(_)
        | SpecializationValue::Sum { .. }
        | SpecializationValue::ArrayF64(_) => None,
    }
}

fn evaluate_primitive(
    primitive: &Primitive,
    values: &[SpecializationValue],
) -> Result<SpecializationValue, PolyvariantR1S4Error> {
    match primitive {
        Primitive::I64Add(mode) => {
            let (left, right) = i64_pair(values)?;
            Ok(SpecializationValue::I64(apply_i64(
                *mode,
                left,
                right,
                I64Operation::Add,
            )?))
        }
        Primitive::I64Sub(mode) => {
            let (left, right) = i64_pair(values)?;
            Ok(SpecializationValue::I64(apply_i64(
                *mode,
                left,
                right,
                I64Operation::Sub,
            )?))
        }
        Primitive::I64Mul(mode) => {
            let (left, right) = i64_pair(values)?;
            Ok(SpecializationValue::I64(apply_i64(
                *mode,
                left,
                right,
                I64Operation::Mul,
            )?))
        }
        Primitive::F64Add => {
            let (left, right) = f64_pair(values)?;
            Ok(SpecializationValue::F64(left + right))
        }
        Primitive::F64Sub => {
            let (left, right) = f64_pair(values)?;
            Ok(SpecializationValue::F64(left - right))
        }
        Primitive::I64CmpLt => {
            let (left, right) = i64_pair(values)?;
            Ok(SpecializationValue::Bool(left < right))
        }
        Primitive::I64CmpGe => {
            let (left, right) = i64_pair(values)?;
            Ok(SpecializationValue::Bool(left >= right))
        }
        Primitive::ArrayLenF64 | Primitive::ArrayGetF64 => {
            Err(PolyvariantR1S4Error::InternalInvariant {
                message: "array primitive passed R1-S4 admission".to_owned(),
            })
        }
    }
}

#[derive(Clone, Copy)]
enum I64Operation {
    Add,
    Sub,
    Mul,
}

fn apply_i64(
    mode: NumericMode,
    left: i64,
    right: i64,
    operation: I64Operation,
) -> Result<i64, PolyvariantR1S4Error> {
    Ok(match (mode, operation) {
        (NumericMode::Wrapping, I64Operation::Add) => left.wrapping_add(right),
        (NumericMode::Wrapping, I64Operation::Sub) => left.wrapping_sub(right),
        (NumericMode::Wrapping, I64Operation::Mul) => left.wrapping_mul(right),
        (NumericMode::Saturating, I64Operation::Add) => left.saturating_add(right),
        (NumericMode::Saturating, I64Operation::Sub) => left.saturating_sub(right),
        (NumericMode::Saturating, I64Operation::Mul) => left.saturating_mul(right),
        (NumericMode::Checked, _) => {
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: "checked arithmetic passed R1-S4 admission".to_owned(),
            });
        }
    })
}

fn i64_pair(values: &[SpecializationValue]) -> Result<(i64, i64), PolyvariantR1S4Error> {
    let [SpecializationValue::I64(left), SpecializationValue::I64(right)] = values else {
        return Err(PolyvariantR1S4Error::InternalInvariant {
            message: "verified R1-S4 I64 primitive argument mismatch".to_owned(),
        });
    };
    Ok((*left, *right))
}

fn f64_pair(values: &[SpecializationValue]) -> Result<(f64, f64), PolyvariantR1S4Error> {
    let [SpecializationValue::F64(left), SpecializationValue::F64(right)] = values else {
        return Err(PolyvariantR1S4Error::InternalInvariant {
            message: "verified R1-S4 F64 primitive argument mismatch".to_owned(),
        });
    };
    Ok((*left, *right))
}

fn pattern_nodes(patterns: &[PolyvariantR1S4Pattern]) -> Result<u64, PolyvariantR1S4Error> {
    let mut nodes = 0_u64;
    for pattern in patterns {
        nodes = nodes.checked_add(pattern_node_count(pattern)?).ok_or(
            PolyvariantR1S4Error::WorkBudgetExceeded {
                limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
            },
        )?;
    }
    Ok(nodes)
}

fn pattern_node_count(pattern: &PolyvariantR1S4Pattern) -> Result<u64, PolyvariantR1S4Error> {
    let mut nodes = 1_u64;
    match pattern {
        PolyvariantR1S4Pattern::KnownTuple(fields) | PolyvariantR1S4Pattern::Tuple(fields) => {
            for field in fields {
                nodes = nodes.checked_add(pattern_node_count(field)?).ok_or(
                    PolyvariantR1S4Error::WorkBudgetExceeded {
                        limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
                    },
                )?;
            }
        }
        PolyvariantR1S4Pattern::Hole { ty, .. } => {
            nodes = nodes.checked_add(type_node_count(ty)?).ok_or(
                PolyvariantR1S4Error::WorkBudgetExceeded {
                    limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
                },
            )?;
        }
        PolyvariantR1S4Pattern::KnownSum { sum, fields, .. } => {
            nodes = nodes.checked_add(sum_type_node_count(sum)?).ok_or(
                PolyvariantR1S4Error::WorkBudgetExceeded {
                    limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
                },
            )?;
            for field in fields {
                nodes = nodes.checked_add(pattern_node_count(field)?).ok_or(
                    PolyvariantR1S4Error::WorkBudgetExceeded {
                        limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
                    },
                )?;
            }
        }
        PolyvariantR1S4Pattern::UnknownSum { sum, .. } => {
            nodes = nodes.checked_add(sum_type_node_count(sum)?).ok_or(
                PolyvariantR1S4Error::WorkBudgetExceeded {
                    limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
                },
            )?;
        }
        PolyvariantR1S4Pattern::KnownUnit
        | PolyvariantR1S4Pattern::KnownBool(_)
        | PolyvariantR1S4Pattern::KnownI64(_)
        | PolyvariantR1S4Pattern::KnownF64(_)
        | PolyvariantR1S4Pattern::SharedStatic { .. } => {}
    }
    Ok(nodes)
}

fn type_node_count(ty: &Type) -> Result<u64, PolyvariantR1S4Error> {
    let mut nodes = 1_u64;
    match ty {
        Type::Tuple(fields) => {
            for field in fields {
                nodes = nodes.checked_add(type_node_count(field)?).ok_or(
                    PolyvariantR1S4Error::WorkBudgetExceeded {
                        limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
                    },
                )?;
            }
        }
        Type::Sum(sum) => {
            nodes = nodes.checked_add(sum_type_node_count(sum)?).ok_or(
                PolyvariantR1S4Error::WorkBudgetExceeded {
                    limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
                },
            )?;
        }
        _ => {}
    }
    Ok(nodes)
}

fn sum_type_node_count(sum: &SumType) -> Result<u64, PolyvariantR1S4Error> {
    let mut nodes = 1_u64;
    for constructor in &sum.constructors {
        nodes = nodes
            .checked_add(1)
            .ok_or(PolyvariantR1S4Error::WorkBudgetExceeded {
                limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
            })?;
        for field in &constructor.fields {
            nodes = nodes.checked_add(type_node_count(field)?).ok_or(
                PolyvariantR1S4Error::WorkBudgetExceeded {
                    limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
                },
            )?;
        }
    }
    Ok(nodes)
}

fn collect_pattern_aliases(
    patterns: &[PolyvariantR1S4Pattern],
) -> Result<BTreeMap<u32, Type>, PolyvariantR1S4Error> {
    let mut aliases = BTreeMap::new();
    for pattern in patterns {
        collect_pattern_alias(pattern, &mut aliases)?;
    }
    Ok(aliases)
}

fn collect_pattern_alias(
    pattern: &PolyvariantR1S4Pattern,
    aliases: &mut BTreeMap<u32, Type>,
) -> Result<(), PolyvariantR1S4Error> {
    match pattern {
        PolyvariantR1S4Pattern::Hole { ty, alias } => {
            if matches!(ty, Type::Sum(_)) {
                return Err(PolyvariantR1S4Error::InternalInvariant {
                    message: "Sum-typed dynamic pattern is not UnknownSum".to_owned(),
                });
            }
            insert_alias(aliases, *alias, ty.clone())
        }
        PolyvariantR1S4Pattern::UnknownSum { sum, alias } => {
            insert_alias(aliases, *alias, Type::Sum(sum.clone()))
        }
        PolyvariantR1S4Pattern::KnownTuple(fields)
        | PolyvariantR1S4Pattern::Tuple(fields)
        | PolyvariantR1S4Pattern::KnownSum { fields, .. } => {
            for field in fields {
                collect_pattern_alias(field, aliases)?;
            }
            Ok(())
        }
        PolyvariantR1S4Pattern::KnownUnit
        | PolyvariantR1S4Pattern::KnownBool(_)
        | PolyvariantR1S4Pattern::KnownI64(_)
        | PolyvariantR1S4Pattern::KnownF64(_)
        | PolyvariantR1S4Pattern::SharedStatic { .. } => Ok(()),
    }
}

fn insert_alias(
    aliases: &mut BTreeMap<u32, Type>,
    alias: u32,
    ty: Type,
) -> Result<(), PolyvariantR1S4Error> {
    if let Some(existing) = aliases.get(&alias) {
        if *existing != ty {
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: format!("R1-S4 alias {alias} has inconsistent types"),
            });
        }
    } else {
        aliases.insert(alias, ty);
    }
    Ok(())
}

fn version_key_bytes(key: &VersionKey) -> Result<Vec<u8>, PolyvariantR1S4Error> {
    let mut bytes = VERSION_KEY_DOMAIN.to_vec();
    bytes.extend_from_slice(&key.source_function.0.to_be_bytes());
    put_len(&mut bytes, key.patterns.len(), "version pattern count")?;
    for pattern in &key.patterns {
        encode_pattern(&mut bytes, pattern)?;
    }
    Ok(bytes)
}

fn variant_table_hash(
    variants: &[PolyvariantR1S4Variant],
) -> Result<SemanticHash, PolyvariantR1S4Error> {
    let mut bytes = VARIANT_TABLE_DOMAIN.to_vec();
    put_len(&mut bytes, variants.len(), "variant evidence count")?;
    for variant in variants {
        bytes.extend_from_slice(&variant.source_function.0.to_be_bytes());
        bytes.extend_from_slice(&variant.residual_function.0.to_be_bytes());
        put_len(
            &mut bytes,
            variant.patterns.len(),
            "variant evidence pattern count",
        )?;
        for pattern in &variant.patterns {
            encode_pattern(&mut bytes, pattern)?;
        }
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn encode_pattern(
    bytes: &mut Vec<u8>,
    pattern: &PolyvariantR1S4Pattern,
) -> Result<(), PolyvariantR1S4Error> {
    match pattern {
        PolyvariantR1S4Pattern::KnownUnit => bytes.push(0),
        PolyvariantR1S4Pattern::KnownBool(value) => {
            bytes.push(1);
            bytes.push(u8::from(*value));
        }
        PolyvariantR1S4Pattern::KnownI64(value) => {
            bytes.push(2);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        PolyvariantR1S4Pattern::KnownF64(bits) => {
            bytes.push(3);
            bytes.extend_from_slice(&bits.to_be_bytes());
        }
        PolyvariantR1S4Pattern::KnownTuple(fields) => {
            bytes.push(4);
            put_len(bytes, fields.len(), "KnownTuple field count")?;
            for field in fields {
                encode_pattern(bytes, field)?;
            }
        }
        PolyvariantR1S4Pattern::Hole { ty, alias } => {
            bytes.push(5);
            encode_type(bytes, ty)?;
            bytes.extend_from_slice(&alias.to_be_bytes());
        }
        PolyvariantR1S4Pattern::Tuple(fields) => {
            bytes.push(6);
            put_len(bytes, fields.len(), "Tuple pattern field count")?;
            for field in fields {
                encode_pattern(bytes, field)?;
            }
        }
        PolyvariantR1S4Pattern::KnownSum {
            sum,
            constructor,
            fields,
        } => {
            bytes.push(7);
            encode_sum_type(bytes, sum)?;
            bytes.extend_from_slice(&constructor.to_be_bytes());
            put_len(bytes, fields.len(), "KnownSum field count")?;
            for field in fields {
                encode_pattern(bytes, field)?;
            }
        }
        PolyvariantR1S4Pattern::UnknownSum { sum, alias } => {
            bytes.push(8);
            encode_sum_type(bytes, sum)?;
            bytes.extend_from_slice(&alias.to_be_bytes());
        }
        PolyvariantR1S4Pattern::SharedStatic { hash } => {
            bytes.push(9);
            bytes.extend_from_slice(&hash.0);
        }
    }
    Ok(())
}

fn encode_type(bytes: &mut Vec<u8>, ty: &Type) -> Result<(), PolyvariantR1S4Error> {
    match ty {
        Type::Unit => bytes.push(0),
        Type::Bool => bytes.push(1),
        Type::I64 => bytes.push(2),
        Type::F64 => bytes.push(3),
        Type::Tuple(fields) => {
            bytes.push(4);
            put_len(bytes, fields.len(), "Tuple type field count")?;
            for field in fields {
                encode_type(bytes, field)?;
            }
        }
        Type::Sum(sum) => {
            bytes.push(5);
            encode_sum_type(bytes, sum)?;
        }
        Type::Array {
            region,
            mutability: Mutability::Read,
            element,
        } if element.as_ref() == &Type::F64 => {
            bytes.push(6);
            bytes.extend_from_slice(&region.0.to_be_bytes());
            bytes.push(0);
            encode_type(bytes, element)?;
        }
        _ => {
            return Err(PolyvariantR1S4Error::InternalInvariant {
                message: "excluded type entered the R1-S4 key encoder".to_owned(),
            });
        }
    }
    Ok(())
}

fn encode_sum_type(bytes: &mut Vec<u8>, sum: &SumType) -> Result<(), PolyvariantR1S4Error> {
    put_string(bytes, &sum.name, "Sum name")?;
    put_len(bytes, sum.constructors.len(), "Sum constructor count")?;
    for constructor in &sum.constructors {
        put_string(bytes, &constructor.name, "constructor name")?;
        put_len(bytes, constructor.fields.len(), "constructor field count")?;
        for field in &constructor.fields {
            encode_type(bytes, field)?;
        }
    }
    Ok(())
}

fn put_len(
    bytes: &mut Vec<u8>,
    len: usize,
    context: &'static str,
) -> Result<(), PolyvariantR1S4Error> {
    let len = u32::try_from(len).map_err(|_| PolyvariantR1S4Error::InternalInvariant {
        message: format!("R1-S4 {context} exceeds U32"),
    })?;
    bytes.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn put_string(
    bytes: &mut Vec<u8>,
    value: &str,
    context: &'static str,
) -> Result<(), PolyvariantR1S4Error> {
    put_len(bytes, value.len(), context)?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn polyvariant_request_hash(
    source_hash: SemanticHash,
    upstream_request_hash: SemanticHash,
    entry: FunctionId,
    budget: PolyvariantR1S4Budget,
    policy_hash: SemanticHash,
    control: &PolyvariantR1S4Control,
) -> SemanticHash {
    let mut bytes = REQUEST_DOMAIN.to_vec();
    put_version(&mut bytes, POLYVARIANT_R1_S4_VERSION);
    bytes.extend_from_slice(&source_hash.0);
    bytes.extend_from_slice(&upstream_request_hash.0);
    bytes.extend_from_slice(&policy_hash.0);
    bytes.extend_from_slice(&control.control_hash().0);
    bytes.extend_from_slice(&entry.0.to_be_bytes());
    for limit in [
        budget.max_work_units,
        budget.max_partial_value_nodes,
        budget.max_variants,
        budget.max_control_splits,
        budget.max_dynamic_parameters,
        budget.max_helper_unfolds,
        budget.max_residual_nodes,
        budget.max_residual_bytes,
    ] {
        bytes.extend_from_slice(&limit.to_be_bytes());
    }
    SemanticHash(sha256(&bytes))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn collect_calls(term: &Term, calls: &mut Vec<FunctionId>) {
    match term {
        Term::Let { value, next, .. } => {
            if let RValue::Call { function, .. } = value {
                calls.push(*function);
            }
            collect_calls(next, calls);
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            collect_calls(then_term, calls);
            collect_calls(else_term, calls);
        }
        Term::Case { arms, .. } => {
            for arm in arms {
                collect_calls(&arm.body, calls);
            }
        }
        Term::TailCall { function, .. } => calls.push(*function),
        Term::Region { body, .. } => collect_calls(body, calls),
        Term::Handle { clauses, body, .. } => {
            for clause in clauses {
                collect_calls(&clause.body, calls);
            }
            collect_calls(body, calls);
        }
        Term::Return(_) => {}
    }
}

fn recursive_components(graph: &BTreeMap<FunctionId, Vec<FunctionId>>) -> Vec<Vec<FunctionId>> {
    let mut finish = Vec::new();
    let mut visited = BTreeSet::new();
    for start in graph.keys().copied() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![(start, 0_usize)];
        visited.insert(start);
        while let Some((node, next_index)) = stack.last_mut() {
            let edges = graph.get(node).map(Vec::as_slice).unwrap_or_default();
            if *next_index < edges.len() {
                let target = edges[*next_index];
                *next_index += 1;
                if graph.contains_key(&target) && visited.insert(target) {
                    stack.push((target, 0));
                }
            } else {
                finish.push(*node);
                stack.pop();
            }
        }
    }

    let mut reverse = graph
        .keys()
        .copied()
        .map(|node| (node, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    for (source, targets) in graph {
        for target in targets {
            if let Some(edges) = reverse.get_mut(target) {
                edges.push(*source);
            }
        }
    }
    let mut assigned = BTreeSet::new();
    let mut recursive = Vec::new();
    for start in finish.into_iter().rev() {
        if !assigned.insert(start) {
            continue;
        }
        let mut component = Vec::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            component.push(node);
            for predecessor in reverse.get(&node).map(Vec::as_slice).unwrap_or_default() {
                if assigned.insert(*predecessor) {
                    stack.push(*predecessor);
                }
            }
        }
        component.sort();
        let is_recursive = component.len() > 1
            || component.iter().any(|node| {
                graph
                    .get(node)
                    .is_some_and(|targets| targets.contains(node))
            });
        if is_recursive {
            recursive.push(component);
        }
    }
    recursive
}

fn is_bounded_helper(term: &Term) -> bool {
    match term {
        Term::Let { next, .. } => is_bounded_helper(next),
        Term::Return(_) => true,
        Term::If {
            then_term,
            else_term,
            ..
        } => is_bounded_helper(then_term) && is_bounded_helper(else_term),
        Term::Case { arms, .. } => arms.iter().all(|arm| is_bounded_helper(&arm.body)),
        Term::TailCall { .. } | Term::Region { .. } | Term::Handle { .. } => false,
    }
}

fn term_node_count(term: &Term) -> Result<u64, PolyvariantR1S4Error> {
    let children = match term {
        Term::Let { next, .. } | Term::Region { body: next, .. } => {
            vec![next.as_ref()]
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => vec![then_term.as_ref(), else_term.as_ref()],
        Term::Case { arms, .. } => arms.iter().map(|arm| &arm.body).collect(),
        Term::Handle { clauses, body, .. } => clauses
            .iter()
            .map(|clause| clause.body.as_ref())
            .chain(std::iter::once(body.as_ref()))
            .collect(),
        Term::TailCall { .. } | Term::Return(_) => Vec::new(),
    };
    let mut nodes = 1_u64;
    for child in children {
        nodes = nodes.checked_add(term_node_count(child)?).ok_or(
            PolyvariantR1S4Error::WorkBudgetExceeded {
                limit: R1_S4_MAX_WORK_UNITS_HARD_CAP,
            },
        )?;
    }
    Ok(nodes)
}

fn wrap_bindings(bindings: Vec<MaterializedBinding>, body: Term) -> Term {
    bindings
        .into_iter()
        .rev()
        .fold(body, |next, binding| Term::Let {
            binder: binding.binder,
            ty: binding.ty,
            value: binding.value,
            next: Box::new(next),
        })
}

fn scan_term_locals(term: &Term, maximum: &mut Option<u32>) {
    match term {
        Term::Let { binder, next, .. } => {
            include_local(*binder, maximum);
            scan_term_locals(next, maximum);
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            scan_term_locals(then_term, maximum);
            scan_term_locals(else_term, maximum);
        }
        Term::Case { arms, .. } => {
            for arm in arms {
                for binding in &arm.bindings {
                    include_local(*binding, maximum);
                }
                scan_term_locals(&arm.body, maximum);
            }
        }
        Term::TailCall { .. } | Term::Return(_) => {}
        Term::Region { body, .. } => scan_term_locals(body, maximum),
        Term::Handle {
            capture_parameters,
            clauses,
            body,
            ..
        } => {
            for parameter in capture_parameters {
                include_local(parameter.local, maximum);
            }
            for clause in clauses {
                for parameter in &clause.parameters {
                    include_local(*parameter, maximum);
                }
                scan_term_locals(&clause.body, maximum);
            }
            scan_term_locals(body, maximum);
        }
    }
}

fn include_local(local: LocalId, maximum: &mut Option<u32>) {
    *maximum = Some(maximum.map_or(local.0, |current| current.max(local.0)));
}
