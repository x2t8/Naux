use super::encoding::sha256;
use super::residual::{finalize_residual_with_limits, ResidualCore, ResidualGenerationError};
use super::schema::{
    CoreProfile, EffectRow, Function, FunctionId, LocalId, NumericMode, Operand, Parameter,
    Primitive, Program, RValue, SemanticHash, Term, Type,
};
use super::specialization::{
    SpecializationSlot, SpecializationValue, ValidatedSpecializationRequest,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

pub const POLYVARIANT_R1_S1_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const R1_S1_MAX_STEPS_HARD_CAP: u64 = 100_000_000;
pub const R1_S1_MAX_VARIANTS_HARD_CAP: u64 = 1_000_000;
pub const R1_S1_MAX_BRANCH_SPLITS_HARD_CAP: u64 = 1_000_000;
pub const R1_S1_MAX_DYNAMIC_PARAMETERS_HARD_CAP: u64 = 1_000_000;

const POLICY_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-policy:r1-s1:v1\0";
const REQUEST_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-request:r1-s1:v1\0";
const VERSION_KEY_DOMAIN: &[u8] = b"NAUX:core-n0:polyvariant-version-key:r1-s1:v1\0";
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyvariantR1Budget {
    pub max_steps: u64,
    pub max_variants: u64,
    pub max_branch_splits: u64,
    pub max_dynamic_parameters: u64,
}

impl PolyvariantR1Budget {
    pub const fn new(
        max_steps: u64,
        max_variants: u64,
        max_branch_splits: u64,
        max_dynamic_parameters: u64,
    ) -> Self {
        Self {
            max_steps,
            max_variants,
            max_branch_splits,
            max_dynamic_parameters,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolyvariantR1Usage {
    pub steps: u64,
    pub variants: u64,
    pub branch_splits: u64,
    pub dynamic_parameters: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolyvariantR1Pattern {
    KnownUnit,
    KnownBool(bool),
    KnownI64(i64),
    KnownF64(u64),
    Dynamic(Type),
}

impl PolyvariantR1Pattern {
    pub fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyvariantR1Variant {
    source_function: FunctionId,
    residual_function: FunctionId,
    patterns: Vec<PolyvariantR1Pattern>,
}

impl PolyvariantR1Variant {
    pub fn source_function(&self) -> FunctionId {
        self.source_function
    }

    pub fn residual_function(&self) -> FunctionId {
        self.residual_function
    }

    pub fn patterns(&self) -> &[PolyvariantR1Pattern] {
        &self.patterns
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyvariantR1Report {
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    request_hash: SemanticHash,
    upstream_request_hash: SemanticHash,
    budget: PolyvariantR1Budget,
    usage: PolyvariantR1Usage,
    variants: Vec<PolyvariantR1Variant>,
    residual_hash: SemanticHash,
    residual_nodes: u64,
    residual_bytes: u64,
}

impl PolyvariantR1Report {
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

    pub fn budget(&self) -> PolyvariantR1Budget {
        self.budget
    }

    pub fn usage(&self) -> PolyvariantR1Usage {
        self.usage
    }

    pub fn variants(&self) -> &[PolyvariantR1Variant] {
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
pub struct PolyvariantR1Specialization {
    residual: ResidualCore,
    report: PolyvariantR1Report,
}

impl PolyvariantR1Specialization {
    pub fn residual(&self) -> &ResidualCore {
        &self.residual
    }

    pub fn artifact(&self) -> &super::schema::CoreArtifact {
        &self.residual.artifact
    }

    pub fn report(&self) -> &PolyvariantR1Report {
        &self.report
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PolyvariantR1Error {
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
    MultipleRecursiveComponents {
        count: usize,
    },
    ExpectedBool {
        function: FunctionId,
    },
    StepBudgetExceeded {
        limit: u64,
    },
    VariantBudgetExceeded {
        limit: u64,
    },
    BranchBudgetExceeded {
        limit: u64,
    },
    DynamicParameterBudgetExceeded {
        limit: u64,
    },
    FunctionIdExhausted,
    UnresolvedVariant,
    Residual(ResidualGenerationError),
    InternalInvariant {
        message: String,
    },
}

impl fmt::Display for PolyvariantR1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBudget { field } => write!(formatter, "R1-S1 budget {field} is zero"),
            Self::BudgetHardCapExceeded {
                field,
                limit,
                hard_cap,
            } => write!(
                formatter,
                "R1-S1 budget {field}={limit} exceeds hard cap {hard_cap}"
            ),
            Self::UnsupportedProfile(profile) => {
                write!(formatter, "R1-S1 admits P1V0, found {profile:?}")
            }
            Self::UnsupportedType {
                function,
                context,
                ty,
            } => write!(
                formatter,
                "R1-S1 function {} has unsupported {context} type {ty:?}",
                function.0
            ),
            Self::UnsupportedEffects { function } => write!(
                formatter,
                "R1-S1 function {} has a non-empty effect row",
                function.0
            ),
            Self::UnsupportedRegionParameters { function } => write!(
                formatter,
                "R1-S1 function {} has region parameters",
                function.0
            ),
            Self::UnsupportedNode { function, node } => write!(
                formatter,
                "R1-S1 function {} contains unsupported {node}",
                function.0
            ),
            Self::UnsupportedPrimitive {
                function,
                primitive,
            } => write!(
                formatter,
                "R1-S1 function {} contains unsupported primitive {primitive:?}",
                function.0
            ),
            Self::MissingFunction(function) => {
                write!(formatter, "R1-S1 cannot find function {}", function.0)
            }
            Self::MissingLocal { function, local } => write!(
                formatter,
                "R1-S1 function {} cannot resolve local {}",
                function.0, local.0
            ),
            Self::ArityMismatch {
                function,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S1 call to function {} has {actual} argument(s), expected {expected}",
                function.0
            ),
            Self::InvalidEntrySlot { parameter } => write!(
                formatter,
                "R1-S1 entry parameter {} is not an admitted scalar slot",
                parameter.0
            ),
            Self::MultipleRecursiveComponents { count } => write!(
                formatter,
                "R1-S1 reachable graph has {count} recursive components; at most one is admitted"
            ),
            Self::ExpectedBool { function } => write!(
                formatter,
                "R1-S1 function {} reached a non-Bool If condition",
                function.0
            ),
            Self::StepBudgetExceeded { limit } => {
                write!(formatter, "R1-S1 exceeded max_steps {limit}")
            }
            Self::VariantBudgetExceeded { limit } => {
                write!(formatter, "R1-S1 exceeded max_variants {limit}")
            }
            Self::BranchBudgetExceeded { limit } => {
                write!(formatter, "R1-S1 exceeded max_branch_splits {limit}")
            }
            Self::DynamicParameterBudgetExceeded { limit } => {
                write!(formatter, "R1-S1 exceeded max_dynamic_parameters {limit}")
            }
            Self::FunctionIdExhausted => {
                formatter.write_str("R1-S1 exhausted the FunctionId namespace")
            }
            Self::UnresolvedVariant => {
                formatter.write_str("R1-S1 finished with an unresolved variant")
            }
            Self::Residual(error) => write!(formatter, "R1-S1 residual failed: {error}"),
            Self::InternalInvariant { message } => {
                write!(formatter, "R1-S1 invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for PolyvariantR1Error {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VersionKey {
    source_function: FunctionId,
    patterns: Vec<PolyvariantR1Pattern>,
}

#[derive(Clone, Debug)]
enum PartialScalar {
    Known(SpecializationValue),
    Dynamic { ty: Type, operand: Operand },
}

impl PartialScalar {
    fn pattern(&self) -> Result<PolyvariantR1Pattern, PolyvariantR1Error> {
        match self {
            Self::Known(value) => pattern_from_value(value),
            Self::Dynamic { ty, .. } => Ok(PolyvariantR1Pattern::Dynamic(ty.clone())),
        }
    }

    fn residual_operand(&self) -> Result<Operand, PolyvariantR1Error> {
        match self {
            Self::Known(value) => literal_from_value(value),
            Self::Dynamic { operand, .. } => Ok(operand.clone()),
        }
    }
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

struct Machine {
    functions: BTreeMap<FunctionId, Function>,
    budget: PolyvariantR1Budget,
    usage: PolyvariantR1Usage,
    reserved: BTreeMap<VersionKey, ReservedVersion>,
    worklist: VecDeque<VersionKey>,
    built: Vec<BuiltVersion>,
}

pub fn polyvariant_r1_policy_hash() -> SemanticHash {
    let mut bytes = POLICY_DOMAIN.to_vec();
    put_version(&mut bytes, POLYVARIANT_R1_S1_VERSION);
    bytes.extend_from_slice(&(VERSION_KEY_DOMAIN.len() as u32).to_be_bytes());
    bytes.extend_from_slice(VERSION_KEY_DOMAIN);
    for cap in [
        R1_S1_MAX_STEPS_HARD_CAP,
        R1_S1_MAX_VARIANTS_HARD_CAP,
        R1_S1_MAX_BRANCH_SPLITS_HARD_CAP,
        R1_S1_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
    ] {
        bytes.extend_from_slice(&cap.to_be_bytes());
    }
    for capability in [
        b"scalar-partial-values-v1".as_slice(),
        b"mixed-direct-tail-calls-v1".as_slice(),
        b"dynamic-if-both-branches-v1".as_slice(),
        b"memoized-exact-variants-v1".as_slice(),
        b"canonical-version-key-bytes-v1".as_slice(),
        b"canonical-key-byte-function-id-order-v1".as_slice(),
        b"verified-residual-only-v1".as_slice(),
        b"fail-closed-budgets-v1".as_slice(),
    ] {
        bytes.extend_from_slice(&(capability.len() as u32).to_be_bytes());
        bytes.extend_from_slice(capability);
    }
    SemanticHash(sha256(&bytes))
}

pub fn specialize_polyvariant_r1(
    validated: &ValidatedSpecializationRequest<'_, '_>,
    budget: PolyvariantR1Budget,
) -> Result<PolyvariantR1Specialization, PolyvariantR1Error> {
    validate_budget(budget)?;
    let source = &validated.artifact().program;
    if source.profile != CoreProfile::P1V0 {
        return Err(PolyvariantR1Error::UnsupportedProfile(source.profile));
    }

    let functions = source
        .functions
        .iter()
        .cloned()
        .map(|function| (function.id, function))
        .collect::<BTreeMap<_, _>>();
    let graph = admit_reachable_subset(source.entry, &functions)?;
    let recursive_components = count_recursive_components(&graph);
    if recursive_components > 1 {
        return Err(PolyvariantR1Error::MultipleRecursiveComponents {
            count: recursive_components,
        });
    }

    let entry = functions
        .get(&source.entry)
        .ok_or(PolyvariantR1Error::MissingFunction(source.entry))?;
    if entry.parameters.len() != validated.request().entry_slots.len() {
        return Err(PolyvariantR1Error::ArityMismatch {
            function: source.entry,
            expected: entry.parameters.len(),
            actual: validated.request().entry_slots.len(),
        });
    }
    let entry_patterns = entry
        .parameters
        .iter()
        .zip(&validated.request().entry_slots)
        .map(|(parameter, slot)| entry_pattern(parameter, slot))
        .collect::<Result<Vec<_>, _>>()?;
    let entry_key = VersionKey {
        source_function: source.entry,
        patterns: entry_patterns,
    };
    let policy_hash = polyvariant_r1_policy_hash();
    let request_hash = polyvariant_request_hash(
        validated.artifact().semantic_hash,
        validated.request_hash(),
        source.entry,
        budget,
        policy_hash,
    );

    let mut machine = Machine {
        functions,
        budget,
        usage: PolyvariantR1Usage::default(),
        reserved: BTreeMap::new(),
        worklist: VecDeque::new(),
        built: Vec::new(),
    };
    let entry_temporary = machine.reserve(entry_key.clone())?;
    while let Some(key) = machine.worklist.pop_front() {
        machine.build_version(key)?;
    }
    if machine.reserved.values().any(|version| !version.built) {
        return Err(PolyvariantR1Error::UnresolvedVariant);
    }

    let usage = machine.usage;
    let (program, descriptors) =
        machine.lower_program(entry_temporary, &source.schema, source.profile)?;
    let residual_budget = validated.request().budget;
    let residual = finalize_residual_with_limits(
        validated.artifact().semantic_hash,
        request_hash,
        program,
        residual_budget.max_residual_nodes,
        residual_budget.max_residual_bytes,
    )
    .map_err(PolyvariantR1Error::Residual)?;
    let report = PolyvariantR1Report {
        policy_version: POLYVARIANT_R1_S1_VERSION,
        policy_hash,
        request_hash,
        upstream_request_hash: validated.request_hash(),
        budget,
        usage,
        variants: descriptors,
        residual_hash: residual.artifact.semantic_hash,
        residual_nodes: residual.residual_nodes,
        residual_bytes: residual.residual_bytes,
    };
    Ok(PolyvariantR1Specialization { residual, report })
}

impl Machine {
    fn consume_step(&mut self) -> Result<(), PolyvariantR1Error> {
        if self.usage.steps == self.budget.max_steps {
            return Err(PolyvariantR1Error::StepBudgetExceeded {
                limit: self.budget.max_steps,
            });
        }
        self.usage.steps += 1;
        Ok(())
    }

    fn consume_branch(&mut self) -> Result<(), PolyvariantR1Error> {
        if self.usage.branch_splits == self.budget.max_branch_splits {
            return Err(PolyvariantR1Error::BranchBudgetExceeded {
                limit: self.budget.max_branch_splits,
            });
        }
        self.usage.branch_splits += 1;
        Ok(())
    }

    fn reserve(&mut self, key: VersionKey) -> Result<FunctionId, PolyvariantR1Error> {
        if let Some(version) = self.reserved.get(&key) {
            return Ok(version.temporary_id);
        }
        if self.usage.variants == self.budget.max_variants {
            return Err(PolyvariantR1Error::VariantBudgetExceeded {
                limit: self.budget.max_variants,
            });
        }
        let dynamic_parameters = key
            .patterns
            .iter()
            .filter(|pattern| pattern.is_dynamic())
            .count() as u64;
        let next_dynamic = self
            .usage
            .dynamic_parameters
            .checked_add(dynamic_parameters)
            .ok_or(PolyvariantR1Error::DynamicParameterBudgetExceeded {
                limit: self.budget.max_dynamic_parameters,
            })?;
        if next_dynamic > self.budget.max_dynamic_parameters {
            return Err(PolyvariantR1Error::DynamicParameterBudgetExceeded {
                limit: self.budget.max_dynamic_parameters,
            });
        }
        let temporary = u32::try_from(self.usage.variants)
            .map(FunctionId)
            .map_err(|_| PolyvariantR1Error::FunctionIdExhausted)?;
        self.usage.variants += 1;
        self.usage.dynamic_parameters = next_dynamic;
        self.reserved.insert(
            key.clone(),
            ReservedVersion {
                temporary_id: temporary,
                built: false,
            },
        );
        self.worklist.push_back(key);
        Ok(temporary)
    }

    fn build_version(&mut self, key: VersionKey) -> Result<(), PolyvariantR1Error> {
        let reserved = self
            .reserved
            .get(&key)
            .cloned()
            .ok_or(PolyvariantR1Error::UnresolvedVariant)?;
        if reserved.built {
            return Ok(());
        }
        let source = self
            .functions
            .get(&key.source_function)
            .cloned()
            .ok_or(PolyvariantR1Error::MissingFunction(key.source_function))?;
        if source.parameters.len() != key.patterns.len() {
            return Err(PolyvariantR1Error::ArityMismatch {
                function: source.id,
                expected: source.parameters.len(),
                actual: key.patterns.len(),
            });
        }

        let mut environment = BTreeMap::new();
        let mut residual_parameters = Vec::new();
        for (parameter, pattern) in source.parameters.iter().zip(&key.patterns) {
            let value = match pattern {
                PolyvariantR1Pattern::Dynamic(ty) => {
                    residual_parameters.push(Parameter {
                        local: parameter.local,
                        ty: ty.clone(),
                    });
                    PartialScalar::Dynamic {
                        ty: ty.clone(),
                        operand: Operand::Local(parameter.local),
                    }
                }
                _ => PartialScalar::Known(value_from_pattern(pattern)?),
            };
            environment.insert(parameter.local, value);
        }
        let body = self.specialize_term(source.id, &source.body, &environment)?;
        let function = Function {
            id: reserved.temporary_id,
            region_parameters: Vec::new(),
            parameters: residual_parameters,
            effects: EffectRow::pure(),
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
            .ok_or(PolyvariantR1Error::UnresolvedVariant)?
            .built = true;
        Ok(())
    }

    fn specialize_term(
        &mut self,
        function: FunctionId,
        term: &Term,
        environment: &BTreeMap<LocalId, PartialScalar>,
    ) -> Result<Term, PolyvariantR1Error> {
        self.consume_step()?;
        match term {
            Term::Let {
                binder,
                ty,
                value,
                next,
            } => {
                self.consume_step()?;
                let specialized = self.specialize_rvalue(function, value, environment)?;
                let mut next_environment = environment.clone();
                match specialized {
                    SpecializedRValue::Elided(value) => {
                        next_environment.insert(*binder, value);
                        self.specialize_term(function, next, &next_environment)
                    }
                    SpecializedRValue::Residual(value) => {
                        next_environment.insert(
                            *binder,
                            PartialScalar::Dynamic {
                                ty: ty.clone(),
                                operand: Operand::Local(*binder),
                            },
                        );
                        let next = self.specialize_term(function, next, &next_environment)?;
                        Ok(Term::Let {
                            binder: *binder,
                            ty: ty.clone(),
                            value,
                            next: Box::new(next),
                        })
                    }
                }
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => match resolve_operand(function, condition, environment)? {
                PartialScalar::Known(SpecializationValue::Bool(true)) => {
                    self.specialize_term(function, then_term, environment)
                }
                PartialScalar::Known(SpecializationValue::Bool(false)) => {
                    self.specialize_term(function, else_term, environment)
                }
                PartialScalar::Dynamic {
                    ty: Type::Bool,
                    operand,
                } => {
                    self.consume_branch()?;
                    let then_term = self.specialize_term(function, then_term, environment)?;
                    let else_term = self.specialize_term(function, else_term, environment)?;
                    Ok(Term::If {
                        condition: operand,
                        then_term: Box::new(then_term),
                        else_term: Box::new(else_term),
                    })
                }
                _ => Err(PolyvariantR1Error::ExpectedBool { function }),
            },
            Term::TailCall {
                function: callee,
                arguments,
            } => {
                let partials = resolve_operands(function, arguments, environment)?;
                let (target, dynamic_arguments) = self.reserve_call(*callee, partials)?;
                Ok(Term::TailCall {
                    function: target,
                    arguments: dynamic_arguments,
                })
            }
            Term::Return(operand) => Ok(Term::Return(
                resolve_operand(function, operand, environment)?.residual_operand()?,
            )),
            Term::Case { .. } => Err(PolyvariantR1Error::UnsupportedNode {
                function,
                node: "Case",
            }),
            Term::Region { .. } => Err(PolyvariantR1Error::UnsupportedNode {
                function,
                node: "Region",
            }),
            Term::Handle { .. } => Err(PolyvariantR1Error::UnsupportedNode {
                function,
                node: "Handle",
            }),
        }
    }

    fn specialize_rvalue(
        &mut self,
        function: FunctionId,
        value: &RValue,
        environment: &BTreeMap<LocalId, PartialScalar>,
    ) -> Result<SpecializedRValue, PolyvariantR1Error> {
        match value {
            RValue::Use(operand) => Ok(SpecializedRValue::Elided(resolve_operand(
                function,
                operand,
                environment,
            )?)),
            RValue::Primitive {
                operation,
                arguments,
            } => {
                let partials = resolve_operands(function, arguments, environment)?;
                if partials
                    .iter()
                    .all(|value| matches!(value, PartialScalar::Known(_)))
                {
                    let values = partials
                        .into_iter()
                        .map(|value| match value {
                            PartialScalar::Known(value) => Ok(value),
                            PartialScalar::Dynamic { .. } => {
                                Err(PolyvariantR1Error::InternalInvariant {
                                    message: "all-known primitive carried a dynamic value"
                                        .to_owned(),
                                })
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(SpecializedRValue::Elided(PartialScalar::Known(
                        evaluate_primitive(operation, &values)?,
                    )))
                } else {
                    let arguments = partials
                        .iter()
                        .map(PartialScalar::residual_operand)
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(SpecializedRValue::Residual(RValue::Primitive {
                        operation: operation.clone(),
                        arguments,
                    }))
                }
            }
            RValue::Call {
                function: callee,
                arguments,
            } => {
                let partials = resolve_operands(function, arguments, environment)?;
                let (target, arguments) = self.reserve_call(*callee, partials)?;
                Ok(SpecializedRValue::Residual(RValue::Call {
                    function: target,
                    arguments,
                }))
            }
            RValue::Tuple(_) => Err(PolyvariantR1Error::UnsupportedNode {
                function,
                node: "Tuple rvalue",
            }),
            RValue::Project { .. } => Err(PolyvariantR1Error::UnsupportedNode {
                function,
                node: "Project rvalue",
            }),
            RValue::Construct { .. } => Err(PolyvariantR1Error::UnsupportedNode {
                function,
                node: "Construct rvalue",
            }),
            RValue::RefAlloc { .. }
            | RValue::RefLoad { .. }
            | RValue::RefStore { .. }
            | RValue::PackClosure { .. }
            | RValue::CallClosure { .. }
            | RValue::Perform { .. } => Err(PolyvariantR1Error::UnsupportedNode {
                function,
                node: "effectful or higher-order rvalue",
            }),
        }
    }

    fn reserve_call(
        &mut self,
        function: FunctionId,
        arguments: Vec<PartialScalar>,
    ) -> Result<(FunctionId, Vec<Operand>), PolyvariantR1Error> {
        let callee = self
            .functions
            .get(&function)
            .ok_or(PolyvariantR1Error::MissingFunction(function))?;
        if callee.parameters.len() != arguments.len() {
            return Err(PolyvariantR1Error::ArityMismatch {
                function,
                expected: callee.parameters.len(),
                actual: arguments.len(),
            });
        }
        let patterns = arguments
            .iter()
            .map(PartialScalar::pattern)
            .collect::<Result<Vec<_>, _>>()?;
        let residual_arguments = arguments
            .iter()
            .filter(|argument| matches!(argument, PartialScalar::Dynamic { .. }))
            .map(PartialScalar::residual_operand)
            .collect::<Result<Vec<_>, _>>()?;
        let target = self.reserve(VersionKey {
            source_function: function,
            patterns,
        })?;
        Ok((target, residual_arguments))
    }

    fn lower_program(
        mut self,
        entry_temporary: FunctionId,
        schema: &super::schema::SchemaVersion,
        profile: CoreProfile,
    ) -> Result<(Program, Vec<PolyvariantR1Variant>), PolyvariantR1Error> {
        let mut keyed_versions = std::mem::take(&mut self.built)
            .into_iter()
            .map(|version| Ok((version_key_bytes(&version.key)?, version)))
            .collect::<Result<Vec<_>, PolyvariantR1Error>>()?;
        keyed_versions.sort_by(|left, right| left.0.cmp(&right.0));
        self.built = keyed_versions
            .into_iter()
            .map(|(_, version)| version)
            .collect();
        let mut remap = BTreeMap::new();
        for (index, version) in self.built.iter().enumerate() {
            let final_id = u32::try_from(index)
                .map(FunctionId)
                .map_err(|_| PolyvariantR1Error::FunctionIdExhausted)?;
            remap.insert(version.temporary_id, final_id);
        }
        let entry = remap
            .get(&entry_temporary)
            .copied()
            .ok_or(PolyvariantR1Error::UnresolvedVariant)?;
        let mut descriptors = Vec::with_capacity(self.built.len());
        let mut functions = Vec::with_capacity(self.built.len());
        for mut version in self.built {
            let residual_function = remap
                .get(&version.temporary_id)
                .copied()
                .ok_or(PolyvariantR1Error::UnresolvedVariant)?;
            version.function.id = residual_function;
            rewrite_targets(&mut version.function.body, &remap)?;
            descriptors.push(PolyvariantR1Variant {
                source_function: version.key.source_function,
                residual_function,
                patterns: version.key.patterns,
            });
            functions.push(version.function);
        }
        Ok((
            Program {
                schema: schema.clone(),
                profile,
                entry,
                functions,
            },
            descriptors,
        ))
    }
}

enum SpecializedRValue {
    Elided(PartialScalar),
    Residual(RValue),
}

fn validate_budget(budget: PolyvariantR1Budget) -> Result<(), PolyvariantR1Error> {
    for (field, limit, hard_cap) in [
        ("max_steps", budget.max_steps, R1_S1_MAX_STEPS_HARD_CAP),
        (
            "max_variants",
            budget.max_variants,
            R1_S1_MAX_VARIANTS_HARD_CAP,
        ),
        (
            "max_branch_splits",
            budget.max_branch_splits,
            R1_S1_MAX_BRANCH_SPLITS_HARD_CAP,
        ),
        (
            "max_dynamic_parameters",
            budget.max_dynamic_parameters,
            R1_S1_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
        ),
    ] {
        if limit == 0 {
            return Err(PolyvariantR1Error::ZeroBudget { field });
        }
        if limit > hard_cap {
            return Err(PolyvariantR1Error::BudgetHardCapExceeded {
                field,
                limit,
                hard_cap,
            });
        }
    }
    Ok(())
}

fn is_scalar(ty: &Type) -> bool {
    matches!(ty, Type::Unit | Type::Bool | Type::I64 | Type::F64)
}

fn entry_pattern(
    parameter: &Parameter,
    slot: &SpecializationSlot,
) -> Result<PolyvariantR1Pattern, PolyvariantR1Error> {
    match slot {
        SpecializationSlot::Static(value) if is_scalar(&parameter.ty) => pattern_from_value(value)
            .map_err(|_| PolyvariantR1Error::InvalidEntrySlot {
                parameter: parameter.local,
            }),
        SpecializationSlot::Dynamic(ty) if is_scalar(ty) && *ty == parameter.ty => {
            Ok(PolyvariantR1Pattern::Dynamic(ty.clone()))
        }
        _ => Err(PolyvariantR1Error::InvalidEntrySlot {
            parameter: parameter.local,
        }),
    }
}

fn pattern_from_value(
    value: &SpecializationValue,
) -> Result<PolyvariantR1Pattern, PolyvariantR1Error> {
    Ok(match value {
        SpecializationValue::Unit => PolyvariantR1Pattern::KnownUnit,
        SpecializationValue::Bool(value) => PolyvariantR1Pattern::KnownBool(*value),
        SpecializationValue::I64(value) => PolyvariantR1Pattern::KnownI64(*value),
        SpecializationValue::F64(value) => {
            let bits = if value.is_nan() {
                CANONICAL_NAN_BITS
            } else {
                value.to_bits()
            };
            PolyvariantR1Pattern::KnownF64(bits)
        }
        _ => {
            return Err(PolyvariantR1Error::InternalInvariant {
                message: "aggregate value entered the scalar pattern domain".to_owned(),
            });
        }
    })
}

fn value_from_pattern(
    pattern: &PolyvariantR1Pattern,
) -> Result<SpecializationValue, PolyvariantR1Error> {
    Ok(match pattern {
        PolyvariantR1Pattern::KnownUnit => SpecializationValue::Unit,
        PolyvariantR1Pattern::KnownBool(value) => SpecializationValue::Bool(*value),
        PolyvariantR1Pattern::KnownI64(value) => SpecializationValue::I64(*value),
        PolyvariantR1Pattern::KnownF64(bits) => SpecializationValue::F64(f64::from_bits(*bits)),
        PolyvariantR1Pattern::Dynamic(_) => {
            return Err(PolyvariantR1Error::InternalInvariant {
                message: "dynamic pattern requested a static value".to_owned(),
            });
        }
    })
}

fn literal_from_value(value: &SpecializationValue) -> Result<Operand, PolyvariantR1Error> {
    Ok(match value {
        SpecializationValue::Unit => Operand::Unit,
        SpecializationValue::Bool(value) => Operand::Bool(*value),
        SpecializationValue::I64(value) => Operand::I64(*value),
        SpecializationValue::F64(value) => Operand::F64(*value),
        _ => {
            return Err(PolyvariantR1Error::InternalInvariant {
                message: "aggregate value requested a scalar literal".to_owned(),
            });
        }
    })
}

fn resolve_operand(
    function: FunctionId,
    operand: &Operand,
    environment: &BTreeMap<LocalId, PartialScalar>,
) -> Result<PartialScalar, PolyvariantR1Error> {
    Ok(match operand {
        Operand::Unit => PartialScalar::Known(SpecializationValue::Unit),
        Operand::Bool(value) => PartialScalar::Known(SpecializationValue::Bool(*value)),
        Operand::I64(value) => PartialScalar::Known(SpecializationValue::I64(*value)),
        Operand::F64(value) => PartialScalar::Known(SpecializationValue::F64(*value)),
        Operand::Local(local) => {
            environment
                .get(local)
                .cloned()
                .ok_or(PolyvariantR1Error::MissingLocal {
                    function,
                    local: *local,
                })?
        }
    })
}

fn resolve_operands(
    function: FunctionId,
    operands: &[Operand],
    environment: &BTreeMap<LocalId, PartialScalar>,
) -> Result<Vec<PartialScalar>, PolyvariantR1Error> {
    operands
        .iter()
        .map(|operand| resolve_operand(function, operand, environment))
        .collect()
}

fn evaluate_primitive(
    primitive: &Primitive,
    values: &[SpecializationValue],
) -> Result<SpecializationValue, PolyvariantR1Error> {
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
            Err(PolyvariantR1Error::InternalInvariant {
                message: "array primitive passed scalar admission".to_owned(),
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
) -> Result<i64, PolyvariantR1Error> {
    Ok(match (mode, operation) {
        (NumericMode::Wrapping, I64Operation::Add) => left.wrapping_add(right),
        (NumericMode::Wrapping, I64Operation::Sub) => left.wrapping_sub(right),
        (NumericMode::Wrapping, I64Operation::Mul) => left.wrapping_mul(right),
        (NumericMode::Saturating, I64Operation::Add) => left.saturating_add(right),
        (NumericMode::Saturating, I64Operation::Sub) => left.saturating_sub(right),
        (NumericMode::Saturating, I64Operation::Mul) => left.saturating_mul(right),
        (NumericMode::Checked, _) => {
            return Err(PolyvariantR1Error::InternalInvariant {
                message: "checked arithmetic passed pure scalar admission".to_owned(),
            });
        }
    })
}

fn i64_pair(values: &[SpecializationValue]) -> Result<(i64, i64), PolyvariantR1Error> {
    let [SpecializationValue::I64(left), SpecializationValue::I64(right)] = values else {
        return Err(PolyvariantR1Error::InternalInvariant {
            message: "verified I64 primitive argument mismatch".to_owned(),
        });
    };
    Ok((*left, *right))
}

fn f64_pair(values: &[SpecializationValue]) -> Result<(f64, f64), PolyvariantR1Error> {
    let [SpecializationValue::F64(left), SpecializationValue::F64(right)] = values else {
        return Err(PolyvariantR1Error::InternalInvariant {
            message: "verified F64 primitive argument mismatch".to_owned(),
        });
    };
    Ok((*left, *right))
}

fn admit_reachable_subset(
    entry: FunctionId,
    functions: &BTreeMap<FunctionId, Function>,
) -> Result<BTreeMap<FunctionId, Vec<FunctionId>>, PolyvariantR1Error> {
    let mut graph = BTreeMap::new();
    let mut pending = vec![entry];
    let mut visited = BTreeSet::new();
    while let Some(function_id) = pending.pop() {
        if !visited.insert(function_id) {
            continue;
        }
        let function = functions
            .get(&function_id)
            .ok_or(PolyvariantR1Error::MissingFunction(function_id))?;
        admit_function(function)?;
        let mut callees = Vec::new();
        collect_calls(&function.body, &mut callees);
        callees.sort();
        callees.dedup();
        for callee in callees.iter().rev() {
            if !functions.contains_key(callee) {
                return Err(PolyvariantR1Error::MissingFunction(*callee));
            }
            pending.push(*callee);
        }
        graph.insert(function_id, callees);
    }
    Ok(graph)
}

fn admit_function(function: &Function) -> Result<(), PolyvariantR1Error> {
    if !function.region_parameters.is_empty() {
        return Err(PolyvariantR1Error::UnsupportedRegionParameters {
            function: function.id,
        });
    }
    if !function.effects.effects.is_empty() {
        return Err(PolyvariantR1Error::UnsupportedEffects {
            function: function.id,
        });
    }
    for parameter in &function.parameters {
        admit_type(function.id, "parameter", &parameter.ty)?;
    }
    admit_type(function.id, "result", &function.result)?;
    admit_term(function.id, &function.body)
}

fn admit_type(
    function: FunctionId,
    context: &'static str,
    ty: &Type,
) -> Result<(), PolyvariantR1Error> {
    if is_scalar(ty) {
        Ok(())
    } else {
        Err(PolyvariantR1Error::UnsupportedType {
            function,
            context,
            ty: ty.clone(),
        })
    }
}

fn admit_term(function: FunctionId, term: &Term) -> Result<(), PolyvariantR1Error> {
    match term {
        Term::Let {
            ty, value, next, ..
        } => {
            admit_type(function, "local", ty)?;
            admit_rvalue(function, value)?;
            admit_term(function, next)
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            admit_term(function, then_term)?;
            admit_term(function, else_term)
        }
        Term::TailCall { .. } | Term::Return(_) => Ok(()),
        Term::Case { .. } => Err(PolyvariantR1Error::UnsupportedNode {
            function,
            node: "Case",
        }),
        Term::Region { .. } => Err(PolyvariantR1Error::UnsupportedNode {
            function,
            node: "Region",
        }),
        Term::Handle { .. } => Err(PolyvariantR1Error::UnsupportedNode {
            function,
            node: "Handle",
        }),
    }
}

fn admit_rvalue(function: FunctionId, value: &RValue) -> Result<(), PolyvariantR1Error> {
    match value {
        RValue::Use(_) | RValue::Call { .. } => Ok(()),
        RValue::Primitive { operation, .. } => match operation {
            Primitive::I64Add(NumericMode::Wrapping | NumericMode::Saturating)
            | Primitive::I64Sub(NumericMode::Wrapping | NumericMode::Saturating)
            | Primitive::I64Mul(NumericMode::Wrapping | NumericMode::Saturating)
            | Primitive::F64Add
            | Primitive::F64Sub
            | Primitive::I64CmpLt
            | Primitive::I64CmpGe => Ok(()),
            _ => Err(PolyvariantR1Error::UnsupportedPrimitive {
                function,
                primitive: operation.clone(),
            }),
        },
        RValue::Tuple(_) => Err(PolyvariantR1Error::UnsupportedNode {
            function,
            node: "Tuple rvalue",
        }),
        RValue::Project { .. } => Err(PolyvariantR1Error::UnsupportedNode {
            function,
            node: "Project rvalue",
        }),
        RValue::Construct { .. } => Err(PolyvariantR1Error::UnsupportedNode {
            function,
            node: "Construct rvalue",
        }),
        RValue::RefAlloc { .. }
        | RValue::RefLoad { .. }
        | RValue::RefStore { .. }
        | RValue::PackClosure { .. }
        | RValue::CallClosure { .. }
        | RValue::Perform { .. } => Err(PolyvariantR1Error::UnsupportedNode {
            function,
            node: "effectful or higher-order rvalue",
        }),
    }
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

fn count_recursive_components(graph: &BTreeMap<FunctionId, Vec<FunctionId>>) -> usize {
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
    let mut recursive = 0;
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
        let is_recursive = component.len() > 1
            || component.iter().any(|node| {
                graph
                    .get(node)
                    .is_some_and(|targets| targets.contains(node))
            });
        recursive += usize::from(is_recursive);
    }
    recursive
}

fn rewrite_targets(
    term: &mut Term,
    remap: &BTreeMap<FunctionId, FunctionId>,
) -> Result<(), PolyvariantR1Error> {
    match term {
        Term::Let { value, next, .. } => {
            if let RValue::Call { function, .. } = value {
                *function = remap
                    .get(function)
                    .copied()
                    .ok_or(PolyvariantR1Error::UnresolvedVariant)?;
            }
            rewrite_targets(next, remap)
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            rewrite_targets(then_term, remap)?;
            rewrite_targets(else_term, remap)
        }
        Term::TailCall { function, .. } => {
            *function = remap
                .get(function)
                .copied()
                .ok_or(PolyvariantR1Error::UnresolvedVariant)?;
            Ok(())
        }
        Term::Return(_) => Ok(()),
        Term::Case { arms, .. } => {
            for arm in arms {
                rewrite_targets(&mut arm.body, remap)?;
            }
            Ok(())
        }
        Term::Region { body, .. } => rewrite_targets(body, remap),
        Term::Handle { clauses, body, .. } => {
            for clause in clauses {
                rewrite_targets(&mut clause.body, remap)?;
            }
            rewrite_targets(body, remap)
        }
    }
}

fn version_key_bytes(key: &VersionKey) -> Result<Vec<u8>, PolyvariantR1Error> {
    let mut bytes = VERSION_KEY_DOMAIN.to_vec();
    bytes.extend_from_slice(&key.source_function.0.to_be_bytes());
    let pattern_count =
        u32::try_from(key.patterns.len()).map_err(|_| PolyvariantR1Error::InternalInvariant {
            message: "R1-S1 version-key arity exceeds U32".to_owned(),
        })?;
    bytes.extend_from_slice(&pattern_count.to_be_bytes());
    for pattern in &key.patterns {
        match pattern {
            PolyvariantR1Pattern::KnownUnit => bytes.push(0),
            PolyvariantR1Pattern::KnownBool(value) => {
                bytes.push(1);
                bytes.push(u8::from(*value));
            }
            PolyvariantR1Pattern::KnownI64(value) => {
                bytes.push(2);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            PolyvariantR1Pattern::KnownF64(bits) => {
                bytes.push(3);
                bytes.extend_from_slice(&bits.to_be_bytes());
            }
            PolyvariantR1Pattern::Dynamic(ty) => {
                bytes.push(4);
                let tag = match ty {
                    Type::Unit => 0,
                    Type::Bool => 1,
                    Type::I64 => 2,
                    Type::F64 => 3,
                    _ => {
                        return Err(PolyvariantR1Error::UnsupportedType {
                            function: key.source_function,
                            context: "version pattern",
                            ty: ty.clone(),
                        });
                    }
                };
                bytes.push(tag);
            }
        }
    }
    Ok(bytes)
}

fn polyvariant_request_hash(
    source_hash: SemanticHash,
    upstream_request_hash: SemanticHash,
    entry: FunctionId,
    budget: PolyvariantR1Budget,
    policy_hash: SemanticHash,
) -> SemanticHash {
    let mut bytes = REQUEST_DOMAIN.to_vec();
    put_version(&mut bytes, POLYVARIANT_R1_S1_VERSION);
    bytes.extend_from_slice(&source_hash.0);
    bytes.extend_from_slice(&upstream_request_hash.0);
    bytes.extend_from_slice(&policy_hash.0);
    bytes.extend_from_slice(&entry.0.to_be_bytes());
    for limit in [
        budget.max_steps,
        budget.max_variants,
        budget.max_branch_splits,
        budget.max_dynamic_parameters,
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
