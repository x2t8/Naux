use super::encoding::{semantic_bytes, EncodeError};
use super::schema::{
    CaseArm, CoreArtifact, Function, LocalId, Operand, Parameter, Program, RValue, SemanticHash,
    Term,
};
use super::specialization::{
    SpecializationSlot, SpecializationValue, ValidatedSpecializationRequest,
};
use super::static_evaluate_r0b2::{MixedStaticEvaluation, MixedStaticOutcome};
use super::verify::{verify, VerificationErrors};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct ResidualCore {
    pub artifact: CoreArtifact,
    pub source_hash: SemanticHash,
    pub request_hash: SemanticHash,
    pub residual_nodes: u64,
    pub residual_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResidualGenerationError {
    RecordMismatch {
        expected: SemanticHash,
        actual: SemanticHash,
    },
    UnsupportedStaticSlot {
        parameter: LocalId,
    },
    UnsupportedCompleteResult,
    UnsupportedLiveStaticValue {
        local: Option<LocalId>,
    },
    FreshLocalExhausted,
    ResidualNodeBudgetExceeded {
        limit: u64,
        used: u64,
    },
    ResidualByteBudgetExceeded {
        limit: u64,
        used: u64,
    },
    ResidualRejected(VerificationErrors),
    EncodingFailure(EncodeError),
    InternalInvariant {
        message: String,
    },
}

impl fmt::Display for ResidualGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordMismatch { expected, actual } => write!(
                formatter,
                "R0-C evaluation record binds request {actual} but the validated request is {expected}"
            ),
            Self::UnsupportedStaticSlot { parameter } => write!(
                formatter,
                "R0-C1 admits only scalar static entry slots; parameter local {} is aggregate",
                parameter.0
            ),
            Self::UnsupportedCompleteResult => write!(
                formatter,
                "R0-C1 admits only scalar complete results"
            ),
            Self::UnsupportedLiveStaticValue { local: Some(local) } => write!(
                formatter,
                "R0-C cannot materialize live static value at local {} in the selected Core profile",
                local.0
            ),
            Self::UnsupportedLiveStaticValue { local: None } => write!(
                formatter,
                "R0-C cannot materialize the static result in the selected Core profile"
            ),
            Self::FreshLocalExhausted => {
                write!(formatter, "R0-C exhausted the LocalId namespace")
            }
            Self::ResidualNodeBudgetExceeded { limit, used } => write!(
                formatter,
                "R0-C residual program has {used} node(s), exceeding max_residual_nodes {limit}"
            ),
            Self::ResidualByteBudgetExceeded { limit, used } => write!(
                formatter,
                "R0-C residual program encodes to {used} byte(s), exceeding max_residual_bytes {limit}"
            ),
            Self::ResidualRejected(errors) => {
                write!(formatter, "R0-C residual artifact failed verification: ")?;
                let mut first = true;
                for error in &errors.0 {
                    if !first {
                        write!(formatter, "; ")?;
                    }
                    first = false;
                    write!(formatter, "{} at {}", error.message, error.path)?;
                }
                Ok(())
            }
            Self::EncodingFailure(error) => {
                write!(formatter, "R0-C residual program failed to encode: {error:?}")
            }
            Self::InternalInvariant { message } => {
                write!(formatter, "R0-C invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for ResidualGenerationError {}

/// Generate the bounded R0-C1 Residual Core artifact from a validated
/// specialization request and its R0-B2 evaluation record.
///
/// The generator substitutes scalar static facts at their unique `Let`
/// binding sites, binds scalar static entry parameters in a prologue, and
/// preserves every skipped and untaken computation verbatim. The residual
/// program must fit the declared residual node and byte budgets and pass the
/// ordinary Core verifier before it is returned. Aggregate static slots and
/// aggregate complete results fail closed.
pub fn generate_residual_r0c(
    validated: &ValidatedSpecializationRequest<'_, '_>,
    evaluation: &MixedStaticEvaluation,
) -> Result<ResidualCore, ResidualGenerationError> {
    if evaluation.request_hash() != validated.request_hash() {
        return Err(ResidualGenerationError::RecordMismatch {
            expected: validated.request_hash(),
            actual: evaluation.request_hash(),
        });
    }
    let source = &validated.artifact().program;
    let entry = source
        .functions
        .iter()
        .find(|function| function.id == source.entry)
        .ok_or_else(|| ResidualGenerationError::InternalInvariant {
            message: "validated source has no entry function".to_owned(),
        })?;
    if entry.parameters.len() != validated.request().entry_slots.len() {
        return Err(ResidualGenerationError::InternalInvariant {
            message: "validated entry slots do not match the entry arity".to_owned(),
        });
    }

    let mut static_bindings = Vec::new();
    let mut dynamic_parameters = Vec::new();
    for (parameter, slot) in entry
        .parameters
        .iter()
        .zip(&validated.request().entry_slots)
    {
        match slot {
            SpecializationSlot::Static(value) => {
                let literal = scalar_literal(value).ok_or(
                    ResidualGenerationError::UnsupportedStaticSlot {
                        parameter: parameter.local,
                    },
                )?;
                static_bindings.push((parameter.clone(), literal));
            }
            SpecializationSlot::Dynamic(_) => dynamic_parameters.push(parameter.clone()),
        }
    }

    let body = match evaluation.outcome() {
        MixedStaticOutcome::Complete(value) => {
            if evaluation.skipped_nodes().is_empty() {
                // Every reachable computation executed statically, so the
                // residual collapses to its constant result.
                let literal = scalar_literal(value)
                    .ok_or(ResidualGenerationError::UnsupportedCompleteResult)?;
                Term::Return(literal)
            } else {
                // Skipped work may carry observable typed effects at run
                // time, so the whole body is preserved; without frontier
                // facts no substitution is available.
                prologue(&static_bindings, entry.body.clone())
            }
        }
        MixedStaticOutcome::MixedFrontier { static_facts, .. } => {
            let mut facts = BTreeMap::new();
            for fact in static_facts {
                if let Some(literal) = scalar_literal(&fact.value) {
                    facts.insert(fact.local, literal);
                }
            }
            prologue(&static_bindings, substitute_term(&entry.body, &facts))
        }
    };

    let residual_entry = Function {
        id: entry.id,
        region_parameters: entry.region_parameters.clone(),
        parameters: dynamic_parameters,
        effects: entry.effects.clone(),
        result: entry.result.clone(),
        body,
    };
    let functions = source
        .functions
        .iter()
        .map(|function| {
            if function.id == source.entry {
                residual_entry.clone()
            } else {
                function.clone()
            }
        })
        .collect();
    let program = Program {
        schema: source.schema.clone(),
        profile: source.profile,
        entry: source.entry,
        functions,
    };

    finalize_residual(validated, program)
}

pub(super) fn finalize_residual(
    validated: &ValidatedSpecializationRequest<'_, '_>,
    program: Program,
) -> Result<ResidualCore, ResidualGenerationError> {
    let budget = validated.request().budget;
    finalize_residual_with_limits(
        validated.artifact().semantic_hash,
        validated.request_hash(),
        program,
        budget.max_residual_nodes,
        budget.max_residual_bytes,
    )
}

pub(super) fn finalize_residual_with_limits(
    source_hash: SemanticHash,
    request_hash: SemanticHash,
    program: Program,
    max_residual_nodes: u64,
    max_residual_bytes: u64,
) -> Result<ResidualCore, ResidualGenerationError> {
    let residual_nodes = count_program_nodes(&program);
    if residual_nodes > max_residual_nodes {
        return Err(ResidualGenerationError::ResidualNodeBudgetExceeded {
            limit: max_residual_nodes,
            used: residual_nodes,
        });
    }
    let bytes = semantic_bytes(&program).map_err(ResidualGenerationError::EncodingFailure)?;
    let residual_bytes = bytes.len() as u64;
    if residual_bytes > max_residual_bytes {
        return Err(ResidualGenerationError::ResidualByteBudgetExceeded {
            limit: max_residual_bytes,
            used: residual_bytes,
        });
    }

    let artifact = CoreArtifact::seal(program).map_err(ResidualGenerationError::EncodingFailure)?;
    verify(&artifact).map_err(ResidualGenerationError::ResidualRejected)?;

    Ok(ResidualCore {
        source_hash,
        request_hash,
        residual_nodes,
        residual_bytes,
        artifact,
    })
}

pub(super) fn scalar_literal(value: &SpecializationValue) -> Option<Operand> {
    match value {
        SpecializationValue::Unit => Some(Operand::Unit),
        SpecializationValue::Bool(value) => Some(Operand::Bool(*value)),
        SpecializationValue::I64(value) => Some(Operand::I64(*value)),
        SpecializationValue::F64(value) => Some(Operand::F64(*value)),
        SpecializationValue::Tuple(_)
        | SpecializationValue::Sum { .. }
        | SpecializationValue::ArrayF64(_) => None,
    }
}

/// Bind each scalar static entry parameter at the top of the residual body,
/// in original parameter order.
fn prologue(static_bindings: &[(Parameter, Operand)], body: Term) -> Term {
    static_bindings
        .iter()
        .rev()
        .fold(body, |next, (parameter, literal)| Term::Let {
            binder: parameter.local,
            ty: parameter.ty.clone(),
            value: RValue::Use(literal.clone()),
            next: Box::new(next),
        })
}

/// Rewrite every `Let` whose binder carries a scalar static fact into a
/// literal `Use`. Binders are unique per verified function (the Core
/// verifier rejects duplicates), so substitution by binder is exact.
fn substitute_term(term: &Term, facts: &BTreeMap<LocalId, Operand>) -> Term {
    match term {
        Term::Let {
            binder,
            ty,
            value,
            next,
        } => Term::Let {
            binder: *binder,
            ty: ty.clone(),
            value: match facts.get(binder) {
                Some(literal) => RValue::Use(literal.clone()),
                None => value.clone(),
            },
            next: Box::new(substitute_term(next, facts)),
        },
        Term::If {
            condition,
            then_term,
            else_term,
        } => Term::If {
            condition: condition.clone(),
            then_term: Box::new(substitute_term(then_term, facts)),
            else_term: Box::new(substitute_term(else_term, facts)),
        },
        Term::Case { scrutinee, arms } => Term::Case {
            scrutinee: scrutinee.clone(),
            arms: arms
                .iter()
                .map(|arm| CaseArm {
                    constructor: arm.constructor,
                    bindings: arm.bindings.clone(),
                    body: substitute_term(&arm.body, facts),
                })
                .collect(),
        },
        Term::Region { region, body } => Term::Region {
            region: *region,
            body: Box::new(substitute_term(body, facts)),
        },
        Term::Handle {
            captures,
            capture_parameters,
            clauses,
            body,
        } => Term::Handle {
            captures: captures.clone(),
            capture_parameters: capture_parameters.clone(),
            clauses: clauses.clone(),
            body: Box::new(substitute_term(body, facts)),
        },
        Term::TailCall { .. } | Term::Return(_) => term.clone(),
    }
}

/// Residual size metric locked by ADR-0026: one node per term, rvalue, and
/// operand in every function of the residual program.
pub(super) fn count_program_nodes(program: &Program) -> u64 {
    program
        .functions
        .iter()
        .map(|function| count_term_nodes(&function.body))
        .sum()
}

fn count_term_nodes(term: &Term) -> u64 {
    1 + match term {
        Term::Let { value, next, .. } => count_rvalue_nodes(value) + count_term_nodes(next),
        Term::If {
            then_term,
            else_term,
            ..
        } => 1 + count_term_nodes(then_term) + count_term_nodes(else_term),
        Term::Case { arms, .. } => {
            1 + arms
                .iter()
                .map(|arm| count_term_nodes(&arm.body))
                .sum::<u64>()
        }
        Term::TailCall { arguments, .. } => arguments.len() as u64,
        Term::Return(_) => 1,
        Term::Region { body, .. } => count_term_nodes(body),
        Term::Handle {
            captures,
            clauses,
            body,
            ..
        } => {
            captures.len() as u64
                + clauses
                    .iter()
                    .map(|clause| count_term_nodes(&clause.body))
                    .sum::<u64>()
                + count_term_nodes(body)
        }
    }
}

fn count_rvalue_nodes(rvalue: &RValue) -> u64 {
    1 + match rvalue {
        RValue::Use(_) | RValue::Project { .. } | RValue::RefLoad { .. } => 1,
        RValue::Tuple(operands) => operands.len() as u64,
        RValue::Construct { fields, .. } => fields.len() as u64,
        RValue::Primitive { arguments, .. }
        | RValue::Call { arguments, .. }
        | RValue::Perform { arguments, .. } => arguments.len() as u64,
        RValue::RefAlloc { .. } => 1,
        RValue::RefStore { .. } => 2,
        RValue::PackClosure { captures, .. } => captures.len() as u64,
        RValue::CallClosure { arguments, .. } => 1 + arguments.len() as u64,
    }
}
