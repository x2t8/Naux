use super::residual::{finalize_residual, scalar_literal, ResidualCore, ResidualGenerationError};
use super::schema::{
    CaseArm, Function, FunctionId, HandlerClause, LocalId, Operand, Parameter, Program, RValue,
    Term, Type,
};
use super::specialization::{
    SpecializationSlot, SpecializationValue, ValidatedSpecializationRequest,
};
use super::static_evaluate_r0b2::{MixedStaticEvaluation, MixedStaticOutcome};
use std::collections::{BTreeMap, BTreeSet};

type StaticFacts = BTreeMap<LocalId, SpecializationValue>;

#[derive(Clone)]
struct MaterializedBinding {
    binder: LocalId,
    ty: Type,
    value: RValue,
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

    fn allocate(&mut self) -> Result<LocalId, ResidualGenerationError> {
        let local = self
            .next
            .ok_or(ResidualGenerationError::FreshLocalExhausted)?;
        self.next = local.checked_add(1);
        Ok(LocalId(local))
    }
}

/// Generate the R0-C2 folded Residual Core artifact.
///
/// R0-C2 consumes only an opaque R0-B2 record associated with the validated
/// request. It materializes live scalar/Tuple/Sum facts, folds statically
/// known `If` and `Case` control, removes calls whose binders have static
/// facts, and prunes functions that become unreachable. Static arrays are
/// admitted only when transformation removes every runtime use.
pub fn generate_residual_r0c2(
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

    let mut dynamic_parameters = Vec::new();
    let mut static_parameters = Vec::new();
    let mut entry_facts = StaticFacts::new();
    for (parameter, slot) in entry
        .parameters
        .iter()
        .zip(&validated.request().entry_slots)
    {
        match slot {
            SpecializationSlot::Static(value) => {
                static_parameters.push((parameter.clone(), value.clone()));
                entry_facts.insert(parameter.local, value.clone());
            }
            SpecializationSlot::Dynamic(_) => dynamic_parameters.push(parameter.clone()),
        }
    }

    let mut fresh = FreshLocals::for_function(entry);
    let body = match evaluation.outcome() {
        MixedStaticOutcome::Complete(value) if evaluation.skipped_nodes().is_empty() => {
            materialize_result(value, &entry.result, &mut fresh)?
        }
        MixedStaticOutcome::Complete(_) => {
            let transformed = transform_term(&entry.body, &entry_facts, &mut fresh)?;
            prepend_static_parameters(transformed, &static_parameters, &mut fresh)?
        }
        MixedStaticOutcome::MixedFrontier { static_facts, .. } => {
            let mut facts = entry_facts;
            for fact in static_facts {
                facts.insert(fact.local, fact.value.clone());
            }
            let transformed = transform_term(&entry.body, &facts, &mut fresh)?;
            prepend_static_parameters(transformed, &static_parameters, &mut fresh)?
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
    let candidate_functions: Vec<_> = source
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
    let reachable = reachable_functions(source.entry, &candidate_functions)?;
    let functions = candidate_functions
        .into_iter()
        .filter(|function| reachable.contains(&function.id))
        .collect();
    let program = Program {
        schema: source.schema.clone(),
        profile: source.profile,
        entry: source.entry,
        functions,
    };

    finalize_residual(validated, program)
}

fn transform_term(
    term: &Term,
    facts: &StaticFacts,
    fresh: &mut FreshLocals,
) -> Result<Term, ResidualGenerationError> {
    match term {
        Term::Let {
            binder,
            ty,
            value,
            next,
        } => {
            let next = transform_term(next, facts, fresh)?;
            let Some(static_value) = facts.get(binder) else {
                return Ok(Term::Let {
                    binder: *binder,
                    ty: ty.clone(),
                    value: value.clone(),
                    next: Box::new(next),
                });
            };

            // The R0-B2 fact proves this pure binding was evaluated. If all
            // residual reads disappeared, the binding (including a static
            // call or unrepresentable array) disappears as well.
            if !term_reads_local(&next, *binder) {
                return Ok(next);
            }
            materialize_binding(static_value, ty, *binder, next, fresh)
        }
        Term::If {
            condition,
            then_term,
            else_term,
        } => match resolve_operand(condition, facts) {
            Some(SpecializationValue::Bool(true)) => transform_term(then_term, facts, fresh),
            Some(SpecializationValue::Bool(false)) => transform_term(else_term, facts, fresh),
            Some(_) => Err(ResidualGenerationError::InternalInvariant {
                message: "verified If condition resolved to a non-Bool static value".to_owned(),
            }),
            None => Ok(Term::If {
                condition: condition.clone(),
                then_term: Box::new(transform_term(then_term, facts, fresh)?),
                else_term: Box::new(transform_term(else_term, facts, fresh)?),
            }),
        },
        Term::Case { scrutinee, arms } => match resolve_operand(scrutinee, facts) {
            Some(SpecializationValue::Sum {
                ty,
                constructor,
                fields,
            }) => {
                let arm = arms.get(constructor as usize).ok_or_else(|| {
                    ResidualGenerationError::InternalInvariant {
                        message: "verified static Case constructor is out of range".to_owned(),
                    }
                })?;
                let constructor_type =
                    ty.constructors.get(constructor as usize).ok_or_else(|| {
                        ResidualGenerationError::InternalInvariant {
                            message: "static Sum constructor is absent from its type".to_owned(),
                        }
                    })?;
                if arm.bindings.len() != fields.len()
                    || constructor_type.fields.len() != fields.len()
                {
                    return Err(ResidualGenerationError::InternalInvariant {
                        message: "static Case field arity does not match the selected arm"
                            .to_owned(),
                    });
                }

                let body = transform_term(&arm.body, facts, fresh)?;
                prepend_case_fields(
                    body,
                    &arm.bindings,
                    &constructor_type.fields,
                    &fields,
                    fresh,
                )
            }
            Some(_) => Err(ResidualGenerationError::InternalInvariant {
                message: "verified Case scrutinee resolved to a non-Sum static value".to_owned(),
            }),
            None => Ok(Term::Case {
                scrutinee: scrutinee.clone(),
                arms: arms
                    .iter()
                    .map(|arm| {
                        Ok(CaseArm {
                            constructor: arm.constructor,
                            bindings: arm.bindings.clone(),
                            body: transform_term(&arm.body, facts, fresh)?,
                        })
                    })
                    .collect::<Result<Vec<_>, ResidualGenerationError>>()?,
            }),
        },
        Term::TailCall { .. } | Term::Return(_) => Ok(term.clone()),
        Term::Region { region, body } => Ok(Term::Region {
            region: *region,
            body: Box::new(transform_term(body, facts, fresh)?),
        }),
        Term::Handle {
            captures,
            capture_parameters,
            clauses,
            body,
        } => Ok(Term::Handle {
            captures: captures.clone(),
            capture_parameters: capture_parameters.clone(),
            clauses: clauses
                .iter()
                .map(|clause| {
                    Ok(HandlerClause {
                        operation: clause.operation.clone(),
                        parameters: clause.parameters.clone(),
                        body: Box::new(transform_term(&clause.body, facts, fresh)?),
                    })
                })
                .collect::<Result<Vec<_>, ResidualGenerationError>>()?,
            body: Box::new(transform_term(body, facts, fresh)?),
        }),
    }
}

fn prepend_static_parameters(
    body: Term,
    static_parameters: &[(Parameter, SpecializationValue)],
    fresh: &mut FreshLocals,
) -> Result<Term, ResidualGenerationError> {
    let mut bindings = Vec::new();
    for (parameter, value) in static_parameters {
        if term_reads_local(&body, parameter.local) {
            build_value(
                value,
                &parameter.ty,
                Some(parameter.local),
                Some(parameter.local),
                fresh,
                &mut bindings,
            )?;
        }
    }
    Ok(wrap_bindings(bindings, body))
}

fn prepend_case_fields(
    body: Term,
    locals: &[LocalId],
    types: &[Type],
    values: &[SpecializationValue],
    fresh: &mut FreshLocals,
) -> Result<Term, ResidualGenerationError> {
    let mut bindings = Vec::new();
    for ((local, ty), value) in locals.iter().zip(types).zip(values) {
        if term_reads_local(&body, *local) {
            build_value(value, ty, Some(*local), Some(*local), fresh, &mut bindings)?;
        }
    }
    Ok(wrap_bindings(bindings, body))
}

fn materialize_binding(
    value: &SpecializationValue,
    ty: &Type,
    binder: LocalId,
    next: Term,
    fresh: &mut FreshLocals,
) -> Result<Term, ResidualGenerationError> {
    let mut bindings = Vec::new();
    build_value(value, ty, Some(binder), Some(binder), fresh, &mut bindings)?;
    Ok(wrap_bindings(bindings, next))
}

fn materialize_result(
    value: &SpecializationValue,
    ty: &Type,
    fresh: &mut FreshLocals,
) -> Result<Term, ResidualGenerationError> {
    if let Some(literal) = scalar_literal(value) {
        ensure_scalar_type(value, ty)?;
        return Ok(Term::Return(literal));
    }
    let mut bindings = Vec::new();
    let operand = build_value(value, ty, None, None, fresh, &mut bindings)?;
    Ok(wrap_bindings(bindings, Term::Return(operand)))
}

fn build_value(
    value: &SpecializationValue,
    ty: &Type,
    target: Option<LocalId>,
    root_local: Option<LocalId>,
    fresh: &mut FreshLocals,
    bindings: &mut Vec<MaterializedBinding>,
) -> Result<Operand, ResidualGenerationError> {
    if let Some(literal) = scalar_literal(value) {
        ensure_scalar_type(value, ty)?;
        return match target {
            Some(binder) => {
                bindings.push(MaterializedBinding {
                    binder,
                    ty: ty.clone(),
                    value: RValue::Use(literal),
                });
                Ok(Operand::Local(binder))
            }
            None => Ok(literal),
        };
    }

    match (value, ty) {
        (SpecializationValue::Tuple(values), Type::Tuple(types)) if values.len() == types.len() => {
            let mut fields = Vec::with_capacity(values.len());
            for (value, ty) in values.iter().zip(types) {
                fields.push(build_value(value, ty, None, root_local, fresh, bindings)?);
            }
            let binder = match target {
                Some(target) => target,
                None => fresh.allocate()?,
            };
            bindings.push(MaterializedBinding {
                binder,
                ty: ty.clone(),
                value: RValue::Tuple(fields),
            });
            Ok(Operand::Local(binder))
        }
        (
            SpecializationValue::Sum {
                ty: value_type,
                constructor,
                fields: values,
            },
            Type::Sum(expected_type),
        ) if value_type == expected_type => {
            let constructor_type = expected_type
                .constructors
                .get(*constructor as usize)
                .ok_or_else(|| ResidualGenerationError::InternalInvariant {
                    message: "static Sum constructor is absent from its type".to_owned(),
                })?;
            if values.len() != constructor_type.fields.len() {
                return Err(ResidualGenerationError::InternalInvariant {
                    message: "static Sum field arity does not match its constructor".to_owned(),
                });
            }
            let mut fields = Vec::with_capacity(values.len());
            for (value, ty) in values.iter().zip(&constructor_type.fields) {
                fields.push(build_value(value, ty, None, root_local, fresh, bindings)?);
            }
            let binder = match target {
                Some(target) => target,
                None => fresh.allocate()?,
            };
            bindings.push(MaterializedBinding {
                binder,
                ty: ty.clone(),
                value: RValue::Construct {
                    sum: expected_type.clone(),
                    constructor: *constructor,
                    fields,
                },
            });
            Ok(Operand::Local(binder))
        }
        (SpecializationValue::ArrayF64(_), Type::Array { .. }) => {
            Err(ResidualGenerationError::UnsupportedLiveStaticValue { local: root_local })
        }
        _ => Err(ResidualGenerationError::InternalInvariant {
            message: format!("static value {value:?} does not match residual type {ty:?}"),
        }),
    }
}

fn ensure_scalar_type(
    value: &SpecializationValue,
    ty: &Type,
) -> Result<(), ResidualGenerationError> {
    let matches = matches!(
        (value, ty),
        (SpecializationValue::Unit, Type::Unit)
            | (SpecializationValue::Bool(_), Type::Bool)
            | (SpecializationValue::I64(_), Type::I64)
            | (SpecializationValue::F64(_), Type::F64)
    );
    if matches {
        Ok(())
    } else {
        Err(ResidualGenerationError::InternalInvariant {
            message: format!("static scalar {value:?} does not match residual type {ty:?}"),
        })
    }
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

fn resolve_operand(operand: &Operand, facts: &StaticFacts) -> Option<SpecializationValue> {
    match operand {
        Operand::Unit => Some(SpecializationValue::Unit),
        Operand::Bool(value) => Some(SpecializationValue::Bool(*value)),
        Operand::I64(value) => Some(SpecializationValue::I64(*value)),
        Operand::F64(value) => Some(SpecializationValue::F64(*value)),
        Operand::Local(local) => facts.get(local).cloned(),
    }
}

fn term_reads_local(term: &Term, target: LocalId) -> bool {
    match term {
        Term::Let { value, next, .. } => {
            rvalue_reads_local(value, target) || term_reads_local(next, target)
        }
        Term::If {
            condition,
            then_term,
            else_term,
        } => {
            operand_reads_local(condition, target)
                || term_reads_local(then_term, target)
                || term_reads_local(else_term, target)
        }
        Term::Case { scrutinee, arms } => {
            operand_reads_local(scrutinee, target)
                || arms.iter().any(|arm| term_reads_local(&arm.body, target))
        }
        Term::TailCall { arguments, .. } => operands_read_local(arguments, target),
        Term::Return(operand) => operand_reads_local(operand, target),
        Term::Region { body, .. } => term_reads_local(body, target),
        Term::Handle {
            captures,
            clauses,
            body,
            ..
        } => {
            operands_read_local(captures, target)
                || clauses
                    .iter()
                    .any(|clause| term_reads_local(&clause.body, target))
                || term_reads_local(body, target)
        }
    }
}

fn rvalue_reads_local(value: &RValue, target: LocalId) -> bool {
    match value {
        RValue::Use(operand) => operand_reads_local(operand, target),
        RValue::Tuple(operands)
        | RValue::Primitive {
            arguments: operands,
            ..
        }
        | RValue::Call {
            arguments: operands,
            ..
        }
        | RValue::Perform {
            arguments: operands,
            ..
        } => operands_read_local(operands, target),
        RValue::Project { tuple, .. } => operand_reads_local(tuple, target),
        RValue::Construct { fields, .. } => operands_read_local(fields, target),
        RValue::RefAlloc { value, .. } => operand_reads_local(value, target),
        RValue::RefLoad { reference } => operand_reads_local(reference, target),
        RValue::RefStore { reference, value } => {
            operand_reads_local(reference, target) || operand_reads_local(value, target)
        }
        RValue::PackClosure { captures, .. } => operands_read_local(captures, target),
        RValue::CallClosure { closure, arguments } => {
            operand_reads_local(closure, target) || operands_read_local(arguments, target)
        }
    }
}

fn operands_read_local(operands: &[Operand], target: LocalId) -> bool {
    operands
        .iter()
        .any(|operand| operand_reads_local(operand, target))
}

fn operand_reads_local(operand: &Operand, target: LocalId) -> bool {
    matches!(operand, Operand::Local(local) if *local == target)
}

fn reachable_functions(
    entry: FunctionId,
    functions: &[Function],
) -> Result<BTreeSet<FunctionId>, ResidualGenerationError> {
    let by_id: BTreeMap<_, _> = functions
        .iter()
        .map(|function| (function.id, function))
        .collect();
    let mut reachable = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(function_id) = pending.pop() {
        if !reachable.insert(function_id) {
            continue;
        }
        let function =
            by_id
                .get(&function_id)
                .ok_or_else(|| ResidualGenerationError::InternalInvariant {
                    message: format!(
                        "residual reachability found missing function {}",
                        function_id.0
                    ),
                })?;
        let mut references = BTreeSet::new();
        collect_function_references(&function.body, &mut references);
        pending.extend(references.into_iter().rev());
    }
    Ok(reachable)
}

fn collect_function_references(term: &Term, references: &mut BTreeSet<FunctionId>) {
    match term {
        Term::Let { value, next, .. } => {
            match value {
                RValue::Call { function, .. } | RValue::PackClosure { function, .. } => {
                    references.insert(*function);
                }
                _ => {}
            }
            collect_function_references(next, references);
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            collect_function_references(then_term, references);
            collect_function_references(else_term, references);
        }
        Term::Case { arms, .. } => {
            for arm in arms {
                collect_function_references(&arm.body, references);
            }
        }
        Term::TailCall { function, .. } => {
            references.insert(*function);
        }
        Term::Return(_) => {}
        Term::Region { body, .. } => collect_function_references(body, references),
        Term::Handle { clauses, body, .. } => {
            for clause in clauses {
                collect_function_references(&clause.body, references);
            }
            collect_function_references(body, references);
        }
    }
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
