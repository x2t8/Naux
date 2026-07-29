use super::schema::{LocalId, NumericMode, Operand, Primitive, RValue, SemanticHash, Term};
use super::specialization::{
    SpecializationSlot, SpecializationValue, ValidatedSpecializationRequest,
};
use super::staging::{
    BindingTime, BindingTimeJudgment, BindingTimeNodeId, BindingTimeNodeKind, BindingTimePathField,
    StaticEvaluationEligibility,
};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticResidualReason {
    DynamicDependency,
    DeniedByCertificate,
    InterproceduralDeferred,
    /// R0-B2 only: the node is `Static + EligiblePure`, but a local it reads
    /// was withheld by an earlier skip, so its canonical value is unavailable.
    UnavailableStaticValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticResidual {
    pub node: BindingTimeNodeId,
    pub reason: StaticResidualReason,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StaticEvaluationOutcome {
    Complete(SpecializationValue),
    ResidualRequired(StaticResidual),
}

#[derive(Clone, Debug, PartialEq)]
pub struct StaticEvaluation {
    pub request_hash: SemanticHash,
    pub outcome: StaticEvaluationOutcome,
    pub steps: u64,
    pub executed_nodes: Vec<BindingTimeNodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StaticEvaluationError {
    StepBudgetExceeded {
        limit: u64,
        used: u64,
        node: BindingTimeNodeId,
    },
    FrameBudgetExceeded {
        limit: u64,
        node: BindingTimeNodeId,
    },
    MissingEvidence {
        node: BindingTimeNodeId,
    },
    EvidenceKindMismatch {
        node: BindingTimeNodeId,
        expected: BindingTimeNodeKind,
        actual: BindingTimeNodeKind,
    },
    InternalInvariant {
        node: BindingTimeNodeId,
        message: String,
    },
}

impl fmt::Display for StaticEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StepBudgetExceeded { limit, used, node } => write!(
                formatter,
                "R0-B1 static evaluation exhausted step budget {limit} after {used} step(s) at {node}"
            ),
            Self::FrameBudgetExceeded { limit, node } => write!(
                formatter,
                "R0-B2 static evaluation exhausted the frame budget {limit} at {node}"
            ),
            Self::MissingEvidence { node } => {
                write!(formatter, "R0-B1 has no verified B0 evidence for {node}")
            }
            Self::EvidenceKindMismatch {
                node,
                expected,
                actual,
            } => write!(
                formatter,
                "R0-B1 evidence kind mismatch at {node}: expected {expected:?}, found {actual:?}"
            ),
            Self::InternalInvariant { node, message } => {
                write!(formatter, "R0-B1 invariant failed at {node}: {message}")
            }
        }
    }
}

impl std::error::Error for StaticEvaluationError {}

/// Evaluate the intraprocedural R0-B1 subset through an R0-A validated
/// specialization boundary.
///
/// Every executed Core node is authorized independently by the verified B0
/// certificate. Dynamic, denied, and interprocedural work returns an explicit
/// residual frontier. Exhaustion returns no partial evaluation artifact.
pub fn evaluate_static_r0b1(
    validated: &ValidatedSpecializationRequest<'_, '_>,
) -> Result<StaticEvaluation, StaticEvaluationError> {
    let program = &validated.artifact().program;
    let certificate = validated.certificate().certificate();
    let entry = program
        .functions
        .iter()
        .find(|function| function.id == program.entry)
        .ok_or_else(|| StaticEvaluationError::InternalInvariant {
            node: BindingTimeNodeId::root(program.entry),
            message: "validated source has no entry function".to_owned(),
        })?;

    let mut environment = BTreeMap::new();
    for (parameter, slot) in entry
        .parameters
        .iter()
        .zip(&validated.request().entry_slots)
    {
        let value = match slot {
            SpecializationSlot::Static(value) => Some(value.clone()),
            SpecializationSlot::Dynamic(_) => None,
        };
        environment.insert(parameter.local, value);
    }

    let mut evaluator = StaticEvaluator {
        judgments: &certificate.judgments,
        max_steps: validated.request().budget.max_specialization_steps,
        steps: 0,
        executed_nodes: Vec::new(),
    };
    let root = BindingTimeNodeId::root(program.entry);
    let outcome = match evaluator.eval_term(&entry.body, &mut environment, &root) {
        Ok(value) => StaticEvaluationOutcome::Complete(value),
        Err(EvaluationHalt::Residual(residual)) => {
            StaticEvaluationOutcome::ResidualRequired(residual)
        }
        Err(EvaluationHalt::Failure(error)) => return Err(error),
    };
    Ok(StaticEvaluation {
        request_hash: validated.request_hash(),
        outcome,
        steps: evaluator.steps,
        executed_nodes: evaluator.executed_nodes,
    })
}

struct StaticEvaluator<'evidence> {
    judgments: &'evidence [BindingTimeJudgment],
    max_steps: u64,
    steps: u64,
    executed_nodes: Vec<BindingTimeNodeId>,
}

enum EvaluationHalt {
    Residual(StaticResidual),
    Failure(StaticEvaluationError),
}

type EvaluationResult<T> = Result<T, EvaluationHalt>;
type Environment = BTreeMap<LocalId, Option<SpecializationValue>>;

impl StaticEvaluator<'_> {
    fn eval_term(
        &mut self,
        term: &Term,
        environment: &mut Environment,
        node: &BindingTimeNodeId,
    ) -> EvaluationResult<SpecializationValue> {
        if matches!(term, Term::TailCall { .. }) {
            self.require_authority(node, BindingTimeNodeKind::Term)?;
            return Err(Self::residual(
                node,
                StaticResidualReason::InterproceduralDeferred,
            ));
        }
        self.begin_execution(node, BindingTimeNodeKind::Term)?;

        match term {
            Term::Let {
                binder,
                value,
                next,
                ..
            } => {
                let value_node = node.child(BindingTimePathField::LetValue, 0);
                let value = self.eval_rvalue(value, environment, &value_node)?;
                environment.insert(*binder, Some(value));
                let next_node = node.child(BindingTimePathField::LetNext, 0);
                self.eval_term(next, environment, &next_node)
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => {
                let condition_node = node.child(BindingTimePathField::IfCondition, 0);
                let condition = self.eval_operand(condition, environment, &condition_node)?;
                match condition {
                    SpecializationValue::Bool(true) => {
                        let branch = node.child(BindingTimePathField::IfThen, 0);
                        self.eval_term(then_term, environment, &branch)
                    }
                    SpecializationValue::Bool(false) => {
                        let branch = node.child(BindingTimePathField::IfElse, 0);
                        self.eval_term(else_term, environment, &branch)
                    }
                    _ => Err(self.invariant(node, "verified if condition is not Bool")),
                }
            }
            Term::Case { scrutinee, arms } => {
                let scrutinee_node = node.child(BindingTimePathField::CaseScrutinee, 0);
                let scrutinee = self.eval_operand(scrutinee, environment, &scrutinee_node)?;
                let SpecializationValue::Sum {
                    constructor,
                    fields,
                    ..
                } = scrutinee
                else {
                    return Err(self.invariant(node, "verified case scrutinee is not a sum"));
                };
                let arm = arms.get(constructor as usize).ok_or_else(|| {
                    self.invariant(node, "verified case constructor is out of range")
                })?;
                for (binding, field) in arm.bindings.iter().zip(fields) {
                    environment.insert(*binding, Some(field));
                }
                let branch = node.child(BindingTimePathField::CaseArm, constructor);
                self.eval_term(&arm.body, environment, &branch)
            }
            Term::Return(operand) => {
                let operand_node = node.child(BindingTimePathField::ReturnOperand, 0);
                self.eval_operand(operand, environment, &operand_node)
            }
            Term::TailCall { .. } => unreachable!("tail calls are deferred before execution"),
            Term::Region { .. } | Term::Handle { .. } => {
                Err(self.invariant(node, "R0-B1 reached a node outside verified P1V0"))
            }
        }
    }

    fn eval_rvalue(
        &mut self,
        rvalue: &RValue,
        environment: &Environment,
        node: &BindingTimeNodeId,
    ) -> EvaluationResult<SpecializationValue> {
        if matches!(rvalue, RValue::Call { .. }) {
            self.require_authority(node, BindingTimeNodeKind::RValue)?;
            return Err(Self::residual(
                node,
                StaticResidualReason::InterproceduralDeferred,
            ));
        }
        self.begin_execution(node, BindingTimeNodeKind::RValue)?;

        match rvalue {
            RValue::Use(operand) => {
                let operand_node = node.child(BindingTimePathField::UseOperand, 0);
                self.eval_operand(operand, environment, &operand_node)
            }
            RValue::Tuple(operands) => self
                .eval_operands(
                    operands,
                    environment,
                    node,
                    BindingTimePathField::TupleElement,
                )
                .map(SpecializationValue::Tuple),
            RValue::Project { tuple, index } => {
                let tuple_node = node.child(BindingTimePathField::ProjectTuple, 0);
                let tuple = self.eval_operand(tuple, environment, &tuple_node)?;
                let SpecializationValue::Tuple(fields) = tuple else {
                    return Err(self.invariant(node, "verified projection source is not a tuple"));
                };
                fields
                    .get(*index as usize)
                    .cloned()
                    .ok_or_else(|| self.invariant(node, "verified projection is out of range"))
            }
            RValue::Construct {
                sum,
                constructor,
                fields,
            } => {
                let fields = self.eval_operands(
                    fields,
                    environment,
                    node,
                    BindingTimePathField::ConstructField,
                )?;
                Ok(SpecializationValue::Sum {
                    ty: sum.clone(),
                    constructor: *constructor,
                    fields,
                })
            }
            RValue::Primitive {
                operation,
                arguments,
            } => {
                let arguments = self.eval_operands(
                    arguments,
                    environment,
                    node,
                    BindingTimePathField::PrimitiveArgument,
                )?;
                self.eval_primitive(operation, arguments, node)
            }
            RValue::Call { .. } => unreachable!("calls are deferred before execution"),
            RValue::RefAlloc { .. }
            | RValue::RefLoad { .. }
            | RValue::RefStore { .. }
            | RValue::PackClosure { .. }
            | RValue::CallClosure { .. }
            | RValue::Perform { .. } => {
                Err(self.invariant(node, "R0-B1 reached an rvalue outside verified P1V0"))
            }
        }
    }

    fn eval_operands(
        &mut self,
        operands: &[Operand],
        environment: &Environment,
        node: &BindingTimeNodeId,
        field: BindingTimePathField,
    ) -> EvaluationResult<Vec<SpecializationValue>> {
        operands
            .iter()
            .enumerate()
            .map(|(index, operand)| {
                let index = u32::try_from(index)
                    .map_err(|_| self.invariant(node, "canonical operand index exceeds U32"))?;
                let operand_node = node.child(field, index);
                self.eval_operand(operand, environment, &operand_node)
            })
            .collect()
    }

    fn eval_operand(
        &mut self,
        operand: &Operand,
        environment: &Environment,
        node: &BindingTimeNodeId,
    ) -> EvaluationResult<SpecializationValue> {
        self.begin_execution(node, BindingTimeNodeKind::Operand)?;
        match operand {
            Operand::Unit => Ok(SpecializationValue::Unit),
            Operand::Bool(value) => Ok(SpecializationValue::Bool(*value)),
            Operand::I64(value) => Ok(SpecializationValue::I64(*value)),
            Operand::F64(value) => Ok(SpecializationValue::F64(*value)),
            Operand::Local(local) => environment
                .get(local)
                .ok_or_else(|| self.invariant(node, "verified local is not bound"))?
                .clone()
                .ok_or_else(|| {
                    self.invariant(
                        node,
                        "B0-authorized static local has no canonical static value",
                    )
                }),
        }
    }

    fn eval_primitive(
        &self,
        primitive: &Primitive,
        arguments: Vec<SpecializationValue>,
        node: &BindingTimeNodeId,
    ) -> EvaluationResult<SpecializationValue> {
        match primitive {
            Primitive::I64Add(NumericMode::Checked)
            | Primitive::I64Sub(NumericMode::Checked)
            | Primitive::I64Mul(NumericMode::Checked)
            | Primitive::ArrayGetF64 => Err(self.invariant(
                node,
                "B0 authorized an operation denied by the R0-B1 policy",
            )),
            Primitive::I64Add(mode) => {
                let (left, right) = self.expect_i64_pair(arguments, node)?;
                self.eval_i64(*mode, left, right, I64Operation::Add, node)
            }
            Primitive::I64Sub(mode) => {
                let (left, right) = self.expect_i64_pair(arguments, node)?;
                self.eval_i64(*mode, left, right, I64Operation::Sub, node)
            }
            Primitive::I64Mul(mode) => {
                let (left, right) = self.expect_i64_pair(arguments, node)?;
                self.eval_i64(*mode, left, right, I64Operation::Mul, node)
            }
            Primitive::F64Add => {
                let (left, right) = self.expect_f64_pair(arguments, node)?;
                Ok(SpecializationValue::F64(left + right))
            }
            Primitive::F64Sub => {
                let (left, right) = self.expect_f64_pair(arguments, node)?;
                Ok(SpecializationValue::F64(left - right))
            }
            Primitive::I64CmpLt => {
                let (left, right) = self.expect_i64_pair(arguments, node)?;
                Ok(SpecializationValue::Bool(left < right))
            }
            Primitive::I64CmpGe => {
                let (left, right) = self.expect_i64_pair(arguments, node)?;
                Ok(SpecializationValue::Bool(left >= right))
            }
            Primitive::ArrayLenF64 => {
                let [SpecializationValue::ArrayF64(values)] = arguments.as_slice() else {
                    return Err(self.invariant(node, "verified ArrayLenF64 argument mismatch"));
                };
                let length = i64::try_from(values.len())
                    .map_err(|_| self.invariant(node, "array length does not fit I64"))?;
                Ok(SpecializationValue::I64(length))
            }
        }
    }

    fn eval_i64(
        &self,
        mode: NumericMode,
        left: i64,
        right: i64,
        operation: I64Operation,
        node: &BindingTimeNodeId,
    ) -> EvaluationResult<SpecializationValue> {
        let value = match (mode, operation) {
            (NumericMode::Wrapping, I64Operation::Add) => left.wrapping_add(right),
            (NumericMode::Wrapping, I64Operation::Sub) => left.wrapping_sub(right),
            (NumericMode::Wrapping, I64Operation::Mul) => left.wrapping_mul(right),
            (NumericMode::Saturating, I64Operation::Add) => left.saturating_add(right),
            (NumericMode::Saturating, I64Operation::Sub) => left.saturating_sub(right),
            (NumericMode::Saturating, I64Operation::Mul) => left.saturating_mul(right),
            (NumericMode::Checked, _) => {
                return Err(self.invariant(
                    node,
                    "checked integer arithmetic is not executable in R0-B1",
                ));
            }
        };
        Ok(SpecializationValue::I64(value))
    }

    fn expect_i64_pair(
        &self,
        arguments: Vec<SpecializationValue>,
        node: &BindingTimeNodeId,
    ) -> EvaluationResult<(i64, i64)> {
        let [SpecializationValue::I64(left), SpecializationValue::I64(right)] =
            arguments.as_slice()
        else {
            return Err(self.invariant(node, "verified integer primitive argument mismatch"));
        };
        Ok((*left, *right))
    }

    fn expect_f64_pair(
        &self,
        arguments: Vec<SpecializationValue>,
        node: &BindingTimeNodeId,
    ) -> EvaluationResult<(f64, f64)> {
        let [SpecializationValue::F64(left), SpecializationValue::F64(right)] =
            arguments.as_slice()
        else {
            return Err(self.invariant(node, "verified floating primitive argument mismatch"));
        };
        Ok((*left, *right))
    }

    fn begin_execution(
        &mut self,
        node: &BindingTimeNodeId,
        expected_kind: BindingTimeNodeKind,
    ) -> EvaluationResult<()> {
        self.require_authority(node, expected_kind)?;
        if self.steps == self.max_steps {
            return Err(EvaluationHalt::Failure(
                StaticEvaluationError::StepBudgetExceeded {
                    limit: self.max_steps,
                    used: self.steps,
                    node: node.clone(),
                },
            ));
        }
        self.steps += 1;
        self.executed_nodes.push(node.clone());
        Ok(())
    }

    fn require_authority(
        &self,
        node: &BindingTimeNodeId,
        expected_kind: BindingTimeNodeKind,
    ) -> EvaluationResult<()> {
        let judgment = self
            .judgments
            .binary_search_by(|judgment| judgment.node.cmp(node))
            .ok()
            .and_then(|index| self.judgments.get(index))
            .ok_or_else(|| {
                EvaluationHalt::Failure(StaticEvaluationError::MissingEvidence {
                    node: node.clone(),
                })
            })?;
        if judgment.kind != expected_kind {
            return Err(EvaluationHalt::Failure(
                StaticEvaluationError::EvidenceKindMismatch {
                    node: node.clone(),
                    expected: expected_kind,
                    actual: judgment.kind,
                },
            ));
        }
        if judgment.binding_time == BindingTime::Dynamic {
            return Err(Self::residual(
                node,
                StaticResidualReason::DynamicDependency,
            ));
        }
        if judgment.static_evaluation == StaticEvaluationEligibility::Denied {
            return Err(Self::residual(
                node,
                StaticResidualReason::DeniedByCertificate,
            ));
        }
        Ok(())
    }

    fn residual(node: &BindingTimeNodeId, reason: StaticResidualReason) -> EvaluationHalt {
        EvaluationHalt::Residual(StaticResidual {
            node: node.clone(),
            reason,
        })
    }

    fn invariant(&self, node: &BindingTimeNodeId, message: &str) -> EvaluationHalt {
        EvaluationHalt::Failure(StaticEvaluationError::InternalInvariant {
            node: node.clone(),
            message: message.to_owned(),
        })
    }
}

#[derive(Clone, Copy)]
enum I64Operation {
    Add,
    Sub,
    Mul,
}
