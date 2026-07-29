use super::schema::{
    Function, FunctionId, LocalId, NumericMode, Operand, Primitive, Program, RValue, SemanticHash,
    Term,
};
use super::specialization::{
    SpecializationSlot, SpecializationValue, ValidatedSpecializationRequest,
};
use super::staging::{
    BindingTime, BindingTimeJudgment, BindingTimeNodeId, BindingTimeNodeKind, BindingTimePathField,
    StaticEvaluationEligibility,
};
use super::static_evaluate::{StaticEvaluationError, StaticResidual, StaticResidualReason};
use std::collections::BTreeMap;

/// Hard cap on live continuation frames, aligned with the canonical
/// interpreter's `MAX_SAFE_CALL_DEPTH`. Tail calls replace the top frame and
/// never consume additional frames.
pub const R0B2_MAX_FRAMES: u64 = 256;

#[derive(Clone, Debug, PartialEq)]
pub struct StaticFact {
    pub local: LocalId,
    pub value: SpecializationValue,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SkippedStaticNode {
    pub node: BindingTimeNodeId,
    pub reason: StaticResidualReason,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MixedStaticOutcome {
    Complete(SpecializationValue),
    MixedFrontier {
        halt: StaticResidual,
        static_facts: Vec<StaticFact>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct MixedStaticEvaluation {
    request_hash: SemanticHash,
    outcome: MixedStaticOutcome,
    steps: u64,
    executed_nodes: Vec<BindingTimeNodeId>,
    skipped_nodes: Vec<SkippedStaticNode>,
}

impl MixedStaticEvaluation {
    pub fn request_hash(&self) -> SemanticHash {
        self.request_hash
    }

    pub fn outcome(&self) -> &MixedStaticOutcome {
        &self.outcome
    }

    pub fn steps(&self) -> u64 {
        self.steps
    }

    pub fn executed_nodes(&self) -> &[BindingTimeNodeId] {
        &self.executed_nodes
    }

    pub fn skipped_nodes(&self) -> &[SkippedStaticNode] {
        &self.skipped_nodes
    }
}

/// Evaluate the interprocedural R0-B2 subset through an R0-A validated
/// specialization boundary using an explicit continuation machine.
///
/// Every executed Core node is authorized independently by the verified B0
/// certificate; no `Dynamic` or `Denied` node is ever executed. A `Let`-bound
/// value that cannot execute is skipped into a hole so the remaining static
/// spine still runs. A dynamic, denied, or unavailable control node halts
/// with a mixed static-fact frontier. Exhaustion of the step or frame budget
/// fails closed with no partial artifact.
pub fn evaluate_static_r0b2(
    validated: &ValidatedSpecializationRequest<'_, '_>,
) -> Result<MixedStaticEvaluation, StaticEvaluationError> {
    let program = &validated.artifact().program;
    let certificate = validated.certificate().certificate();
    let entry = find_function(program, program.entry).ok_or_else(|| {
        StaticEvaluationError::InternalInvariant {
            node: BindingTimeNodeId::root(program.entry),
            message: "validated source has no entry function".to_owned(),
        }
    })?;

    let mut environment = Environment::new();
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

    let mut machine = ContinuationMachine {
        program,
        judgments: &certificate.judgments,
        max_steps: validated.request().budget.max_specialization_steps,
        steps: 0,
        executed_nodes: Vec::new(),
        skipped_nodes: Vec::new(),
        frames: vec![Frame {
            environment,
            pending: None,
        }],
    };
    let outcome = machine.run(&entry.body, BindingTimeNodeId::root(program.entry))?;
    Ok(MixedStaticEvaluation {
        request_hash: validated.request_hash(),
        outcome,
        steps: machine.steps,
        executed_nodes: machine.executed_nodes,
        skipped_nodes: machine.skipped_nodes,
    })
}

type Environment = BTreeMap<LocalId, Option<SpecializationValue>>;

struct Frame<'program> {
    environment: Environment,
    pending: Option<PendingReturn<'program>>,
}

struct PendingReturn<'program> {
    binder: LocalId,
    next: &'program Term,
    next_node: BindingTimeNodeId,
}

enum Flow<'program> {
    Goto(&'program Term, BindingTimeNodeId),
    Return(SpecializationValue),
    Halt(StaticResidual),
}

struct ContinuationMachine<'program, 'evidence> {
    program: &'program Program,
    judgments: &'evidence [BindingTimeJudgment],
    max_steps: u64,
    steps: u64,
    executed_nodes: Vec<BindingTimeNodeId>,
    skipped_nodes: Vec<SkippedStaticNode>,
    frames: Vec<Frame<'program>>,
}

impl<'program, 'evidence> ContinuationMachine<'program, 'evidence> {
    fn run(
        &mut self,
        entry_body: &'program Term,
        entry_node: BindingTimeNodeId,
    ) -> Result<MixedStaticOutcome, StaticEvaluationError> {
        let mut term = entry_body;
        let mut node = entry_node;
        loop {
            match self.eval_term(term, &node)? {
                Flow::Goto(next_term, next_node) => {
                    term = next_term;
                    node = next_node;
                }
                Flow::Return(value) => {
                    self.frames.pop();
                    let Some(caller) = self.frames.last_mut() else {
                        return Ok(MixedStaticOutcome::Complete(value));
                    };
                    let pending = caller.pending.take().ok_or_else(|| {
                        StaticEvaluationError::InternalInvariant {
                            node: node.clone(),
                            message: "a completed frame has no pending caller continuation"
                                .to_owned(),
                        }
                    })?;
                    caller.environment.insert(pending.binder, Some(value));
                    term = pending.next;
                    node = pending.next_node;
                }
                Flow::Halt(halt) => {
                    if self.frames.len() != 1 {
                        return Err(StaticEvaluationError::InternalInvariant {
                            node: halt.node,
                            message: "a mixed frontier surfaced outside the entry frame".to_owned(),
                        });
                    }
                    let static_facts = self
                        .frames
                        .first()
                        .expect("frame count checked above")
                        .environment
                        .iter()
                        .filter_map(|(local, value)| {
                            value.as_ref().map(|value| StaticFact {
                                local: *local,
                                value: value.clone(),
                            })
                        })
                        .collect();
                    return Ok(MixedStaticOutcome::MixedFrontier { halt, static_facts });
                }
            }
        }
    }

    fn eval_term(
        &mut self,
        term: &'program Term,
        node: &BindingTimeNodeId,
    ) -> Result<Flow<'program>, StaticEvaluationError> {
        let term_judgment = self.authority(node, BindingTimeNodeKind::Term)?;
        let term_eligible = is_eligible(term_judgment);
        // A tail call is a control transfer: its refusal must consume no
        // step, so its own step is accounted inside its arm.
        if term_eligible && !matches!(term, Term::TailCall { .. }) {
            self.consume_step(node)?;
        }

        match term {
            Term::Let {
                binder,
                value,
                next,
                ..
            } => {
                let value_node = node.child(BindingTimePathField::LetValue, 0);
                let next_node = node.child(BindingTimePathField::LetNext, 0);
                match value {
                    RValue::Call {
                        function,
                        arguments,
                    } => {
                        let call_judgment =
                            self.authority(&value_node, BindingTimeNodeKind::RValue)?;
                        if let Some(reason) = self.refusal(call_judgment, arguments) {
                            self.skip(&value_node, reason, *binder);
                            return Ok(Flow::Goto(next, next_node));
                        }
                        self.consume_step(&value_node)?;
                        let values = self.eval_call_arguments(
                            arguments,
                            &value_node,
                            BindingTimePathField::CallArgument,
                        )?;
                        let callee = self.callee(*function, &value_node)?;
                        if self.frames.len() as u64 == R0B2_MAX_FRAMES {
                            return Err(StaticEvaluationError::FrameBudgetExceeded {
                                limit: R0B2_MAX_FRAMES,
                                node: value_node,
                            });
                        }
                        let top = self.top_frame(&value_node)?;
                        top.pending = Some(PendingReturn {
                            binder: *binder,
                            next,
                            next_node,
                        });
                        self.frames.push(Frame {
                            environment: bind_parameters(callee, values),
                            pending: None,
                        });
                        Ok(Flow::Goto(&callee.body, BindingTimeNodeId::root(*function)))
                    }
                    _ => {
                        let value_judgment =
                            self.authority(&value_node, BindingTimeNodeKind::RValue)?;
                        if let Some(reason) =
                            self.refusal(value_judgment, rvalue_read_operands(value))
                        {
                            self.skip(&value_node, reason, *binder);
                            return Ok(Flow::Goto(next, next_node));
                        }
                        self.consume_step(&value_node)?;
                        let value = self.eval_plain_rvalue(value, &value_node)?;
                        let top = self.top_frame(&value_node)?;
                        top.environment.insert(*binder, Some(value));
                        Ok(Flow::Goto(next, next_node))
                    }
                }
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => {
                let condition_node = node.child(BindingTimePathField::IfCondition, 0);
                let condition = match self.eval_control_operand(condition, &condition_node)? {
                    Ok(value) => value,
                    Err(halt) => return Ok(Flow::Halt(halt)),
                };
                match condition {
                    SpecializationValue::Bool(true) => Ok(Flow::Goto(
                        then_term,
                        node.child(BindingTimePathField::IfThen, 0),
                    )),
                    SpecializationValue::Bool(false) => Ok(Flow::Goto(
                        else_term,
                        node.child(BindingTimePathField::IfElse, 0),
                    )),
                    _ => Err(self.invariant(node, "verified if condition is not Bool")),
                }
            }
            Term::Case { scrutinee, arms } => {
                let scrutinee_node = node.child(BindingTimePathField::CaseScrutinee, 0);
                let scrutinee = match self.eval_control_operand(scrutinee, &scrutinee_node)? {
                    Ok(value) => value,
                    Err(halt) => return Ok(Flow::Halt(halt)),
                };
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
                let top = self.top_frame(node)?;
                for (binding, field) in arm.bindings.iter().zip(fields) {
                    top.environment.insert(*binding, Some(field));
                }
                Ok(Flow::Goto(
                    &arm.body,
                    node.child(BindingTimePathField::CaseArm, constructor),
                ))
            }
            Term::Return(operand) => {
                let operand_node = node.child(BindingTimePathField::ReturnOperand, 0);
                match self.eval_control_operand(operand, &operand_node)? {
                    Ok(value) => Ok(Flow::Return(value)),
                    Err(halt) => Ok(Flow::Halt(halt)),
                }
            }
            Term::TailCall {
                function,
                arguments,
            } => {
                if let Some(reason) = self.refusal(term_judgment, arguments) {
                    return Ok(Flow::Halt(StaticResidual {
                        node: node.clone(),
                        reason,
                    }));
                }
                self.consume_step(node)?;
                let values = self.eval_call_arguments(
                    arguments,
                    node,
                    BindingTimePathField::TailCallArgument,
                )?;
                let callee = self.callee(*function, node)?;
                let top = self.top_frame(node)?;
                top.environment = bind_parameters(callee, values);
                Ok(Flow::Goto(&callee.body, BindingTimeNodeId::root(*function)))
            }
            Term::Region { .. } | Term::Handle { .. } => {
                Err(self.invariant(node, "R0-B2 reached a node outside verified P1V0"))
            }
        }
    }

    /// Evaluate a non-call rvalue whose judgment and operand availability were
    /// already accepted and whose own step was already consumed.
    fn eval_plain_rvalue(
        &mut self,
        rvalue: &RValue,
        node: &BindingTimeNodeId,
    ) -> Result<SpecializationValue, StaticEvaluationError> {
        match rvalue {
            RValue::Use(operand) => {
                let operand_node = node.child(BindingTimePathField::UseOperand, 0);
                self.authority(&operand_node, BindingTimeNodeKind::Operand)?;
                self.consume_step(&operand_node)?;
                self.eval_operand(operand, &operand_node)
            }
            RValue::Tuple(operands) => self
                .eval_operands(operands, node, BindingTimePathField::TupleElement)
                .map(SpecializationValue::Tuple),
            RValue::Project { tuple, index } => {
                let tuple_node = node.child(BindingTimePathField::ProjectTuple, 0);
                self.authority(&tuple_node, BindingTimeNodeKind::Operand)?;
                self.consume_step(&tuple_node)?;
                let tuple = self.eval_operand(tuple, &tuple_node)?;
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
                let fields =
                    self.eval_operands(fields, node, BindingTimePathField::ConstructField)?;
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
                let arguments =
                    self.eval_operands(arguments, node, BindingTimePathField::PrimitiveArgument)?;
                self.eval_primitive(operation, arguments, node)
            }
            RValue::Call { .. } => Err(self.invariant(node, "calls are handled by the machine")),
            RValue::RefAlloc { .. }
            | RValue::RefLoad { .. }
            | RValue::RefStore { .. }
            | RValue::PackClosure { .. }
            | RValue::CallClosure { .. }
            | RValue::Perform { .. } => {
                Err(self.invariant(node, "R0-B2 reached an rvalue outside verified P1V0"))
            }
        }
    }

    fn eval_call_arguments(
        &mut self,
        arguments: &[Operand],
        node: &BindingTimeNodeId,
        field: BindingTimePathField,
    ) -> Result<Vec<SpecializationValue>, StaticEvaluationError> {
        arguments
            .iter()
            .enumerate()
            .map(|(index, argument)| {
                let index = u32::try_from(index)
                    .map_err(|_| self.invariant(node, "canonical operand index exceeds U32"))?;
                let argument_node = node.child(field, index);
                let judgment = self.authority(&argument_node, BindingTimeNodeKind::Operand)?;
                if !is_eligible(judgment) {
                    return Err(self.invariant(
                        &argument_node,
                        "an eligible call carries a non-eligible argument",
                    ));
                }
                self.consume_step(&argument_node)?;
                self.eval_operand(argument, &argument_node)
            })
            .collect()
    }

    fn eval_operands(
        &mut self,
        operands: &[Operand],
        node: &BindingTimeNodeId,
        field: BindingTimePathField,
    ) -> Result<Vec<SpecializationValue>, StaticEvaluationError> {
        operands
            .iter()
            .enumerate()
            .map(|(index, operand)| {
                let index = u32::try_from(index)
                    .map_err(|_| self.invariant(node, "canonical operand index exceeds U32"))?;
                let operand_node = node.child(field, index);
                self.authority(&operand_node, BindingTimeNodeKind::Operand)?;
                self.consume_step(&operand_node)?;
                self.eval_operand(operand, &operand_node)
            })
            .collect()
    }

    /// Evaluate a control-position operand: a dynamic, denied, or unavailable
    /// judgment halts with a mixed frontier instead of skipping.
    fn eval_control_operand(
        &mut self,
        operand: &Operand,
        node: &BindingTimeNodeId,
    ) -> Result<Result<SpecializationValue, StaticResidual>, StaticEvaluationError> {
        let judgment = self.authority(node, BindingTimeNodeKind::Operand)?;
        if let Some(reason) = self.refusal(judgment, std::slice::from_ref(operand)) {
            return Ok(Err(StaticResidual {
                node: node.clone(),
                reason,
            }));
        }
        self.consume_step(node)?;
        self.eval_operand(operand, node).map(Ok)
    }

    fn eval_operand(
        &mut self,
        operand: &Operand,
        node: &BindingTimeNodeId,
    ) -> Result<SpecializationValue, StaticEvaluationError> {
        match operand {
            Operand::Unit => Ok(SpecializationValue::Unit),
            Operand::Bool(value) => Ok(SpecializationValue::Bool(*value)),
            Operand::I64(value) => Ok(SpecializationValue::I64(*value)),
            Operand::F64(value) => Ok(SpecializationValue::F64(*value)),
            Operand::Local(local) => self
                .local_value(local)
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
    ) -> Result<SpecializationValue, StaticEvaluationError> {
        match primitive {
            Primitive::I64Add(NumericMode::Checked)
            | Primitive::I64Sub(NumericMode::Checked)
            | Primitive::I64Mul(NumericMode::Checked)
            | Primitive::ArrayGetF64 => {
                Err(self.invariant(node, "B0 authorized an operation denied by the R0-B policy"))
            }
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
    ) -> Result<SpecializationValue, StaticEvaluationError> {
        let value = match (mode, operation) {
            (NumericMode::Wrapping, I64Operation::Add) => left.wrapping_add(right),
            (NumericMode::Wrapping, I64Operation::Sub) => left.wrapping_sub(right),
            (NumericMode::Wrapping, I64Operation::Mul) => left.wrapping_mul(right),
            (NumericMode::Saturating, I64Operation::Add) => left.saturating_add(right),
            (NumericMode::Saturating, I64Operation::Sub) => left.saturating_sub(right),
            (NumericMode::Saturating, I64Operation::Mul) => left.saturating_mul(right),
            (NumericMode::Checked, _) => {
                return Err(
                    self.invariant(node, "checked integer arithmetic is not executable in R0-B")
                );
            }
        };
        Ok(SpecializationValue::I64(value))
    }

    fn expect_i64_pair(
        &self,
        arguments: Vec<SpecializationValue>,
        node: &BindingTimeNodeId,
    ) -> Result<(i64, i64), StaticEvaluationError> {
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
    ) -> Result<(f64, f64), StaticEvaluationError> {
        let [SpecializationValue::F64(left), SpecializationValue::F64(right)] =
            arguments.as_slice()
        else {
            return Err(self.invariant(node, "verified floating primitive argument mismatch"));
        };
        Ok((*left, *right))
    }

    /// Decide whether an authorized node must be refused: `Dynamic` and
    /// `Denied` judgments are refused outright; an eligible node is refused
    /// when a local it reads was withheld by an earlier skip.
    fn refusal(
        &self,
        judgment: &BindingTimeJudgment,
        read_operands: &[Operand],
    ) -> Option<StaticResidualReason> {
        if judgment.binding_time == BindingTime::Dynamic {
            return Some(StaticResidualReason::DynamicDependency);
        }
        if judgment.static_evaluation == StaticEvaluationEligibility::Denied {
            return Some(StaticResidualReason::DeniedByCertificate);
        }
        let unavailable = read_operands.iter().any(|operand| {
            matches!(operand, Operand::Local(local)
                if self.local_value(local).is_none_or(|value| value.is_none()))
        });
        if unavailable {
            return Some(StaticResidualReason::UnavailableStaticValue);
        }
        None
    }

    fn skip(&mut self, node: &BindingTimeNodeId, reason: StaticResidualReason, binder: LocalId) {
        self.skipped_nodes.push(SkippedStaticNode {
            node: node.clone(),
            reason,
        });
        if let Some(frame) = self.frames.last_mut() {
            frame.environment.insert(binder, None);
        }
    }

    fn local_value(&self, local: &LocalId) -> Option<&Option<SpecializationValue>> {
        self.frames
            .last()
            .and_then(|frame| frame.environment.get(local))
    }

    fn top_frame(
        &mut self,
        node: &BindingTimeNodeId,
    ) -> Result<&mut Frame<'program>, StaticEvaluationError> {
        self.frames
            .last_mut()
            .ok_or_else(|| StaticEvaluationError::InternalInvariant {
                node: node.clone(),
                message: "the continuation machine has no live frame".to_owned(),
            })
    }

    fn callee(
        &self,
        function: FunctionId,
        node: &BindingTimeNodeId,
    ) -> Result<&'program Function, StaticEvaluationError> {
        find_function(self.program, function).ok_or_else(|| {
            StaticEvaluationError::InternalInvariant {
                node: node.clone(),
                message: format!("verified call targets missing function {}", function.0),
            }
        })
    }

    fn authority(
        &self,
        node: &BindingTimeNodeId,
        expected_kind: BindingTimeNodeKind,
    ) -> Result<&'evidence BindingTimeJudgment, StaticEvaluationError> {
        let judgment = self
            .judgments
            .binary_search_by(|judgment| judgment.node.cmp(node))
            .ok()
            .and_then(|index| self.judgments.get(index))
            .ok_or_else(|| StaticEvaluationError::MissingEvidence { node: node.clone() })?;
        if judgment.kind != expected_kind {
            return Err(StaticEvaluationError::EvidenceKindMismatch {
                node: node.clone(),
                expected: expected_kind,
                actual: judgment.kind,
            });
        }
        Ok(judgment)
    }

    fn consume_step(&mut self, node: &BindingTimeNodeId) -> Result<(), StaticEvaluationError> {
        if self.steps == self.max_steps {
            return Err(StaticEvaluationError::StepBudgetExceeded {
                limit: self.max_steps,
                used: self.steps,
                node: node.clone(),
            });
        }
        self.steps += 1;
        self.executed_nodes.push(node.clone());
        Ok(())
    }

    fn invariant(&self, node: &BindingTimeNodeId, message: &str) -> StaticEvaluationError {
        StaticEvaluationError::InternalInvariant {
            node: node.clone(),
            message: message.to_owned(),
        }
    }
}

fn is_eligible(judgment: &BindingTimeJudgment) -> bool {
    judgment.binding_time == BindingTime::Static
        && judgment.static_evaluation == StaticEvaluationEligibility::EligiblePure
}

fn bind_parameters(callee: &Function, values: Vec<SpecializationValue>) -> Environment {
    callee
        .parameters
        .iter()
        .zip(values)
        .map(|(parameter, value)| (parameter.local, Some(value)))
        .collect()
}

fn find_function(program: &Program, id: FunctionId) -> Option<&Function> {
    program.functions.iter().find(|function| function.id == id)
}

fn rvalue_read_operands(rvalue: &RValue) -> &[Operand] {
    match rvalue {
        RValue::Use(operand) => std::slice::from_ref(operand),
        RValue::Tuple(operands) => operands,
        RValue::Project { tuple, .. } => std::slice::from_ref(tuple),
        RValue::Construct { fields, .. } => fields,
        RValue::Primitive { arguments, .. } => arguments,
        RValue::Call { arguments, .. } => arguments,
        RValue::RefAlloc { .. }
        | RValue::RefLoad { .. }
        | RValue::RefStore { .. }
        | RValue::PackClosure { .. }
        | RValue::CallClosure { .. }
        | RValue::Perform { .. } => &[],
    }
}

#[derive(Clone, Copy)]
enum I64Operation {
    Add,
    Sub,
    Mul,
}
