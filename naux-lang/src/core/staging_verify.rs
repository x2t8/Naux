use super::encoding::binding_time_certificate_hash;
use super::schema::{
    CoreArtifact, FunctionId, LocalId, NumericMode, Operand, Primitive, RValue, Term,
};
use super::staging::{
    validate_binding_time_b0_request, BindingTime, BindingTimeAnalysis, BindingTimeAnalysisError,
    BindingTimeBudgetUsage, BindingTimeCertificate, BindingTimeFunctionSummary,
    BindingTimeJudgment, BindingTimeNodeId, BindingTimeNodeKind, BindingTimePathField,
    BindingTimeRequest, StaticEvaluationEligibility, ValidatedBindingTimeRequest,
    B0_CERTIFICATE_SCHEMA_VERSION,
};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingTimeCertificateCode {
    InvalidRequest,
    UnsupportedCertificateSchema,
    SourceProgramHashMismatch,
    InterpreterSemanticsHashMismatch,
    PolicyHashMismatch,
    RequestHashMismatch,
    EntryFunctionMismatch,
    EntryManifestMismatch,
    DeclaredBudgetMismatch,
    CertificateHashMismatch,
    NonCanonicalSummaryOrder,
    FunctionSummarySetMismatch,
    NonCanonicalJudgmentOrder,
    FunctionSummariesMismatch,
    JudgmentsMismatch,
    BudgetUsageMismatch,
    IndependentReplayFailure,
    EncodingFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeCertificateError {
    pub code: BindingTimeCertificateCode,
    pub path: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeCertificateErrors(pub Vec<BindingTimeCertificateError>);

impl fmt::Display for BindingTimeCertificateErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} binding-time B0 certificate error(s)",
            self.0.len()
        )?;
        for error in &self.0 {
            write!(
                formatter,
                "\n- {:?} at {}: {}",
                error.code, error.path, error.message
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for BindingTimeCertificateErrors {}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedBindingTimeCertificate<'certificate> {
    certificate: &'certificate BindingTimeCertificate,
}

impl<'certificate> VerifiedBindingTimeCertificate<'certificate> {
    pub fn certificate(&self) -> &'certificate BindingTimeCertificate {
        self.certificate
    }
}

pub fn verify_binding_time_b0_certificate<'certificate>(
    artifact: &CoreArtifact,
    request: &BindingTimeRequest,
    certificate: &'certificate BindingTimeCertificate,
) -> Result<VerifiedBindingTimeCertificate<'certificate>, BindingTimeCertificateErrors> {
    let validated = validate_binding_time_b0_request(artifact, request).map_err(|errors| {
        BindingTimeCertificateErrors(vec![BindingTimeCertificateError {
            code: BindingTimeCertificateCode::InvalidRequest,
            path: "certificate.request",
            message: errors.to_string(),
        }])
    })?;
    let program = validated.artifact().program();
    let mut errors = Vec::new();

    if certificate.schema_version != B0_CERTIFICATE_SCHEMA_VERSION {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::UnsupportedCertificateSchema,
            "certificate.schema_version",
            format!(
                "expected {:?}, found {:?}",
                B0_CERTIFICATE_SCHEMA_VERSION, certificate.schema_version
            ),
        );
    }
    if certificate.source_program_hash != request.source_program_hash {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::SourceProgramHashMismatch,
            "certificate.source_program_hash",
            "certificate source hash does not match the validated request".to_owned(),
        );
    }
    if certificate.interpreter_semantics_hash != request.interpreter_semantics_hash {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::InterpreterSemanticsHashMismatch,
            "certificate.interpreter_semantics_hash",
            "certificate interpreter semantics do not match the validated request".to_owned(),
        );
    }
    if certificate.policy_hash != request.policy_hash {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::PolicyHashMismatch,
            "certificate.policy_hash",
            "certificate policy hash does not match the validated request".to_owned(),
        );
    }
    if certificate.request_hash != validated.request_hash() {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::RequestHashMismatch,
            "certificate.request_hash",
            "certificate request hash does not match the canonical validated request".to_owned(),
        );
    }
    if certificate.entry_function != program.entry {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::EntryFunctionMismatch,
            "certificate.entry_function",
            format!(
                "expected entry function {}, found {}",
                program.entry.0, certificate.entry_function.0
            ),
        );
    }
    if certificate.entry_parameters != request.entry_parameters {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::EntryManifestMismatch,
            "certificate.entry_parameters",
            "certificate entry manifest does not match the validated request".to_owned(),
        );
    }
    if certificate.declared_budget != request.budget {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::DeclaredBudgetMismatch,
            "certificate.declared_budget",
            "certificate budgets do not match the validated request".to_owned(),
        );
    }

    match binding_time_certificate_hash(certificate) {
        Ok(expected) if certificate.certificate_hash != expected => push_error(
            &mut errors,
            BindingTimeCertificateCode::CertificateHashMismatch,
            "certificate.certificate_hash",
            "declared certificate hash does not match canonical certificate bytes".to_owned(),
        ),
        Err(error) => push_error(
            &mut errors,
            BindingTimeCertificateCode::EncodingFailure,
            "certificate",
            error.to_string(),
        ),
        _ => {}
    }

    if !certificate
        .function_summaries
        .windows(2)
        .all(|pair| pair[0].function < pair[1].function)
    {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::NonCanonicalSummaryOrder,
            "certificate.function_summaries",
            "function summaries must be strictly ordered by FunctionId".to_owned(),
        );
    }
    if certificate.function_summaries.len() != program.functions.len()
        || certificate
            .function_summaries
            .iter()
            .zip(&program.functions)
            .any(|(summary, function)| summary.function != function.id)
    {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::FunctionSummarySetMismatch,
            "certificate.function_summaries",
            "certificate must contain exactly one summary for every canonical function".to_owned(),
        );
    }
    if !certificate
        .judgments
        .windows(2)
        .all(|pair| pair[0].node < pair[1].node)
    {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::NonCanonicalJudgmentOrder,
            "certificate.judgments",
            "node judgments must be strictly ordered by canonical node identity".to_owned(),
        );
    }

    if !errors.is_empty() {
        return Err(BindingTimeCertificateErrors(errors));
    }

    let expected = replay_binding_time_b0c(&validated).map_err(|error| {
        BindingTimeCertificateErrors(vec![BindingTimeCertificateError {
            code: BindingTimeCertificateCode::IndependentReplayFailure,
            path: "certificate.evidence",
            message: error.to_string(),
        }])
    })?;

    if certificate.function_summaries != expected.function_summaries {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::FunctionSummariesMismatch,
            "certificate.function_summaries",
            "function summaries disagree with independent B0-C replay".to_owned(),
        );
    }
    if certificate.judgments != expected.judgments {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::JudgmentsMismatch,
            "certificate.judgments",
            "node judgments disagree with independent B0-C replay".to_owned(),
        );
    }
    if certificate.budget_usage != expected.budget_usage {
        push_error(
            &mut errors,
            BindingTimeCertificateCode::BudgetUsageMismatch,
            "certificate.budget_usage",
            "budget usage disagrees with independent B0-C replay".to_owned(),
        );
    }

    if errors.is_empty() {
        Ok(VerifiedBindingTimeCertificate { certificate })
    } else {
        Err(BindingTimeCertificateErrors(errors))
    }
}

fn push_error(
    errors: &mut Vec<BindingTimeCertificateError>,
    code: BindingTimeCertificateCode,
    path: &'static str,
    message: String,
) {
    errors.push(BindingTimeCertificateError {
        code,
        path,
        message,
    });
}

#[derive(Clone, Copy)]
struct ReplayedNode {
    binding_time: BindingTime,
    static_evaluation: StaticEvaluationEligibility,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayContribution {
    parameters: Vec<BindingTime>,
    control: BindingTime,
}

struct EvidenceTraversal<'summary> {
    max_nodes: u64,
    max_call_edges: u64,
    judgments: Vec<BindingTimeJudgment>,
    nodes: u64,
    call_edges: u64,
    summaries: &'summary BTreeMap<FunctionId, BindingTimeFunctionSummary>,
    contributions: BTreeMap<FunctionId, ReplayContribution>,
}

impl EvidenceTraversal<'_> {
    fn term(
        &mut self,
        term: &Term,
        environment: &mut BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
    ) -> Result<ReplayedNode, BindingTimeAnalysisError> {
        let result = match term {
            Term::Let {
                binder,
                value,
                next,
                ..
            } => {
                let value_node = node.child(BindingTimePathField::LetValue, 0);
                let value = self.rvalue(value, environment, control, &value_node)?;
                environment.insert(*binder, value.binding_time);
                let next_node = node.child(BindingTimePathField::LetNext, 0);
                let next = self.term(next, environment, control, &next_node)?;
                ReplayedNode {
                    binding_time: next.binding_time,
                    static_evaluation: replay_eligible_if(
                        next.binding_time,
                        [value.static_evaluation, next.static_evaluation],
                    ),
                }
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => {
                let condition_node = node.child(BindingTimePathField::IfCondition, 0);
                let condition = self.operand(condition, environment, control, &condition_node)?;
                let mut then_environment = environment.clone();
                let then_node = node.child(BindingTimePathField::IfThen, 0);
                let then_result = self.term(
                    then_term,
                    &mut then_environment,
                    condition.binding_time,
                    &then_node,
                )?;
                let mut else_environment = environment.clone();
                let else_node = node.child(BindingTimePathField::IfElse, 0);
                let else_result = self.term(
                    else_term,
                    &mut else_environment,
                    condition.binding_time,
                    &else_node,
                )?;
                let binding_time = then_result.binding_time.join(else_result.binding_time);
                ReplayedNode {
                    binding_time,
                    static_evaluation: replay_eligible_if(
                        binding_time,
                        [
                            condition.static_evaluation,
                            then_result.static_evaluation,
                            else_result.static_evaluation,
                        ],
                    ),
                }
            }
            Term::Case { scrutinee, arms } => {
                let scrutinee_node = node.child(BindingTimePathField::CaseScrutinee, 0);
                let scrutinee = self.operand(scrutinee, environment, control, &scrutinee_node)?;
                let mut binding_time = BindingTime::Static;
                let mut eligibility = vec![scrutinee.static_evaluation];
                for (index, arm) in arms.iter().enumerate() {
                    let mut arm_environment = environment.clone();
                    for binding in &arm.bindings {
                        arm_environment.insert(*binding, scrutinee.binding_time);
                    }
                    let index = replay_index(index, node)?;
                    let arm_node = node.child(BindingTimePathField::CaseArm, index);
                    let arm_result = self.term(
                        &arm.body,
                        &mut arm_environment,
                        scrutinee.binding_time,
                        &arm_node,
                    )?;
                    binding_time = binding_time.join(arm_result.binding_time);
                    eligibility.push(arm_result.static_evaluation);
                }
                ReplayedNode {
                    binding_time,
                    static_evaluation: replay_eligible_if(binding_time, eligibility),
                }
            }
            Term::TailCall {
                function,
                arguments,
            } => self.call(
                *function,
                arguments,
                environment,
                control,
                node,
                BindingTimePathField::TailCallArgument,
            )?,
            Term::Return(operand) => {
                let operand_node = node.child(BindingTimePathField::ReturnOperand, 0);
                self.operand(operand, environment, control, &operand_node)?
            }
            Term::Region { .. } | Term::Handle { .. } => {
                return Err(replay_error(
                    node,
                    "independent B0 verifier admits only verified P1V0 terms",
                ));
            }
        };
        self.record(node, BindingTimeNodeKind::Term, result)?;
        Ok(result)
    }

    fn rvalue(
        &mut self,
        value: &RValue,
        environment: &BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
    ) -> Result<ReplayedNode, BindingTimeAnalysisError> {
        let result = match value {
            RValue::Use(operand) => {
                let operand_node = node.child(BindingTimePathField::UseOperand, 0);
                self.operand(operand, environment, control, &operand_node)?
            }
            RValue::Tuple(operands) => self.operands(
                operands,
                environment,
                control,
                node,
                BindingTimePathField::TupleElement,
            )?,
            RValue::Project { tuple, .. } => {
                let tuple_node = node.child(BindingTimePathField::ProjectTuple, 0);
                self.operand(tuple, environment, control, &tuple_node)?
            }
            RValue::Construct { fields, .. } => self.operands(
                fields,
                environment,
                control,
                node,
                BindingTimePathField::ConstructField,
            )?,
            RValue::Primitive {
                operation,
                arguments,
            } => {
                let arguments = self.operands(
                    arguments,
                    environment,
                    control,
                    node,
                    BindingTimePathField::PrimitiveArgument,
                )?;
                ReplayedNode {
                    binding_time: arguments.binding_time,
                    static_evaluation: if replay_primitive_is_default_pure(operation) {
                        arguments.static_evaluation
                    } else {
                        StaticEvaluationEligibility::Denied
                    },
                }
            }
            RValue::Call {
                function,
                arguments,
            } => self.call(
                *function,
                arguments,
                environment,
                control,
                node,
                BindingTimePathField::CallArgument,
            )?,
            RValue::RefAlloc { .. }
            | RValue::RefLoad { .. }
            | RValue::RefStore { .. }
            | RValue::PackClosure { .. }
            | RValue::CallClosure { .. }
            | RValue::Perform { .. } => {
                return Err(replay_error(
                    node,
                    "independent B0 verifier admits only verified P1V0 rvalues",
                ));
            }
        };
        self.record(node, BindingTimeNodeKind::RValue, result)?;
        Ok(result)
    }

    fn operands(
        &mut self,
        operands: &[Operand],
        environment: &BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
        field: BindingTimePathField,
    ) -> Result<ReplayedNode, BindingTimeAnalysisError> {
        let mut binding_time = control;
        let mut eligibility = Vec::with_capacity(operands.len());
        for (index, operand) in operands.iter().enumerate() {
            let index = replay_index(index, node)?;
            let operand_node = node.child(field, index);
            let operand = self.operand(operand, environment, control, &operand_node)?;
            binding_time = binding_time.join(operand.binding_time);
            eligibility.push(operand.static_evaluation);
        }
        Ok(ReplayedNode {
            binding_time,
            static_evaluation: replay_eligible_if(binding_time, eligibility),
        })
    }

    fn call(
        &mut self,
        function: FunctionId,
        arguments: &[Operand],
        environment: &BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
        field: BindingTimePathField,
    ) -> Result<ReplayedNode, BindingTimeAnalysisError> {
        let Some(callee) = self.summaries.get(&function).cloned() else {
            return Err(replay_error(
                node,
                &format!("call targets missing function {}", function.0),
            ));
        };
        if arguments.len() != callee.parameters.len() {
            return Err(replay_error(
                node,
                &format!(
                    "call to function {} has {} argument(s), expected {}",
                    function.0,
                    arguments.len(),
                    callee.parameters.len()
                ),
            ));
        }
        if self.call_edges == self.max_call_edges {
            return Err(replay_error(
                node,
                &format!("exceeded max_call_edges {}", self.max_call_edges),
            ));
        }
        self.call_edges += 1;

        let mut inferred_arguments = Vec::with_capacity(arguments.len());
        for (index, argument) in arguments.iter().enumerate() {
            let index = replay_index(index, node)?;
            let argument_node = node.child(field, index);
            inferred_arguments.push(self.operand(
                argument,
                environment,
                control,
                &argument_node,
            )?);
        }

        let contribution =
            self.contributions
                .entry(function)
                .or_insert_with(|| ReplayContribution {
                    parameters: vec![BindingTime::Static; arguments.len()],
                    control: BindingTime::Static,
                });
        contribution.control = contribution.control.join(control);
        for (parameter, argument) in contribution.parameters.iter_mut().zip(&inferred_arguments) {
            *parameter = parameter.join(argument.binding_time);
        }

        let binding_time = callee.result.join(control);
        Ok(ReplayedNode {
            binding_time,
            static_evaluation: replay_eligible_if(
                binding_time,
                inferred_arguments
                    .into_iter()
                    .map(|argument| argument.static_evaluation)
                    .chain([callee.static_evaluation]),
            ),
        })
    }

    fn operand(
        &mut self,
        operand: &Operand,
        environment: &BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
    ) -> Result<ReplayedNode, BindingTimeAnalysisError> {
        let dependency = match operand {
            Operand::Unit | Operand::Bool(_) | Operand::I64(_) | Operand::F64(_) => {
                BindingTime::Static
            }
            Operand::Local(local) => environment.get(local).copied().ok_or_else(|| {
                replay_error(
                    node,
                    &format!("independent B0 environment has no local {}", local.0),
                )
            })?,
        };
        let binding_time = dependency.join(control);
        let result = ReplayedNode {
            binding_time,
            static_evaluation: replay_eligible_if(binding_time, []),
        };
        self.record(node, BindingTimeNodeKind::Operand, result)?;
        Ok(result)
    }

    fn record(
        &mut self,
        node: &BindingTimeNodeId,
        kind: BindingTimeNodeKind,
        result: ReplayedNode,
    ) -> Result<(), BindingTimeAnalysisError> {
        if self.nodes == self.max_nodes {
            return Err(replay_error(
                node,
                &format!("exceeded max_nodes {}", self.max_nodes),
            ));
        }
        self.nodes += 1;
        self.judgments.push(BindingTimeJudgment {
            node: node.clone(),
            kind,
            binding_time: result.binding_time,
            static_evaluation: result.static_evaluation,
        });
        Ok(())
    }
}

fn replay_binding_time_b0c(
    validated: &ValidatedBindingTimeRequest<'_>,
) -> Result<BindingTimeAnalysis, BindingTimeAnalysisError> {
    let program = validated.artifact().program();
    let mut summaries = program
        .functions
        .iter()
        .map(|function| {
            (
                function.id,
                BindingTimeFunctionSummary {
                    function: function.id,
                    reachable: false,
                    parameters: vec![BindingTime::Static; function.parameters.len()],
                    control: BindingTime::Static,
                    result: BindingTime::Static,
                    static_evaluation: StaticEvaluationEligibility::EligiblePure,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let Some(entry) = summaries.get_mut(&program.entry) else {
        return Err(replay_error(
            &BindingTimeNodeId::root(program.entry),
            "verified request has no entry function",
        ));
    };
    entry.reachable = true;
    entry.parameters = validated.request().entry_parameters.clone();

    let budget = validated.request().budget;
    let mut usage = BindingTimeBudgetUsage::default();
    loop {
        if usage.fixpoint_iterations == budget.max_fixpoint_iterations {
            return Err(replay_error(
                &BindingTimeNodeId::root(program.entry),
                &format!(
                    "exceeded max_fixpoint_iterations {}",
                    budget.max_fixpoint_iterations
                ),
            ));
        }
        usage.fixpoint_iterations += 1;

        let snapshot = summaries.clone();
        let mut next = summaries.clone();
        let mut round_judgments = Vec::new();
        for function in &program.functions {
            let summary = snapshot
                .get(&function.id)
                .expect("verified function has an independent replay summary");
            if !summary.reachable {
                continue;
            }
            let mut environment = function
                .parameters
                .iter()
                .zip(&summary.parameters)
                .map(|(parameter, binding_time)| (parameter.local, *binding_time))
                .collect::<BTreeMap<_, _>>();
            let mut traversal = EvidenceTraversal {
                max_nodes: budget.max_nodes,
                max_call_edges: budget.max_call_edges,
                judgments: Vec::new(),
                nodes: usage.nodes,
                call_edges: usage.call_edges,
                summaries: &snapshot,
                contributions: BTreeMap::new(),
            };
            let result = traversal.term(
                &function.body,
                &mut environment,
                summary.control,
                &BindingTimeNodeId::root(function.id),
            )?;
            usage.nodes = traversal.nodes;
            usage.call_edges = traversal.call_edges;
            round_judgments.extend(traversal.judgments);

            let next_summary = next
                .get_mut(&function.id)
                .expect("verified function has a next independent replay summary");
            next_summary.result = next_summary.result.join(result.binding_time);
            next_summary.static_evaluation =
                replay_eligibility_join(next_summary.static_evaluation, result.static_evaluation);

            for (callee, contribution) in traversal.contributions {
                let Some(callee_summary) = next.get_mut(&callee) else {
                    return Err(replay_error(
                        &BindingTimeNodeId::root(function.id),
                        &format!("contribution targets missing function {}", callee.0),
                    ));
                };
                callee_summary.reachable = true;
                callee_summary.control = callee_summary.control.join(contribution.control);
                for (parameter, binding_time) in callee_summary
                    .parameters
                    .iter_mut()
                    .zip(contribution.parameters)
                {
                    *parameter = parameter.join(binding_time);
                }
            }
        }

        let stable = next == summaries;
        summaries = next;
        if stable {
            round_judgments.sort_by(|left, right| left.node.cmp(&right.node));
            let entry = summaries
                .get(&program.entry)
                .expect("entry initialized before independent replay");
            let result_binding_time = entry.result;
            let static_evaluation = entry.static_evaluation;
            return Ok(BindingTimeAnalysis {
                request_hash: validated.request_hash(),
                entry_function: program.entry,
                function_summaries: summaries.into_values().collect(),
                judgments: round_judgments,
                result_binding_time,
                static_evaluation,
                budget_usage: usage,
            });
        }
    }
}

fn replay_eligible_if(
    binding_time: BindingTime,
    dependencies: impl IntoIterator<Item = StaticEvaluationEligibility>,
) -> StaticEvaluationEligibility {
    if binding_time == BindingTime::Static
        && dependencies
            .into_iter()
            .all(|eligibility| eligibility == StaticEvaluationEligibility::EligiblePure)
    {
        StaticEvaluationEligibility::EligiblePure
    } else {
        StaticEvaluationEligibility::Denied
    }
}

fn replay_eligibility_join(
    left: StaticEvaluationEligibility,
    right: StaticEvaluationEligibility,
) -> StaticEvaluationEligibility {
    if left == StaticEvaluationEligibility::EligiblePure
        && right == StaticEvaluationEligibility::EligiblePure
    {
        StaticEvaluationEligibility::EligiblePure
    } else {
        StaticEvaluationEligibility::Denied
    }
}

fn replay_primitive_is_default_pure(primitive: &Primitive) -> bool {
    match primitive {
        Primitive::I64Add(mode) | Primitive::I64Sub(mode) | Primitive::I64Mul(mode) => {
            *mode != NumericMode::Checked
        }
        Primitive::ArrayGetF64 => false,
        Primitive::F64Add
        | Primitive::F64Sub
        | Primitive::I64CmpLt
        | Primitive::I64CmpGe
        | Primitive::ArrayLenF64 => true,
    }
}

fn replay_index(index: usize, node: &BindingTimeNodeId) -> Result<u32, BindingTimeAnalysisError> {
    u32::try_from(index)
        .map_err(|_| replay_error(node, &format!("canonical node index {index} exceeds u32")))
}

fn replay_error(node: &BindingTimeNodeId, message: &str) -> BindingTimeAnalysisError {
    BindingTimeAnalysisError {
        code: super::staging::BindingTimeAnalysisCode::UnsupportedNode,
        node: node.clone(),
        message: message.to_owned(),
    }
}
