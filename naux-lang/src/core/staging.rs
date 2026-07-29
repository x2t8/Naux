use super::encoding::{
    binding_time_certificate_hash, binding_time_policy_hash, binding_time_request_hash,
    interpreter_semantics_hash, EncodeError,
};
use super::schema::{
    CoreArtifact, CoreProfile, FunctionId, LocalId, NumericMode, Operand, Primitive, RValue,
    SemanticHash, Term,
};
use super::verify::{verify, VerifiedArtifact};
use std::collections::BTreeMap;
use std::fmt;

pub const B0_REQUEST_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const B0_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const B0_CERTIFICATE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const B0_MAX_NODES_HARD_CAP: u64 = 1_000_000;
pub const B0_MAX_CALL_EDGES_HARD_CAP: u64 = 1_000_000;
pub const B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP: u32 = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingTime {
    Static,
    Dynamic,
}

impl BindingTime {
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Static, Self::Static) => Self::Static,
            _ => Self::Dynamic,
        }
    }

    pub const fn is_at_most(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Static, Self::Static | Self::Dynamic) | (Self::Dynamic, Self::Dynamic)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingTimePathField {
    LetValue,
    LetNext,
    IfCondition,
    IfThen,
    IfElse,
    CaseScrutinee,
    CaseArm,
    ReturnOperand,
    UseOperand,
    TupleElement,
    ProjectTuple,
    ConstructField,
    PrimitiveArgument,
    CallArgument,
    TailCallArgument,
}

impl BindingTimePathField {
    pub const fn tag(self) -> u8 {
        match self {
            Self::LetValue => 0,
            Self::LetNext => 1,
            Self::IfCondition => 2,
            Self::IfThen => 3,
            Self::IfElse => 4,
            Self::CaseScrutinee => 5,
            Self::CaseArm => 6,
            Self::ReturnOperand => 7,
            Self::UseOperand => 8,
            Self::TupleElement => 9,
            Self::ProjectTuple => 10,
            Self::ConstructField => 11,
            Self::PrimitiveArgument => 12,
            Self::CallArgument => 13,
            Self::TailCallArgument => 14,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingTimePathSegment {
    pub field: BindingTimePathField,
    pub index: u32,
}

impl BindingTimePathSegment {
    pub const fn new(field: BindingTimePathField, index: u32) -> Self {
        Self { field, index }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingTimeNodeId {
    pub function: FunctionId,
    pub path: Vec<BindingTimePathSegment>,
}

impl BindingTimeNodeId {
    pub fn root(function: FunctionId) -> Self {
        Self {
            function,
            path: Vec::new(),
        }
    }

    pub fn child(&self, field: BindingTimePathField, index: u32) -> Self {
        let mut path = self.path.clone();
        path.push(BindingTimePathSegment::new(field, index));
        Self {
            function: self.function,
            path,
        }
    }
}

impl fmt::Display for BindingTimeNodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "function[{}]", self.function.0)?;
        if self.path.is_empty() {
            return formatter.write_str(".body");
        }
        for segment in &self.path {
            write!(formatter, ".{:?}[{}]", segment.field, segment.index)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingTimeNodeKind {
    Term,
    RValue,
    Operand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticEvaluationEligibility {
    EligiblePure,
    Denied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeJudgment {
    pub node: BindingTimeNodeId,
    pub kind: BindingTimeNodeKind,
    pub binding_time: BindingTime,
    pub static_evaluation: StaticEvaluationEligibility,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BindingTimeBudgetUsage {
    pub nodes: u64,
    pub call_edges: u64,
    pub fixpoint_iterations: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeAnalysis {
    pub request_hash: SemanticHash,
    pub entry_function: FunctionId,
    pub function_summaries: Vec<BindingTimeFunctionSummary>,
    pub judgments: Vec<BindingTimeJudgment>,
    pub result_binding_time: BindingTime,
    pub static_evaluation: StaticEvaluationEligibility,
    pub budget_usage: BindingTimeBudgetUsage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeFunctionSummary {
    pub function: FunctionId,
    pub reachable: bool,
    pub parameters: Vec<BindingTime>,
    pub control: BindingTime,
    pub result: BindingTime,
    pub static_evaluation: StaticEvaluationEligibility,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeCertificate {
    pub schema_version: (u16, u16, u16),
    pub source_program_hash: SemanticHash,
    pub interpreter_semantics_hash: SemanticHash,
    pub policy_hash: SemanticHash,
    pub request_hash: SemanticHash,
    pub entry_function: FunctionId,
    pub entry_parameters: Vec<BindingTime>,
    pub judgments: Vec<BindingTimeJudgment>,
    pub function_summaries: Vec<BindingTimeFunctionSummary>,
    pub declared_budget: BindingTimeBudget,
    pub budget_usage: BindingTimeBudgetUsage,
    pub certificate_hash: SemanticHash,
}

#[derive(Debug)]
pub enum BindingTimeCertificateBuildError {
    Analysis(BindingTimeAnalysisError),
    Encoding(EncodeError),
}

impl fmt::Display for BindingTimeCertificateBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Analysis(error) => write!(formatter, "B0-D analysis failed: {error}"),
            Self::Encoding(error) => write!(formatter, "B0-D certificate encoding failed: {error}"),
        }
    }
}

impl std::error::Error for BindingTimeCertificateBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Analysis(error) => Some(error),
            Self::Encoding(error) => Some(error),
        }
    }
}

impl From<BindingTimeAnalysisError> for BindingTimeCertificateBuildError {
    fn from(error: BindingTimeAnalysisError) -> Self {
        Self::Analysis(error)
    }
}

impl From<EncodeError> for BindingTimeCertificateBuildError {
    fn from(error: EncodeError) -> Self {
        Self::Encoding(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingTimeAnalysisCode {
    NodeBudgetExceeded,
    CallEdgeBudgetExceeded,
    FixpointBudgetExceeded,
    UnsupportedInterprocedural,
    UnsupportedNode,
    MissingLocal,
    MissingFunction,
    CallArityMismatch,
    MissingEntry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeAnalysisError {
    pub code: BindingTimeAnalysisCode,
    pub node: BindingTimeNodeId,
    pub message: String,
}

impl fmt::Display for BindingTimeAnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at {}: {}",
            self.code, self.node, self.message
        )
    }
}

impl std::error::Error for BindingTimeAnalysisError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingTimeBudget {
    pub max_nodes: u64,
    pub max_call_edges: u64,
    pub max_fixpoint_iterations: u32,
}

impl BindingTimeBudget {
    pub const fn new(max_nodes: u64, max_call_edges: u64, max_fixpoint_iterations: u32) -> Self {
        Self {
            max_nodes,
            max_call_edges,
            max_fixpoint_iterations,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeRequest {
    pub schema_version: (u16, u16, u16),
    pub source_program_hash: SemanticHash,
    pub interpreter_semantics_hash: SemanticHash,
    pub policy_version: (u16, u16, u16),
    pub policy_hash: SemanticHash,
    pub entry_parameters: Vec<BindingTime>,
    pub budget: BindingTimeBudget,
}

impl BindingTimeRequest {
    /// Build the canonical B0 request envelope for a P1V0 artifact.
    ///
    /// Construction does not verify the artifact. The request becomes trusted
    /// only after `validate_binding_time_b0_request` succeeds.
    pub fn p1v0(
        artifact: &CoreArtifact,
        entry_parameters: Vec<BindingTime>,
        budget: BindingTimeBudget,
    ) -> Result<Self, EncodeError> {
        Ok(Self {
            schema_version: B0_REQUEST_SCHEMA_VERSION,
            source_program_hash: artifact.semantic_hash,
            interpreter_semantics_hash: interpreter_semantics_hash(CoreProfile::P1V0)?,
            policy_version: B0_POLICY_VERSION,
            policy_hash: binding_time_policy_hash()?,
            entry_parameters,
            budget,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingTimeRequestCode {
    InvalidArtifact,
    UnsupportedProfile,
    UnsupportedRequestSchema,
    SourceProgramHashMismatch,
    InterpreterSemanticsHashMismatch,
    UnsupportedPolicyVersion,
    PolicyHashMismatch,
    EntryManifestArity,
    ZeroBudget,
    BudgetHardCapExceeded,
    EncodingFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeRequestError {
    pub code: BindingTimeRequestCode,
    pub path: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingTimeRequestErrors(pub Vec<BindingTimeRequestError>);

impl fmt::Display for BindingTimeRequestErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} binding-time B0 request error(s)",
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

impl std::error::Error for BindingTimeRequestErrors {}

#[derive(Clone, Debug)]
pub struct ValidatedBindingTimeRequest<'artifact> {
    verified_artifact: VerifiedArtifact<'artifact>,
    request: BindingTimeRequest,
    request_hash: SemanticHash,
}

impl<'artifact> ValidatedBindingTimeRequest<'artifact> {
    pub fn artifact(&self) -> VerifiedArtifact<'artifact> {
        self.verified_artifact
    }

    pub fn request(&self) -> &BindingTimeRequest {
        &self.request
    }

    pub fn request_hash(&self) -> SemanticHash {
        self.request_hash
    }
}

pub fn analyze_binding_time_b0b(
    validated: &ValidatedBindingTimeRequest<'_>,
) -> Result<BindingTimeAnalysis, BindingTimeAnalysisError> {
    let program = validated.artifact().program();
    let Some(entry) = program
        .functions
        .iter()
        .find(|function| function.id == program.entry)
    else {
        return Err(BindingTimeAnalysisError {
            code: BindingTimeAnalysisCode::MissingEntry,
            node: BindingTimeNodeId::root(program.entry),
            message: "verified B0 request has no entry function".to_owned(),
        });
    };

    let mut environment = entry
        .parameters
        .iter()
        .zip(&validated.request().entry_parameters)
        .map(|(parameter, binding_time)| (parameter.local, *binding_time))
        .collect::<BTreeMap<_, _>>();
    let mut analyzer = IntraproceduralAnalyzer {
        max_nodes: validated.request().budget.max_nodes,
        max_call_edges: validated.request().budget.max_call_edges,
        judgments: Vec::new(),
        nodes: 0,
        call_edges: 0,
        call_summaries: None,
        contributions: BTreeMap::new(),
    };
    let result = analyzer.analyze_term(
        &entry.body,
        &mut environment,
        BindingTime::Static,
        &BindingTimeNodeId::root(entry.id),
    )?;
    analyzer
        .judgments
        .sort_by(|left, right| left.node.cmp(&right.node));

    Ok(BindingTimeAnalysis {
        request_hash: validated.request_hash(),
        entry_function: entry.id,
        function_summaries: vec![BindingTimeFunctionSummary {
            function: entry.id,
            reachable: true,
            parameters: validated.request().entry_parameters.clone(),
            control: BindingTime::Static,
            result: result.binding_time,
            static_evaluation: result.static_evaluation,
        }],
        judgments: analyzer.judgments,
        result_binding_time: result.binding_time,
        static_evaluation: result.static_evaluation,
        budget_usage: BindingTimeBudgetUsage {
            nodes: analyzer.nodes,
            call_edges: 0,
            fixpoint_iterations: 0,
        },
    })
}

pub fn analyze_binding_time_b0c(
    validated: &ValidatedBindingTimeRequest<'_>,
) -> Result<BindingTimeAnalysis, BindingTimeAnalysisError> {
    let program = validated.artifact().program();
    if !program
        .functions
        .iter()
        .any(|function| function.id == program.entry)
    {
        return Err(BindingTimeAnalysisError {
            code: BindingTimeAnalysisCode::MissingEntry,
            node: BindingTimeNodeId::root(program.entry),
            message: "verified B0 request has no entry function".to_owned(),
        });
    }

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
    let entry = summaries
        .get_mut(&program.entry)
        .expect("entry existence checked above");
    entry.reachable = true;
    entry.parameters = validated.request().entry_parameters.clone();

    let budget = validated.request().budget;
    let mut usage = BindingTimeBudgetUsage::default();

    loop {
        if usage.fixpoint_iterations == budget.max_fixpoint_iterations {
            return Err(BindingTimeAnalysisError {
                code: BindingTimeAnalysisCode::FixpointBudgetExceeded,
                node: BindingTimeNodeId::root(program.entry),
                message: format!(
                    "B0-C exceeded max_fixpoint_iterations {}",
                    budget.max_fixpoint_iterations
                ),
            });
        }
        usage.fixpoint_iterations += 1;

        let snapshot = summaries.clone();
        let mut next = summaries.clone();
        let mut round_judgments = Vec::new();

        for function in &program.functions {
            let summary = snapshot
                .get(&function.id)
                .expect("verified function has an initialized B0-C summary");
            if !summary.reachable {
                continue;
            }

            let mut environment = function
                .parameters
                .iter()
                .zip(&summary.parameters)
                .map(|(parameter, binding_time)| (parameter.local, *binding_time))
                .collect::<BTreeMap<_, _>>();
            let mut analyzer = IntraproceduralAnalyzer {
                max_nodes: budget.max_nodes,
                max_call_edges: budget.max_call_edges,
                judgments: Vec::new(),
                nodes: usage.nodes,
                call_edges: usage.call_edges,
                call_summaries: Some(&snapshot),
                contributions: BTreeMap::new(),
            };
            let result = analyzer.analyze_term(
                &function.body,
                &mut environment,
                summary.control,
                &BindingTimeNodeId::root(function.id),
            )?;
            usage.nodes = analyzer.nodes;
            usage.call_edges = analyzer.call_edges;
            round_judgments.extend(analyzer.judgments);

            let next_summary = next
                .get_mut(&function.id)
                .expect("verified function has a next-round B0-C summary");
            next_summary.result = next_summary.result.join(result.binding_time);
            next_summary.static_evaluation =
                eligibility_join(next_summary.static_evaluation, result.static_evaluation);

            for (callee, contribution) in analyzer.contributions {
                let Some(callee_summary) = next.get_mut(&callee) else {
                    return Err(BindingTimeAnalysisError {
                        code: BindingTimeAnalysisCode::MissingFunction,
                        node: BindingTimeNodeId::root(function.id),
                        message: format!(
                            "verified B0-C call contribution targets missing function {}",
                            callee.0
                        ),
                    });
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
            let entry_summary = summaries
                .get(&program.entry)
                .expect("entry existence checked above");
            let result_binding_time = entry_summary.result;
            let static_evaluation = entry_summary.static_evaluation;
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

pub fn certify_binding_time_b0d(
    validated: &ValidatedBindingTimeRequest<'_>,
) -> Result<BindingTimeCertificate, BindingTimeCertificateBuildError> {
    let analysis = analyze_binding_time_b0c(validated)?;
    let request = validated.request();
    let mut certificate = BindingTimeCertificate {
        schema_version: B0_CERTIFICATE_SCHEMA_VERSION,
        source_program_hash: request.source_program_hash,
        interpreter_semantics_hash: request.interpreter_semantics_hash,
        policy_hash: request.policy_hash,
        request_hash: validated.request_hash(),
        entry_function: analysis.entry_function,
        entry_parameters: request.entry_parameters.clone(),
        judgments: analysis.judgments,
        function_summaries: analysis.function_summaries,
        declared_budget: request.budget,
        budget_usage: analysis.budget_usage,
        certificate_hash: SemanticHash::ZERO,
    };
    certificate.certificate_hash = binding_time_certificate_hash(&certificate)?;
    Ok(certificate)
}

pub fn validate_binding_time_b0_request<'artifact>(
    artifact: &'artifact CoreArtifact,
    request: &BindingTimeRequest,
) -> Result<ValidatedBindingTimeRequest<'artifact>, BindingTimeRequestErrors> {
    let verified_artifact = verify(artifact).map_err(|errors| {
        BindingTimeRequestErrors(vec![BindingTimeRequestError {
            code: BindingTimeRequestCode::InvalidArtifact,
            path: "request.source",
            message: errors.to_string(),
        }])
    })?;
    let program = verified_artifact.program();
    let mut errors = Vec::new();

    if program.profile != CoreProfile::P1V0 {
        push_error(
            &mut errors,
            BindingTimeRequestCode::UnsupportedProfile,
            "request.source.profile",
            format!("B0 admits P1V0, found {:?}", program.profile),
        );
    }
    if request.schema_version != B0_REQUEST_SCHEMA_VERSION {
        push_error(
            &mut errors,
            BindingTimeRequestCode::UnsupportedRequestSchema,
            "request.schema_version",
            format!(
                "expected {:?}, found {:?}",
                B0_REQUEST_SCHEMA_VERSION, request.schema_version
            ),
        );
    }
    if request.source_program_hash != verified_artifact.semantic_hash() {
        push_error(
            &mut errors,
            BindingTimeRequestCode::SourceProgramHashMismatch,
            "request.source_program_hash",
            "request source hash does not match the verified artifact".to_owned(),
        );
    }

    match interpreter_semantics_hash(CoreProfile::P1V0) {
        Ok(expected) if request.interpreter_semantics_hash != expected => push_error(
            &mut errors,
            BindingTimeRequestCode::InterpreterSemanticsHashMismatch,
            "request.interpreter_semantics_hash",
            "request semantics hash does not match frozen P1V0".to_owned(),
        ),
        Err(error) => push_error(
            &mut errors,
            BindingTimeRequestCode::EncodingFailure,
            "request.interpreter_semantics_hash",
            error.to_string(),
        ),
        _ => {}
    }

    if request.policy_version != B0_POLICY_VERSION {
        push_error(
            &mut errors,
            BindingTimeRequestCode::UnsupportedPolicyVersion,
            "request.policy_version",
            format!(
                "expected {:?}, found {:?}",
                B0_POLICY_VERSION, request.policy_version
            ),
        );
    }
    match binding_time_policy_hash() {
        Ok(expected) if request.policy_hash != expected => push_error(
            &mut errors,
            BindingTimeRequestCode::PolicyHashMismatch,
            "request.policy_hash",
            "request policy hash does not match B0 policy v1".to_owned(),
        ),
        Err(error) => push_error(
            &mut errors,
            BindingTimeRequestCode::EncodingFailure,
            "request.policy_hash",
            error.to_string(),
        ),
        _ => {}
    }

    let entry_arity = program
        .functions
        .iter()
        .find(|function| function.id == program.entry)
        .map_or(0, |function| function.parameters.len());
    if request.entry_parameters.len() != entry_arity {
        push_error(
            &mut errors,
            BindingTimeRequestCode::EntryManifestArity,
            "request.entry_parameters",
            format!(
                "expected {entry_arity} entry parameter(s), found {}",
                request.entry_parameters.len()
            ),
        );
    }

    validate_budget(&mut errors, request.budget);

    if !errors.is_empty() {
        return Err(BindingTimeRequestErrors(errors));
    }

    let request_hash = binding_time_request_hash(request).map_err(|error| {
        BindingTimeRequestErrors(vec![BindingTimeRequestError {
            code: BindingTimeRequestCode::EncodingFailure,
            path: "request",
            message: error.to_string(),
        }])
    })?;
    Ok(ValidatedBindingTimeRequest {
        verified_artifact,
        request: request.clone(),
        request_hash,
    })
}

fn validate_budget(errors: &mut Vec<BindingTimeRequestError>, budget: BindingTimeBudget) {
    if budget.max_nodes == 0 {
        push_error(
            errors,
            BindingTimeRequestCode::ZeroBudget,
            "request.budget.max_nodes",
            "max_nodes must be non-zero".to_owned(),
        );
    } else if budget.max_nodes > B0_MAX_NODES_HARD_CAP {
        push_error(
            errors,
            BindingTimeRequestCode::BudgetHardCapExceeded,
            "request.budget.max_nodes",
            format!("max_nodes exceeds hard cap {B0_MAX_NODES_HARD_CAP}"),
        );
    }

    if budget.max_call_edges == 0 {
        push_error(
            errors,
            BindingTimeRequestCode::ZeroBudget,
            "request.budget.max_call_edges",
            "max_call_edges must be non-zero".to_owned(),
        );
    } else if budget.max_call_edges > B0_MAX_CALL_EDGES_HARD_CAP {
        push_error(
            errors,
            BindingTimeRequestCode::BudgetHardCapExceeded,
            "request.budget.max_call_edges",
            format!("max_call_edges exceeds hard cap {B0_MAX_CALL_EDGES_HARD_CAP}"),
        );
    }

    if budget.max_fixpoint_iterations == 0 {
        push_error(
            errors,
            BindingTimeRequestCode::ZeroBudget,
            "request.budget.max_fixpoint_iterations",
            "max_fixpoint_iterations must be non-zero".to_owned(),
        );
    } else if budget.max_fixpoint_iterations > B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP {
        push_error(
            errors,
            BindingTimeRequestCode::BudgetHardCapExceeded,
            "request.budget.max_fixpoint_iterations",
            format!(
                "max_fixpoint_iterations exceeds hard cap \
                 {B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP}"
            ),
        );
    }
}

fn push_error(
    errors: &mut Vec<BindingTimeRequestError>,
    code: BindingTimeRequestCode,
    path: &'static str,
    message: String,
) {
    errors.push(BindingTimeRequestError {
        code,
        path,
        message,
    });
}

#[derive(Clone, Copy)]
struct InferredNode {
    binding_time: BindingTime,
    static_evaluation: StaticEvaluationEligibility,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CallContribution {
    parameters: Vec<BindingTime>,
    control: BindingTime,
}

struct IntraproceduralAnalyzer<'summary> {
    max_nodes: u64,
    max_call_edges: u64,
    judgments: Vec<BindingTimeJudgment>,
    nodes: u64,
    call_edges: u64,
    call_summaries: Option<&'summary BTreeMap<FunctionId, BindingTimeFunctionSummary>>,
    contributions: BTreeMap<FunctionId, CallContribution>,
}

impl IntraproceduralAnalyzer<'_> {
    fn analyze_term(
        &mut self,
        term: &Term,
        environment: &mut BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
    ) -> Result<InferredNode, BindingTimeAnalysisError> {
        let result = match term {
            Term::Let {
                binder,
                value,
                next,
                ..
            } => {
                let value_node = node.child(BindingTimePathField::LetValue, 0);
                let value = self.analyze_rvalue(value, environment, control, &value_node)?;
                environment.insert(*binder, value.binding_time);
                let next_node = node.child(BindingTimePathField::LetNext, 0);
                let next = self.analyze_term(next, environment, control, &next_node)?;
                InferredNode {
                    binding_time: next.binding_time,
                    static_evaluation: eligible_if(
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
                let condition =
                    self.analyze_operand(condition, environment, control, &condition_node)?;
                let mut then_environment = environment.clone();
                let then_node = node.child(BindingTimePathField::IfThen, 0);
                let then_result = self.analyze_term(
                    then_term,
                    &mut then_environment,
                    condition.binding_time,
                    &then_node,
                )?;
                let mut else_environment = environment.clone();
                let else_node = node.child(BindingTimePathField::IfElse, 0);
                let else_result = self.analyze_term(
                    else_term,
                    &mut else_environment,
                    condition.binding_time,
                    &else_node,
                )?;
                let binding_time = then_result.binding_time.join(else_result.binding_time);
                InferredNode {
                    binding_time,
                    static_evaluation: eligible_if(
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
                let scrutinee =
                    self.analyze_operand(scrutinee, environment, control, &scrutinee_node)?;
                let mut binding_time = BindingTime::Static;
                let mut eligibility = vec![scrutinee.static_evaluation];
                for (index, arm) in arms.iter().enumerate() {
                    let mut arm_environment = environment.clone();
                    for binding in &arm.bindings {
                        arm_environment.insert(*binding, scrutinee.binding_time);
                    }
                    let index = canonical_index(index, node)?;
                    let arm_node = node.child(BindingTimePathField::CaseArm, index);
                    let arm_result = self.analyze_term(
                        &arm.body,
                        &mut arm_environment,
                        scrutinee.binding_time,
                        &arm_node,
                    )?;
                    binding_time = binding_time.join(arm_result.binding_time);
                    eligibility.push(arm_result.static_evaluation);
                }
                InferredNode {
                    binding_time,
                    static_evaluation: eligible_if(binding_time, eligibility),
                }
            }
            Term::TailCall {
                function,
                arguments,
            } => self.analyze_call(
                *function,
                arguments,
                environment,
                control,
                node,
                BindingTimePathField::TailCallArgument,
            )?,
            Term::Return(operand) => {
                let operand_node = node.child(BindingTimePathField::ReturnOperand, 0);
                self.analyze_operand(operand, environment, control, &operand_node)?
            }
            Term::Region { .. } | Term::Handle { .. } => {
                return Err(BindingTimeAnalysisError {
                    code: BindingTimeAnalysisCode::UnsupportedNode,
                    node: node.clone(),
                    message: "B0-B admits only verified P1V0 intraprocedural nodes".to_owned(),
                });
            }
        };
        self.record(node, BindingTimeNodeKind::Term, result)?;
        Ok(result)
    }

    fn analyze_rvalue(
        &mut self,
        value: &RValue,
        environment: &BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
    ) -> Result<InferredNode, BindingTimeAnalysisError> {
        let result = match value {
            RValue::Use(operand) => {
                let operand_node = node.child(BindingTimePathField::UseOperand, 0);
                self.analyze_operand(operand, environment, control, &operand_node)?
            }
            RValue::Tuple(operands) => self.analyze_operands(
                operands,
                environment,
                control,
                node,
                BindingTimePathField::TupleElement,
            )?,
            RValue::Project { tuple, .. } => {
                let tuple_node = node.child(BindingTimePathField::ProjectTuple, 0);
                self.analyze_operand(tuple, environment, control, &tuple_node)?
            }
            RValue::Construct { fields, .. } => self.analyze_operands(
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
                let arguments = self.analyze_operands(
                    arguments,
                    environment,
                    control,
                    node,
                    BindingTimePathField::PrimitiveArgument,
                )?;
                InferredNode {
                    binding_time: arguments.binding_time,
                    static_evaluation: if primitive_is_default_pure(operation) {
                        arguments.static_evaluation
                    } else {
                        StaticEvaluationEligibility::Denied
                    },
                }
            }
            RValue::Call {
                function,
                arguments,
            } => self.analyze_call(
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
                return Err(BindingTimeAnalysisError {
                    code: BindingTimeAnalysisCode::UnsupportedNode,
                    node: node.clone(),
                    message: "B0-B admits only verified P1V0 rvalues".to_owned(),
                });
            }
        };
        self.record(node, BindingTimeNodeKind::RValue, result)?;
        Ok(result)
    }

    fn analyze_operands(
        &mut self,
        operands: &[Operand],
        environment: &BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
        field: BindingTimePathField,
    ) -> Result<InferredNode, BindingTimeAnalysisError> {
        let mut binding_time = control;
        let mut eligibility = Vec::with_capacity(operands.len());
        for (index, operand) in operands.iter().enumerate() {
            let index = canonical_index(index, node)?;
            let operand_node = node.child(field, index);
            let operand = self.analyze_operand(operand, environment, control, &operand_node)?;
            binding_time = binding_time.join(operand.binding_time);
            eligibility.push(operand.static_evaluation);
        }
        Ok(InferredNode {
            binding_time,
            static_evaluation: eligible_if(binding_time, eligibility),
        })
    }

    fn analyze_call(
        &mut self,
        function: FunctionId,
        arguments: &[Operand],
        environment: &BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
        field: BindingTimePathField,
    ) -> Result<InferredNode, BindingTimeAnalysisError> {
        let Some(call_summaries) = self.call_summaries else {
            return Err(BindingTimeAnalysisError {
                code: BindingTimeAnalysisCode::UnsupportedInterprocedural,
                node: node.clone(),
                message: "B0-B defers direct and tail-call summaries to B0-C".to_owned(),
            });
        };
        let Some(callee) = call_summaries.get(&function).cloned() else {
            return Err(BindingTimeAnalysisError {
                code: BindingTimeAnalysisCode::MissingFunction,
                node: node.clone(),
                message: format!("verified B0-C call targets missing function {}", function.0),
            });
        };
        if arguments.len() != callee.parameters.len() {
            return Err(BindingTimeAnalysisError {
                code: BindingTimeAnalysisCode::CallArityMismatch,
                node: node.clone(),
                message: format!(
                    "verified B0-C call to function {} has {} argument(s), expected {}",
                    function.0,
                    arguments.len(),
                    callee.parameters.len()
                ),
            });
        }
        if self.call_edges == self.max_call_edges {
            return Err(BindingTimeAnalysisError {
                code: BindingTimeAnalysisCode::CallEdgeBudgetExceeded,
                node: node.clone(),
                message: format!("B0-C exceeded max_call_edges {}", self.max_call_edges),
            });
        }
        self.call_edges += 1;

        let mut inferred_arguments = Vec::with_capacity(arguments.len());
        for (index, argument) in arguments.iter().enumerate() {
            let index = canonical_index(index, node)?;
            let argument_node = node.child(field, index);
            inferred_arguments.push(self.analyze_operand(
                argument,
                environment,
                control,
                &argument_node,
            )?);
        }

        let contribution = self
            .contributions
            .entry(function)
            .or_insert_with(|| CallContribution {
                parameters: vec![BindingTime::Static; arguments.len()],
                control: BindingTime::Static,
            });
        contribution.control = contribution.control.join(control);
        for (parameter, argument) in contribution.parameters.iter_mut().zip(&inferred_arguments) {
            *parameter = parameter.join(argument.binding_time);
        }

        let binding_time = callee.result.join(control);
        Ok(InferredNode {
            binding_time,
            static_evaluation: eligible_if(
                binding_time,
                inferred_arguments
                    .into_iter()
                    .map(|argument| argument.static_evaluation)
                    .chain([callee.static_evaluation]),
            ),
        })
    }

    fn analyze_operand(
        &mut self,
        operand: &Operand,
        environment: &BTreeMap<LocalId, BindingTime>,
        control: BindingTime,
        node: &BindingTimeNodeId,
    ) -> Result<InferredNode, BindingTimeAnalysisError> {
        let dependency = match operand {
            Operand::Unit | Operand::Bool(_) | Operand::I64(_) | Operand::F64(_) => {
                BindingTime::Static
            }
            Operand::Local(local) => {
                environment
                    .get(local)
                    .copied()
                    .ok_or_else(|| BindingTimeAnalysisError {
                        code: BindingTimeAnalysisCode::MissingLocal,
                        node: node.clone(),
                        message: format!("verified B0-B environment has no local {}", local.0),
                    })?
            }
        };
        let binding_time = dependency.join(control);
        let result = InferredNode {
            binding_time,
            static_evaluation: eligible_if(binding_time, []),
        };
        self.record(node, BindingTimeNodeKind::Operand, result)?;
        Ok(result)
    }

    fn record(
        &mut self,
        node: &BindingTimeNodeId,
        kind: BindingTimeNodeKind,
        result: InferredNode,
    ) -> Result<(), BindingTimeAnalysisError> {
        if self.nodes == self.max_nodes {
            return Err(BindingTimeAnalysisError {
                code: BindingTimeAnalysisCode::NodeBudgetExceeded,
                node: node.clone(),
                message: format!("B0-B exceeded max_nodes {}", self.max_nodes),
            });
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

fn eligibility_join(
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

fn eligible_if(
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

fn primitive_is_default_pure(primitive: &Primitive) -> bool {
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

fn canonical_index(
    index: usize,
    node: &BindingTimeNodeId,
) -> Result<u32, BindingTimeAnalysisError> {
    u32::try_from(index).map_err(|_| BindingTimeAnalysisError {
        code: BindingTimeAnalysisCode::UnsupportedNode,
        node: node.clone(),
        message: format!("canonical node index {index} exceeds u32"),
    })
}
