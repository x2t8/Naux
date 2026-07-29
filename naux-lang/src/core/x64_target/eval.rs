//! Bounded logical evaluator for the canonical R1-S7a x86-64 target plan.
//!
//! This evaluator deliberately interprets target macro operations and logical
//! stack homes. It neither delegates to the Machine IR evaluator nor maps or
//! executes the artifact's raw x86-64 bytes.

use super::super::encoding::canonical_f64_bits;
use super::super::interpret::{
    CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome,
};
use super::super::machine_ir::MachineType;
use super::super::schema::ErrorKind;
use super::{
    X64Block, X64BlockId, X64Function, X64FunctionId, X64Home, X64HomeSlot, X64I64Opcode,
    X64Immediate, X64InstructionKind, X64LabelId, X64LabelOwner, X64Operand, X64SetCondition,
    X64Sse2F64Opcode, X64TargetProgram, X64Terminator, X64_TARGET_MAX_PLAN_EVAL_WORK,
};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanExecutionError {
    UnsupportedHost {
        architecture: &'static str,
    },
    InvalidBudget {
        limit: u64,
        requested: u64,
    },
    InvalidEntryArguments {
        expected_count: usize,
        actual_count: usize,
        expected_prefix: Vec<MachineType>,
        actual_prefix: Vec<&'static str>,
    },
    StepBudgetExceeded {
        limit: u64,
    },
    InternalInvariant(String),
}

impl fmt::Display for PlanExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost { architecture } => write!(
                formatter,
                "x86-64 target-plan evaluation requires an x86-64 host, found {architecture}"
            ),
            Self::InvalidBudget { limit, requested } => write!(
                formatter,
                "x86-64 target-plan evaluation work budget {requested} exceeds hard limit {limit}"
            ),
            Self::InvalidEntryArguments {
                expected_count,
                actual_count,
                expected_prefix,
                actual_prefix,
            } => write!(
                formatter,
                "x86-64 target-plan entry argument mismatch: expected {expected_count} value(s) \
                 beginning {expected_prefix:?}; found {actual_count} beginning {actual_prefix:?}"
            ),
            Self::StepBudgetExceeded { limit } => write!(
                formatter,
                "x86-64 target-plan evaluation exceeded {limit} execution work units"
            ),
            Self::InternalInvariant(message) => {
                write!(
                    formatter,
                    "verified x86-64 target-plan invariant failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for PlanExecutionError {}

/// Evaluate an already-verified canonical target plan.
///
/// `max_call_depth` is intentionally irrelevant: the closed R1-S7a operation
/// set has no returning call and every tail transfer reuses one logical frame.
pub(super) fn evaluate_program(
    program: &X64TargetProgram,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, PlanExecutionError> {
    PlanEvaluator::new(program, budget)?.evaluate(arguments)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct HomeKey {
    slot: X64HomeSlot,
    offset: u32,
}

impl From<X64Home> for HomeKey {
    fn from(home: X64Home) -> Self {
        Self {
            slot: home.slot,
            offset: home.offset,
        }
    }
}

#[derive(Clone, Debug)]
struct StoredHome {
    descriptor: X64Home,
    value: CoreValue,
}

struct LogicalFrame {
    function: X64FunctionId,
    block: X64BlockId,
    next_instruction: usize,
    homes: BTreeMap<HomeKey, StoredHome>,
}

enum PlanComputation {
    Value(CoreValue),
    Bounds,
}

struct PlanEvaluator<'program> {
    program: &'program X64TargetProgram,
    budget: EvaluationBudget,
    steps: u64,
    effect_trace: Vec<EffectEvent>,
}

impl<'program> PlanEvaluator<'program> {
    fn new(
        program: &'program X64TargetProgram,
        budget: EvaluationBudget,
    ) -> Result<Self, PlanExecutionError> {
        if budget.max_steps > X64_TARGET_MAX_PLAN_EVAL_WORK {
            return Err(PlanExecutionError::InvalidBudget {
                limit: X64_TARGET_MAX_PLAN_EVAL_WORK,
                requested: budget.max_steps,
            });
        }
        Ok(Self {
            program,
            budget,
            steps: 0,
            effect_trace: Vec::new(),
        })
    }

    fn evaluate(mut self, arguments: Vec<CoreValue>) -> Result<Evaluation, PlanExecutionError> {
        let _strict_f64 = StrictF64Guard::enter()?;
        let entry = self.find_function(self.program.entry).ok_or_else(|| {
            Self::invariant(format!(
                "entry function {} disappeared",
                self.program.entry.0
            ))
        })?;
        self.validate_entry_arguments(entry, &arguments)?;
        let entry_id = entry.id;
        let entry_block = entry.entry_block;
        self.charge(frame_transfer_work(arguments.len())?)?;

        let mut frame = self.new_frame(entry_id, entry_block, arguments)?;
        let outcome = loop {
            let instruction = {
                let block = self.current_block(&frame)?;
                block.instructions.get(frame.next_instruction).cloned()
            };

            if let Some(instruction) = instruction {
                self.charge(1)?;
                frame.next_instruction = frame
                    .next_instruction
                    .checked_add(1)
                    .ok_or_else(|| Self::invariant("instruction cursor overflow"))?;
                let computation = self.evaluate_instruction(&instruction.kind, &frame.homes)?;
                match computation {
                    PlanComputation::Value(value) => {
                        assign_home(&mut frame.homes, instruction.result, value)?;
                    }
                    PlanComputation::Bounds => {
                        self.effect_trace
                            .push(EffectEvent::Error(ErrorKind::Bounds));
                        break EvaluationOutcome::Error(ErrorKind::Bounds);
                    }
                }
                continue;
            }

            let terminator = self.current_block(&frame)?.terminator.clone();
            match terminator {
                X64Terminator::Return { value, .. } => {
                    self.charge(1)?;
                    let value = evaluate_operand(&value, &frame.homes)?;
                    let function = self.find_function(frame.function).ok_or_else(|| {
                        Self::invariant(format!(
                            "current function {} disappeared",
                            frame.function.0
                        ))
                    })?;
                    if !value_matches_type(&value, function.result) {
                        return Err(Self::invariant(format!(
                            "function {} returned a value outside its declared {:?} representation",
                            function.id.0, function.result
                        )));
                    }
                    break EvaluationOutcome::Return(canonicalize_observable(value));
                }
                X64Terminator::BranchRel32 {
                    condition,
                    then_label,
                    else_label,
                    ..
                } => {
                    self.charge(1)?;
                    let CoreValue::Bool(condition) = evaluate_operand(&condition, &frame.homes)?
                    else {
                        return Err(Self::invariant(
                            "target branch condition is not canonical Bool",
                        ));
                    };
                    let label = if condition { then_label } else { else_label };
                    let (function, block) = self.resolve_block_label(label)?;
                    if function != frame.function {
                        return Err(Self::invariant(format!(
                            "branch label {} escapes function {} to function {}",
                            label.0, frame.function.0, function.0
                        )));
                    }
                    frame.block = block;
                    frame.next_instruction = 0;
                }
                X64Terminator::TailJumpRel32 {
                    function,
                    target_label,
                    arguments,
                    ..
                } => {
                    self.charge(frame_transfer_work(arguments.len())?)?;

                    // Stage every source value before committing any callee
                    // parameter home. This is the logical form of the
                    // non-aliasing outgoing tail area.
                    let staged = arguments
                        .iter()
                        .map(|operand| evaluate_operand(operand, &frame.homes))
                        .collect::<Result<Vec<_>, _>>()?;

                    let target = self.find_function(function).ok_or_else(|| {
                        Self::invariant(format!("tail target function {} disappeared", function.0))
                    })?;
                    if !arguments_match_parameters(&staged, target) {
                        return Err(Self::invariant(format!(
                            "tail transfer to function {} has invalid staged arguments",
                            function.0
                        )));
                    }
                    let (label_function, label_block) = self.resolve_block_label(target_label)?;
                    if label_function != function || label_block != target.entry_block {
                        return Err(Self::invariant(format!(
                            "tail label {} does not name function {} entry block {}",
                            target_label.0, function.0, target.entry_block.0
                        )));
                    }

                    // Commit into a fresh map, then replace the current
                    // logical frame in one step. No host stack or
                    // continuation is retained.
                    let homes = parameter_homes(target, staged)?;
                    frame = LogicalFrame {
                        function,
                        block: label_block,
                        next_instruction: 0,
                        homes,
                    };
                }
            }
        };

        Ok(Evaluation {
            outcome,
            steps: self.steps,
            effect_trace: self.effect_trace,
        })
    }

    fn evaluate_instruction(
        &self,
        instruction: &X64InstructionKind,
        homes: &BTreeMap<HomeKey, StoredHome>,
    ) -> Result<PlanComputation, PlanExecutionError> {
        match instruction {
            X64InstructionKind::Move(operand) => {
                Ok(PlanComputation::Value(evaluate_operand(operand, homes)?))
            }
            X64InstructionKind::I64Wrapping {
                opcode,
                left,
                right,
            } => {
                let left = expect_i64(evaluate_operand(left, homes)?)?;
                let right = expect_i64(evaluate_operand(right, homes)?)?;
                let value = match opcode {
                    X64I64Opcode::Add => left.wrapping_add(right),
                    X64I64Opcode::Sub => left.wrapping_sub(right),
                    X64I64Opcode::Mul => left.wrapping_mul(right),
                };
                Ok(PlanComputation::Value(CoreValue::I64(value)))
            }
            X64InstructionKind::Sse2F64 {
                opcode,
                left,
                right,
            } => {
                let left = expect_f64(evaluate_operand(left, homes)?)?;
                let right = expect_f64(evaluate_operand(right, homes)?)?;
                let value = match opcode {
                    X64Sse2F64Opcode::AddSd => left + right,
                    X64Sse2F64Opcode::SubSd => left - right,
                };
                Ok(PlanComputation::Value(CoreValue::F64(value)))
            }
            X64InstructionKind::I64Setcc {
                condition,
                left,
                right,
            } => {
                let left = expect_i64(evaluate_operand(left, homes)?)?;
                let right = expect_i64(evaluate_operand(right, homes)?)?;
                let value = match condition {
                    X64SetCondition::SignedLessThan => left < right,
                    X64SetCondition::SignedGreaterOrEqual => left >= right,
                };
                Ok(PlanComputation::Value(CoreValue::Bool(value)))
            }
            X64InstructionKind::ArrayLenF64 { array } => {
                let CoreValue::ArrayF64(values) = evaluate_operand(array, homes)? else {
                    return Err(Self::invariant("ArrayLenF64 operand is not F64Array"));
                };
                let length = i64::try_from(values.len()).map_err(|_| {
                    Self::invariant("logical F64Array length does not fit canonical I64")
                })?;
                Ok(PlanComputation::Value(CoreValue::I64(length)))
            }
            X64InstructionKind::ArrayGetF64Checked { array, index } => {
                let CoreValue::ArrayF64(values) = evaluate_operand(array, homes)? else {
                    return Err(Self::invariant(
                        "ArrayGetF64Checked array operand is not F64Array",
                    ));
                };
                let index = expect_i64(evaluate_operand(index, homes)?)?;
                if index < 0 {
                    return Ok(PlanComputation::Bounds);
                }
                let index = usize::try_from(index).map_err(|_| {
                    Self::invariant("non-negative I64 index does not fit host usize")
                })?;
                match values.get(index) {
                    Some(value) => Ok(PlanComputation::Value(CoreValue::F64(*value))),
                    None => Ok(PlanComputation::Bounds),
                }
            }
        }
    }

    fn new_frame(
        &self,
        function: X64FunctionId,
        block: X64BlockId,
        arguments: Vec<CoreValue>,
    ) -> Result<LogicalFrame, PlanExecutionError> {
        let function_plan = self
            .find_function(function)
            .ok_or_else(|| Self::invariant(format!("missing target function {}", function.0)))?;
        let homes = parameter_homes(function_plan, arguments)?;
        Ok(LogicalFrame {
            function,
            block,
            next_instruction: 0,
            homes,
        })
    }

    fn validate_entry_arguments(
        &self,
        entry: &X64Function,
        arguments: &[CoreValue],
    ) -> Result<(), PlanExecutionError> {
        if arguments_match_parameters(arguments, entry) {
            return Ok(());
        }
        Err(PlanExecutionError::InvalidEntryArguments {
            expected_count: entry.parameters.len(),
            actual_count: arguments.len(),
            expected_prefix: entry
                .parameters
                .iter()
                .take(8)
                .map(|parameter| parameter.home.ty)
                .collect(),
            actual_prefix: arguments.iter().take(8).map(value_kind).collect(),
        })
    }

    fn current_block(&self, frame: &LogicalFrame) -> Result<&X64Block, PlanExecutionError> {
        let function = self.find_function(frame.function).ok_or_else(|| {
            Self::invariant(format!("current function {} disappeared", frame.function.0))
        })?;
        find_block(function, frame.block).ok_or_else(|| {
            Self::invariant(format!(
                "function {} block {} disappeared",
                frame.function.0, frame.block.0
            ))
        })
    }

    fn find_function(&self, id: X64FunctionId) -> Option<&X64Function> {
        self.program
            .functions
            .binary_search_by_key(&id, |function| function.id)
            .ok()
            .map(|index| &self.program.functions[index])
    }

    fn resolve_block_label(
        &self,
        id: X64LabelId,
    ) -> Result<(X64FunctionId, X64BlockId), PlanExecutionError> {
        let label = self
            .program
            .labels
            .binary_search_by_key(&id, |label| label.id)
            .ok()
            .map(|index| self.program.labels[index])
            .ok_or_else(|| Self::invariant(format!("missing target label {}", id.0)))?;
        let X64LabelOwner::Block { function, block } = label.owner else {
            return Err(Self::invariant(format!(
                "control transfer label {} does not own a target block",
                id.0
            )));
        };
        let target = self.find_function(function).ok_or_else(|| {
            Self::invariant(format!(
                "label {} names missing function {}",
                id.0, function.0
            ))
        })?;
        if find_block(target, block).is_none() {
            return Err(Self::invariant(format!(
                "label {} names missing function {} block {}",
                id.0, function.0, block.0
            )));
        }
        Ok((function, block))
    }

    fn charge(&mut self, work: u64) -> Result<(), PlanExecutionError> {
        let next = self
            .steps
            .checked_add(work)
            .ok_or(PlanExecutionError::StepBudgetExceeded {
                limit: self.budget.max_steps,
            })?;
        if next > self.budget.max_steps {
            return Err(PlanExecutionError::StepBudgetExceeded {
                limit: self.budget.max_steps,
            });
        }
        self.steps = next;
        Ok(())
    }

    fn invariant(message: impl Into<String>) -> PlanExecutionError {
        PlanExecutionError::InternalInvariant(message.into())
    }
}

#[cfg(target_arch = "x86_64")]
struct StrictF64Guard {
    saved_mxcsr: u32,
}

#[cfg(target_arch = "x86_64")]
impl StrictF64Guard {
    fn enter() -> Result<Self, PlanExecutionError> {
        let mut saved_mxcsr = 0_u32;
        let canonical_mxcsr = 0x0000_1f80_u32;
        // SAFETY: both operands point to initialized, suitably aligned u32
        // storage for the duration of each instruction. STMXCSR/ LDMXCSR are
        // baseline x86-64 SSE instructions, touch no stack memory through the
        // assembly template, and preserve integer flags.
        unsafe {
            core::arch::asm!(
                "stmxcsr [{address}]",
                address = in(reg) &mut saved_mxcsr,
                options(nostack, preserves_flags)
            );
            core::arch::asm!(
                "ldmxcsr [{address}]",
                address = in(reg) &canonical_mxcsr,
                options(nostack, preserves_flags, readonly)
            );
        }
        Ok(Self { saved_mxcsr })
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for StrictF64Guard {
    fn drop(&mut self) {
        // SAFETY: `saved_mxcsr` was produced by STMXCSR on this thread and
        // remains initialized until the guard is dropped.
        unsafe {
            core::arch::asm!(
                "ldmxcsr [{address}]",
                address = in(reg) &self.saved_mxcsr,
                options(nostack, preserves_flags, readonly)
            );
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
struct StrictF64Guard;

#[cfg(not(target_arch = "x86_64"))]
impl StrictF64Guard {
    fn enter() -> Result<Self, PlanExecutionError> {
        Err(PlanExecutionError::UnsupportedHost {
            architecture: std::env::consts::ARCH,
        })
    }
}

fn frame_transfer_work(argument_count: usize) -> Result<u64, PlanExecutionError> {
    let argument_count = u64::try_from(argument_count)
        .map_err(|_| PlanEvaluator::invariant("argument count does not fit u64"))?;
    argument_count
        .checked_mul(2)
        .and_then(|work| work.checked_add(1))
        .ok_or_else(|| PlanEvaluator::invariant("frame-transfer work overflow"))
}

fn find_block(function: &X64Function, id: X64BlockId) -> Option<&X64Block> {
    function
        .blocks
        .binary_search_by_key(&id, |block| block.id)
        .ok()
        .map(|index| &function.blocks[index])
}

fn parameter_homes(
    function: &X64Function,
    arguments: Vec<CoreValue>,
) -> Result<BTreeMap<HomeKey, StoredHome>, PlanExecutionError> {
    if !arguments_match_parameters(&arguments, function) {
        return Err(PlanEvaluator::invariant(format!(
            "function {} parameter commit has invalid arguments",
            function.id.0
        )));
    }
    let mut homes = BTreeMap::new();
    for (parameter, argument) in function.parameters.iter().zip(arguments) {
        assign_home(&mut homes, parameter.home, argument)?;
    }
    Ok(homes)
}

fn assign_home(
    homes: &mut BTreeMap<HomeKey, StoredHome>,
    home: X64Home,
    value: CoreValue,
) -> Result<(), PlanExecutionError> {
    if !value_matches_type(&value, home.ty) {
        return Err(PlanEvaluator::invariant(format!(
            "home slot {} offset {} cannot store {:?} as {:?}",
            home.slot.0,
            home.offset,
            value_kind(&value),
            home.ty
        )));
    }
    let expected_width = type_width(home.ty);
    if home.width != expected_width {
        return Err(PlanEvaluator::invariant(format!(
            "home slot {} offset {} has width {}; expected {} for {:?}",
            home.slot.0, home.offset, home.width, expected_width, home.ty
        )));
    }
    let key = HomeKey::from(home);
    if let Some(existing) = homes.get(&key) {
        if existing.descriptor != home {
            return Err(PlanEvaluator::invariant(format!(
                "home slot {} offset {} changed descriptor",
                home.slot.0, home.offset
            )));
        }
    }
    homes.insert(
        key,
        StoredHome {
            descriptor: home,
            value,
        },
    );
    Ok(())
}

fn evaluate_operand(
    operand: &X64Operand,
    homes: &BTreeMap<HomeKey, StoredHome>,
) -> Result<CoreValue, PlanExecutionError> {
    match operand {
        X64Operand::Immediate { ty, value } => {
            let value = match value {
                X64Immediate::Unit => CoreValue::Unit,
                X64Immediate::Bool(value) => CoreValue::Bool(*value),
                X64Immediate::I64(value) => CoreValue::I64(*value),
                X64Immediate::F64Bits(bits) => CoreValue::F64(f64::from_bits(*bits)),
            };
            if !value_matches_type(&value, *ty) {
                return Err(PlanEvaluator::invariant(format!(
                    "target immediate {:?} does not match declared type {ty:?}",
                    value_kind(&value)
                )));
            }
            Ok(value)
        }
        X64Operand::Home(home) => {
            let stored = homes.get(&HomeKey::from(*home)).ok_or_else(|| {
                PlanEvaluator::invariant(format!(
                    "home slot {} offset {} is unavailable",
                    home.slot.0, home.offset
                ))
            })?;
            if stored.descriptor != *home {
                return Err(PlanEvaluator::invariant(format!(
                    "home slot {} offset {} descriptor mismatch",
                    home.slot.0, home.offset
                )));
            }
            Ok(stored.value.clone())
        }
    }
}

fn expect_i64(value: CoreValue) -> Result<i64, PlanExecutionError> {
    let CoreValue::I64(value) = value else {
        return Err(PlanEvaluator::invariant("expected canonical I64 value"));
    };
    Ok(value)
}

fn expect_f64(value: CoreValue) -> Result<f64, PlanExecutionError> {
    let CoreValue::F64(value) = value else {
        return Err(PlanEvaluator::invariant("expected canonical F64 value"));
    };
    Ok(value)
}

fn arguments_match_parameters(arguments: &[CoreValue], function: &X64Function) -> bool {
    arguments.len() == function.parameters.len()
        && arguments
            .iter()
            .zip(&function.parameters)
            .all(|(value, parameter)| value_matches_type(value, parameter.home.ty))
}

fn value_matches_type(value: &CoreValue, ty: MachineType) -> bool {
    matches!(
        (value, ty),
        (CoreValue::Unit, MachineType::Unit)
            | (CoreValue::Bool(_), MachineType::Bool)
            | (CoreValue::I64(_), MachineType::I64)
            | (CoreValue::F64(_), MachineType::F64)
            | (CoreValue::ArrayF64(_), MachineType::F64Array)
    )
}

fn value_kind(value: &CoreValue) -> &'static str {
    match value {
        CoreValue::Unit => "Unit",
        CoreValue::Bool(_) => "Bool",
        CoreValue::I64(_) => "I64",
        CoreValue::F64(_) => "F64",
        CoreValue::Tuple(_) => "Tuple",
        CoreValue::Sum { .. } => "Sum",
        CoreValue::ArrayF64(_) => "ArrayF64",
        CoreValue::Reference(_) => "Reference",
        CoreValue::Closure(_) => "Closure",
    }
}

fn type_width(ty: MachineType) -> u8 {
    match ty {
        MachineType::F64Array => 16,
        MachineType::Unit | MachineType::Bool | MachineType::I64 | MachineType::F64 => 8,
    }
}

fn canonicalize_observable(value: CoreValue) -> CoreValue {
    match value {
        CoreValue::F64(value) => CoreValue::F64(f64::from_bits(canonical_f64_bits(value))),
        value => value,
    }
}
