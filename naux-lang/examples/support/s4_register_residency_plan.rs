//! Contract-scoped one-hot register-residency plan for S4-WP8C.
//!
//! This boundary does not encode machine code. It rewrites only accesses to
//! one exact `i64` slot into a fixed `r12` home and proves that erasing the new
//! home reconstructs the complete source Machine IR instruction stream.

use crate::baseline::X64Plan;
use crate::machine::{
    IntegerBinary, IntegerCompare, MachineInstruction, MachineTerminator, MachineType,
    ResidualMachineProgram, TypedRegister,
};
use std::fmt;

pub const DEFAULT_REPLAY_STEP_LIMIT: u64 = 30_000_000;
const RESIDENCY_PLAN_DOMAIN: &[u8] = b"NAUX:s4-register-residency-plan:v1\0";
const REPLAY_EVIDENCE_DOMAIN: &[u8] = b"NAUX:s4-register-residency-replay-evidence:v1\0";
const PLAN_REPORT_DOMAIN: &[u8] = b"NAUX:s4-register-residency-plan-report:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalRegister {
    R12,
}

impl PhysicalRegister {
    pub fn canonical_text(self) -> &'static str {
        match self {
            Self::R12 => "r12",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub slot: u32,
    pub expected_static_reads: u32,
    pub expected_static_writes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidencyInstruction {
    PassThrough(MachineInstruction),
    LoadPhysical {
        result: TypedRegister,
        register: PhysicalRegister,
    },
    StorePhysical {
        register: PhysicalRegister,
        value: TypedRegister,
        keep: bool,
    },
    AddPhysicalConst {
        register: PhysicalRegister,
        value: i64,
    },
}

impl ResidencyInstruction {
    pub fn canonical_text(&self) -> String {
        match self {
            Self::PassThrough(instruction) => instruction.canonical_text(),
            Self::LoadPhysical { result, register } => format!(
                "load-physical\tr{}:{}\t{}",
                result.id,
                result.ty.canonical_text(),
                register.canonical_text()
            ),
            Self::StorePhysical {
                register,
                value,
                keep,
            } => format!(
                "store-physical\t{}\tr{}:{}\t{}",
                register.canonical_text(),
                value.id,
                value.ty.canonical_text(),
                if *keep { "keep" } else { "consume" }
            ),
            Self::AddPhysicalConst { register, value } => {
                format!("add-physical-const\t{}\t{value}", register.canonical_text())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidencyBlock {
    pub id: u32,
    pub instructions: Vec<ResidencyInstruction>,
    pub terminator: MachineTerminator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidencyPlan {
    pub source_machine_hash: naux::core::SemanticHash,
    pub frame_bytes: u32,
    pub promoted_slot: u32,
    pub promoted_type: MachineType,
    pub physical_register: PhysicalRegister,
    pub save_on_entry: bool,
    pub restore_on_return: bool,
    pub error_path_nonreturning: bool,
    pub static_reads: u32,
    pub static_writes: u32,
    pub blocks: Vec<ResidencyBlock>,
}

impl ResidencyPlan {
    pub fn semantic_hash(&self) -> Result<naux::core::SemanticHash, ResidencyError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.source_machine_hash.0);
        put_u32(&mut bytes, self.frame_bytes);
        put_u32(&mut bytes, self.promoted_slot);
        put_string(&mut bytes, self.promoted_type.canonical_text())?;
        put_string(&mut bytes, self.physical_register.canonical_text())?;
        bytes.extend_from_slice(&[
            u8::from(self.save_on_entry),
            u8::from(self.restore_on_return),
            u8::from(self.error_path_nonreturning),
        ]);
        put_u32(&mut bytes, self.static_reads);
        put_u32(&mut bytes, self.static_writes);
        put_len(&mut bytes, self.blocks.len())?;
        for block in &self.blocks {
            put_u32(&mut bytes, block.id);
            put_len(&mut bytes, block.instructions.len())?;
            for instruction in &block.instructions {
                put_string(&mut bytes, &instruction.canonical_text())?;
            }
            put_string(&mut bytes, &block.terminator.canonical_text())?;
        }
        let mut preimage = Vec::with_capacity(RESIDENCY_PLAN_DOMAIN.len() + bytes.len());
        preimage.extend_from_slice(RESIDENCY_PLAN_DOMAIN);
        preimage.extend_from_slice(&bytes);
        Ok(naux::core::SemanticHash(sha256(&preimage)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplaySummary {
    pub result: i64,
    pub steps: u64,
    pub overflow_events: u64,
    pub allocations: u64,
    pub releases: u64,
    pub live_owned_lists: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayEvidence {
    pub baseline: ReplaySummary,
    pub candidate: ReplaySummary,
    pub abi_restored: bool,
}

impl ReplayEvidence {
    pub fn semantic_hash(&self, plan_hash: naux::core::SemanticHash) -> naux::core::SemanticHash {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&plan_hash.0);
        put_replay_summary(&mut bytes, self.baseline);
        put_replay_summary(&mut bytes, self.candidate);
        bytes.push(u8::from(self.abi_restored));
        let mut preimage = Vec::with_capacity(REPLAY_EVIDENCE_DOMAIN.len() + bytes.len());
        preimage.extend_from_slice(REPLAY_EVIDENCE_DOMAIN);
        preimage.extend_from_slice(&bytes);
        naux::core::SemanticHash(sha256(&preimage))
    }
}

pub fn plan_report_hash(payload: &[u8]) -> naux::core::SemanticHash {
    let mut preimage = Vec::with_capacity(PLAN_REPORT_DOMAIN.len() + payload.len());
    preimage.extend_from_slice(PLAN_REPORT_DOMAIN);
    preimage.extend_from_slice(payload);
    naux::core::SemanticHash(sha256(&preimage))
}

pub fn verify_frozen_plan_report(
    raw: &[u8],
    expected_report_root: &str,
    expected_document_sha256: &str,
) -> Result<(), ResidencyError> {
    const MAGIC: &str = "NAUX-S4-REGISTER-RESIDENCY-PLAN\t1";
    const MAX_REPORT_BYTES: usize = 1_000_000;
    if raw.is_empty()
        || raw.len() > MAX_REPORT_BYTES
        || !raw.ends_with(b"\n")
        || raw.contains(&b'\r')
        || raw.contains(&0)
    {
        return Err(ResidencyError::InvalidPlan(
            "frozen candidate report has invalid extent or encoding".into(),
        ));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| ResidencyError::InvalidPlan("frozen candidate report is not UTF-8".into()))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() < 2
        || lines[0] != MAGIC
        || lines
            .iter()
            .any(|line| line.is_empty() || *line != line.trim())
    {
        return Err(ResidencyError::InvalidPlan(
            "frozen candidate report canonical shape drifted".into(),
        ));
    }
    let root_row = lines
        .last()
        .ok_or_else(|| ResidencyError::InvalidPlan("frozen candidate report is empty".into()))?;
    let declared = root_row.strip_prefix("report-root\t").ok_or_else(|| {
        ResidencyError::InvalidPlan("frozen candidate report lacks its root".into())
    })?;
    let declared = decode_hash(declared)?;
    let expected_root = decode_hash(expected_report_root)?;
    let expected_document = decode_hash(expected_document_sha256)?;
    let body_len = raw
        .len()
        .checked_sub(root_row.len() + 1)
        .ok_or_else(|| ResidencyError::InvalidPlan("frozen report extent underflowed".into()))?;
    if declared != expected_root || plan_report_hash(&raw[..body_len]) != declared {
        return Err(ResidencyError::InvalidPlan(
            "frozen candidate report root drifted".into(),
        ));
    }
    if naux::core::SemanticHash(sha256(raw)) != expected_document {
        return Err(ResidencyError::InvalidPlan(
            "frozen candidate report document identity drifted".into(),
        ));
    }
    Ok(())
}

pub fn sealed_document_root(
    raw: &[u8],
    magic: &str,
    domain: &[u8],
) -> Result<naux::core::SemanticHash, ResidencyError> {
    const MAX_DOCUMENT_BYTES: usize = 1_000_000;
    if raw.is_empty()
        || raw.len() > MAX_DOCUMENT_BYTES
        || !raw.ends_with(b"\n")
        || raw.contains(&b'\r')
        || raw.contains(&0)
    {
        return Err(ResidencyError::InvalidPlan(
            "sealed parent has invalid extent or encoding".into(),
        ));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| ResidencyError::InvalidPlan("sealed parent is not UTF-8".into()))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() < 2
        || lines[0] != magic
        || lines
            .iter()
            .any(|line| line.is_empty() || *line != line.trim())
    {
        return Err(ResidencyError::InvalidPlan(
            "sealed parent canonical shape drifted".into(),
        ));
    }
    let declared = lines
        .last()
        .and_then(|line| line.strip_prefix("seal\t"))
        .ok_or_else(|| ResidencyError::InvalidPlan("sealed parent lacks its seal row".into()))?;
    let declared = decode_hash(declared)?;
    let body_len = raw
        .len()
        .checked_sub(lines.last().expect("lines are non-empty").len() + 1)
        .ok_or_else(|| ResidencyError::InvalidPlan("sealed parent extent underflowed".into()))?;
    let mut preimage = Vec::with_capacity(domain.len() + body_len);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&raw[..body_len]);
    let computed = naux::core::SemanticHash(sha256(&preimage));
    if computed != declared {
        return Err(ResidencyError::InvalidPlan(
            "sealed parent body does not match its declared root".into(),
        ));
    }
    Ok(declared)
}

fn decode_hash(value: &str) -> Result<naux::core::SemanticHash, ResidencyError> {
    if value.len() != 64 {
        return Err(ResidencyError::InvalidPlan(
            "sealed parent root is not canonical SHA-256 hex".into(),
        ));
    }
    let mut output = [0_u8; 32];
    for (index, target) in output.iter_mut().enumerate() {
        let offset = index * 2;
        let high = decode_nibble(value.as_bytes()[offset])?;
        let low = decode_nibble(value.as_bytes()[offset + 1])?;
        *target = (high << 4) | low;
    }
    Ok(naux::core::SemanticHash(output))
}

fn decode_nibble(value: u8) -> Result<u8, ResidencyError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ResidencyError::InvalidPlan(
            "sealed parent root is not lowercase hexadecimal".into(),
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidencyError {
    InvalidSelection(String),
    InvalidPlan(String),
    Replay(String),
}

impl fmt::Display for ResidencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, message) = match self {
            Self::InvalidSelection(message) => ("selection", message),
            Self::InvalidPlan(message) => ("plan", message),
            Self::Replay(message) => ("replay", message),
        };
        write!(
            formatter,
            "S4-WP8C register-residency {kind} error: {message}"
        )
    }
}

impl std::error::Error for ResidencyError {}

pub fn lower_register_residency(
    machine: &ResidualMachineProgram,
    baseline: &X64Plan,
    selection: Selection,
) -> Result<ResidencyPlan, ResidencyError> {
    if baseline.source_machine_hash != machine.semantic_hash() {
        return Err(ResidencyError::InvalidSelection(
            "baseline target plan does not bind the source Machine IR".into(),
        ));
    }
    if machine.slot_types.get(selection.slot as usize) != Some(&MachineType::I64) {
        return Err(ResidencyError::InvalidSelection(format!(
            "selected slot s{} is not an admitted i64 home",
            selection.slot
        )));
    }
    let mut reads = 0_u32;
    let mut writes = 0_u32;
    let mut blocks = Vec::with_capacity(machine.blocks.len());
    for source_block in &machine.blocks {
        let mut instructions = Vec::with_capacity(source_block.instructions.len());
        for source in &source_block.instructions {
            let rewritten = match source {
                MachineInstruction::LoadSlot { result, slot } if *slot == selection.slot => {
                    reads = reads.checked_add(1).ok_or_else(|| {
                        ResidencyError::InvalidSelection("static read count overflowed".into())
                    })?;
                    ResidencyInstruction::LoadPhysical {
                        result: *result,
                        register: PhysicalRegister::R12,
                    }
                }
                MachineInstruction::StoreSlot { slot, value, keep } if *slot == selection.slot => {
                    writes = writes.checked_add(1).ok_or_else(|| {
                        ResidencyError::InvalidSelection("static write count overflowed".into())
                    })?;
                    ResidencyInstruction::StorePhysical {
                        register: PhysicalRegister::R12,
                        value: *value,
                        keep: *keep,
                    }
                }
                MachineInstruction::AddSlotConst { slot, value } if *slot == selection.slot => {
                    reads = reads.checked_add(1).ok_or_else(|| {
                        ResidencyError::InvalidSelection("static read count overflowed".into())
                    })?;
                    writes = writes.checked_add(1).ok_or_else(|| {
                        ResidencyError::InvalidSelection("static write count overflowed".into())
                    })?;
                    ResidencyInstruction::AddPhysicalConst {
                        register: PhysicalRegister::R12,
                        value: *value,
                    }
                }
                _ => ResidencyInstruction::PassThrough(source.clone()),
            };
            instructions.push(rewritten);
        }
        blocks.push(ResidencyBlock {
            id: source_block.id,
            instructions,
            terminator: source_block.terminator.clone(),
        });
    }
    if reads != selection.expected_static_reads || writes != selection.expected_static_writes {
        return Err(ResidencyError::InvalidSelection(format!(
            "selected site extent is {reads} reads/{writes} writes, expected {}/{}",
            selection.expected_static_reads, selection.expected_static_writes
        )));
    }
    let plan = ResidencyPlan {
        source_machine_hash: machine.semantic_hash(),
        frame_bytes: baseline.frame_bytes,
        promoted_slot: selection.slot,
        promoted_type: MachineType::I64,
        physical_register: PhysicalRegister::R12,
        save_on_entry: true,
        restore_on_return: true,
        error_path_nonreturning: true,
        static_reads: reads,
        static_writes: writes,
        blocks,
    };
    verify_register_residency(&plan, machine, baseline)?;
    Ok(plan)
}

pub fn verify_register_residency(
    plan: &ResidencyPlan,
    machine: &ResidualMachineProgram,
    baseline: &X64Plan,
) -> Result<(), ResidencyError> {
    if plan.source_machine_hash != machine.semantic_hash()
        || baseline.source_machine_hash != machine.semantic_hash()
        || plan.frame_bytes != baseline.frame_bytes
        || plan.promoted_type != MachineType::I64
        || plan.physical_register != PhysicalRegister::R12
        || !plan.save_on_entry
        || !plan.restore_on_return
        || !plan.error_path_nonreturning
    {
        return Err(ResidencyError::InvalidPlan(
            "source, frame, type, physical register, or ABI obligation drifted".into(),
        ));
    }
    if machine.slot_types.get(plan.promoted_slot as usize) != Some(&MachineType::I64)
        || plan.blocks.len() != machine.blocks.len()
    {
        return Err(ResidencyError::InvalidPlan(
            "promoted slot or block extent drifted".into(),
        ));
    }
    let mut reads = 0_u32;
    let mut writes = 0_u32;
    for (expected, (planned, source)) in plan.blocks.iter().zip(&machine.blocks).enumerate() {
        if planned.id != expected as u32
            || planned.id != source.id
            || planned.terminator != source.terminator
            || planned.instructions.len() != source.instructions.len()
        {
            return Err(ResidencyError::InvalidPlan(
                "block, terminator, or instruction extent drifted".into(),
            ));
        }
        for (rewritten, original) in planned.instructions.iter().zip(&source.instructions) {
            match (rewritten, original) {
                (
                    ResidencyInstruction::LoadPhysical { result, register },
                    MachineInstruction::LoadSlot {
                        result: source_result,
                        slot,
                    },
                ) if result == source_result
                    && *slot == plan.promoted_slot
                    && *register == PhysicalRegister::R12 =>
                {
                    reads = reads.checked_add(1).ok_or_else(|| {
                        ResidencyError::InvalidPlan("verified read count overflowed".into())
                    })?;
                }
                (
                    ResidencyInstruction::StorePhysical {
                        register,
                        value,
                        keep,
                    },
                    MachineInstruction::StoreSlot {
                        slot,
                        value: source_value,
                        keep: source_keep,
                    },
                ) if value == source_value
                    && keep == source_keep
                    && *slot == plan.promoted_slot
                    && *register == PhysicalRegister::R12 =>
                {
                    writes = writes.checked_add(1).ok_or_else(|| {
                        ResidencyError::InvalidPlan("verified write count overflowed".into())
                    })?;
                }
                (
                    ResidencyInstruction::AddPhysicalConst { register, value },
                    MachineInstruction::AddSlotConst {
                        slot,
                        value: source_value,
                    },
                ) if value == source_value
                    && *slot == plan.promoted_slot
                    && *register == PhysicalRegister::R12 =>
                {
                    reads = reads.checked_add(1).ok_or_else(|| {
                        ResidencyError::InvalidPlan("verified read count overflowed".into())
                    })?;
                    writes = writes.checked_add(1).ok_or_else(|| {
                        ResidencyError::InvalidPlan("verified write count overflowed".into())
                    })?;
                }
                (ResidencyInstruction::PassThrough(candidate), source_instruction)
                    if candidate == source_instruction
                        && !references_slot(source_instruction, plan.promoted_slot) => {}
                _ => {
                    return Err(ResidencyError::InvalidPlan(
                        "residency erasure does not reconstruct source Machine IR".into(),
                    ));
                }
            }
        }
    }
    if reads != plan.static_reads || writes != plan.static_writes || reads == 0 || writes == 0 {
        return Err(ResidencyError::InvalidPlan(
            "verified transformed access extent drifted".into(),
        ));
    }
    verify_definite_initialization(plan, machine.entry_block)?;
    Ok(())
}

fn verify_definite_initialization(
    plan: &ResidencyPlan,
    entry_block: u32,
) -> Result<(), ResidencyError> {
    let entry = usize::try_from(entry_block)
        .map_err(|_| ResidencyError::InvalidPlan("entry block exceeds host index space".into()))?;
    if entry >= plan.blocks.len() {
        return Err(ResidencyError::InvalidPlan(
            "entry block is outside the residency graph".into(),
        ));
    }

    // `incoming[b]` is a must fact: true only when every currently known path
    // into b has initialized the promoted physical home.  Facts can move only
    // from unknown -> true/false or true -> false, so the worklist terminates.
    let mut incoming = vec![None; plan.blocks.len()];
    incoming[entry] = Some(false);
    let mut worklist = std::collections::VecDeque::from([entry_block]);
    while let Some(block_id) = worklist.pop_front() {
        let block_index = usize::try_from(block_id).map_err(|_| {
            ResidencyError::InvalidPlan("reachable block exceeds host index space".into())
        })?;
        let block = plan.blocks.get(block_index).ok_or_else(|| {
            ResidencyError::InvalidPlan(format!(
                "residency control flow targets missing block b{block_id}"
            ))
        })?;
        if block.id != block_id {
            return Err(ResidencyError::InvalidPlan(
                "residency blocks are not canonical contiguous ids".into(),
            ));
        }
        let mut initialized = incoming[block_index].ok_or_else(|| {
            ResidencyError::InvalidPlan("worklist lost its incoming must fact".into())
        })?;
        for instruction in &block.instructions {
            match instruction {
                ResidencyInstruction::StorePhysical { .. } => initialized = true,
                ResidencyInstruction::LoadPhysical { .. }
                | ResidencyInstruction::AddPhysicalConst { .. }
                    if !initialized =>
                {
                    return Err(ResidencyError::InvalidPlan(format!(
                        "reachable block b{block_id} reads r12 before definite initialization"
                    )));
                }
                _ => {}
            }
        }

        let successors = match block.terminator {
            MachineTerminator::Goto { target } => [Some(target), None],
            MachineTerminator::Branch {
                if_true, if_false, ..
            } => [Some(if_true), Some(if_false)],
            MachineTerminator::Return { .. } => [None, None],
        };
        for successor in successors.into_iter().flatten() {
            let successor_index = usize::try_from(successor).map_err(|_| {
                ResidencyError::InvalidPlan("successor block exceeds host index space".into())
            })?;
            let current = incoming.get_mut(successor_index).ok_or_else(|| {
                ResidencyError::InvalidPlan(format!(
                    "residency control flow targets missing block b{successor}"
                ))
            })?;
            let merged = current.map_or(initialized, |known| known && initialized);
            if *current != Some(merged) {
                *current = Some(merged);
                worklist.push_back(successor);
            }
        }
    }
    Ok(())
}

pub fn replay_register_residency(
    machine: &ResidualMachineProgram,
    plan: &ResidencyPlan,
    baseline: &X64Plan,
    oracle: i64,
    step_limit: u64,
) -> Result<ReplayEvidence, ResidencyError> {
    verify_register_residency(plan, machine, baseline)?;
    if step_limit == 0 {
        return Err(ResidencyError::Replay(
            "semantic replay step limit must be positive".into(),
        ));
    }

    // These executions intentionally use independent states.  The candidate
    // does not erase itself back into Machine IR before execution.
    let baseline_summary = replay_machine(machine, step_limit)?;
    let (candidate_summary, abi_restored) = replay_candidate(machine, plan, step_limit)?;
    if baseline_summary.result != oracle || candidate_summary.result != oracle {
        return Err(ResidencyError::Replay(format!(
            "oracle mismatch: expected {oracle}, baseline {}, candidate {}",
            baseline_summary.result, candidate_summary.result
        )));
    }
    if baseline_summary != candidate_summary {
        return Err(ResidencyError::Replay(format!(
            "baseline/candidate semantic evidence diverged: {baseline_summary:?} != {candidate_summary:?}"
        )));
    }
    if baseline_summary.allocations != baseline_summary.releases
        || baseline_summary.live_owned_lists != 0
    {
        return Err(ResidencyError::Replay(
            "owned-list allocation/release closure failed".into(),
        ));
    }
    if !abi_restored {
        return Err(ResidencyError::Replay(
            "callee-saved r12 was not restored at return".into(),
        ));
    }
    Ok(ReplayEvidence {
        baseline: baseline_summary,
        candidate: candidate_summary,
        abi_restored,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReplayValue {
    Unit,
    Bool(bool),
    I64(i64),
    OwnedList(u32),
}

impl ReplayValue {
    fn ty(&self) -> MachineType {
        match self {
            Self::Unit => MachineType::Unit,
            Self::Bool(_) => MachineType::Bool,
            Self::I64(_) => MachineType::I64,
            Self::OwnedList(_) => MachineType::OwnedI64List,
        }
    }
}

#[derive(Clone, Debug)]
struct ReplayState {
    slot_types: Vec<MachineType>,
    slots: Vec<Option<ReplayValue>>,
    registers: Vec<Option<ReplayValue>>,
    heap: Vec<Option<Vec<i64>>>,
    steps: u64,
    overflow_events: u64,
    allocations: u64,
    releases: u64,
}

impl ReplayState {
    fn new(machine: &ResidualMachineProgram) -> Self {
        Self {
            slot_types: machine.slot_types.clone(),
            slots: vec![None; machine.slot_types.len()],
            registers: vec![None; machine.register_count as usize],
            heap: Vec::new(),
            steps: 0,
            overflow_events: 0,
            allocations: 0,
            releases: 0,
        }
    }

    fn tick(&mut self, limit: u64) -> Result<(), ResidencyError> {
        if self.steps >= limit {
            return Err(ResidencyError::Replay(format!(
                "semantic replay exceeded its {limit}-step envelope"
            )));
        }
        self.steps += 1;
        Ok(())
    }

    fn record_overflow(&mut self, overflowed: bool) -> Result<(), ResidencyError> {
        if overflowed {
            self.overflow_events = self.overflow_events.checked_add(1).ok_or_else(|| {
                ResidencyError::Replay("overflow-event counter overflowed".into())
            })?;
        }
        Ok(())
    }

    fn record_allocation(&mut self) -> Result<(), ResidencyError> {
        self.allocations = self
            .allocations
            .checked_add(1)
            .ok_or_else(|| ResidencyError::Replay("allocation counter overflowed".into()))?;
        Ok(())
    }

    fn record_release(&mut self) -> Result<(), ResidencyError> {
        self.releases = self
            .releases
            .checked_add(1)
            .ok_or_else(|| ResidencyError::Replay("release counter overflowed".into()))?;
        Ok(())
    }

    fn register(&self, register: TypedRegister) -> Result<ReplayValue, ResidencyError> {
        let value = self
            .registers
            .get(register.id as usize)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                ResidencyError::Replay(format!("read undefined virtual register r{}", register.id))
            })?;
        if value.ty() != register.ty {
            return Err(ResidencyError::Replay(format!(
                "virtual register r{} type drifted from {} to {}",
                register.id,
                register.ty.canonical_text(),
                value.ty().canonical_text()
            )));
        }
        Ok(value.clone())
    }

    fn set_register(
        &mut self,
        register: TypedRegister,
        value: ReplayValue,
    ) -> Result<(), ResidencyError> {
        if value.ty() != register.ty {
            return Err(ResidencyError::Replay(format!(
                "write to r{} expected {}, received {}",
                register.id,
                register.ty.canonical_text(),
                value.ty().canonical_text()
            )));
        }
        let home = self
            .registers
            .get_mut(register.id as usize)
            .ok_or_else(|| ResidencyError::Replay(format!("r{} is out of range", register.id)))?;
        *home = Some(value);
        Ok(())
    }

    fn consume_register(&mut self, register: TypedRegister) -> Result<(), ResidencyError> {
        let home = self
            .registers
            .get_mut(register.id as usize)
            .ok_or_else(|| ResidencyError::Replay(format!("r{} is out of range", register.id)))?;
        *home = None;
        Ok(())
    }

    fn slot(&self, slot: u32) -> Result<ReplayValue, ResidencyError> {
        self.slots
            .get(slot as usize)
            .and_then(Option::as_ref)
            .cloned()
            .ok_or_else(|| ResidencyError::Replay(format!("read undefined slot s{slot}")))
    }

    fn set_slot(&mut self, slot: u32, value: ReplayValue) -> Result<(), ResidencyError> {
        let expected = self
            .slot_types
            .get(slot as usize)
            .ok_or_else(|| ResidencyError::Replay(format!("slot s{slot} is outside the frame")))?;
        if value.ty() != *expected {
            return Err(ResidencyError::Replay(format!(
                "write to s{slot} expected {}, received {}",
                expected.canonical_text(),
                value.ty().canonical_text()
            )));
        }
        self.slots[slot as usize] = Some(value);
        Ok(())
    }

    fn integer_register(&self, register: TypedRegister) -> Result<i64, ResidencyError> {
        match self.register(register)? {
            ReplayValue::I64(value) => Ok(value),
            other => Err(ResidencyError::Replay(format!(
                "r{} is {}, not i64",
                register.id,
                other.ty().canonical_text()
            ))),
        }
    }

    fn integer_slot(&self, slot: u32) -> Result<i64, ResidencyError> {
        match self.slot(slot)? {
            ReplayValue::I64(value) => Ok(value),
            other => Err(ResidencyError::Replay(format!(
                "s{slot} is {}, not i64",
                other.ty().canonical_text()
            ))),
        }
    }

    fn list_register(&self, register: TypedRegister) -> Result<u32, ResidencyError> {
        match self.register(register)? {
            ReplayValue::OwnedList(handle) => Ok(handle),
            other => Err(ResidencyError::Replay(format!(
                "r{} is {}, not an owned list",
                register.id,
                other.ty().canonical_text()
            ))),
        }
    }

    fn live_list(&self, handle: u32) -> Result<&Vec<i64>, ResidencyError> {
        self.heap
            .get(handle as usize)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                ResidencyError::Replay(format!("owned-list handle {handle} is not live"))
            })
    }

    fn live_list_mut(&mut self, handle: u32) -> Result<&mut Vec<i64>, ResidencyError> {
        self.heap
            .get_mut(handle as usize)
            .and_then(Option::as_mut)
            .ok_or_else(|| {
                ResidencyError::Replay(format!("owned-list handle {handle} is not live"))
            })
    }

    fn finish(self, result: i64) -> Result<ReplaySummary, ResidencyError> {
        let live_owned_lists =
            u64::try_from(self.heap.iter().filter(|value| value.is_some()).count())
                .map_err(|_| ResidencyError::Replay("live-owner count exceeded u64".into()))?;
        Ok(ReplaySummary {
            result,
            steps: self.steps,
            overflow_events: self.overflow_events,
            allocations: self.allocations,
            releases: self.releases,
            live_owned_lists,
        })
    }
}

fn replay_machine(
    machine: &ResidualMachineProgram,
    step_limit: u64,
) -> Result<ReplaySummary, ResidencyError> {
    let mut state = ReplayState::new(machine);
    let mut block_id = machine.entry_block;
    loop {
        let block = machine.blocks.get(block_id as usize).ok_or_else(|| {
            ResidencyError::Replay(format!("baseline jumped outside the graph to b{block_id}"))
        })?;
        if block.id != block_id {
            return Err(ResidencyError::Replay(
                "baseline blocks are not canonical contiguous ids".into(),
            ));
        }
        for instruction in &block.instructions {
            state.tick(step_limit)?;
            execute_machine_instruction(&mut state, instruction)?;
        }
        state.tick(step_limit)?;
        match &block.terminator {
            MachineTerminator::Goto { target } => block_id = *target,
            MachineTerminator::Branch {
                condition,
                if_true,
                if_false,
            } => {
                block_id = match state.register(*condition)? {
                    ReplayValue::Bool(true) => *if_true,
                    ReplayValue::Bool(false) => *if_false,
                    _ => {
                        return Err(ResidencyError::Replay(
                            "baseline branch condition is not bool".into(),
                        ));
                    }
                };
            }
            MachineTerminator::Return { value } => {
                let result = state.integer_register(*value)?;
                return state.finish(result);
            }
        }
    }
}

fn replay_candidate(
    machine: &ResidualMachineProgram,
    plan: &ResidencyPlan,
    step_limit: u64,
) -> Result<(ReplaySummary, bool), ResidencyError> {
    const CALLER_R12: i64 = 0x5a17_12ab_4c3d_2901;

    let mut state = ReplayState::new(machine);
    let mut physical_r12 = Some(CALLER_R12);
    let saved_r12 = plan.save_on_entry.then_some(physical_r12).flatten();
    // The admitted prologue turns the physical register into the promoted
    // home only after preserving its incoming caller value.
    physical_r12 = None;
    let mut block_id = machine.entry_block;
    loop {
        let block = plan.blocks.get(block_id as usize).ok_or_else(|| {
            ResidencyError::Replay(format!("candidate jumped outside the graph to b{block_id}"))
        })?;
        if block.id != block_id {
            return Err(ResidencyError::Replay(
                "candidate blocks are not canonical contiguous ids".into(),
            ));
        }
        for instruction in &block.instructions {
            state.tick(step_limit)?;
            match instruction {
                ResidencyInstruction::PassThrough(instruction) => {
                    execute_machine_instruction(&mut state, instruction)?;
                }
                ResidencyInstruction::LoadPhysical { result, register } => {
                    if *register != PhysicalRegister::R12 {
                        return Err(ResidencyError::Replay(
                            "candidate referenced an unadmitted physical register".into(),
                        ));
                    }
                    let value = physical_r12.ok_or_else(|| {
                        ResidencyError::Replay("candidate read r12 before initialization".into())
                    })?;
                    state.set_register(*result, ReplayValue::I64(value))?;
                }
                ResidencyInstruction::StorePhysical {
                    register,
                    value,
                    keep,
                } => {
                    if *register != PhysicalRegister::R12 {
                        return Err(ResidencyError::Replay(
                            "candidate referenced an unadmitted physical register".into(),
                        ));
                    }
                    physical_r12 = Some(state.integer_register(*value)?);
                    if !keep {
                        state.consume_register(*value)?;
                    }
                }
                ResidencyInstruction::AddPhysicalConst { register, value } => {
                    if *register != PhysicalRegister::R12 {
                        return Err(ResidencyError::Replay(
                            "candidate referenced an unadmitted physical register".into(),
                        ));
                    }
                    let current = physical_r12.ok_or_else(|| {
                        ResidencyError::Replay("candidate updated r12 before initialization".into())
                    })?;
                    let (updated, overflowed) = current.overflowing_add(*value);
                    state.record_overflow(overflowed)?;
                    physical_r12 = Some(updated);
                }
            }
        }
        state.tick(step_limit)?;
        match &block.terminator {
            MachineTerminator::Goto { target } => block_id = *target,
            MachineTerminator::Branch {
                condition,
                if_true,
                if_false,
            } => {
                block_id = match state.register(*condition)? {
                    ReplayValue::Bool(true) => *if_true,
                    ReplayValue::Bool(false) => *if_false,
                    _ => {
                        return Err(ResidencyError::Replay(
                            "candidate branch condition is not bool".into(),
                        ));
                    }
                };
            }
            MachineTerminator::Return { value } => {
                let result = state.integer_register(*value)?;
                if plan.restore_on_return {
                    physical_r12 = saved_r12;
                }
                return Ok((state.finish(result)?, physical_r12 == Some(CALLER_R12)));
            }
        }
    }
}

fn execute_machine_instruction(
    state: &mut ReplayState,
    instruction: &MachineInstruction,
) -> Result<(), ResidencyError> {
    match instruction {
        MachineInstruction::ConstI64 { result, value } => {
            state.set_register(*result, ReplayValue::I64(*value))?;
        }
        MachineInstruction::LoadSlot { result, slot } => {
            let value = state.slot(*slot)?;
            state.set_register(*result, value)?;
        }
        MachineInstruction::StoreSlot { slot, value, keep } => {
            let stored = state.register(*value)?;
            state.set_slot(*slot, stored)?;
            if !keep {
                state.consume_register(*value)?;
            }
        }
        MachineInstruction::AddSlotConst { slot, value } => {
            let current = state.integer_slot(*slot)?;
            let (updated, overflowed) = current.overflowing_add(*value);
            state.record_overflow(overflowed)?;
            state.set_slot(*slot, ReplayValue::I64(updated))?;
        }
        MachineInstruction::IntegerBinary {
            result,
            operation,
            left,
            right,
        } => {
            let left = state.integer_register(*left)?;
            let right = state.integer_register(*right)?;
            let (value, overflowed) = match operation {
                IntegerBinary::Add => left.overflowing_add(right),
                IntegerBinary::Sub => left.overflowing_sub(right),
                IntegerBinary::Mul => left.overflowing_mul(right),
                _ => {
                    return Err(ResidencyError::Replay(format!(
                        "integer operation {operation:?} is outside the WP8C replay envelope"
                    )));
                }
            };
            state.record_overflow(overflowed)?;
            state.set_register(*result, ReplayValue::I64(value))?;
        }
        MachineInstruction::IntegerCompare {
            result,
            operation,
            left,
            right,
        } => {
            let left = state.integer_register(*left)?;
            let right = state.integer_register(*right)?;
            let value = match operation {
                IntegerCompare::Eq => left == right,
                IntegerCompare::Ne => left != right,
                IntegerCompare::Gt => left > right,
                IntegerCompare::Ge => left >= right,
                IntegerCompare::Lt => left < right,
                IntegerCompare::Le => left <= right,
            };
            state.set_register(*result, ReplayValue::Bool(value))?;
        }
        MachineInstruction::RangeAllocateInit { result, length } => {
            let length = usize::try_from(*length).map_err(|_| {
                ResidencyError::Replay("owned-list length is not host-addressable".into())
            })?;
            let mut values = Vec::new();
            values.try_reserve_exact(length).map_err(|_| {
                ResidencyError::Replay("owned-list allocation exceeded host capacity".into())
            })?;
            for index in 0..length {
                values
                    .push(i64::try_from(index).map_err(|_| {
                        ResidencyError::Replay("range element exceeded i64".into())
                    })?);
            }
            let handle = u32::try_from(state.heap.len())
                .map_err(|_| ResidencyError::Replay("owned-list handle space exhausted".into()))?;
            state.heap.push(Some(values));
            state.record_allocation()?;
            state.set_register(*result, ReplayValue::OwnedList(handle))?;
        }
        MachineInstruction::ListLengthStatic {
            result,
            slot,
            length,
        } => {
            let handle = match state.slot(*slot)? {
                ReplayValue::OwnedList(handle) => handle,
                _ => {
                    return Err(ResidencyError::Replay(format!(
                        "list-length-static source s{slot} is not an owned list"
                    )));
                }
            };
            let actual = u64::try_from(state.live_list(handle)?.len())
                .map_err(|_| ResidencyError::Replay("live list length exceeded u64".into()))?;
            if actual != *length {
                return Err(ResidencyError::Replay(format!(
                    "static list length {length} disagrees with live length {actual}"
                )));
            }
            let value = i64::try_from(*length)
                .map_err(|_| ResidencyError::Replay("static list length exceeded i64".into()))?;
            state.set_register(*result, ReplayValue::I64(value))?;
        }
        MachineInstruction::ListLoadChecked {
            result,
            list,
            index,
        } => {
            let handle = state.list_register(*list)?;
            let index = checked_index(state.integer_register(*index)?)?;
            let value = *state.live_list(handle)?.get(index).ok_or_else(|| {
                ResidencyError::Replay("checked list load escaped its live bounds".into())
            })?;
            state.set_register(*result, ReplayValue::I64(value))?;
        }
        MachineInstruction::ListStoreChecked {
            result,
            list,
            index,
            value,
        } => {
            let handle = state.list_register(*list)?;
            let index = checked_index(state.integer_register(*index)?)?;
            let value = state.integer_register(*value)?;
            let destination = state.live_list_mut(handle)?.get_mut(index).ok_or_else(|| {
                ResidencyError::Replay("checked list store escaped its live bounds".into())
            })?;
            *destination = value;
            state.set_register(*result, ReplayValue::Unit)?;
        }
        MachineInstruction::ReleaseOwnedList { slot } => {
            let handle = match state.slot(*slot)? {
                ReplayValue::OwnedList(handle) => handle,
                _ => {
                    return Err(ResidencyError::Replay(format!(
                        "release source s{slot} is not an owned list"
                    )));
                }
            };
            let live = state.heap.get_mut(handle as usize).ok_or_else(|| {
                ResidencyError::Replay(format!("owned-list handle {handle} is out of range"))
            })?;
            if live.take().is_none() {
                return Err(ResidencyError::Replay(format!(
                    "owned-list handle {handle} was released twice"
                )));
            }
            state.record_release()?;
            state.slots[*slot as usize] = None;
        }
    }
    Ok(())
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_replay_summary(bytes: &mut Vec<u8>, summary: ReplaySummary) {
    put_i64(bytes, summary.result);
    put_u64(bytes, summary.steps);
    put_u64(bytes, summary.overflow_events);
    put_u64(bytes, summary.allocations);
    put_u64(bytes, summary.releases);
    put_u64(bytes, summary.live_owned_lists);
}

fn put_len(bytes: &mut Vec<u8>, value: usize) -> Result<(), ResidencyError> {
    let value = u64::try_from(value)
        .map_err(|_| ResidencyError::InvalidPlan("plan extent exceeds u64".into()))?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ResidencyError> {
    put_len(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut output = [0_u8; 32];
    for (chunk, value) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    output
}

fn checked_index(value: i64) -> Result<usize, ResidencyError> {
    usize::try_from(value)
        .map_err(|_| ResidencyError::Replay(format!("negative list index {value}")))
}

fn references_slot(instruction: &MachineInstruction, slot: u32) -> bool {
    match instruction {
        MachineInstruction::LoadSlot { slot: value, .. }
        | MachineInstruction::StoreSlot { slot: value, .. }
        | MachineInstruction::AddSlotConst { slot: value, .. }
        | MachineInstruction::ListLengthStatic { slot: value, .. }
        | MachineInstruction::ReleaseOwnedList { slot: value } => *value == slot,
        _ => false,
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use crate::machine::MachineBlock;
    use naux::core::SemanticHash;

    #[test]
    fn plan_sha256_matches_standard_vector() {
        assert_eq!(
            SemanticHash(sha256(b"abc")).to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sealed_parent_replay_is_canonical_and_mutation_sensitive() {
        let magic = "NAUX-TEST-PARENT\t1";
        let domain = b"NAUX:test-parent:v1\0";
        let body = format!("{magic}\nmeta\tstatus\taccepted\n");
        let mut preimage = domain.to_vec();
        preimage.extend_from_slice(body.as_bytes());
        let root = SemanticHash(sha256(&preimage));
        let document = format!("{body}seal\t{root}\n");
        assert_eq!(
            sealed_document_root(document.as_bytes(), magic, domain)
                .expect("canonical parent replays"),
            root
        );

        let mutation = document.replacen("accepted", "rejected", 1);
        assert!(sealed_document_root(mutation.as_bytes(), magic, domain).is_err());
        assert!(sealed_document_root(document.trim_end().as_bytes(), magic, domain).is_err());
        assert!(sealed_document_root(document.as_bytes(), "NAUX-WRONG\t1", domain).is_err());
    }

    fn overflow_vector() -> (ResidualMachineProgram, ResidencyPlan) {
        let r0 = TypedRegister {
            id: 0,
            ty: MachineType::I64,
        };
        let r1 = TypedRegister {
            id: 1,
            ty: MachineType::I64,
        };
        let machine = ResidualMachineProgram {
            source_residual_hash: SemanticHash::ZERO,
            source_witness_hash: SemanticHash::ZERO,
            entry_block: 0,
            slot_types: vec![MachineType::I64],
            register_count: 2,
            blocks: vec![MachineBlock {
                id: 0,
                residual_start: 0,
                residual_end: 4,
                instructions: vec![
                    MachineInstruction::ConstI64 {
                        result: r0,
                        value: i64::MAX,
                    },
                    MachineInstruction::StoreSlot {
                        slot: 0,
                        value: r0,
                        keep: true,
                    },
                    MachineInstruction::AddSlotConst { slot: 0, value: 1 },
                    MachineInstruction::LoadSlot {
                        result: r1,
                        slot: 0,
                    },
                ],
                terminator: MachineTerminator::Return { value: r1 },
            }],
            source_map: Vec::new(),
        };
        let plan = ResidencyPlan {
            source_machine_hash: machine.semantic_hash(),
            frame_bytes: 16,
            promoted_slot: 0,
            promoted_type: MachineType::I64,
            physical_register: PhysicalRegister::R12,
            save_on_entry: true,
            restore_on_return: true,
            error_path_nonreturning: true,
            static_reads: 2,
            static_writes: 2,
            blocks: vec![ResidencyBlock {
                id: 0,
                instructions: vec![
                    ResidencyInstruction::PassThrough(MachineInstruction::ConstI64 {
                        result: r0,
                        value: i64::MAX,
                    }),
                    ResidencyInstruction::StorePhysical {
                        register: PhysicalRegister::R12,
                        value: r0,
                        keep: true,
                    },
                    ResidencyInstruction::AddPhysicalConst {
                        register: PhysicalRegister::R12,
                        value: 1,
                    },
                    ResidencyInstruction::LoadPhysical {
                        result: r1,
                        register: PhysicalRegister::R12,
                    },
                ],
                terminator: MachineTerminator::Return { value: r1 },
            }],
        };
        (machine, plan)
    }

    #[test]
    fn baseline_and_physical_home_share_exact_wrapping_overflow_policy() {
        let (machine, plan) = overflow_vector();
        let baseline = replay_machine(&machine, 5).expect("baseline overflow vector replays");
        let (candidate, abi_restored) =
            replay_candidate(&machine, &plan, 5).expect("candidate overflow vector replays");
        assert_eq!(baseline, candidate);
        assert_eq!(candidate.result, i64::MIN);
        assert_eq!(candidate.steps, 5);
        assert_eq!(candidate.overflow_events, 1);
        assert!(abi_restored);
    }

    #[test]
    fn cfg_path_that_reads_before_initialization_fails_closed() {
        let i0 = TypedRegister {
            id: 0,
            ty: MachineType::I64,
        };
        let i1 = TypedRegister {
            id: 1,
            ty: MachineType::I64,
        };
        let condition = TypedRegister {
            id: 2,
            ty: MachineType::Bool,
        };
        let premature = TypedRegister {
            id: 3,
            ty: MachineType::I64,
        };
        let result = TypedRegister {
            id: 4,
            ty: MachineType::I64,
        };
        let machine = ResidualMachineProgram {
            source_residual_hash: SemanticHash::ZERO,
            source_witness_hash: SemanticHash::ZERO,
            entry_block: 0,
            slot_types: vec![MachineType::I64],
            register_count: 5,
            blocks: vec![
                MachineBlock {
                    id: 0,
                    residual_start: 0,
                    residual_end: 3,
                    instructions: vec![
                        MachineInstruction::ConstI64 {
                            result: i0,
                            value: 0,
                        },
                        MachineInstruction::ConstI64 {
                            result: i1,
                            value: 0,
                        },
                        MachineInstruction::IntegerCompare {
                            result: condition,
                            operation: IntegerCompare::Eq,
                            left: i0,
                            right: i1,
                        },
                    ],
                    terminator: MachineTerminator::Branch {
                        condition,
                        if_true: 1,
                        if_false: 2,
                    },
                },
                MachineBlock {
                    id: 1,
                    residual_start: 3,
                    residual_end: 4,
                    instructions: vec![MachineInstruction::StoreSlot {
                        slot: 0,
                        value: i0,
                        keep: true,
                    }],
                    terminator: MachineTerminator::Goto { target: 3 },
                },
                MachineBlock {
                    id: 2,
                    residual_start: 4,
                    residual_end: 5,
                    instructions: vec![MachineInstruction::LoadSlot {
                        result: premature,
                        slot: 0,
                    }],
                    terminator: MachineTerminator::Goto { target: 3 },
                },
                MachineBlock {
                    id: 3,
                    residual_start: 5,
                    residual_end: 6,
                    instructions: vec![MachineInstruction::LoadSlot { result, slot: 0 }],
                    terminator: MachineTerminator::Return { value: result },
                },
            ],
            source_map: Vec::new(),
        };
        let baseline = X64Plan {
            source_machine_hash: machine.semantic_hash(),
            frame_bytes: 16,
            list_length: 1,
            slot_homes: Vec::new(),
            register_homes: Vec::new(),
            blocks: Vec::new(),
        };
        let error = lower_register_residency(
            &machine,
            &baseline,
            Selection {
                slot: 0,
                expected_static_reads: 2,
                expected_static_writes: 1,
            },
        )
        .expect_err("one uninitialized CFG path must be rejected");
        assert!(matches!(error, ResidencyError::InvalidPlan(_)));
        assert!(error.to_string().contains("before definite initialization"));
    }
}
