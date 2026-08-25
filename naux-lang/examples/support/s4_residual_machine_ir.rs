//! Target-independent residual Machine IR for S4-WP5C.
//!
//! The sealed R1-S6 Machine IR is intentionally not widened here: its value
//! and effect envelope predates owned mutable I64 lists.  This scoped schema
//! converts the verified WP5B stack program into typed slots, virtual
//! registers, basic blocks, and explicit terminators.  Every residual
//! instruction receives exactly one correspondence entry and unsupported
//! stack, type, ownership, or control-flow shapes fail closed.

use crate::residual::{verify_work, ResidualError, ResidualOp, ResidualProgram, WorkWitness};
use naux::core::SemanticHash;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MACHINE_DOMAIN: &[u8] = b"NAUX:s4-residual-machine-ir:program:v1\0";
const CORRESPONDENCE_DOMAIN: &[u8] = b"NAUX:s4-residual-machine-ir:correspondence:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineType {
    Unit,
    Bool,
    I64,
    OwnedI64List,
}

impl MachineType {
    pub fn canonical_text(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Bool => "bool",
            Self::I64 => "i64",
            Self::OwnedI64List => "owned-list-i64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypedRegister {
    pub id: u32,
    pub ty: MachineType,
}

impl TypedRegister {
    fn canonical_text(self) -> String {
        format!("r{}:{}", self.id, self.ty.canonical_text())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegerBinary {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Xor,
    Shl,
    And,
    Or,
}

impl IntegerBinary {
    fn canonical_text(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Mod => "mod",
            Self::Xor => "xor",
            Self::Shl => "shl",
            Self::And => "and",
            Self::Or => "or",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegerCompare {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl IntegerCompare {
    fn canonical_text(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Gt => "gt",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Le => "le",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineInstruction {
    ConstI64 {
        result: TypedRegister,
        value: i64,
    },
    LoadSlot {
        result: TypedRegister,
        slot: u32,
    },
    StoreSlot {
        slot: u32,
        value: TypedRegister,
        keep: bool,
    },
    AddSlotConst {
        slot: u32,
        value: i64,
    },
    IntegerBinary {
        result: TypedRegister,
        operation: IntegerBinary,
        left: TypedRegister,
        right: TypedRegister,
    },
    IntegerCompare {
        result: TypedRegister,
        operation: IntegerCompare,
        left: TypedRegister,
        right: TypedRegister,
    },
    RangeAllocateInit {
        result: TypedRegister,
        length: u64,
    },
    ListLengthStatic {
        result: TypedRegister,
        slot: u32,
        length: u64,
    },
    ListLoadChecked {
        result: TypedRegister,
        list: TypedRegister,
        index: TypedRegister,
    },
    ListStoreChecked {
        result: TypedRegister,
        list: TypedRegister,
        index: TypedRegister,
        value: TypedRegister,
    },
    ReleaseOwnedList {
        slot: u32,
    },
}

impl MachineInstruction {
    pub fn canonical_text(&self) -> String {
        match self {
            Self::ConstI64 { result, value } => {
                format!("const-i64\t{}\t{value}", result.canonical_text())
            }
            Self::LoadSlot { result, slot } => {
                format!("load-slot\t{}\ts{slot}", result.canonical_text())
            }
            Self::StoreSlot { slot, value, keep } => format!(
                "store-slot\ts{slot}\t{}\t{}",
                value.canonical_text(),
                if *keep { "keep" } else { "consume" }
            ),
            Self::AddSlotConst { slot, value } => {
                format!("add-slot-const\ts{slot}\t{value}")
            }
            Self::IntegerBinary {
                result,
                operation,
                left,
                right,
            } => format!(
                "i64-{}\t{}\t{}\t{}",
                operation.canonical_text(),
                result.canonical_text(),
                left.canonical_text(),
                right.canonical_text()
            ),
            Self::IntegerCompare {
                result,
                operation,
                left,
                right,
            } => format!(
                "i64-{}\t{}\t{}\t{}",
                operation.canonical_text(),
                result.canonical_text(),
                left.canonical_text(),
                right.canonical_text()
            ),
            Self::RangeAllocateInit { result, length } => {
                format!("range-allocate-init\t{}\t{length}", result.canonical_text())
            }
            Self::ListLengthStatic {
                result,
                slot,
                length,
            } => format!(
                "list-length-static\t{}\ts{slot}\t{length}",
                result.canonical_text()
            ),
            Self::ListLoadChecked {
                result,
                list,
                index,
            } => format!(
                "list-load-checked\t{}\t{}\t{}",
                result.canonical_text(),
                list.canonical_text(),
                index.canonical_text()
            ),
            Self::ListStoreChecked {
                result,
                list,
                index,
                value,
            } => format!(
                "list-store-checked\t{}\t{}\t{}\t{}",
                result.canonical_text(),
                list.canonical_text(),
                index.canonical_text(),
                value.canonical_text()
            ),
            Self::ReleaseOwnedList { slot } => format!("release-owned-list\ts{slot}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineTerminator {
    Goto {
        target: u32,
    },
    Branch {
        condition: TypedRegister,
        if_true: u32,
        if_false: u32,
    },
    Return {
        value: TypedRegister,
    },
}

impl MachineTerminator {
    pub fn canonical_text(&self) -> String {
        match self {
            Self::Goto { target } => format!("goto\tb{target}"),
            Self::Branch {
                condition,
                if_true,
                if_false,
            } => format!(
                "branch\t{}\tb{if_true}\tb{if_false}",
                condition.canonical_text()
            ),
            Self::Return { value } => format!("return\t{}", value.canonical_text()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineBlock {
    pub id: u32,
    pub residual_start: u32,
    pub residual_end: u32,
    pub instructions: Vec<MachineInstruction>,
    pub terminator: MachineTerminator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingKind {
    Instruction,
    Terminator,
}

impl MappingKind {
    fn canonical_text(self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::Terminator => "terminator",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceMapping {
    pub residual_ip: u32,
    pub block: u32,
    pub machine_ordinal: u32,
    pub kind: MappingKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidualMachineProgram {
    pub source_residual_hash: SemanticHash,
    pub source_witness_hash: SemanticHash,
    pub entry_block: u32,
    pub slot_types: Vec<MachineType>,
    pub register_count: u32,
    pub blocks: Vec<MachineBlock>,
    pub source_map: Vec<SourceMapping>,
}

impl ResidualMachineProgram {
    pub fn semantic_hash(&self) -> SemanticHash {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.source_residual_hash.0);
        bytes.extend_from_slice(&self.source_witness_hash.0);
        put_u32(&mut bytes, self.entry_block);
        put_u32(&mut bytes, self.register_count);
        put_u32(&mut bytes, self.slot_types.len() as u32);
        for ty in &self.slot_types {
            put_string(&mut bytes, ty.canonical_text());
        }
        put_u32(&mut bytes, self.blocks.len() as u32);
        for block in &self.blocks {
            put_u32(&mut bytes, block.id);
            put_u32(&mut bytes, block.residual_start);
            put_u32(&mut bytes, block.residual_end);
            put_u32(&mut bytes, block.instructions.len() as u32);
            for instruction in &block.instructions {
                put_string(&mut bytes, &instruction.canonical_text());
            }
            put_string(&mut bytes, &block.terminator.canonical_text());
        }
        put_u32(&mut bytes, self.source_map.len() as u32);
        for mapping in &self.source_map {
            put_u32(&mut bytes, mapping.residual_ip);
            put_u32(&mut bytes, mapping.block);
            put_u32(&mut bytes, mapping.machine_ordinal);
            put_string(&mut bytes, mapping.kind.canonical_text());
        }
        hash_domain(MACHINE_DOMAIN, &bytes)
    }

    pub fn instruction_count(&self) -> u32 {
        self.blocks
            .iter()
            .map(|block| block.instructions.len() as u32)
            .sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineCorrespondence {
    pub machine_hash: SemanticHash,
    pub residual_hash: SemanticHash,
    pub witness_hash: SemanticHash,
    pub block_count: u32,
    pub instruction_count: u32,
    pub terminator_count: u32,
    pub register_count: u32,
    pub mapping_count: u32,
    pub allocation_block: u32,
    pub release_block: u32,
    pub outer_header_block: u32,
    pub outer_exit_block: u32,
    pub inner_header_block: u32,
    pub inner_exit_block: u32,
    pub traversal_count: u64,
    pub list_loads: u32,
    pub list_stores: u32,
}

impl MachineCorrespondence {
    pub fn semantic_hash(&self) -> SemanticHash {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.machine_hash.0);
        bytes.extend_from_slice(&self.residual_hash.0);
        bytes.extend_from_slice(&self.witness_hash.0);
        for value in [
            self.block_count,
            self.instruction_count,
            self.terminator_count,
            self.register_count,
            self.mapping_count,
            self.allocation_block,
            self.release_block,
            self.outer_header_block,
            self.outer_exit_block,
            self.inner_header_block,
            self.inner_exit_block,
            self.list_loads,
            self.list_stores,
        ] {
            put_u32(&mut bytes, value);
        }
        put_u64(&mut bytes, self.traversal_count);
        hash_domain(CORRESPONDENCE_DOMAIN, &bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineLoweringError {
    Residual(String),
    InvalidControlFlow(String),
    InvalidType(String),
    InvalidOwnership(String),
    InvalidCorrespondence(String),
}

impl fmt::Display for MachineLoweringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (label, message) = match self {
            Self::Residual(message) => ("residual", message),
            Self::InvalidControlFlow(message) => ("control flow", message),
            Self::InvalidType(message) => ("type", message),
            Self::InvalidOwnership(message) => ("ownership", message),
            Self::InvalidCorrespondence(message) => ("correspondence", message),
        };
        write!(formatter, "residual Machine IR {label} error: {message}")
    }
}

impl std::error::Error for MachineLoweringError {}

impl From<ResidualError> for MachineLoweringError {
    fn from(error: ResidualError) -> Self {
        Self::Residual(error.to_string())
    }
}

struct LoweringState {
    next_register: u32,
    slot_types: Vec<Option<MachineType>>,
}

impl LoweringState {
    fn register(&mut self, ty: MachineType) -> Result<TypedRegister, MachineLoweringError> {
        let id = self.next_register;
        self.next_register = self.next_register.checked_add(1).ok_or_else(|| {
            MachineLoweringError::InvalidType("virtual register space overflowed".into())
        })?;
        Ok(TypedRegister { id, ty })
    }

    fn slot(&self, slot: u32) -> Result<MachineType, MachineLoweringError> {
        self.slot_types
            .get(slot as usize)
            .and_then(|ty| *ty)
            .ok_or_else(|| {
                MachineLoweringError::InvalidType(format!(
                    "slot {slot} is read before its type is established"
                ))
            })
    }

    fn establish_slot(&mut self, slot: u32, ty: MachineType) -> Result<(), MachineLoweringError> {
        let target = self.slot_types.get_mut(slot as usize).ok_or_else(|| {
            MachineLoweringError::InvalidType(format!("slot {slot} is outside the frame"))
        })?;
        match *target {
            Some(existing) if existing != ty => Err(MachineLoweringError::InvalidType(format!(
                "slot {slot} changes type from {} to {}",
                existing.canonical_text(),
                ty.canonical_text()
            ))),
            Some(_) => Ok(()),
            None => {
                *target = Some(ty);
                Ok(())
            }
        }
    }
}

/// Lower one verified WP5B residual through a single stack-to-register path.
pub fn lower_residual_machine_ir(
    residual: &ResidualProgram,
) -> Result<(ResidualMachineProgram, MachineCorrespondence), MachineLoweringError> {
    let work = verify_work(residual)?;
    let leaders = block_leaders(residual)?;
    let ranges = block_ranges(&leaders, residual.ops.len())?;
    let ip_to_block = ip_to_block(&ranges, residual.ops.len())?;
    let mut state = LoweringState {
        next_register: 0,
        slot_types: vec![None; residual.local_count as usize],
    };
    state.establish_slot(residual.list_local, MachineType::OwnedI64List)?;
    let mut blocks = Vec::with_capacity(ranges.len());
    let mut source_map = Vec::with_capacity(residual.ops.len());

    for (block_id, (start, end)) in ranges.iter().copied().enumerate() {
        let mut stack = Vec::new();
        let mut instructions = Vec::new();
        let mut terminator = None;
        for ip in start..end {
            let op = &residual.ops[ip];
            if is_terminator(op) {
                if ip + 1 != end {
                    return Err(MachineLoweringError::InvalidControlFlow(format!(
                        "residual terminator {ip} does not end block {block_id}"
                    )));
                }
                let machine_ordinal = instructions.len() as u32;
                terminator = Some(lower_terminator(
                    op,
                    ip,
                    &mut stack,
                    &ip_to_block,
                    residual.ops.len(),
                )?);
                source_map.push(SourceMapping {
                    residual_ip: ip as u32,
                    block: block_id as u32,
                    machine_ordinal,
                    kind: MappingKind::Terminator,
                });
            } else {
                let machine_ordinal = instructions.len() as u32;
                instructions.push(lower_instruction(op, &mut stack, &mut state)?);
                source_map.push(SourceMapping {
                    residual_ip: ip as u32,
                    block: block_id as u32,
                    machine_ordinal,
                    kind: MappingKind::Instruction,
                });
            }
        }
        if !stack.is_empty() {
            return Err(MachineLoweringError::InvalidControlFlow(format!(
                "block {block_id} carries a residual operand stack across an edge"
            )));
        }
        let terminator = match terminator {
            Some(terminator) => terminator,
            None if end < residual.ops.len() => MachineTerminator::Goto {
                target: ip_to_block[end],
            },
            None => {
                return Err(MachineLoweringError::InvalidControlFlow(format!(
                    "terminal block {block_id} has no explicit residual terminator"
                )))
            }
        };
        blocks.push(MachineBlock {
            id: block_id as u32,
            residual_start: start as u32,
            residual_end: end as u32,
            instructions,
            terminator,
        });
    }

    let slot_types = state
        .slot_types
        .into_iter()
        .enumerate()
        .map(|(slot, ty)| {
            ty.ok_or_else(|| {
                MachineLoweringError::InvalidType(format!(
                    "slot {slot} never receives a closed machine type"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let machine = ResidualMachineProgram {
        source_residual_hash: residual.semantic_hash(),
        source_witness_hash: work.semantic_hash(),
        entry_block: 0,
        slot_types,
        register_count: state.next_register,
        blocks,
        source_map,
    };
    let correspondence = verify_machine_ir(residual, &work, &machine)?;
    Ok((machine, correspondence))
}

pub fn verify_machine_ir(
    residual: &ResidualProgram,
    work: &WorkWitness,
    machine: &ResidualMachineProgram,
) -> Result<MachineCorrespondence, MachineLoweringError> {
    if machine.source_residual_hash != residual.semantic_hash()
        || machine.source_witness_hash != work.semantic_hash()
    {
        return Err(MachineLoweringError::InvalidCorrespondence(
            "source residual or witness identity drifted".into(),
        ));
    }
    if machine.entry_block != 0 || machine.blocks.is_empty() {
        return Err(MachineLoweringError::InvalidControlFlow(
            "entry block is not canonical block zero".into(),
        ));
    }
    if machine.slot_types.len() != residual.local_count as usize
        || machine.slot_types[residual.list_local as usize] != MachineType::OwnedI64List
    {
        return Err(MachineLoweringError::InvalidType(
            "closed slot frame does not preserve the owned list".into(),
        ));
    }

    let mut expected_start = 0_u32;
    let mut seen_registers = BTreeSet::new();
    let mut defined_registers = BTreeMap::new();
    let mut allocation_sites = Vec::new();
    let mut release_sites = Vec::new();
    let mut list_loads = 0_u32;
    let mut list_stores = 0_u32;
    for (expected_id, block) in machine.blocks.iter().enumerate() {
        if block.id != expected_id as u32
            || block.residual_start != expected_start
            || block.residual_start >= block.residual_end
        {
            return Err(MachineLoweringError::InvalidControlFlow(
                "machine blocks are not contiguous canonical ranges".into(),
            ));
        }
        expected_start = block.residual_end;
        for (ordinal, instruction) in block.instructions.iter().enumerate() {
            verify_instruction(
                instruction,
                &machine.slot_types,
                &mut seen_registers,
                &mut defined_registers,
            )?;
            match instruction {
                MachineInstruction::RangeAllocateInit { .. } => {
                    allocation_sites.push((block.id, ordinal as u32));
                }
                MachineInstruction::ReleaseOwnedList { .. } => {
                    release_sites.push((block.id, ordinal as u32));
                }
                MachineInstruction::ListLoadChecked { .. } => list_loads += 1,
                MachineInstruction::ListStoreChecked { .. } => list_stores += 1,
                _ => {}
            }
        }
        verify_terminator(
            &block.terminator,
            machine.blocks.len() as u32,
            &defined_registers,
        )?;
    }
    if expected_start as usize != residual.ops.len() {
        return Err(MachineLoweringError::InvalidControlFlow(
            "machine block ranges do not cover the residual".into(),
        ));
    }
    if seen_registers.len() != machine.register_count as usize
        || seen_registers.iter().copied().ne(0..machine.register_count)
    {
        return Err(MachineLoweringError::InvalidType(
            "virtual registers are not single-assignment contiguous identities".into(),
        ));
    }
    if allocation_sites.len() != 1 || release_sites.len() != 1 {
        return Err(MachineLoweringError::InvalidOwnership(
            "exactly one allocation and release must remain".into(),
        ));
    }
    if list_loads != work.list_loads || list_stores != work.list_stores {
        return Err(MachineLoweringError::InvalidCorrespondence(
            "machine list effects do not match the residual witness".into(),
        ));
    }
    verify_source_map(residual, machine)?;

    let block_for = |ip: u32| -> Result<u32, MachineLoweringError> {
        machine
            .source_map
            .get(ip as usize)
            .filter(|mapping| mapping.residual_ip == ip)
            .map(|mapping| mapping.block)
            .ok_or_else(|| {
                MachineLoweringError::InvalidCorrespondence(format!(
                    "residual instruction {ip} has no exact machine mapping"
                ))
            })
    };
    Ok(MachineCorrespondence {
        machine_hash: machine.semantic_hash(),
        residual_hash: residual.semantic_hash(),
        witness_hash: work.semantic_hash(),
        block_count: machine.blocks.len() as u32,
        instruction_count: machine.instruction_count(),
        terminator_count: machine.blocks.len() as u32,
        register_count: machine.register_count,
        mapping_count: machine.source_map.len() as u32,
        allocation_block: block_for(work.allocation)?,
        release_block: block_for(work.release)?,
        outer_header_block: block_for(work.outer.header)?,
        outer_exit_block: block_for(work.outer.guard_exit)?,
        inner_header_block: block_for(work.inner.header)?,
        inner_exit_block: block_for(work.inner.guard_exit)?,
        traversal_count: work.traversal_count,
        list_loads,
        list_stores,
    })
}

fn block_leaders(residual: &ResidualProgram) -> Result<Vec<usize>, MachineLoweringError> {
    let mut leaders = BTreeSet::from([0_usize]);
    for (ip, op) in residual.ops.iter().enumerate() {
        match *op {
            ResidualOp::Jump(target) | ResidualOp::JumpIfFalse(target) => {
                let target = target as usize;
                if target >= residual.ops.len() {
                    return Err(MachineLoweringError::InvalidControlFlow(format!(
                        "jump {ip} targets {target} outside the residual"
                    )));
                }
                leaders.insert(target);
                if ip + 1 < residual.ops.len() {
                    leaders.insert(ip + 1);
                }
            }
            ResidualOp::Return => {}
            _ => {}
        }
    }
    Ok(leaders.into_iter().collect())
}

fn block_ranges(
    leaders: &[usize],
    op_count: usize,
) -> Result<Vec<(usize, usize)>, MachineLoweringError> {
    if leaders.first() != Some(&0) || leaders.iter().any(|leader| *leader >= op_count) {
        return Err(MachineLoweringError::InvalidControlFlow(
            "invalid basic-block leader set".into(),
        ));
    }
    Ok(leaders
        .iter()
        .copied()
        .enumerate()
        .map(|(index, start)| (start, leaders.get(index + 1).copied().unwrap_or(op_count)))
        .collect())
}

fn ip_to_block(
    ranges: &[(usize, usize)],
    op_count: usize,
) -> Result<Vec<u32>, MachineLoweringError> {
    let mut result = vec![u32::MAX; op_count];
    for (block, (start, end)) in ranges.iter().copied().enumerate() {
        for slot in result
            .get_mut(start..end)
            .ok_or_else(|| MachineLoweringError::InvalidControlFlow("invalid block range".into()))?
        {
            if *slot != u32::MAX {
                return Err(MachineLoweringError::InvalidControlFlow(
                    "overlapping basic-block ranges".into(),
                ));
            }
            *slot = block as u32;
        }
    }
    if result.contains(&u32::MAX) {
        return Err(MachineLoweringError::InvalidControlFlow(
            "basic-block ranges do not cover the residual".into(),
        ));
    }
    Ok(result)
}

fn is_terminator(op: &ResidualOp) -> bool {
    matches!(
        op,
        ResidualOp::Jump(_) | ResidualOp::JumpIfFalse(_) | ResidualOp::Return
    )
}

fn pop(
    stack: &mut Vec<TypedRegister>,
    expected: MachineType,
    label: &str,
) -> Result<TypedRegister, MachineLoweringError> {
    let value = stack.pop().ok_or_else(|| {
        MachineLoweringError::InvalidType(format!("{label} underflowed the operand stack"))
    })?;
    if value.ty != expected {
        return Err(MachineLoweringError::InvalidType(format!(
            "{label} expected {}, found {}",
            expected.canonical_text(),
            value.ty.canonical_text()
        )));
    }
    Ok(value)
}

fn lower_instruction(
    op: &ResidualOp,
    stack: &mut Vec<TypedRegister>,
    state: &mut LoweringState,
) -> Result<MachineInstruction, MachineLoweringError> {
    let instruction = match *op {
        ResidualOp::ConstI64(value) => {
            let result = state.register(MachineType::I64)?;
            stack.push(result);
            MachineInstruction::ConstI64 { result, value }
        }
        ResidualOp::LoadLocal(slot) => {
            let result = state.register(state.slot(slot)?)?;
            stack.push(result);
            MachineInstruction::LoadSlot { result, slot }
        }
        ResidualOp::StoreLocal(slot) | ResidualOp::StoreLocalKeep(slot) => {
            let keep = matches!(op, ResidualOp::StoreLocalKeep(_));
            let value = stack.pop().ok_or_else(|| {
                MachineLoweringError::InvalidType("store underflowed the operand stack".into())
            })?;
            state.establish_slot(slot, value.ty)?;
            if keep {
                stack.push(value);
            }
            MachineInstruction::StoreSlot { slot, value, keep }
        }
        ResidualOp::AddLocalConst(slot, value) => {
            if state.slot(slot)? != MachineType::I64 {
                return Err(MachineLoweringError::InvalidType(format!(
                    "add-local-const targets non-i64 slot {slot}"
                )));
            }
            MachineInstruction::AddSlotConst { slot, value }
        }
        ResidualOp::Add
        | ResidualOp::Sub
        | ResidualOp::Mul
        | ResidualOp::Div
        | ResidualOp::Mod
        | ResidualOp::Xor
        | ResidualOp::Shl
        | ResidualOp::And
        | ResidualOp::Or => {
            let right = pop(stack, MachineType::I64, "integer binary")?;
            let left = pop(stack, MachineType::I64, "integer binary")?;
            let result = state.register(MachineType::I64)?;
            stack.push(result);
            let operation = match op {
                ResidualOp::Add => IntegerBinary::Add,
                ResidualOp::Sub => IntegerBinary::Sub,
                ResidualOp::Mul => IntegerBinary::Mul,
                ResidualOp::Div => IntegerBinary::Div,
                ResidualOp::Mod => IntegerBinary::Mod,
                ResidualOp::Xor => IntegerBinary::Xor,
                ResidualOp::Shl => IntegerBinary::Shl,
                ResidualOp::And => IntegerBinary::And,
                ResidualOp::Or => IntegerBinary::Or,
                _ => unreachable!(),
            };
            MachineInstruction::IntegerBinary {
                result,
                operation,
                left,
                right,
            }
        }
        ResidualOp::Eq
        | ResidualOp::Ne
        | ResidualOp::Gt
        | ResidualOp::Ge
        | ResidualOp::Lt
        | ResidualOp::Le => {
            let right = pop(stack, MachineType::I64, "integer compare")?;
            let left = pop(stack, MachineType::I64, "integer compare")?;
            let result = state.register(MachineType::Bool)?;
            stack.push(result);
            let operation = match op {
                ResidualOp::Eq => IntegerCompare::Eq,
                ResidualOp::Ne => IntegerCompare::Ne,
                ResidualOp::Gt => IntegerCompare::Gt,
                ResidualOp::Ge => IntegerCompare::Ge,
                ResidualOp::Lt => IntegerCompare::Lt,
                ResidualOp::Le => IntegerCompare::Le,
                _ => unreachable!(),
            };
            MachineInstruction::IntegerCompare {
                result,
                operation,
                left,
                right,
            }
        }
        ResidualOp::RangeAllocateInit { length } => {
            let result = state.register(MachineType::OwnedI64List)?;
            stack.push(result);
            MachineInstruction::RangeAllocateInit { result, length }
        }
        ResidualOp::ListLengthStatic {
            local: slot,
            length,
        } => {
            if state.slot(slot)? != MachineType::OwnedI64List {
                return Err(MachineLoweringError::InvalidType(format!(
                    "list length reads non-list slot {slot}"
                )));
            }
            let result = state.register(MachineType::I64)?;
            stack.push(result);
            MachineInstruction::ListLengthStatic {
                result,
                slot,
                length,
            }
        }
        ResidualOp::ListLoad => {
            let index = pop(stack, MachineType::I64, "list load index")?;
            let list = pop(stack, MachineType::OwnedI64List, "list load owner")?;
            let result = state.register(MachineType::I64)?;
            stack.push(result);
            MachineInstruction::ListLoadChecked {
                result,
                list,
                index,
            }
        }
        ResidualOp::ListStore => {
            let value = pop(stack, MachineType::I64, "list store value")?;
            let index = pop(stack, MachineType::I64, "list store index")?;
            let list = pop(stack, MachineType::OwnedI64List, "list store owner")?;
            let result = state.register(MachineType::Unit)?;
            stack.push(result);
            MachineInstruction::ListStoreChecked {
                result,
                list,
                index,
                value,
            }
        }
        ResidualOp::ReleaseList { local: slot } => {
            if state.slot(slot)? != MachineType::OwnedI64List {
                return Err(MachineLoweringError::InvalidOwnership(format!(
                    "release targets non-list slot {slot}"
                )));
            }
            MachineInstruction::ReleaseOwnedList { slot }
        }
        ResidualOp::Jump(_) | ResidualOp::JumpIfFalse(_) | ResidualOp::Return => {
            return Err(MachineLoweringError::InvalidControlFlow(
                "terminator reached instruction lowering".into(),
            ))
        }
    };
    Ok(instruction)
}

fn lower_terminator(
    op: &ResidualOp,
    ip: usize,
    stack: &mut Vec<TypedRegister>,
    ip_to_block: &[u32],
    op_count: usize,
) -> Result<MachineTerminator, MachineLoweringError> {
    let block = |target: u32| -> Result<u32, MachineLoweringError> {
        ip_to_block.get(target as usize).copied().ok_or_else(|| {
            MachineLoweringError::InvalidControlFlow(format!(
                "terminator {ip} targets out-of-range residual instruction {target}"
            ))
        })
    };
    match *op {
        ResidualOp::Jump(target) => Ok(MachineTerminator::Goto {
            target: block(target)?,
        }),
        ResidualOp::JumpIfFalse(target) => {
            let condition = pop(stack, MachineType::Bool, "conditional branch")?;
            if ip + 1 >= op_count {
                return Err(MachineLoweringError::InvalidControlFlow(
                    "conditional branch lacks a fallthrough".into(),
                ));
            }
            Ok(MachineTerminator::Branch {
                condition,
                if_true: ip_to_block[ip + 1],
                if_false: block(target)?,
            })
        }
        ResidualOp::Return => Ok(MachineTerminator::Return {
            value: pop(stack, MachineType::I64, "return")?,
        }),
        _ => Err(MachineLoweringError::InvalidControlFlow(
            "non-terminator reached terminator lowering".into(),
        )),
    }
}

fn register_result(instruction: &MachineInstruction) -> Option<TypedRegister> {
    match instruction {
        MachineInstruction::ConstI64 { result, .. }
        | MachineInstruction::LoadSlot { result, .. }
        | MachineInstruction::IntegerBinary { result, .. }
        | MachineInstruction::IntegerCompare { result, .. }
        | MachineInstruction::RangeAllocateInit { result, .. }
        | MachineInstruction::ListLengthStatic { result, .. }
        | MachineInstruction::ListLoadChecked { result, .. }
        | MachineInstruction::ListStoreChecked { result, .. } => Some(*result),
        MachineInstruction::StoreSlot { .. }
        | MachineInstruction::AddSlotConst { .. }
        | MachineInstruction::ReleaseOwnedList { .. } => None,
    }
}

fn operands(instruction: &MachineInstruction) -> Vec<TypedRegister> {
    match instruction {
        MachineInstruction::ConstI64 { .. }
        | MachineInstruction::LoadSlot { .. }
        | MachineInstruction::AddSlotConst { .. }
        | MachineInstruction::RangeAllocateInit { .. }
        | MachineInstruction::ListLengthStatic { .. }
        | MachineInstruction::ReleaseOwnedList { .. } => Vec::new(),
        MachineInstruction::StoreSlot { value, .. } => vec![*value],
        MachineInstruction::IntegerBinary { left, right, .. }
        | MachineInstruction::IntegerCompare { left, right, .. } => vec![*left, *right],
        MachineInstruction::ListLoadChecked { list, index, .. } => vec![*list, *index],
        MachineInstruction::ListStoreChecked {
            list, index, value, ..
        } => vec![*list, *index, *value],
    }
}

fn verify_instruction(
    instruction: &MachineInstruction,
    slot_types: &[MachineType],
    seen: &mut BTreeSet<u32>,
    definitions: &mut BTreeMap<u32, MachineType>,
) -> Result<(), MachineLoweringError> {
    for operand in operands(instruction) {
        if definitions.get(&operand.id) != Some(&operand.ty) {
            return Err(MachineLoweringError::InvalidType(format!(
                "register r{} is used before an equal typed definition",
                operand.id
            )));
        }
    }
    match instruction {
        MachineInstruction::LoadSlot { result, slot } => {
            if slot_types.get(*slot as usize) != Some(&result.ty) {
                return Err(MachineLoweringError::InvalidType(format!(
                    "load-slot s{slot} result type drifted"
                )));
            }
        }
        MachineInstruction::StoreSlot { slot, value, .. } => {
            if slot_types.get(*slot as usize) != Some(&value.ty) {
                return Err(MachineLoweringError::InvalidType(format!(
                    "store-slot s{slot} value type drifted"
                )));
            }
        }
        MachineInstruction::AddSlotConst { slot, .. } => {
            if slot_types.get(*slot as usize) != Some(&MachineType::I64) {
                return Err(MachineLoweringError::InvalidType(format!(
                    "add-slot-const s{slot} is not i64"
                )));
            }
        }
        MachineInstruction::ReleaseOwnedList { slot }
            if slot_types.get(*slot as usize) != Some(&MachineType::OwnedI64List) =>
        {
            return Err(MachineLoweringError::InvalidOwnership(format!(
                "release-owned-list s{slot} is not owned-list-i64"
            )));
        }
        _ => {}
    }
    if let Some(result) = register_result(instruction) {
        if !seen.insert(result.id) || definitions.insert(result.id, result.ty).is_some() {
            return Err(MachineLoweringError::InvalidType(format!(
                "register r{} is defined more than once",
                result.id
            )));
        }
    }
    Ok(())
}

fn verify_terminator(
    terminator: &MachineTerminator,
    block_count: u32,
    definitions: &BTreeMap<u32, MachineType>,
) -> Result<(), MachineLoweringError> {
    let target = |block: u32| {
        if block >= block_count {
            Err(MachineLoweringError::InvalidControlFlow(format!(
                "terminator targets missing block {block}"
            )))
        } else {
            Ok(())
        }
    };
    match terminator {
        MachineTerminator::Goto { target: block } => target(*block),
        MachineTerminator::Branch {
            condition,
            if_true,
            if_false,
        } => {
            if definitions.get(&condition.id) != Some(&MachineType::Bool)
                || condition.ty != MachineType::Bool
            {
                return Err(MachineLoweringError::InvalidType(
                    "branch condition is not a defined bool register".into(),
                ));
            }
            target(*if_true)?;
            target(*if_false)
        }
        MachineTerminator::Return { value } => {
            if definitions.get(&value.id) != Some(&MachineType::I64) || value.ty != MachineType::I64
            {
                Err(MachineLoweringError::InvalidType(
                    "return value is not a defined i64 register".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

fn verify_source_map(
    residual: &ResidualProgram,
    machine: &ResidualMachineProgram,
) -> Result<(), MachineLoweringError> {
    if machine.source_map.len() != residual.ops.len() {
        return Err(MachineLoweringError::InvalidCorrespondence(
            "source map does not cover every residual instruction".into(),
        ));
    }
    for (expected_ip, mapping) in machine.source_map.iter().enumerate() {
        if mapping.residual_ip != expected_ip as u32 {
            return Err(MachineLoweringError::InvalidCorrespondence(
                "source map is not in exact residual order".into(),
            ));
        }
        let block = machine.blocks.get(mapping.block as usize).ok_or_else(|| {
            MachineLoweringError::InvalidCorrespondence("source map names a missing block".into())
        })?;
        if !(block.residual_start..block.residual_end).contains(&mapping.residual_ip) {
            return Err(MachineLoweringError::InvalidCorrespondence(
                "source map entry escaped its block range".into(),
            ));
        }
        match mapping.kind {
            MappingKind::Instruction => {
                if mapping.machine_ordinal as usize >= block.instructions.len()
                    || is_terminator(&residual.ops[expected_ip])
                {
                    return Err(MachineLoweringError::InvalidCorrespondence(
                        "instruction mapping kind or ordinal drifted".into(),
                    ));
                }
            }
            MappingKind::Terminator => {
                if mapping.machine_ordinal as usize != block.instructions.len()
                    || !is_terminator(&residual.ops[expected_ip])
                {
                    return Err(MachineLoweringError::InvalidCorrespondence(
                        "terminator mapping kind or ordinal drifted".into(),
                    ));
                }
            }
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

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u32(bytes, value.len() as u32);
    bytes.extend_from_slice(value.as_bytes());
}

fn hash_domain(domain: &[u8], payload: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(domain.len() + payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(payload);
    SemanticHash(sha256(&bytes))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::residual::lower_whole_program;
    use naux::vm::compiler::compile_script;
    use naux::{lexer, parser, typecheck};

    const SOURCES: [&str; 4] = [
        include_str!("../../../benchmarks/s4/naux/sum_dense.nx"),
        include_str!("../../../benchmarks/s4/naux/branch_mix.nx"),
        include_str!("../../../benchmarks/s4/naux/dot_product.nx"),
        include_str!("../../../benchmarks/s4/naux/list_update.nx"),
    ];

    fn residual(source: &str) -> ResidualProgram {
        let tokens = lexer::lex(source).expect("source should lex");
        let statements = parser::parse_script(&tokens).expect("source should parse");
        typecheck::check_program(&statements).expect("source should typecheck");
        lower_whole_program(&compile_script(&statements), 16_384, 50)
            .expect("source should residualize")
    }

    #[test]
    fn all_frozen_residuals_lower_through_one_typed_machine_path() {
        let mut hashes = Vec::new();
        for source in SOURCES {
            let residual = residual(source);
            let (machine, correspondence) =
                lower_residual_machine_ir(&residual).expect("machine lowering should succeed");
            assert_eq!(correspondence.mapping_count, residual.ops.len() as u32);
            assert_eq!(correspondence.traversal_count, 819_200);
            assert_eq!(correspondence.list_loads, 1);
            assert_eq!(
                machine.slot_types[residual.list_local as usize],
                MachineType::OwnedI64List
            );
            hashes.push(machine.semantic_hash());
        }
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 4);
    }

    #[test]
    fn lowering_is_deterministic() {
        let residual = residual(SOURCES[0]);
        let first = lower_residual_machine_ir(&residual).expect("first lowering");
        let second = lower_residual_machine_ir(&residual).expect("second lowering");
        assert_eq!(first, second);
    }

    #[test]
    fn non_boolean_branch_fails_closed() {
        let mut residual = residual(SOURCES[0]);
        residual.ops[12] = ResidualOp::Add;
        assert!(matches!(
            lower_residual_machine_ir(&residual),
            Err(MachineLoweringError::InvalidType(_)) | Err(MachineLoweringError::Residual(_))
        ));
    }

    #[test]
    fn cross_block_stack_value_fails_closed() {
        let mut residual = residual(SOURCES[0]);
        residual.ops[44] = ResidualOp::ConstI64(1);
        assert!(lower_residual_machine_ir(&residual).is_err());
    }

    #[test]
    fn correspondence_mutation_is_rejected() {
        let residual = residual(SOURCES[3]);
        let (mut machine, _) =
            lower_residual_machine_ir(&residual).expect("machine lowering should succeed");
        machine.source_map[0].block = 1;
        let work = verify_work(&residual).expect("work witness should replay");
        assert!(matches!(
            verify_machine_ir(&residual, &work, &machine),
            Err(MachineLoweringError::InvalidCorrespondence(_))
        ));
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            SemanticHash(sha256(b"abc")).to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
