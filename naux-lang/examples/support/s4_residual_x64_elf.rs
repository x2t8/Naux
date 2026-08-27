//! Closed x86-64/ELF64 lowering boundary for S4-WP5D.
//!
//! This module deliberately stops before process execution.  It lowers the
//! admitted WP5C Machine IR through one stack-home target plan, emits a
//! callable System V x86-64 function, wraps that function in a deterministic
//! linker-free Linux ELF64 image, and independently parses the resulting
//! bytes.  Fresh-process execution and benchmark-role admission belong to a
//! later gate.

use crate::machine::{
    IntegerBinary, IntegerCompare, MachineInstruction, MachineTerminator, MachineType,
    ResidualMachineProgram, TypedRegister,
};
use std::collections::BTreeSet;
use std::fmt;

const ELF_BASE: u64 = 0x0040_0000;
const ELF_ENTRY_OFFSET: usize = 0x100;
const ELF_ENTRY: u64 = ELF_BASE + ELF_ENTRY_OFFSET as u64;
const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const PROGRAM_HEADER_COUNT: usize = 2;
const PROGRAM_HEADERS_END: usize = ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES * PROGRAM_HEADER_COUNT;
const TARGET_ALIGNMENT: usize = 16;
const STARTUP: [u8; 16] = [
    0xe8, 0, 0, 0, 0, // call target; displacement is patched per image
    0x31, 0xff, // xor edi, edi
    0xb8, 0x3c, 0, 0, 0, // mov eax, SYS_exit
    0x0f, 0x05, // syscall
    0x0f, 0x0b, // ud2
];
const MAX_FRAME_BYTES: u32 = 1_048_576;
const MAX_TARGET_BYTES: usize = 1_048_576;
const MAX_ELF_BYTES: usize = 1_114_112;
const SYS_MMAP: i64 = 9;
const SYS_MUNMAP: i64 = 11;
const SYS_EXIT: i64 = 60;
const FAILURE_EXIT_CODE: u32 = 70;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeKind {
    Slot,
    Register,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackHome {
    pub kind: HomeKind,
    pub index: u32,
    pub ty: MachineType,
    pub displacement: i32,
}

impl StackHome {
    fn canonical_text(self) -> String {
        let prefix = match self.kind {
            HomeKind::Slot => 's',
            HomeKind::Register => 'r',
        };
        format!(
            "{prefix}{}:{}@{}",
            self.index,
            self.ty.canonical_text(),
            self.displacement
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64Operation {
    ConstI64 {
        result: StackHome,
        value: i64,
    },
    Copy {
        result: StackHome,
        source: StackHome,
    },
    StoreSlot {
        slot: StackHome,
        value: StackHome,
    },
    AddSlotConst {
        slot: StackHome,
        value: i64,
    },
    IntegerBinary {
        result: StackHome,
        operation: IntegerBinary,
        left: StackHome,
        right: StackHome,
    },
    IntegerCompare {
        result: StackHome,
        operation: IntegerCompare,
        left: StackHome,
        right: StackHome,
    },
    RangeAllocateInit {
        result: StackHome,
        length: u64,
    },
    ListLengthStatic {
        result: StackHome,
        length: u64,
    },
    ListLoadChecked {
        result: StackHome,
        list: StackHome,
        index: StackHome,
        length: u64,
    },
    ListStoreChecked {
        result: StackHome,
        list: StackHome,
        index: StackHome,
        value: StackHome,
        length: u64,
    },
    ReleaseOwnedList {
        slot: StackHome,
        length: u64,
    },
}

impl X64Operation {
    pub fn canonical_text(&self) -> String {
        match self {
            Self::ConstI64 { result, value } => {
                format!("const-i64\t{}\t{value}", result.canonical_text())
            }
            Self::Copy { result, source } => format!(
                "copy\t{}\t{}",
                result.canonical_text(),
                source.canonical_text()
            ),
            Self::StoreSlot { slot, value } => format!(
                "store-slot\t{}\t{}",
                slot.canonical_text(),
                value.canonical_text()
            ),
            Self::AddSlotConst { slot, value } => {
                format!("add-slot-const\t{}\t{value}", slot.canonical_text())
            }
            Self::IntegerBinary {
                result,
                operation,
                left,
                right,
            } => format!(
                "i64-{operation:?}\t{}\t{}\t{}",
                result.canonical_text(),
                left.canonical_text(),
                right.canonical_text()
            )
            .to_ascii_lowercase(),
            Self::IntegerCompare {
                result,
                operation,
                left,
                right,
            } => format!(
                "i64-{operation:?}\t{}\t{}\t{}",
                result.canonical_text(),
                left.canonical_text(),
                right.canonical_text()
            )
            .to_ascii_lowercase(),
            Self::RangeAllocateInit { result, length } => {
                format!("range-allocate-init\t{}\t{length}", result.canonical_text())
            }
            Self::ListLengthStatic { result, length } => {
                format!("list-length-static\t{}\t{length}", result.canonical_text())
            }
            Self::ListLoadChecked {
                result,
                list,
                index,
                length,
            } => format!(
                "list-load-checked\t{}\t{}\t{}\t{length}",
                result.canonical_text(),
                list.canonical_text(),
                index.canonical_text()
            ),
            Self::ListStoreChecked {
                result,
                list,
                index,
                value,
                length,
            } => format!(
                "list-store-checked\t{}\t{}\t{}\t{}\t{length}",
                result.canonical_text(),
                list.canonical_text(),
                index.canonical_text(),
                value.canonical_text()
            ),
            Self::ReleaseOwnedList { slot, length } => {
                format!("release-owned-list\t{}\t{length}", slot.canonical_text())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64Terminator {
    Goto {
        target: u32,
    },
    Branch {
        condition: StackHome,
        if_true: u32,
        if_false: u32,
    },
    Return {
        value: StackHome,
    },
}

impl X64Terminator {
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
pub struct X64Block {
    pub id: u32,
    pub operations: Vec<X64Operation>,
    pub terminator: X64Terminator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64Plan {
    pub source_machine_hash: naux::core::SemanticHash,
    pub frame_bytes: u32,
    pub list_length: u64,
    pub slot_homes: Vec<StackHome>,
    pub register_homes: Vec<StackHome>,
    pub blocks: Vec<X64Block>,
}

impl X64Plan {
    pub fn operation_count(&self) -> u32 {
        self.blocks
            .iter()
            .map(|block| block.operations.len() as u32)
            .sum()
    }

    pub fn terminator_count(&self) -> u32 {
        self.blocks.len() as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingKind {
    Operation,
    Terminator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodingRange {
    pub block: u32,
    pub ordinal: u32,
    pub kind: EncodingKind,
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedX64 {
    pub bytes: Vec<u8>,
    pub block_offsets: Vec<u32>,
    pub error_offset: u32,
    pub ranges: Vec<EncodingRange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Elf64Image {
    pub bytes: Vec<u8>,
    pub target_offset: u32,
    pub target_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedElf64Facts {
    pub entry: u64,
    pub image_bytes: u64,
    pub target_offset: u64,
    pub target_bytes: u64,
    pub load_flags: u32,
    pub stack_flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64ElfError {
    Unsupported(String),
    InvalidPlan(String),
    Encoding(String),
    InvalidElf(String),
}

impl fmt::Display for X64ElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (label, message) = match self {
            Self::Unsupported(message) => ("unsupported", message),
            Self::InvalidPlan(message) => ("target plan", message),
            Self::Encoding(message) => ("x86-64 encoding", message),
            Self::InvalidElf(message) => ("ELF64", message),
        };
        write!(formatter, "S4-WP5D {label} error: {message}")
    }
}

impl std::error::Error for X64ElfError {}

/// Lower the admitted WP5C program through one generic stack-home plan.
pub fn lower_x64_plan(machine: &ResidualMachineProgram) -> Result<X64Plan, X64ElfError> {
    if machine.entry_block != 0 || machine.blocks.is_empty() {
        return Err(X64ElfError::InvalidPlan(
            "entry block is not canonical block zero".into(),
        ));
    }
    let list_lengths = machine
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter_map(|instruction| match instruction {
            MachineInstruction::RangeAllocateInit { length, .. } => Some(*length),
            _ => None,
        })
        .collect::<Vec<_>>();
    if list_lengths.len() != 1 || list_lengths[0] == 0 {
        return Err(X64ElfError::InvalidPlan(
            "exactly one non-empty list allocation is required".into(),
        ));
    }
    let list_length = list_lengths[0];
    list_length
        .checked_mul(8)
        .ok_or_else(|| X64ElfError::InvalidPlan("list byte length overflowed".into()))?;

    let home_count = machine
        .slot_types
        .len()
        .checked_add(machine.register_count as usize)
        .ok_or_else(|| X64ElfError::InvalidPlan("home count overflowed".into()))?;
    let raw_frame = home_count
        .checked_mul(8)
        .ok_or_else(|| X64ElfError::InvalidPlan("frame byte count overflowed".into()))?;
    let frame_bytes = align_up(raw_frame.max(16), 16)?;
    let frame_bytes = u32::try_from(frame_bytes)
        .map_err(|_| X64ElfError::InvalidPlan("frame exceeds u32".into()))?;
    if frame_bytes > MAX_FRAME_BYTES {
        return Err(X64ElfError::InvalidPlan(format!(
            "frame uses {frame_bytes} bytes; limit is {MAX_FRAME_BYTES}"
        )));
    }

    let mut slot_homes = Vec::with_capacity(machine.slot_types.len());
    for (index, ty) in machine.slot_types.iter().copied().enumerate() {
        slot_homes.push(home(HomeKind::Slot, index as u32, ty, index)?);
    }
    let mut register_types = vec![None; machine.register_count as usize];
    for block in &machine.blocks {
        for instruction in &block.instructions {
            if let Some(register) = instruction_result(instruction) {
                let target = register_types
                    .get_mut(register.id as usize)
                    .ok_or_else(|| X64ElfError::InvalidPlan("register id exceeds frame".into()))?;
                if target.replace(register.ty).is_some() {
                    return Err(X64ElfError::InvalidPlan(format!(
                        "register r{} is defined more than once",
                        register.id
                    )));
                }
            }
        }
    }
    let mut register_homes = Vec::with_capacity(register_types.len());
    for (index, ty) in register_types.into_iter().enumerate() {
        let ty = ty.ok_or_else(|| {
            X64ElfError::InvalidPlan(format!("register r{index} lacks a definition"))
        })?;
        register_homes.push(home(
            HomeKind::Register,
            index as u32,
            ty,
            machine.slot_types.len() + index,
        )?);
    }

    let slot = |index: u32| -> Result<StackHome, X64ElfError> {
        slot_homes
            .get(index as usize)
            .copied()
            .ok_or_else(|| X64ElfError::InvalidPlan(format!("missing slot s{index}")))
    };
    let register = |value: TypedRegister| -> Result<StackHome, X64ElfError> {
        let result = register_homes
            .get(value.id as usize)
            .copied()
            .ok_or_else(|| X64ElfError::InvalidPlan(format!("missing register r{}", value.id)))?;
        if result.ty != value.ty {
            return Err(X64ElfError::InvalidPlan(format!(
                "register r{} type drifted",
                value.id
            )));
        }
        Ok(result)
    };

    let mut blocks = Vec::with_capacity(machine.blocks.len());
    for (expected, block) in machine.blocks.iter().enumerate() {
        if block.id != expected as u32 {
            return Err(X64ElfError::InvalidPlan(
                "machine blocks are not canonical contiguous ids".into(),
            ));
        }
        let mut operations = Vec::with_capacity(block.instructions.len());
        for instruction in &block.instructions {
            operations.push(match instruction {
                MachineInstruction::ConstI64 { result, value } => X64Operation::ConstI64 {
                    result: register(*result)?,
                    value: *value,
                },
                MachineInstruction::LoadSlot {
                    result,
                    slot: source,
                } => X64Operation::Copy {
                    result: register(*result)?,
                    source: slot(*source)?,
                },
                MachineInstruction::StoreSlot {
                    slot: target,
                    value,
                    ..
                } => X64Operation::StoreSlot {
                    slot: slot(*target)?,
                    value: register(*value)?,
                },
                MachineInstruction::AddSlotConst {
                    slot: target,
                    value,
                } => X64Operation::AddSlotConst {
                    slot: slot(*target)?,
                    value: *value,
                },
                MachineInstruction::IntegerBinary {
                    result,
                    operation,
                    left,
                    right,
                } => {
                    if !matches!(
                        operation,
                        IntegerBinary::Add | IntegerBinary::Sub | IntegerBinary::Mul
                    ) {
                        return Err(X64ElfError::Unsupported(format!(
                            "integer operation {operation:?} is outside WP5D-v1"
                        )));
                    }
                    X64Operation::IntegerBinary {
                        result: register(*result)?,
                        operation: *operation,
                        left: register(*left)?,
                        right: register(*right)?,
                    }
                }
                MachineInstruction::IntegerCompare {
                    result,
                    operation,
                    left,
                    right,
                } => X64Operation::IntegerCompare {
                    result: register(*result)?,
                    operation: *operation,
                    left: register(*left)?,
                    right: register(*right)?,
                },
                MachineInstruction::RangeAllocateInit { result, length } => {
                    if *length != list_length {
                        return Err(X64ElfError::InvalidPlan(
                            "multiple list lengths entered one plan".into(),
                        ));
                    }
                    X64Operation::RangeAllocateInit {
                        result: register(*result)?,
                        length: *length,
                    }
                }
                MachineInstruction::ListLengthStatic { result, length, .. } => {
                    if *length != list_length {
                        return Err(X64ElfError::InvalidPlan(
                            "list length observation drifted".into(),
                        ));
                    }
                    X64Operation::ListLengthStatic {
                        result: register(*result)?,
                        length: *length,
                    }
                }
                MachineInstruction::ListLoadChecked {
                    result,
                    list,
                    index,
                } => X64Operation::ListLoadChecked {
                    result: register(*result)?,
                    list: register(*list)?,
                    index: register(*index)?,
                    length: list_length,
                },
                MachineInstruction::ListStoreChecked {
                    result,
                    list,
                    index,
                    value,
                } => X64Operation::ListStoreChecked {
                    result: register(*result)?,
                    list: register(*list)?,
                    index: register(*index)?,
                    value: register(*value)?,
                    length: list_length,
                },
                MachineInstruction::ReleaseOwnedList { slot: owner } => {
                    X64Operation::ReleaseOwnedList {
                        slot: slot(*owner)?,
                        length: list_length,
                    }
                }
            });
        }
        let terminator = match &block.terminator {
            MachineTerminator::Goto { target } => X64Terminator::Goto { target: *target },
            MachineTerminator::Branch {
                condition,
                if_true,
                if_false,
            } => X64Terminator::Branch {
                condition: register(*condition)?,
                if_true: *if_true,
                if_false: *if_false,
            },
            MachineTerminator::Return { value } => X64Terminator::Return {
                value: register(*value)?,
            },
        };
        blocks.push(X64Block {
            id: block.id,
            operations,
            terminator,
        });
    }
    let plan = X64Plan {
        source_machine_hash: machine.semantic_hash(),
        frame_bytes,
        list_length,
        slot_homes,
        register_homes,
        blocks,
    };
    verify_plan(&plan)?;
    Ok(plan)
}

pub fn verify_plan(plan: &X64Plan) -> Result<(), X64ElfError> {
    if plan.blocks.is_empty() || plan.blocks[0].id != 0 {
        return Err(X64ElfError::InvalidPlan(
            "missing canonical entry block".into(),
        ));
    }
    if plan.frame_bytes == 0
        || !plan.frame_bytes.is_multiple_of(16)
        || plan.frame_bytes > MAX_FRAME_BYTES
    {
        return Err(X64ElfError::InvalidPlan(
            "frame is not a bounded 16-byte-aligned allocation".into(),
        ));
    }
    if plan.list_length == 0 || plan.list_length.checked_mul(8).is_none() {
        return Err(X64ElfError::InvalidPlan(
            "invalid frozen list length".into(),
        ));
    }
    let mut displacements = BTreeSet::new();
    for (ordinal, home) in plan
        .slot_homes
        .iter()
        .chain(&plan.register_homes)
        .enumerate()
    {
        let expected_kind = if ordinal < plan.slot_homes.len() {
            HomeKind::Slot
        } else {
            HomeKind::Register
        };
        let expected_index = if expected_kind == HomeKind::Slot {
            ordinal
        } else {
            ordinal - plan.slot_homes.len()
        };
        let expected_bytes = ordinal
            .checked_add(1)
            .and_then(|value| value.checked_mul(8))
            .ok_or_else(|| X64ElfError::InvalidPlan("stack-home ordinal overflowed".into()))?;
        let expected_displacement = i32::try_from(expected_bytes)
            .map_err(|_| X64ElfError::InvalidPlan("stack-home ordinal overflowed".into()))?
            .checked_neg()
            .ok_or_else(|| X64ElfError::InvalidPlan("stack-home displacement overflowed".into()))?;
        if home.kind != expected_kind
            || home.index as usize != expected_index
            || home.displacement != expected_displacement
            || home.displacement % 8 != 0
            || home.displacement > -8
            || (-i64::from(home.displacement)) > i64::from(plan.frame_bytes)
            || !displacements.insert(home.displacement)
        {
            return Err(X64ElfError::InvalidPlan(
                "stack homes are not canonical aligned non-overlapping frame entries".into(),
            ));
        }
    }
    let admitted_home = |home: StackHome| {
        let admitted = match home.kind {
            HomeKind::Slot => plan.slot_homes.get(home.index as usize),
            HomeKind::Register => plan.register_homes.get(home.index as usize),
        };
        if admitted == Some(&home) {
            Ok(())
        } else {
            Err(X64ElfError::InvalidPlan(format!(
                "operation references undeclared home {}",
                home.canonical_text()
            )))
        }
    };
    let require = |condition: bool, message: &str| {
        if condition {
            Ok(())
        } else {
            Err(X64ElfError::InvalidPlan(message.into()))
        }
    };
    let block_count = plan.blocks.len() as u32;
    let target = |block: u32| {
        if block < block_count {
            Ok(())
        } else {
            Err(X64ElfError::InvalidPlan(format!(
                "terminator targets absent block b{block}"
            )))
        }
    };
    for (expected, block) in plan.blocks.iter().enumerate() {
        if block.id != expected as u32 {
            return Err(X64ElfError::InvalidPlan(
                "block ids are not contiguous".into(),
            ));
        }
        for operation in &block.operations {
            match *operation {
                X64Operation::ConstI64 { result, .. } => {
                    admitted_home(result)?;
                    require(
                        result.kind == HomeKind::Register && result.ty == MachineType::I64,
                        "const result is not a declared i64 register",
                    )?;
                }
                X64Operation::Copy { result, source } => {
                    admitted_home(result)?;
                    admitted_home(source)?;
                    require(
                        result.kind == HomeKind::Register && result.ty == source.ty,
                        "copy homes have an invalid role or type",
                    )?;
                }
                X64Operation::StoreSlot { slot, value } => {
                    admitted_home(slot)?;
                    admitted_home(value)?;
                    require(
                        slot.kind == HomeKind::Slot
                            && value.kind == HomeKind::Register
                            && slot.ty == value.ty,
                        "slot store homes have an invalid role or type",
                    )?;
                }
                X64Operation::AddSlotConst { slot, .. } => {
                    admitted_home(slot)?;
                    require(
                        slot.kind == HomeKind::Slot && slot.ty == MachineType::I64,
                        "slot increment does not target an i64 slot",
                    )?;
                }
                X64Operation::IntegerBinary {
                    result,
                    left,
                    right,
                    ..
                } => {
                    for home in [result, left, right] {
                        admitted_home(home)?;
                    }
                    require(
                        result.kind == HomeKind::Register
                            && [result, left, right]
                                .iter()
                                .all(|home| home.ty == MachineType::I64),
                        "integer binary homes have an invalid role or type",
                    )?;
                }
                X64Operation::IntegerCompare {
                    result,
                    left,
                    right,
                    ..
                } => {
                    for home in [result, left, right] {
                        admitted_home(home)?;
                    }
                    require(
                        result.kind == HomeKind::Register
                            && result.ty == MachineType::Bool
                            && left.ty == MachineType::I64
                            && right.ty == MachineType::I64,
                        "integer comparison homes have an invalid role or type",
                    )?;
                }
                X64Operation::RangeAllocateInit { result, length } => {
                    admitted_home(result)?;
                    require(
                        result.kind == HomeKind::Register
                            && result.ty == MachineType::OwnedI64List
                            && length == plan.list_length,
                        "range allocation has an invalid result or length",
                    )?;
                }
                X64Operation::ListLengthStatic { result, length } => {
                    admitted_home(result)?;
                    require(
                        result.kind == HomeKind::Register
                            && result.ty == MachineType::I64
                            && length == plan.list_length,
                        "list length operation has an invalid result or length",
                    )?;
                }
                X64Operation::ListLoadChecked {
                    result,
                    list,
                    index,
                    length,
                } => {
                    for home in [result, list, index] {
                        admitted_home(home)?;
                    }
                    require(
                        [result, list, index]
                            .iter()
                            .all(|home| home.kind == HomeKind::Register)
                            && result.ty == MachineType::I64
                            && list.ty == MachineType::OwnedI64List
                            && index.ty == MachineType::I64
                            && length == plan.list_length,
                        "checked list load has an invalid home, type, or length",
                    )?;
                }
                X64Operation::ListStoreChecked {
                    result,
                    list,
                    index,
                    value,
                    length,
                } => {
                    for home in [result, list, index, value] {
                        admitted_home(home)?;
                    }
                    require(
                        [result, list, index, value]
                            .iter()
                            .all(|home| home.kind == HomeKind::Register)
                            && result.ty == MachineType::Unit
                            && list.ty == MachineType::OwnedI64List
                            && index.ty == MachineType::I64
                            && value.ty == MachineType::I64
                            && length == plan.list_length,
                        "checked list store has an invalid home, type, or length",
                    )?;
                }
                X64Operation::ReleaseOwnedList { slot, length } => {
                    admitted_home(slot)?;
                    require(
                        slot.kind == HomeKind::Slot
                            && slot.ty == MachineType::OwnedI64List
                            && length == plan.list_length,
                        "list release has an invalid owner or length",
                    )?;
                }
            }
        }
        match block.terminator {
            X64Terminator::Goto {
                target: destination,
            } => target(destination)?,
            X64Terminator::Branch {
                condition,
                if_true,
                if_false,
            } => {
                admitted_home(condition)?;
                if condition.ty != MachineType::Bool {
                    return Err(X64ElfError::InvalidPlan(
                        "branch condition is not bool".into(),
                    ));
                }
                target(if_true)?;
                target(if_false)?;
            }
            X64Terminator::Return { value } => {
                admitted_home(value)?;
                require(
                    value.kind == HomeKind::Register && value.ty == MachineType::I64,
                    "return value is not a declared i64 register",
                )?;
            }
        }
    }
    Ok(())
}

/// Encode one verified target plan.  The result is a callable SysV function;
/// its only Linux dependencies are direct mmap/munmap/exit syscalls.
pub fn encode_x64(plan: &X64Plan) -> Result<EncodedX64, X64ElfError> {
    verify_plan(plan)?;
    let mut emitter = Emitter::default();
    emitter
        .bytes
        .extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec]);
    emitter
        .bytes
        .extend_from_slice(&plan.frame_bytes.to_le_bytes());
    let mut block_offsets = Vec::with_capacity(plan.blocks.len());
    let mut ranges =
        Vec::with_capacity(plan.operation_count() as usize + plan.terminator_count() as usize);
    for block in &plan.blocks {
        block_offsets.push(as_u32(emitter.bytes.len(), "block offset")?);
        for (ordinal, operation) in block.operations.iter().enumerate() {
            let start = as_u32(emitter.bytes.len(), "operation start")?;
            emit_operation(&mut emitter, operation)?;
            let end = as_u32(emitter.bytes.len(), "operation end")?;
            ranges.push(EncodingRange {
                block: block.id,
                ordinal: ordinal as u32,
                kind: EncodingKind::Operation,
                start,
                end,
            });
        }
        let start = as_u32(emitter.bytes.len(), "terminator start")?;
        emit_terminator(&mut emitter, &block.terminator)?;
        let end = as_u32(emitter.bytes.len(), "terminator end")?;
        ranges.push(EncodingRange {
            block: block.id,
            ordinal: block.operations.len() as u32,
            kind: EncodingKind::Terminator,
            start,
            end,
        });
    }
    let error_offset = as_u32(emitter.bytes.len(), "error offset")?;
    emitter.bytes.push(0xbf);
    emitter
        .bytes
        .extend_from_slice(&FAILURE_EXIT_CODE.to_le_bytes());
    emitter.bytes.push(0xb8);
    emitter
        .bytes
        .extend_from_slice(&(SYS_EXIT as u32).to_le_bytes());
    emitter.bytes.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    for fixup in &emitter.fixups {
        let target = match fixup.target {
            FixupTarget::Block(block) => *block_offsets.get(block as usize).ok_or_else(|| {
                X64ElfError::Encoding(format!("fixup targets missing block b{block}"))
            })?,
            FixupTarget::Error => error_offset,
        };
        patch_rel32(&mut emitter.bytes, fixup.displacement, target)?;
    }
    if emitter.bytes.len() > MAX_TARGET_BYTES {
        return Err(X64ElfError::Encoding(format!(
            "target uses {} bytes; limit is {MAX_TARGET_BYTES}",
            emitter.bytes.len()
        )));
    }
    let encoded = EncodedX64 {
        bytes: emitter.bytes,
        block_offsets,
        error_offset,
        ranges,
    };
    verify_x64_encoding(plan, &encoded)?;
    Ok(encoded)
}

/// Parse the encoding envelope and independently reconstruct it from the
/// target plan.  This gate intentionally requires exact canonical bytes.
pub fn verify_x64_encoding(plan: &X64Plan, encoded: &EncodedX64) -> Result<(), X64ElfError> {
    verify_plan(plan)?;
    if encoded.bytes.len() > MAX_TARGET_BYTES
        || encoded.block_offsets.len() != plan.blocks.len()
        || encoded.ranges.len()
            != plan.operation_count() as usize + plan.terminator_count() as usize
    {
        return Err(X64ElfError::Encoding(
            "encoding receipt cardinality or byte limit drifted".into(),
        ));
    }
    if encoded.bytes.get(..7) != Some(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec])
        || read_u32(&encoded.bytes, 7, "frame immediate")? != plan.frame_bytes
    {
        return Err(X64ElfError::Encoding("canonical prologue drifted".into()));
    }
    let independently_encoded = encode_without_verification(plan)?;
    if independently_encoded.bytes != encoded.bytes
        || independently_encoded.block_offsets != encoded.block_offsets
        || independently_encoded.error_offset != encoded.error_offset
        || independently_encoded.ranges != encoded.ranges
    {
        return Err(X64ElfError::Encoding(
            "independent canonical reconstruction differs".into(),
        ));
    }
    if encoded
        .ranges
        .windows(2)
        .any(|pair| pair[0].end != pair[1].start)
        || encoded.ranges.first().map(|range| range.start) != Some(11)
        || encoded.ranges.last().map(|range| range.end) != Some(encoded.error_offset)
    {
        return Err(X64ElfError::Encoding(
            "encoding ranges do not partition the target body".into(),
        ));
    }
    Ok(())
}

fn encode_without_verification(plan: &X64Plan) -> Result<EncodedX64, X64ElfError> {
    let mut emitter = Emitter::default();
    emitter
        .bytes
        .extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec]);
    emitter
        .bytes
        .extend_from_slice(&plan.frame_bytes.to_le_bytes());
    let mut block_offsets = Vec::with_capacity(plan.blocks.len());
    let mut ranges = Vec::new();
    for block in &plan.blocks {
        block_offsets.push(as_u32(emitter.bytes.len(), "block offset")?);
        for (ordinal, operation) in block.operations.iter().enumerate() {
            let start = as_u32(emitter.bytes.len(), "operation start")?;
            emit_operation(&mut emitter, operation)?;
            ranges.push(EncodingRange {
                block: block.id,
                ordinal: ordinal as u32,
                kind: EncodingKind::Operation,
                start,
                end: as_u32(emitter.bytes.len(), "operation end")?,
            });
        }
        let start = as_u32(emitter.bytes.len(), "terminator start")?;
        emit_terminator(&mut emitter, &block.terminator)?;
        ranges.push(EncodingRange {
            block: block.id,
            ordinal: block.operations.len() as u32,
            kind: EncodingKind::Terminator,
            start,
            end: as_u32(emitter.bytes.len(), "terminator end")?,
        });
    }
    let error_offset = as_u32(emitter.bytes.len(), "error offset")?;
    emitter.bytes.push(0xbf);
    emitter
        .bytes
        .extend_from_slice(&FAILURE_EXIT_CODE.to_le_bytes());
    emitter.bytes.push(0xb8);
    emitter
        .bytes
        .extend_from_slice(&(SYS_EXIT as u32).to_le_bytes());
    emitter.bytes.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    for fixup in &emitter.fixups {
        let target = match fixup.target {
            FixupTarget::Block(block) => *block_offsets.get(block as usize).ok_or_else(|| {
                X64ElfError::Encoding(format!("fixup targets missing block b{block}"))
            })?,
            FixupTarget::Error => error_offset,
        };
        patch_rel32(&mut emitter.bytes, fixup.displacement, target)?;
    }
    Ok(EncodedX64 {
        bytes: emitter.bytes,
        block_offsets,
        error_offset,
        ranges,
    })
}

pub fn build_elf64(encoded: &EncodedX64) -> Result<Elf64Image, X64ElfError> {
    if encoded.bytes.is_empty() || encoded.bytes.len() > MAX_TARGET_BYTES {
        return Err(X64ElfError::InvalidElf(
            "target is empty or exceeds its byte limit".into(),
        ));
    }
    let startup_end = ELF_ENTRY_OFFSET
        .checked_add(STARTUP.len())
        .ok_or_else(|| X64ElfError::InvalidElf("startup end overflowed".into()))?;
    let target_offset = align_up(startup_end, TARGET_ALIGNMENT)?;
    let image_bytes = target_offset
        .checked_add(encoded.bytes.len())
        .ok_or_else(|| X64ElfError::InvalidElf("image length overflowed".into()))?;
    if image_bytes > MAX_ELF_BYTES {
        return Err(X64ElfError::InvalidElf(format!(
            "image uses {image_bytes} bytes; limit is {MAX_ELF_BYTES}"
        )));
    }
    let mut bytes = Vec::with_capacity(image_bytes);
    write_elf_header(&mut bytes, image_bytes as u64);
    if bytes.len() != PROGRAM_HEADERS_END {
        return Err(X64ElfError::InvalidElf(
            "writer did not finish at program-header boundary".into(),
        ));
    }
    bytes.resize(ELF_ENTRY_OFFSET, 0);
    let mut startup = STARTUP;
    let displacement = relative_displacement(ELF_ENTRY_OFFSET + 1, target_offset)?;
    startup[1..5].copy_from_slice(&displacement.to_le_bytes());
    bytes.extend_from_slice(&startup);
    bytes.resize(target_offset, 0);
    bytes.extend_from_slice(&encoded.bytes);
    let image = Elf64Image {
        bytes,
        target_offset: as_u32(target_offset, "ELF target offset")?,
        target_bytes: as_u32(encoded.bytes.len(), "ELF target bytes")?,
    };
    verify_elf64(&image, encoded)?;
    Ok(image)
}

pub fn verify_elf64(
    image: &Elf64Image,
    encoded: &EncodedX64,
) -> Result<VerifiedElf64Facts, X64ElfError> {
    if encoded.bytes.is_empty() || encoded.bytes.len() > MAX_TARGET_BYTES {
        return Err(X64ElfError::InvalidElf(
            "target is empty or exceeds its byte limit".into(),
        ));
    }
    let bytes = &image.bytes;
    if bytes.len() > MAX_ELF_BYTES || bytes.len() < ELF_ENTRY_OFFSET + STARTUP.len() {
        return Err(X64ElfError::InvalidElf(
            "image length is outside bounds".into(),
        ));
    }
    expect(bytes, 0, b"\x7fELF", "magic")?;
    expect(bytes, 4, &[2, 1, 1, 0, 0], "identity")?;
    zeroes(bytes, 9, 16, "identity padding")?;
    expect_u16(bytes, 16, 2, "type")?;
    expect_u16(bytes, 18, 62, "machine")?;
    expect_u32(bytes, 20, 1, "version")?;
    expect_u64(bytes, 24, ELF_ENTRY, "entry")?;
    expect_u64(bytes, 32, ELF_HEADER_BYTES as u64, "program-header offset")?;
    expect_u64(bytes, 40, 0, "section-header offset")?;
    expect_u32(bytes, 48, 0, "flags")?;
    expect_u16(bytes, 52, ELF_HEADER_BYTES as u16, "header size")?;
    expect_u16(
        bytes,
        54,
        PROGRAM_HEADER_BYTES as u16,
        "program-header size",
    )?;
    expect_u16(
        bytes,
        56,
        PROGRAM_HEADER_COUNT as u16,
        "program-header count",
    )?;
    expect_u16(bytes, 58, 0, "section-header size")?;
    expect_u16(bytes, 60, 0, "section-header count")?;
    expect_u16(bytes, 62, 0, "section-name index")?;

    let load = ELF_HEADER_BYTES;
    expect_u32(bytes, load, 1, "load type")?;
    expect_u32(bytes, load + 4, 5, "load flags")?;
    expect_u64(bytes, load + 8, 0, "load offset")?;
    expect_u64(bytes, load + 16, ELF_BASE, "load virtual address")?;
    expect_u64(bytes, load + 24, ELF_BASE, "load physical address")?;
    expect_u64(bytes, load + 32, bytes.len() as u64, "load file size")?;
    expect_u64(bytes, load + 40, bytes.len() as u64, "load memory size")?;
    expect_u64(bytes, load + 48, 4096, "load alignment")?;
    let stack = ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES;
    expect_u32(bytes, stack, 0x6474_e551, "stack type")?;
    expect_u32(bytes, stack + 4, 6, "stack flags")?;
    for offset in [8, 16, 24, 32, 40] {
        expect_u64(bytes, stack + offset, 0, "stack zero field")?;
    }
    expect_u64(bytes, stack + 48, 16, "stack alignment")?;
    zeroes(
        bytes,
        PROGRAM_HEADERS_END,
        ELF_ENTRY_OFFSET,
        "header padding",
    )?;

    let target_offset = image.target_offset as usize;
    if !target_offset.is_multiple_of(TARGET_ALIGNMENT)
        || image.target_bytes as usize != encoded.bytes.len()
        || target_offset.checked_add(encoded.bytes.len()) != Some(bytes.len())
    {
        return Err(X64ElfError::InvalidElf(
            "target layout receipt drifted".into(),
        ));
    }
    let expected_displacement = relative_displacement(ELF_ENTRY_OFFSET + 1, target_offset)?;
    let mut startup = STARTUP;
    startup[1..5].copy_from_slice(&expected_displacement.to_le_bytes());
    expect(bytes, ELF_ENTRY_OFFSET, &startup, "startup")?;
    zeroes(
        bytes,
        ELF_ENTRY_OFFSET + STARTUP.len(),
        target_offset,
        "target alignment padding",
    )?;
    expect(bytes, target_offset, &encoded.bytes, "target")?;

    let reconstructed = reconstruct_elf(&encoded.bytes)?;
    if reconstructed != *bytes {
        return Err(X64ElfError::InvalidElf(
            "independent ELF reconstruction differs".into(),
        ));
    }
    Ok(VerifiedElf64Facts {
        entry: ELF_ENTRY,
        image_bytes: bytes.len() as u64,
        target_offset: image.target_offset as u64,
        target_bytes: image.target_bytes as u64,
        load_flags: 5,
        stack_flags: 6,
    })
}

fn reconstruct_elf(target: &[u8]) -> Result<Vec<u8>, X64ElfError> {
    let target_offset = align_up(ELF_ENTRY_OFFSET + STARTUP.len(), TARGET_ALIGNMENT)?;
    let image_bytes = target_offset
        .checked_add(target.len())
        .ok_or_else(|| X64ElfError::InvalidElf("reconstruction overflowed".into()))?;
    let mut result = Vec::with_capacity(image_bytes);
    write_elf_header(&mut result, image_bytes as u64);
    result.resize(ELF_ENTRY_OFFSET, 0);
    let mut startup = STARTUP;
    startup[1..5].copy_from_slice(
        &relative_displacement(ELF_ENTRY_OFFSET + 1, target_offset)?.to_le_bytes(),
    );
    result.extend_from_slice(&startup);
    result.resize(target_offset, 0);
    result.extend_from_slice(target);
    Ok(result)
}

#[derive(Clone, Copy)]
enum FixupTarget {
    Block(u32),
    Error,
}

#[derive(Clone, Copy)]
struct Fixup {
    displacement: usize,
    target: FixupTarget,
}

#[derive(Default)]
struct Emitter {
    bytes: Vec<u8>,
    fixups: Vec<Fixup>,
}

impl Emitter {
    fn rel32(&mut self, opcode: &[u8], target: FixupTarget) {
        self.bytes.extend_from_slice(opcode);
        let displacement = self.bytes.len();
        self.bytes.extend_from_slice(&[0; 4]);
        self.fixups.push(Fixup {
            displacement,
            target,
        });
    }
}

fn emit_operation(emitter: &mut Emitter, operation: &X64Operation) -> Result<(), X64ElfError> {
    match operation {
        X64Operation::ConstI64 { result, value } => {
            mov_rax_imm64(&mut emitter.bytes, *value);
            store_rax(&mut emitter.bytes, *result);
        }
        X64Operation::Copy { result, source } => {
            load_rax(&mut emitter.bytes, *source);
            store_rax(&mut emitter.bytes, *result);
        }
        X64Operation::StoreSlot { slot, value } => {
            load_rax(&mut emitter.bytes, *value);
            store_rax(&mut emitter.bytes, *slot);
        }
        X64Operation::AddSlotConst { slot, value } => {
            load_rax(&mut emitter.bytes, *slot);
            mov_rcx_imm64(&mut emitter.bytes, *value);
            emitter.bytes.extend_from_slice(&[0x48, 0x01, 0xc8]);
            store_rax(&mut emitter.bytes, *slot);
        }
        X64Operation::IntegerBinary {
            result,
            operation,
            left,
            right,
        } => {
            load_rax(&mut emitter.bytes, *left);
            load_rcx(&mut emitter.bytes, *right);
            match operation {
                IntegerBinary::Add => emitter.bytes.extend_from_slice(&[0x48, 0x01, 0xc8]),
                IntegerBinary::Sub => emitter.bytes.extend_from_slice(&[0x48, 0x29, 0xc8]),
                IntegerBinary::Mul => emitter.bytes.extend_from_slice(&[0x48, 0x0f, 0xaf, 0xc1]),
                _ => {
                    return Err(X64ElfError::Unsupported(format!(
                        "integer operation {operation:?} reached the encoder"
                    )))
                }
            }
            store_rax(&mut emitter.bytes, *result);
        }
        X64Operation::IntegerCompare {
            result,
            operation,
            left,
            right,
        } => {
            load_rax(&mut emitter.bytes, *left);
            load_rcx(&mut emitter.bytes, *right);
            emitter.bytes.extend_from_slice(&[0x48, 0x39, 0xc8]);
            emitter
                .bytes
                .extend_from_slice(&[0x0f, compare_opcode(*operation), 0xc0]);
            emitter.bytes.extend_from_slice(&[0x48, 0x0f, 0xb6, 0xc0]);
            store_rax(&mut emitter.bytes, *result);
        }
        X64Operation::RangeAllocateInit { result, length } => {
            let bytes = list_bytes(*length)?;
            emitter.bytes.extend_from_slice(&[0x48, 0x31, 0xff]);
            mov_rsi_imm64(&mut emitter.bytes, bytes as i64);
            mov_rdx_imm64(&mut emitter.bytes, 3);
            mov_r10_imm64(&mut emitter.bytes, 0x22);
            mov_r8_imm64(&mut emitter.bytes, -1);
            emitter.bytes.extend_from_slice(&[0x4d, 0x31, 0xc9]);
            mov_rax_imm64(&mut emitter.bytes, SYS_MMAP);
            emitter
                .bytes
                .extend_from_slice(&[0x0f, 0x05, 0x48, 0x85, 0xc0]);
            emitter.rel32(&[0x0f, 0x88], FixupTarget::Error);
            store_rax(&mut emitter.bytes, *result);
            emitter.bytes.extend_from_slice(&[0x48, 0x31, 0xc9]);
            mov_rdx_imm64(&mut emitter.bytes, *length as i64);
            let loop_offset = emitter.bytes.len();
            emitter.bytes.extend_from_slice(&[0x48, 0x39, 0xd1]);
            let done_opcode = emitter.bytes.len();
            emitter.bytes.extend_from_slice(&[0x0f, 0x8d, 0, 0, 0, 0]);
            emitter.bytes.extend_from_slice(&[0x48, 0x89, 0x0c, 0xc8]);
            emitter.bytes.extend_from_slice(&[0x48, 0xff, 0xc1]);
            emit_local_rel32(&mut emitter.bytes, &[0xe9], loop_offset)?;
            let done = emitter.bytes.len();
            patch_rel32(
                &mut emitter.bytes,
                done_opcode + 2,
                as_u32(done, "init done")?,
            )?;
        }
        X64Operation::ListLengthStatic { result, length } => {
            mov_rax_imm64(&mut emitter.bytes, *length as i64);
            store_rax(&mut emitter.bytes, *result);
        }
        X64Operation::ListLoadChecked {
            result,
            list,
            index,
            length,
        } => {
            load_rax(&mut emitter.bytes, *list);
            load_rcx(&mut emitter.bytes, *index);
            emit_bounds_check(emitter, *length);
            emitter.bytes.extend_from_slice(&[0x48, 0x8b, 0x04, 0xc8]);
            store_rax(&mut emitter.bytes, *result);
        }
        X64Operation::ListStoreChecked {
            result,
            list,
            index,
            value,
            length,
        } => {
            load_rax(&mut emitter.bytes, *list);
            load_rcx(&mut emitter.bytes, *index);
            emit_bounds_check(emitter, *length);
            // The bounds check uses RDX for the static length.  Load the
            // value only after that check so the store cannot accidentally
            // commit the length in place of the requested value.
            load_rdx(&mut emitter.bytes, *value);
            emitter.bytes.extend_from_slice(&[0x48, 0x89, 0x14, 0xc8]);
            emitter.bytes.extend_from_slice(&[0x48, 0x31, 0xc0]);
            store_rax(&mut emitter.bytes, *result);
        }
        X64Operation::ReleaseOwnedList { slot, length } => {
            load_rdi(&mut emitter.bytes, *slot);
            mov_rsi_imm64(&mut emitter.bytes, list_bytes(*length)? as i64);
            mov_rax_imm64(&mut emitter.bytes, SYS_MUNMAP);
            emitter
                .bytes
                .extend_from_slice(&[0x0f, 0x05, 0x48, 0x85, 0xc0]);
            emitter.rel32(&[0x0f, 0x85], FixupTarget::Error);
            emitter.bytes.extend_from_slice(&[0x48, 0xc7, 0x85]);
            emitter
                .bytes
                .extend_from_slice(&slot.displacement.to_le_bytes());
            emitter.bytes.extend_from_slice(&[0, 0, 0, 0]);
        }
    }
    Ok(())
}

fn emit_terminator(emitter: &mut Emitter, terminator: &X64Terminator) -> Result<(), X64ElfError> {
    match terminator {
        X64Terminator::Goto { target } => emitter.rel32(&[0xe9], FixupTarget::Block(*target)),
        X64Terminator::Branch {
            condition,
            if_true,
            if_false,
        } => {
            load_rax(&mut emitter.bytes, *condition);
            emitter.bytes.extend_from_slice(&[0x48, 0x85, 0xc0]);
            emitter.rel32(&[0x0f, 0x85], FixupTarget::Block(*if_true));
            emitter.rel32(&[0xe9], FixupTarget::Block(*if_false));
        }
        X64Terminator::Return { value } => {
            load_rax(&mut emitter.bytes, *value);
            emitter.bytes.extend_from_slice(&[0xc9, 0xc3]);
        }
    }
    Ok(())
}

fn emit_bounds_check(emitter: &mut Emitter, length: u64) {
    emitter.bytes.extend_from_slice(&[0x48, 0x85, 0xc9]);
    emitter.rel32(&[0x0f, 0x88], FixupTarget::Error);
    mov_rdx_imm64(&mut emitter.bytes, length as i64);
    emitter.bytes.extend_from_slice(&[0x48, 0x39, 0xd1]);
    emitter.rel32(&[0x0f, 0x8d], FixupTarget::Error);
}

fn write_elf_header(bytes: &mut Vec<u8>, image_bytes: u64) {
    bytes.extend_from_slice(b"\x7fELF");
    bytes.extend_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(bytes, 2);
    put_u16(bytes, 62);
    put_u32(bytes, 1);
    put_u64(bytes, ELF_ENTRY);
    put_u64(bytes, ELF_HEADER_BYTES as u64);
    put_u64(bytes, 0);
    put_u32(bytes, 0);
    put_u16(bytes, ELF_HEADER_BYTES as u16);
    put_u16(bytes, PROGRAM_HEADER_BYTES as u16);
    put_u16(bytes, PROGRAM_HEADER_COUNT as u16);
    put_u16(bytes, 0);
    put_u16(bytes, 0);
    put_u16(bytes, 0);
    put_u32(bytes, 1);
    put_u32(bytes, 5);
    put_u64(bytes, 0);
    put_u64(bytes, ELF_BASE);
    put_u64(bytes, ELF_BASE);
    put_u64(bytes, image_bytes);
    put_u64(bytes, image_bytes);
    put_u64(bytes, 4096);
    put_u32(bytes, 0x6474_e551);
    put_u32(bytes, 6);
    for _ in 0..5 {
        put_u64(bytes, 0);
    }
    put_u64(bytes, 16);
}

fn home(
    kind: HomeKind,
    index: u32,
    ty: MachineType,
    ordinal: usize,
) -> Result<StackHome, X64ElfError> {
    let bytes = ordinal
        .checked_add(1)
        .and_then(|value| value.checked_mul(8))
        .ok_or_else(|| X64ElfError::InvalidPlan("home displacement overflowed".into()))?;
    let bytes = i32::try_from(bytes)
        .map_err(|_| X64ElfError::InvalidPlan("home displacement exceeds i32".into()))?;
    Ok(StackHome {
        kind,
        index,
        ty,
        displacement: -bytes,
    })
}

fn instruction_result(instruction: &MachineInstruction) -> Option<TypedRegister> {
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

fn compare_opcode(operation: IntegerCompare) -> u8 {
    match operation {
        IntegerCompare::Eq => 0x94,
        IntegerCompare::Ne => 0x95,
        IntegerCompare::Gt => 0x9f,
        IntegerCompare::Ge => 0x9d,
        IntegerCompare::Lt => 0x9c,
        IntegerCompare::Le => 0x9e,
    }
}

fn load_rax(bytes: &mut Vec<u8>, home: StackHome) {
    bytes.extend_from_slice(&[0x48, 0x8b, 0x85]);
    bytes.extend_from_slice(&home.displacement.to_le_bytes());
}

fn load_rcx(bytes: &mut Vec<u8>, home: StackHome) {
    bytes.extend_from_slice(&[0x48, 0x8b, 0x8d]);
    bytes.extend_from_slice(&home.displacement.to_le_bytes());
}

fn load_rdx(bytes: &mut Vec<u8>, home: StackHome) {
    bytes.extend_from_slice(&[0x48, 0x8b, 0x95]);
    bytes.extend_from_slice(&home.displacement.to_le_bytes());
}

fn load_rdi(bytes: &mut Vec<u8>, home: StackHome) {
    bytes.extend_from_slice(&[0x48, 0x8b, 0xbd]);
    bytes.extend_from_slice(&home.displacement.to_le_bytes());
}

fn store_rax(bytes: &mut Vec<u8>, home: StackHome) {
    bytes.extend_from_slice(&[0x48, 0x89, 0x85]);
    bytes.extend_from_slice(&home.displacement.to_le_bytes());
}

fn mov_rax_imm64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&[0x48, 0xb8]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn mov_rcx_imm64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&[0x48, 0xb9]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn mov_rsi_imm64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&[0x48, 0xbe]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn mov_rdx_imm64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&[0x48, 0xba]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn mov_r10_imm64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&[0x49, 0xba]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn mov_r8_imm64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&[0x49, 0xb8]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn patch_rel32(bytes: &mut [u8], displacement: usize, target: u32) -> Result<(), X64ElfError> {
    let next = displacement
        .checked_add(4)
        .ok_or_else(|| X64ElfError::Encoding("rel32 next offset overflowed".into()))?;
    let delta = i64::from(target) - i64::try_from(next).unwrap_or(i64::MAX);
    let delta = i32::try_from(delta)
        .map_err(|_| X64ElfError::Encoding("rel32 target is out of range".into()))?;
    let destination = bytes
        .get_mut(displacement..next)
        .ok_or_else(|| X64ElfError::Encoding("rel32 displacement escapes target bytes".into()))?;
    destination.copy_from_slice(&delta.to_le_bytes());
    Ok(())
}

fn emit_local_rel32(bytes: &mut Vec<u8>, opcode: &[u8], target: usize) -> Result<(), X64ElfError> {
    bytes.extend_from_slice(opcode);
    let displacement = bytes.len();
    bytes.extend_from_slice(&[0; 4]);
    patch_rel32(bytes, displacement, as_u32(target, "local target")?)
}

fn relative_displacement(displacement_offset: usize, target: usize) -> Result<i32, X64ElfError> {
    let next = displacement_offset
        .checked_add(4)
        .ok_or_else(|| X64ElfError::InvalidElf("call next offset overflowed".into()))?;
    i32::try_from(
        i64::try_from(target).unwrap_or(i64::MAX) - i64::try_from(next).unwrap_or(i64::MIN),
    )
    .map_err(|_| X64ElfError::InvalidElf("call displacement exceeds rel32".into()))
}

fn list_bytes(length: u64) -> Result<u64, X64ElfError> {
    length
        .checked_mul(8)
        .ok_or_else(|| X64ElfError::Encoding("list byte length overflowed".into()))
}

fn align_up(value: usize, alignment: usize) -> Result<usize, X64ElfError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(X64ElfError::InvalidPlan("invalid alignment".into()));
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| X64ElfError::InvalidPlan("alignment overflowed".into()))
}

fn as_u32(value: usize, label: &str) -> Result<u32, X64ElfError> {
    u32::try_from(value).map_err(|_| X64ElfError::Encoding(format!("{label} exceeds u32")))
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16, X64ElfError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| X64ElfError::InvalidElf(format!("{label} is truncated")))?
        .try_into()
        .expect("two-byte slice");
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32, X64ElfError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| X64ElfError::InvalidElf(format!("{label} is truncated")))?
        .try_into()
        .expect("four-byte slice");
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize, label: &str) -> Result<u64, X64ElfError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| X64ElfError::InvalidElf(format!("{label} is truncated")))?
        .try_into()
        .expect("eight-byte slice");
    Ok(u64::from_le_bytes(raw))
}

fn expect(bytes: &[u8], offset: usize, expected: &[u8], label: &str) -> Result<(), X64ElfError> {
    if bytes.get(offset..offset + expected.len()) == Some(expected) {
        Ok(())
    } else {
        Err(X64ElfError::InvalidElf(format!("{label} bytes drifted")))
    }
}

fn zeroes(bytes: &[u8], start: usize, end: usize, label: &str) -> Result<(), X64ElfError> {
    if start <= end
        && bytes
            .get(start..end)
            .is_some_and(|region| region.iter().all(|byte| *byte == 0))
    {
        Ok(())
    } else {
        Err(X64ElfError::InvalidElf(format!(
            "{label} is not zero-filled"
        )))
    }
}

fn expect_u16(bytes: &[u8], offset: usize, expected: u16, label: &str) -> Result<(), X64ElfError> {
    if read_u16(bytes, offset, label)? == expected {
        Ok(())
    } else {
        Err(X64ElfError::InvalidElf(format!("{label} drifted")))
    }
}

fn expect_u32(bytes: &[u8], offset: usize, expected: u32, label: &str) -> Result<(), X64ElfError> {
    if read_u32(bytes, offset, label)? == expected {
        Ok(())
    } else {
        Err(X64ElfError::InvalidElf(format!("{label} drifted")))
    }
}

fn expect_u64(bytes: &[u8], offset: usize, expected: u64, label: &str) -> Result<(), X64ElfError> {
    if read_u64(bytes, offset, label)? == expected {
        Ok(())
    } else {
        Err(X64ElfError::InvalidElf(format!("{label} drifted")))
    }
}
