//! Candidate x86-64 byte encoding for the bounded S4-WP8D residency contract.
//!
//! This module deliberately stops at function bytes.  It neither constructs
//! an ELF image nor executes or measures the candidate.  The frozen WP5D
//! encoder remains untouched: unselected ranges are copied from its verified
//! receipt and every external rel32 displacement is rebound to the candidate
//! layout.

use crate::baseline::{
    lower_x64_plan, verify_x64_encoding, EncodedX64, EncodingKind, EncodingRange, HomeKind,
    StackHome, X64Operation, X64Plan, X64Terminator,
};
use crate::machine::{MachineType, ResidualMachineProgram};
use crate::residency::{
    verify_register_residency, PhysicalRegister, ResidencyInstruction, ResidencyPlan,
};
use std::fmt;

const PROLOGUE_BYTES: u32 = 11;
const TEMPLATE_BYTES: u32 = 7;
const MAX_TARGET_BYTES: usize = 1_048_576;
const ENCODING_REPORT_DOMAIN: &[u8] = b"NAUX:s4-register-residency-encoding-report:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateRangeKind {
    PassThroughOperation,
    LoadPhysical,
    StorePhysical,
    PassThroughTerminator,
    ReturnWithRestore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRange {
    pub block: u32,
    pub ordinal: u32,
    pub kind: CandidateRangeKind,
    pub start: u32,
    pub end: u32,
    pub baseline_start: u32,
    pub baseline_end: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidencyEncodedX64 {
    pub bytes: Vec<u8>,
    pub block_offsets: Vec<u32>,
    pub error_offset: u32,
    pub save_start: u32,
    pub save_end: u32,
    pub ranges: Vec<CandidateRange>,
}

impl ResidencyEncodedX64 {
    pub fn transformed_site_count(&self) -> u32 {
        self.ranges
            .iter()
            .filter(|range| {
                matches!(
                    range.kind,
                    CandidateRangeKind::LoadPhysical | CandidateRangeKind::StorePhysical
                )
            })
            .count() as u32
    }

    pub fn return_count(&self) -> u32 {
        self.ranges
            .iter()
            .filter(|range| range.kind == CandidateRangeKind::ReturnWithRestore)
            .count() as u32
    }
}

pub fn encoding_report_hash(payload: &[u8]) -> naux::core::SemanticHash {
    let mut preimage = Vec::with_capacity(ENCODING_REPORT_DOMAIN.len() + payload.len());
    preimage.extend_from_slice(ENCODING_REPORT_DOMAIN);
    preimage.extend_from_slice(payload);
    naux::core::SemanticHash(sha256(&preimage))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidencyEncodingError {
    InvalidInput(String),
    Unsupported(String),
    Encoding(String),
}

impl fmt::Display for ResidencyEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, message) = match self {
            Self::InvalidInput(message) => ("input", message),
            Self::Unsupported(message) => ("unsupported", message),
            Self::Encoding(message) => ("encoding", message),
        };
        write!(formatter, "S4-WP8E residency {kind} error: {message}")
    }
}

impl std::error::Error for ResidencyEncodingError {}

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

/// Materialize candidate function bytes from one verified WP8C plan and the
/// exact frozen WP5D encoding receipt that plan was derived from.
pub fn encode_register_residency(
    machine: &ResidualMachineProgram,
    baseline_plan: &X64Plan,
    residency_plan: &ResidencyPlan,
    baseline: &EncodedX64,
) -> Result<ResidencyEncodedX64, ResidencyEncodingError> {
    validate_inputs(machine, baseline_plan, residency_plan, baseline)?;

    let promoted = promoted_home(baseline_plan, residency_plan)?;
    let mut bytes = baseline
        .bytes
        .get(..PROLOGUE_BYTES as usize)
        .ok_or_else(|| ResidencyEncodingError::Encoding("baseline prologue is truncated".into()))?
        .to_vec();
    let save_start = as_u32(bytes.len(), "ABI save start")?;
    emit_store_r12(&mut bytes, promoted);
    let save_end = as_u32(bytes.len(), "ABI save end")?;

    let mut block_offsets = Vec::with_capacity(baseline_plan.blocks.len());
    let mut ranges = Vec::with_capacity(baseline.ranges.len());
    let mut fixups = Vec::new();
    let mut range_index = 0_usize;

    for ((baseline_block, residency_block), machine_block) in baseline_plan
        .blocks
        .iter()
        .zip(&residency_plan.blocks)
        .zip(&machine.blocks)
    {
        block_offsets.push(as_u32(bytes.len(), "candidate block offset")?);
        for (ordinal, ((operation, instruction), source_instruction)) in baseline_block
            .operations
            .iter()
            .zip(&residency_block.instructions)
            .zip(&machine_block.instructions)
            .enumerate()
        {
            let baseline_range = expected_baseline_range(
                baseline,
                range_index,
                baseline_block.id,
                ordinal as u32,
                EncodingKind::Operation,
            )?;
            range_index += 1;
            let source = baseline_slice(baseline, baseline_range)?;
            let start = as_u32(bytes.len(), "candidate operation start")?;
            let kind = match instruction {
                ResidencyInstruction::PassThrough(candidate) if candidate == source_instruction => {
                    let candidate_start = bytes.len();
                    bytes.extend_from_slice(source);
                    collect_operation_fixups(operation, candidate_start, source, &mut fixups)?;
                    CandidateRangeKind::PassThroughOperation
                }
                ResidencyInstruction::LoadPhysical { result, register }
                    if *register == PhysicalRegister::R12 =>
                {
                    let X64Operation::Copy {
                        result: result_home,
                        source: source_home,
                    } = operation
                    else {
                        return Err(ResidencyEncodingError::InvalidInput(
                            "load-physical does not align with a WP5D copy".into(),
                        ));
                    };
                    require_register_home(*result_home, result.id, result.ty)?;
                    require_promoted_home(*source_home, promoted)?;
                    emit_store_r12(&mut bytes, *result_home);
                    CandidateRangeKind::LoadPhysical
                }
                ResidencyInstruction::StorePhysical {
                    register,
                    value,
                    keep,
                } if *register == PhysicalRegister::R12 => {
                    let X64Operation::StoreSlot {
                        slot,
                        value: value_home,
                    } = operation
                    else {
                        return Err(ResidencyEncodingError::InvalidInput(
                            "store-physical does not align with a WP5D slot store".into(),
                        ));
                    };
                    let source_keep = match source_instruction {
                        crate::machine::MachineInstruction::StoreSlot { keep, .. } => keep,
                        _ => {
                            return Err(ResidencyEncodingError::InvalidInput(
                                "store-physical source instruction drifted".into(),
                            ))
                        }
                    };
                    if keep != source_keep {
                        return Err(ResidencyEncodingError::InvalidInput(
                            "store-physical ownership mode drifted".into(),
                        ));
                    }
                    require_promoted_home(*slot, promoted)?;
                    require_register_home(*value_home, value.id, value.ty)?;
                    emit_load_r12(&mut bytes, *value_home);
                    CandidateRangeKind::StorePhysical
                }
                ResidencyInstruction::AddPhysicalConst { .. } => {
                    return Err(ResidencyEncodingError::Unsupported(
                        "add-physical-const has no admitted WP8D byte template".into(),
                    ));
                }
                _ => {
                    return Err(ResidencyEncodingError::InvalidInput(
                        "residency instruction does not align with source and baseline plans"
                            .into(),
                    ));
                }
            };
            let end = as_u32(bytes.len(), "candidate operation end")?;
            ranges.push(candidate_range(baseline_range, kind, start, end));
        }

        let ordinal = baseline_block.operations.len() as u32;
        let baseline_range = expected_baseline_range(
            baseline,
            range_index,
            baseline_block.id,
            ordinal,
            EncodingKind::Terminator,
        )?;
        range_index += 1;
        let source = baseline_slice(baseline, baseline_range)?;
        let start = as_u32(bytes.len(), "candidate terminator start")?;
        let kind = match &baseline_block.terminator {
            X64Terminator::Return { .. } => {
                emit_load_r12(&mut bytes, promoted);
                bytes.extend_from_slice(source);
                CandidateRangeKind::ReturnWithRestore
            }
            terminator => {
                let candidate_start = bytes.len();
                bytes.extend_from_slice(source);
                collect_terminator_fixups(terminator, candidate_start, source, &mut fixups)?;
                CandidateRangeKind::PassThroughTerminator
            }
        };
        let end = as_u32(bytes.len(), "candidate terminator end")?;
        ranges.push(candidate_range(baseline_range, kind, start, end));
    }

    if range_index != baseline.ranges.len() {
        return Err(ResidencyEncodingError::InvalidInput(
            "baseline encoding contains unconsumed ranges".into(),
        ));
    }
    let error_offset = as_u32(bytes.len(), "candidate error offset")?;
    let error_suffix = baseline
        .bytes
        .get(baseline.error_offset as usize..)
        .ok_or_else(|| {
            ResidencyEncodingError::Encoding("baseline error suffix is absent".into())
        })?;
    bytes.extend_from_slice(error_suffix);

    for fixup in fixups {
        let target = match fixup.target {
            FixupTarget::Block(block) => *block_offsets.get(block as usize).ok_or_else(|| {
                ResidencyEncodingError::Encoding(format!(
                    "candidate fixup targets absent block b{block}"
                ))
            })?,
            FixupTarget::Error => error_offset,
        };
        patch_rel32(&mut bytes, fixup.displacement, target)?;
    }
    if bytes.len() > MAX_TARGET_BYTES {
        return Err(ResidencyEncodingError::Encoding(format!(
            "candidate uses {} bytes; limit is {MAX_TARGET_BYTES}",
            bytes.len()
        )));
    }

    let candidate = ResidencyEncodedX64 {
        bytes,
        block_offsets,
        error_offset,
        save_start,
        save_end,
        ranges,
    };
    verify_register_residency_encoding(
        machine,
        baseline_plan,
        residency_plan,
        baseline,
        &candidate,
    )?;
    Ok(candidate)
}

/// Independently parse the candidate receipt and enforce the WP8D byte
/// templates, range partition, passthrough bytes, and every external target.
pub fn verify_register_residency_encoding(
    machine: &ResidualMachineProgram,
    baseline_plan: &X64Plan,
    residency_plan: &ResidencyPlan,
    baseline: &EncodedX64,
    candidate: &ResidencyEncodedX64,
) -> Result<(), ResidencyEncodingError> {
    validate_inputs(machine, baseline_plan, residency_plan, baseline)?;
    let promoted = promoted_home(baseline_plan, residency_plan)?;
    if candidate.bytes.len() > MAX_TARGET_BYTES
        || candidate.block_offsets.len() != baseline_plan.blocks.len()
        || candidate.ranges.len() != baseline.ranges.len()
    {
        return Err(ResidencyEncodingError::Encoding(
            "candidate receipt cardinality or byte limit drifted".into(),
        ));
    }
    if candidate.save_start != PROLOGUE_BYTES
        || candidate.save_end != PROLOGUE_BYTES + TEMPLATE_BYTES
        || candidate.bytes.get(..PROLOGUE_BYTES as usize)
            != baseline.bytes.get(..PROLOGUE_BYTES as usize)
        || candidate
            .bytes
            .get(candidate.save_start as usize..candidate.save_end as usize)
            != Some(expected_store_r12(promoted).as_slice())
    {
        return Err(ResidencyEncodingError::Encoding(
            "canonical prologue or ABI save template drifted".into(),
        ));
    }

    let mut cursor = candidate.save_end;
    let mut range_index = 0_usize;
    let mut transformed = 0_u32;
    let mut returns = 0_u32;
    for ((baseline_block, residency_block), machine_block) in baseline_plan
        .blocks
        .iter()
        .zip(&residency_plan.blocks)
        .zip(&machine.blocks)
    {
        if candidate.block_offsets.get(baseline_block.id as usize) != Some(&cursor) {
            return Err(ResidencyEncodingError::Encoding(
                "candidate block offset drifted".into(),
            ));
        }
        for (ordinal, ((operation, instruction), source_instruction)) in baseline_block
            .operations
            .iter()
            .zip(&residency_block.instructions)
            .zip(&machine_block.instructions)
            .enumerate()
        {
            let baseline_range = &baseline.ranges[range_index];
            let range = &candidate.ranges[range_index];
            require_range_receipt(
                range,
                baseline_range,
                baseline_block.id,
                ordinal as u32,
                cursor,
            )?;
            let actual = candidate_slice(candidate, range)?;
            let source = baseline_slice(baseline, baseline_range)?;
            match instruction {
                ResidencyInstruction::PassThrough(value) if value == source_instruction => {
                    if range.kind != CandidateRangeKind::PassThroughOperation {
                        return Err(kind_drift());
                    }
                    verify_passthrough_operation(
                        operation,
                        source,
                        actual,
                        range.start,
                        candidate.error_offset,
                    )?;
                }
                ResidencyInstruction::LoadPhysical { result, register }
                    if *register == PhysicalRegister::R12 =>
                {
                    if range.kind != CandidateRangeKind::LoadPhysical
                        || actual
                            != expected_store_r12(register_home(
                                baseline_plan,
                                result.id,
                                result.ty,
                            )?)
                            .as_slice()
                    {
                        return Err(ResidencyEncodingError::Encoding(
                            "load-physical byte template drifted".into(),
                        ));
                    }
                    transformed += 1;
                }
                ResidencyInstruction::StorePhysical {
                    register, value, ..
                } if *register == PhysicalRegister::R12 => {
                    if range.kind != CandidateRangeKind::StorePhysical
                        || actual
                            != expected_load_r12(register_home(baseline_plan, value.id, value.ty)?)
                                .as_slice()
                    {
                        return Err(ResidencyEncodingError::Encoding(
                            "store-physical byte template drifted".into(),
                        ));
                    }
                    transformed += 1;
                }
                ResidencyInstruction::AddPhysicalConst { .. } => {
                    return Err(ResidencyEncodingError::Unsupported(
                        "add-physical-const has no admitted WP8D byte template".into(),
                    ));
                }
                _ => return Err(kind_drift()),
            }
            cursor = range.end;
            range_index += 1;
        }

        let baseline_range = &baseline.ranges[range_index];
        let range = &candidate.ranges[range_index];
        require_range_receipt(
            range,
            baseline_range,
            baseline_block.id,
            baseline_block.operations.len() as u32,
            cursor,
        )?;
        let actual = candidate_slice(candidate, range)?;
        let source = baseline_slice(baseline, baseline_range)?;
        match &baseline_block.terminator {
            X64Terminator::Return { .. } => {
                let mut expected = expected_load_r12(promoted).to_vec();
                expected.extend_from_slice(source);
                if range.kind != CandidateRangeKind::ReturnWithRestore || actual != expected {
                    return Err(ResidencyEncodingError::Encoding(
                        "return ABI restore template drifted".into(),
                    ));
                }
                returns += 1;
            }
            terminator => {
                if range.kind != CandidateRangeKind::PassThroughTerminator {
                    return Err(kind_drift());
                }
                verify_passthrough_terminator(
                    terminator,
                    source,
                    actual,
                    range.start,
                    &candidate.block_offsets,
                )?;
            }
        }
        cursor = range.end;
        range_index += 1;
    }

    if cursor != candidate.error_offset
        || candidate.bytes.get(candidate.error_offset as usize..)
            != baseline.bytes.get(baseline.error_offset as usize..)
        || transformed != residency_plan.static_reads + residency_plan.static_writes
        || transformed != candidate.transformed_site_count()
        || returns == 0
        || returns != candidate.return_count()
    {
        return Err(ResidencyEncodingError::Encoding(
            "candidate body, error suffix, or site cardinality drifted".into(),
        ));
    }

    let removed = transformed
        .checked_mul(TEMPLATE_BYTES)
        .ok_or_else(|| ResidencyEncodingError::Encoding("byte decrease overflowed".into()))?;
    let added = TEMPLATE_BYTES
        .checked_mul(1 + returns)
        .ok_or_else(|| ResidencyEncodingError::Encoding("ABI byte count overflowed".into()))?;
    let expected_bytes = (baseline.bytes.len() as i64) - i64::from(removed) + i64::from(added);
    if expected_bytes <= 0 || candidate.bytes.len() as i64 != expected_bytes {
        return Err(ResidencyEncodingError::Encoding(
            "candidate byte-width equation drifted".into(),
        ));
    }
    Ok(())
}

fn validate_inputs(
    machine: &ResidualMachineProgram,
    baseline_plan: &X64Plan,
    residency_plan: &ResidencyPlan,
    baseline: &EncodedX64,
) -> Result<(), ResidencyEncodingError> {
    let reconstructed_baseline = lower_x64_plan(machine)
        .map_err(|error| ResidencyEncodingError::InvalidInput(error.to_string()))?;
    if &reconstructed_baseline != baseline_plan {
        return Err(ResidencyEncodingError::InvalidInput(
            "WP5D plan does not exactly reconstruct from source Machine IR".into(),
        ));
    }
    verify_x64_encoding(baseline_plan, baseline)
        .map_err(|error| ResidencyEncodingError::InvalidInput(error.to_string()))?;
    verify_register_residency(residency_plan, machine, baseline_plan)
        .map_err(|error| ResidencyEncodingError::InvalidInput(error.to_string()))?;
    if baseline_plan.source_machine_hash != machine.semantic_hash()
        || residency_plan.source_machine_hash != machine.semantic_hash()
        || residency_plan.frame_bytes != baseline_plan.frame_bytes
        || residency_plan.physical_register != PhysicalRegister::R12
        || residency_plan.promoted_type != MachineType::I64
        || !residency_plan.save_on_entry
        || !residency_plan.restore_on_return
        || !residency_plan.error_path_nonreturning
        || baseline_plan.blocks.len() != residency_plan.blocks.len()
        || baseline_plan.blocks.len() != machine.blocks.len()
    {
        return Err(ResidencyEncodingError::InvalidInput(
            "WP5D/WP8C identity, frame, ABI, or CFG binding drifted".into(),
        ));
    }
    for ((target, residency), source) in baseline_plan
        .blocks
        .iter()
        .zip(&residency_plan.blocks)
        .zip(&machine.blocks)
    {
        if target.id != residency.id
            || target.id != source.id
            || target.operations.len() != residency.instructions.len()
            || target.operations.len() != source.instructions.len()
            || residency.terminator != source.terminator
        {
            return Err(ResidencyEncodingError::InvalidInput(
                "block, operation, or terminator extent drifted".into(),
            ));
        }
    }
    Ok(())
}

fn promoted_home(
    baseline_plan: &X64Plan,
    residency_plan: &ResidencyPlan,
) -> Result<StackHome, ResidencyEncodingError> {
    let home = baseline_plan
        .slot_homes
        .get(residency_plan.promoted_slot as usize)
        .copied()
        .ok_or_else(|| {
            ResidencyEncodingError::InvalidInput("promoted slot home is absent".into())
        })?;
    require_promoted_home(home, home)?;
    if home.ty != MachineType::I64 {
        return Err(ResidencyEncodingError::InvalidInput(
            "promoted home is not i64".into(),
        ));
    }
    Ok(home)
}

fn register_home(
    plan: &X64Plan,
    id: u32,
    ty: MachineType,
) -> Result<StackHome, ResidencyEncodingError> {
    let home = plan
        .register_homes
        .get(id as usize)
        .copied()
        .ok_or_else(|| ResidencyEncodingError::InvalidInput(format!("register r{id} is absent")))?;
    require_register_home(home, id, ty)?;
    Ok(home)
}

fn require_register_home(
    home: StackHome,
    id: u32,
    ty: MachineType,
) -> Result<(), ResidencyEncodingError> {
    if home.kind != HomeKind::Register || home.index != id || home.ty != ty {
        return Err(ResidencyEncodingError::InvalidInput(format!(
            "register home r{id} drifted"
        )));
    }
    Ok(())
}

fn require_promoted_home(
    actual: StackHome,
    promoted: StackHome,
) -> Result<(), ResidencyEncodingError> {
    if actual != promoted || actual.kind != HomeKind::Slot || actual.ty != MachineType::I64 {
        return Err(ResidencyEncodingError::InvalidInput(
            "promoted slot home drifted".into(),
        ));
    }
    Ok(())
}

fn expected_baseline_range(
    baseline: &EncodedX64,
    index: usize,
    block: u32,
    ordinal: u32,
    kind: EncodingKind,
) -> Result<&EncodingRange, ResidencyEncodingError> {
    let range = baseline.ranges.get(index).ok_or_else(|| {
        ResidencyEncodingError::InvalidInput("baseline encoding range is absent".into())
    })?;
    if range.block != block || range.ordinal != ordinal || range.kind != kind {
        return Err(ResidencyEncodingError::InvalidInput(
            "baseline encoding range order drifted".into(),
        ));
    }
    Ok(range)
}

fn baseline_slice<'a>(
    baseline: &'a EncodedX64,
    range: &EncodingRange,
) -> Result<&'a [u8], ResidencyEncodingError> {
    baseline
        .bytes
        .get(range.start as usize..range.end as usize)
        .ok_or_else(|| {
            ResidencyEncodingError::InvalidInput("baseline range is out of bounds".into())
        })
}

fn candidate_slice<'a>(
    candidate: &'a ResidencyEncodedX64,
    range: &CandidateRange,
) -> Result<&'a [u8], ResidencyEncodingError> {
    candidate
        .bytes
        .get(range.start as usize..range.end as usize)
        .ok_or_else(|| ResidencyEncodingError::Encoding("candidate range is out of bounds".into()))
}

fn candidate_range(
    baseline: &EncodingRange,
    kind: CandidateRangeKind,
    start: u32,
    end: u32,
) -> CandidateRange {
    CandidateRange {
        block: baseline.block,
        ordinal: baseline.ordinal,
        kind,
        start,
        end,
        baseline_start: baseline.start,
        baseline_end: baseline.end,
    }
}

fn require_range_receipt(
    candidate: &CandidateRange,
    baseline: &EncodingRange,
    block: u32,
    ordinal: u32,
    start: u32,
) -> Result<(), ResidencyEncodingError> {
    if candidate.block != block
        || candidate.ordinal != ordinal
        || candidate.start != start
        || candidate.end <= candidate.start
        || candidate.baseline_start != baseline.start
        || candidate.baseline_end != baseline.end
    {
        return Err(ResidencyEncodingError::Encoding(
            "candidate range receipt drifted".into(),
        ));
    }
    Ok(())
}

fn collect_operation_fixups(
    operation: &X64Operation,
    candidate_start: usize,
    bytes: &[u8],
    fixups: &mut Vec<Fixup>,
) -> Result<(), ResidencyEncodingError> {
    let patterns: &[&[u8]] = match operation {
        X64Operation::RangeAllocateInit { .. } => &[&[0x0f, 0x88]],
        X64Operation::ListLoadChecked { .. } | X64Operation::ListStoreChecked { .. } => {
            &[&[0x0f, 0x88], &[0x0f, 0x8d]]
        }
        X64Operation::ReleaseOwnedList { .. } => &[&[0x0f, 0x85]],
        _ => &[],
    };
    for pattern in patterns {
        let opcode = unique_pattern(bytes, pattern)?;
        fixups.push(Fixup {
            displacement: candidate_start + opcode + pattern.len(),
            target: FixupTarget::Error,
        });
    }
    Ok(())
}

fn collect_terminator_fixups(
    terminator: &X64Terminator,
    candidate_start: usize,
    bytes: &[u8],
    fixups: &mut Vec<Fixup>,
) -> Result<(), ResidencyEncodingError> {
    match terminator {
        X64Terminator::Goto { target } => {
            if bytes.len() != 5 || bytes[0] != 0xe9 {
                return Err(ResidencyEncodingError::InvalidInput(
                    "baseline goto template drifted".into(),
                ));
            }
            fixups.push(Fixup {
                displacement: candidate_start + 1,
                target: FixupTarget::Block(*target),
            });
        }
        X64Terminator::Branch {
            if_true, if_false, ..
        } => {
            if bytes.len() != 21
                || bytes.get(10..12) != Some(&[0x0f, 0x85])
                || bytes.get(16) != Some(&0xe9)
            {
                return Err(ResidencyEncodingError::InvalidInput(
                    "baseline branch template drifted".into(),
                ));
            }
            fixups.push(Fixup {
                displacement: candidate_start + 12,
                target: FixupTarget::Block(*if_true),
            });
            fixups.push(Fixup {
                displacement: candidate_start + 17,
                target: FixupTarget::Block(*if_false),
            });
        }
        X64Terminator::Return { .. } => {
            return Err(ResidencyEncodingError::Encoding(
                "return entered passthrough fixup collection".into(),
            ));
        }
    }
    Ok(())
}

fn verify_passthrough_operation(
    operation: &X64Operation,
    baseline: &[u8],
    candidate: &[u8],
    candidate_start: u32,
    error_offset: u32,
) -> Result<(), ResidencyEncodingError> {
    let patterns: &[&[u8]] = match operation {
        X64Operation::RangeAllocateInit { .. } => &[&[0x0f, 0x88]],
        X64Operation::ListLoadChecked { .. } | X64Operation::ListStoreChecked { .. } => {
            &[&[0x0f, 0x88], &[0x0f, 0x8d]]
        }
        X64Operation::ReleaseOwnedList { .. } => &[&[0x0f, 0x85]],
        _ => &[],
    };
    verify_equal_except_rel32(baseline, candidate, patterns)?;
    for pattern in patterns {
        let opcode = unique_pattern(candidate, pattern)?;
        if rel32_target(candidate, opcode + pattern.len(), candidate_start)? != error_offset as i64
        {
            return Err(ResidencyEncodingError::Encoding(
                "passthrough operation error target drifted".into(),
            ));
        }
    }
    Ok(())
}

fn verify_passthrough_terminator(
    terminator: &X64Terminator,
    baseline: &[u8],
    candidate: &[u8],
    candidate_start: u32,
    block_offsets: &[u32],
) -> Result<(), ResidencyEncodingError> {
    match terminator {
        X64Terminator::Goto { target } => {
            verify_equal_except_offsets(baseline, candidate, &[1])?;
            verify_target(candidate, 1, candidate_start, *target, block_offsets)?;
        }
        X64Terminator::Branch {
            if_true, if_false, ..
        } => {
            verify_equal_except_offsets(baseline, candidate, &[12, 17])?;
            verify_target(candidate, 12, candidate_start, *if_true, block_offsets)?;
            verify_target(candidate, 17, candidate_start, *if_false, block_offsets)?;
        }
        X64Terminator::Return { .. } => return Err(kind_drift()),
    }
    Ok(())
}

fn verify_target(
    bytes: &[u8],
    displacement: usize,
    candidate_start: u32,
    block: u32,
    block_offsets: &[u32],
) -> Result<(), ResidencyEncodingError> {
    let expected = *block_offsets.get(block as usize).ok_or_else(|| {
        ResidencyEncodingError::Encoding(format!("missing candidate block b{block}"))
    })?;
    if rel32_target(bytes, displacement, candidate_start)? != expected as i64 {
        return Err(ResidencyEncodingError::Encoding(
            "candidate control-flow target drifted".into(),
        ));
    }
    Ok(())
}

fn verify_equal_except_rel32(
    baseline: &[u8],
    candidate: &[u8],
    patterns: &[&[u8]],
) -> Result<(), ResidencyEncodingError> {
    let offsets = patterns
        .iter()
        .map(|pattern| unique_pattern(candidate, pattern).map(|offset| offset + pattern.len()))
        .collect::<Result<Vec<_>, _>>()?;
    verify_equal_except_offsets(baseline, candidate, &offsets)
}

fn verify_equal_except_offsets(
    baseline: &[u8],
    candidate: &[u8],
    displacements: &[usize],
) -> Result<(), ResidencyEncodingError> {
    if baseline.len() != candidate.len() {
        return Err(ResidencyEncodingError::Encoding(
            "passthrough range width drifted".into(),
        ));
    }
    for (index, (left, right)) in baseline.iter().zip(candidate).enumerate() {
        let ignored = displacements
            .iter()
            .any(|start| index >= *start && index < start.saturating_add(4));
        if !ignored && left != right {
            return Err(ResidencyEncodingError::Encoding(
                "passthrough opcode or immediate drifted".into(),
            ));
        }
    }
    Ok(())
}

fn unique_pattern(bytes: &[u8], pattern: &[u8]) -> Result<usize, ResidencyEncodingError> {
    let offsets = bytes
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == pattern).then_some(offset))
        .collect::<Vec<_>>();
    match offsets.as_slice() {
        [offset] => Ok(*offset),
        _ => Err(ResidencyEncodingError::Encoding(format!(
            "expected one {:?} opcode, found {}",
            pattern,
            offsets.len()
        ))),
    }
}

fn rel32_target(
    bytes: &[u8],
    displacement: usize,
    range_start: u32,
) -> Result<i64, ResidencyEncodingError> {
    let raw = bytes.get(displacement..displacement + 4).ok_or_else(|| {
        ResidencyEncodingError::Encoding("rel32 displacement is truncated".into())
    })?;
    let relative = i32::from_le_bytes(raw.try_into().expect("four-byte slice"));
    Ok(i64::from(range_start) + displacement as i64 + 4 + i64::from(relative))
}

fn emit_store_r12(bytes: &mut Vec<u8>, home: StackHome) {
    bytes.extend_from_slice(&expected_store_r12(home));
}

fn emit_load_r12(bytes: &mut Vec<u8>, home: StackHome) {
    bytes.extend_from_slice(&expected_load_r12(home));
}

fn expected_store_r12(home: StackHome) -> [u8; 7] {
    let displacement = home.displacement.to_le_bytes();
    [
        0x4c,
        0x89,
        0xa5,
        displacement[0],
        displacement[1],
        displacement[2],
        displacement[3],
    ]
}

fn expected_load_r12(home: StackHome) -> [u8; 7] {
    let displacement = home.displacement.to_le_bytes();
    [
        0x4c,
        0x8b,
        0xa5,
        displacement[0],
        displacement[1],
        displacement[2],
        displacement[3],
    ]
}

fn patch_rel32(
    bytes: &mut [u8],
    displacement: usize,
    target: u32,
) -> Result<(), ResidencyEncodingError> {
    let next = displacement
        .checked_add(4)
        .ok_or_else(|| ResidencyEncodingError::Encoding("rel32 origin overflowed".into()))?;
    let relative = i64::from(target) - next as i64;
    let relative = i32::try_from(relative)
        .map_err(|_| ResidencyEncodingError::Encoding("rel32 target is out of range".into()))?;
    let target_bytes = bytes.get_mut(displacement..next).ok_or_else(|| {
        ResidencyEncodingError::Encoding("rel32 displacement is out of bounds".into())
    })?;
    target_bytes.copy_from_slice(&relative.to_le_bytes());
    Ok(())
}

fn as_u32(value: usize, label: &str) -> Result<u32, ResidencyEncodingError> {
    u32::try_from(value).map_err(|_| {
        ResidencyEncodingError::Encoding(format!("{label} exceeds the u32 receipt boundary"))
    })
}

fn kind_drift() -> ResidencyEncodingError {
    ResidencyEncodingError::Encoding("candidate range kind or source alignment drifted".into())
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
