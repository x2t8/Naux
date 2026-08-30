//! Fresh-process completion witness for verified WP8E residency bytes.
//!
//! This module preserves the admitted WP8E target except for the final
//! canonical 16-byte restore-and-return sequence, which becomes a same-width
//! jump to an appended completion verifier. The verified WP5E startup/envelope is reused
//! to serialize one fixed 48-byte record. No checksum oracle is embedded.

use crate::baseline::{StackHome, X64Plan, X64Terminator};
use crate::machine::{MachineType, ResidualMachineProgram};
use crate::process_envelope::{
    build_process_elf64, verify_process_elf64, CompletionWitness, ProcessElf64, ProcessElfError,
    ProcessTarget,
};
use crate::residency::ResidencyPlan;
use crate::residency_encoding::{
    verify_register_residency_encoding, CandidateRangeKind, ResidencyEncodedX64,
};
use crate::residual::WorkWitness;
use std::fmt;

const MAX_TARGET_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidencyProcessError {
    Parent(String),
    InvalidWitness(String),
    InvalidTarget(String),
    InvalidElf(String),
}

impl fmt::Display for ResidencyProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, message) = match self {
            Self::Parent(message) => ("parent", message),
            Self::InvalidWitness(message) => ("completion witness", message),
            Self::InvalidTarget(message) => ("process target", message),
            Self::InvalidElf(message) => ("process ELF64", message),
        };
        write!(formatter, "S4-WP8G residency {kind} error: {message}")
    }
}

impl std::error::Error for ResidencyProcessError {}

impl From<ProcessElfError> for ResidencyProcessError {
    fn from(error: ProcessElfError) -> Self {
        match error {
            ProcessElfError::Parent(message) => Self::Parent(message),
            ProcessElfError::InvalidWitness(message) => Self::InvalidWitness(message),
            ProcessElfError::InvalidTarget(message) => Self::InvalidTarget(message),
            ProcessElfError::InvalidElf(message) => Self::InvalidElf(message),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn append_residency_completion_witness(
    machine: &ResidualMachineProgram,
    baseline_plan: &X64Plan,
    residency_plan: &ResidencyPlan,
    baseline: &crate::baseline::EncodedX64,
    candidate: &ResidencyEncodedX64,
    work: &WorkWitness,
    owner_local: u32,
) -> Result<ProcessTarget, ResidencyProcessError> {
    verify_parent(machine, baseline_plan, residency_plan, baseline, candidate)?;
    let (witness, return_home, outer_home, inner_home, owner_home, promoted_home) =
        witness_inputs(baseline_plan, residency_plan, candidate, work, owner_local)?;
    let bytes = reconstruct_process_target(
        candidate,
        &witness,
        return_home,
        outer_home,
        inner_home,
        owner_home,
        promoted_home,
    )?;
    let process = ProcessTarget { bytes, witness };
    verify_residency_process_target(
        machine,
        baseline_plan,
        residency_plan,
        baseline,
        candidate,
        work,
        owner_local,
        &process,
    )?;
    Ok(process)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_residency_process_target(
    machine: &ResidualMachineProgram,
    baseline_plan: &X64Plan,
    residency_plan: &ResidencyPlan,
    baseline: &crate::baseline::EncodedX64,
    candidate: &ResidencyEncodedX64,
    work: &WorkWitness,
    owner_local: u32,
    process: &ProcessTarget,
) -> Result<(), ResidencyProcessError> {
    verify_parent(machine, baseline_plan, residency_plan, baseline, candidate)?;
    let (witness, return_home, outer_home, inner_home, owner_home, promoted_home) =
        witness_inputs(baseline_plan, residency_plan, candidate, work, owner_local)?;
    if process.witness != witness {
        return Err(ResidencyProcessError::InvalidWitness(
            "receipt differs from independently derived WP8G witness".into(),
        ));
    }
    let expected = reconstruct_process_target(
        candidate,
        &witness,
        return_home,
        outer_home,
        inner_home,
        owner_home,
        promoted_home,
    )?;
    if process.bytes != expected || process.bytes.len() > MAX_TARGET_BYTES {
        return Err(ResidencyProcessError::InvalidTarget(
            "target differs from exact reconstruction or exceeds its limit".into(),
        ));
    }
    Ok(())
}

pub fn build_residency_process_elf64(
    process: &ProcessTarget,
    ordinal: u64,
) -> Result<ProcessElf64, ResidencyProcessError> {
    let image = build_process_elf64(process, ordinal)?;
    verify_process_elf64(&image, process)?;
    Ok(image)
}

fn verify_parent(
    machine: &ResidualMachineProgram,
    baseline_plan: &X64Plan,
    residency_plan: &ResidencyPlan,
    baseline: &crate::baseline::EncodedX64,
    candidate: &ResidencyEncodedX64,
) -> Result<(), ResidencyProcessError> {
    verify_register_residency_encoding(machine, baseline_plan, residency_plan, baseline, candidate)
        .map_err(|error| ResidencyProcessError::Parent(error.to_string()))
}

fn witness_inputs(
    plan: &X64Plan,
    residency_plan: &ResidencyPlan,
    candidate: &ResidencyEncodedX64,
    work: &WorkWitness,
    owner_local: u32,
) -> Result<
    (
        CompletionWitness,
        StackHome,
        StackHome,
        StackHome,
        StackHome,
        StackHome,
    ),
    ResidencyProcessError,
> {
    if work.outer.bound == 0
        || work.inner.bound == 0
        || work.inner.bound != plan.list_length
        || work.traversal_count
            != work
                .outer
                .bound
                .checked_mul(work.inner.bound)
                .ok_or_else(|| {
                    ResidencyProcessError::InvalidWitness("traversal count overflowed".into())
                })?
    {
        return Err(ResidencyProcessError::InvalidWitness(
            "loop bounds do not match the sealed traversal witness".into(),
        ));
    }
    let outer_home = slot_home(plan, work.outer.counter_local, MachineType::I64, "outer")?;
    let inner_home = slot_home(plan, work.inner.counter_local, MachineType::I64, "inner")?;
    let owner_home = slot_home(plan, owner_local, MachineType::OwnedI64List, "owner")?;
    let _checksum_home = slot_home(plan, work.checksum_local, MachineType::I64, "checksum")?;
    let promoted_home = slot_home(
        plan,
        residency_plan.promoted_slot,
        MachineType::I64,
        "promoted",
    )?;
    if promoted_home != outer_home && promoted_home != inner_home {
        return Err(ResidencyProcessError::InvalidWitness(
            "promoted slot is not one of the sealed loop counters".into(),
        ));
    }

    let returns = plan
        .blocks
        .iter()
        .filter_map(|block| match block.terminator {
            X64Terminator::Return { value } => Some((block, value)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if returns.len() != 1 {
        return Err(ResidencyProcessError::InvalidWitness(format!(
            "expected one completion return, found {}",
            returns.len()
        )));
    }
    let (block, return_home) = returns[0];
    let range = candidate
        .ranges
        .iter()
        .find(|range| {
            range.block == block.id
                && range.kind == CandidateRangeKind::ReturnWithRestore
                && range.ordinal == block.operations.len() as u32
        })
        .ok_or_else(|| {
            ResidencyProcessError::InvalidWitness("candidate completion return is missing".into())
        })?;
    if range.end != candidate.error_offset
        || range.end.checked_sub(range.start) != Some(16)
        || return_home.ty != MachineType::I64
    {
        return Err(ResidencyProcessError::InvalidWitness(
            "candidate completion return is not restore plus checksum load".into(),
        ));
    }
    let witness = CompletionWitness {
        return_start: range.start,
        verifier_offset: as_u32(candidate.bytes.len(), "verifier offset")?,
        error_offset: candidate.error_offset,
        checksum_displacement: return_home.displacement,
        outer_displacement: outer_home.displacement,
        inner_displacement: inner_home.displacement,
        owner_displacement: owner_home.displacement,
        expected_outer: work.outer.bound,
        expected_inner: work.inner.bound,
    };
    Ok((
        witness,
        return_home,
        outer_home,
        inner_home,
        owner_home,
        promoted_home,
    ))
}

fn slot_home(
    plan: &X64Plan,
    local: u32,
    ty: MachineType,
    label: &str,
) -> Result<StackHome, ResidencyProcessError> {
    let home = *plan.slot_homes.get(local as usize).ok_or_else(|| {
        ResidencyProcessError::InvalidWitness(format!("{label} local escapes target slots"))
    })?;
    if home.index != local || home.ty != ty {
        return Err(ResidencyProcessError::InvalidWitness(format!(
            "{label} home has the wrong identity or type"
        )));
    }
    Ok(home)
}

fn reconstruct_process_target(
    candidate: &ResidencyEncodedX64,
    witness: &CompletionWitness,
    return_home: StackHome,
    outer_home: StackHome,
    inner_home: StackHome,
    owner_home: StackHome,
    promoted_home: StackHome,
) -> Result<Vec<u8>, ResidencyProcessError> {
    let start = witness.return_start as usize;
    let end = start
        .checked_add(16)
        .ok_or_else(|| ResidencyProcessError::InvalidTarget("return range overflowed".into()))?;
    let expected_return = load_bytes(0x85, return_home);
    if candidate.bytes.get(start..start + 7) != Some(load_r12(promoted_home).as_slice())
        || candidate.bytes.get(start + 7..start + 14) != Some(expected_return.as_slice())
        || candidate.bytes.get(start + 14..end) != Some(&[0xc9, 0xc3])
        || witness.verifier_offset as usize != candidate.bytes.len()
    {
        return Err(ResidencyProcessError::InvalidTarget(
            "admitted candidate return bytes drifted".into(),
        ));
    }

    let mut bytes = candidate.bytes.clone();
    let verifier = candidate.bytes.len();
    bytes[start] = 0xe9;
    patch_rel32(&mut bytes, start + 1, verifier)?;
    bytes[start + 5..end].fill(0x90);

    bytes.extend_from_slice(&load_bytes(0x85, return_home));
    if promoted_home == outer_home {
        bytes.extend_from_slice(&[0x4c, 0x89, 0xe1]);
    } else {
        bytes.extend_from_slice(&load_bytes(0x8d, outer_home));
    }
    mov_r8_imm64(&mut bytes, witness.expected_outer);
    bytes.extend_from_slice(&[0x4c, 0x39, 0xc1]);
    emit_rel32(&mut bytes, &[0x0f, 0x85], witness.error_offset as usize)?;
    if promoted_home == inner_home {
        bytes.extend_from_slice(&[0x4c, 0x89, 0xe2]);
    } else {
        bytes.extend_from_slice(&load_bytes(0x95, inner_home));
    }
    mov_r8_imm64(&mut bytes, witness.expected_inner);
    bytes.extend_from_slice(&[0x4c, 0x39, 0xc2]);
    emit_rel32(&mut bytes, &[0x0f, 0x85], witness.error_offset as usize)?;
    bytes.extend_from_slice(&load_bytes(0xb5, owner_home));
    bytes.extend_from_slice(&[0x48, 0x85, 0xf6]);
    emit_rel32(&mut bytes, &[0x0f, 0x85], witness.error_offset as usize)?;
    bytes.extend_from_slice(&load_r12(promoted_home));
    bytes.extend_from_slice(&[0xc9, 0xc3]);
    Ok(bytes)
}

fn load_bytes(modrm: u8, home: StackHome) -> Vec<u8> {
    let mut bytes = vec![0x48, 0x8b, modrm];
    bytes.extend_from_slice(&home.displacement.to_le_bytes());
    bytes
}

fn load_r12(home: StackHome) -> Vec<u8> {
    let mut bytes = vec![0x4c, 0x8b, 0xa5];
    bytes.extend_from_slice(&home.displacement.to_le_bytes());
    bytes
}

fn mov_r8_imm64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&[0x49, 0xb8]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn emit_rel32(
    bytes: &mut Vec<u8>,
    opcode: &[u8],
    target: usize,
) -> Result<(), ResidencyProcessError> {
    bytes.extend_from_slice(opcode);
    let displacement = bytes.len();
    bytes.extend_from_slice(&[0; 4]);
    patch_rel32(bytes, displacement, target)
}

fn patch_rel32(
    bytes: &mut [u8],
    displacement: usize,
    target: usize,
) -> Result<(), ResidencyProcessError> {
    let next = displacement
        .checked_add(4)
        .ok_or_else(|| ResidencyProcessError::InvalidTarget("rel32 overflowed".into()))?;
    let delta = i64::try_from(target).unwrap_or(i64::MAX) - i64::try_from(next).unwrap_or(i64::MIN);
    let delta = i32::try_from(delta)
        .map_err(|_| ResidencyProcessError::InvalidTarget("rel32 target is out of range".into()))?;
    let destination = bytes.get_mut(displacement..next).ok_or_else(|| {
        ResidencyProcessError::InvalidTarget("rel32 displacement escapes target".into())
    })?;
    destination.copy_from_slice(&delta.to_le_bytes());
    Ok(())
}

fn as_u32(value: usize, label: &str) -> Result<u32, ResidencyProcessError> {
    u32::try_from(value).map_err(|_| {
        ResidencyProcessError::InvalidTarget(format!("{label} exceeds u32 receipt boundary"))
    })
}
