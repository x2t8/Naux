//! Role-four specialization of the sealed WP7B timing wrapper.
//!
//! WP7B deliberately serializes role owner one for the retained baseline.  The
//! register-residency candidate is a separate role, so this module changes the
//! single post-clock owner literal to four and independently reconstructs that
//! exact specialization.  The embedded process target is never modified.

use crate::process::ProcessTarget;
use crate::timing::{build_timing_elf64, TimingElf64, TimingElf64Facts};
use std::fmt;

const BASELINE_OWNER: u64 = 1;
const CANDIDATE_OWNER: u64 = 4;
const OWNER_OFFSET: u8 = 72;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateTimingElfError {
    Parent(String),
    Specialization(String),
}

impl fmt::Display for CandidateTimingElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parent(message) => write!(formatter, "S4-WP8J parent wrapper error: {message}"),
            Self::Specialization(message) => {
                write!(formatter, "S4-WP8J role specialization error: {message}")
            }
        }
    }
}

impl std::error::Error for CandidateTimingElfError {}

/// Build the exact WP7B wrapper and specialize only its serialized role owner.
pub fn build_candidate_timing_elf64(
    process: &ProcessTarget,
    ordinal: u64,
    oracle: i64,
) -> Result<TimingElf64, CandidateTimingElfError> {
    let image = build_timing_elf64(process, ordinal, oracle)
        .map_err(|error| CandidateTimingElfError::Parent(error.to_string()))?;
    specialize(image, process)
}

/// Reconstruct and verify the complete role-four image.
#[cfg_attr(not(test), allow(dead_code))]
pub fn verify_candidate_timing_elf64(
    image: &TimingElf64,
    process: &ProcessTarget,
) -> Result<TimingElf64Facts, CandidateTimingElfError> {
    let baseline = build_timing_elf64(process, image.ordinal, image.oracle)
        .map_err(|error| CandidateTimingElfError::Parent(error.to_string()))?;
    let expected = specialize(baseline, process)?;
    if image != &expected
        || image.bytes.get(image.target_offset as usize..) != Some(process.bytes.as_slice())
    {
        return Err(CandidateTimingElfError::Specialization(
            "image differs from independent role-four reconstruction".into(),
        ));
    }
    Ok(TimingElf64Facts {
        entry: 0x0040_0100,
        image_bytes: image.bytes.len() as u64,
        startup_bytes: u64::from(image.startup_bytes),
        target_offset: u64::from(image.target_offset),
        target_bytes: u64::from(image.target_bytes),
        result_bytes: 56,
        clock_reads: 2,
        owner_zero_checks: 1,
        result_owner: CANDIDATE_OWNER,
        load_flags: 5,
        stack_flags: 6,
    })
}

fn specialize(
    mut image: TimingElf64,
    process: &ProcessTarget,
) -> Result<TimingElf64, CandidateTimingElfError> {
    let pattern = owner_store(BASELINE_OWNER);
    let replacement = owner_store(CANDIDATE_OWNER);
    let startup = image
        .bytes
        .get_mut(0x100..image.target_offset as usize)
        .ok_or_else(|| {
            CandidateTimingElfError::Specialization("startup extent is invalid".into())
        })?;
    let positions: Vec<usize> = startup
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(index, window)| (window == pattern).then_some(index))
        .collect();
    if positions.len() != 1 {
        return Err(CandidateTimingElfError::Specialization(format!(
            "expected one role-owner literal, observed {}",
            positions.len()
        )));
    }
    let position = positions[0];
    startup[position..position + replacement.len()].copy_from_slice(&replacement);
    if image.bytes.get(image.target_offset as usize..) != Some(process.bytes.as_slice()) {
        return Err(CandidateTimingElfError::Specialization(
            "role specialization changed the process target".into(),
        ));
    }
    Ok(image)
}

fn owner_store(owner: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(15);
    bytes.extend_from_slice(&[0x49, 0xb8]);
    bytes.extend_from_slice(&owner.to_le_bytes());
    bytes.extend_from_slice(&[0x4c, 0x89, 0x44, 0x24, OWNER_OFFSET]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_owner_sequences_are_distinct_and_fixed_width() {
        let baseline = owner_store(BASELINE_OWNER);
        let candidate = owner_store(CANDIDATE_OWNER);
        assert_eq!(baseline.len(), candidate.len());
        assert_ne!(baseline, candidate);
        assert_eq!(&candidate[..2], &[0x49, 0xb8]);
        assert_eq!(&candidate[10..], &[0x4c, 0x89, 0x44, 0x24, OWNER_OFFSET]);
    }
}
