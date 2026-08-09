//! Fixed-width canonical IPC commitment for ADR-0053 candidate workers.
//!
//! The full ADR-0052 correctness record remains in the verified parent
//! evidence. A child transports its exact record hash plus every routing
//! identity needed to bind that commitment to one canonical case.

use super::corevm0_gate_a::{CoreVmGateAError, CoreVmGateAWorkload};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_candidate_admission::{
    x64_gate_b_policy15_candidate_accepted_correctness_results_hash,
    x64_gate_b_policy15_candidate_correctness_record_hash,
    X64GateBPolicy15CandidateCorrectnessError, X64GateBPolicy15CandidateCorrectnessRecord,
    X64GateBPolicy15CandidateSelection, X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION,
    X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION,
};
use super::x64_native_lighthouse::{x64_native_lighthouse_case, X64NativeLighthouseError};
use super::x64_target::x64_target_policy15_accepted_candidate_capsule_hash;
use std::fmt;

pub const X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_CANDIDATE_IPC_MAX_FRAME_BYTES: u64 = 512;

const IPC_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-process:ipc:v1\0";
const VERSION_BYTES: usize = 6;
const HASH_BYTES: usize = 32;
const FRAME_BYTES: usize = IPC_DOMAIN.len()
    + (4 * VERSION_BYTES)
    + (3 * HASH_BYTES)
    + 4
    + 1
    + 1
    + HASH_BYTES
    + HASH_BYTES
    + HASH_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15CandidateIpcRecord {
    ipc_schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    correctness_schema_version: (u16, u16, u16),
    correctness_policy_version: (u16, u16, u16),
    corpus_manifest_hash: SemanticHash,
    correctness_results_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    case_ordinal: u32,
    workload: CoreVmGateAWorkload,
    selection: X64GateBPolicy15CandidateSelection,
    input_hash: SemanticHash,
    correctness_record_hash: SemanticHash,
    frame_hash: SemanticHash,
}

impl X64GateBPolicy15CandidateIpcRecord {
    pub const fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub const fn workload(&self) -> CoreVmGateAWorkload {
        self.workload
    }

    pub const fn selection(&self) -> X64GateBPolicy15CandidateSelection {
        self.selection
    }

    pub const fn input_hash(&self) -> SemanticHash {
        self.input_hash
    }

    pub const fn correctness_results_hash(&self) -> SemanticHash {
        self.correctness_results_hash
    }

    pub const fn candidate_capsule_hash(&self) -> SemanticHash {
        self.candidate_capsule_hash
    }

    pub const fn correctness_record_hash(&self) -> SemanticHash {
        self.correctness_record_hash
    }

    pub const fn frame_hash(&self) -> SemanticHash {
        self.frame_hash
    }
}

#[derive(Debug)]
pub enum X64GateBPolicy15CandidateIpcError {
    Corpus(CoreVmGateAError),
    Lighthouse(String),
    Correctness(X64GateBPolicy15CandidateCorrectnessError),
    FrameLength { expected: usize, actual: usize },
    InvalidDomain,
    InvalidVersion { field: &'static str },
    InvalidIdentity { field: &'static str },
    WrongCase { expected: u32, actual: u32 },
    WrongWorkload { case_ordinal: u32 },
    WrongSelection { case_ordinal: u32 },
    WrongInput { case_ordinal: u32 },
    UnknownTag { field: &'static str, actual: u8 },
    RecordHashMismatch { case_ordinal: u32 },
    FrameHashMismatch,
    NonCanonicalEncoding,
}

impl fmt::Display for X64GateBPolicy15CandidateIpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(error) => write!(formatter, "candidate IPC corpus failed: {error}"),
            Self::Lighthouse(error) => {
                write!(formatter, "candidate IPC lighthouse failed: {error}")
            }
            Self::Correctness(error) => write!(formatter, "candidate IPC record failed: {error}"),
            Self::FrameLength { expected, actual } => write!(
                formatter,
                "candidate IPC frame uses {actual} bytes; canonical length is {expected}"
            ),
            Self::InvalidDomain => formatter.write_str("candidate IPC domain is invalid"),
            Self::InvalidVersion { field } => {
                write!(formatter, "candidate IPC {field} version is invalid")
            }
            Self::InvalidIdentity { field } => {
                write!(formatter, "candidate IPC {field} identity is invalid")
            }
            Self::WrongCase { expected, actual } => write!(
                formatter,
                "candidate IPC expected case {expected}, found {actual}"
            ),
            Self::WrongWorkload { case_ordinal } => {
                write!(
                    formatter,
                    "candidate IPC case {case_ordinal} has wrong workload"
                )
            }
            Self::WrongSelection { case_ordinal } => {
                write!(
                    formatter,
                    "candidate IPC case {case_ordinal} has wrong selection"
                )
            }
            Self::WrongInput { case_ordinal } => {
                write!(
                    formatter,
                    "candidate IPC case {case_ordinal} has wrong input"
                )
            }
            Self::UnknownTag { field, actual } => {
                write!(formatter, "candidate IPC {field} has unknown tag {actual}")
            }
            Self::RecordHashMismatch { case_ordinal } => write!(
                formatter,
                "candidate IPC case {case_ordinal} correctness record is not sealed"
            ),
            Self::FrameHashMismatch => formatter.write_str("candidate IPC frame seal is invalid"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("candidate IPC frame encoding is not canonical")
            }
        }
    }
}

impl std::error::Error for X64GateBPolicy15CandidateIpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Corpus(error) => Some(error),
            Self::Correctness(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreVmGateAError> for X64GateBPolicy15CandidateIpcError {
    fn from(value: CoreVmGateAError) -> Self {
        Self::Corpus(value)
    }
}

impl From<X64NativeLighthouseError> for X64GateBPolicy15CandidateIpcError {
    fn from(value: X64NativeLighthouseError) -> Self {
        Self::Lighthouse(value.to_string())
    }
}

impl From<X64GateBPolicy15CandidateCorrectnessError> for X64GateBPolicy15CandidateIpcError {
    fn from(value: X64GateBPolicy15CandidateCorrectnessError) -> Self {
        Self::Correctness(value)
    }
}

pub fn seal_x64_gate_b_policy15_candidate_ipc_record(
    correctness: &X64GateBPolicy15CandidateCorrectnessRecord,
) -> Result<X64GateBPolicy15CandidateIpcRecord, X64GateBPolicy15CandidateIpcError> {
    if x64_gate_b_policy15_candidate_correctness_record_hash(correctness)?
        != correctness.record_hash()
    {
        return Err(X64GateBPolicy15CandidateIpcError::RecordHashMismatch {
            case_ordinal: correctness.case_ordinal(),
        });
    }
    let case = x64_native_lighthouse_case(correctness.case_ordinal())?;
    let manifest = super::corevm0_gate_a::corevm0_gate_a_manifest()?;
    let mut record = X64GateBPolicy15CandidateIpcRecord {
        ipc_schema_version: X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION,
        process_policy_version: X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION,
        correctness_schema_version: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION,
        correctness_policy_version: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION,
        corpus_manifest_hash: manifest.manifest_hash,
        correctness_results_hash: x64_gate_b_policy15_candidate_accepted_correctness_results_hash(),
        candidate_capsule_hash: correctness.candidate_capsule_hash(),
        case_ordinal: correctness.case_ordinal(),
        workload: correctness.workload(),
        selection: correctness.selection(),
        input_hash: correctness.input_hash(),
        correctness_record_hash: correctness.record_hash(),
        frame_hash: SemanticHash::ZERO,
    };
    validate_record(&record, case.ordinal)?;
    record.frame_hash = candidate_ipc_hash(&record)?;
    Ok(record)
}

pub fn encode_x64_gate_b_policy15_candidate_ipc_record(
    record: &X64GateBPolicy15CandidateIpcRecord,
) -> Result<Vec<u8>, X64GateBPolicy15CandidateIpcError> {
    validate_record(record, record.case_ordinal)?;
    if candidate_ipc_hash(record)? != record.frame_hash {
        return Err(X64GateBPolicy15CandidateIpcError::FrameHashMismatch);
    }
    let mut bytes = candidate_ipc_preimage(record);
    bytes.extend_from_slice(&record.frame_hash.0);
    debug_assert_eq!(bytes.len(), FRAME_BYTES);
    Ok(bytes)
}

pub fn decode_x64_gate_b_policy15_candidate_ipc_record(
    bytes: &[u8],
    expected_case_ordinal: u32,
) -> Result<X64GateBPolicy15CandidateIpcRecord, X64GateBPolicy15CandidateIpcError> {
    if bytes.len() != FRAME_BYTES {
        return Err(X64GateBPolicy15CandidateIpcError::FrameLength {
            expected: FRAME_BYTES,
            actual: bytes.len(),
        });
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(IPC_DOMAIN.len()) != IPC_DOMAIN {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidDomain);
    }
    let record = X64GateBPolicy15CandidateIpcRecord {
        ipc_schema_version: cursor.version(),
        process_policy_version: cursor.version(),
        correctness_schema_version: cursor.version(),
        correctness_policy_version: cursor.version(),
        corpus_manifest_hash: cursor.hash(),
        correctness_results_hash: cursor.hash(),
        candidate_capsule_hash: cursor.hash(),
        case_ordinal: cursor.u32(),
        workload: decode_workload(cursor.u8())?,
        selection: decode_selection(cursor.u8())?,
        input_hash: cursor.hash(),
        correctness_record_hash: cursor.hash(),
        frame_hash: cursor.hash(),
    };
    debug_assert_eq!(cursor.offset, FRAME_BYTES);
    validate_record(&record, expected_case_ordinal)?;
    if candidate_ipc_hash(&record)? != record.frame_hash {
        return Err(X64GateBPolicy15CandidateIpcError::FrameHashMismatch);
    }
    if encode_x64_gate_b_policy15_candidate_ipc_record(&record)? != bytes {
        return Err(X64GateBPolicy15CandidateIpcError::NonCanonicalEncoding);
    }
    Ok(record)
}

fn validate_record(
    record: &X64GateBPolicy15CandidateIpcRecord,
    expected_case_ordinal: u32,
) -> Result<(), X64GateBPolicy15CandidateIpcError> {
    if record.ipc_schema_version != X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidVersion { field: "IPC" });
    }
    if record.process_policy_version != X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidVersion { field: "process" });
    }
    if record.correctness_schema_version != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION
    {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidVersion {
            field: "correctness schema",
        });
    }
    if record.correctness_policy_version != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION
    {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidVersion {
            field: "correctness policy",
        });
    }
    if record.case_ordinal != expected_case_ordinal {
        return Err(X64GateBPolicy15CandidateIpcError::WrongCase {
            expected: expected_case_ordinal,
            actual: record.case_ordinal,
        });
    }
    let manifest = super::corevm0_gate_a::corevm0_gate_a_manifest()?;
    if record.corpus_manifest_hash != manifest.manifest_hash {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidIdentity { field: "manifest" });
    }
    if record.correctness_results_hash
        != x64_gate_b_policy15_candidate_accepted_correctness_results_hash()
    {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidIdentity {
            field: "ADR-0052 correctness result",
        });
    }
    if record.candidate_capsule_hash != x64_target_policy15_accepted_candidate_capsule_hash() {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidIdentity {
            field: "ADR-0051 capsule",
        });
    }
    if record.correctness_record_hash == SemanticHash::ZERO {
        return Err(X64GateBPolicy15CandidateIpcError::InvalidIdentity {
            field: "correctness record",
        });
    }
    let case = x64_native_lighthouse_case(record.case_ordinal)?;
    if record.workload != case.workload {
        return Err(X64GateBPolicy15CandidateIpcError::WrongWorkload {
            case_ordinal: record.case_ordinal,
        });
    }
    let expected_selection = match case.workload {
        CoreVmGateAWorkload::BranchMix => X64GateBPolicy15CandidateSelection::Policy15Candidate,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => {
            X64GateBPolicy15CandidateSelection::Policy14Fallback
        }
    };
    if record.selection != expected_selection {
        return Err(X64GateBPolicy15CandidateIpcError::WrongSelection {
            case_ordinal: record.case_ordinal,
        });
    }
    if record.input_hash != case.input_hash {
        return Err(X64GateBPolicy15CandidateIpcError::WrongInput {
            case_ordinal: record.case_ordinal,
        });
    }
    Ok(())
}

fn candidate_ipc_hash(
    record: &X64GateBPolicy15CandidateIpcRecord,
) -> Result<SemanticHash, X64GateBPolicy15CandidateIpcError> {
    validate_record(record, record.case_ordinal)?;
    Ok(SemanticHash(sha256(&candidate_ipc_preimage(record))))
}

fn candidate_ipc_preimage(record: &X64GateBPolicy15CandidateIpcRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FRAME_BYTES - HASH_BYTES);
    bytes.extend_from_slice(IPC_DOMAIN);
    put_version(&mut bytes, record.ipc_schema_version);
    put_version(&mut bytes, record.process_policy_version);
    put_version(&mut bytes, record.correctness_schema_version);
    put_version(&mut bytes, record.correctness_policy_version);
    for hash in [
        record.corpus_manifest_hash,
        record.correctness_results_hash,
        record.candidate_capsule_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    bytes.extend_from_slice(&record.case_ordinal.to_be_bytes());
    bytes.push(workload_tag(record.workload));
    bytes.push(selection_tag(record.selection));
    bytes.extend_from_slice(&record.input_hash.0);
    bytes.extend_from_slice(&record.correctness_record_hash.0);
    bytes
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

const fn workload_tag(workload: CoreVmGateAWorkload) -> u8 {
    match workload {
        CoreVmGateAWorkload::BranchMix => 0,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => 1,
    }
}

fn decode_workload(tag: u8) -> Result<CoreVmGateAWorkload, X64GateBPolicy15CandidateIpcError> {
    match tag {
        0 => Ok(CoreVmGateAWorkload::BranchMix),
        1 => Ok(CoreVmGateAWorkload::BoundsOrderedArrayGet),
        actual => Err(X64GateBPolicy15CandidateIpcError::UnknownTag {
            field: "workload",
            actual,
        }),
    }
}

const fn selection_tag(selection: X64GateBPolicy15CandidateSelection) -> u8 {
    match selection {
        X64GateBPolicy15CandidateSelection::Policy15Candidate => 0,
        X64GateBPolicy15CandidateSelection::Policy14Fallback => 1,
    }
}

fn decode_selection(
    tag: u8,
) -> Result<X64GateBPolicy15CandidateSelection, X64GateBPolicy15CandidateIpcError> {
    match tag {
        0 => Ok(X64GateBPolicy15CandidateSelection::Policy15Candidate),
        1 => Ok(X64GateBPolicy15CandidateSelection::Policy14Fallback),
        actual => Err(X64GateBPolicy15CandidateIpcError::UnknownTag {
            field: "selection",
            actual,
        }),
    }
}

struct Cursor<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> Cursor<'bytes> {
    const fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> &'bytes [u8] {
        let start = self.offset;
        self.offset += length;
        &self.bytes[start..self.offset]
    }

    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn u16(&mut self) -> u16 {
        let bytes: [u8; 2] = self.take(2).try_into().expect("fixed frame slice");
        u16::from_be_bytes(bytes)
    }

    fn u32(&mut self) -> u32 {
        let bytes: [u8; 4] = self.take(4).try_into().expect("fixed frame slice");
        u32::from_be_bytes(bytes)
    }

    fn version(&mut self) -> (u16, u16, u16) {
        (self.u16(), self.u16(), self.u16())
    }

    fn hash(&mut self) -> SemanticHash {
        let bytes: [u8; HASH_BYTES] = self.take(HASH_BYTES).try_into().expect("fixed frame slice");
        SemanticHash(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::emit_x64_gate_b_policy15_candidate_process_record;

    #[test]
    fn canonical_candidate_ipc_round_trips_and_rejects_byte_mutations() {
        let correctness = emit_x64_gate_b_policy15_candidate_process_record(0)
            .expect("process reconstruction record");
        let record = seal_x64_gate_b_policy15_candidate_ipc_record(&correctness)
            .expect("candidate IPC record");
        let frame =
            encode_x64_gate_b_policy15_candidate_ipc_record(&record).expect("candidate IPC frame");
        assert!(frame.len() <= X64_GATE_B_POLICY15_CANDIDATE_IPC_MAX_FRAME_BYTES as usize);
        assert_eq!(
            decode_x64_gate_b_policy15_candidate_ipc_record(&frame, 0)
                .expect("candidate IPC decode"),
            record
        );

        for index in 0..frame.len() {
            let mut mutated = frame.clone();
            mutated[index] ^= 1;
            assert!(decode_x64_gate_b_policy15_candidate_ipc_record(&mutated, 0).is_err());
        }
        assert!(
            decode_x64_gate_b_policy15_candidate_ipc_record(&frame[..frame.len() - 1], 0).is_err()
        );
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode_x64_gate_b_policy15_candidate_ipc_record(&trailing, 0).is_err());
        assert!(decode_x64_gate_b_policy15_candidate_ipc_record(&frame, 1).is_err());
    }
}
