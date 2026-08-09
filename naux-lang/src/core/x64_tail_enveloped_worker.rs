//! Child-only ADR-0069 construction boundary.
//!
//! Keeping this module separate prevents the parent process verifier from
//! importing the ADR-0068 native emitter even though both live in one seed
//! crate during the Rust-debt phase.

use super::x64_tail_enveloped_correspondence::{
    emit_x64_tail_enveloped_correspondence, X64TailEnvelopedCorrespondenceError,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_ACCEPTED_ROOT,
};
use super::x64_tail_enveloped_ipc::{encode_x64_tail_enveloped_ipc, X64TailEnvelopedIpcError};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedWorkerError {
    UnsupportedHost,
    Correspondence(X64TailEnvelopedCorrespondenceError),
    Ipc(X64TailEnvelopedIpcError),
    AcceptedRootMismatch,
}

impl fmt::Display for X64TailEnvelopedWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => formatter.write_str("ADR-0069 worker requires Linux x86-64"),
            Self::Correspondence(error) => write!(formatter, "ADR-0068 emission failed: {error}"),
            Self::Ipc(error) => write!(formatter, "{error}"),
            Self::AcceptedRootMismatch => {
                formatter.write_str("ADR-0069 worker regenerated a non-accepted ADR-0068 root")
            }
        }
    }
}

impl std::error::Error for X64TailEnvelopedWorkerError {}

impl From<X64TailEnvelopedCorrespondenceError> for X64TailEnvelopedWorkerError {
    fn from(value: X64TailEnvelopedCorrespondenceError) -> Self {
        Self::Correspondence(value)
    }
}

impl From<X64TailEnvelopedIpcError> for X64TailEnvelopedWorkerError {
    fn from(value: X64TailEnvelopedIpcError) -> Self {
        Self::Ipc(value)
    }
}

/// Regenerate the accepted ADR-0068 observation and encode exactly one frame.
#[doc(hidden)]
pub fn emit_x64_tail_enveloped_worker_frame_adr0069() -> Result<Vec<u8>, X64TailEnvelopedWorkerError>
{
    if !cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        return Err(X64TailEnvelopedWorkerError::UnsupportedHost);
    }
    let evidence = emit_x64_tail_enveloped_correspondence()?;
    if evidence.evidence_hash() != X64_TAIL_ENVELOPED_CORRESPONDENCE_ACCEPTED_ROOT {
        return Err(X64TailEnvelopedWorkerError::AcceptedRootMismatch);
    }
    Ok(encode_x64_tail_enveloped_ipc(&evidence)?)
}
