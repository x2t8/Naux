//! Candidate-specific standalone ELF composition for ADR-0054.
//!
//! The ordinary R1-S8 artifact types are intentionally not reused.  Only the
//! mechanical startup and ELF encoders/verifiers are shared, behind the
//! opaque candidate authority.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_candidate_admission::X64GateBPolicy15CandidateSelection;
use super::x64_gate_b_candidate_standalone_authority::{
    X64GateBPolicy15StandaloneAuthority, X64GateBPolicy15StandaloneAuthorityError,
};
use super::x64_standalone_artifact::validate_verified_elf_facts;
use super::x64_standalone_elf::{
    build_x64_standalone_elf_r1_s8, verify_x64_standalone_elf_r1_s8, VerifiedX64StandaloneElfImage,
    X64StandaloneElfError, X64StandaloneElfImage, X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES,
    X64_STANDALONE_ELF_STARTUP_OFFSET,
};
use super::x64_standalone_protocol::X64StandaloneProfile;
use super::x64_standalone_startup::{
    build_x64_gate_b_policy15_standalone_startup,
    independently_verify_x64_standalone_startup_code_r1_s8, x64_standalone_io_contract_hash,
    x64_standalone_startup_code_hash, x64_standalone_startup_plan_hash, X64StandaloneStartupError,
};
use super::x64_standalone_startup_raw::IndependentlyVerifiedX64StandaloneStartupRaw;
use std::fmt;

pub const X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_WRITER_POLICY_VERSION: (u16, u16, u16) =
    (1, 0, 0);
pub const X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_VERIFIER_POLICY_VERSION: (u16, u16, u16) =
    (1, 0, 0);

const ARTIFACT_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-standalone:artifact:v1\0";
const FROZEN_BRANCH_ARTIFACT_HASH: SemanticHash = SemanticHash([
    0x2c, 0xdc, 0xad, 0x6a, 0x08, 0xfd, 0x8c, 0x9f, 0x31, 0xa2, 0x15, 0x7c, 0x13, 0x4b, 0xaa, 0x2d,
    0x74, 0xe1, 0xeb, 0x99, 0xc3, 0xd6, 0x24, 0x41, 0xc9, 0x17, 0xd3, 0x83, 0x93, 0xba, 0xd8, 0x1d,
]);
const FROZEN_BOUNDS_ARTIFACT_HASH: SemanticHash = SemanticHash([
    0x19, 0x5a, 0xe4, 0xba, 0x36, 0x18, 0x3d, 0x6f, 0xb8, 0x8e, 0x90, 0x4c, 0xd6, 0xa6, 0xb0, 0x31,
    0x60, 0x5d, 0xa6, 0x83, 0x96, 0x40, 0x2d, 0x36, 0xfe, 0x06, 0xf9, 0x07, 0xa7, 0xbb, 0xb4, 0x4c,
]);

#[derive(Debug)]
pub enum X64GateBPolicy15StandaloneArtifactError {
    Authority(X64GateBPolicy15StandaloneAuthorityError),
    Startup(X64StandaloneStartupError),
    Elf(String),
    InvalidField { field: &'static str },
    MetricOverflow { field: &'static str },
}

impl fmt::Display for X64GateBPolicy15StandaloneArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(formatter, "{error}"),
            Self::Startup(error) => {
                write!(formatter, "candidate standalone startup failed: {error}")
            }
            Self::Elf(error) => write!(formatter, "candidate standalone ELF failed: {error}"),
            Self::InvalidField { field } => write!(
                formatter,
                "candidate standalone artifact has invalid {field}"
            ),
            Self::MetricOverflow { field } => write!(
                formatter,
                "candidate standalone artifact {field} overflowed"
            ),
        }
    }
}

impl std::error::Error for X64GateBPolicy15StandaloneArtifactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Startup(error) => Some(error),
            _ => None,
        }
    }
}

impl From<X64GateBPolicy15StandaloneAuthorityError> for X64GateBPolicy15StandaloneArtifactError {
    fn from(value: X64GateBPolicy15StandaloneAuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<X64StandaloneStartupError> for X64GateBPolicy15StandaloneArtifactError {
    fn from(value: X64StandaloneStartupError) -> Self {
        Self::Startup(value)
    }
}

fn elf_error(error: X64StandaloneElfError) -> X64GateBPolicy15StandaloneArtifactError {
    X64GateBPolicy15StandaloneArtifactError::Elf(error.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CandidateStandaloneArtifactIdentity {
    profile: X64StandaloneProfile,
    selection: X64GateBPolicy15CandidateSelection,
    manifest_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    correctness_results_hash: SemanticHash,
    process_results_hash: SemanticHash,
    source_core_hash: SemanticHash,
    source_ssa_hash: SemanticHash,
    source_machine_ir_hash: SemanticHash,
    target_artifact_hash: SemanticHash,
    target_plan_hash: SemanticHash,
    target_code_hash: SemanticHash,
    canonical_abi_hash: SemanticHash,
    startup_plan_hash: SemanticHash,
    startup_code_hash: SemanticHash,
    io_contract_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    startup_bytes: u64,
    target_offset: u64,
    target_bytes: u64,
    image_bytes: u64,
    overhead_bytes: u64,
    artifact_hash: SemanticHash,
}

/// Deterministically emitted candidate image. Raw bytes grant no execution
/// authority until independently verified against the same live authority.
pub struct X64GateBPolicy15StandaloneArtifact {
    elf: X64StandaloneElfImage,
}

impl fmt::Debug for X64GateBPolicy15StandaloneArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X64GateBPolicy15StandaloneArtifact")
            .field("image_bytes", &self.elf.bytes().len())
            .finish()
    }
}

impl X64GateBPolicy15StandaloneArtifact {
    pub fn image_bytes(&self) -> &[u8] {
        self.elf.bytes()
    }
}

/// Exact verified candidate image, lifetime-bound to authority and bytes.
pub struct VerifiedX64GateBPolicy15StandaloneArtifact<'authority, 'correctness, 'process, 'image> {
    _authority: &'authority X64GateBPolicy15StandaloneAuthority<'correctness, 'process>,
    elf: VerifiedX64StandaloneElfImage<'image>,
    _startup: IndependentlyVerifiedX64StandaloneStartupRaw<'image>,
    identity: CandidateStandaloneArtifactIdentity,
}

impl fmt::Debug for VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedX64GateBPolicy15StandaloneArtifact")
            .field("profile", &self.identity.profile)
            .field("selection", &self.identity.selection)
            .field("artifact_hash", &self.identity.artifact_hash)
            .field("elf_image_hash", &self.identity.elf_image_hash)
            .finish()
    }
}

impl VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_> {
    pub fn image_bytes(&self) -> &[u8] {
        self.elf.bytes()
    }

    pub const fn profile(&self) -> X64StandaloneProfile {
        self.identity.profile
    }

    pub const fn selection(&self) -> X64GateBPolicy15CandidateSelection {
        self.identity.selection
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.identity.artifact_hash
    }

    pub const fn elf_image_hash(&self) -> SemanticHash {
        self.identity.elf_image_hash
    }

    pub const fn startup_plan_hash(&self) -> SemanticHash {
        self.identity.startup_plan_hash
    }

    pub const fn startup_code_hash(&self) -> SemanticHash {
        self.identity.startup_code_hash
    }

    pub const fn io_contract_hash(&self) -> SemanticHash {
        self.identity.io_contract_hash
    }

    pub const fn target_code_hash(&self) -> SemanticHash {
        self.identity.target_code_hash
    }

    pub const fn interpreter_dependency(&self) -> bool {
        false
    }

    pub const fn external_symbol_dependency(&self) -> bool {
        false
    }

    pub const fn dynamic_loader_dependency(&self) -> bool {
        false
    }

    pub const fn system_linker_dependency(&self) -> bool {
        false
    }

    pub const fn fallback(&self) -> bool {
        false
    }
}

/// Build and immediately independently verify one candidate-specific ELF.
pub fn build_x64_gate_b_policy15_standalone_artifact(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
) -> Result<X64GateBPolicy15StandaloneArtifact, X64GateBPolicy15StandaloneArtifactError> {
    let startup = build_x64_gate_b_policy15_standalone_startup(authority)?;
    let code = startup.code();
    let elf = build_x64_standalone_elf_r1_s8(code.bytes(), authority.target_bytes())
        .map_err(elf_error)?;
    let _ = verify_x64_gate_b_policy15_standalone_artifact(authority, elf.bytes())?;
    Ok(X64GateBPolicy15StandaloneArtifact { elf })
}

/// Frozen ADR-0054 artifact identity for one closed profile selection.
pub const fn x64_gate_b_policy15_accepted_standalone_artifact_hash(
    profile: X64StandaloneProfile,
) -> SemanticHash {
    match profile {
        X64StandaloneProfile::BranchMix => FROZEN_BRANCH_ARTIFACT_HASH,
        X64StandaloneProfile::Bounds => FROZEN_BOUNDS_ARTIFACT_HASH,
    }
}

/// Independently regenerate startup/target and parse/reconstruct exact bytes.
pub fn verify_x64_gate_b_policy15_standalone_artifact<
    'authority,
    'correctness,
    'process,
    'image,
>(
    authority: &'authority X64GateBPolicy15StandaloneAuthority<'correctness, 'process>,
    image: &'image [u8],
) -> Result<
    VerifiedX64GateBPolicy15StandaloneArtifact<'authority, 'correctness, 'process, 'image>,
    X64GateBPolicy15StandaloneArtifactError,
> {
    authority.revalidate_complete()?;
    let startup = build_x64_gate_b_policy15_standalone_startup(authority)?;
    let plan = startup.plan();
    let code = startup.code();
    let target = authority.target_bytes();
    let elf = verify_x64_standalone_elf_r1_s8(image, code.bytes(), target).map_err(elf_error)?;
    let startup_end = X64_STANDALONE_ELF_STARTUP_OFFSET
        .checked_add(code.bytes().len())
        .ok_or(X64GateBPolicy15StandaloneArtifactError::MetricOverflow {
            field: "startup slice end",
        })?;
    let startup_slice = image
        .get(X64_STANDALONE_ELF_STARTUP_OFFSET..startup_end)
        .ok_or(X64GateBPolicy15StandaloneArtifactError::InvalidField {
            field: "startup slice",
        })?;
    let verified_startup =
        independently_verify_x64_standalone_startup_code_r1_s8(plan, startup_slice)?;
    if plan.profile() != authority.profile()
        || code.profile() != authority.profile()
        || plan.plan_hash() != x64_standalone_startup_plan_hash(plan)?
        || plan.plan_hash() != code.plan_hash()
        || code.code_hash() != x64_standalone_startup_code_hash(plan.plan_hash(), code.bytes())?
        || verified_startup.code() != code.bytes()
        || verified_startup.profile() != authority.profile()
        || elf.startup_bytes() != code.bytes().len() as u64
        || elf.target_bytes() != target.len() as u64
        || elf.target_offset() != code.target_offset()
        || elf.overhead_bytes() > X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES as u64
    {
        return Err(X64GateBPolicy15StandaloneArtifactError::InvalidField {
            field: "startup/ELF composition",
        });
    }
    validate_verified_elf_facts(elf.facts(), image.len() as u64)
        .map_err(|error| X64GateBPolicy15StandaloneArtifactError::Elf(error.to_string()))?;
    let io_contract_hash = x64_standalone_io_contract_hash(authority.profile())?;
    if plan.io_contract_hash() != io_contract_hash {
        return Err(X64GateBPolicy15StandaloneArtifactError::InvalidField {
            field: "I/O contract",
        });
    }
    let mut identity = CandidateStandaloneArtifactIdentity {
        profile: authority.profile(),
        selection: authority.selection(),
        manifest_hash: authority.manifest_hash(),
        candidate_capsule_hash: authority.candidate_capsule_hash(),
        correctness_results_hash: authority.correctness_results_hash(),
        process_results_hash: authority.process_results_hash(),
        source_core_hash: authority.source_core_hash(),
        source_ssa_hash: authority.source_ssa_hash(),
        source_machine_ir_hash: authority.source_machine_ir_hash(),
        target_artifact_hash: authority.target_artifact_hash(),
        target_plan_hash: authority.target_plan_hash(),
        target_code_hash: authority.target_code_hash(),
        canonical_abi_hash: authority.canonical_abi_hash(),
        startup_plan_hash: plan.plan_hash(),
        startup_code_hash: code.code_hash(),
        io_contract_hash,
        elf_image_hash: elf.image_hash(),
        startup_bytes: elf.startup_bytes(),
        target_offset: elf.target_offset(),
        target_bytes: elf.target_bytes(),
        image_bytes: image.len() as u64,
        overhead_bytes: elf.overhead_bytes(),
        artifact_hash: SemanticHash::ZERO,
    };
    if [
        identity.manifest_hash,
        identity.candidate_capsule_hash,
        identity.correctness_results_hash,
        identity.process_results_hash,
        identity.source_core_hash,
        identity.source_ssa_hash,
        identity.source_machine_ir_hash,
        identity.target_artifact_hash,
        identity.target_plan_hash,
        identity.target_code_hash,
        identity.canonical_abi_hash,
        identity.startup_plan_hash,
        identity.startup_code_hash,
        identity.io_contract_hash,
        identity.elf_image_hash,
    ]
    .contains(&SemanticHash::ZERO)
    {
        return Err(X64GateBPolicy15StandaloneArtifactError::InvalidField {
            field: "zero identity",
        });
    }
    identity.artifact_hash = candidate_artifact_hash(&identity);
    if identity.artifact_hash
        != x64_gate_b_policy15_accepted_standalone_artifact_hash(authority.profile())
    {
        return Err(X64GateBPolicy15StandaloneArtifactError::InvalidField {
            field: "accepted artifact identity",
        });
    }
    Ok(VerifiedX64GateBPolicy15StandaloneArtifact {
        _authority: authority,
        elf,
        _startup: verified_startup,
        identity,
    })
}

fn candidate_artifact_hash(identity: &CandidateStandaloneArtifactIdentity) -> SemanticHash {
    let mut bytes = Vec::with_capacity(ARTIFACT_DOMAIN.len() + 700);
    bytes.extend_from_slice(ARTIFACT_DOMAIN);
    put_version(
        &mut bytes,
        X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_SCHEMA_VERSION,
    );
    put_version(
        &mut bytes,
        X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_VERIFIER_POLICY_VERSION,
    );
    bytes.extend_from_slice(&identity.profile.wire_tag().to_le_bytes());
    bytes.push(match identity.selection {
        X64GateBPolicy15CandidateSelection::Policy15Candidate => 1,
        X64GateBPolicy15CandidateSelection::Policy14Fallback => 2,
    });
    for hash in [
        identity.manifest_hash,
        identity.candidate_capsule_hash,
        identity.correctness_results_hash,
        identity.process_results_hash,
        identity.source_core_hash,
        identity.source_ssa_hash,
        identity.source_machine_ir_hash,
        identity.target_artifact_hash,
        identity.target_plan_hash,
        identity.target_code_hash,
        identity.canonical_abi_hash,
        identity.startup_plan_hash,
        identity.startup_code_hash,
        identity.io_contract_hash,
        identity.elf_image_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    for value in [
        identity.startup_bytes,
        identity.target_offset,
        identity.target_bytes,
        identity.image_bytes,
        identity.overhead_bytes,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    SemanticHash(sha256(&bytes))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_le_bytes());
    bytes.extend_from_slice(&version.1.to_le_bytes());
    bytes.extend_from_slice(&version.2.to_le_bytes());
}
