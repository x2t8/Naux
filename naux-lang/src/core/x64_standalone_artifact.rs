//! Authority-bound R1-S8 standalone artifact composition.
//!
//! This is the only layer that may combine the opaque R1-S7b-derived seed
//! authority, the canonical syscall-only startup, and the inherited R1-S7a
//! target into a direct ELF64 image.  Construction is deliberately separate
//! from verification: the public verifier accepts only live authority and raw
//! image bytes, regenerates every derived component, and returns an opaque
//! view tied to both inputs.

use super::corevm0_gate_a::{COREVM0_GATE_A_BOUNDS_CASES, COREVM0_GATE_A_TOTAL_CASES};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_standalone_authority::{
    RevalidatedX64StandaloneAuthority, X64StandaloneAuthorityBinding, X64StandaloneAuthorityError,
    X64StandaloneSeedAuthority, X64_STANDALONE_INHERITED_ENVELOPE_BYTES,
};
use super::x64_standalone_elf::{
    build_x64_standalone_elf_r1_s8, verify_x64_standalone_elf_r1_s8, VerifiedX64StandaloneElfImage,
    X64StandaloneElfFacts, X64StandaloneElfImage, X64_STANDALONE_ELF_BASE,
    X64_STANDALONE_ELF_ENTRY, X64_STANDALONE_ELF_MAX_IMAGE_BYTES,
    X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES, X64_STANDALONE_ELF_MAX_STARTUP_BYTES,
    X64_STANDALONE_ELF_MAX_TARGET_BYTES, X64_STANDALONE_ELF_STARTUP_OFFSET,
};
use super::x64_standalone_protocol::{
    X64StandaloneProfile, X64_STANDALONE_MAX_ARRAY_ELEMENTS, X64_STANDALONE_MAX_INPUT_BYTES,
    X64_STANDALONE_MAX_PAYLOAD_BYTES, X64_STANDALONE_OUTPUT_BYTES,
};
use super::x64_standalone_startup::{
    build_x64_standalone_startup_seed_r1_s8,
    independently_verify_x64_standalone_startup_code_r1_s8, x64_standalone_io_contract_hash,
    x64_standalone_startup_code_hash, x64_standalone_startup_plan_hash, X64StandaloneStartupCode,
    X64StandaloneStartupError, X64StandaloneStartupPlan, X64StandaloneStartupUsage,
    X64_STANDALONE_IO_POLICY_VERSION, X64_STANDALONE_IO_SCHEMA_VERSION,
    X64_STANDALONE_STARTUP_ENCODER_POLICY_VERSION, X64_STANDALONE_STARTUP_LOWERING_POLICY_VERSION,
    X64_STANDALONE_STARTUP_MAX_CODE_BYTES, X64_STANDALONE_STARTUP_MAX_FIXUPS,
    X64_STANDALONE_STARTUP_MAX_LABELS, X64_STANDALONE_STARTUP_MAX_OPS,
    X64_STANDALONE_STARTUP_MAX_STACK_BYTES, X64_STANDALONE_STARTUP_PLANNER_POLICY_VERSION,
    X64_STANDALONE_STARTUP_SCHEMA_VERSION, X64_STANDALONE_STARTUP_TARGET_CALL_FIXUPS,
    X64_STANDALONE_TARGET_ALIGNMENT,
};
use super::x64_standalone_startup_raw::IndependentlyVerifiedX64StandaloneStartupRaw;
use super::x64_target::X64_TARGET_MAX_CODE_BYTES;
use std::fmt;

pub const X64_STANDALONE_ARTIFACT_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_ARTIFACT_WRITER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_ARTIFACT_VERIFIER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_ELF_LAYOUT_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_ELF_WRITER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_ELF_VERIFIER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

const ARTIFACT_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s8:artifact:v1\0";
const ARTIFACT_IDENTITY_MAX_BYTES: usize = 8_192;

const MAX_PT_LOAD_SEGMENTS: u32 = 1;
const MAX_PROGRAM_HEADERS: u32 = 2;
const MAX_TARGET_BLOB_COPIES: u32 = 1;
const MAX_INPUT_ARRAYS: u32 = 1;
const MAX_RUNTIME_INPUT_MAPPINGS: u32 = 1;
const PER_PROCESS_TIMEOUT_MS: u32 = 30_000;
const MAX_CAPTURED_DIAGNOSTIC_BYTES: u32 = 16_384;
const MAX_CAPTURED_DIAGNOSTIC_RECORDS: u32 = 128;

/// Complete frozen R1-S8 limit vector carried by the artifact identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneArtifactLimits {
    max_pt_load_segments: u32,
    max_program_headers: u32,
    max_target_entry_fixups: u32,
    max_startup_plan_ops: u32,
    max_startup_labels: u32,
    max_startup_fixups: u32,
    max_startup_code_bytes: u64,
    max_inherited_target_code_bytes: u64,
    max_target_blob_copies: u32,
    max_standalone_overhead_bytes: u64,
    max_elf_image_bytes: u64,
    max_input_arrays: u32,
    max_array_elements: u64,
    max_mapped_input_bytes: u64,
    max_input_frame_bytes: u64,
    output_frame_bytes: u64,
    max_runtime_input_mappings: u32,
    max_startup_stack_bytes: u32,
    fixed_corpus_cases: u32,
    per_process_timeout_ms: u32,
    max_captured_diagnostic_bytes: u32,
    max_captured_diagnostic_records: u32,
}

impl X64StandaloneArtifactLimits {
    const fn r1_s8() -> Self {
        Self {
            max_pt_load_segments: MAX_PT_LOAD_SEGMENTS,
            max_program_headers: MAX_PROGRAM_HEADERS,
            max_target_entry_fixups: X64_STANDALONE_STARTUP_TARGET_CALL_FIXUPS,
            max_startup_plan_ops: X64_STANDALONE_STARTUP_MAX_OPS,
            max_startup_labels: X64_STANDALONE_STARTUP_MAX_LABELS,
            max_startup_fixups: X64_STANDALONE_STARTUP_MAX_FIXUPS,
            max_startup_code_bytes: X64_STANDALONE_ELF_MAX_STARTUP_BYTES as u64,
            max_inherited_target_code_bytes: X64_STANDALONE_ELF_MAX_TARGET_BYTES as u64,
            max_target_blob_copies: MAX_TARGET_BLOB_COPIES,
            max_standalone_overhead_bytes: X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES as u64,
            max_elf_image_bytes: X64_STANDALONE_ELF_MAX_IMAGE_BYTES as u64,
            max_input_arrays: MAX_INPUT_ARRAYS,
            max_array_elements: X64_STANDALONE_MAX_ARRAY_ELEMENTS,
            max_mapped_input_bytes: X64_STANDALONE_MAX_PAYLOAD_BYTES,
            max_input_frame_bytes: X64_STANDALONE_MAX_INPUT_BYTES as u64,
            output_frame_bytes: X64_STANDALONE_OUTPUT_BYTES as u64,
            max_runtime_input_mappings: MAX_RUNTIME_INPUT_MAPPINGS,
            max_startup_stack_bytes: X64_STANDALONE_STARTUP_MAX_STACK_BYTES,
            fixed_corpus_cases: COREVM0_GATE_A_TOTAL_CASES,
            per_process_timeout_ms: PER_PROCESS_TIMEOUT_MS,
            max_captured_diagnostic_bytes: MAX_CAPTURED_DIAGNOSTIC_BYTES,
            max_captured_diagnostic_records: MAX_CAPTURED_DIAGNOSTIC_RECORDS,
        }
    }

    pub const fn max_startup_code_bytes(self) -> u64 {
        self.max_startup_code_bytes
    }

    pub const fn max_pt_load_segments(self) -> u32 {
        self.max_pt_load_segments
    }

    pub const fn max_program_headers(self) -> u32 {
        self.max_program_headers
    }

    pub const fn max_target_entry_fixups(self) -> u32 {
        self.max_target_entry_fixups
    }

    pub const fn max_startup_plan_ops(self) -> u32 {
        self.max_startup_plan_ops
    }

    pub const fn max_startup_labels(self) -> u32 {
        self.max_startup_labels
    }

    pub const fn max_startup_fixups(self) -> u32 {
        self.max_startup_fixups
    }

    pub const fn max_inherited_target_code_bytes(self) -> u64 {
        self.max_inherited_target_code_bytes
    }

    pub const fn max_target_blob_copies(self) -> u32 {
        self.max_target_blob_copies
    }

    pub const fn max_standalone_overhead_bytes(self) -> u64 {
        self.max_standalone_overhead_bytes
    }

    pub const fn max_elf_image_bytes(self) -> u64 {
        self.max_elf_image_bytes
    }

    pub const fn max_array_elements(self) -> u64 {
        self.max_array_elements
    }

    pub const fn max_input_arrays(self) -> u32 {
        self.max_input_arrays
    }

    pub const fn max_mapped_input_bytes(self) -> u64 {
        self.max_mapped_input_bytes
    }

    pub const fn max_input_frame_bytes(self) -> u64 {
        self.max_input_frame_bytes
    }

    pub const fn output_frame_bytes(self) -> u64 {
        self.output_frame_bytes
    }

    pub const fn max_runtime_input_mappings(self) -> u32 {
        self.max_runtime_input_mappings
    }

    pub const fn max_startup_stack_bytes(self) -> u32 {
        self.max_startup_stack_bytes
    }

    pub const fn fixed_corpus_cases(self) -> u32 {
        self.fixed_corpus_cases
    }

    pub const fn per_process_timeout_ms(self) -> u32 {
        self.per_process_timeout_ms
    }

    pub const fn max_captured_diagnostic_bytes(self) -> u32 {
        self.max_captured_diagnostic_bytes
    }

    pub const fn max_captured_diagnostic_records(self) -> u32 {
        self.max_captured_diagnostic_records
    }
}

/// Exact structural usage of one composed image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneArtifactUsage {
    pt_load_segments: u32,
    program_headers: u32,
    target_entry_fixups: u32,
    startup_plan_ops: u32,
    startup_labels: u32,
    startup_fixups: u32,
    startup_internal_call_fixups: u32,
    startup_syscall_sites: u32,
    startup_code_bytes: u64,
    startup_stack_bytes: u32,
    inherited_target_code_bytes: u64,
    target_blob_copies: u32,
    standalone_overhead_bytes: u64,
    elf_image_bytes: u64,
    admitted_input_arrays: u32,
    admitted_runtime_input_mappings: u32,
    profile_corpus_cases: u32,
}

impl X64StandaloneArtifactUsage {
    pub const fn pt_load_segments(self) -> u32 {
        self.pt_load_segments
    }

    pub const fn program_headers(self) -> u32 {
        self.program_headers
    }

    pub const fn target_entry_fixups(self) -> u32 {
        self.target_entry_fixups
    }

    pub const fn startup_plan_ops(self) -> u32 {
        self.startup_plan_ops
    }

    pub const fn startup_labels(self) -> u32 {
        self.startup_labels
    }

    pub const fn startup_fixups(self) -> u32 {
        self.startup_fixups
    }

    pub const fn startup_internal_call_fixups(self) -> u32 {
        self.startup_internal_call_fixups
    }

    pub const fn startup_syscall_sites(self) -> u32 {
        self.startup_syscall_sites
    }

    pub const fn startup_code_bytes(self) -> u64 {
        self.startup_code_bytes
    }

    pub const fn startup_stack_bytes(self) -> u32 {
        self.startup_stack_bytes
    }

    pub const fn inherited_target_code_bytes(self) -> u64 {
        self.inherited_target_code_bytes
    }

    pub const fn target_blob_copies(self) -> u32 {
        self.target_blob_copies
    }

    pub const fn standalone_overhead_bytes(self) -> u64 {
        self.standalone_overhead_bytes
    }

    pub const fn elf_image_bytes(self) -> u64 {
        self.elf_image_bytes
    }

    pub const fn admitted_input_arrays(self) -> u32 {
        self.admitted_input_arrays
    }

    pub const fn admitted_runtime_input_mappings(self) -> u32 {
        self.admitted_runtime_input_mappings
    }

    pub const fn profile_corpus_cases(self) -> u32 {
        self.profile_corpus_cases
    }
}

/// Canonical file and virtual-address placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneArtifactLayout {
    elf_base: u64,
    elf_entry: u64,
    startup_offset: u64,
    startup_vaddr: u64,
    startup_bytes: u64,
    target_offset: u64,
    inherited_entry_offset: u32,
    target_entry_vaddr: u64,
    target_bytes: u64,
    image_bytes: u64,
    overhead_bytes: u64,
    target_alignment: u64,
}

impl X64StandaloneArtifactLayout {
    pub const fn elf_base(self) -> u64 {
        self.elf_base
    }

    pub const fn elf_entry(self) -> u64 {
        self.elf_entry
    }

    pub const fn startup_bytes(self) -> u64 {
        self.startup_bytes
    }

    pub const fn startup_offset(self) -> u64 {
        self.startup_offset
    }

    pub const fn startup_vaddr(self) -> u64 {
        self.startup_vaddr
    }

    pub const fn target_offset(self) -> u64 {
        self.target_offset
    }

    pub const fn inherited_entry_offset(self) -> u32 {
        self.inherited_entry_offset
    }

    pub const fn target_entry_vaddr(self) -> u64 {
        self.target_entry_vaddr
    }

    pub const fn target_bytes(self) -> u64 {
        self.target_bytes
    }

    pub const fn image_bytes(self) -> u64 {
        self.image_bytes
    }

    pub const fn overhead_bytes(self) -> u64 {
        self.overhead_bytes
    }

    pub const fn target_alignment(self) -> u64 {
        self.target_alignment
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct X64StandaloneDependencyClaims {
    interpreter_dependency: bool,
    external_symbol_dependency: bool,
    dynamic_loader_dependency: bool,
    system_linker_dependency: bool,
    fallback: bool,
}

impl X64StandaloneDependencyClaims {
    const fn from_verified_structure_and_authority(
        elf: X64StandaloneElfFacts,
        structural_erasure: bool,
        upstream_interpreter_dependency: bool,
        upstream_fallback: bool,
    ) -> Self {
        Self {
            interpreter_dependency: !structural_erasure || upstream_interpreter_dependency,
            external_symbol_dependency: elf.pt_dynamic_segments != 0
                || elf.section_header_count != 0,
            dynamic_loader_dependency: elf.pt_interp_segments != 0 || elf.pt_dynamic_segments != 0,
            system_linker_dependency: elf.pt_interp_segments != 0
                || elf.pt_dynamic_segments != 0
                || elf.section_header_count != 0,
            fallback: upstream_fallback,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct X64StandaloneArtifactIdentity {
    authority: X64StandaloneAuthorityBinding,
    inherited_envelope_bytes: [u8; X64_STANDALONE_INHERITED_ENVELOPE_BYTES],
    profile: X64StandaloneProfile,
    startup_plan_hash: SemanticHash,
    io_contract_hash: SemanticHash,
    startup_code_hash: SemanticHash,
    target_code_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    layout: X64StandaloneArtifactLayout,
    elf: X64StandaloneElfFacts,
    limits: X64StandaloneArtifactLimits,
    usage: X64StandaloneArtifactUsage,
    dependencies: X64StandaloneDependencyClaims,
    artifact_hash: SemanticHash,
}

/// Deterministically emitted image.  Its bytes are not execution authority;
/// callers must pass them through [`verify_x64_standalone_artifact_r1_s8`].
pub struct X64StandaloneArtifact {
    elf: X64StandaloneElfImage,
}

impl fmt::Debug for X64StandaloneArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X64StandaloneArtifact")
            .field("image_bytes", &self.elf.bytes().len())
            .finish()
    }
}

impl X64StandaloneArtifact {
    pub fn image_bytes(&self) -> &[u8] {
        self.elf.bytes()
    }
}

/// Independently verified view tied to both live authority and exact image.
///
/// There is no constructor and no detached claim tuple can create this type.
pub struct VerifiedX64StandaloneArtifact<'authority, 'evidence, 'image> {
    _authority: &'authority X64StandaloneSeedAuthority<'evidence>,
    elf: VerifiedX64StandaloneElfImage<'image>,
    _startup: IndependentlyVerifiedX64StandaloneStartupRaw<'image>,
    identity: X64StandaloneArtifactIdentity,
}

impl fmt::Debug for VerifiedX64StandaloneArtifact<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedX64StandaloneArtifact")
            .field("profile", &self.identity.profile)
            .field("artifact_hash", &self.identity.artifact_hash)
            .field("elf_image_hash", &self.identity.elf_image_hash)
            .field("layout", &self.identity.layout)
            .field("usage", &self.identity.usage)
            .finish()
    }
}

impl<'authority, 'evidence, 'image> VerifiedX64StandaloneArtifact<'authority, 'evidence, 'image> {
    pub const fn image_bytes(&self) -> &'image [u8] {
        self.elf.bytes()
    }

    pub const fn profile(&self) -> X64StandaloneProfile {
        self.identity.profile
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

    pub const fn inherited_envelope_bytes(&self) -> &[u8] {
        &self.identity.inherited_envelope_bytes
    }

    pub const fn layout(&self) -> X64StandaloneArtifactLayout {
        self.identity.layout
    }

    pub const fn limits(&self) -> X64StandaloneArtifactLimits {
        self.identity.limits
    }

    pub const fn usage(&self) -> X64StandaloneArtifactUsage {
        self.identity.usage
    }

    /// Artifact-local structural dependency fact.
    ///
    /// `false` is necessary but not sufficient for the final R1-S8 absence
    /// claim; only verified direct-process evidence can close that claim.
    pub const fn interpreter_dependency(&self) -> bool {
        self.identity.dependencies.interpreter_dependency
    }

    pub const fn external_symbol_dependency(&self) -> bool {
        self.identity.dependencies.external_symbol_dependency
    }

    pub const fn dynamic_loader_dependency(&self) -> bool {
        self.identity.dependencies.dynamic_loader_dependency
    }

    pub const fn system_linker_dependency(&self) -> bool {
        self.identity.dependencies.system_linker_dependency
    }

    pub const fn fallback(&self) -> bool {
        self.identity.dependencies.fallback
    }
}

#[derive(Debug)]
pub enum X64StandaloneArtifactError {
    Authority(X64StandaloneAuthorityError),
    Startup(X64StandaloneStartupError),
    Elf {
        message: String,
    },
    LengthConversion {
        field: &'static str,
        actual: usize,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    CompositionMismatch {
        field: &'static str,
    },
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    IdentityByteLimit {
        limit: usize,
        attempted: usize,
    },
}

impl fmt::Display for X64StandaloneArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(formatter, "{error}"),
            Self::Startup(error) => write!(formatter, "{error}"),
            Self::Elf { message } => write!(formatter, "R1-S8 ELF composition failed: {message}"),
            Self::LengthConversion { field, actual } => write!(
                formatter,
                "R1-S8 artifact {field} length {actual} does not fit its canonical u64 encoding"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "R1-S8 artifact {field} arithmetic overflow")
            }
            Self::CompositionMismatch { field } => {
                write!(formatter, "R1-S8 artifact has inconsistent {field}")
            }
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S8 artifact {field} usage {actual} exceeds hard limit {limit}"
            ),
            Self::IdentityByteLimit { limit, attempted } => write!(
                formatter,
                "R1-S8 artifact identity attempted {attempted} bytes; fixed limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for X64StandaloneArtifactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Startup(error) => Some(error),
            _ => None,
        }
    }
}

impl From<X64StandaloneStartupError> for X64StandaloneArtifactError {
    fn from(error: X64StandaloneStartupError) -> Self {
        Self::Startup(error)
    }
}

impl From<X64StandaloneAuthorityError> for X64StandaloneArtifactError {
    fn from(error: X64StandaloneAuthorityError) -> Self {
        Self::Authority(error)
    }
}

/// Build and immediately locally verify one canonical direct ELF64 artifact.
///
/// Placement is derived by the startup seed builder; no caller-provided
/// offset, address, raw target, ABI, syscall, or dependency flag is accepted.
pub fn build_x64_standalone_artifact_r1_s8(
    authority: &X64StandaloneSeedAuthority<'_>,
) -> Result<X64StandaloneArtifact, X64StandaloneArtifactError> {
    let startup = build_x64_standalone_startup_seed_r1_s8(authority)?;
    let plan = startup.plan();
    let code = startup.code();
    let target = authority.target_bytes();
    let elf = build_x64_standalone_elf_r1_s8(code.bytes(), target).map_err(elf_error)?;

    require(
        elf.startup_bytes() == usize_to_u64(code.bytes().len(), "startup code")?
            && elf.target_offset() == code.target_offset()
            && elf.target_bytes() == usize_to_u64(target.len(), "inherited target code")?
            && elf.overhead_bytes() <= X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES as u64,
        "writer component receipt",
    )?;
    let verified = verify_x64_standalone_artifact_r1_s8(authority, elf.bytes())?;
    require(
        verified.startup_plan_hash() == plan.plan_hash()
            && verified.startup_code_hash() == code.code_hash(),
        "writer/verifier identity",
    )?;

    Ok(X64StandaloneArtifact { elf })
}

/// Independently verify raw image bytes against one live opaque authority.
///
/// Writer metadata is not accepted.  The function regenerates the typed plan,
/// raw startup, I/O identity, target placement, inherited target bytes, ELF
/// grammar, complete image hash, limit/usage vectors, and artifact identity.
pub fn verify_x64_standalone_artifact_r1_s8<'authority, 'evidence, 'image>(
    authority: &'authority X64StandaloneSeedAuthority<'evidence>,
    image: &'image [u8],
) -> Result<VerifiedX64StandaloneArtifact<'authority, 'evidence, 'image>, X64StandaloneArtifactError>
{
    let revalidated_authority = authority.revalidate_complete()?;
    let startup = build_x64_standalone_startup_seed_r1_s8(authority)?;
    let plan = startup.plan();
    let code = startup.code();
    let target = authority.target_bytes();
    let elf = verify_x64_standalone_elf_r1_s8(image, code.bytes(), target).map_err(elf_error)?;
    let startup_end = X64_STANDALONE_ELF_STARTUP_OFFSET
        .checked_add(code.bytes().len())
        .ok_or(X64StandaloneArtifactError::ArithmeticOverflow {
            field: "verified startup slice end",
        })?;
    let startup_slice = image
        .get(X64_STANDALONE_ELF_STARTUP_OFFSET..startup_end)
        .ok_or(X64StandaloneArtifactError::CompositionMismatch {
            field: "verified startup slice",
        })?;
    let verified_startup =
        independently_verify_x64_standalone_startup_code_r1_s8(plan, startup_slice)?;
    let identity = compose_verified_identity(
        authority,
        revalidated_authority,
        plan,
        code,
        &verified_startup,
        elf,
    )?;

    Ok(VerifiedX64StandaloneArtifact {
        _authority: authority,
        elf,
        _startup: verified_startup,
        identity,
    })
}

fn compose_verified_identity(
    authority: &X64StandaloneSeedAuthority<'_>,
    revalidated_authority: RevalidatedX64StandaloneAuthority,
    plan: &X64StandaloneStartupPlan,
    code: &X64StandaloneStartupCode,
    verified_startup: &IndependentlyVerifiedX64StandaloneStartupRaw<'_>,
    elf: VerifiedX64StandaloneElfImage<'_>,
) -> Result<X64StandaloneArtifactIdentity, X64StandaloneArtifactError> {
    let target = authority.target_bytes();
    let startup_bytes = usize_to_u64(code.bytes().len(), "startup code")?;
    let target_bytes = usize_to_u64(target.len(), "inherited target code")?;
    let image_bytes = usize_to_u64(elf.bytes().len(), "ELF image")?;
    let expected_target_offset = independently_derive_target_offset(startup_bytes)?;
    let expected_target_entry = X64_STANDALONE_ELF_BASE
        .checked_add(expected_target_offset)
        .and_then(|address| address.checked_add(u64::from(authority.entry_offset())))
        .ok_or(X64StandaloneArtifactError::ArithmeticOverflow {
            field: "target entry",
        })?;

    require(
        authority.profile() == plan.profile() && authority.profile() == code.profile(),
        "baked workload profile",
    )?;
    require(
        authority.binding().profile == authority.profile(),
        "authority profile binding",
    )?;
    require(
        plan.plan_hash() == code.plan_hash()
            && plan.plan_hash() == x64_standalone_startup_plan_hash(plan)?,
        "startup plan identity",
    )?;
    require(
        code.code_hash() == x64_standalone_startup_code_hash(plan.plan_hash(), code.bytes())?,
        "startup code identity",
    )?;
    let io_contract_hash = x64_standalone_io_contract_hash(authority.profile())?;
    require(
        plan.io_contract_hash() == io_contract_hash,
        "I/O contract identity",
    )?;
    require(
        plan.target_offset() == expected_target_offset
            && code.target_offset() == expected_target_offset
            && elf.target_offset() == expected_target_offset,
        "plan/code/ELF target placement",
    )?;
    require(
        plan.inherited_entry_offset() == authority.entry_offset()
            && plan.target_entry_vaddr() == expected_target_entry
            && code.target_entry_vaddr() == expected_target_entry,
        "inherited target entry",
    )?;
    require(
        plan.input_lanes() == authority.input_lanes(),
        "inherited input-lane count",
    )?;
    require(
        elf.startup_bytes() == startup_bytes
            && elf.target_bytes() == target_bytes
            && image_bytes
                == expected_target_offset.checked_add(target_bytes).ok_or(
                    X64StandaloneArtifactError::ArithmeticOverflow {
                        field: "image length",
                    },
                )?,
        "ELF component lengths",
    )?;
    let expected_overhead = image_bytes.checked_sub(target_bytes).ok_or(
        X64StandaloneArtifactError::ArithmeticOverflow {
            field: "standalone overhead",
        },
    )?;
    require(
        elf.overhead_bytes() == expected_overhead,
        "standalone overhead",
    )?;

    let startup_usage = plan.usage();
    require(
        u64::from(startup_usage.code_bytes()) == startup_bytes
            && startup_usage.target_call_fixups() == X64_STANDALONE_STARTUP_TARGET_CALL_FIXUPS
            && verified_startup.code() == code.bytes()
            && verified_startup.profile() == authority.profile()
            && verified_startup.target_entry_vaddr() == expected_target_entry
            && verified_startup.label_count() == startup_usage.labels()
            && verified_startup.fixup_count() == startup_usage.fixups()
            && u32::from(verified_startup.syscall_site_count()) == startup_usage.syscall_sites(),
        "startup usage",
    )?;
    validate_plan_limits(plan)?;

    let layout = X64StandaloneArtifactLayout {
        elf_base: X64_STANDALONE_ELF_BASE,
        elf_entry: X64_STANDALONE_ELF_ENTRY,
        startup_offset: X64_STANDALONE_ELF_STARTUP_OFFSET as u64,
        startup_vaddr: X64_STANDALONE_ELF_ENTRY,
        startup_bytes,
        target_offset: expected_target_offset,
        inherited_entry_offset: authority.entry_offset(),
        target_entry_vaddr: expected_target_entry,
        target_bytes,
        image_bytes,
        overhead_bytes: expected_overhead,
        target_alignment: X64_STANDALONE_TARGET_ALIGNMENT,
    };
    let elf_contract = elf.facts();
    validate_verified_elf_facts(elf_contract, image_bytes)?;
    let usage = artifact_usage(authority, startup_usage, layout, elf_contract);
    let limits = X64StandaloneArtifactLimits::r1_s8();
    validate_artifact_limits(limits, usage, authority.profile())?;
    validate_canonical_artifact_usage(usage, authority.profile())?;
    let inherited_envelope = revalidated_authority.inherited;
    require(
        authority.structural_erasure()
            && !authority.upstream_interpreter_dependency()
            && !authority.fallback()
            && inherited_envelope.structural_erasure
            && !inherited_envelope.upstream_interpreter_dependency
            && !inherited_envelope.fallback,
        "inherited erasure/dependency envelope",
    )?;
    let inherited_envelope_bytes = inherited_envelope.canonical_bytes()?;
    require(
        inherited_envelope_bytes.len() == X64_STANDALONE_INHERITED_ENVELOPE_BYTES,
        "inherited envelope byte width",
    )?;
    let dependencies = X64StandaloneDependencyClaims::from_verified_structure_and_authority(
        elf_contract,
        inherited_envelope.structural_erasure,
        inherited_envelope.upstream_interpreter_dependency,
        inherited_envelope.fallback,
    );
    require(
        !dependencies.external_symbol_dependency
            && !dependencies.dynamic_loader_dependency
            && !dependencies.system_linker_dependency,
        "verified ELF dependency absence",
    )?;
    let mut identity = X64StandaloneArtifactIdentity {
        authority: revalidated_authority.binding,
        inherited_envelope_bytes,
        profile: authority.profile(),
        startup_plan_hash: plan.plan_hash(),
        io_contract_hash,
        startup_code_hash: code.code_hash(),
        target_code_hash: authority.target_code_hash(),
        elf_image_hash: elf.image_hash(),
        layout,
        elf: elf_contract,
        limits,
        usage,
        dependencies,
        artifact_hash: SemanticHash::ZERO,
    };
    identity.artifact_hash = artifact_hash(&identity)?;
    Ok(identity)
}

fn independently_derive_target_offset(
    startup_bytes: u64,
) -> Result<u64, X64StandaloneArtifactError> {
    let startup_end = (X64_STANDALONE_ELF_STARTUP_OFFSET as u64)
        .checked_add(startup_bytes)
        .ok_or(X64StandaloneArtifactError::ArithmeticOverflow {
            field: "verified startup end",
        })?;
    require(
        X64_STANDALONE_TARGET_ALIGNMENT.is_power_of_two(),
        "target alignment policy",
    )?;
    let remainder = startup_end % X64_STANDALONE_TARGET_ALIGNMENT;
    let padding = if remainder == 0 {
        0
    } else {
        X64_STANDALONE_TARGET_ALIGNMENT - remainder
    };
    startup_end
        .checked_add(padding)
        .ok_or(X64StandaloneArtifactError::ArithmeticOverflow {
            field: "verified target alignment",
        })
}

pub(super) fn validate_verified_elf_facts(
    elf: X64StandaloneElfFacts,
    image_bytes: u64,
) -> Result<(), X64StandaloneArtifactError> {
    require(
        elf.class == 2
            && elf.data == 1
            && elf.ident_version == 1
            && elf.os_abi == 0
            && elf.abi_version == 0,
        "parsed ELF identification",
    )?;
    require(
        elf.object_type == 2
            && elf.machine == 62
            && elf.version == 1
            && elf.entry == X64_STANDALONE_ELF_ENTRY
            && elf.program_headers_offset == 64
            && elf.section_headers_offset == 0
            && elf.flags == 0,
        "parsed ELF header",
    )?;
    require(
        elf.elf_header_bytes == 64
            && elf.program_header_bytes == 56
            && elf.program_header_count == 2
            && elf.section_header_bytes == 0
            && elf.section_header_count == 0
            && elf.section_name_index == 0,
        "parsed ELF table dimensions",
    )?;
    require(
        elf.load_type == 1
            && elf.load_flags == 5
            && elf.load_offset == 0
            && elf.load_vaddr == X64_STANDALONE_ELF_BASE
            && elf.load_paddr == X64_STANDALONE_ELF_BASE
            && elf.load_filesz == image_bytes
            && elf.load_memsz == image_bytes
            && elf.load_alignment == 4_096,
        "parsed load segment",
    )?;
    require(
        elf.stack_type == 0x6474_e551
            && elf.stack_flags == 6
            && elf.stack_offset == 0
            && elf.stack_vaddr == 0
            && elf.stack_paddr == 0
            && elf.stack_filesz == 0
            && elf.stack_memsz == 0
            && elf.stack_alignment == 16,
        "parsed GNU stack segment",
    )?;
    require(
        elf.pt_load_segments == 1
            && elf.pt_interp_segments == 0
            && elf.pt_dynamic_segments == 0
            && elf.writable_executable_load_segments == 0,
        "parsed forbidden segment absence",
    )
}

fn artifact_usage(
    authority: &X64StandaloneSeedAuthority<'_>,
    startup: X64StandaloneStartupUsage,
    layout: X64StandaloneArtifactLayout,
    elf: X64StandaloneElfFacts,
) -> X64StandaloneArtifactUsage {
    X64StandaloneArtifactUsage {
        pt_load_segments: elf.pt_load_segments,
        program_headers: u32::from(elf.program_header_count),
        target_entry_fixups: startup.target_call_fixups(),
        startup_plan_ops: startup.ops(),
        startup_labels: startup.labels(),
        startup_fixups: startup.fixups(),
        startup_internal_call_fixups: startup.internal_call_fixups(),
        startup_syscall_sites: startup.syscall_sites(),
        startup_code_bytes: layout.startup_bytes,
        startup_stack_bytes: startup.stack_bytes(),
        inherited_target_code_bytes: layout.target_bytes,
        target_blob_copies: 1,
        standalone_overhead_bytes: layout.overhead_bytes,
        elf_image_bytes: layout.image_bytes,
        admitted_input_arrays: 1,
        admitted_runtime_input_mappings: 1,
        profile_corpus_cases: authority.canonical_case_count(),
    }
}

fn validate_plan_limits(plan: &X64StandaloneStartupPlan) -> Result<(), X64StandaloneArtifactError> {
    let limits = plan.limits();
    for (field, actual, expected) in [
        (
            "startup max operations",
            limits.max_ops(),
            X64_STANDALONE_STARTUP_MAX_OPS,
        ),
        (
            "startup max labels",
            limits.max_labels(),
            X64_STANDALONE_STARTUP_MAX_LABELS,
        ),
        (
            "startup max fixups",
            limits.max_fixups(),
            X64_STANDALONE_STARTUP_MAX_FIXUPS,
        ),
        (
            "startup max code bytes",
            limits.max_code_bytes(),
            X64_STANDALONE_STARTUP_MAX_CODE_BYTES,
        ),
        (
            "startup max stack bytes",
            limits.max_stack_bytes(),
            X64_STANDALONE_STARTUP_MAX_STACK_BYTES,
        ),
    ] {
        require(actual == expected, field)?;
    }
    Ok(())
}

fn validate_artifact_limits(
    limits: X64StandaloneArtifactLimits,
    usage: X64StandaloneArtifactUsage,
    profile: X64StandaloneProfile,
) -> Result<(), X64StandaloneArtifactError> {
    require(
        limits == X64StandaloneArtifactLimits::r1_s8(),
        "standalone limit vector",
    )?;
    require(
        limits.max_startup_code_bytes == u64::from(X64_STANDALONE_STARTUP_MAX_CODE_BYTES)
            && limits.max_inherited_target_code_bytes == X64_TARGET_MAX_CODE_BYTES,
        "cross-stage code byte caps",
    )?;

    for (field, actual, limit) in [
        (
            "PT_LOAD segments",
            u64::from(usage.pt_load_segments),
            u64::from(limits.max_pt_load_segments),
        ),
        (
            "program headers",
            u64::from(usage.program_headers),
            u64::from(limits.max_program_headers),
        ),
        (
            "target entry fixups",
            u64::from(usage.target_entry_fixups),
            u64::from(limits.max_target_entry_fixups),
        ),
        (
            "startup plan operations",
            u64::from(usage.startup_plan_ops),
            u64::from(limits.max_startup_plan_ops),
        ),
        (
            "startup labels",
            u64::from(usage.startup_labels),
            u64::from(limits.max_startup_labels),
        ),
        (
            "startup fixups",
            u64::from(usage.startup_fixups),
            u64::from(limits.max_startup_fixups),
        ),
        (
            "startup code bytes",
            usage.startup_code_bytes,
            limits.max_startup_code_bytes,
        ),
        (
            "inherited target code bytes",
            usage.inherited_target_code_bytes,
            limits.max_inherited_target_code_bytes,
        ),
        (
            "target blob copies",
            u64::from(usage.target_blob_copies),
            u64::from(limits.max_target_blob_copies),
        ),
        (
            "standalone overhead bytes",
            usage.standalone_overhead_bytes,
            limits.max_standalone_overhead_bytes,
        ),
        (
            "ELF image bytes",
            usage.elf_image_bytes,
            limits.max_elf_image_bytes,
        ),
        (
            "admitted input arrays",
            u64::from(usage.admitted_input_arrays),
            u64::from(limits.max_input_arrays),
        ),
        (
            "admitted runtime input mappings",
            u64::from(usage.admitted_runtime_input_mappings),
            u64::from(limits.max_runtime_input_mappings),
        ),
        (
            "startup stack bytes",
            u64::from(usage.startup_stack_bytes),
            u64::from(limits.max_startup_stack_bytes),
        ),
        (
            "profile corpus cases",
            u64::from(usage.profile_corpus_cases),
            u64::from(limits.fixed_corpus_cases),
        ),
    ] {
        if actual > limit {
            return Err(X64StandaloneArtifactError::Limit {
                field,
                limit,
                actual,
            });
        }
    }
    for (field, actual, expected) in [
        ("PT_LOAD segment count", usage.pt_load_segments, 1),
        ("program-header count", usage.program_headers, 2),
        (
            "target-entry fixup count",
            usage.target_entry_fixups,
            X64_STANDALONE_STARTUP_TARGET_CALL_FIXUPS,
        ),
        ("target blob copy count", usage.target_blob_copies, 1),
        ("admitted input-array count", usage.admitted_input_arrays, 1),
        (
            "admitted runtime mapping count",
            usage.admitted_runtime_input_mappings,
            1,
        ),
    ] {
        require(actual == expected, field)?;
    }
    let expected_profile_cases = match profile {
        X64StandaloneProfile::BranchMix => COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES,
        X64StandaloneProfile::Bounds => COREVM0_GATE_A_BOUNDS_CASES,
    };
    require(
        usage.profile_corpus_cases == expected_profile_cases,
        "profile corpus case count",
    )?;

    let relational_limit = usage
        .inherited_target_code_bytes
        .checked_add(limits.max_standalone_overhead_bytes)
        .ok_or(X64StandaloneArtifactError::ArithmeticOverflow {
            field: "target plus standalone overhead",
        })?;
    if usage.elf_image_bytes > relational_limit {
        return Err(X64StandaloneArtifactError::Limit {
            field: "image/target overhead relation",
            limit: relational_limit,
            actual: usage.elf_image_bytes,
        });
    }
    require(
        usage.elf_image_bytes
            == usage
                .inherited_target_code_bytes
                .checked_add(usage.standalone_overhead_bytes)
                .ok_or(X64StandaloneArtifactError::ArithmeticOverflow {
                    field: "exact image/target overhead relation",
                })?,
        "exact image/target overhead relation",
    )?;
    Ok(())
}

fn validate_canonical_artifact_usage(
    usage: X64StandaloneArtifactUsage,
    profile: X64StandaloneProfile,
) -> Result<(), X64StandaloneArtifactError> {
    let (expected_fixups, expected_code_bytes, expected_cases) = match profile {
        X64StandaloneProfile::BranchMix => (
            58,
            1_032,
            COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES,
        ),
        X64StandaloneProfile::Bounds => (59, 1_038, COREVM0_GATE_A_BOUNDS_CASES),
    };
    require(
        usage.pt_load_segments == 1
            && usage.program_headers == 2
            && usage.target_entry_fixups == 1
            && usage.startup_plan_ops == 26
            && usage.startup_labels == 32
            && usage.startup_fixups == expected_fixups
            && usage.startup_internal_call_fixups == 4
            && usage.startup_syscall_sites == 8
            && usage.startup_code_bytes == expected_code_bytes
            && usage.startup_stack_bytes == 183
            && usage.target_blob_copies == 1
            && usage.admitted_input_arrays == 1
            && usage.admitted_runtime_input_mappings == 1
            && usage.profile_corpus_cases == expected_cases,
        "canonical artifact usage vector",
    )
}

fn artifact_hash(
    identity: &X64StandaloneArtifactIdentity,
) -> Result<SemanticHash, X64StandaloneArtifactError> {
    let mut encoder = ArtifactIdentityEncoder::new();
    encoder.bytes(ARTIFACT_DOMAIN)?;
    for version in [
        X64_STANDALONE_ARTIFACT_SCHEMA_VERSION,
        X64_STANDALONE_ARTIFACT_WRITER_POLICY_VERSION,
        X64_STANDALONE_ARTIFACT_VERIFIER_POLICY_VERSION,
        X64_STANDALONE_ELF_LAYOUT_POLICY_VERSION,
        X64_STANDALONE_ELF_WRITER_POLICY_VERSION,
        X64_STANDALONE_ELF_VERIFIER_POLICY_VERSION,
        X64_STANDALONE_STARTUP_SCHEMA_VERSION,
        X64_STANDALONE_STARTUP_PLANNER_POLICY_VERSION,
        X64_STANDALONE_STARTUP_LOWERING_POLICY_VERSION,
        X64_STANDALONE_STARTUP_ENCODER_POLICY_VERSION,
        X64_STANDALONE_IO_SCHEMA_VERSION,
        X64_STANDALONE_IO_POLICY_VERSION,
    ] {
        encoder.version(version)?;
    }
    encoder.u16(identity.profile.wire_tag())?;
    encode_authority(&mut encoder, identity.authority)?;
    encoder.u32(
        u32::try_from(X64_STANDALONE_INHERITED_ENVELOPE_BYTES).map_err(|_| {
            X64StandaloneArtifactError::LengthConversion {
                field: "inherited envelope",
                actual: X64_STANDALONE_INHERITED_ENVELOPE_BYTES,
            }
        })?,
    )?;
    encoder.bytes(&identity.inherited_envelope_bytes)?;
    for hash in [
        identity.startup_plan_hash,
        identity.io_contract_hash,
        identity.startup_code_hash,
        identity.target_code_hash,
        identity.elf_image_hash,
    ] {
        encoder.hash(hash)?;
    }
    encode_layout(&mut encoder, identity.layout)?;
    encode_elf(&mut encoder, identity.elf)?;
    encode_limits(&mut encoder, identity.limits)?;
    encode_usage(&mut encoder, identity.usage)?;
    encode_dependencies(&mut encoder, identity.dependencies)?;
    Ok(SemanticHash(sha256(encoder.as_bytes())))
}

fn encode_authority(
    encoder: &mut ArtifactIdentityEncoder,
    authority: X64StandaloneAuthorityBinding,
) -> Result<(), X64StandaloneArtifactError> {
    encoder.u16(authority.profile.wire_tag())?;
    for hash in [
        authority.manifest_hash,
        authority.source_core_hash,
        authority.source_ssa_hash,
        authority.source_machine_ir_hash,
        authority.target_artifact_hash,
        authority.target_plan_hash,
        authority.target_code_hash,
        authority.canonical_abi_hash,
    ] {
        encoder.hash(hash)?;
    }
    encoder.u32(authority.entry_offset)?;
    encoder.u8(authority.input_lanes)?;
    encoder.hash(authority.semantic_results_hash)?;
    encoder.hash(authority.process_results_hash)?;
    encoder.u32(authority.canonical_case_count)
}

fn encode_layout(
    encoder: &mut ArtifactIdentityEncoder,
    layout: X64StandaloneArtifactLayout,
) -> Result<(), X64StandaloneArtifactError> {
    for value in [
        layout.elf_base,
        layout.elf_entry,
        layout.startup_offset,
        layout.startup_vaddr,
        layout.startup_bytes,
        layout.target_offset,
    ] {
        encoder.u64(value)?;
    }
    encoder.u32(layout.inherited_entry_offset)?;
    for value in [
        layout.target_entry_vaddr,
        layout.target_bytes,
        layout.image_bytes,
        layout.overhead_bytes,
        layout.target_alignment,
    ] {
        encoder.u64(value)?;
    }
    Ok(())
}

fn encode_elf(
    encoder: &mut ArtifactIdentityEncoder,
    elf: X64StandaloneElfFacts,
) -> Result<(), X64StandaloneArtifactError> {
    for value in [
        elf.class,
        elf.data,
        elf.ident_version,
        elf.os_abi,
        elf.abi_version,
    ] {
        encoder.u8(value)?;
    }
    encoder.u16(elf.object_type)?;
    encoder.u16(elf.machine)?;
    encoder.u32(elf.version)?;
    encoder.u64(elf.entry)?;
    encoder.u64(elf.program_headers_offset)?;
    encoder.u64(elf.section_headers_offset)?;
    encoder.u32(elf.flags)?;
    for value in [
        elf.elf_header_bytes,
        elf.program_header_bytes,
        elf.program_header_count,
        elf.section_header_bytes,
        elf.section_header_count,
        elf.section_name_index,
    ] {
        encoder.u16(value)?;
    }
    encoder.u32(elf.load_type)?;
    encoder.u32(elf.load_flags)?;
    for value in [
        elf.load_offset,
        elf.load_vaddr,
        elf.load_paddr,
        elf.load_filesz,
        elf.load_memsz,
        elf.load_alignment,
    ] {
        encoder.u64(value)?;
    }
    encoder.u32(elf.stack_type)?;
    encoder.u32(elf.stack_flags)?;
    for value in [
        elf.stack_offset,
        elf.stack_vaddr,
        elf.stack_paddr,
        elf.stack_filesz,
        elf.stack_memsz,
        elf.stack_alignment,
    ] {
        encoder.u64(value)?;
    }
    for value in [
        elf.pt_load_segments,
        elf.pt_interp_segments,
        elf.pt_dynamic_segments,
        elf.writable_executable_load_segments,
    ] {
        encoder.u32(value)?;
    }
    Ok(())
}

fn encode_limits(
    encoder: &mut ArtifactIdentityEncoder,
    limits: X64StandaloneArtifactLimits,
) -> Result<(), X64StandaloneArtifactError> {
    for value in [
        limits.max_pt_load_segments,
        limits.max_program_headers,
        limits.max_target_entry_fixups,
        limits.max_startup_plan_ops,
        limits.max_startup_labels,
        limits.max_startup_fixups,
    ] {
        encoder.u32(value)?;
    }
    for value in [
        limits.max_startup_code_bytes,
        limits.max_inherited_target_code_bytes,
    ] {
        encoder.u64(value)?;
    }
    encoder.u32(limits.max_target_blob_copies)?;
    for value in [
        limits.max_standalone_overhead_bytes,
        limits.max_elf_image_bytes,
    ] {
        encoder.u64(value)?;
    }
    encoder.u32(limits.max_input_arrays)?;
    for value in [
        limits.max_array_elements,
        limits.max_mapped_input_bytes,
        limits.max_input_frame_bytes,
        limits.output_frame_bytes,
    ] {
        encoder.u64(value)?;
    }
    for value in [
        limits.max_runtime_input_mappings,
        limits.max_startup_stack_bytes,
        limits.fixed_corpus_cases,
        limits.per_process_timeout_ms,
        limits.max_captured_diagnostic_bytes,
        limits.max_captured_diagnostic_records,
    ] {
        encoder.u32(value)?;
    }
    Ok(())
}

fn encode_usage(
    encoder: &mut ArtifactIdentityEncoder,
    usage: X64StandaloneArtifactUsage,
) -> Result<(), X64StandaloneArtifactError> {
    for value in [
        usage.pt_load_segments,
        usage.program_headers,
        usage.target_entry_fixups,
        usage.startup_plan_ops,
        usage.startup_labels,
        usage.startup_fixups,
        usage.startup_internal_call_fixups,
        usage.startup_syscall_sites,
    ] {
        encoder.u32(value)?;
    }
    encoder.u64(usage.startup_code_bytes)?;
    encoder.u32(usage.startup_stack_bytes)?;
    for value in [
        usage.inherited_target_code_bytes,
        usage.standalone_overhead_bytes,
        usage.elf_image_bytes,
    ] {
        encoder.u64(value)?;
    }
    for value in [
        usage.target_blob_copies,
        usage.admitted_input_arrays,
        usage.admitted_runtime_input_mappings,
        usage.profile_corpus_cases,
    ] {
        encoder.u32(value)?;
    }
    Ok(())
}

fn encode_dependencies(
    encoder: &mut ArtifactIdentityEncoder,
    dependencies: X64StandaloneDependencyClaims,
) -> Result<(), X64StandaloneArtifactError> {
    for value in [
        dependencies.interpreter_dependency,
        dependencies.external_symbol_dependency,
        dependencies.dynamic_loader_dependency,
        dependencies.system_linker_dependency,
        dependencies.fallback,
    ] {
        encoder.boolean(value)?;
    }
    Ok(())
}

fn require(condition: bool, field: &'static str) -> Result<(), X64StandaloneArtifactError> {
    if condition {
        Ok(())
    } else {
        Err(X64StandaloneArtifactError::CompositionMismatch { field })
    }
}

fn usize_to_u64(actual: usize, field: &'static str) -> Result<u64, X64StandaloneArtifactError> {
    u64::try_from(actual)
        .map_err(|_| X64StandaloneArtifactError::LengthConversion { field, actual })
}

fn elf_error(error: impl fmt::Display) -> X64StandaloneArtifactError {
    X64StandaloneArtifactError::Elf {
        message: error.to_string(),
    }
}

struct ArtifactIdentityEncoder {
    bytes: [u8; ARTIFACT_IDENTITY_MAX_BYTES],
    length: usize,
}

impl ArtifactIdentityEncoder {
    const fn new() -> Self {
        Self {
            bytes: [0; ARTIFACT_IDENTITY_MAX_BYTES],
            length: 0,
        }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), X64StandaloneArtifactError> {
        let end = self.length.checked_add(value.len()).ok_or(
            X64StandaloneArtifactError::IdentityByteLimit {
                limit: ARTIFACT_IDENTITY_MAX_BYTES,
                attempted: usize::MAX,
            },
        )?;
        if end > ARTIFACT_IDENTITY_MAX_BYTES {
            return Err(X64StandaloneArtifactError::IdentityByteLimit {
                limit: ARTIFACT_IDENTITY_MAX_BYTES,
                attempted: end,
            });
        }
        self.bytes[self.length..end].copy_from_slice(value);
        self.length = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), X64StandaloneArtifactError> {
        self.bytes(&[value])
    }

    fn boolean(&mut self, value: bool) -> Result<(), X64StandaloneArtifactError> {
        self.u8(u8::from(value))
    }

    fn u16(&mut self, value: u16) -> Result<(), X64StandaloneArtifactError> {
        self.bytes(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), X64StandaloneArtifactError> {
        self.bytes(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64StandaloneArtifactError> {
        self.bytes(&value.to_be_bytes())
    }

    fn version(&mut self, version: (u16, u16, u16)) -> Result<(), X64StandaloneArtifactError> {
        self.u16(version.0)?;
        self.u16(version.1)?;
        self.u16(version.2)
    }

    fn hash(&mut self, hash: SemanticHash) -> Result<(), X64StandaloneArtifactError> {
        self.bytes(&hash.0)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_cap_usage() -> X64StandaloneArtifactUsage {
        let limits = X64StandaloneArtifactLimits::r1_s8();
        X64StandaloneArtifactUsage {
            pt_load_segments: 1,
            program_headers: 2,
            target_entry_fixups: 1,
            startup_plan_ops: limits.max_startup_plan_ops,
            startup_labels: limits.max_startup_labels,
            startup_fixups: limits.max_startup_fixups,
            startup_internal_call_fixups: 4,
            startup_syscall_sites: 8,
            startup_code_bytes: limits.max_startup_code_bytes,
            startup_stack_bytes: limits.max_startup_stack_bytes,
            inherited_target_code_bytes: limits.max_inherited_target_code_bytes,
            target_blob_copies: 1,
            standalone_overhead_bytes: limits.max_standalone_overhead_bytes,
            elf_image_bytes: limits.max_elf_image_bytes,
            admitted_input_arrays: 1,
            admitted_runtime_input_mappings: 1,
            profile_corpus_cases: COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES,
        }
    }

    fn canonical_usage(profile: X64StandaloneProfile) -> X64StandaloneArtifactUsage {
        let (startup_fixups, startup_code_bytes, profile_corpus_cases) = match profile {
            X64StandaloneProfile::BranchMix => (
                58,
                1_032,
                COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES,
            ),
            X64StandaloneProfile::Bounds => (59, 1_038, COREVM0_GATE_A_BOUNDS_CASES),
        };
        X64StandaloneArtifactUsage {
            pt_load_segments: 1,
            program_headers: 2,
            target_entry_fixups: 1,
            startup_plan_ops: 26,
            startup_labels: 32,
            startup_fixups,
            startup_internal_call_fixups: 4,
            startup_syscall_sites: 8,
            startup_code_bytes,
            startup_stack_bytes: 183,
            inherited_target_code_bytes: 128,
            target_blob_copies: 1,
            standalone_overhead_bytes: 1_296,
            elf_image_bytes: 1_424,
            admitted_input_arrays: 1,
            admitted_runtime_input_mappings: 1,
            profile_corpus_cases,
        }
    }

    #[test]
    fn frozen_limit_vector_is_fully_inspectable_and_exact() {
        let limits = X64StandaloneArtifactLimits::r1_s8();
        assert_eq!(limits.max_pt_load_segments(), 1);
        assert_eq!(limits.max_program_headers(), 2);
        assert_eq!(limits.max_target_entry_fixups(), 1);
        assert_eq!(limits.max_startup_plan_ops(), 64);
        assert_eq!(limits.max_startup_labels(), 128);
        assert_eq!(limits.max_startup_fixups(), 128);
        assert_eq!(limits.max_startup_code_bytes(), 32_768);
        assert_eq!(limits.max_inherited_target_code_bytes(), 67_108_864);
        assert_eq!(limits.max_target_blob_copies(), 1);
        assert_eq!(limits.max_standalone_overhead_bytes(), 65_536);
        assert_eq!(limits.max_elf_image_bytes(), 67_174_400);
        assert_eq!(limits.max_input_arrays(), 1);
        assert_eq!(limits.max_array_elements(), 1_048_576);
        assert_eq!(limits.max_mapped_input_bytes(), 8_388_608);
        assert_eq!(limits.max_input_frame_bytes(), 8_388_648);
        assert_eq!(limits.output_frame_bytes(), 40);
        assert_eq!(limits.max_runtime_input_mappings(), 1);
        assert_eq!(limits.max_startup_stack_bytes(), 512);
        assert_eq!(limits.fixed_corpus_cases(), 51);
        assert_eq!(limits.per_process_timeout_ms(), 30_000);
        assert_eq!(limits.max_captured_diagnostic_bytes(), 16_384);
        assert_eq!(limits.max_captured_diagnostic_records(), 128);
    }

    #[test]
    fn exhaustive_artifact_admission_accepts_exact_caps() {
        validate_artifact_limits(
            X64StandaloneArtifactLimits::r1_s8(),
            exact_cap_usage(),
            X64StandaloneProfile::BranchMix,
        )
        .expect("every exact R1-S8 cap must be admitted");
    }

    #[test]
    fn exhaustive_artifact_admission_rejects_each_reachable_one_over_cap() {
        let limits = X64StandaloneArtifactLimits::r1_s8();
        let mut candidates = Vec::new();

        let mut usage = exact_cap_usage();
        usage.pt_load_segments = limits.max_pt_load_segments + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.program_headers = limits.max_program_headers + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.target_entry_fixups = limits.max_target_entry_fixups + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.startup_plan_ops = limits.max_startup_plan_ops + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.startup_labels = limits.max_startup_labels + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.startup_fixups = limits.max_startup_fixups + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.startup_code_bytes = limits.max_startup_code_bytes + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.inherited_target_code_bytes = limits.max_inherited_target_code_bytes + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.target_blob_copies = limits.max_target_blob_copies + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.standalone_overhead_bytes = limits.max_standalone_overhead_bytes + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.elf_image_bytes = limits.max_elf_image_bytes + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.admitted_input_arrays = limits.max_input_arrays + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.admitted_runtime_input_mappings = limits.max_runtime_input_mappings + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.startup_stack_bytes = limits.max_startup_stack_bytes + 1;
        candidates.push(usage);
        usage = exact_cap_usage();
        usage.profile_corpus_cases = limits.fixed_corpus_cases + 1;
        candidates.push(usage);

        for candidate in candidates {
            assert!(
                validate_artifact_limits(limits, candidate, X64StandaloneProfile::BranchMix)
                    .is_err(),
                "every independently constructible one-over usage must fail closed"
            );
        }
    }

    #[test]
    fn artifact_admission_rejects_inexact_relations_and_profile_counts() {
        let limits = X64StandaloneArtifactLimits::r1_s8();
        let mut usage = exact_cap_usage();
        usage.elf_image_bytes -= 1;
        assert!(validate_artifact_limits(limits, usage, X64StandaloneProfile::BranchMix).is_err());

        usage = exact_cap_usage();
        usage.profile_corpus_cases = COREVM0_GATE_A_BOUNDS_CASES;
        assert!(validate_artifact_limits(limits, usage, X64StandaloneProfile::BranchMix).is_err());

        usage.profile_corpus_cases = COREVM0_GATE_A_BOUNDS_CASES;
        validate_artifact_limits(limits, usage, X64StandaloneProfile::Bounds)
            .expect("the exact five-case Bounds profile count must be admitted");
    }

    #[test]
    fn canonical_usage_vector_is_profile_exact() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let usage = canonical_usage(profile);
            validate_canonical_artifact_usage(usage, profile)
                .expect("the exact profile usage must be admitted");

            let mut mutated = usage;
            mutated.startup_syscall_sites += 1;
            assert!(validate_canonical_artifact_usage(mutated, profile).is_err());
        }
        assert!(validate_canonical_artifact_usage(
            canonical_usage(X64StandaloneProfile::BranchMix),
            X64StandaloneProfile::Bounds,
        )
        .is_err());
    }

    #[test]
    fn target_alignment_and_identity_capacity_fail_closed() {
        assert_eq!(
            independently_derive_target_offset(1_032).expect("BranchMix placement"),
            0x510
        );
        assert_eq!(
            independently_derive_target_offset(1_038).expect("Bounds placement"),
            0x510
        );

        let mut encoder = ArtifactIdentityEncoder::new();
        encoder
            .bytes(&vec![0; ARTIFACT_IDENTITY_MAX_BYTES])
            .expect("the exact identity byte cap must be accepted");
        assert!(matches!(
            encoder.u8(0),
            Err(X64StandaloneArtifactError::IdentityByteLimit {
                limit: ARTIFACT_IDENTITY_MAX_BYTES,
                attempted
            }) if attempted == ARTIFACT_IDENTITY_MAX_BYTES + 1
        ));
    }
}
