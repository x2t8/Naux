//! Owned, deterministic raw x86-64 encoding for the R1-S7A target plan.
//!
//! The encoder deliberately exposes no arbitrary instruction or byte escape.
//! Every emitted byte belongs to one fixed System V AMD64/SSE2 template, and
//! every control transfer is an internal retained `rel32` fixup.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RawEncoding {
    pub(super) labels: Vec<X64Label>,
    pub(super) fixups: Vec<X64Fixup>,
    pub(super) code: Vec<u8>,
    pub(super) realization: RawRealization,
    /// Internal transient used only for independent prospective replay. These
    /// bytes are never selected as the executable policy-1.4 encoding.
    pub(super) prospective_shadow: Option<RawProspectiveShadow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RawExecutionEvent {
    Entry,
    Instruction { label: X64LabelId, index: u32 },
    Tail { label: X64LabelId },
    Return { label: X64LabelId },
    Branch { label: X64LabelId },
    BranchElse { label: X64LabelId },
    ReturnEpilogue,
    BoundsEpilogue,
    Static,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RawTemplateClass {
    EntryPrologue,
    OrdinaryInstruction,
    RegisterInstruction,
    TailTransfer,
    ReturnTransfer,
    BranchCondition,
    BranchElseJump,
    FusedCompareInstruction,
    ReturnEpilogue,
    BoundsEpilogue,
    Tombstone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RawSharedJoinKind {
    RegisterInstruction,
    FusedCompare,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawSharedJoinIngress {
    pub(super) root: X64LabelId,
    pub(super) trigger: X64LabelId,
    pub(super) frame_accesses: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RawSharedJoinOpportunity {
    pub(super) target: X64LabelId,
    pub(super) kind: RawSharedJoinKind,
    pub(super) ingresses: Vec<RawSharedJoinIngress>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RawSharedJoinLineageEvent {
    Instruction {
        label: X64LabelId,
        index: u32,
    },
    Tail {
        source: X64LabelId,
        target: X64LabelId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RawSharedJoinCompositionIngress {
    pub(super) root: X64LabelId,
    /// A pre-composition tail event whose dynamic count remains equal to this
    /// root's executions after deterministic one-operation clones are added.
    pub(super) authority_trigger: X64LabelId,
    pub(super) frame_accesses: u32,
    /// Exact logical route from `authority_trigger` to this composition
    /// step's target, independently replayed from the unmodified target CFG.
    pub(super) lineage: Vec<RawSharedJoinLineageEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawSharedJoinBranchPath {
    pub(super) branch_label: X64LabelId,
    pub(super) then_label: X64LabelId,
    pub(super) else_label: X64LabelId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RawSharedJoinCompositionStep {
    pub(super) target: X64LabelId,
    pub(super) kind: RawSharedJoinKind,
    pub(super) branch_path: Option<RawSharedJoinBranchPath>,
    /// Earlier shared targets whose clones feed at least one ingress here.
    pub(super) ancestors: Vec<X64LabelId>,
    pub(super) ingresses: Vec<RawSharedJoinCompositionIngress>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RawSharedJoinComposition {
    pub(super) complete: bool,
    pub(super) steps: Vec<RawSharedJoinCompositionStep>,
    pub(super) body_replicas: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawRealizationAtom {
    pub(super) event: RawExecutionEvent,
    pub(super) class: RawTemplateClass,
    pub(super) start: u32,
    pub(super) end: u32,
}

impl RawRealizationAtom {
    pub(super) const fn byte_len(self) -> u32 {
        self.end - self.start
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RawProspectiveSharedJoinPartition {
    All,
    Else,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RawProspectiveExecutionAuthority {
    SemanticEvent(RawExecutionEvent),
    Static,
    SharedJoin {
        target: X64LabelId,
        root: X64LabelId,
        authority_trigger: X64LabelId,
        partition: RawProspectiveSharedJoinPartition,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawProspectiveRealizationAtom {
    pub(super) physical_owner: X64LabelId,
    pub(super) semantic_event: RawExecutionEvent,
    pub(super) class: RawTemplateClass,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) execution_authority: RawProspectiveExecutionAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RawProspectiveLabelDisposition {
    Live,
    ReachabilityTombstone,
    UniqueChainTombstone,
    SharedJoinTombstone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawProspectiveLabelReceipt {
    pub(super) label: X64LabelId,
    pub(super) owner: X64LabelOwner,
    pub(super) code_offset: u32,
    pub(super) owning_atom: u32,
    pub(super) disposition: RawProspectiveLabelDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawProspectiveFixupReceipt {
    pub(super) fixup_index: u32,
    pub(super) owning_atom: u32,
    pub(super) patch_offset: u32,
    pub(super) target: X64LabelId,
    pub(super) addend: i32,
}

/// Shadow-only evidence for the first shared-join realization slice.
///
/// Candidate bytes are never selected by encoder policy 1.4. Any failure
/// while encoding or independently validating them yields `Default`, so a
/// partial prospective proof cannot escape into profiling or replay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RawProspectiveSharedJoinRealization {
    pub(super) complete: bool,
    pub(super) baseline_code_bytes: u64,
    pub(super) baseline_code_hash: SemanticHash,
    pub(super) candidate_code_bytes: u64,
    pub(super) candidate_code_hash: SemanticHash,
    pub(super) code_bytes_added: u64,
    pub(super) code_bytes_removed: u64,
    pub(super) baseline_atom_count: u64,
    pub(super) candidate_atom_count: u64,
    pub(super) atom_count_added: u64,
    pub(super) atom_count_removed: u64,
    pub(super) baseline_fixup_count: u64,
    pub(super) candidate_fixup_count: u64,
    pub(super) fixup_count_added: u64,
    pub(super) fixup_count_removed: u64,
    pub(super) body_replicas: u32,
    /// Candidate atoms whose execution authority is a shared-join ingress.
    pub(super) shared_join_authority_atoms: u32,
    pub(super) atoms: Vec<RawProspectiveRealizationAtom>,
    pub(super) labels: Vec<RawProspectiveLabelReceipt>,
    pub(super) fixups: Vec<RawProspectiveFixupReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RawProspectiveShadow {
    pub(super) labels: Vec<X64Label>,
    pub(super) fixups: Vec<X64Fixup>,
    pub(super) code: Vec<u8>,
    pub(super) atoms: Vec<RawRealizationAtom>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RawRealization {
    pub(super) optimized: bool,
    pub(super) atoms: Vec<RawRealizationAtom>,
    pub(super) shared_join_opportunities: Vec<RawSharedJoinOpportunity>,
    pub(super) shared_join_composition: RawSharedJoinComposition,
    pub(super) prospective_shared_join_realization: RawProspectiveSharedJoinRealization,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RawEncodeError {
    CodeLimit {
        limit: u64,
        attempted: u64,
    },
    FixupLimit {
        limit: u64,
        attempted: u64,
    },
    LabelLimit {
        limit: u64,
        actual: u64,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    OffsetOutOfRange {
        field: &'static str,
        offset: u64,
    },
    FrameAccess {
        field: &'static str,
        offset: u32,
        width: u32,
        frame_bytes: u32,
    },
    InvalidHome {
        field: &'static str,
        home: X64Home,
    },
    InvalidOutgoingAccess {
        offset: u32,
        width: u32,
        outgoing_base: u32,
        outgoing_bytes: u32,
    },
    DuplicateLabel {
        label: X64LabelId,
    },
    DuplicateLabelOwner {
        owner: X64LabelOwner,
    },
    MissingLabelOwner {
        owner: X64LabelOwner,
    },
    UnknownLabel {
        label: X64LabelId,
    },
    LabelAlreadyMarked {
        label: X64LabelId,
    },
    LabelNotMarked {
        label: X64LabelId,
    },
    MissingFunction {
        function: X64FunctionId,
    },
    MissingBlock {
        function: X64FunctionId,
        block: X64BlockId,
    },
    EntryOffset {
        declared: u32,
    },
    EntryLaneManifest {
        expected: usize,
        actual: usize,
    },
    InvalidEntryLane {
        parameter: u32,
        word: u8,
    },
    InvalidOperand {
        context: &'static str,
        expected: MachineType,
        actual: MachineType,
    },
    InvalidArrayOperand {
        context: &'static str,
    },
    InvalidResultWidth {
        context: &'static str,
        ty: MachineType,
        expected: u8,
        actual: u8,
    },
    TailArity {
        function: X64FunctionId,
        arguments: usize,
        parameters: usize,
    },
    TailExtent {
        required: u32,
        declared: u32,
    },
    Rel32OutOfRange {
        patch_offset: u32,
        target: X64LabelId,
        displacement: i64,
    },
    FixupPatchRange {
        patch_offset: u32,
        code_bytes: usize,
    },
    FixupOrder {
        previous: u32,
        current: u32,
    },
    OptimizationRefused {
        context: &'static str,
    },
}

impl fmt::Display for RawEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CodeLimit { limit, attempted } => {
                write!(
                    formatter,
                    "raw x86-64 code would use {attempted} bytes; limit is {limit}"
                )
            }
            Self::FixupLimit { limit, attempted } => {
                write!(
                    formatter,
                    "raw x86-64 encoding would use {attempted} fixups; limit is {limit}"
                )
            }
            Self::LabelLimit { limit, actual } => {
                write!(
                    formatter,
                    "raw x86-64 encoding has {actual} labels; limit is {limit}"
                )
            }
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "arithmetic overflow while encoding {field}")
            }
            Self::OffsetOutOfRange { field, offset } => {
                write!(formatter, "{field} offset {offset} cannot be encoded")
            }
            Self::FrameAccess {
                field,
                offset,
                width,
                frame_bytes,
            } => write!(
                formatter,
                "{field} frame access [{offset}, {offset}+{width}) exceeds frame size {frame_bytes}"
            ),
            Self::InvalidHome { field, home } => write!(
                formatter,
                "{field} uses invalid home slot {} at offset {} with width {}",
                home.slot.0, home.offset, home.width
            ),
            Self::InvalidOutgoingAccess {
                offset,
                width,
                outgoing_base,
                outgoing_bytes,
            } => write!(
                formatter,
                "outgoing access [{offset}, {offset}+{width}) is outside [{outgoing_base}, {outgoing_base}+{outgoing_bytes})"
            ),
            Self::DuplicateLabel { label } => {
                write!(formatter, "target label {} is duplicated", label.0)
            }
            Self::DuplicateLabelOwner { owner } => {
                write!(formatter, "target label owner {owner:?} is duplicated")
            }
            Self::MissingLabelOwner { owner } => {
                write!(formatter, "target label owner {owner:?} is missing")
            }
            Self::UnknownLabel { label } => {
                write!(formatter, "target label {} is unknown", label.0)
            }
            Self::LabelAlreadyMarked { label } => {
                write!(formatter, "target label {} was marked twice", label.0)
            }
            Self::LabelNotMarked { label } => {
                write!(formatter, "target label {} was not laid out", label.0)
            }
            Self::MissingFunction { function } => {
                write!(formatter, "target function {} is missing", function.0)
            }
            Self::MissingBlock { function, block } => write!(
                formatter,
                "target function {} has no block {}",
                function.0, block.0
            ),
            Self::EntryOffset { declared } => {
                write!(
                    formatter,
                    "target entry offset must be zero, found {declared}"
                )
            }
            Self::EntryLaneManifest { expected, actual } => write!(
                formatter,
                "target entry ABI requires {expected} input lanes, found {actual}"
            ),
            Self::InvalidEntryLane { parameter, word } => write!(
                formatter,
                "target entry lane references invalid parameter {parameter} word {word}"
            ),
            Self::InvalidOperand {
                context,
                expected,
                actual,
            } => write!(
                formatter,
                "{context} expected operand {expected:?}, found {actual:?}"
            ),
            Self::InvalidArrayOperand { context } => {
                write!(formatter, "{context} requires an F64Array home operand")
            }
            Self::InvalidResultWidth {
                context,
                ty,
                expected,
                actual,
            } => write!(
                formatter,
                "{context} result {ty:?} requires width {expected}, found {actual}"
            ),
            Self::TailArity {
                function,
                arguments,
                parameters,
            } => write!(
                formatter,
                "tail transfer to function {} has {arguments} arguments for {parameters} parameters",
                function.0
            ),
            Self::TailExtent { required, declared } => write!(
                formatter,
                "tail transfer requires {required} outgoing bytes; frame declares {declared}"
            ),
            Self::Rel32OutOfRange {
                patch_offset,
                target,
                displacement,
            } => write!(
                formatter,
                "rel32 at {patch_offset} targeting label {} has out-of-range displacement {displacement}",
                target.0
            ),
            Self::FixupPatchRange {
                patch_offset,
                code_bytes,
            } => write!(
                formatter,
                "rel32 patch [{patch_offset}, {patch_offset}+4) exceeds {code_bytes} code bytes"
            ),
            Self::FixupOrder { previous, current } => write!(
                formatter,
                "fixup offsets are not strictly increasing: {previous}, then {current}"
            ),
            Self::OptimizationRefused { context } => {
                write!(formatter, "raw x86-64 optimization refused: {context}")
            }
        }
    }
}

impl std::error::Error for RawEncodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gpr {
    Rax,
    Rcx,
    Rdx,
    Rdi,
    Rsi,
    R8,
    R9,
}

impl Gpr {
    const fn number(self) -> u8 {
        match self {
            Self::Rax => 0,
            Self::Rcx => 1,
            Self::Rdx => 2,
            Self::Rsi => 6,
            Self::Rdi => 7,
            Self::R8 => 8,
            Self::R9 => 9,
        }
    }
}

struct RawEmitter {
    code: Vec<u8>,
    labels: Vec<X64Label>,
    label_indices: BTreeMap<X64LabelId, usize>,
    marked_labels: BTreeMap<X64LabelId, u32>,
    fixups: Vec<X64Fixup>,
    code_limit: u64,
    fixup_limit: u64,
    atoms: Vec<RawRealizationAtom>,
}

impl RawEmitter {
    fn new(program: &X64TargetProgram) -> Result<Self, RawEncodeError> {
        let label_limit = program.limits.max_labels.min(X64_TARGET_MAX_LABELS);
        let label_count = u64::try_from(program.labels.len()).map_err(|_| {
            RawEncodeError::ArithmeticOverflow {
                field: "label count",
            }
        })?;
        if label_count > label_limit {
            return Err(RawEncodeError::LabelLimit {
                limit: label_limit,
                actual: label_count,
            });
        }

        let mut label_indices = BTreeMap::new();
        let mut labels = program.labels.clone();
        for (index, label) in labels.iter_mut().enumerate() {
            if label_indices.insert(label.id, index).is_some() {
                return Err(RawEncodeError::DuplicateLabel { label: label.id });
            }
            label.code_offset = 0;
        }

        Ok(Self {
            code: Vec::new(),
            labels,
            label_indices,
            marked_labels: BTreeMap::new(),
            fixups: Vec::new(),
            code_limit: program.limits.max_code_bytes.min(X64_TARGET_MAX_CODE_BYTES),
            fixup_limit: program.limits.max_fixups.min(X64_TARGET_MAX_FIXUPS),
            atoms: Vec::new(),
        })
    }

    fn offset(&self, field: &'static str) -> Result<u32, RawEncodeError> {
        u32::try_from(self.code.len()).map_err(|_| RawEncodeError::OffsetOutOfRange {
            field,
            offset: self.code.len() as u64,
        })
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), RawEncodeError> {
        let attempted =
            self.code
                .len()
                .checked_add(bytes.len())
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "raw code length",
                })?;
        let attempted =
            u64::try_from(attempted).map_err(|_| RawEncodeError::ArithmeticOverflow {
                field: "raw code length",
            })?;
        if attempted > self.code_limit {
            return Err(RawEncodeError::CodeLimit {
                limit: self.code_limit,
                attempted,
            });
        }
        self.code.extend_from_slice(bytes);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), RawEncodeError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), RawEncodeError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), RawEncodeError> {
        self.bytes(&value.to_le_bytes())
    }

    fn mark(&mut self, label: X64LabelId) -> Result<(), RawEncodeError> {
        let index = *self
            .label_indices
            .get(&label)
            .ok_or(RawEncodeError::UnknownLabel { label })?;
        let offset = self.offset("label")?;
        if self.marked_labels.insert(label, offset).is_some() {
            return Err(RawEncodeError::LabelAlreadyMarked { label });
        }
        self.labels[index].code_offset = offset;
        Ok(())
    }

    fn rel32(&mut self, opcode: &[u8], target: X64LabelId) -> Result<(), RawEncodeError> {
        if !self.label_indices.contains_key(&target) {
            return Err(RawEncodeError::UnknownLabel { label: target });
        }
        self.bytes(opcode)?;
        let patch_offset = self.offset("rel32 patch")?;
        self.u32(0)?;
        let attempted =
            self.fixups
                .len()
                .checked_add(1)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "fixup count",
                })?;
        let attempted =
            u64::try_from(attempted).map_err(|_| RawEncodeError::ArithmeticOverflow {
                field: "fixup count",
            })?;
        if attempted > self.fixup_limit {
            return Err(RawEncodeError::FixupLimit {
                limit: self.fixup_limit,
                attempted,
            });
        }
        self.fixups.push(X64Fixup {
            patch_offset,
            target,
            addend: 0,
        });
        Ok(())
    }

    fn atom<ResultValue>(
        &mut self,
        event: RawExecutionEvent,
        class: RawTemplateClass,
        emit: impl FnOnce(&mut Self) -> Result<ResultValue, RawEncodeError>,
    ) -> Result<ResultValue, RawEncodeError> {
        let start = self.offset("realization atom start")?;
        let result = emit(self)?;
        let end = self.offset("realization atom end")?;
        if end > start {
            self.atoms.push(RawRealizationAtom {
                event,
                class,
                start,
                end,
            });
        }
        Ok(result)
    }

    fn finish(
        mut self,
        optimized: bool,
        shared_join_opportunities: Vec<RawSharedJoinOpportunity>,
        shared_join_composition: RawSharedJoinComposition,
    ) -> Result<RawEncoding, RawEncodeError> {
        for label in &self.labels {
            if !self.marked_labels.contains_key(&label.id) {
                return Err(RawEncodeError::LabelNotMarked { label: label.id });
            }
        }

        self.fixups.sort_by_key(|fixup| fixup.patch_offset);
        let mut previous = None;
        for fixup in &self.fixups {
            if let Some(previous) = previous {
                if fixup.patch_offset <= previous {
                    return Err(RawEncodeError::FixupOrder {
                        previous,
                        current: fixup.patch_offset,
                    });
                }
            }
            previous = Some(fixup.patch_offset);

            let patch_start = usize::try_from(fixup.patch_offset).map_err(|_| {
                RawEncodeError::FixupPatchRange {
                    patch_offset: fixup.patch_offset,
                    code_bytes: self.code.len(),
                }
            })?;
            let patch_end =
                patch_start
                    .checked_add(4)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "rel32 patch end",
                    })?;
            if patch_end > self.code.len() {
                return Err(RawEncodeError::FixupPatchRange {
                    patch_offset: fixup.patch_offset,
                    code_bytes: self.code.len(),
                });
            }
            let target_offset =
                *self
                    .marked_labels
                    .get(&fixup.target)
                    .ok_or(RawEncodeError::LabelNotMarked {
                        label: fixup.target,
                    })?;
            let next_instruction = i64::from(fixup.patch_offset).checked_add(4).ok_or(
                RawEncodeError::ArithmeticOverflow {
                    field: "rel32 next instruction",
                },
            )?;
            let displacement = i64::from(target_offset)
                .checked_add(i64::from(fixup.addend))
                .and_then(|target| target.checked_sub(next_instruction))
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "rel32 displacement",
                })?;
            let displacement =
                i32::try_from(displacement).map_err(|_| RawEncodeError::Rel32OutOfRange {
                    patch_offset: fixup.patch_offset,
                    target: fixup.target,
                    displacement,
                })?;
            self.code[patch_start..patch_end].copy_from_slice(&displacement.to_le_bytes());
        }

        let mut cursor = 0_u32;
        for atom in &self.atoms {
            if atom.start != cursor || atom.end <= atom.start {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "non-canonical realization atom coverage",
                });
            }
            cursor = atom.end;
        }
        if usize::try_from(cursor).ok() != Some(self.code.len()) {
            return Err(RawEncodeError::OptimizationRefused {
                context: "incomplete realization atom coverage",
            });
        }

        Ok(RawEncoding {
            labels: self.labels,
            fixups: self.fixups,
            code: self.code,
            realization: RawRealization {
                optimized,
                atoms: self.atoms,
                shared_join_opportunities,
                shared_join_composition,
                prospective_shared_join_realization: RawProspectiveSharedJoinRealization::default(),
            },
            prospective_shadow: None,
        })
    }
}

pub(super) fn encode(program: &X64TargetProgram) -> Result<RawEncoding, RawEncodeError> {
    if program.entry_offset != 0 {
        return Err(RawEncodeError::EntryOffset {
            declared: program.entry_offset,
        });
    }
    check_frame_header(program)?;

    let entry_adapter = unique_owner_label(program, X64LabelOwner::EntryAdapter)?;
    let return_epilogue = unique_owner_label(program, X64LabelOwner::ReturnEpilogue)?;
    let bounds_epilogue = unique_owner_label(program, X64LabelOwner::BoundsEpilogue)?;
    let entry_function = function(program, program.entry)?;
    let entry_block = block(entry_function, entry_function.entry_block)?;
    let threaded_entry = thread_noop_tail_target(program, entry_block.label)?;

    // Preserve the ordinary encoder's validation/error boundary before any
    // reachability-based omission is considered. Optimization proof failure
    // is fail-closed and retains these bytes.
    let ordinary = encode_layout(
        program,
        entry_adapter,
        return_epilogue,
        bounds_epilogue,
        entry_function,
        threaded_entry,
        None,
    )?;
    let Ok(planning) = EmissionPlan::build_with_prospective(program, threaded_entry) else {
        return Ok(ordinary);
    };
    let plan = &planning.emission;
    let optimized = encode_layout(
        program,
        entry_adapter,
        return_epilogue,
        bounds_epilogue,
        entry_function,
        threaded_entry,
        Some(EmissionLayoutView::accepted(plan)),
    );
    let Ok(mut selected) = optimized else {
        return Ok(ordinary);
    };
    let prospective = shadow_shared_join_realization(
        ProspectiveShadowEncodingContext {
            program,
            entry_adapter,
            return_epilogue,
            bounds_epilogue,
            entry_function,
            threaded_entry,
        },
        plan,
        &planning.prospective,
        &selected,
        ProspectiveRealizationLimits::production(),
    );
    attach_prospective_shared_join_realization(&mut selected, prospective);
    Ok(selected)
}

fn attach_prospective_shared_join_realization(
    selected: &mut RawEncoding,
    prospective: Result<
        (RawProspectiveSharedJoinRealization, RawProspectiveShadow),
        RawEncodeError,
    >,
) {
    match prospective {
        Ok((evidence, shadow)) if evidence.complete => {
            selected.realization.prospective_shared_join_realization = evidence;
            selected.prospective_shadow = Some(shadow);
        }
        Ok(_) | Err(_) => {
            selected.realization.prospective_shared_join_realization =
                RawProspectiveSharedJoinRealization::default();
            selected.prospective_shadow = None;
        }
    }
}

#[cfg(test)]
fn fail_closed_optimized_layout(
    ordinary: RawEncoding,
    optimized: Result<RawEncoding, RawEncodeError>,
) -> RawEncoding {
    match optimized {
        Ok(encoding) => encoding,
        Err(_) => ordinary,
    }
}

#[derive(Clone, Copy)]
struct ProspectiveRealizationLimits {
    max_body_replicas: u32,
    max_atoms_per_replica: u32,
    max_positive_code_growth: u64,
}

impl ProspectiveRealizationLimits {
    const fn production() -> Self {
        Self {
            max_body_replicas: MAX_SHARED_JOIN_BODY_REPLICAS,
            max_atoms_per_replica: 3,
            max_positive_code_growth: 64 * 1024,
        }
    }
}

#[derive(Clone, Copy)]
struct ProspectiveShadowEncodingContext<'program> {
    program: &'program X64TargetProgram,
    entry_adapter: X64LabelId,
    return_epilogue: X64LabelId,
    bounds_epilogue: X64LabelId,
    entry_function: &'program X64Function,
    threaded_entry: X64LabelId,
}

fn shadow_shared_join_realization(
    context: ProspectiveShadowEncodingContext<'_>,
    plan: &EmissionPlan,
    prospective_plan: &ProspectiveSharedJoinPlan,
    baseline: &RawEncoding,
    limits: ProspectiveRealizationLimits,
) -> Result<(RawProspectiveSharedJoinRealization, RawProspectiveShadow), RawEncodeError> {
    if !plan.shared_join_composition.complete
        || plan.shared_join_composition.steps.is_empty()
        || plan.shared_join_composition.body_replicas == 0
    {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared-join composition is empty",
        });
    }

    let selected_targets = plan
        .shared_join_composition
        .steps
        .iter()
        .map(|step| step.target)
        .collect::<BTreeSet<_>>();
    if selected_targets.len() != plan.shared_join_composition.steps.len()
        || selected_targets != prospective_plan.shared_consumed
        || selected_targets
            .iter()
            .any(|target| plan.consumed.contains(target) || !plan.reachable.contains(target))
    {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared-join selected target ownership",
        });
    }

    let mut replica_count = 0_u32;
    for step in &plan.shared_join_composition.steps {
        let step_replicas = u32::try_from(step.ingresses.len()).map_err(|_| {
            RawEncodeError::ArithmeticOverflow {
                field: "prospective shared-join step replicas",
            }
        })?;
        replica_count =
            replica_count
                .checked_add(step_replicas)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "prospective shared-join replicas",
                })?;
    }
    if replica_count != plan.shared_join_composition.body_replicas
        || replica_count > limits.max_body_replicas
    {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared-join replica cap",
        });
    }

    let mut candidate_consumed = plan.consumed.clone();
    candidate_consumed.extend(prospective_plan.shared_consumed.iter().copied());
    let candidate = encode_layout(
        context.program,
        context.entry_adapter,
        context.return_epilogue,
        context.bounds_epilogue,
        context.entry_function,
        context.threaded_entry,
        Some(EmissionLayoutView {
            reachable: &plan.reachable,
            consumed: &candidate_consumed,
            chains: &prospective_plan.composed_chains,
            shared_join_opportunities: &plan.shared_join_opportunities,
            shared_join_composition: &plan.shared_join_composition,
        }),
    )?;

    let evidence = validate_prospective_shared_join_realization(
        context.program,
        plan,
        prospective_plan,
        baseline,
        &candidate,
        limits,
    )?;
    let shadow = RawProspectiveShadow {
        labels: candidate.labels,
        fixups: candidate.fixups,
        code: candidate.code,
        atoms: candidate.realization.atoms,
    };
    Ok((evidence, shadow))
}

fn validate_prospective_shared_join_realization(
    program: &X64TargetProgram,
    plan: &EmissionPlan,
    prospective_plan: &ProspectiveSharedJoinPlan,
    baseline: &RawEncoding,
    candidate: &RawEncoding,
    limits: ProspectiveRealizationLimits,
) -> Result<RawProspectiveSharedJoinRealization, RawEncodeError> {
    if !baseline.realization.optimized
        || !candidate.realization.optimized
        || candidate.realization.shared_join_composition != plan.shared_join_composition
        || candidate.prospective_shadow.is_some()
    {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared-join encoding boundary",
        });
    }

    let baseline_code_bytes = prospective_len("prospective baseline code", baseline.code.len())?;
    let candidate_code_bytes = prospective_len("prospective candidate code", candidate.code.len())?;
    let baseline_atom_count = prospective_len(
        "prospective baseline atom count",
        baseline.realization.atoms.len(),
    )?;
    let candidate_atom_count = prospective_len(
        "prospective candidate atom count",
        candidate.realization.atoms.len(),
    )?;
    let baseline_fixup_count =
        prospective_len("prospective baseline fixup count", baseline.fixups.len())?;
    let candidate_fixup_count =
        prospective_len("prospective candidate fixup count", candidate.fixups.len())?;
    let (code_bytes_added, code_bytes_removed) =
        prospective_delta(baseline_code_bytes, candidate_code_bytes)?;
    let (atom_count_added, atom_count_removed) =
        prospective_delta(baseline_atom_count, candidate_atom_count)?;
    let (fixup_count_added, fixup_count_removed) =
        prospective_delta(baseline_fixup_count, candidate_fixup_count)?;

    let code_limit = program.limits.max_code_bytes.min(X64_TARGET_MAX_CODE_BYTES);
    let fixup_limit = program.limits.max_fixups.min(X64_TARGET_MAX_FIXUPS);
    if candidate_code_bytes > code_limit || candidate_fixup_count > fixup_limit {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared-join global output cap",
        });
    }
    let relative_growth_cap = baseline_code_bytes / 4;
    let positive_growth_cap = relative_growth_cap.min(limits.max_positive_code_growth);
    if code_bytes_added > positive_growth_cap {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared-join code growth cap",
        });
    }

    validate_prospective_atom_coverage(&candidate.realization.atoms, candidate_code_bytes)?;
    let (labels, labels_by_offset, label_dispositions) = prospective_label_receipts(
        program,
        plan,
        prospective_plan,
        &candidate.labels,
        &candidate.code,
        &candidate.realization.atoms,
    )?;
    let baseline_labels_by_offset = baseline
        .labels
        .iter()
        .map(|label| (label.code_offset, label.id))
        .collect::<BTreeMap<_, _>>();
    if baseline_labels_by_offset.len() != baseline.labels.len() {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective baseline duplicate label offset",
        });
    }
    let (atoms, shared_join_authority_atoms) = prospective_atom_receipts(
        plan,
        &baseline.realization.atoms,
        &baseline_labels_by_offset,
        &candidate.realization.atoms,
        &labels_by_offset,
        &label_dispositions,
    )?;
    let max_added_atoms = limits
        .max_atoms_per_replica
        .checked_mul(plan.shared_join_composition.body_replicas)
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "prospective shared-join added atom cap",
        })?;
    if atom_count_added > u64::from(max_added_atoms) {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared-join added atom cap",
        });
    }
    let max_added_fixups = plan
        .shared_join_composition
        .body_replicas
        .checked_mul(2)
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "prospective shared-join added fixup cap",
        })?;
    if fixup_count_added > u64::from(max_added_fixups) {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared-join added fixup cap",
        });
    }
    let no_fixup_tail_edges = prospective_no_fixup_tail_edges(prospective_plan)?;
    let fixups = prospective_fixup_receipts(
        program,
        &candidate.labels,
        &candidate.fixups,
        &candidate.code,
        &atoms,
        &label_dispositions,
        &no_fixup_tail_edges,
    )?;

    let baseline_code_hash =
        x64_target_code_hash(&baseline.code).map_err(|_| RawEncodeError::OptimizationRefused {
            context: "prospective baseline code hash",
        })?;
    let candidate_code_hash = prospective_shared_join_code_hash(&candidate.code)?;

    Ok(RawProspectiveSharedJoinRealization {
        complete: true,
        baseline_code_bytes,
        baseline_code_hash,
        candidate_code_bytes,
        candidate_code_hash,
        code_bytes_added,
        code_bytes_removed,
        baseline_atom_count,
        candidate_atom_count,
        atom_count_added,
        atom_count_removed,
        baseline_fixup_count,
        candidate_fixup_count,
        fixup_count_added,
        fixup_count_removed,
        body_replicas: plan.shared_join_composition.body_replicas,
        shared_join_authority_atoms,
        atoms,
        labels,
        fixups,
    })
}

fn prospective_len(field: &'static str, length: usize) -> Result<u64, RawEncodeError> {
    u64::try_from(length).map_err(|_| RawEncodeError::ArithmeticOverflow { field })
}

const PROSPECTIVE_SHARED_JOIN_CODE_DOMAIN: &[u8] = b"NAUX:x86-64:prospective-shared-join:code:v1\0";

fn prospective_shared_join_code_hash(code: &[u8]) -> Result<SemanticHash, RawEncodeError> {
    let code_len = prospective_len("prospective candidate hash length", code.len())?;
    let preimage_len = PROSPECTIVE_SHARED_JOIN_CODE_DOMAIN
        .len()
        .checked_add(8)
        .and_then(|length| length.checked_add(code.len()))
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "prospective candidate hash preimage",
        })?;
    let mut preimage = Vec::with_capacity(preimage_len);
    preimage.extend_from_slice(PROSPECTIVE_SHARED_JOIN_CODE_DOMAIN);
    preimage.extend_from_slice(&code_len.to_be_bytes());
    preimage.extend_from_slice(code);
    Ok(SemanticHash(sha256(&preimage)))
}

/// Return a canonical normalized delta pair. At most one side is nonzero and
/// `candidate = baseline + added - removed` is checked without signed casts.
fn prospective_delta(baseline: u64, candidate: u64) -> Result<(u64, u64), RawEncodeError> {
    if candidate >= baseline {
        Ok((
            candidate
                .checked_sub(baseline)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "prospective positive delta",
                })?,
            0,
        ))
    } else {
        Ok((
            0,
            baseline
                .checked_sub(candidate)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "prospective negative delta",
                })?,
        ))
    }
}

fn validate_prospective_atom_coverage(
    atoms: &[RawRealizationAtom],
    code_bytes: u64,
) -> Result<(), RawEncodeError> {
    let mut cursor = 0_u32;
    for atom in atoms {
        if atom.start != cursor || atom.end <= atom.start {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective non-canonical atom coverage",
            });
        }
        cursor = atom.end;
    }
    if u64::from(cursor) != code_bytes {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective incomplete atom coverage",
        });
    }
    Ok(())
}

type ProspectiveLabelsByOffset = BTreeMap<u32, X64LabelId>;
type ProspectiveLabelDispositions = BTreeMap<X64LabelId, RawProspectiveLabelDisposition>;
type ProspectiveNoFixupTailEdges = BTreeSet<(X64LabelId, X64LabelId, X64LabelId)>;

fn prospective_label_receipts(
    program: &X64TargetProgram,
    plan: &EmissionPlan,
    prospective_plan: &ProspectiveSharedJoinPlan,
    candidate_labels: &[X64Label],
    candidate_code: &[u8],
    candidate_atoms: &[RawRealizationAtom],
) -> Result<
    (
        Vec<RawProspectiveLabelReceipt>,
        ProspectiveLabelsByOffset,
        ProspectiveLabelDispositions,
    ),
    RawEncodeError,
> {
    if candidate_labels.len() != program.labels.len() {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective synthetic label count",
        });
    }
    if candidate_labels
        .windows(2)
        .any(|pair| pair[1].code_offset <= pair[0].code_offset)
    {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective non-canonical label order",
        });
    }

    let atom_starts = candidate_atoms
        .iter()
        .enumerate()
        .map(|(index, atom)| (atom.start, index))
        .collect::<BTreeMap<_, _>>();
    if atom_starts.len() != candidate_atoms.len() {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective duplicate atom start",
        });
    }

    let mut labels_by_offset = BTreeMap::new();
    let mut dispositions = BTreeMap::new();
    let mut receipts = Vec::with_capacity(candidate_labels.len());
    for (expected, actual) in program.labels.iter().zip(candidate_labels) {
        if actual.id != expected.id || actual.owner != expected.owner {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective synthetic label identity",
            });
        }
        if labels_by_offset
            .insert(actual.code_offset, actual.id)
            .is_some()
        {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective duplicate label offset",
            });
        }
        let owning_atom =
            *atom_starts
                .get(&actual.code_offset)
                .ok_or(RawEncodeError::OptimizationRefused {
                    context: "prospective label does not own an atom start",
                })?;
        let owning_atom =
            u32::try_from(owning_atom).map_err(|_| RawEncodeError::ArithmeticOverflow {
                field: "prospective label owning atom",
            })?;
        let disposition = match actual.owner {
            X64LabelOwner::EntryAdapter
            | X64LabelOwner::ReturnEpilogue
            | X64LabelOwner::BoundsEpilogue => RawProspectiveLabelDisposition::Live,
            X64LabelOwner::Block { .. } if !plan.reachable.contains(&actual.id) => {
                RawProspectiveLabelDisposition::ReachabilityTombstone
            }
            X64LabelOwner::Block { .. }
                if prospective_plan.shared_consumed.contains(&actual.id) =>
            {
                RawProspectiveLabelDisposition::SharedJoinTombstone
            }
            X64LabelOwner::Block { .. } if plan.consumed.contains(&actual.id) => {
                RawProspectiveLabelDisposition::UniqueChainTombstone
            }
            X64LabelOwner::Block { .. } => RawProspectiveLabelDisposition::Live,
        };
        let atom = candidate_atoms.get(owning_atom as usize).ok_or(
            RawEncodeError::OptimizationRefused {
                context: "prospective label atom range",
            },
        )?;
        match disposition {
            RawProspectiveLabelDisposition::Live => {
                if atom.class == RawTemplateClass::Tombstone {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective live label owns tombstone",
                    });
                }
            }
            RawProspectiveLabelDisposition::ReachabilityTombstone
            | RawProspectiveLabelDisposition::UniqueChainTombstone
            | RawProspectiveLabelDisposition::SharedJoinTombstone => {
                if atom.class != RawTemplateClass::Tombstone || atom.byte_len() != 1 {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective tombstone label body",
                    });
                }
                let start = usize::try_from(atom.start).map_err(|_| {
                    RawEncodeError::OptimizationRefused {
                        context: "prospective tombstone byte range",
                    }
                })?;
                let end =
                    usize::try_from(atom.end).map_err(|_| RawEncodeError::OptimizationRefused {
                        context: "prospective tombstone byte range",
                    })?;
                if candidate_code.get(start..end) != Some(&[0x90][..]) {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective tombstone byte mismatch",
                    });
                }
            }
        }
        if dispositions.insert(actual.id, disposition).is_some() {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective duplicate label identity",
            });
        }
        receipts.push(RawProspectiveLabelReceipt {
            label: actual.id,
            owner: actual.owner,
            code_offset: actual.code_offset,
            owning_atom,
            disposition,
        });
    }

    let shared_tombstones = receipts
        .iter()
        .filter_map(|receipt| {
            (receipt.disposition == RawProspectiveLabelDisposition::SharedJoinTombstone)
                .then_some(receipt.label)
        })
        .collect::<BTreeSet<_>>();
    if shared_tombstones != prospective_plan.shared_consumed {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective shared tombstone target set",
        });
    }
    Ok((receipts, labels_by_offset, dispositions))
}

type ProspectiveAuthorityKey = (X64LabelId, RawExecutionEvent);

fn prospective_atom_receipts(
    plan: &EmissionPlan,
    baseline_atoms: &[RawRealizationAtom],
    baseline_labels_by_offset: &ProspectiveLabelsByOffset,
    candidate_atoms: &[RawRealizationAtom],
    labels_by_offset: &ProspectiveLabelsByOffset,
    label_dispositions: &ProspectiveLabelDispositions,
) -> Result<(Vec<RawProspectiveRealizationAtom>, u32), RawEncodeError> {
    let mut expected = BTreeMap::<
        ProspectiveAuthorityKey,
        (RawTemplateClass, RawProspectiveExecutionAuthority),
    >::new();
    let mut expected_order = BTreeMap::<
        X64LabelId,
        Vec<(
            RawExecutionEvent,
            RawTemplateClass,
            RawProspectiveExecutionAuthority,
        )>,
    >::new();
    let mut selected_events = BTreeSet::new();
    let mut eliminable_authority_tails = BTreeSet::new();
    for step in &plan.shared_join_composition.steps {
        for ingress in &step.ingresses {
            if step.kind == RawSharedJoinKind::RegisterInstruction {
                eliminable_authority_tails.insert(RawExecutionEvent::Tail {
                    label: ingress.authority_trigger,
                });
            }
            let authority = |partition| RawProspectiveExecutionAuthority::SharedJoin {
                target: step.target,
                root: ingress.root,
                authority_trigger: ingress.authority_trigger,
                partition,
            };
            let mut insert = |event, class, partition| {
                selected_events.insert(event);
                let authority = authority(partition);
                if expected
                    .insert((ingress.root, event), (class, authority))
                    .is_some()
                {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective duplicate shared-join atom authority",
                    });
                }
                expected_order
                    .entry(ingress.root)
                    .or_default()
                    .push((event, class, authority));
                Ok(())
            };
            match (step.kind, step.branch_path) {
                (RawSharedJoinKind::RegisterInstruction, None) => {
                    insert(
                        RawExecutionEvent::Instruction {
                            label: step.target,
                            index: 0,
                        },
                        RawTemplateClass::RegisterInstruction,
                        RawProspectiveSharedJoinPartition::All,
                    )?;
                    insert(
                        RawExecutionEvent::Tail { label: step.target },
                        RawTemplateClass::TailTransfer,
                        RawProspectiveSharedJoinPartition::All,
                    )?;
                }
                (RawSharedJoinKind::FusedCompare, Some(path)) => {
                    insert(
                        RawExecutionEvent::Instruction {
                            label: step.target,
                            index: 0,
                        },
                        RawTemplateClass::FusedCompareInstruction,
                        RawProspectiveSharedJoinPartition::All,
                    )?;
                    insert(
                        RawExecutionEvent::Branch {
                            label: path.branch_label,
                        },
                        RawTemplateClass::BranchCondition,
                        RawProspectiveSharedJoinPartition::All,
                    )?;
                    insert(
                        RawExecutionEvent::BranchElse {
                            label: path.branch_label,
                        },
                        RawTemplateClass::BranchElseJump,
                        RawProspectiveSharedJoinPartition::Else,
                    )?;
                }
                _ => {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective shared-join authority shape",
                    });
                }
            }
        }
    }

    let mut remaining_semantic_atoms =
        BTreeMap::<(RawExecutionEvent, RawTemplateClass), u32>::new();
    let mut expected_semantic_order =
        BTreeMap::<X64LabelId, Vec<(RawExecutionEvent, RawTemplateClass)>>::new();
    for atom in baseline_atoms {
        if atom.event == RawExecutionEvent::Static
            || selected_events.contains(&atom.event)
            || eliminable_authority_tails.contains(&atom.event)
        {
            continue;
        }
        let physical_owner = prospective_atom_physical_owner(baseline_labels_by_offset, *atom)?;
        let count = remaining_semantic_atoms
            .entry((atom.event, atom.class))
            .or_default();
        *count = count
            .checked_add(1)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "prospective baseline semantic atom multiplicity",
            })?;
        expected_semantic_order
            .entry(physical_owner)
            .or_default()
            .push((atom.event, atom.class));
    }

    let mut receipts = Vec::with_capacity(candidate_atoms.len());
    let mut matched = BTreeSet::new();
    let mut order_cursors = BTreeMap::<X64LabelId, usize>::new();
    let mut semantic_order_cursors = BTreeMap::<X64LabelId, usize>::new();
    let mut shared_suffix_started = BTreeSet::<X64LabelId>::new();
    let mut added_atoms = 0_u32;
    for atom in candidate_atoms {
        let physical_owner = prospective_atom_physical_owner(labels_by_offset, *atom)?;
        if let Some((next_offset, _)) = labels_by_offset
            .range((
                std::ops::Bound::Excluded(atom.start),
                std::ops::Bound::Unbounded,
            ))
            .next()
        {
            if *next_offset < atom.end {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective atom crosses physical owner boundary",
                });
            }
        }

        let key = (physical_owner, atom.event);
        let execution_authority =
            if let Some((expected_class, authority)) = expected.get(&key).copied() {
                shared_suffix_started.insert(physical_owner);
                if atom.class != expected_class {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective shared-join atom template class",
                    });
                }
                if !matched.insert(key) {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective repeated shared-join atom",
                    });
                }
                let cursor = order_cursors.entry(physical_owner).or_default();
                let expected_row = expected_order
                    .get(&physical_owner)
                    .and_then(|rows| rows.get(*cursor))
                    .ok_or(RawEncodeError::OptimizationRefused {
                        context: "prospective shared-join atom order overflow",
                    })?;
                if *expected_row != (atom.event, atom.class, authority) {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective shared-join atom order",
                    });
                }
                *cursor = cursor
                    .checked_add(1)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "prospective shared-join atom order cursor",
                    })?;
                added_atoms =
                    added_atoms
                        .checked_add(1)
                        .ok_or(RawEncodeError::ArithmeticOverflow {
                            field: "prospective shared-join atom count",
                        })?;
                authority
            } else if selected_events.contains(&atom.event) {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective spurious shared-join semantic event",
                });
            } else if atom.event == RawExecutionEvent::Static {
                if atom.class != RawTemplateClass::Tombstone {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective static atom template class",
                    });
                }
                let tombstone_label = labels_by_offset.get(&atom.start).ok_or(
                    RawEncodeError::OptimizationRefused {
                        context: "prospective static atom has no label",
                    },
                )?;
                if !matches!(
                    label_dispositions.get(tombstone_label),
                    Some(
                        RawProspectiveLabelDisposition::ReachabilityTombstone
                            | RawProspectiveLabelDisposition::UniqueChainTombstone
                            | RawProspectiveLabelDisposition::SharedJoinTombstone
                    )
                ) {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective static atom lacks tombstone label",
                    });
                }
                RawProspectiveExecutionAuthority::Static
            } else {
                if shared_suffix_started.contains(&physical_owner) {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective shared-join suffix placement",
                    });
                }
                if !prospective_event_class_is_canonical(atom.event, atom.class) {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective semantic atom template class",
                    });
                }
                let remaining = remaining_semantic_atoms
                    .get_mut(&(atom.event, atom.class))
                    .ok_or(RawEncodeError::OptimizationRefused {
                        context: "prospective spurious ordinary semantic atom",
                    })?;
                *remaining =
                    (*remaining)
                        .checked_sub(1)
                        .ok_or(RawEncodeError::OptimizationRefused {
                            context: "prospective duplicate ordinary semantic atom",
                        })?;
                let cursor = semantic_order_cursors.entry(physical_owner).or_default();
                let expected_row = expected_semantic_order
                    .get(&physical_owner)
                    .and_then(|rows| rows.get(*cursor))
                    .ok_or(RawEncodeError::OptimizationRefused {
                        context: "prospective ordinary atom physical owner",
                    })?;
                if *expected_row != (atom.event, atom.class) {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "prospective ordinary atom order",
                    });
                }
                *cursor = (*cursor)
                    .checked_add(1)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "prospective ordinary atom order cursor",
                    })?;
                RawProspectiveExecutionAuthority::SemanticEvent(atom.event)
            };
        receipts.push(RawProspectiveRealizationAtom {
            physical_owner,
            semantic_event: atom.event,
            class: atom.class,
            start: atom.start,
            end: atom.end,
            execution_authority,
        });
    }
    if matched.len() != expected.len() {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective missing shared-join atom",
        });
    }
    if expected_order
        .iter()
        .any(|(owner, rows)| order_cursors.get(owner).copied().unwrap_or_default() != rows.len())
    {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective incomplete shared-join atom order",
        });
    }
    if remaining_semantic_atoms.values().any(|count| *count != 0) {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective unexplained semantic atom removal",
        });
    }
    if expected_semantic_order.iter().any(|(owner, rows)| {
        semantic_order_cursors
            .get(owner)
            .copied()
            .unwrap_or_default()
            != rows.len()
    }) {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective incomplete ordinary atom order",
        });
    }
    Ok((receipts, added_atoms))
}

fn prospective_atom_physical_owner(
    labels_by_offset: &ProspectiveLabelsByOffset,
    atom: RawRealizationAtom,
) -> Result<X64LabelId, RawEncodeError> {
    labels_by_offset
        .range(..=atom.start)
        .next_back()
        .map(|(_, label)| *label)
        .ok_or(RawEncodeError::OptimizationRefused {
            context: "prospective atom has no physical owner",
        })
}

fn prospective_event_class_is_canonical(event: RawExecutionEvent, class: RawTemplateClass) -> bool {
    match event {
        RawExecutionEvent::Entry => class == RawTemplateClass::EntryPrologue,
        RawExecutionEvent::Instruction { .. } => matches!(
            class,
            RawTemplateClass::OrdinaryInstruction
                | RawTemplateClass::RegisterInstruction
                | RawTemplateClass::FusedCompareInstruction
        ),
        RawExecutionEvent::Tail { .. } => class == RawTemplateClass::TailTransfer,
        RawExecutionEvent::Return { .. } => class == RawTemplateClass::ReturnTransfer,
        RawExecutionEvent::Branch { .. } => class == RawTemplateClass::BranchCondition,
        RawExecutionEvent::BranchElse { .. } => class == RawTemplateClass::BranchElseJump,
        RawExecutionEvent::ReturnEpilogue => class == RawTemplateClass::ReturnEpilogue,
        RawExecutionEvent::BoundsEpilogue => class == RawTemplateClass::BoundsEpilogue,
        RawExecutionEvent::Static => class == RawTemplateClass::Tombstone,
    }
}

fn prospective_no_fixup_tail_edges(
    prospective_plan: &ProspectiveSharedJoinPlan,
) -> Result<ProspectiveNoFixupTailEdges, RawEncodeError> {
    let mut edges = BTreeSet::new();
    for (root, chain) in &prospective_plan.composed_chains {
        if let PlannedExit::Compare {
            target_label,
            trigger_label,
            ..
        } = &chain.exit
        {
            if !edges.insert((*root, *trigger_label, *target_label)) {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective duplicate no-fixup tail edge",
                });
            }
        }
    }
    Ok(edges)
}

fn prospective_fixup_receipts(
    program: &X64TargetProgram,
    labels: &[X64Label],
    fixups: &[X64Fixup],
    code: &[u8],
    atoms: &[RawProspectiveRealizationAtom],
    label_dispositions: &ProspectiveLabelDispositions,
    no_fixup_tail_edges: &ProspectiveNoFixupTailEdges,
) -> Result<Vec<RawProspectiveFixupReceipt>, RawEncodeError> {
    let label_offsets = labels
        .iter()
        .map(|label| (label.id, label.code_offset))
        .collect::<BTreeMap<_, _>>();
    if label_offsets.len() != labels.len() {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective fixup duplicate target identity",
        });
    }
    let label_starts = labels
        .iter()
        .map(|label| label.code_offset)
        .collect::<BTreeSet<_>>();
    let mut atom_fixup_counts = vec![0_usize; atoms.len()];
    let mut receipts = Vec::with_capacity(fixups.len());
    let mut previous_patch = None;
    let mut previous_patch_end = None;
    for (index, fixup) in fixups.iter().enumerate() {
        if previous_patch.is_some_and(|previous| fixup.patch_offset <= previous) {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective non-canonical fixup order",
            });
        }
        previous_patch = Some(fixup.patch_offset);
        if fixup.addend != 0 {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup nonzero addend",
            });
        }
        if label_dispositions.get(&fixup.target) != Some(&RawProspectiveLabelDisposition::Live) {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective live fixup targets tombstone",
            });
        }
        let patch_end =
            fixup
                .patch_offset
                .checked_add(4)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "prospective fixup patch end",
                })?;
        if previous_patch_end.is_some_and(|previous_end| fixup.patch_offset < previous_end) {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective overlapping fixup patches",
            });
        }
        previous_patch_end = Some(patch_end);
        let owning_atom = atoms
            .partition_point(|atom| atom.start <= fixup.patch_offset)
            .checked_sub(1)
            .ok_or(RawEncodeError::OptimizationRefused {
                context: "prospective fixup has no owning atom",
            })?;
        let atom = &atoms[owning_atom];
        if atom.class == RawTemplateClass::Tombstone {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective tombstone owns live fixup",
            });
        }
        if fixup.patch_offset < atom.start || patch_end > atom.end {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup crosses atom boundary",
            });
        }
        let patch_start = usize::try_from(fixup.patch_offset).map_err(|_| {
            RawEncodeError::OptimizationRefused {
                context: "prospective fixup patch conversion",
            }
        })?;
        let patch_end_usize =
            usize::try_from(patch_end).map_err(|_| RawEncodeError::OptimizationRefused {
                context: "prospective fixup patch conversion",
            })?;
        let displacement_bytes =
            code.get(patch_start..patch_end_usize)
                .ok_or(RawEncodeError::OptimizationRefused {
                    context: "prospective fixup patch bytes",
                })?;
        let actual_displacement =
            i32::from_le_bytes(displacement_bytes.try_into().map_err(|_| {
                RawEncodeError::OptimizationRefused {
                    context: "prospective fixup displacement width",
                }
            })?);
        let site_index = atom_fixup_counts[owning_atom];
        if !prospective_fixup_opcode_matches(
            program,
            code,
            atoms,
            owning_atom,
            fixup.patch_offset,
            site_index,
        )? {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup opcode site",
            });
        }
        if let Some(expected_target) =
            prospective_expected_fixup_target(program, *atom, site_index)?
        {
            if fixup.target != expected_target {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective fixup semantic target",
                });
            }
        }
        let target_offset =
            *label_offsets
                .get(&fixup.target)
                .ok_or(RawEncodeError::OptimizationRefused {
                    context: "prospective fixup target offset",
                })?;
        let next_instruction = i64::from(fixup.patch_offset).checked_add(4).ok_or(
            RawEncodeError::ArithmeticOverflow {
                field: "prospective fixup next instruction",
            },
        )?;
        let expected_displacement = i64::from(target_offset)
            .checked_add(i64::from(fixup.addend))
            .and_then(|target| target.checked_sub(next_instruction))
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "prospective fixup displacement",
            })?;
        if i64::from(actual_displacement) != expected_displacement {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup displacement mismatch",
            });
        }
        atom_fixup_counts[owning_atom] = atom_fixup_counts[owning_atom].checked_add(1).ok_or(
            RawEncodeError::ArithmeticOverflow {
                field: "prospective atom fixup count",
            },
        )?;
        receipts.push(RawProspectiveFixupReceipt {
            fixup_index: u32::try_from(index).map_err(|_| RawEncodeError::ArithmeticOverflow {
                field: "prospective fixup index",
            })?,
            owning_atom: u32::try_from(owning_atom).map_err(|_| {
                RawEncodeError::ArithmeticOverflow {
                    field: "prospective fixup owning atom",
                }
            })?,
            patch_offset: fixup.patch_offset,
            target: fixup.target,
            addend: fixup.addend,
        });
    }
    for (index, actual) in atom_fixup_counts.iter().copied().enumerate() {
        let expected = prospective_expected_fixup_count(
            program,
            atoms,
            &label_starts,
            no_fixup_tail_edges,
            index,
        )?;
        if actual != expected {
            return Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup atom cardinality",
            });
        }
    }
    Ok(receipts)
}

fn prospective_expected_fixup_count(
    program: &X64TargetProgram,
    atoms: &[RawProspectiveRealizationAtom],
    label_starts: &BTreeSet<u32>,
    no_fixup_tail_edges: &ProspectiveNoFixupTailEdges,
    atom_index: usize,
) -> Result<usize, RawEncodeError> {
    let atom = atoms
        .get(atom_index)
        .ok_or(RawEncodeError::OptimizationRefused {
            context: "prospective fixup atom index",
        })?;
    match (atom.semantic_event, atom.class) {
        (RawExecutionEvent::Entry, RawTemplateClass::EntryPrologue)
        | (RawExecutionEvent::Return { .. }, RawTemplateClass::ReturnTransfer)
        | (RawExecutionEvent::Branch { .. }, RawTemplateClass::BranchCondition)
        | (RawExecutionEvent::BranchElse { .. }, RawTemplateClass::BranchElseJump) => Ok(1),
        (RawExecutionEvent::Tail { label: trigger }, RawTemplateClass::TailTransfer) => {
            let followed_by_in_owner_fused_compare =
                atoms.get(atom_index + 1).is_some_and(|next| {
                    next.start == atom.end
                        && next.physical_owner == atom.physical_owner
                        && next.class == RawTemplateClass::FusedCompareInstruction
                        && !label_starts.contains(&next.start)
                });
            if !followed_by_in_owner_fused_compare {
                return Ok(1);
            }
            let RawExecutionEvent::Instruction {
                label: target,
                index: 0,
            } = atoms[atom_index + 1].semantic_event
            else {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective no-fixup tail edge",
                });
            };
            if !no_fixup_tail_edges.contains(&(atom.physical_owner, trigger, target)) {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective no-fixup tail edge",
                });
            }
            Ok(0)
        }
        (
            RawExecutionEvent::Instruction { label, index },
            RawTemplateClass::OrdinaryInstruction,
        ) => {
            let block = target_block_for_label(program, label)?;
            let instruction_index =
                usize::try_from(index).map_err(|_| RawEncodeError::OptimizationRefused {
                    context: "prospective fixup instruction index",
                })?;
            let instruction = block.instructions.get(instruction_index).ok_or(
                RawEncodeError::OptimizationRefused {
                    context: "prospective fixup instruction site",
                },
            )?;
            Ok(usize::from(matches!(
                &instruction.kind,
                X64InstructionKind::ArrayGetF64Checked { .. }
            )) * 2)
        }
        (event, class) if prospective_event_class_is_canonical(event, class) => Ok(0),
        _ => Err(RawEncodeError::OptimizationRefused {
            context: "prospective fixup event class",
        }),
    }
}

fn prospective_fixup_opcode_matches(
    program: &X64TargetProgram,
    code: &[u8],
    atoms: &[RawProspectiveRealizationAtom],
    atom_index: usize,
    patch_offset: u32,
    site_index: usize,
) -> Result<bool, RawEncodeError> {
    let atom = atoms
        .get(atom_index)
        .ok_or(RawEncodeError::OptimizationRefused {
            context: "prospective fixup opcode atom",
        })?;
    let patch = usize::try_from(patch_offset).map_err(|_| RawEncodeError::OptimizationRefused {
        context: "prospective fixup opcode offset",
    })?;
    let jump_opcode = || {
        patch
            .checked_sub(1)
            .and_then(|start| code.get(start..patch))
            == Some(&[0xe9][..])
    };
    let conditional_opcode = |last: u8| {
        patch
            .checked_sub(2)
            .and_then(|start| code.get(start..patch))
            == Some(&[0x0f, last][..])
    };
    Ok(match (atom.semantic_event, atom.class) {
        (RawExecutionEvent::Entry, RawTemplateClass::EntryPrologue)
        | (RawExecutionEvent::Tail { .. }, RawTemplateClass::TailTransfer)
        | (RawExecutionEvent::Return { .. }, RawTemplateClass::ReturnTransfer)
        | (RawExecutionEvent::BranchElse { .. }, RawTemplateClass::BranchElseJump) => {
            site_index == 0 && jump_opcode()
        }
        (RawExecutionEvent::Branch { .. }, RawTemplateClass::BranchCondition) => {
            site_index == 0
                && conditional_opcode(prospective_branch_condition_opcode(
                    program, atoms, atom_index,
                )?)
        }
        (RawExecutionEvent::Instruction { .. }, RawTemplateClass::OrdinaryInstruction) => {
            match site_index {
                0 => conditional_opcode(0x88),
                1 => conditional_opcode(0x83),
                _ => false,
            }
        }
        _ => false,
    })
}

fn prospective_branch_condition_opcode(
    program: &X64TargetProgram,
    atoms: &[RawProspectiveRealizationAtom],
    branch_index: usize,
) -> Result<u8, RawEncodeError> {
    let branch = atoms
        .get(branch_index)
        .ok_or(RawEncodeError::OptimizationRefused {
            context: "prospective branch opcode atom",
        })?;
    let Some(compare_index) = branch_index.checked_sub(1) else {
        return Ok(0x85);
    };
    let Some(compare) = atoms.get(compare_index) else {
        return Ok(0x85);
    };
    if compare.end != branch.start
        || compare.physical_owner != branch.physical_owner
        || compare.class != RawTemplateClass::FusedCompareInstruction
    {
        return Ok(0x85);
    }
    let RawExecutionEvent::Instruction { label, index: 0 } = compare.semantic_event else {
        return Err(RawEncodeError::OptimizationRefused {
            context: "prospective fused branch compare event",
        });
    };
    let fused =
        classify_fused_compare_tail_branch(program, target_block_for_label(program, label)?)
            .ok_or(RawEncodeError::OptimizationRefused {
                context: "prospective fused branch classification",
            })?;
    Ok(match fused.comparison {
        X64SetCondition::SignedLessThan => 0x8c,
        X64SetCondition::SignedGreaterOrEqual => 0x8d,
    })
}

fn prospective_expected_fixup_target(
    program: &X64TargetProgram,
    atom: RawProspectiveRealizationAtom,
    site_index: usize,
) -> Result<Option<X64LabelId>, RawEncodeError> {
    match (atom.semantic_event, atom.class) {
        (RawExecutionEvent::Entry, RawTemplateClass::EntryPrologue) => {
            let entry_function = function(program, program.entry)?;
            let entry = block(entry_function, entry_function.entry_block)?.label;
            Ok(Some(thread_noop_tail_target(program, entry)?))
        }
        (
            RawExecutionEvent::Instruction { label, index },
            RawTemplateClass::OrdinaryInstruction,
        ) => {
            let instruction_index =
                usize::try_from(index).map_err(|_| RawEncodeError::OptimizationRefused {
                    context: "prospective fixup instruction target index",
                })?;
            let instruction = target_block_for_label(program, label)?
                .instructions
                .get(instruction_index)
                .ok_or(RawEncodeError::OptimizationRefused {
                    context: "prospective fixup instruction target site",
                })?;
            if !matches!(
                &instruction.kind,
                X64InstructionKind::ArrayGetF64Checked { .. }
            ) || site_index > 1
            {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective fixup instruction target class",
                });
            }
            Ok(Some(unique_owner_label(
                program,
                X64LabelOwner::BoundsEpilogue,
            )?))
        }
        (RawExecutionEvent::Tail { label }, RawTemplateClass::TailTransfer) => {
            let source = target_block_for_label(program, label)?;
            let X64Terminator::TailJumpRel32 {
                function,
                target_label,
                arguments,
                ..
            } = &source.terminator
            else {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective fixup tail target event",
                });
            };
            let route =
                select_direct_composed_tail_route(program, *function, *target_label, arguments)?;
            Ok(Some(thread_noop_tail_target(program, route.target_label)?))
        }
        (RawExecutionEvent::Return { label }, RawTemplateClass::ReturnTransfer) => {
            if !matches!(
                &target_block_for_label(program, label)?.terminator,
                X64Terminator::Return { .. }
            ) {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective fixup return target event",
                });
            }
            Ok(Some(unique_owner_label(
                program,
                X64LabelOwner::ReturnEpilogue,
            )?))
        }
        (RawExecutionEvent::Branch { label }, RawTemplateClass::BranchCondition)
        | (RawExecutionEvent::BranchElse { label }, RawTemplateClass::BranchElseJump) => {
            let source = target_block_for_label(program, label)?;
            let X64Terminator::BranchRel32 {
                then_label,
                else_label,
                ..
            } = &source.terminator
            else {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "prospective fixup branch target event",
                });
            };
            let target = if matches!(atom.semantic_event, RawExecutionEvent::Branch { .. }) {
                *then_label
            } else {
                *else_label
            };
            Ok(Some(thread_noop_tail_target(program, target)?))
        }
        _ => Ok(None),
    }
}

fn encode_layout(
    program: &X64TargetProgram,
    entry_adapter: X64LabelId,
    return_epilogue: X64LabelId,
    bounds_epilogue: X64LabelId,
    entry_function: &X64Function,
    threaded_entry: X64LabelId,
    plan: Option<EmissionLayoutView<'_>>,
) -> Result<RawEncoding, RawEncodeError> {
    let mut emitter = RawEmitter::new(program)?;
    emitter.mark(entry_adapter)?;
    emitter.atom(
        RawExecutionEvent::Entry,
        RawTemplateClass::EntryPrologue,
        |emitter| emit_prologue(emitter, program, entry_function, threaded_entry),
    )?;

    for target_function in &program.functions {
        for target_block in &target_function.blocks {
            emitter.mark(target_block.label)?;
            if plan.is_some_and(|plan| {
                !plan.reachable.contains(&target_block.label)
                    || plan.consumed.contains(&target_block.label)
            }) {
                // Target verification requires every declared label to own a
                // unique in-blob offset. Omitted bodies therefore retain one
                // deterministic unreachable NOP tombstone.
                emitter.atom(
                    RawExecutionEvent::Static,
                    RawTemplateClass::Tombstone,
                    |emitter| emitter.u8(0x90),
                )?;
                continue;
            }
            if emit_fused_compare_tail_branch(&mut emitter, program, target_block)? {
                continue;
            }
            for (index, instruction) in target_block.instructions.iter().enumerate() {
                let index =
                    u32::try_from(index).map_err(|_| RawEncodeError::ArithmeticOverflow {
                        field: "instruction realization index",
                    })?;
                emitter.atom(
                    RawExecutionEvent::Instruction {
                        label: target_block.label,
                        index,
                    },
                    RawTemplateClass::OrdinaryInstruction,
                    |emitter| emit_instruction(emitter, program, instruction, bounds_epilogue),
                )?;
            }
            if let Some(chain) = plan.and_then(|plan| plan.chains.get(&target_block.label)) {
                if !emit_planned_chain(&mut emitter, program, chain, bounds_epilogue)? {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "planned superblock emission",
                    });
                }
                continue;
            }
            emit_terminator(
                &mut emitter,
                program,
                target_block.label,
                &target_block.terminator,
                return_epilogue,
            )?;
        }
    }

    emitter.mark(return_epilogue)?;
    emitter.atom(
        RawExecutionEvent::ReturnEpilogue,
        RawTemplateClass::ReturnEpilogue,
        |emitter| emit_return_epilogue(emitter, program),
    )?;
    emitter.mark(bounds_epilogue)?;
    emitter.atom(
        RawExecutionEvent::BoundsEpilogue,
        RawTemplateClass::BoundsEpilogue,
        |emitter| emit_bounds_epilogue(emitter, program),
    )?;
    emitter.finish(
        plan.is_some(),
        plan.map(|plan| plan.shared_join_opportunities.to_vec())
            .unwrap_or_default(),
        plan.map(|plan| plan.shared_join_composition.clone())
            .unwrap_or_default(),
    )
}

fn check_frame_header(program: &X64TargetProgram) -> Result<(), RawEncodeError> {
    if program.frame.header_bytes != X64_FRAME_HEADER_BYTES
        || program.frame.home_base != X64_FRAME_HEADER_BYTES
        || program.frame.frame_bytes < X64_FRAME_HEADER_BYTES
    {
        return Err(RawEncodeError::FrameAccess {
            field: "canonical header",
            offset: 0,
            width: X64_FRAME_HEADER_BYTES,
            frame_bytes: program.frame.frame_bytes,
        });
    }
    for (field, offset, width) in [
        ("saved MXCSR", 0, 4),
        ("canonical MXCSR", 4, 4),
        ("hidden output pointer", 8, 8),
        ("reserved header", 16, 16),
    ] {
        check_frame_access(program, field, offset, width)?;
    }
    Ok(())
}

fn unique_owner_label(
    program: &X64TargetProgram,
    owner: X64LabelOwner,
) -> Result<X64LabelId, RawEncodeError> {
    let mut found = None;
    for label in &program.labels {
        if label.owner == owner && found.replace(label.id).is_some() {
            return Err(RawEncodeError::DuplicateLabelOwner { owner });
        }
    }
    found.ok_or(RawEncodeError::MissingLabelOwner { owner })
}

fn function(program: &X64TargetProgram, id: X64FunctionId) -> Result<&X64Function, RawEncodeError> {
    program
        .functions
        .iter()
        .find(|function| function.id == id)
        .ok_or(RawEncodeError::MissingFunction { function: id })
}

fn block(function: &X64Function, id: X64BlockId) -> Result<&X64Block, RawEncodeError> {
    function
        .blocks
        .iter()
        .find(|block| block.id == id)
        .ok_or(RawEncodeError::MissingBlock {
            function: function.id,
            block: id,
        })
}

fn target_block_for_label(
    program: &X64TargetProgram,
    label: X64LabelId,
) -> Result<&X64Block, RawEncodeError> {
    let label = program
        .labels
        .iter()
        .find(|candidate| candidate.id == label)
        .ok_or(RawEncodeError::UnknownLabel { label })?;
    let X64LabelOwner::Block {
        function: function_id,
        block: block_id,
    } = label.owner
    else {
        return Err(RawEncodeError::UnknownLabel { label: label.id });
    };
    block(function(program, function_id)?, block_id)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EncoderValue {
    Operand(X64Operand),
    Gpr { generation: u32, ty: MachineType },
    Xmm { generation: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum EncoderRegisterBank {
    Gpr,
    Xmm,
}

impl EncoderValue {
    fn ty(&self) -> MachineType {
        match self {
            Self::Operand(operand) => operand.ty(),
            Self::Gpr { ty, .. } => *ty,
            Self::Xmm { .. } => MachineType::F64,
        }
    }

    fn register_generation(&self) -> Option<(EncoderRegisterBank, u32)> {
        match self {
            Self::Operand(_) => None,
            Self::Gpr { generation, .. } => Some((EncoderRegisterBank::Gpr, *generation)),
            Self::Xmm { generation } => Some((EncoderRegisterBank::Xmm, *generation)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PlannedInstructionKind {
    Move(EncoderValue),
    I64Wrapping {
        opcode: X64I64Opcode,
        left: EncoderValue,
        right: EncoderValue,
    },
    Sse2F64 {
        opcode: X64Sse2F64Opcode,
        left: EncoderValue,
        right: EncoderValue,
    },
    I64Setcc {
        condition: X64SetCondition,
        left: EncoderValue,
        right: EncoderValue,
    },
    ArrayLenF64 {
        array: EncoderValue,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlannedInstruction {
    label: X64LabelId,
    index: u32,
    kind: PlannedInstructionKind,
    result: EncoderValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValueTailRoute {
    callee: X64FunctionId,
    target_label: X64LabelId,
    arguments: Vec<EncoderValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PlannedExit {
    Tail {
        ingress: ValueTailRoute,
        trigger_label: X64LabelId,
    },
    Compare {
        ingress: ValueTailRoute,
        target_label: X64LabelId,
        trigger_label: X64LabelId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlannedChain {
    instructions: Vec<PlannedInstruction>,
    exit: PlannedExit,
    consumed: Vec<X64LabelId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EmissionPlan {
    reachable: BTreeSet<X64LabelId>,
    consumed: BTreeSet<X64LabelId>,
    chains: BTreeMap<X64LabelId, PlannedChain>,
    shared_join_opportunities: Vec<RawSharedJoinOpportunity>,
    shared_join_composition: RawSharedJoinComposition,
}

/// A non-owning layout input shared by accepted policy-1.4 emission and the
/// prospective shadow encoder. Candidate chains never inhabit `EmissionPlan`.
#[derive(Clone, Copy)]
struct EmissionLayoutView<'plan> {
    reachable: &'plan BTreeSet<X64LabelId>,
    consumed: &'plan BTreeSet<X64LabelId>,
    chains: &'plan BTreeMap<X64LabelId, PlannedChain>,
    shared_join_opportunities: &'plan [RawSharedJoinOpportunity],
    shared_join_composition: &'plan RawSharedJoinComposition,
}

impl<'plan> EmissionLayoutView<'plan> {
    fn accepted(plan: &'plan EmissionPlan) -> Self {
        Self {
            reachable: &plan.reachable,
            consumed: &plan.consumed,
            chains: &plan.chains,
            shared_join_opportunities: &plan.shared_join_opportunities,
            shared_join_composition: &plan.shared_join_composition,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ProspectiveSharedJoinPlan {
    composed_chains: BTreeMap<X64LabelId, PlannedChain>,
    shared_consumed: BTreeSet<X64LabelId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EmissionPlanningResult {
    emission: EmissionPlan,
    prospective: ProspectiveSharedJoinPlan,
}

impl EmissionPlan {
    #[cfg(test)]
    fn build(program: &X64TargetProgram, entry: X64LabelId) -> Result<Self, RawEncodeError> {
        Ok(Self::build_with_prospective(program, entry)?.emission)
    }

    fn build_with_prospective(
        program: &X64TargetProgram,
        entry: X64LabelId,
    ) -> Result<EmissionPlanningResult, RawEncodeError> {
        let mut reachable = BTreeSet::new();
        let mut predecessors = BTreeMap::<X64LabelId, BTreeSet<X64LabelId>>::new();
        let mut pending = vec![entry];

        while let Some(label) = pending.pop() {
            if !reachable.insert(label) {
                continue;
            }
            let source = target_block_for_label(program, label)?;
            for successor in transformed_successors(program, source)? {
                predecessors.entry(successor).or_default().insert(label);
                if !reachable.contains(&successor) {
                    pending.push(successor);
                }
            }
        }

        let mut potential_targets = BTreeSet::new();
        for label in &reachable {
            if *label == entry {
                continue;
            }
            let Some(sources) = predecessors.get(label) else {
                continue;
            };
            if sources.len() != 1 {
                continue;
            }
            let target = target_block_for_label(program, *label)?;
            if target.instructions.len() == 1
                && (classify_fused_compare_tail_branch(program, target).is_some()
                    || supports_register_result(&target.instructions[0]))
            {
                potential_targets.insert(*label);
            }
        }

        let mut roots = Vec::new();
        for target_function in &program.functions {
            for source in &target_function.blocks {
                if reachable.contains(&source.label) && !potential_targets.contains(&source.label) {
                    roots.push(source.label);
                }
            }
        }
        // A fail-closed predecessor proof can turn a structural target into a
        // new root. The second canonical scan also breaks malformed cycles.
        for label in &reachable {
            if !roots.contains(label) {
                roots.push(*label);
            }
        }

        let mut consumed = BTreeSet::new();
        let mut chains = BTreeMap::new();
        for root in roots {
            if consumed.contains(&root) || chains.contains_key(&root) {
                continue;
            }
            let source = target_block_for_label(program, root)?;
            let Some(chain) =
                plan_one_instruction_chain(program, source, entry, &predecessors, &consumed)?
            else {
                continue;
            };
            if chain
                .consumed
                .iter()
                .any(|label| consumed.contains(label) || chains.contains_key(label))
            {
                continue;
            }
            consumed.extend(chain.consumed.iter().copied());
            chains.insert(root, chain);
        }

        let shared_join_opportunities =
            plan_shared_join_opportunities(program, entry, &reachable, &consumed, &chains)?;
        let shared_join_plan = plan_shared_join_composition(
            program,
            entry,
            &reachable,
            &consumed,
            &chains,
            &shared_join_opportunities,
        )
        .unwrap_or_default();

        Ok(EmissionPlanningResult {
            emission: Self {
                reachable,
                consumed,
                chains,
                shared_join_opportunities,
                shared_join_composition: shared_join_plan.composition,
            },
            prospective: ProspectiveSharedJoinPlan {
                composed_chains: shared_join_plan.composed_chains,
                shared_consumed: shared_join_plan.shared_consumed,
            },
        })
    }
}

const MAX_SHARED_JOIN_PREDECESSORS: usize = 8;
const MAX_SHARED_JOIN_COMPOSITION_TARGETS: usize = 16;
const MAX_SHARED_JOIN_BODY_REPLICAS: u32 = 64;
const MAX_SHARED_JOIN_COMPOSITION_WORK: u64 = 32_000_000;

#[derive(Clone, Debug)]
struct PhysicalTailIngress {
    root: X64LabelId,
    trigger: X64LabelId,
    route: ValueTailRoute,
    base_chain: Option<PlannedChain>,
}

struct PhysicalIngressGraph {
    predecessors: BTreeMap<X64LabelId, BTreeSet<X64LabelId>>,
    tail_ingresses: BTreeMap<X64LabelId, Vec<PhysicalTailIngress>>,
}

/// Find shared entries that policy 1.4 cannot consume but for which every
/// physical incoming tail can independently extend its existing chain across
/// exactly one shared operation. This is opportunity/proof metadata only:
/// policy 1.4 still emits the unchanged join body and incoming transfers.
fn plan_shared_join_opportunities(
    program: &X64TargetProgram,
    entry: X64LabelId,
    reachable: &BTreeSet<X64LabelId>,
    consumed: &BTreeSet<X64LabelId>,
    chains: &BTreeMap<X64LabelId, PlannedChain>,
) -> Result<Vec<RawSharedJoinOpportunity>, RawEncodeError> {
    let PhysicalIngressGraph {
        predecessors: physical_predecessors,
        tail_ingresses,
    } = collect_physical_ingresses(program, reachable, consumed, chains)?;

    let mut opportunities = Vec::new();
    for (target, mut ingresses) in tail_ingresses {
        if target == entry || consumed.contains(&target) || chains.contains_key(&target) {
            continue;
        }
        let Some(predecessors) = physical_predecessors.get(&target) else {
            continue;
        };
        if predecessors.len() < 2
            || predecessors.len() > MAX_SHARED_JOIN_PREDECESSORS
            || ingresses.len() != predecessors.len()
        {
            continue;
        }
        ingresses.sort_by_key(|ingress| (ingress.root, ingress.trigger));
        if ingresses
            .iter()
            .map(|ingress| ingress.root)
            .collect::<BTreeSet<_>>()
            != *predecessors
        {
            continue;
        }

        let target_block = target_block_for_label(program, target)?;
        let [instruction] = target_block.instructions.as_slice() else {
            continue;
        };
        let kind = if classify_fused_compare_tail_branch(program, target_block).is_some() {
            RawSharedJoinKind::FusedCompare
        } else if supports_register_result(instruction) {
            RawSharedJoinKind::RegisterInstruction
        } else {
            continue;
        };

        let mut summaries = Vec::with_capacity(ingresses.len());
        let mut all_proven = true;
        for ingress in &ingresses {
            if extend_chain_across_shared_join(program, target_block, ingress)?.is_none() {
                all_proven = false;
                break;
            }
            let frame_accesses = ingress_frame_accesses(program, &ingress.route)?;
            summaries.push(RawSharedJoinIngress {
                root: ingress.root,
                trigger: ingress.trigger,
                frame_accesses,
            });
        }
        if all_proven {
            opportunities.push(RawSharedJoinOpportunity {
                target,
                kind,
                ingresses: summaries,
            });
        }
    }
    Ok(opportunities)
}

#[derive(Clone, Debug)]
struct SharedJoinLineage {
    authority_trigger: X64LabelId,
    dependencies: BTreeSet<X64LabelId>,
}

/// One planner result feeds both the sealed policy-1.4 proof metadata and the
/// shadow encoder. Retaining the final chains here prevents prospective
/// realization from rerunning (and potentially diverging from) selection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SharedJoinCompositionPlan {
    composition: RawSharedJoinComposition,
    composed_chains: BTreeMap<X64LabelId, PlannedChain>,
    shared_consumed: BTreeSet<X64LabelId>,
}

/// Independently replay the ordered logical route owned by one execution
/// authority. The first event is the authority's original tail. Every
/// intermediate block must then be either a zero-instruction tail-only block
/// or one declared register-result ancestor followed by a deterministic tail.
///
/// This proof deliberately reads the immutable target CFG instead of the
/// conceptually extended chains. Work is charged per visited tail source, and
/// repeated sources fail closed, so malformed or cyclic routes cannot produce
/// partial lineage evidence.
fn derive_shared_join_lineage(
    program: &X64TargetProgram,
    authority_trigger: X64LabelId,
    target: X64LabelId,
    dependencies: &BTreeSet<X64LabelId>,
    composition_work: &mut u64,
) -> Result<Vec<RawSharedJoinLineageEvent>, RawEncodeError> {
    if authority_trigger == target
        || dependencies.contains(&authority_trigger)
        || dependencies.contains(&target)
    {
        return Err(RawEncodeError::OptimizationRefused {
            context: "shared-join lineage endpoint ownership",
        });
    }

    let mut current = authority_trigger;
    let mut first = true;
    let mut visited_sources = BTreeSet::new();
    let mut visited_ancestors = BTreeSet::new();
    let mut events = Vec::new();

    loop {
        charge_shared_join_composition_work(composition_work, 1)?;
        if !visited_sources.insert(current) {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join lineage cycle",
            });
        }

        let source = target_block_for_label(program, current)?;
        if !first {
            match source.instructions.as_slice() {
                [] => {
                    if dependencies.contains(&current) {
                        return Err(RawEncodeError::OptimizationRefused {
                            context: "shared-join lineage ancestor shape",
                        });
                    }
                }
                [instruction]
                    if dependencies.contains(&current) && supports_register_result(instruction) =>
                {
                    if !visited_ancestors.insert(current) {
                        return Err(RawEncodeError::OptimizationRefused {
                            context: "shared-join lineage repeats ancestor",
                        });
                    }
                    events.push(RawSharedJoinLineageEvent::Instruction {
                        label: current,
                        index: 0,
                    });
                }
                [_] => {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "shared-join lineage undeclared instruction ancestor",
                    });
                }
                _ => {
                    return Err(RawEncodeError::OptimizationRefused {
                        context: "shared-join lineage intermediate shape",
                    });
                }
            }
        }

        let X64Terminator::TailJumpRel32 {
            function: callee_id,
            target_label,
            ..
        } = &source.terminator
        else {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join lineage nondeterministic edge",
            });
        };
        let callee = function(program, *callee_id)?;
        if block(callee, callee.entry_block)?.label != *target_label {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join lineage non-entry tail",
            });
        }

        events.push(RawSharedJoinLineageEvent::Tail {
            source: current,
            target: *target_label,
        });
        if *target_label == target {
            break;
        }
        current = *target_label;
        first = false;
    }

    if visited_ancestors != *dependencies {
        return Err(RawEncodeError::OptimizationRefused {
            context: "shared-join lineage ancestor mismatch",
        });
    }
    Ok(events)
}

/// Prove that every independently eligible shared join can coexist in one
/// deterministic transitive plan. This remains metadata under policy 1.4:
/// it never changes `consumed`, emitted chains, labels, fixups, or code bytes.
///
/// Selection is topological. After each target is conceptually cloned into
/// every exact incoming tail, the physical graph is rebuilt before the next
/// target is considered. A lineage retains the last pre-composition tail
/// event that partitions dynamic executions by root; using the cloned
/// target's aggregate tail event would double-count converging roots.
fn plan_shared_join_composition(
    program: &X64TargetProgram,
    entry: X64LabelId,
    reachable: &BTreeSet<X64LabelId>,
    consumed: &BTreeSet<X64LabelId>,
    chains: &BTreeMap<X64LabelId, PlannedChain>,
    opportunities: &[RawSharedJoinOpportunity],
) -> Result<SharedJoinCompositionPlan, RawEncodeError> {
    if opportunities.is_empty() {
        return Ok(SharedJoinCompositionPlan {
            composition: RawSharedJoinComposition {
                complete: true,
                ..RawSharedJoinComposition::default()
            },
            composed_chains: chains.clone(),
            shared_consumed: BTreeSet::new(),
        });
    }
    if opportunities.len() > MAX_SHARED_JOIN_COMPOSITION_TARGETS {
        return Err(RawEncodeError::OptimizationRefused {
            context: "shared-join composition target cap",
        });
    }

    let candidates = opportunities
        .iter()
        .map(|opportunity| (opportunity.target, opportunity.kind))
        .collect::<BTreeMap<_, _>>();
    if candidates.len() != opportunities.len()
        || candidates.keys().any(|target| {
            *target == entry || consumed.contains(target) || chains.contains_key(target)
        })
    {
        return Err(RawEncodeError::OptimizationRefused {
            context: "shared-join composition candidate ownership",
        });
    }

    let mut direct_dependencies = BTreeMap::<X64LabelId, BTreeSet<X64LabelId>>::new();
    for opportunity in opportunities {
        let dependencies = direct_dependencies.entry(opportunity.target).or_default();
        for ingress in &opportunity.ingresses {
            if candidates.contains_key(&ingress.root) {
                dependencies.insert(ingress.root);
            }
        }
        if dependencies.contains(&opportunity.target) {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition self dependency",
            });
        }
    }

    let mut remaining = candidates.keys().copied().collect::<BTreeSet<_>>();
    let mut selected = BTreeSet::new();
    let mut shared_consumed = BTreeSet::new();
    let mut composition_work = 0_u64;
    charge_shared_join_composition_work(&mut composition_work, reachable.len())?;
    for chain in chains.values() {
        charge_shared_join_composition_work(
            &mut composition_work,
            chain
                .instructions
                .len()
                .saturating_add(chain.consumed.len()),
        )?;
    }
    let mut composed_chains = chains.clone();
    let mut lineages = BTreeMap::<X64LabelId, SharedJoinLineage>::new();
    let mut steps = Vec::with_capacity(candidates.len());
    let mut body_replicas = 0_u32;

    while !remaining.is_empty() {
        let Some(target) = remaining.iter().copied().find(|candidate| {
            direct_dependencies
                .get(candidate)
                .is_none_or(|dependencies| dependencies.is_subset(&selected))
        }) else {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition dependency cycle",
            });
        };
        if composed_chains.contains_key(&target) {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join target already owns a physical chain",
            });
        }

        let mut omitted = consumed.clone();
        omitted.extend(shared_consumed.iter().copied());
        charge_shared_join_composition_work(&mut composition_work, reachable.len())?;
        let PhysicalIngressGraph {
            predecessors: physical_predecessors,
            mut tail_ingresses,
        } = collect_physical_ingresses(program, reachable, &omitted, &composed_chains)?;
        let predecessors =
            physical_predecessors
                .get(&target)
                .ok_or(RawEncodeError::OptimizationRefused {
                    context: "shared-join composition target has no physical predecessors",
                })?;
        let mut ingresses =
            tail_ingresses
                .remove(&target)
                .ok_or(RawEncodeError::OptimizationRefused {
                    context: "shared-join composition target has no tail ingresses",
                })?;
        if predecessors.len() < 2
            || predecessors.len() > MAX_SHARED_JOIN_PREDECESSORS
            || ingresses.len() != predecessors.len()
        {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition has incomplete predecessor coverage",
            });
        }
        ingresses.sort_by_key(|ingress| (ingress.root, ingress.trigger));
        if ingresses
            .iter()
            .map(|ingress| ingress.root)
            .collect::<BTreeSet<_>>()
            != *predecessors
        {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition predecessor mismatch",
            });
        }

        let target_block = target_block_for_label(program, target)?;
        let [instruction] = target_block.instructions.as_slice() else {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition target shape",
            });
        };
        let (kind, branch_path) =
            if let Some(fused) = classify_fused_compare_tail_branch(program, target_block) {
                (
                    RawSharedJoinKind::FusedCompare,
                    Some(RawSharedJoinBranchPath {
                        branch_label: fused.branch_label,
                        then_label: fused.then_label,
                        else_label: fused.else_label,
                    }),
                )
            } else if supports_register_result(instruction) {
                (RawSharedJoinKind::RegisterInstruction, None)
            } else {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "shared-join composition target class",
                });
            };
        if candidates.get(&target).copied() != Some(kind) {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition class changed",
            });
        }

        let mut authority_triggers = BTreeSet::new();
        let mut step_dependencies = BTreeSet::new();
        let mut summaries = Vec::with_capacity(ingresses.len());
        let mut extensions = Vec::with_capacity(ingresses.len());
        let mut next_lineages = Vec::with_capacity(ingresses.len());
        for ingress in &ingresses {
            let lineage =
                lineages
                    .get(&ingress.root)
                    .cloned()
                    .unwrap_or_else(|| SharedJoinLineage {
                        authority_trigger: ingress.trigger,
                        dependencies: BTreeSet::new(),
                    });
            if lineage.dependencies.iter().any(|dependency| {
                candidates.get(dependency).copied() != Some(RawSharedJoinKind::RegisterInstruction)
            }) {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "shared-join lineage non-register dependency",
                });
            }
            if !authority_triggers.insert(lineage.authority_trigger) {
                return Err(RawEncodeError::OptimizationRefused {
                    context: "shared-join composition repeats execution authority",
                });
            }
            step_dependencies.extend(lineage.dependencies.iter().copied());

            let extended = extend_chain_across_shared_join(program, target_block, ingress)?.ok_or(
                RawEncodeError::OptimizationRefused {
                    context: "shared-join composition extension proof",
                },
            )?;
            charge_shared_join_composition_work(
                &mut composition_work,
                extended
                    .instructions
                    .len()
                    .saturating_add(extended.consumed.len())
                    .saturating_add(ingress.route.arguments.len()),
            )?;
            let frame_accesses = ingress_frame_accesses(program, &ingress.route)?;
            let ordered_lineage = derive_shared_join_lineage(
                program,
                lineage.authority_trigger,
                target,
                &lineage.dependencies,
                &mut composition_work,
            )?;
            summaries.push(RawSharedJoinCompositionIngress {
                root: ingress.root,
                authority_trigger: lineage.authority_trigger,
                frame_accesses,
                lineage: ordered_lineage,
            });
            extensions.push((ingress.root, extended));

            let mut dependencies = lineage.dependencies;
            dependencies.insert(target);
            next_lineages.push((
                ingress.root,
                SharedJoinLineage {
                    authority_trigger: lineage.authority_trigger,
                    dependencies,
                },
            ));
        }
        let lineage_ancestor_union = summaries
            .iter()
            .flat_map(|ingress| ingress.lineage.iter())
            .filter_map(|event| match event {
                RawSharedJoinLineageEvent::Instruction { label, .. } => Some(*label),
                RawSharedJoinLineageEvent::Tail { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        if lineage_ancestor_union != step_dependencies {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition ancestor union mismatch",
            });
        }
        if !direct_dependencies
            .get(&target)
            .is_none_or(|dependencies| dependencies.is_subset(&step_dependencies))
        {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition lost a dependency lineage",
            });
        }

        let replicas =
            u32::try_from(summaries.len()).map_err(|_| RawEncodeError::ArithmeticOverflow {
                field: "shared-join body replica count",
            })?;
        body_replicas =
            body_replicas
                .checked_add(replicas)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "shared-join total body replicas",
                })?;
        if body_replicas > MAX_SHARED_JOIN_BODY_REPLICAS {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition body replica cap",
            });
        }

        for (root, chain) in extensions {
            composed_chains.insert(root, chain);
        }
        for (root, lineage) in next_lineages {
            lineages.insert(root, lineage);
        }
        lineages.remove(&target);
        shared_consumed.insert(target);
        selected.insert(target);
        remaining.remove(&target);
        let mut omitted = consumed.clone();
        omitted.extend(shared_consumed.iter().copied());
        charge_shared_join_composition_work(&mut composition_work, reachable.len())?;
        let post_graph =
            collect_physical_ingresses(program, reachable, &omitted, &composed_chains)?;
        if post_graph
            .predecessors
            .keys()
            .any(|successor| shared_consumed.contains(successor))
        {
            return Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition leaves a live edge to an owned target",
            });
        }
        steps.push(RawSharedJoinCompositionStep {
            target,
            kind,
            branch_path,
            ancestors: lineage_ancestor_union.into_iter().collect(),
            ingresses: summaries,
        });
    }

    Ok(SharedJoinCompositionPlan {
        composition: RawSharedJoinComposition {
            complete: true,
            steps,
            body_replicas,
        },
        composed_chains,
        shared_consumed,
    })
}

fn charge_shared_join_composition_work(
    work: &mut u64,
    amount: usize,
) -> Result<(), RawEncodeError> {
    let amount = u64::try_from(amount).map_err(|_| RawEncodeError::ArithmeticOverflow {
        field: "shared-join composition work",
    })?;
    *work = work
        .checked_add(amount)
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "shared-join composition work",
        })?;
    if *work > MAX_SHARED_JOIN_COMPOSITION_WORK {
        return Err(RawEncodeError::OptimizationRefused {
            context: "shared-join composition work cap",
        });
    }
    Ok(())
}

fn collect_physical_ingresses(
    program: &X64TargetProgram,
    reachable: &BTreeSet<X64LabelId>,
    omitted: &BTreeSet<X64LabelId>,
    chains: &BTreeMap<X64LabelId, PlannedChain>,
) -> Result<PhysicalIngressGraph, RawEncodeError> {
    let mut physical_predecessors = BTreeMap::<X64LabelId, BTreeSet<X64LabelId>>::new();
    let mut tail_ingresses = BTreeMap::<X64LabelId, Vec<PhysicalTailIngress>>::new();

    for root in reachable {
        if omitted.contains(root) {
            continue;
        }
        for successor in physical_successors(program, *root, chains.get(root))? {
            physical_predecessors
                .entry(successor)
                .or_default()
                .insert(*root);
        }
        if let Some(ingress) = physical_tail_ingress(program, *root, chains.get(root))? {
            let target = thread_noop_tail_target(program, ingress.route.target_label)?;
            tail_ingresses.entry(target).or_default().push(ingress);
        }
    }

    Ok(PhysicalIngressGraph {
        predecessors: physical_predecessors,
        tail_ingresses,
    })
}

fn physical_successors(
    program: &X64TargetProgram,
    root: X64LabelId,
    chain: Option<&PlannedChain>,
) -> Result<Vec<X64LabelId>, RawEncodeError> {
    let Some(chain) = chain else {
        return transformed_successors(program, target_block_for_label(program, root)?);
    };
    match &chain.exit {
        PlannedExit::Tail { ingress, .. } => Ok(vec![thread_noop_tail_target(
            program,
            ingress.target_label,
        )?]),
        PlannedExit::Compare { target_label, .. } => {
            let target = target_block_for_label(program, *target_label)?;
            let fused = classify_fused_compare_tail_branch(program, target).ok_or(
                RawEncodeError::OptimizationRefused {
                    context: "planned compare no longer classifies",
                },
            )?;
            Ok(vec![
                thread_noop_tail_target(program, fused.then_label)?,
                thread_noop_tail_target(program, fused.else_label)?,
            ])
        }
    }
}

fn physical_tail_ingress(
    program: &X64TargetProgram,
    root: X64LabelId,
    chain: Option<&PlannedChain>,
) -> Result<Option<PhysicalTailIngress>, RawEncodeError> {
    if let Some(chain) = chain {
        let PlannedExit::Tail {
            ingress,
            trigger_label,
        } = &chain.exit
        else {
            return Ok(None);
        };
        return Ok(Some(PhysicalTailIngress {
            root,
            trigger: *trigger_label,
            route: ingress.clone(),
            base_chain: Some(chain.clone()),
        }));
    }

    let source = target_block_for_label(program, root)?;
    if classify_fused_compare_tail_branch(program, source).is_some() {
        return Ok(None);
    }
    let X64Terminator::TailJumpRel32 {
        function,
        target_label,
        arguments,
        ..
    } = &source.terminator
    else {
        return Ok(None);
    };
    let route = select_direct_composed_tail_route(program, *function, *target_label, arguments)?;
    let route = ValueTailRoute {
        callee: route.callee,
        target_label: route.target_label,
        arguments: route
            .arguments
            .into_iter()
            .map(EncoderValue::Operand)
            .collect(),
    };
    if direct_value_schedule(
        &route.arguments,
        &validate_value_tail_transfer(program, route.callee, &route.arguments)?.parameters,
    )
    .is_none()
    {
        return Ok(None);
    }
    Ok(Some(PhysicalTailIngress {
        root,
        trigger: root,
        route,
        base_chain: None,
    }))
}

fn extend_chain_across_shared_join(
    program: &X64TargetProgram,
    target: &X64Block,
    ingress: &PhysicalTailIngress,
) -> Result<Option<PlannedChain>, RawEncodeError> {
    let callee =
        validate_value_tail_transfer(program, ingress.route.callee, &ingress.route.arguments)?;
    if block(callee, callee.entry_block)?.label != target.label
        || ingress.route.target_label != target.label
    {
        return Ok(None);
    }

    let mut instructions = ingress
        .base_chain
        .as_ref()
        .map(|chain| chain.instructions.clone())
        .unwrap_or_default();
    let mut consumed = ingress
        .base_chain
        .as_ref()
        .map(|chain| chain.consumed.clone())
        .unwrap_or_default();

    if classify_fused_compare_tail_branch(program, target).is_some() {
        if direct_value_schedule(&ingress.route.arguments, &callee.parameters).is_none() {
            return Ok(None);
        }
        consumed.push(target.label);
        return Ok(Some(PlannedChain {
            instructions,
            exit: PlannedExit::Compare {
                ingress: ingress.route.clone(),
                target_label: target.label,
                trigger_label: ingress.trigger,
            },
            consumed,
        }));
    }

    let [instruction] = target.instructions.as_slice() else {
        return Ok(None);
    };
    if !supports_register_result(instruction) {
        return Ok(None);
    }
    let generation = u32::try_from(instructions.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "shared-join value generation",
        })?;
    let Some(planned) = plan_register_instruction(
        instruction,
        target.label,
        &callee.parameters,
        &ingress.route.arguments,
        generation,
    ) else {
        return Ok(None);
    };
    let X64Terminator::TailJumpRel32 {
        function: next_callee,
        target_label: next_target,
        arguments: next_arguments,
        ..
    } = &target.terminator
    else {
        return Ok(None);
    };
    let Some(next_arguments) = substitute_instruction_tail_values(
        &callee.parameters,
        &ingress.route.arguments,
        instruction.result,
        &planned.result,
        next_arguments,
    ) else {
        return Ok(None);
    };
    if retains_overwritten_register_generation(
        &ingress.route.arguments,
        &next_arguments,
        &planned.result,
    )? {
        return Ok(None);
    }
    let Some(next_route) =
        select_direct_value_route(program, *next_callee, *next_target, next_arguments)?
    else {
        return Ok(None);
    };
    if direct_value_schedule(
        &next_route.arguments,
        &validate_value_tail_transfer(program, next_route.callee, &next_route.arguments)?
            .parameters,
    )
    .is_none()
    {
        return Ok(None);
    }

    instructions.push(planned);
    consumed.push(target.label);
    Ok(Some(PlannedChain {
        instructions,
        exit: PlannedExit::Tail {
            ingress: next_route,
            trigger_label: target.label,
        },
        consumed,
    }))
}

fn retains_overwritten_register_generation(
    before: &[EncoderValue],
    after: &[EncoderValue],
    result: &EncoderValue,
) -> Result<bool, RawEncodeError> {
    let overwritten_bank = result.register_generation().map(|(bank, _)| bank).ok_or(
        RawEncodeError::OptimizationRefused {
            context: "planned result has no register bank",
        },
    )?;
    let overwritten_generations = before
        .iter()
        .filter_map(EncoderValue::register_generation)
        .filter(|(bank, _)| *bank == overwritten_bank)
        .collect::<BTreeSet<_>>();
    Ok(after.iter().any(|value| {
        value
            .register_generation()
            .is_some_and(|generation| overwritten_generations.contains(&generation))
    }))
}

fn ingress_frame_accesses(
    program: &X64TargetProgram,
    route: &ValueTailRoute,
) -> Result<u32, RawEncodeError> {
    let callee = validate_value_tail_transfer(program, route.callee, &route.arguments)?;
    let schedule = direct_value_schedule(&route.arguments, &callee.parameters).ok_or(
        RawEncodeError::OptimizationRefused {
            context: "shared-join ingress has no direct schedule",
        },
    )?;
    schedule.into_iter().try_fold(0_u32, |total, index| {
        let accesses = match &route.arguments[index] {
            EncoderValue::Operand(X64Operand::Home(home)) if home.ty == MachineType::F64Array => 4,
            EncoderValue::Operand(X64Operand::Home(_)) => 2,
            EncoderValue::Operand(X64Operand::Immediate { .. })
            | EncoderValue::Gpr { .. }
            | EncoderValue::Xmm { .. } => 1,
        };
        total
            .checked_add(accesses)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "shared-join ingress frame accesses",
            })
    })
}

fn transformed_successors(
    program: &X64TargetProgram,
    source: &X64Block,
) -> Result<Vec<X64LabelId>, RawEncodeError> {
    if let Some(fused) = classify_fused_compare_tail_branch(program, source) {
        return Ok(vec![
            thread_noop_tail_target(program, fused.then_label)?,
            thread_noop_tail_target(program, fused.else_label)?,
        ]);
    }
    match &source.terminator {
        X64Terminator::Return { .. } => Ok(Vec::new()),
        X64Terminator::BranchRel32 {
            then_label,
            else_label,
            ..
        } => Ok(vec![
            thread_noop_tail_target(program, *then_label)?,
            thread_noop_tail_target(program, *else_label)?,
        ]),
        X64Terminator::TailJumpRel32 {
            function: callee,
            target_label,
            arguments,
            ..
        } => {
            let route =
                select_direct_composed_tail_route(program, *callee, *target_label, arguments)?;
            Ok(vec![thread_noop_tail_target(program, route.target_label)?])
        }
    }
}

fn supports_register_result(instruction: &X64Instruction) -> bool {
    if instruction.result.ty == MachineType::F64Array {
        return false;
    }
    !matches!(
        instruction.kind,
        X64InstructionKind::ArrayGetF64Checked { .. }
    )
}

fn plan_one_instruction_chain(
    program: &X64TargetProgram,
    source: &X64Block,
    entry: X64LabelId,
    predecessors: &BTreeMap<X64LabelId, BTreeSet<X64LabelId>>,
    already_consumed: &BTreeSet<X64LabelId>,
) -> Result<Option<PlannedChain>, RawEncodeError> {
    if classify_fused_compare_tail_branch(program, source).is_some() {
        return Ok(None);
    }
    let X64Terminator::TailJumpRel32 {
        function: callee,
        target_label,
        arguments,
        ..
    } = &source.terminator
    else {
        return Ok(None);
    };
    let route = select_direct_composed_tail_route(program, *callee, *target_label, arguments)?;
    let mut route = ValueTailRoute {
        callee: route.callee,
        target_label: route.target_label,
        arguments: route
            .arguments
            .into_iter()
            .map(EncoderValue::Operand)
            .collect(),
    };
    let mut current_source = source.label;
    let mut visited = BTreeSet::new();
    let mut consumed = Vec::new();
    let mut instructions = Vec::new();
    let mut generation = 0_u32;

    for _ in 0..=program.labels.len() {
        let target_label = route.target_label;
        if target_label == entry
            || already_consumed.contains(&target_label)
            || !visited.insert(target_label)
            || predecessors
                .get(&target_label)
                .is_none_or(|sources| sources.len() != 1 || !sources.contains(&current_source))
        {
            break;
        }
        let callee = function(program, route.callee)?;
        let target = block(callee, callee.entry_block)?;
        if target.label != target_label || target.instructions.len() != 1 {
            break;
        }

        if classify_fused_compare_tail_branch(program, target).is_some() {
            if direct_value_schedule(&route.arguments, &callee.parameters).is_none() {
                break;
            }
            consumed.push(target_label);
            return Ok(Some(PlannedChain {
                instructions,
                exit: PlannedExit::Compare {
                    ingress: route,
                    target_label,
                    trigger_label: current_source,
                },
                consumed,
            }));
        }

        let instruction = &target.instructions[0];
        if !supports_register_result(instruction) {
            break;
        }
        let X64Terminator::TailJumpRel32 {
            function: next_callee,
            target_label: next_target,
            arguments: next_arguments,
            ..
        } = &target.terminator
        else {
            break;
        };
        generation = generation
            .checked_add(1)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "superblock value generation",
            })?;
        let Some(planned) = plan_register_instruction(
            instruction,
            target_label,
            &callee.parameters,
            &route.arguments,
            generation,
        ) else {
            break;
        };
        // Preserve policy 1.4's original single-generation rule. Typed
        // cross-bank residency is proof metadata for a later shared-join
        // policy and must not silently change current emitted bytes.
        let old_generations = route
            .arguments
            .iter()
            .filter_map(EncoderValue::register_generation)
            .map(|(_, generation)| generation)
            .collect::<BTreeSet<_>>();
        let Some(next_arguments) = substitute_instruction_tail_values(
            &callee.parameters,
            &route.arguments,
            instruction.result,
            &planned.result,
            next_arguments,
        ) else {
            break;
        };
        if next_arguments.iter().any(|value| {
            value
                .register_generation()
                .is_some_and(|(_, generation)| old_generations.contains(&generation))
        }) {
            break;
        }
        let Some(next_route) =
            select_direct_value_route(program, *next_callee, *next_target, next_arguments)?
        else {
            break;
        };

        instructions.push(planned);
        consumed.push(target_label);
        current_source = target_label;
        route = next_route;
    }

    if instructions.is_empty() {
        return Ok(None);
    }
    if direct_value_schedule(
        &route.arguments,
        &function(program, route.callee)?.parameters,
    )
    .is_none()
    {
        return Ok(None);
    }
    Ok(Some(PlannedChain {
        instructions,
        exit: PlannedExit::Tail {
            ingress: route,
            trigger_label: current_source,
        },
        consumed,
    }))
}

fn plan_register_instruction(
    instruction: &X64Instruction,
    label: X64LabelId,
    parameters: &[X64Parameter],
    arguments: &[EncoderValue],
    generation: u32,
) -> Option<PlannedInstruction> {
    if parameters
        .iter()
        .any(|parameter| parameter.home == instruction.result)
    {
        return None;
    }
    let map = |operand: &X64Operand| substitute_parameter_value(parameters, arguments, operand);
    let kind = match &instruction.kind {
        X64InstructionKind::Move(value) => PlannedInstructionKind::Move(map(value)?),
        X64InstructionKind::I64Wrapping {
            opcode,
            left,
            right,
        } => PlannedInstructionKind::I64Wrapping {
            opcode: *opcode,
            left: map(left)?,
            right: map(right)?,
        },
        X64InstructionKind::Sse2F64 {
            opcode,
            left,
            right,
        } => PlannedInstructionKind::Sse2F64 {
            opcode: *opcode,
            left: map(left)?,
            right: map(right)?,
        },
        X64InstructionKind::I64Setcc {
            condition,
            left,
            right,
        } => PlannedInstructionKind::I64Setcc {
            condition: *condition,
            left: map(left)?,
            right: map(right)?,
        },
        X64InstructionKind::ArrayLenF64 { array } => {
            PlannedInstructionKind::ArrayLenF64 { array: map(array)? }
        }
        X64InstructionKind::ArrayGetF64Checked { .. } => return None,
    };
    if !planned_instruction_types_match(&kind, instruction.result.ty) {
        return None;
    }
    let result = match instruction.result.ty {
        MachineType::Unit | MachineType::Bool | MachineType::I64 => EncoderValue::Gpr {
            generation,
            ty: instruction.result.ty,
        },
        MachineType::F64 => EncoderValue::Xmm { generation },
        MachineType::F64Array => return None,
    };
    Some(PlannedInstruction {
        label,
        index: 0,
        kind,
        result,
    })
}

fn planned_instruction_types_match(kind: &PlannedInstructionKind, result: MachineType) -> bool {
    match kind {
        PlannedInstructionKind::Move(value) => value.ty() == result,
        PlannedInstructionKind::I64Wrapping { left, right, .. } => {
            result == MachineType::I64
                && left.ty() == MachineType::I64
                && right.ty() == MachineType::I64
        }
        PlannedInstructionKind::Sse2F64 { left, right, .. } => {
            result == MachineType::F64
                && left.ty() == MachineType::F64
                && right.ty() == MachineType::F64
        }
        PlannedInstructionKind::I64Setcc { left, right, .. } => {
            result == MachineType::Bool
                && left.ty() == MachineType::I64
                && right.ty() == MachineType::I64
        }
        PlannedInstructionKind::ArrayLenF64 { array } => {
            result == MachineType::I64 && array.ty() == MachineType::F64Array
        }
    }
}

fn substitute_parameter_value(
    parameters: &[X64Parameter],
    arguments: &[EncoderValue],
    operand: &X64Operand,
) -> Option<EncoderValue> {
    match operand {
        X64Operand::Immediate { .. } => Some(EncoderValue::Operand(operand.clone())),
        X64Operand::Home(home) => {
            let mut matches = parameters
                .iter()
                .enumerate()
                .filter_map(|(index, parameter)| (parameter.home == *home).then_some(index));
            let index = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            arguments.get(index).cloned()
        }
    }
}

fn substitute_instruction_tail_values(
    parameters: &[X64Parameter],
    arguments: &[EncoderValue],
    result_home: X64Home,
    result: &EncoderValue,
    next_arguments: &[X64Operand],
) -> Option<Vec<EncoderValue>> {
    if parameters.len() != arguments.len()
        || parameters
            .iter()
            .any(|parameter| parameter.home == result_home)
    {
        return None;
    }
    next_arguments
        .iter()
        .map(|argument| match argument {
            X64Operand::Home(home) if *home == result_home => Some(result.clone()),
            _ => substitute_parameter_value(parameters, arguments, argument),
        })
        .collect()
}

fn substitute_value_tail_arguments(
    parameters: &[X64Parameter],
    arguments: &[EncoderValue],
    next_arguments: &[X64Operand],
) -> Option<Vec<EncoderValue>> {
    if parameters.len() != arguments.len() {
        return None;
    }
    for (index, parameter) in parameters.iter().enumerate() {
        if parameters[..index]
            .iter()
            .any(|previous| previous.home == parameter.home)
        {
            return None;
        }
    }
    next_arguments
        .iter()
        .map(|argument| substitute_parameter_value(parameters, arguments, argument))
        .collect()
}

fn select_direct_value_route(
    program: &X64TargetProgram,
    callee: X64FunctionId,
    target_label: X64LabelId,
    arguments: Vec<EncoderValue>,
) -> Result<Option<ValueTailRoute>, RawEncodeError> {
    let original = ValueTailRoute {
        callee,
        target_label,
        arguments,
    };
    let mut route = original.clone();
    let mut visited = BTreeSet::new();

    for _ in 0..=program.functions.len() {
        if !visited.insert(route.callee) {
            route = original.clone();
            break;
        }
        let current = validate_value_tail_transfer(program, route.callee, &route.arguments)?;
        let entry = block(current, current.entry_block)?;
        if entry.label != route.target_label {
            route = original.clone();
            break;
        }
        if !entry.instructions.is_empty() {
            break;
        }
        let X64Terminator::TailJumpRel32 {
            function: next_callee,
            target_label: next_target,
            arguments: next_arguments,
            ..
        } = &entry.terminator
        else {
            break;
        };
        let next = function(program, *next_callee)?;
        if block(next, next.entry_block)?.label != *next_target {
            route = original.clone();
            break;
        }
        let Some(arguments) =
            substitute_value_tail_arguments(&current.parameters, &route.arguments, next_arguments)
        else {
            route = original.clone();
            break;
        };
        route = ValueTailRoute {
            callee: *next_callee,
            target_label: *next_target,
            arguments,
        };
    }

    let final_callee = validate_value_tail_transfer(program, route.callee, &route.arguments)?;
    if direct_value_schedule(&route.arguments, &final_callee.parameters).is_some() {
        return Ok(Some(route));
    }
    let original_callee =
        validate_value_tail_transfer(program, original.callee, &original.arguments)?;
    Ok(direct_value_schedule(&original.arguments, &original_callee.parameters).map(|_| original))
}

fn validate_value_tail_transfer<'program>(
    program: &'program X64TargetProgram,
    callee_id: X64FunctionId,
    arguments: &[EncoderValue],
) -> Result<&'program X64Function, RawEncodeError> {
    let callee = function(program, callee_id)?;
    if arguments.len() != callee.parameters.len() {
        return Err(RawEncodeError::TailArity {
            function: callee_id,
            arguments: arguments.len(),
            parameters: callee.parameters.len(),
        });
    }
    let mut cursor = 0_u32;
    for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
        if argument.ty() != parameter.home.ty {
            return Err(RawEncodeError::InvalidOperand {
                context: "superblock tail argument",
                expected: parameter.home.ty,
                actual: argument.ty(),
            });
        }
        check_home(program, "superblock tail parameter", parameter.home)?;
        if let EncoderValue::Operand(X64Operand::Home(home)) = argument {
            check_home(program, "superblock tail argument", *home)?;
        }
        let width = u32::from(parameter.home.width);
        let stage_offset = program.frame.outgoing_base.checked_add(cursor).ok_or(
            RawEncodeError::ArithmeticOverflow {
                field: "superblock tail stage offset",
            },
        )?;
        check_outgoing(program, stage_offset, width)?;
        cursor = cursor
            .checked_add(width)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "superblock tail extent",
            })?;
    }
    if cursor > program.frame.outgoing_bytes {
        return Err(RawEncodeError::TailExtent {
            required: cursor,
            declared: program.frame.outgoing_bytes,
        });
    }
    Ok(callee)
}

fn is_identity_value_argument(argument: &EncoderValue, parameter: &X64Parameter) -> bool {
    matches!(
        argument,
        EncoderValue::Operand(X64Operand::Home(home))
            if *home == parameter.home
    )
}

fn direct_value_schedule(
    arguments: &[EncoderValue],
    parameters: &[X64Parameter],
) -> Option<Vec<usize>> {
    if arguments.len() != parameters.len() {
        return None;
    }
    let mut destination_words = BTreeSet::new();
    for parameter in parameters {
        for offset in home_word_offsets(parameter.home) {
            if !destination_words.insert(offset) {
                return None;
            }
        }
    }
    let mut pending = arguments
        .iter()
        .zip(parameters)
        .enumerate()
        .filter_map(|(index, (argument, parameter))| {
            (!is_identity_value_argument(argument, parameter)).then_some(index)
        })
        .collect::<Vec<_>>();
    let mut schedule = Vec::with_capacity(pending.len());
    while !pending.is_empty() {
        let mut source_words = BTreeSet::new();
        for index in &pending {
            if let EncoderValue::Operand(X64Operand::Home(home)) = arguments[*index] {
                source_words.extend(home_word_offsets(home));
            }
        }
        let position = pending.iter().position(|index| {
            home_word_offsets(parameters[*index].home)
                .into_iter()
                .all(|offset| !source_words.contains(&offset))
        })?;
        schedule.push(pending.remove(position));
    }
    Some(schedule)
}

/// Resolve through empty blocks whose only action is an exact typed identity
/// tail transfer. Cycles deliberately retain the caller's original label.
fn thread_noop_tail_target(
    program: &X64TargetProgram,
    target: X64LabelId,
) -> Result<X64LabelId, RawEncodeError> {
    let original = target;
    let mut current = target;
    let mut visited = BTreeSet::new();

    loop {
        if !visited.insert(current) {
            return Ok(original);
        }
        let label = program
            .labels
            .iter()
            .find(|label| label.id == current)
            .ok_or(RawEncodeError::UnknownLabel { label: current })?;
        let X64LabelOwner::Block {
            function: function_id,
            block: block_id,
        } = label.owner
        else {
            return Ok(current);
        };
        let target_function = function(program, function_id)?;
        let target_block = block(target_function, block_id)?;
        if !target_block.instructions.is_empty() {
            return Ok(current);
        }
        let X64Terminator::TailJumpRel32 {
            function: callee_id,
            target_label,
            arguments,
            ..
        } = &target_block.terminator
        else {
            return Ok(current);
        };
        let callee = function(program, *callee_id)?;
        if arguments.len() != callee.parameters.len()
            || !arguments
                .iter()
                .zip(&callee.parameters)
                .all(|(argument, parameter)| is_identity_tail_argument(argument, parameter))
        {
            return Ok(current);
        }
        let callee_entry = block(callee, callee.entry_block)?;
        if callee_entry.label != *target_label {
            return Ok(current);
        }
        current = *target_label;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ComposedTailRoute {
    callee: X64FunctionId,
    target_label: X64LabelId,
    arguments: Vec<X64Operand>,
}

/// Compose a tail call through transitive empty callee entries before any
/// destructive copy is emitted. Every intermediate parameter read is
/// substituted with the caller-side operand that would have populated it.
/// Cycles, exhausted work, ambiguous homes, or malformed entry routing retain
/// the complete original route.
fn compose_empty_tail_route(
    program: &X64TargetProgram,
    callee: X64FunctionId,
    target_label: X64LabelId,
    arguments: &[X64Operand],
) -> Result<ComposedTailRoute, RawEncodeError> {
    let original = ComposedTailRoute {
        callee,
        target_label,
        arguments: arguments.to_vec(),
    };
    let mut route = original.clone();
    let mut visited = BTreeSet::new();

    for _ in 0..=program.functions.len() {
        if !visited.insert(route.callee) {
            return Ok(original);
        }
        let current = validate_tail_transfer(program, route.callee, &route.arguments)?;
        let entry = block(current, current.entry_block)?;
        if entry.label != route.target_label {
            return Ok(original);
        }
        if !entry.instructions.is_empty() {
            return Ok(route);
        }
        let X64Terminator::TailJumpRel32 {
            function: next_callee,
            target_label: next_target,
            arguments: next_arguments,
            ..
        } = &entry.terminator
        else {
            return Ok(route);
        };
        let next = function(program, *next_callee)?;
        let next_entry = block(next, next.entry_block)?;
        if next_entry.label != *next_target {
            return Ok(original);
        }
        let Some(composed_arguments) =
            substitute_tail_arguments(&current.parameters, &route.arguments, next_arguments)
        else {
            return Ok(original);
        };
        validate_tail_transfer(program, *next_callee, &composed_arguments)?;
        route = ComposedTailRoute {
            callee: *next_callee,
            target_label: *next_target,
            arguments: composed_arguments,
        };
    }

    Ok(original)
}

/// Select a composed empty-tail route only when its final parallel transfer
/// has a deterministic destructive-copy schedule. This fail-closed gate
/// prevents route shortening from turning several cheap direct transfers into
/// one conservative two-phase copy.
fn select_direct_composed_tail_route(
    program: &X64TargetProgram,
    callee: X64FunctionId,
    target_label: X64LabelId,
    arguments: &[X64Operand],
) -> Result<ComposedTailRoute, RawEncodeError> {
    let original = ComposedTailRoute {
        callee,
        target_label,
        arguments: arguments.to_vec(),
    };
    let route = compose_empty_tail_route(program, callee, target_label, arguments)?;
    if route == original {
        return Ok(original);
    }

    let final_callee = validate_tail_transfer(program, route.callee, &route.arguments)?;
    if direct_tail_schedule(&route.arguments, &final_callee.parameters).is_some() {
        Ok(route)
    } else {
        Ok(original)
    }
}

fn substitute_tail_arguments(
    current_parameters: &[X64Parameter],
    current_arguments: &[X64Operand],
    next_arguments: &[X64Operand],
) -> Option<Vec<X64Operand>> {
    if current_parameters.len() != current_arguments.len() {
        return None;
    }
    for (index, parameter) in current_parameters.iter().enumerate() {
        if current_parameters[..index]
            .iter()
            .any(|previous| previous.home == parameter.home)
        {
            return None;
        }
    }

    next_arguments
        .iter()
        .map(|argument| match argument {
            X64Operand::Immediate { .. } => Some(argument.clone()),
            X64Operand::Home(home) => {
                let mut matches = current_parameters
                    .iter()
                    .enumerate()
                    .filter_map(|(index, parameter)| (parameter.home == *home).then_some(index));
                let index = matches.next()?;
                if matches.next().is_some() {
                    return None;
                }
                Some(current_arguments[index].clone())
            }
        })
        .collect()
}

fn physical_width(ty: MachineType) -> u8 {
    match ty {
        MachineType::F64Array => 16,
        MachineType::Unit | MachineType::Bool | MachineType::I64 | MachineType::F64 => 8,
    }
}

fn check_frame_access(
    program: &X64TargetProgram,
    field: &'static str,
    offset: u32,
    width: u32,
) -> Result<(), RawEncodeError> {
    let end = offset
        .checked_add(width)
        .ok_or(RawEncodeError::ArithmeticOverflow { field })?;
    if end > program.frame.frame_bytes || offset > i32::MAX as u32 {
        return Err(RawEncodeError::FrameAccess {
            field,
            offset,
            width,
            frame_bytes: program.frame.frame_bytes,
        });
    }
    Ok(())
}

fn check_home(
    program: &X64TargetProgram,
    field: &'static str,
    home: X64Home,
) -> Result<(), RawEncodeError> {
    let expected = physical_width(home.ty);
    let end = home
        .offset
        .checked_add(u32::from(home.width))
        .ok_or(RawEncodeError::ArithmeticOverflow { field })?;
    if home.width != expected
        || !home.offset.is_multiple_of(8)
        || home.offset < program.frame.home_base
        || end > program.frame.outgoing_base
    {
        return Err(RawEncodeError::InvalidHome { field, home });
    }
    check_frame_access(program, field, home.offset, u32::from(home.width))
}

fn check_outgoing(
    program: &X64TargetProgram,
    offset: u32,
    width: u32,
) -> Result<(), RawEncodeError> {
    let outgoing_end = program
        .frame
        .outgoing_base
        .checked_add(program.frame.outgoing_bytes)
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "outgoing area end",
        })?;
    let end = offset
        .checked_add(width)
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "outgoing access end",
        })?;
    if offset < program.frame.outgoing_base || end > outgoing_end {
        return Err(RawEncodeError::InvalidOutgoingAccess {
            offset,
            width,
            outgoing_base: program.frame.outgoing_base,
            outgoing_bytes: program.frame.outgoing_bytes,
        });
    }
    check_frame_access(program, "outgoing argument", offset, width)
}

fn abi_gpr(register: X64AbiRegister) -> Gpr {
    match register {
        X64AbiRegister::Rdi => Gpr::Rdi,
        X64AbiRegister::Rsi => Gpr::Rsi,
        X64AbiRegister::Rdx => Gpr::Rdx,
        X64AbiRegister::Rcx => Gpr::Rcx,
        X64AbiRegister::R8 => Gpr::R8,
        X64AbiRegister::R9 => Gpr::R9,
    }
}

fn emit_prologue(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    entry_function: &X64Function,
    entry_label: X64LabelId,
) -> Result<(), RawEncodeError> {
    let expected_lanes =
        entry_function
            .parameters
            .iter()
            .try_fold(0usize, |total, parameter| {
                let words = match parameter.home.ty {
                    MachineType::Unit => 0,
                    MachineType::F64Array => 2,
                    MachineType::Bool | MachineType::I64 | MachineType::F64 => 1,
                };
                total
                    .checked_add(words)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "entry lane count",
                    })
            })?;
    if program.entry_abi.input_lanes.len() != expected_lanes {
        return Err(RawEncodeError::EntryLaneManifest {
            expected: expected_lanes,
            actual: program.entry_abi.input_lanes.len(),
        });
    }
    for lane in &program.entry_abi.input_lanes {
        let Some(parameter) = entry_function.parameters.get(lane.parameter as usize) else {
            return Err(RawEncodeError::InvalidEntryLane {
                parameter: lane.parameter,
                word: lane.word,
            });
        };
        let words = match parameter.home.ty {
            MachineType::Unit => 0,
            MachineType::F64Array => 2,
            MachineType::Bool | MachineType::I64 | MachineType::F64 => 1,
        };
        if usize::from(lane.word) >= words {
            return Err(RawEncodeError::InvalidEntryLane {
                parameter: lane.parameter,
                word: lane.word,
            });
        }
    }

    // push rbp; mov rbp, rsp; sub rsp, frame_bytes
    emitter.bytes(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec])?;
    emitter.u32(program.frame.frame_bytes)?;

    // Save the caller's numeric state, install the canonical state, and retain
    // the hidden output pointer before any ABI input register is reused.
    emit_stmxcsr_rsp_disp32(emitter, 0)?;
    emit_mov_mem32_imm32(emitter, 4, program.abi.canonical_mxcsr)?;
    emit_ldmxcsr_rsp_disp32(emitter, 4)?;
    emit_store_frame_gpr(emitter, 8, abi_gpr(program.entry_abi.output_register))?;
    emit_mov_mem64_imm32(emitter, 16, 0)?;
    emit_mov_mem64_imm32(emitter, 24, 0)?;

    for (parameter_index, parameter) in entry_function.parameters.iter().enumerate() {
        check_home(program, "entry parameter", parameter.home)?;
        if parameter.home.ty == MachineType::Unit {
            emit_mov_mem64_imm32(emitter, parameter.home.offset, 0)?;
            continue;
        }

        let expected_words = usize::from(parameter.home.width / 8);
        let mut lanes = program
            .entry_abi
            .input_lanes
            .iter()
            .filter(|lane| lane.parameter as usize == parameter_index)
            .collect::<Vec<_>>();
        lanes.sort_by_key(|lane| lane.word);
        if lanes.len() != expected_words {
            return Err(RawEncodeError::InvalidResultWidth {
                context: "entry lane manifest",
                ty: parameter.home.ty,
                expected: parameter.home.width,
                actual: u8::try_from(lanes.len().saturating_mul(8)).unwrap_or(u8::MAX),
            });
        }
        for (word, lane) in lanes.into_iter().enumerate() {
            if usize::from(lane.word) != word {
                return Err(RawEncodeError::OffsetOutOfRange {
                    field: "entry lane word",
                    offset: u64::from(lane.word),
                });
            }
            let word_offset = u32::try_from(word)
                .map_err(|_| RawEncodeError::ArithmeticOverflow {
                    field: "entry lane word",
                })?
                .checked_mul(8)
                .and_then(|offset| parameter.home.offset.checked_add(offset))
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "entry lane home offset",
                })?;
            emit_store_frame_gpr(emitter, word_offset, abi_gpr(lane.register))?;
        }
    }

    emitter.rel32(&[0xe9], entry_label)
}

struct FusedCompareTailBranch<'program> {
    comparison: X64SetCondition,
    left: &'program X64Operand,
    right: &'program X64Operand,
    result: X64Home,
    callee: X64FunctionId,
    arguments: &'program [X64Operand],
    condition_home: X64Home,
    branch_label: X64LabelId,
    then_label: X64LabelId,
    else_label: X64LabelId,
}

fn emit_fused_compare_tail_branch(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    source_block: &X64Block,
) -> Result<bool, RawEncodeError> {
    let Some(fused) = classify_fused_compare_tail_branch(program, source_block) else {
        return Ok(false);
    };

    validate_tail_transfer(program, fused.callee, fused.arguments)?;
    require_operand_type("fused signed compare left", MachineType::I64, fused.left)?;
    require_operand_type("fused signed compare right", MachineType::I64, fused.right)?;
    require_home_type(
        "fused signed compare result",
        fused.result,
        MachineType::Bool,
    )?;
    require_home_type(
        "fused branch condition",
        fused.condition_home,
        MachineType::Bool,
    )?;

    emitter.atom(
        RawExecutionEvent::Instruction {
            label: source_block.label,
            index: 0,
        },
        RawTemplateClass::FusedCompareInstruction,
        |emitter| {
            emit_load_scalar(emitter, program, fused.left, Gpr::Rax)?;
            emit_load_scalar(emitter, program, fused.right, Gpr::Rcx)?;
            emitter.bytes(&[0x48, 0x39, 0xc8])?; // cmp rax, rcx
            match fused.comparison {
                X64SetCondition::SignedLessThan => emitter.bytes(&[0x0f, 0x9c, 0xc0])?,
                X64SetCondition::SignedGreaterOrEqual => emitter.bytes(&[0x0f, 0x9d, 0xc0])?,
            }
            emitter.bytes(&[0x48, 0x0f, 0xb6, 0xc0])?; // movzx rax, al
                                                       // The compare result has exactly one live continuation use: the
                                                       // callee's condition parameter. Materialize the canonical Bool
                                                       // directly there.
            emit_store_frame_gpr(emitter, fused.condition_home.offset, Gpr::Rax)
        },
    )?;

    let then_label = thread_noop_tail_target(program, fused.then_label)?;
    let else_label = thread_noop_tail_target(program, fused.else_label)?;
    emitter.atom(
        RawExecutionEvent::Branch {
            label: fused.branch_label,
        },
        RawTemplateClass::BranchCondition,
        |emitter| match fused.comparison {
            X64SetCondition::SignedLessThan => {
                emitter.rel32(&[0x0f, 0x8c], then_label) // jl then
            }
            X64SetCondition::SignedGreaterOrEqual => {
                emitter.rel32(&[0x0f, 0x8d], then_label) // jge then
            }
        },
    )?;
    emitter.atom(
        RawExecutionEvent::BranchElse {
            label: fused.branch_label,
        },
        RawTemplateClass::BranchElseJump,
        |emitter| emitter.rel32(&[0xe9], else_label),
    )?;
    Ok(true)
}

fn classify_fused_compare_tail_branch<'program>(
    program: &'program X64TargetProgram,
    source_block: &'program X64Block,
) -> Option<FusedCompareTailBranch<'program>> {
    let [instruction] = source_block.instructions.as_slice() else {
        return None;
    };
    let X64InstructionKind::I64Setcc {
        condition,
        left,
        right,
    } = &instruction.kind
    else {
        return None;
    };
    if instruction.result.ty != MachineType::Bool {
        return None;
    }
    let X64Terminator::TailJumpRel32 {
        function: callee_id,
        target_label,
        arguments,
        ..
    } = &source_block.terminator
    else {
        return None;
    };
    let callee = function(program, *callee_id).ok()?;
    if arguments.len() != callee.parameters.len() {
        return None;
    }
    let callee_entry = block(callee, callee.entry_block).ok()?;
    if callee_entry.label != *target_label || !callee_entry.instructions.is_empty() {
        return None;
    }
    let X64Terminator::BranchRel32 {
        condition: X64Operand::Home(condition_home),
        then_label,
        else_label,
        ..
    } = &callee_entry.terminator
    else {
        return None;
    };
    if then_label == else_label {
        return None;
    }

    let mut condition_indices = callee
        .parameters
        .iter()
        .enumerate()
        .filter_map(|(index, parameter)| (parameter.home == *condition_home).then_some(index));
    let condition_index = condition_indices.next()?;
    if condition_indices.next().is_some() {
        return None;
    }
    for (index, (argument, parameter)) in arguments.iter().zip(&callee.parameters).enumerate() {
        if index == condition_index {
            if !matches!(argument, X64Operand::Home(home) if *home == instruction.result) {
                return None;
            }
        } else if !is_identity_tail_argument(argument, parameter)
            || matches!(argument, X64Operand::Home(home) if *home == instruction.result)
        {
            return None;
        }
    }

    Some(FusedCompareTailBranch {
        comparison: *condition,
        left,
        right,
        result: instruction.result,
        callee: *callee_id,
        arguments,
        condition_home: *condition_home,
        branch_label: callee_entry.label,
        then_label: *then_label,
        else_label: *else_label,
    })
}

fn emit_instruction(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    instruction: &X64Instruction,
    bounds_label: X64LabelId,
) -> Result<(), RawEncodeError> {
    check_home(program, "instruction result", instruction.result)?;
    match &instruction.kind {
        X64InstructionKind::Move(operand) => {
            require_operand_type("move", instruction.result.ty, operand)?;
            require_result_width("move", instruction.result)?;
            emit_move(emitter, program, operand, instruction.result)
        }
        X64InstructionKind::I64Wrapping {
            opcode,
            left,
            right,
        } => {
            require_operand_type("wrapping I64 left", MachineType::I64, left)?;
            require_operand_type("wrapping I64 right", MachineType::I64, right)?;
            require_home_type("wrapping I64 result", instruction.result, MachineType::I64)?;
            emit_load_scalar(emitter, program, left, Gpr::Rax)?;
            emit_load_scalar(emitter, program, right, Gpr::Rcx)?;
            match opcode {
                X64I64Opcode::Add => emitter.bytes(&[0x48, 0x01, 0xc8])?,
                X64I64Opcode::Sub => emitter.bytes(&[0x48, 0x29, 0xc8])?,
                X64I64Opcode::Mul => emitter.bytes(&[0x48, 0x0f, 0xaf, 0xc1])?,
            }
            emit_store_frame_gpr(emitter, instruction.result.offset, Gpr::Rax)
        }
        X64InstructionKind::Sse2F64 {
            opcode,
            left,
            right,
        } => {
            require_operand_type("SSE2 F64 left", MachineType::F64, left)?;
            require_operand_type("SSE2 F64 right", MachineType::F64, right)?;
            require_home_type("SSE2 F64 result", instruction.result, MachineType::F64)?;
            emit_load_f64_xmm0(emitter, program, left)?;
            emit_load_f64_xmm1(emitter, program, right)?;
            match opcode {
                X64Sse2F64Opcode::AddSd => emitter.bytes(&[0xf2, 0x0f, 0x58, 0xc1])?,
                X64Sse2F64Opcode::SubSd => emitter.bytes(&[0xf2, 0x0f, 0x5c, 0xc1])?,
            }
            emit_store_xmm0_frame(emitter, instruction.result.offset)
        }
        X64InstructionKind::I64Setcc {
            condition,
            left,
            right,
        } => {
            require_operand_type("signed compare left", MachineType::I64, left)?;
            require_operand_type("signed compare right", MachineType::I64, right)?;
            require_home_type(
                "signed compare result",
                instruction.result,
                MachineType::Bool,
            )?;
            emit_load_scalar(emitter, program, left, Gpr::Rax)?;
            emit_load_scalar(emitter, program, right, Gpr::Rcx)?;
            emitter.bytes(&[0x48, 0x39, 0xc8])?; // cmp rax, rcx
            match condition {
                X64SetCondition::SignedLessThan => emitter.bytes(&[0x0f, 0x9c, 0xc0])?,
                X64SetCondition::SignedGreaterOrEqual => emitter.bytes(&[0x0f, 0x9d, 0xc0])?,
            }
            emitter.bytes(&[0x48, 0x0f, 0xb6, 0xc0])?; // movzx rax, al
            emit_store_frame_gpr(emitter, instruction.result.offset, Gpr::Rax)
        }
        X64InstructionKind::ArrayLenF64 { array } => {
            require_operand_type("F64Array length", MachineType::F64Array, array)?;
            require_home_type(
                "F64Array length result",
                instruction.result,
                MachineType::I64,
            )?;
            let array = array_home("F64Array length", program, array)?;
            let length_offset =
                array
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array length offset",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rax, length_offset)?;
            emit_store_frame_gpr(emitter, instruction.result.offset, Gpr::Rax)
        }
        X64InstructionKind::ArrayGetF64Checked { array, index } => {
            require_operand_type("checked F64Array access", MachineType::F64Array, array)?;
            require_operand_type("checked F64Array index", MachineType::I64, index)?;
            require_home_type(
                "checked F64Array result",
                instruction.result,
                MachineType::F64,
            )?;
            let array = array_home("checked F64Array access", program, array)?;
            emit_load_scalar(emitter, program, index, Gpr::Rdx)?;
            emitter.bytes(&[0x48, 0x85, 0xd2])?; // test rdx, rdx
            emitter.rel32(&[0x0f, 0x88], bounds_label)?; // js Bounds
            let length_offset =
                array
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array length offset",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rcx, length_offset)?;
            emitter.bytes(&[0x48, 0x39, 0xca])?; // cmp rdx, rcx
            emitter.rel32(&[0x0f, 0x83], bounds_label)?; // jae Bounds
            emit_load_frame_gpr(emitter, Gpr::Rax, array.offset)?;
            // movsd xmm0, qword ptr [rax + rdx*8]
            emitter.bytes(&[0xf2, 0x0f, 0x10, 0x04, 0xd0])?;
            emit_store_xmm0_frame(emitter, instruction.result.offset)
        }
    }
}

fn emit_planned_chain(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    chain: &PlannedChain,
    bounds_label: X64LabelId,
) -> Result<bool, RawEncodeError> {
    for instruction in &chain.instructions {
        emitter.atom(
            RawExecutionEvent::Instruction {
                label: instruction.label,
                index: instruction.index,
            },
            RawTemplateClass::RegisterInstruction,
            |emitter| emit_planned_instruction(emitter, program, instruction, bounds_label),
        )?;
    }
    match &chain.exit {
        PlannedExit::Tail {
            ingress,
            trigger_label,
        } => {
            let emitted = emitter.atom(
                RawExecutionEvent::Tail {
                    label: *trigger_label,
                },
                RawTemplateClass::TailTransfer,
                |emitter| {
                    if !emit_value_tail_transfer(
                        emitter,
                        program,
                        ingress.callee,
                        &ingress.arguments,
                    )? {
                        return Ok(false);
                    }
                    let target = thread_noop_tail_target(program, ingress.target_label)?;
                    emitter.rel32(&[0xe9], target)?;
                    Ok(true)
                },
            )?;
            if !emitted {
                return Ok(false);
            }
        }
        PlannedExit::Compare {
            ingress,
            target_label,
            trigger_label,
        } => {
            let emitted = emitter.atom(
                RawExecutionEvent::Tail {
                    label: *trigger_label,
                },
                RawTemplateClass::TailTransfer,
                |emitter| {
                    emit_value_tail_transfer(emitter, program, ingress.callee, &ingress.arguments)
                },
            )?;
            if !emitted {
                return Ok(false);
            }
            let target = target_block_for_label(program, *target_label)?;
            if !emit_fused_compare_tail_branch(emitter, program, target)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn emit_planned_instruction(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    instruction: &PlannedInstruction,
    _bounds_label: X64LabelId,
) -> Result<(), RawEncodeError> {
    match &instruction.kind {
        PlannedInstructionKind::Move(value) => match instruction.result.ty() {
            MachineType::Unit => emit_zero_gpr32(emitter, Gpr::R8),
            MachineType::Bool | MachineType::I64 => {
                emit_load_value_gpr(emitter, program, value, Gpr::R8)
            }
            MachineType::F64 => emit_load_value_xmm(emitter, program, value, 2),
            MachineType::F64Array => Err(RawEncodeError::InvalidArrayOperand {
                context: "superblock register result",
            }),
        },
        PlannedInstructionKind::I64Wrapping {
            opcode,
            left,
            right,
        } => {
            require_value_type("superblock wrapping I64 left", MachineType::I64, left)?;
            require_value_type("superblock wrapping I64 right", MachineType::I64, right)?;
            emit_load_value_gpr(emitter, program, left, Gpr::Rax)?;
            emit_load_value_gpr(emitter, program, right, Gpr::Rcx)?;
            match opcode {
                X64I64Opcode::Add => emitter.bytes(&[0x48, 0x01, 0xc8])?,
                X64I64Opcode::Sub => emitter.bytes(&[0x48, 0x29, 0xc8])?,
                X64I64Opcode::Mul => emitter.bytes(&[0x48, 0x0f, 0xaf, 0xc1])?,
            }
            emit_mov_gpr(emitter, Gpr::R8, Gpr::Rax)
        }
        PlannedInstructionKind::Sse2F64 {
            opcode,
            left,
            right,
        } => {
            require_value_type("superblock SSE2 F64 left", MachineType::F64, left)?;
            require_value_type("superblock SSE2 F64 right", MachineType::F64, right)?;
            emit_load_value_xmm(emitter, program, left, 0)?;
            emit_load_value_xmm(emitter, program, right, 1)?;
            match opcode {
                X64Sse2F64Opcode::AddSd => emitter.bytes(&[0xf2, 0x0f, 0x58, 0xc1])?,
                X64Sse2F64Opcode::SubSd => emitter.bytes(&[0xf2, 0x0f, 0x5c, 0xc1])?,
            }
            emit_movsd_xmm(emitter, 2, 0)
        }
        PlannedInstructionKind::I64Setcc {
            condition,
            left,
            right,
        } => {
            require_value_type("superblock signed compare left", MachineType::I64, left)?;
            require_value_type("superblock signed compare right", MachineType::I64, right)?;
            emit_load_value_gpr(emitter, program, left, Gpr::Rax)?;
            emit_load_value_gpr(emitter, program, right, Gpr::Rcx)?;
            emitter.bytes(&[0x48, 0x39, 0xc8])?;
            match condition {
                X64SetCondition::SignedLessThan => emitter.bytes(&[0x0f, 0x9c, 0xc0])?,
                X64SetCondition::SignedGreaterOrEqual => emitter.bytes(&[0x0f, 0x9d, 0xc0])?,
            }
            emitter.bytes(&[0x48, 0x0f, 0xb6, 0xc0])?;
            emit_mov_gpr(emitter, Gpr::R8, Gpr::Rax)
        }
        PlannedInstructionKind::ArrayLenF64 { array } => {
            require_value_type("superblock F64Array length", MachineType::F64Array, array)?;
            let EncoderValue::Operand(array) = array else {
                return Err(RawEncodeError::InvalidArrayOperand {
                    context: "superblock F64Array length",
                });
            };
            let array = array_home("superblock F64Array length", program, array)?;
            let length = array
                .offset
                .checked_add(8)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "superblock F64Array length offset",
                })?;
            emit_load_frame_gpr(emitter, Gpr::R8, length)
        }
    }
}

fn require_value_type(
    context: &'static str,
    expected: MachineType,
    value: &EncoderValue,
) -> Result<(), RawEncodeError> {
    let actual = value.ty();
    if actual == expected {
        Ok(())
    } else {
        Err(RawEncodeError::InvalidOperand {
            context,
            expected,
            actual,
        })
    }
}

fn emit_load_value_gpr(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    value: &EncoderValue,
    destination: Gpr,
) -> Result<(), RawEncodeError> {
    match value {
        EncoderValue::Operand(operand) => emit_load_scalar(emitter, program, operand, destination),
        EncoderValue::Gpr {
            ty: MachineType::Unit | MachineType::Bool | MachineType::I64,
            ..
        } => emit_mov_gpr(emitter, destination, Gpr::R8),
        _ => Err(RawEncodeError::InvalidOperand {
            context: "superblock GPR load",
            expected: value.ty(),
            actual: value.ty(),
        }),
    }
}

fn emit_load_value_xmm(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    value: &EncoderValue,
    destination: u8,
) -> Result<(), RawEncodeError> {
    match value {
        EncoderValue::Operand(X64Operand::Immediate {
            ty: MachineType::F64,
            value: X64Immediate::F64Bits(bits),
        }) => {
            emit_mov_imm64(emitter, Gpr::Rax, *bits)?;
            emit_movq_xmm_gpr(emitter, destination, Gpr::Rax)
        }
        EncoderValue::Operand(X64Operand::Home(home)) if home.ty == MachineType::F64 => {
            check_home(program, "superblock F64 operand", *home)?;
            emit_load_frame_xmm(emitter, destination, home.offset)
        }
        EncoderValue::Xmm { .. } => emit_movsd_xmm(emitter, destination, 2),
        _ => Err(RawEncodeError::InvalidOperand {
            context: "superblock XMM load",
            expected: MachineType::F64,
            actual: value.ty(),
        }),
    }
}

fn emit_value_tail_transfer(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    callee_id: X64FunctionId,
    arguments: &[EncoderValue],
) -> Result<bool, RawEncodeError> {
    let callee = validate_value_tail_transfer(program, callee_id, arguments)?;
    let Some(schedule) = direct_value_schedule(arguments, &callee.parameters) else {
        return Ok(false);
    };
    for index in schedule {
        let destination = callee.parameters[index].home;
        match &arguments[index] {
            EncoderValue::Operand(operand) => {
                emit_move(emitter, program, operand, destination)?;
            }
            EncoderValue::Gpr { ty, .. } => {
                if *ty != destination.ty
                    || !matches!(ty, MachineType::Unit | MachineType::Bool | MachineType::I64)
                {
                    return Err(RawEncodeError::InvalidOperand {
                        context: "superblock tail register",
                        expected: destination.ty,
                        actual: *ty,
                    });
                }
                emit_store_frame_gpr(emitter, destination.offset, Gpr::R8)?;
            }
            EncoderValue::Xmm { .. } if destination.ty == MachineType::F64 => {
                emit_store_frame_xmm(emitter, 2, destination.offset)?;
            }
            value => {
                return Err(RawEncodeError::InvalidOperand {
                    context: "superblock tail register",
                    expected: destination.ty,
                    actual: value.ty(),
                });
            }
        }
    }
    Ok(true)
}

fn emit_terminator(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    source_label: X64LabelId,
    terminator: &X64Terminator,
    return_label: X64LabelId,
) -> Result<(), RawEncodeError> {
    match terminator {
        X64Terminator::Return { value, .. } => emitter.atom(
            RawExecutionEvent::Return {
                label: source_label,
            },
            RawTemplateClass::ReturnTransfer,
            |emitter| {
                emit_return_stage(emitter, program, value)?;
                emitter.rel32(&[0xe9], return_label)
            },
        ),
        X64Terminator::BranchRel32 {
            condition,
            then_label,
            else_label,
            ..
        } => {
            require_operand_type("branch condition", MachineType::Bool, condition)?;
            let then_label = thread_noop_tail_target(program, *then_label)?;
            let else_label = thread_noop_tail_target(program, *else_label)?;
            emitter.atom(
                RawExecutionEvent::Branch {
                    label: source_label,
                },
                RawTemplateClass::BranchCondition,
                |emitter| {
                    emit_load_scalar(emitter, program, condition, Gpr::Rax)?;
                    emitter.bytes(&[0x48, 0x85, 0xc0])?; // test rax, rax
                    emitter.rel32(&[0x0f, 0x85], then_label) // jnz then
                },
            )?;
            emitter.atom(
                RawExecutionEvent::BranchElse {
                    label: source_label,
                },
                RawTemplateClass::BranchElseJump,
                |emitter| emitter.rel32(&[0xe9], else_label),
            )
        }
        X64Terminator::TailJumpRel32 {
            function: callee,
            target_label,
            arguments,
            ..
        } => emitter.atom(
            RawExecutionEvent::Tail {
                label: source_label,
            },
            RawTemplateClass::TailTransfer,
            |emitter| {
                let route =
                    select_direct_composed_tail_route(program, *callee, *target_label, arguments)?;
                emit_tail_transfer(emitter, program, route.callee, &route.arguments)?;
                let target_label = thread_noop_tail_target(program, route.target_label)?;
                emitter.rel32(&[0xe9], target_label)
            },
        ),
    }
}

fn emit_move(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
    result: X64Home,
) -> Result<(), RawEncodeError> {
    match result.ty {
        MachineType::Unit => emit_mov_mem64_imm32(emitter, result.offset, 0),
        MachineType::Bool | MachineType::I64 | MachineType::F64 => {
            emit_load_scalar(emitter, program, operand, Gpr::Rax)?;
            emit_store_frame_gpr(emitter, result.offset, Gpr::Rax)
        }
        MachineType::F64Array => {
            let source = array_home("F64Array move", program, operand)?;
            emit_load_frame_gpr(emitter, Gpr::Rax, source.offset)?;
            let source_length =
                source
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array move source length",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rdx, source_length)?;
            emit_store_frame_gpr(emitter, result.offset, Gpr::Rax)?;
            let result_length =
                result
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array move result length",
                    })?;
            emit_store_frame_gpr(emitter, result_length, Gpr::Rdx)
        }
    }
}

fn emit_return_stage(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    value: &X64Operand,
) -> Result<(), RawEncodeError> {
    match value.ty() {
        MachineType::Unit => {
            emit_zero_gpr32(emitter, Gpr::Rax)?;
            emit_zero_gpr32(emitter, Gpr::Rdx)
        }
        MachineType::Bool | MachineType::I64 => {
            emit_load_scalar(emitter, program, value, Gpr::Rax)?;
            emit_zero_gpr32(emitter, Gpr::Rdx)
        }
        MachineType::F64 => {
            emit_load_scalar(emitter, program, value, Gpr::Rax)?;
            // movq xmm0, rax; ucomisd xmm0, xmm0; movabs rcx, canonical NaN;
            // cmovp rax, rcx. Signed zero and every non-NaN bit pattern pass
            // through unchanged.
            emitter.bytes(&[0x66, 0x48, 0x0f, 0x6e, 0xc0])?;
            emitter.bytes(&[0x66, 0x0f, 0x2e, 0xc0])?;
            emit_mov_imm64(emitter, Gpr::Rcx, X64_CANONICAL_NAN_BITS)?;
            emitter.bytes(&[0x48, 0x0f, 0x4a, 0xc1])?;
            emit_zero_gpr32(emitter, Gpr::Rdx)
        }
        MachineType::F64Array => {
            let home = array_home("F64Array return", program, value)?;
            emit_load_frame_gpr(emitter, Gpr::Rax, home.offset)?;
            let length_offset =
                home.offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array return length",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rdx, length_offset)
        }
    }
}

fn emit_tail_transfer(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    callee_id: X64FunctionId,
    arguments: &[X64Operand],
) -> Result<(), RawEncodeError> {
    let callee = validate_tail_transfer(program, callee_id, arguments)?;

    if let Some(schedule) = direct_tail_schedule(arguments, &callee.parameters) {
        for index in schedule {
            emit_move(
                emitter,
                program,
                &arguments[index],
                callee.parameters[index].home,
            )?;
        }
        return Ok(());
    }

    // Cyclic parallel copies retain the conservative two-phase fallback:
    // stage every non-identity source before committing any destination.
    let mut cursor = 0;
    for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
        let width = u32::from(parameter.home.width);
        if !is_identity_tail_argument(argument, parameter) {
            let stage_offset = program.frame.outgoing_base.checked_add(cursor).ok_or(
                RawEncodeError::ArithmeticOverflow {
                    field: "tail stage offset",
                },
            )?;
            emit_stage_operand(emitter, program, argument, parameter.home.ty, stage_offset)?;
        }
        cursor = cursor
            .checked_add(width)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "tail stage extent",
            })?;
    }

    cursor = 0;
    for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
        let width = u32::from(parameter.home.width);
        if is_identity_tail_argument(argument, parameter) {
            cursor = cursor
                .checked_add(width)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "identity tail commit extent",
                })?;
            continue;
        }
        let words = width / 8;
        for word in 0..words {
            let word_delta = word
                .checked_mul(8)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "tail commit word",
                })?;
            let source = program
                .frame
                .outgoing_base
                .checked_add(cursor)
                .and_then(|offset| offset.checked_add(word_delta))
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "tail commit source",
                })?;
            let destination = parameter.home.offset.checked_add(word_delta).ok_or(
                RawEncodeError::ArithmeticOverflow {
                    field: "tail commit destination",
                },
            )?;
            emit_load_frame_gpr(emitter, Gpr::Rax, source)?;
            emit_store_frame_gpr(emitter, destination, Gpr::Rax)?;
        }
        cursor = cursor
            .checked_add(width)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "tail commit extent",
            })?;
    }
    Ok(())
}

fn validate_tail_transfer<'program>(
    program: &'program X64TargetProgram,
    callee_id: X64FunctionId,
    arguments: &[X64Operand],
) -> Result<&'program X64Function, RawEncodeError> {
    let callee = function(program, callee_id)?;
    if arguments.len() != callee.parameters.len() {
        return Err(RawEncodeError::TailArity {
            function: callee_id,
            arguments: arguments.len(),
            parameters: callee.parameters.len(),
        });
    }

    let mut cursor = 0u32;
    for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
        require_operand_type("tail argument", parameter.home.ty, argument)?;
        check_home(program, "tail parameter", parameter.home)?;
        if let X64Operand::Home(home) = argument {
            check_home(program, "tail argument", *home)?;
        }
        let width = u32::from(parameter.home.width);
        let stage_offset = program.frame.outgoing_base.checked_add(cursor).ok_or(
            RawEncodeError::ArithmeticOverflow {
                field: "tail stage offset",
            },
        )?;
        check_outgoing(program, stage_offset, width)?;
        cursor = cursor
            .checked_add(width)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "tail stage extent",
            })?;
    }
    if cursor > program.frame.outgoing_bytes {
        return Err(RawEncodeError::TailExtent {
            required: cursor,
            declared: program.frame.outgoing_bytes,
        });
    }
    Ok(callee)
}

fn is_identity_tail_argument(argument: &X64Operand, parameter: &X64Parameter) -> bool {
    matches!(argument, X64Operand::Home(home) if *home == parameter.home)
}

/// Return a deterministic destructive-copy order when the non-identity part
/// of a parallel tail transfer is acyclic. A destination may be written only
/// after its old words are absent from every remaining source. A valid cycle
/// keeps two-phase staging; noncanonical overlapping destinations also refuse
/// the fast path and remain rejectable by the target verifier.
fn direct_tail_schedule(
    arguments: &[X64Operand],
    parameters: &[X64Parameter],
) -> Option<Vec<usize>> {
    if arguments.len() != parameters.len() {
        return None;
    }

    let mut destination_words = BTreeSet::new();
    for parameter in parameters {
        for offset in home_word_offsets(parameter.home) {
            if !destination_words.insert(offset) {
                return None;
            }
        }
    }

    let mut pending = arguments
        .iter()
        .zip(parameters)
        .enumerate()
        .filter_map(|(index, (argument, parameter))| {
            (!is_identity_tail_argument(argument, parameter)).then_some(index)
        })
        .collect::<Vec<_>>();
    let mut schedule = Vec::with_capacity(pending.len());

    while !pending.is_empty() {
        let mut source_words = BTreeSet::new();
        for index in &pending {
            if let X64Operand::Home(home) = arguments[*index] {
                source_words.extend(home_word_offsets(home));
            }
        }
        let position = pending.iter().position(|index| {
            home_word_offsets(parameters[*index].home)
                .into_iter()
                .all(|offset| !source_words.contains(&offset))
        })?;
        schedule.push(pending.remove(position));
    }

    Some(schedule)
}

fn home_word_offsets(home: X64Home) -> Vec<u32> {
    (0..u32::from(home.width / 8))
        .map(|word| home.offset + word * 8)
        .collect()
}

fn emit_stage_operand(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
    ty: MachineType,
    destination: u32,
) -> Result<(), RawEncodeError> {
    match ty {
        MachineType::Unit => emit_mov_mem64_imm32(emitter, destination, 0),
        MachineType::Bool | MachineType::I64 | MachineType::F64 => {
            emit_load_scalar(emitter, program, operand, Gpr::Rax)?;
            emit_store_frame_gpr(emitter, destination, Gpr::Rax)
        }
        MachineType::F64Array => {
            let source = array_home("tail F64Array argument", program, operand)?;
            emit_load_frame_gpr(emitter, Gpr::Rax, source.offset)?;
            emit_store_frame_gpr(emitter, destination, Gpr::Rax)?;
            let source_length =
                source
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "tail F64Array source length",
                    })?;
            let destination_length =
                destination
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "tail F64Array destination length",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rax, source_length)?;
            emit_store_frame_gpr(emitter, destination_length, Gpr::Rax)
        }
    }
}

fn emit_return_epilogue(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
) -> Result<(), RawEncodeError> {
    emit_load_frame_gpr(emitter, Gpr::Rcx, 8)?;
    emitter.bytes(&[0x48, 0x89, 0x01])?; // mov [rcx], rax
    emitter.bytes(&[0x48, 0x89, 0x91])?; // mov [rcx+disp32], rdx
    emitter.u32(8)?;
    emit_zero_gpr32(emitter, Gpr::Rax)?;
    emit_ldmxcsr_rsp_disp32(emitter, 0)?;
    emit_frame_release_and_return(emitter, program.frame.frame_bytes)
}

fn emit_bounds_epilogue(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
) -> Result<(), RawEncodeError> {
    emit_load_frame_gpr(emitter, Gpr::Rcx, 8)?;
    emit_zero_gpr32(emitter, Gpr::Rax)?;
    emitter.bytes(&[0x48, 0x89, 0x01])?; // mov [rcx], rax
    emitter.bytes(&[0x48, 0x89, 0x81])?; // mov [rcx+disp32], rax
    emitter.u32(8)?;
    emitter.bytes(&[0xb8])?; // mov eax, 1
    emitter.u32(1)?;
    emit_ldmxcsr_rsp_disp32(emitter, 0)?;
    emit_frame_release_and_return(emitter, program.frame.frame_bytes)
}

fn emit_frame_release_and_return(
    emitter: &mut RawEmitter,
    frame_bytes: u32,
) -> Result<(), RawEncodeError> {
    // add rsp, frame_bytes; pop rbp; ret
    emitter.bytes(&[0x48, 0x81, 0xc4])?;
    emitter.u32(frame_bytes)?;
    emitter.bytes(&[0x5d, 0xc3])
}

fn require_operand_type(
    context: &'static str,
    expected: MachineType,
    operand: &X64Operand,
) -> Result<(), RawEncodeError> {
    let actual = operand.ty();
    if actual != expected {
        return Err(RawEncodeError::InvalidOperand {
            context,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_result_width(context: &'static str, home: X64Home) -> Result<(), RawEncodeError> {
    let expected = physical_width(home.ty);
    if home.width != expected {
        return Err(RawEncodeError::InvalidResultWidth {
            context,
            ty: home.ty,
            expected,
            actual: home.width,
        });
    }
    Ok(())
}

fn require_home_type(
    context: &'static str,
    home: X64Home,
    expected: MachineType,
) -> Result<(), RawEncodeError> {
    if home.ty != expected {
        return Err(RawEncodeError::InvalidOperand {
            context,
            expected,
            actual: home.ty,
        });
    }
    require_result_width(context, home)
}

fn array_home(
    context: &'static str,
    program: &X64TargetProgram,
    operand: &X64Operand,
) -> Result<X64Home, RawEncodeError> {
    match operand {
        X64Operand::Home(home) if home.ty == MachineType::F64Array => {
            check_home(program, context, *home)?;
            Ok(*home)
        }
        _ => Err(RawEncodeError::InvalidArrayOperand { context }),
    }
}

fn emit_load_scalar(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
    destination: Gpr,
) -> Result<(), RawEncodeError> {
    match operand {
        X64Operand::Immediate { ty, value } => {
            let bits = match (ty, value) {
                (MachineType::Unit, X64Immediate::Unit) => 0,
                (MachineType::Bool, X64Immediate::Bool(value)) => u64::from(*value),
                (MachineType::I64, X64Immediate::I64(value)) => *value as u64,
                (MachineType::F64, X64Immediate::F64Bits(bits)) => *bits,
                _ => {
                    return Err(RawEncodeError::InvalidOperand {
                        context: "scalar immediate representation",
                        expected: *ty,
                        actual: *ty,
                    });
                }
            };
            emit_mov_imm64(emitter, destination, bits)
        }
        X64Operand::Home(home) => {
            if home.ty == MachineType::F64Array {
                return Err(RawEncodeError::InvalidArrayOperand {
                    context: "scalar load",
                });
            }
            check_home(program, "scalar operand", *home)?;
            emit_load_frame_gpr(emitter, destination, home.offset)
        }
    }
}

fn emit_load_f64_xmm0(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
) -> Result<(), RawEncodeError> {
    match operand {
        X64Operand::Immediate {
            ty: MachineType::F64,
            value: X64Immediate::F64Bits(bits),
        } => {
            emit_mov_imm64(emitter, Gpr::Rax, *bits)?;
            emitter.bytes(&[0x66, 0x48, 0x0f, 0x6e, 0xc0])
        }
        X64Operand::Home(home) if home.ty == MachineType::F64 => {
            check_home(program, "SSE2 F64 left operand", *home)?;
            emitter.bytes(&[0xf2, 0x0f, 0x10, 0x84, 0x24])?;
            emitter.u32(home.offset)
        }
        _ => Err(RawEncodeError::InvalidOperand {
            context: "SSE2 F64 left operand",
            expected: MachineType::F64,
            actual: operand.ty(),
        }),
    }
}

fn emit_load_f64_xmm1(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
) -> Result<(), RawEncodeError> {
    match operand {
        X64Operand::Immediate {
            ty: MachineType::F64,
            value: X64Immediate::F64Bits(bits),
        } => {
            emit_mov_imm64(emitter, Gpr::Rcx, *bits)?;
            emitter.bytes(&[0x66, 0x48, 0x0f, 0x6e, 0xc9])
        }
        X64Operand::Home(home) if home.ty == MachineType::F64 => {
            check_home(program, "SSE2 F64 right operand", *home)?;
            emitter.bytes(&[0xf2, 0x0f, 0x10, 0x8c, 0x24])?;
            emitter.u32(home.offset)
        }
        _ => Err(RawEncodeError::InvalidOperand {
            context: "SSE2 F64 right operand",
            expected: MachineType::F64,
            actual: operand.ty(),
        }),
    }
}

fn emit_store_xmm0_frame(emitter: &mut RawEmitter, offset: u32) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0xf2, 0x0f, 0x11, 0x84, 0x24])?;
    emitter.u32(offset)
}

fn emit_load_frame_gpr(
    emitter: &mut RawEmitter,
    destination: Gpr,
    offset: u32,
) -> Result<(), RawEncodeError> {
    let number = destination.number();
    let rex = 0x48 | if number >= 8 { 0x04 } else { 0 };
    let modrm = 0x84 | ((number & 7) << 3);
    emitter.bytes(&[rex, 0x8b, modrm, 0x24])?;
    emitter.u32(offset)
}

fn emit_store_frame_gpr(
    emitter: &mut RawEmitter,
    offset: u32,
    source: Gpr,
) -> Result<(), RawEncodeError> {
    let number = source.number();
    let rex = 0x48 | if number >= 8 { 0x04 } else { 0 };
    let modrm = 0x84 | ((number & 7) << 3);
    emitter.bytes(&[rex, 0x89, modrm, 0x24])?;
    emitter.u32(offset)
}

fn emit_mov_gpr(
    emitter: &mut RawEmitter,
    destination: Gpr,
    source: Gpr,
) -> Result<(), RawEncodeError> {
    if destination == source {
        return Ok(());
    }
    let destination = destination.number();
    let source = source.number();
    let rex = 0x48 | if source >= 8 { 0x04 } else { 0 } | if destination >= 8 { 0x01 } else { 0 };
    let modrm = 0xc0 | ((source & 7) << 3) | (destination & 7);
    emitter.bytes(&[rex, 0x89, modrm])
}

fn emit_load_frame_xmm(
    emitter: &mut RawEmitter,
    destination: u8,
    offset: u32,
) -> Result<(), RawEncodeError> {
    if destination >= 8 {
        return Err(RawEncodeError::OffsetOutOfRange {
            field: "XMM register",
            offset: u64::from(destination),
        });
    }
    emitter.bytes(&[0xf2, 0x0f, 0x10, 0x84 | (destination << 3), 0x24])?;
    emitter.u32(offset)
}

fn emit_store_frame_xmm(
    emitter: &mut RawEmitter,
    source: u8,
    offset: u32,
) -> Result<(), RawEncodeError> {
    if source >= 8 {
        return Err(RawEncodeError::OffsetOutOfRange {
            field: "XMM register",
            offset: u64::from(source),
        });
    }
    emitter.bytes(&[0xf2, 0x0f, 0x11, 0x84 | (source << 3), 0x24])?;
    emitter.u32(offset)
}

fn emit_movsd_xmm(
    emitter: &mut RawEmitter,
    destination: u8,
    source: u8,
) -> Result<(), RawEncodeError> {
    if destination >= 8 || source >= 8 {
        return Err(RawEncodeError::OffsetOutOfRange {
            field: "XMM register",
            offset: u64::from(destination.max(source)),
        });
    }
    if destination == source {
        return Ok(());
    }
    emitter.bytes(&[0xf2, 0x0f, 0x10, 0xc0 | (destination << 3) | source])
}

fn emit_movq_xmm_gpr(
    emitter: &mut RawEmitter,
    destination: u8,
    source: Gpr,
) -> Result<(), RawEncodeError> {
    if destination >= 8 {
        return Err(RawEncodeError::OffsetOutOfRange {
            field: "XMM register",
            offset: u64::from(destination),
        });
    }
    let source = source.number();
    let rex = 0x48 | if source >= 8 { 0x01 } else { 0 };
    emitter.bytes(&[
        0x66,
        rex,
        0x0f,
        0x6e,
        0xc0 | (destination << 3) | (source & 7),
    ])
}

fn emit_mov_imm64(
    emitter: &mut RawEmitter,
    destination: Gpr,
    value: u64,
) -> Result<(), RawEncodeError> {
    let number = destination.number();
    let rex = 0x48 | if number >= 8 { 0x01 } else { 0 };
    emitter.bytes(&[rex, 0xb8 + (number & 7)])?;
    emitter.u64(value)
}

fn emit_zero_gpr32(emitter: &mut RawEmitter, register: Gpr) -> Result<(), RawEncodeError> {
    let number = register.number();
    let rex = if number >= 8 { Some(0x45) } else { None };
    if let Some(rex) = rex {
        emitter.u8(rex)?;
    }
    let modrm = 0xc0 | ((number & 7) << 3) | (number & 7);
    emitter.bytes(&[0x31, modrm])
}

fn emit_mov_mem32_imm32(
    emitter: &mut RawEmitter,
    offset: u32,
    value: u32,
) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0xc7, 0x84, 0x24])?;
    emitter.u32(offset)?;
    emitter.u32(value)
}

fn emit_mov_mem64_imm32(
    emitter: &mut RawEmitter,
    offset: u32,
    value: u32,
) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0x48, 0xc7, 0x84, 0x24])?;
    emitter.u32(offset)?;
    emitter.u32(value)
}

fn emit_stmxcsr_rsp_disp32(emitter: &mut RawEmitter, offset: u32) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0x0f, 0xae, 0x9c, 0x24])?;
    emitter.u32(offset)
}

fn emit_ldmxcsr_rsp_disp32(emitter: &mut RawEmitter, offset: u32) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0x0f, 0xae, 0x94, 0x24])?;
    emitter.u32(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;

    fn emitter() -> RawEmitter {
        RawEmitter {
            code: Vec::new(),
            labels: Vec::new(),
            label_indices: BTreeMap::new(),
            marked_labels: BTreeMap::new(),
            fixups: Vec::new(),
            code_limit: 1024,
            fixup_limit: 16,
            atoms: Vec::new(),
        }
    }

    fn tail_transfer_program(parameters: Vec<X64Parameter>) -> X64TargetProgram {
        let outgoing_base = parameters
            .iter()
            .map(|parameter| parameter.home.offset + u32::from(parameter.home.width))
            .max()
            .unwrap_or(32);
        let outgoing_bytes = parameters
            .iter()
            .map(|parameter| u32::from(parameter.home.width))
            .sum();
        X64TargetProgram {
            schema: X64TargetSchemaVersion::r1_s7a(),
            lowering_policy_version: X64_TARGET_LOWERING_POLICY_VERSION,
            encoder_policy_version: X64_TARGET_ENCODER_POLICY_VERSION,
            abi: X64TargetAbi::r1_s7a(),
            limits: X64TargetLimits::r1_s7a(),
            source_core_hash: SemanticHash::ZERO,
            source_ssa_hash: SemanticHash::ZERO,
            source_machine_ir_hash: SemanticHash::ZERO,
            entry: X64FunctionId(0),
            entry_offset: 0,
            entry_abi: X64EntryAbi {
                parameter_types: Vec::new(),
                input_lanes: Vec::new(),
                output_register: X64AbiRegister::Rdx,
                result: MachineType::Unit,
                output_words: 0,
            },
            frame: X64FrameLayout {
                header_bytes: 32,
                home_base: 32,
                max_home_bytes: outgoing_base - 32,
                outgoing_base,
                outgoing_bytes,
                frame_bytes: outgoing_base + outgoing_bytes,
            },
            functions: vec![X64Function {
                id: X64FunctionId(0),
                parameters,
                effects: Vec::new(),
                result: MachineType::Unit,
                entry_block: X64BlockId(0),
                blocks: Vec::new(),
            }],
            labels: Vec::new(),
            fixups: Vec::new(),
            code: Vec::new(),
            plan_hash: SemanticHash::ZERO,
            code_hash: SemanticHash::ZERO,
        }
    }

    fn origin(function: u32, block: u32, position: X64SourcePosition) -> X64SourceOrigin {
        X64SourceOrigin {
            function: X64FunctionId(function),
            block: X64BlockId(block),
            position,
        }
    }

    fn fused_compare_program(condition: X64SetCondition) -> X64TargetProgram {
        let left = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::I64,
        };
        let right = X64Home {
            slot: X64HomeSlot(1),
            offset: 40,
            width: 8,
            ty: MachineType::I64,
        };
        let branch_condition = X64Home {
            slot: X64HomeSlot(2),
            offset: 48,
            width: 8,
            ty: MachineType::Bool,
        };
        let comparison_result = X64Home {
            slot: X64HomeSlot(3),
            offset: 56,
            width: 8,
            ty: MachineType::Bool,
        };
        let mut program = tail_transfer_program(Vec::new());
        program.entry = X64FunctionId(0);
        program.frame = X64FrameLayout {
            header_bytes: 32,
            home_base: 32,
            max_home_bytes: 32,
            outgoing_base: 64,
            outgoing_bytes: 24,
            frame_bytes: 96,
        };
        program.functions = vec![
            X64Function {
                id: X64FunctionId(0),
                parameters: vec![X64Parameter { home: left }, X64Parameter { home: right }],
                effects: Vec::new(),
                result: MachineType::Unit,
                entry_block: X64BlockId(0),
                blocks: vec![X64Block {
                    id: X64BlockId(0),
                    label: X64LabelId(0),
                    instructions: vec![X64Instruction {
                        origin: origin(0, 0, X64SourcePosition::Instruction(0)),
                        result: comparison_result,
                        kind: X64InstructionKind::I64Setcc {
                            condition,
                            left: X64Operand::Home(left),
                            right: X64Operand::Home(right),
                        },
                    }],
                    terminator: X64Terminator::TailJumpRel32 {
                        origin: origin(0, 0, X64SourcePosition::Terminator),
                        function: X64FunctionId(1),
                        target_label: X64LabelId(1),
                        arguments: vec![
                            X64Operand::Home(left),
                            X64Operand::Home(right),
                            X64Operand::Home(comparison_result),
                        ],
                    },
                }],
            },
            X64Function {
                id: X64FunctionId(1),
                parameters: vec![
                    X64Parameter { home: left },
                    X64Parameter { home: right },
                    X64Parameter {
                        home: branch_condition,
                    },
                ],
                effects: Vec::new(),
                result: MachineType::Unit,
                entry_block: X64BlockId(0),
                blocks: vec![
                    X64Block {
                        id: X64BlockId(0),
                        label: X64LabelId(1),
                        instructions: Vec::new(),
                        terminator: X64Terminator::BranchRel32 {
                            origin: origin(1, 0, X64SourcePosition::Terminator),
                            condition: X64Operand::Home(branch_condition),
                            then_label: X64LabelId(2),
                            else_label: X64LabelId(3),
                        },
                    },
                    X64Block {
                        id: X64BlockId(1),
                        label: X64LabelId(2),
                        instructions: Vec::new(),
                        terminator: X64Terminator::Return {
                            origin: origin(1, 1, X64SourcePosition::Terminator),
                            value: X64Operand::Immediate {
                                ty: MachineType::Unit,
                                value: X64Immediate::Unit,
                            },
                        },
                    },
                    X64Block {
                        id: X64BlockId(2),
                        label: X64LabelId(3),
                        instructions: Vec::new(),
                        terminator: X64Terminator::Return {
                            origin: origin(1, 2, X64SourcePosition::Terminator),
                            value: X64Operand::Immediate {
                                ty: MachineType::Unit,
                                value: X64Immediate::Unit,
                            },
                        },
                    },
                ],
            },
        ];
        program.labels = vec![
            X64Label {
                id: X64LabelId(0),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(0),
                    block: X64BlockId(0),
                },
                code_offset: 0,
            },
            X64Label {
                id: X64LabelId(1),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(1),
                    block: X64BlockId(0),
                },
                code_offset: 0,
            },
            X64Label {
                id: X64LabelId(2),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(1),
                    block: X64BlockId(1),
                },
                code_offset: 0,
            },
            X64Label {
                id: X64LabelId(3),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(1),
                    block: X64BlockId(2),
                },
                code_offset: 0,
            },
        ];
        program
    }

    fn identity_thread_program() -> X64TargetProgram {
        let parameter = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::I64,
        };
        let mut program = tail_transfer_program(Vec::new());
        program.functions = (0_u32..3)
            .map(|function_id| X64Function {
                id: X64FunctionId(function_id),
                parameters: vec![X64Parameter { home: parameter }],
                effects: Vec::new(),
                result: MachineType::Unit,
                entry_block: X64BlockId(0),
                blocks: vec![X64Block {
                    id: X64BlockId(0),
                    label: X64LabelId(function_id),
                    instructions: Vec::new(),
                    terminator: if function_id < 2 {
                        X64Terminator::TailJumpRel32 {
                            origin: origin(function_id, 0, X64SourcePosition::Terminator),
                            function: X64FunctionId(function_id + 1),
                            target_label: X64LabelId(function_id + 1),
                            arguments: vec![X64Operand::Home(parameter)],
                        }
                    } else {
                        X64Terminator::Return {
                            origin: origin(function_id, 0, X64SourcePosition::Terminator),
                            value: X64Operand::Immediate {
                                ty: MachineType::Unit,
                                value: X64Immediate::Unit,
                            },
                        }
                    },
                }],
            })
            .collect();
        program.labels = (0_u32..3)
            .map(|id| X64Label {
                id: X64LabelId(id),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(id),
                    block: X64BlockId(0),
                },
                code_offset: 0,
            })
            .collect();
        program
    }

    fn mixed_tail_composition_program() -> (X64TargetProgram, X64Home, X64Home) {
        let home = |slot: u32, offset: u32| X64Home {
            slot: X64HomeSlot(slot),
            offset,
            width: 8,
            ty: MachineType::I64,
        };
        let source_a = home(0, 32);
        let source_b = home(1, 40);
        let parameter_sets = [
            [home(2, 48), home(3, 56)],
            [home(4, 64), home(5, 72)],
            [home(6, 80), home(7, 88)],
        ];
        let mut program = tail_transfer_program(Vec::new());
        program.frame = X64FrameLayout {
            header_bytes: 32,
            home_base: 32,
            max_home_bytes: 64,
            outgoing_base: 96,
            outgoing_bytes: 16,
            frame_bytes: 112,
        };
        program.functions = (0..3)
            .map(|index| {
                let function_id = index as u32 + 1;
                let parameters = parameter_sets[index]
                    .map(|home| X64Parameter { home })
                    .to_vec();
                let terminator = match index {
                    0 => X64Terminator::TailJumpRel32 {
                        origin: origin(function_id, 0, X64SourcePosition::Terminator),
                        function: X64FunctionId(2),
                        target_label: X64LabelId(2),
                        arguments: vec![
                            X64Operand::Home(parameter_sets[0][1]),
                            X64Operand::Immediate {
                                ty: MachineType::I64,
                                value: X64Immediate::I64(7),
                            },
                        ],
                    },
                    1 => X64Terminator::TailJumpRel32 {
                        origin: origin(function_id, 0, X64SourcePosition::Terminator),
                        function: X64FunctionId(3),
                        target_label: X64LabelId(3),
                        arguments: vec![
                            X64Operand::Home(parameter_sets[1][1]),
                            X64Operand::Home(parameter_sets[1][0]),
                        ],
                    },
                    _ => X64Terminator::Return {
                        origin: origin(function_id, 0, X64SourcePosition::Terminator),
                        value: X64Operand::Immediate {
                            ty: MachineType::Unit,
                            value: X64Immediate::Unit,
                        },
                    },
                };
                X64Function {
                    id: X64FunctionId(function_id),
                    parameters,
                    effects: Vec::new(),
                    result: MachineType::Unit,
                    entry_block: X64BlockId(0),
                    blocks: vec![X64Block {
                        id: X64BlockId(0),
                        label: X64LabelId(function_id),
                        instructions: Vec::new(),
                        terminator,
                    }],
                }
            })
            .collect();
        program.labels = (1_u32..=3)
            .map(|id| X64Label {
                id: X64LabelId(id),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(id),
                    block: X64BlockId(0),
                },
                code_offset: 0,
            })
            .collect();
        (program, source_a, source_b)
    }

    fn compare_predecessor_program(multiple: bool) -> (X64TargetProgram, X64LabelId) {
        let mut program = fused_compare_program(X64SetCondition::SignedLessThan);
        let left = program.functions[0].parameters[0].home;
        let right = program.functions[0].parameters[1].home;
        let scratch = program.functions[0].blocks[0].instructions[0].result;
        let tail = |block: u32| X64Terminator::TailJumpRel32 {
            origin: origin(2, block, X64SourcePosition::Terminator),
            function: X64FunctionId(0),
            target_label: X64LabelId(0),
            arguments: vec![
                X64Operand::Immediate {
                    ty: MachineType::I64,
                    value: X64Immediate::I64(7),
                },
                X64Operand::Immediate {
                    ty: MachineType::I64,
                    value: X64Immediate::I64(11),
                },
            ],
        };
        let move_false = |block: u32| X64Instruction {
            origin: origin(2, block, X64SourcePosition::Instruction(0)),
            result: scratch,
            kind: X64InstructionKind::Move(X64Operand::Immediate {
                ty: MachineType::Bool,
                value: X64Immediate::Bool(false),
            }),
        };
        let blocks = if multiple {
            vec![
                X64Block {
                    id: X64BlockId(0),
                    label: X64LabelId(10),
                    instructions: Vec::new(),
                    terminator: X64Terminator::BranchRel32 {
                        origin: origin(2, 0, X64SourcePosition::Terminator),
                        condition: X64Operand::Immediate {
                            ty: MachineType::Bool,
                            value: X64Immediate::Bool(true),
                        },
                        then_label: X64LabelId(11),
                        else_label: X64LabelId(12),
                    },
                },
                X64Block {
                    id: X64BlockId(1),
                    label: X64LabelId(11),
                    instructions: vec![move_false(1)],
                    terminator: tail(1),
                },
                X64Block {
                    id: X64BlockId(2),
                    label: X64LabelId(12),
                    instructions: vec![move_false(2)],
                    terminator: tail(2),
                },
            ]
        } else {
            vec![X64Block {
                id: X64BlockId(0),
                label: X64LabelId(10),
                instructions: vec![move_false(0)],
                terminator: tail(0),
            }]
        };
        program.entry = X64FunctionId(2);
        program.functions.push(X64Function {
            id: X64FunctionId(2),
            parameters: Vec::new(),
            effects: Vec::new(),
            result: MachineType::Unit,
            entry_block: X64BlockId(0),
            blocks,
        });
        let block_count = if multiple { 3 } else { 1 };
        program
            .labels
            .extend((0..block_count).map(|block| X64Label {
                id: X64LabelId(10 + block),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(2),
                    block: X64BlockId(block),
                },
                code_offset: 0,
            }));
        let _ = (left, right);
        (program, X64LabelId(10))
    }

    fn one_op_superblock_program() -> X64TargetProgram {
        let first = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::I64,
        };
        let second = X64Home {
            slot: X64HomeSlot(1),
            offset: 40,
            width: 8,
            ty: MachineType::I64,
        };
        let mut program = tail_transfer_program(Vec::new());
        program.entry = X64FunctionId(0);
        program.entry_abi = X64EntryAbi {
            parameter_types: Vec::new(),
            input_lanes: Vec::new(),
            output_register: X64AbiRegister::Rdx,
            result: MachineType::I64,
            output_words: 1,
        };
        program.frame = X64FrameLayout {
            header_bytes: 32,
            home_base: 32,
            max_home_bytes: 16,
            outgoing_base: 48,
            outgoing_bytes: 8,
            frame_bytes: 64,
        };
        program.functions = vec![
            X64Function {
                id: X64FunctionId(0),
                parameters: Vec::new(),
                effects: Vec::new(),
                result: MachineType::I64,
                entry_block: X64BlockId(0),
                blocks: vec![X64Block {
                    id: X64BlockId(0),
                    label: X64LabelId(0),
                    instructions: vec![X64Instruction {
                        origin: origin(0, 0, X64SourcePosition::Instruction(0)),
                        result: first,
                        kind: X64InstructionKind::Move(X64Operand::Immediate {
                            ty: MachineType::I64,
                            value: X64Immediate::I64(0),
                        }),
                    }],
                    terminator: X64Terminator::TailJumpRel32 {
                        origin: origin(0, 0, X64SourcePosition::Terminator),
                        function: X64FunctionId(1),
                        target_label: X64LabelId(1),
                        arguments: Vec::new(),
                    },
                }],
            },
            X64Function {
                id: X64FunctionId(1),
                parameters: Vec::new(),
                effects: Vec::new(),
                result: MachineType::I64,
                entry_block: X64BlockId(0),
                blocks: vec![X64Block {
                    id: X64BlockId(0),
                    label: X64LabelId(1),
                    instructions: vec![X64Instruction {
                        origin: origin(1, 0, X64SourcePosition::Instruction(0)),
                        result: second,
                        kind: X64InstructionKind::Move(X64Operand::Immediate {
                            ty: MachineType::I64,
                            value: X64Immediate::I64(41),
                        }),
                    }],
                    terminator: X64Terminator::TailJumpRel32 {
                        origin: origin(1, 0, X64SourcePosition::Terminator),
                        function: X64FunctionId(2),
                        target_label: X64LabelId(2),
                        arguments: vec![X64Operand::Home(second)],
                    },
                }],
            },
            X64Function {
                id: X64FunctionId(2),
                parameters: vec![X64Parameter { home: first }],
                effects: Vec::new(),
                result: MachineType::I64,
                entry_block: X64BlockId(0),
                blocks: vec![X64Block {
                    id: X64BlockId(0),
                    label: X64LabelId(2),
                    instructions: Vec::new(),
                    terminator: X64Terminator::Return {
                        origin: origin(2, 0, X64SourcePosition::Terminator),
                        value: X64Operand::Home(first),
                    },
                }],
            },
            X64Function {
                id: X64FunctionId(3),
                parameters: Vec::new(),
                effects: Vec::new(),
                result: MachineType::I64,
                entry_block: X64BlockId(0),
                blocks: vec![X64Block {
                    id: X64BlockId(0),
                    label: X64LabelId(3),
                    instructions: Vec::new(),
                    terminator: X64Terminator::Return {
                        origin: origin(3, 0, X64SourcePosition::Terminator),
                        value: X64Operand::Immediate {
                            ty: MachineType::I64,
                            value: X64Immediate::I64(99),
                        },
                    },
                }],
            },
        ];
        program.labels = (0_u32..4)
            .map(|id| X64Label {
                id: X64LabelId(id),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(id),
                    block: X64BlockId(0),
                },
                code_offset: 0,
            })
            .chain([
                X64Label {
                    id: X64LabelId(4),
                    owner: X64LabelOwner::EntryAdapter,
                    code_offset: 0,
                },
                X64Label {
                    id: X64LabelId(5),
                    owner: X64LabelOwner::ReturnEpilogue,
                    code_offset: 0,
                },
                X64Label {
                    id: X64LabelId(6),
                    owner: X64LabelOwner::BoundsEpilogue,
                    code_offset: 0,
                },
            ])
            .collect();
        program
    }

    #[test]
    fn fixed_rsp_disp32_templates_are_exact() {
        let mut emitter = emitter();
        emit_store_frame_gpr(&mut emitter, 0x1122_3344, Gpr::R8).unwrap();
        emit_load_frame_gpr(&mut emitter, Gpr::R9, 0x5566_7788).unwrap();
        assert_eq!(
            emitter.code,
            vec![
                0x4c, 0x89, 0x84, 0x24, 0x44, 0x33, 0x22, 0x11, 0x4c, 0x8b, 0x8c, 0x24, 0x88, 0x77,
                0x66, 0x55,
            ]
        );
    }

    #[test]
    fn rel32_patch_is_retained_and_little_endian() {
        let target = X64LabelId(0);
        let mut emitter = RawEmitter {
            code: Vec::new(),
            labels: vec![X64Label {
                id: target,
                owner: X64LabelOwner::ReturnEpilogue,
                code_offset: 0,
            }],
            label_indices: BTreeMap::from([(target, 0)]),
            marked_labels: BTreeMap::new(),
            fixups: Vec::new(),
            code_limit: 1024,
            fixup_limit: 16,
            atoms: Vec::new(),
        };
        emitter
            .atom(
                RawExecutionEvent::Static,
                RawTemplateClass::Tombstone,
                |emitter| {
                    emitter.rel32(&[0xe9], target)?;
                    emitter.bytes(&[0x90, 0x90])
                },
            )
            .unwrap();
        emitter.mark(target).unwrap();
        let encoding = emitter
            .finish(false, Vec::new(), RawSharedJoinComposition::default())
            .unwrap();
        assert_eq!(encoding.code, vec![0xe9, 0x02, 0, 0, 0, 0x90, 0x90]);
        assert_eq!(
            encoding.fixups,
            vec![X64Fixup {
                patch_offset: 1,
                target,
                addend: 0,
            }]
        );
    }

    #[test]
    fn tail_identity_requires_the_exact_typed_destination_home() {
        let home = X64Home {
            slot: X64HomeSlot(3),
            offset: 56,
            width: 8,
            ty: MachineType::I64,
        };
        let parameter = X64Parameter { home };
        assert!(is_identity_tail_argument(
            &X64Operand::Home(home),
            &parameter,
        ));
        assert!(!is_identity_tail_argument(
            &X64Operand::Immediate {
                ty: MachineType::I64,
                value: X64Immediate::I64(0),
            },
            &parameter,
        ));
        assert!(!is_identity_tail_argument(
            &X64Operand::Home(X64Home {
                slot: X64HomeSlot(4),
                offset: 64,
                ..home
            }),
            &parameter,
        ));
    }

    #[test]
    fn acyclic_copy_preserves_identity_source_before_overwrite() {
        let first = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::I64,
        };
        let second = X64Home {
            slot: X64HomeSlot(1),
            offset: 40,
            width: 8,
            ty: MachineType::I64,
        };
        let program = tail_transfer_program(vec![
            X64Parameter { home: first },
            X64Parameter { home: second },
        ]);
        let mut emitter = emitter();

        // Parallel transfer [p0, p0]: p0 <- p0 is elided and p1 <- p0
        // directly reads the unchanged p0.
        emit_tail_transfer(
            &mut emitter,
            &program,
            X64FunctionId(0),
            &[X64Operand::Home(first), X64Operand::Home(first)],
        )
        .unwrap();

        assert_eq!(
            emitter.code,
            vec![0x48, 0x8b, 0x84, 0x24, 0x20, 0, 0, 0, 0x48, 0x89, 0x84, 0x24, 0x28, 0, 0, 0,]
        );
    }

    #[test]
    fn cyclic_parallel_copy_uses_the_two_phase_fallback() {
        let first = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::I64,
        };
        let second = X64Home {
            slot: X64HomeSlot(1),
            offset: 40,
            width: 8,
            ty: MachineType::I64,
        };
        let parameters = vec![X64Parameter { home: first }, X64Parameter { home: second }];
        let arguments = vec![X64Operand::Home(second), X64Operand::Home(first)];
        assert_eq!(direct_tail_schedule(&arguments, &parameters), None);

        let program = tail_transfer_program(parameters);
        let mut emitter = emitter();
        emit_tail_transfer(&mut emitter, &program, X64FunctionId(0), &arguments).unwrap();

        assert_eq!(
            emitter.code,
            vec![
                // Stage p1 and p0 before either destination is overwritten.
                0x48, 0x8b, 0x84, 0x24, 0x28, 0, 0, 0, 0x48, 0x89, 0x84, 0x24, 0x30, 0, 0, 0, 0x48,
                0x8b, 0x84, 0x24, 0x20, 0, 0, 0, 0x48, 0x89, 0x84, 0x24, 0x38, 0, 0, 0,
                // Commit the staged swap.
                0x48, 0x8b, 0x84, 0x24, 0x30, 0, 0, 0, 0x48, 0x89, 0x84, 0x24, 0x20, 0, 0, 0, 0x48,
                0x8b, 0x84, 0x24, 0x38, 0, 0, 0, 0x48, 0x89, 0x84, 0x24, 0x28, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn destructive_copy_order_keeps_old_sources_live() {
        let first = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::I64,
        };
        let second = X64Home {
            slot: X64HomeSlot(1),
            offset: 40,
            width: 8,
            ty: MachineType::I64,
        };
        let parameters = [X64Parameter { home: first }, X64Parameter { home: second }];
        let arguments = [
            X64Operand::Home(second),
            X64Operand::Immediate {
                ty: MachineType::I64,
                value: X64Immediate::I64(7),
            },
        ];

        assert_eq!(
            direct_tail_schedule(&arguments, &parameters),
            Some(vec![0, 1]),
            "p0 must consume old p1 before p1 is overwritten"
        );
    }

    #[test]
    fn larger_cycles_and_overlapping_destinations_refuse_direct_copy() {
        let homes = [0_u32, 1, 2].map(|slot| X64Home {
            slot: X64HomeSlot(slot),
            offset: 32 + slot * 8,
            width: 8,
            ty: MachineType::I64,
        });
        let parameters = homes.map(|home| X64Parameter { home });
        let arguments = [
            X64Operand::Home(homes[1]),
            X64Operand::Home(homes[2]),
            X64Operand::Home(homes[0]),
        ];
        assert_eq!(direct_tail_schedule(&arguments, &parameters), None);

        let array = X64Home {
            slot: X64HomeSlot(3),
            offset: 32,
            width: 16,
            ty: MachineType::F64Array,
        };
        let overlapping_scalar = X64Home {
            slot: X64HomeSlot(4),
            offset: 40,
            width: 8,
            ty: MachineType::I64,
        };
        assert_eq!(
            direct_tail_schedule(
                &[
                    X64Operand::Home(array),
                    X64Operand::Immediate {
                        ty: MachineType::I64,
                        value: X64Immediate::I64(0),
                    },
                ],
                &[
                    X64Parameter { home: array },
                    X64Parameter {
                        home: overlapping_scalar,
                    },
                ],
            ),
            None
        );
    }

    #[test]
    fn direct_array_copy_loads_pointer_and_length_before_stores() {
        let first = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 16,
            ty: MachineType::F64Array,
        };
        let second = X64Home {
            slot: X64HomeSlot(1),
            offset: 48,
            width: 16,
            ty: MachineType::F64Array,
        };
        let program = tail_transfer_program(vec![
            X64Parameter { home: first },
            X64Parameter { home: second },
        ]);
        let mut emitter = emitter();
        emit_tail_transfer(
            &mut emitter,
            &program,
            X64FunctionId(0),
            &[X64Operand::Home(first), X64Operand::Home(first)],
        )
        .unwrap();

        assert_eq!(
            emitter.code,
            vec![
                // Both source words are loaded before either destination word.
                0x48, 0x8b, 0x84, 0x24, 0x20, 0, 0, 0, 0x48, 0x8b, 0x94, 0x24, 0x28, 0, 0, 0, 0x48,
                0x89, 0x84, 0x24, 0x30, 0, 0, 0, 0x48, 0x89, 0x94, 0x24, 0x38, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn compare_tail_branch_fusion_emits_canonical_bool_and_signed_branch() {
        for (condition, setcc, branch) in [
            (X64SetCondition::SignedLessThan, 0x9c, 0x8c),
            (X64SetCondition::SignedGreaterOrEqual, 0x9d, 0x8d),
        ] {
            let program = fused_compare_program(condition);
            let source = &program.functions[0].blocks[0];
            let fused = classify_fused_compare_tail_branch(&program, source)
                .expect("exact compare-tail-branch pattern must classify");
            assert_eq!(fused.condition_home.offset, 48);
            let mut emitter = RawEmitter::new(&program).unwrap();
            assert!(emit_fused_compare_tail_branch(&mut emitter, &program, source).unwrap());
            assert_eq!(emitter.code.len(), 45);
            assert_eq!(&emitter.code[19..22], &[0x0f, setcc, 0xc0]);
            assert_eq!(&emitter.code[22..26], &[0x48, 0x0f, 0xb6, 0xc0]);
            assert_eq!(
                &emitter.code[26..34],
                &[0x48, 0x89, 0x84, 0x24, 0x30, 0, 0, 0]
            );
            assert_eq!(&emitter.code[34..36], &[0x0f, branch]);
            assert_eq!(&emitter.code[40..41], &[0xe9]);
            assert_eq!(
                emitter.fixups,
                vec![
                    X64Fixup {
                        patch_offset: 36,
                        target: X64LabelId(2),
                        addend: 0,
                    },
                    X64Fixup {
                        patch_offset: 41,
                        target: X64LabelId(3),
                        addend: 0,
                    },
                ]
            );
        }
    }

    #[test]
    fn compare_tail_branch_fusion_rejects_nonexact_shapes() {
        let mut sibling_move = fused_compare_program(X64SetCondition::SignedLessThan);
        let X64Terminator::TailJumpRel32 { arguments, .. } =
            &mut sibling_move.functions[0].blocks[0].terminator
        else {
            unreachable!()
        };
        arguments[0] = X64Operand::Immediate {
            ty: MachineType::I64,
            value: X64Immediate::I64(0),
        };
        assert!(classify_fused_compare_tail_branch(
            &sibling_move,
            &sibling_move.functions[0].blocks[0]
        )
        .is_none());

        let mut nonempty_callee = fused_compare_program(X64SetCondition::SignedLessThan);
        nonempty_callee.functions[1].blocks[0]
            .instructions
            .push(X64Instruction {
                origin: origin(1, 0, X64SourcePosition::Instruction(0)),
                result: X64Home {
                    slot: X64HomeSlot(2),
                    offset: 48,
                    width: 8,
                    ty: MachineType::Bool,
                },
                kind: X64InstructionKind::Move(X64Operand::Immediate {
                    ty: MachineType::Bool,
                    value: X64Immediate::Bool(false),
                }),
            });
        assert!(classify_fused_compare_tail_branch(
            &nonempty_callee,
            &nonempty_callee.functions[0].blocks[0]
        )
        .is_none());

        let mut immediate_condition = fused_compare_program(X64SetCondition::SignedLessThan);
        let X64Terminator::BranchRel32 { condition, .. } =
            &mut immediate_condition.functions[1].blocks[0].terminator
        else {
            unreachable!()
        };
        *condition = X64Operand::Immediate {
            ty: MachineType::Bool,
            value: X64Immediate::Bool(true),
        };
        assert!(classify_fused_compare_tail_branch(
            &immediate_condition,
            &immediate_condition.functions[0].blocks[0]
        )
        .is_none());
    }

    #[test]
    fn noop_tail_target_threading_is_transitive_and_cycle_safe() {
        let mut program = identity_thread_program();
        assert_eq!(
            thread_noop_tail_target(&program, X64LabelId(0)).unwrap(),
            X64LabelId(2)
        );

        program.functions[2].blocks[0].terminator = X64Terminator::TailJumpRel32 {
            origin: origin(2, 0, X64SourcePosition::Terminator),
            function: X64FunctionId(0),
            target_label: X64LabelId(0),
            arguments: vec![X64Operand::Home(program.functions[0].parameters[0].home)],
        };
        assert_eq!(
            thread_noop_tail_target(&program, X64LabelId(0)).unwrap(),
            X64LabelId(0),
            "a no-op cycle must keep the caller's original target"
        );
    }

    #[test]
    fn empty_tail_routes_compose_mixed_values_transitively() {
        let (program, source_a, source_b) = mixed_tail_composition_program();
        let route = compose_empty_tail_route(
            &program,
            X64FunctionId(1),
            X64LabelId(1),
            &[X64Operand::Home(source_a), X64Operand::Home(source_b)],
        )
        .unwrap();

        assert_eq!(route.callee, X64FunctionId(3));
        assert_eq!(route.target_label, X64LabelId(3));
        assert_eq!(
            route.arguments,
            vec![
                X64Operand::Immediate {
                    ty: MachineType::I64,
                    value: X64Immediate::I64(7),
                },
                X64Operand::Home(source_b),
            ]
        );
    }

    #[test]
    fn empty_tail_composition_is_selected_only_for_a_direct_final_copy() {
        let (mut program, source_a, source_b) = mixed_tail_composition_program();
        let arguments = vec![X64Operand::Home(source_a), X64Operand::Home(source_b)];
        let selected = select_direct_composed_tail_route(
            &program,
            X64FunctionId(1),
            X64LabelId(1),
            &arguments,
        )
        .unwrap();
        assert_eq!(selected.callee, X64FunctionId(3));
        assert_ne!(selected.arguments, arguments);

        let first_parameters = program.functions[0].parameters.clone();
        let second_parameters = program.functions[1].parameters.clone();
        let final_parameters = program.functions[2].parameters.clone();
        let X64Terminator::TailJumpRel32 {
            arguments: first_arguments,
            ..
        } = &mut program.functions[0].blocks[0].terminator
        else {
            unreachable!()
        };
        *first_arguments = vec![
            X64Operand::Home(first_parameters[1].home),
            X64Operand::Home(first_parameters[0].home),
        ];
        let X64Terminator::TailJumpRel32 {
            arguments: second_arguments,
            ..
        } = &mut program.functions[1].blocks[0].terminator
        else {
            unreachable!()
        };
        *second_arguments = vec![
            X64Operand::Home(second_parameters[0].home),
            X64Operand::Home(second_parameters[1].home),
        ];
        let cyclic_arguments = vec![
            X64Operand::Home(final_parameters[0].home),
            X64Operand::Home(final_parameters[1].home),
        ];
        let rejected = select_direct_composed_tail_route(
            &program,
            X64FunctionId(1),
            X64LabelId(1),
            &cyclic_arguments,
        )
        .unwrap();
        assert_eq!(
            rejected,
            ComposedTailRoute {
                callee: X64FunctionId(1),
                target_label: X64LabelId(1),
                arguments: cyclic_arguments,
            }
        );
    }

    #[test]
    fn empty_tail_composition_refuses_cycles_and_unbound_homes() {
        let (mut cycle, source_a, source_b) = mixed_tail_composition_program();
        let second_parameters = cycle.functions[1].parameters.clone();
        cycle.functions[1].blocks[0].terminator = X64Terminator::TailJumpRel32 {
            origin: origin(2, 0, X64SourcePosition::Terminator),
            function: X64FunctionId(1),
            target_label: X64LabelId(1),
            arguments: second_parameters
                .iter()
                .map(|parameter| X64Operand::Home(parameter.home))
                .collect(),
        };
        let original_arguments = vec![X64Operand::Home(source_a), X64Operand::Home(source_b)];
        let route =
            compose_empty_tail_route(&cycle, X64FunctionId(1), X64LabelId(1), &original_arguments)
                .unwrap();
        assert_eq!(
            route,
            ComposedTailRoute {
                callee: X64FunctionId(1),
                target_label: X64LabelId(1),
                arguments: original_arguments.clone(),
            }
        );

        let (mut unbound, _, _) = mixed_tail_composition_program();
        let X64Terminator::TailJumpRel32 { arguments, .. } =
            &mut unbound.functions[0].blocks[0].terminator
        else {
            unreachable!()
        };
        arguments[0] = X64Operand::Home(source_a);
        let route = compose_empty_tail_route(
            &unbound,
            X64FunctionId(1),
            X64LabelId(1),
            &original_arguments,
        )
        .unwrap();
        assert_eq!(route.callee, X64FunctionId(1));
        assert_eq!(route.arguments, original_arguments);
    }

    #[test]
    fn tail_substitution_preserves_typed_array_home_as_one_value() {
        let parameter = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 16,
            ty: MachineType::F64Array,
        };
        let source = X64Home {
            slot: X64HomeSlot(1),
            offset: 48,
            width: 16,
            ty: MachineType::F64Array,
        };
        assert_eq!(
            substitute_tail_arguments(
                &[X64Parameter { home: parameter }],
                &[X64Operand::Home(source)],
                &[X64Operand::Home(parameter)],
            ),
            Some(vec![X64Operand::Home(source)])
        );
    }

    #[test]
    fn optimized_layout_error_returns_the_cached_ordinary_encoding() {
        let ordinary = RawEncoding {
            labels: Vec::new(),
            fixups: Vec::new(),
            code: vec![0x90, 0xc3],
            realization: RawRealization::default(),
            prospective_shadow: None,
        };
        let selected = fail_closed_optimized_layout(
            ordinary.clone(),
            Err(RawEncodeError::OptimizationRefused {
                context: "forced test refusal",
            }),
        );
        assert_eq!(selected, ordinary);
    }

    #[test]
    fn unique_compare_predecessor_fuses_after_materialized_ingress() {
        let (program, entry) = compare_predecessor_program(false);
        let plan = EmissionPlan::build(&program, entry).unwrap();

        assert_eq!(plan.consumed, BTreeSet::from([X64LabelId(0)]));
        let chain = plan
            .chains
            .get(&entry)
            .expect("unique compare target must join its predecessor");
        assert!(chain.instructions.is_empty());
        assert_eq!(chain.consumed, vec![X64LabelId(0)]);
        assert!(matches!(chain.exit, PlannedExit::Compare { .. }));
        assert!(plan
            .chains
            .keys()
            .all(|label| !plan.consumed.contains(label)));

        let mut emitter = RawEmitter::new(&program).unwrap();
        assert!(emit_planned_chain(&mut emitter, &program, chain, X64LabelId(99),).unwrap());
        assert_eq!(emitter.fixups.len(), 2);
        assert_eq!(emitter.fixups[0].target, X64LabelId(2));
        assert_eq!(emitter.fixups[1].target, X64LabelId(3));
        assert!(
            emitter
                .code
                .windows(4)
                .any(|bytes| bytes == [0x48, 0x89, 0x84, 0x24]),
            "non-identity ingress must be materialized before compare reuse"
        );
    }

    #[test]
    fn compare_target_with_two_reachable_predecessors_is_not_consumed() {
        let (program, entry) = compare_predecessor_program(true);
        let plan = EmissionPlan::build(&program, entry).unwrap();

        assert!(plan.reachable.contains(&X64LabelId(0)));
        assert!(!plan.consumed.contains(&X64LabelId(0)));
        assert!(plan
            .chains
            .values()
            .all(|chain| !chain.consumed.contains(&X64LabelId(0))));
        assert_eq!(
            plan.shared_join_opportunities,
            vec![RawSharedJoinOpportunity {
                target: X64LabelId(0),
                kind: RawSharedJoinKind::FusedCompare,
                ingresses: vec![
                    RawSharedJoinIngress {
                        root: X64LabelId(11),
                        trigger: X64LabelId(11),
                        frame_accesses: 2,
                    },
                    RawSharedJoinIngress {
                        root: X64LabelId(12),
                        trigger: X64LabelId(12),
                        frame_accesses: 2,
                    },
                ],
            }]
        );
    }

    #[test]
    fn shared_join_requires_every_physical_predecessor_to_be_a_proven_tail() {
        let (mut program, entry) = compare_predecessor_program(true);
        program.functions[2].blocks[2].terminator = X64Terminator::BranchRel32 {
            origin: origin(2, 2, X64SourcePosition::Terminator),
            condition: X64Operand::Immediate {
                ty: MachineType::Bool,
                value: X64Immediate::Bool(true),
            },
            then_label: X64LabelId(0),
            else_label: X64LabelId(0),
        };

        let plan = EmissionPlan::build(&program, entry).unwrap();
        assert!(plan.shared_join_opportunities.is_empty());
        assert!(!plan.consumed.contains(&X64LabelId(0)));
    }

    #[test]
    fn register_result_substitution_is_unique_typed_and_acyclic() {
        let parameter = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::I64,
        };
        let result = X64Home {
            slot: X64HomeSlot(1),
            offset: 40,
            width: 8,
            ty: MachineType::I64,
        };
        let instruction = X64Instruction {
            origin: origin(0, 0, X64SourcePosition::Instruction(0)),
            result,
            kind: X64InstructionKind::I64Wrapping {
                opcode: X64I64Opcode::Add,
                left: X64Operand::Home(parameter),
                right: X64Operand::Immediate {
                    ty: MachineType::I64,
                    value: X64Immediate::I64(1),
                },
            },
        };
        let incoming = vec![EncoderValue::Operand(X64Operand::Immediate {
            ty: MachineType::I64,
            value: X64Immediate::I64(41),
        })];
        let planned = plan_register_instruction(
            &instruction,
            X64LabelId(0),
            &[X64Parameter { home: parameter }],
            &incoming,
            7,
        )
        .expect("a unique typed scalar result must remain in R8");
        assert_eq!(
            planned.result,
            EncoderValue::Gpr {
                generation: 7,
                ty: MachineType::I64,
            }
        );
        let outgoing = substitute_instruction_tail_values(
            &[X64Parameter { home: parameter }],
            &incoming,
            result,
            &planned.result,
            &[X64Operand::Home(result)],
        )
        .unwrap();
        assert_eq!(outgoing, vec![planned.result]);

        let homes = [parameter, result];
        assert_eq!(
            direct_value_schedule(
                &[
                    EncoderValue::Operand(X64Operand::Home(homes[1])),
                    EncoderValue::Operand(X64Operand::Home(homes[0])),
                ],
                &homes.map(|home| X64Parameter { home }),
            ),
            None,
            "a generalized register tail must refuse cyclic copies"
        );
        assert_eq!(
            direct_value_schedule(
                &incoming,
                &[
                    X64Parameter { home: parameter },
                    X64Parameter { home: parameter },
                ],
            ),
            None,
            "overlapping destinations must be rejected before emission"
        );
    }

    #[test]
    fn branchmix_hot_shared_add_preserves_one_gpr_and_one_xmm_generation() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;
        let entry_function = function(program, program.entry).unwrap();
        let entry = thread_noop_tail_target(
            program,
            block(entry_function, entry_function.entry_block)
                .unwrap()
                .label,
        )
        .unwrap();
        let plan = EmissionPlan::build(program, entry).unwrap();
        let target = target_block_for_label(program, X64LabelId(121)).unwrap();

        let opportunity = plan
            .shared_join_opportunities
            .iter()
            .find(|opportunity| opportunity.target == X64LabelId(121))
            .expect("typed cross-bank residency must prove the hot shared add");
        assert_eq!(opportunity.kind, RawSharedJoinKind::RegisterInstruction);
        assert_eq!(
            opportunity
                .ingresses
                .iter()
                .map(|ingress| (ingress.root, ingress.trigger))
                .collect::<Vec<_>>(),
            vec![
                (X64LabelId(106), X64LabelId(107)),
                (X64LabelId(116), X64LabelId(117)),
            ]
        );
        for root in [X64LabelId(106), X64LabelId(116)] {
            let ingress = physical_tail_ingress(program, root, plan.chains.get(&root))
                .unwrap()
                .expect("hot checked-get edge must remain a physical tail");
            assert_eq!(
                thread_noop_tail_target(program, ingress.route.target_label).unwrap(),
                X64LabelId(121)
            );
            let extended = extend_chain_across_shared_join(program, target, &ingress)
                .unwrap()
                .expect("one GPR and one XMM generation must coexist");
            assert_eq!(extended.instructions.len(), 2);
            let PlannedExit::Tail {
                ingress: final_route,
                ..
            } = extended.exit
            else {
                unreachable!()
            };
            assert_eq!(
                final_route
                    .arguments
                    .iter()
                    .filter_map(EncoderValue::register_generation)
                    .map(|(bank, _)| bank)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([EncoderRegisterBank::Gpr, EncoderRegisterBank::Xmm])
            );
        }
    }

    #[test]
    fn branchmix_shared_joins_compose_topologically_without_ambiguous_ownership() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;
        let entry_function = function(program, program.entry).unwrap();
        let entry = thread_noop_tail_target(
            program,
            block(entry_function, entry_function.entry_block)
                .unwrap()
                .label,
        )
        .unwrap();
        let plan = EmissionPlan::build(program, entry).unwrap();
        let replayed_composition = plan_shared_join_composition(
            program,
            entry,
            &plan.reachable,
            &plan.consumed,
            &plan.chains,
            &plan.shared_join_opportunities,
        )
        .expect("BranchMix shared-join composition proof");
        let composition = &plan.shared_join_composition;

        assert_eq!(composition, &replayed_composition.composition);
        assert!(composition.complete);
        assert_eq!(composition.body_replicas, 11);
        assert_eq!(
            composition
                .steps
                .iter()
                .map(|step| step.target.0)
                .collect::<Vec<_>>(),
            vec![49, 92, 93, 121, 48]
        );
        let hot_add = composition
            .steps
            .iter()
            .find(|step| step.target == X64LabelId(121))
            .expect("hot add composition step");
        assert!(hot_add.ancestors.is_empty());
        assert_eq!(hot_add.branch_path, None);
        assert_eq!(
            hot_add
                .ingresses
                .iter()
                .map(|ingress| (ingress.root.0, ingress.authority_trigger.0))
                .collect::<Vec<_>>(),
            vec![(106, 107), (116, 117)]
        );

        let downstream = composition
            .steps
            .iter()
            .find(|step| step.target == X64LabelId(48))
            .expect("downstream compare composition step");
        assert_eq!(downstream.ancestors, vec![X64LabelId(121)]);
        let expected_branch = classify_fused_compare_tail_branch(
            program,
            target_block_for_label(program, downstream.target).unwrap(),
        )
        .unwrap();
        assert_eq!(
            downstream.branch_path,
            Some(RawSharedJoinBranchPath {
                branch_label: expected_branch.branch_label,
                then_label: expected_branch.then_label,
                else_label: expected_branch.else_label,
            })
        );
        assert_eq!(downstream.ingresses.len(), 3);
        assert!(downstream
            .ingresses
            .iter()
            .any(|ingress| ingress.root == X64LabelId(106)));
        assert!(downstream
            .ingresses
            .iter()
            .any(|ingress| ingress.root == X64LabelId(116)));
        assert_eq!(
            downstream
                .ingresses
                .iter()
                .map(|ingress| ingress.authority_trigger)
                .collect::<BTreeSet<_>>()
                .len(),
            downstream.ingresses.len(),
            "each transitive root needs an unambiguous dynamic-count authority"
        );
        let lineage_for = |authority_trigger| {
            downstream
                .ingresses
                .iter()
                .find(|ingress| ingress.authority_trigger == X64LabelId(authority_trigger))
                .unwrap_or_else(|| panic!("missing authority {authority_trigger}"))
                .lineage
                .clone()
        };
        assert_eq!(
            lineage_for(38),
            vec![
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(38),
                    target: X64LabelId(41),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(41),
                    target: X64LabelId(44),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(44),
                    target: X64LabelId(46),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(46),
                    target: X64LabelId(48),
                },
            ]
        );
        assert_eq!(
            lineage_for(107),
            vec![
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(107),
                    target: X64LabelId(108),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(108),
                    target: X64LabelId(109),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(109),
                    target: X64LabelId(119),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(119),
                    target: X64LabelId(120),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(120),
                    target: X64LabelId(121),
                },
                RawSharedJoinLineageEvent::Instruction {
                    label: X64LabelId(121),
                    index: 0,
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(121),
                    target: X64LabelId(122),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(122),
                    target: X64LabelId(123),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(123),
                    target: X64LabelId(44),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(44),
                    target: X64LabelId(46),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(46),
                    target: X64LabelId(48),
                },
            ]
        );
        assert_eq!(
            lineage_for(117),
            vec![
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(117),
                    target: X64LabelId(118),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(118),
                    target: X64LabelId(119),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(119),
                    target: X64LabelId(120),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(120),
                    target: X64LabelId(121),
                },
                RawSharedJoinLineageEvent::Instruction {
                    label: X64LabelId(121),
                    index: 0,
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(121),
                    target: X64LabelId(122),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(122),
                    target: X64LabelId(123),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(123),
                    target: X64LabelId(44),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(44),
                    target: X64LabelId(46),
                },
                RawSharedJoinLineageEvent::Tail {
                    source: X64LabelId(46),
                    target: X64LabelId(48),
                },
            ]
        );
    }

    #[test]
    fn shared_join_lineage_refuses_missing_or_spurious_instruction_ancestors() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;

        let mut work = 0;
        assert!(matches!(
            derive_shared_join_lineage(
                program,
                X64LabelId(107),
                X64LabelId(48),
                &BTreeSet::new(),
                &mut work,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "shared-join lineage undeclared instruction ancestor"
            })
        ));

        let mut work = 0;
        assert!(matches!(
            derive_shared_join_lineage(
                program,
                X64LabelId(107),
                X64LabelId(48),
                &BTreeSet::from([X64LabelId(92), X64LabelId(121)]),
                &mut work,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "shared-join lineage ancestor mismatch"
            })
        ));
    }

    #[test]
    fn shared_join_composition_refuses_cycles_and_caps_without_partial_evidence() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;
        let entry_function = function(program, program.entry).unwrap();
        let entry = thread_noop_tail_target(
            program,
            block(entry_function, entry_function.entry_block)
                .unwrap()
                .label,
        )
        .unwrap();
        let plan = EmissionPlan::build(program, entry).unwrap();

        let mut cyclic = plan.shared_join_opportunities.clone();
        cyclic
            .iter_mut()
            .find(|opportunity| opportunity.target == X64LabelId(121))
            .unwrap()
            .ingresses[0]
            .root = X64LabelId(48);
        assert!(matches!(
            plan_shared_join_composition(
                program,
                entry,
                &plan.reachable,
                &plan.consumed,
                &plan.chains,
                &cyclic,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition dependency cycle"
            })
        ));
        let refused = plan_shared_join_composition(
            program,
            entry,
            &plan.reachable,
            &plan.consumed,
            &plan.chains,
            &cyclic,
        )
        .unwrap_or_default();
        assert!(!refused.composition.complete);
        assert!(refused.composition.steps.is_empty());
        assert_eq!(refused.composition.body_replicas, 0);

        let over_target_cap = (0..=MAX_SHARED_JOIN_COMPOSITION_TARGETS)
            .map(|_| plan.shared_join_opportunities[0].clone())
            .collect::<Vec<_>>();
        assert!(matches!(
            plan_shared_join_composition(
                program,
                entry,
                &plan.reachable,
                &plan.consumed,
                &plan.chains,
                &over_target_cap,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition target cap"
            })
        ));

        let mut work = MAX_SHARED_JOIN_COMPOSITION_WORK;
        assert!(matches!(
            charge_shared_join_composition_work(&mut work, 1),
            Err(RawEncodeError::OptimizationRefused {
                context: "shared-join composition work cap"
            })
        ));
    }

    #[test]
    fn shared_join_generation_check_is_register_bank_precise() {
        let old_gpr = EncoderValue::Gpr {
            generation: 1,
            ty: MachineType::I64,
        };
        let old_xmm = EncoderValue::Xmm { generation: 2 };
        let new_gpr = EncoderValue::Gpr {
            generation: 3,
            ty: MachineType::I64,
        };
        let new_xmm = EncoderValue::Xmm { generation: 4 };
        let before = [old_gpr.clone(), old_xmm.clone()];

        assert!(!retains_overwritten_register_generation(
            &before,
            &[new_gpr.clone(), old_xmm.clone()],
            &new_gpr,
        )
        .unwrap());
        assert!(retains_overwritten_register_generation(
            &before,
            &[old_gpr, old_xmm.clone()],
            &new_gpr,
        )
        .unwrap());
        assert!(
            retains_overwritten_register_generation(&before, &[new_gpr, old_xmm], &new_xmm,)
                .unwrap()
        );
    }

    #[test]
    fn array_results_and_checked_array_targets_remain_in_memory() {
        let array = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 16,
            ty: MachineType::F64Array,
        };
        let f64_result = X64Home {
            slot: X64HomeSlot(1),
            offset: 48,
            width: 8,
            ty: MachineType::F64,
        };
        let array_move = X64Instruction {
            origin: origin(0, 0, X64SourcePosition::Instruction(0)),
            result: array,
            kind: X64InstructionKind::Move(X64Operand::Home(array)),
        };
        let checked_get = X64Instruction {
            origin: origin(0, 0, X64SourcePosition::Instruction(1)),
            result: f64_result,
            kind: X64InstructionKind::ArrayGetF64Checked {
                array: X64Operand::Home(array),
                index: X64Operand::Immediate {
                    ty: MachineType::I64,
                    value: X64Immediate::I64(0),
                },
            },
        };

        assert!(!supports_register_result(&array_move));
        assert!(!supports_register_result(&checked_get));
    }

    #[test]
    fn non_topological_one_instruction_cycle_has_one_chain_owner() {
        let parameter = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::I64,
        };
        let result = X64Home {
            slot: X64HomeSlot(1),
            offset: 40,
            width: 8,
            ty: MachineType::I64,
        };
        let make_function =
            |function: u32, label: u32, next_function: u32, next_label: u32| X64Function {
                id: X64FunctionId(function),
                parameters: vec![X64Parameter { home: parameter }],
                effects: Vec::new(),
                result: MachineType::Unit,
                entry_block: X64BlockId(0),
                blocks: vec![X64Block {
                    id: X64BlockId(0),
                    label: X64LabelId(label),
                    instructions: vec![X64Instruction {
                        origin: origin(function, 0, X64SourcePosition::Instruction(0)),
                        result,
                        kind: X64InstructionKind::Move(X64Operand::Home(parameter)),
                    }],
                    terminator: X64Terminator::TailJumpRel32 {
                        origin: origin(function, 0, X64SourcePosition::Terminator),
                        function: X64FunctionId(next_function),
                        target_label: X64LabelId(next_label),
                        arguments: vec![X64Operand::Home(result)],
                    },
                }],
            };
        let mut program = tail_transfer_program(vec![X64Parameter { home: parameter }]);
        program.entry = X64FunctionId(0);
        program.frame = X64FrameLayout {
            header_bytes: 32,
            home_base: 32,
            max_home_bytes: 16,
            outgoing_base: 48,
            outgoing_bytes: 8,
            frame_bytes: 56,
        };
        // Both vectors deliberately put the target before the entry root.
        program.functions = vec![make_function(1, 5, 0, 20), make_function(0, 20, 1, 5)];
        program.labels = vec![
            X64Label {
                id: X64LabelId(5),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(1),
                    block: X64BlockId(0),
                },
                code_offset: 0,
            },
            X64Label {
                id: X64LabelId(20),
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(0),
                    block: X64BlockId(0),
                },
                code_offset: 0,
            },
        ];

        let plan = EmissionPlan::build(&program, X64LabelId(20)).unwrap();
        assert_eq!(plan.consumed, BTreeSet::from([X64LabelId(5)]));
        assert_eq!(
            plan.chains.keys().copied().collect::<Vec<_>>(),
            vec![X64LabelId(20)]
        );
        assert!(
            plan.chains
                .keys()
                .all(|label| !plan.consumed.contains(label)),
            "a chain root must never later become another chain's body"
        );
    }

    #[test]
    fn optimized_layout_prunes_bodies_with_unique_tombstones_and_live_fixups() {
        let program = one_op_superblock_program();
        let entry = X64LabelId(0);
        let plan = EmissionPlan::build(&program, entry).unwrap();
        assert_eq!(plan.consumed, BTreeSet::from([X64LabelId(1)]));
        assert!(!plan.reachable.contains(&X64LabelId(3)));

        let ordinary = encode_layout(
            &program,
            X64LabelId(4),
            X64LabelId(5),
            X64LabelId(6),
            &program.functions[0],
            entry,
            None,
        )
        .unwrap();
        let optimized = encode_layout(
            &program,
            X64LabelId(4),
            X64LabelId(5),
            X64LabelId(6),
            &program.functions[0],
            entry,
            Some(EmissionLayoutView::accepted(&plan)),
        )
        .unwrap();
        assert!(optimized.code.len() < ordinary.code.len());

        let offsets = optimized
            .labels
            .iter()
            .map(|label| (label.id, label.code_offset))
            .collect::<BTreeMap<_, _>>();
        let unique_offsets = offsets.values().copied().collect::<BTreeSet<_>>();
        assert_eq!(unique_offsets.len(), offsets.len());
        assert_eq!(
            offsets[&X64LabelId(2)] - offsets[&X64LabelId(1)],
            1,
            "the consumed body must retain exactly one NOP tombstone"
        );
        assert_eq!(
            offsets[&X64LabelId(5)] - offsets[&X64LabelId(3)],
            1,
            "the unreachable body must retain exactly one NOP tombstone"
        );
        assert_eq!(optimized.code[offsets[&X64LabelId(1)] as usize], 0x90);
        assert_eq!(optimized.code[offsets[&X64LabelId(3)] as usize], 0x90);

        for fixup in &optimized.fixups {
            assert!(
                !matches!(fixup.target, X64LabelId(1) | X64LabelId(3)),
                "no live edge may target an omitted body"
            );
            let patch = fixup.patch_offset as usize;
            let displacement =
                i32::from_le_bytes(optimized.code[patch..patch + 4].try_into().unwrap());
            let resolved = i64::from(fixup.patch_offset) + 4 + i64::from(displacement);
            assert_eq!(
                resolved,
                i64::from(offsets[&fixup.target]) + i64::from(fixup.addend)
            );
        }
    }

    #[test]
    fn planned_xmm_generations_forward_twice_then_materialize_once() {
        let first_parameter = X64Home {
            slot: X64HomeSlot(0),
            offset: 32,
            width: 8,
            ty: MachineType::F64,
        };
        let first_result = X64Home {
            slot: X64HomeSlot(1),
            offset: 40,
            width: 8,
            ty: MachineType::F64,
        };
        let first = X64Instruction {
            origin: origin(0, 0, X64SourcePosition::Instruction(0)),
            result: first_result,
            kind: X64InstructionKind::Sse2F64 {
                opcode: X64Sse2F64Opcode::AddSd,
                left: X64Operand::Home(first_parameter),
                right: X64Operand::Immediate {
                    ty: MachineType::F64,
                    value: X64Immediate::F64Bits(2.0_f64.to_bits()),
                },
            },
        };
        let incoming = vec![EncoderValue::Operand(X64Operand::Immediate {
            ty: MachineType::F64,
            value: X64Immediate::F64Bits(3.5_f64.to_bits()),
        })];
        let planned_first = plan_register_instruction(
            &first,
            X64LabelId(0),
            &[X64Parameter {
                home: first_parameter,
            }],
            &incoming,
            1,
        )
        .unwrap();
        assert_eq!(planned_first.result, EncoderValue::Xmm { generation: 1 });

        let next_parameters = [
            X64Parameter {
                home: X64Home {
                    slot: X64HomeSlot(2),
                    offset: 48,
                    width: 8,
                    ty: MachineType::F64,
                },
            },
            X64Parameter {
                home: X64Home {
                    slot: X64HomeSlot(3),
                    offset: 56,
                    width: 8,
                    ty: MachineType::F64,
                },
            },
        ];
        let second = X64Instruction {
            origin: origin(1, 0, X64SourcePosition::Instruction(0)),
            result: X64Home {
                slot: X64HomeSlot(4),
                offset: 64,
                width: 8,
                ty: MachineType::F64,
            },
            kind: X64InstructionKind::Sse2F64 {
                opcode: X64Sse2F64Opcode::SubSd,
                left: X64Operand::Home(next_parameters[0].home),
                right: X64Operand::Home(next_parameters[1].home),
            },
        };
        let planned_second = plan_register_instruction(
            &second,
            X64LabelId(1),
            &next_parameters,
            &[planned_first.result.clone(), planned_first.result.clone()],
            2,
        )
        .unwrap();
        assert_eq!(planned_second.result, EncoderValue::Xmm { generation: 2 });

        let destination = X64Home {
            slot: X64HomeSlot(5),
            offset: 72,
            width: 8,
            ty: MachineType::F64,
        };
        let program = tail_transfer_program(vec![X64Parameter { home: destination }]);
        let mut emitter = RawEmitter::new(&program).unwrap();
        emit_planned_instruction(&mut emitter, &program, &planned_first, X64LabelId(99)).unwrap();
        emit_planned_instruction(&mut emitter, &program, &planned_second, X64LabelId(99)).unwrap();
        assert!(emit_value_tail_transfer(
            &mut emitter,
            &program,
            X64FunctionId(0),
            &[planned_second.result],
        )
        .unwrap());
        assert!(emitter
            .code
            .windows(4)
            .any(|bytes| bytes == [0xf2, 0x0f, 0x10, 0xc2]));
        assert!(emitter
            .code
            .windows(4)
            .any(|bytes| bytes == [0xf2, 0x0f, 0x10, 0xca]));
        assert!(
            emitter
                .code
                .windows(5)
                .any(|bytes| bytes == [0xf2, 0x0f, 0x11, 0x94, 0x24]),
            "the final XMM2 value must materialize through the typed tail copy"
        );
    }

    #[test]
    fn ambiguous_unbound_and_result_alias_substitutions_refuse_consumption() {
        let mut program = one_op_superblock_program();
        let duplicate = program.functions[2].parameters[0].home;
        program.functions[1].parameters = vec![
            X64Parameter { home: duplicate },
            X64Parameter { home: duplicate },
        ];
        program.functions[1].blocks[0].instructions[0].kind =
            X64InstructionKind::Move(X64Operand::Home(duplicate));
        let distinct_arguments = vec![
            X64Operand::Immediate {
                ty: MachineType::I64,
                value: X64Immediate::I64(1),
            },
            X64Operand::Immediate {
                ty: MachineType::I64,
                value: X64Immediate::I64(2),
            },
        ];
        let X64Terminator::TailJumpRel32 { arguments, .. } =
            &mut program.functions[0].blocks[0].terminator
        else {
            unreachable!()
        };
        *arguments = distinct_arguments.clone();
        program.frame.outgoing_bytes = 16;
        let plan = EmissionPlan::build(&program, X64LabelId(0)).unwrap();
        assert!(!plan.consumed.contains(&X64LabelId(1)));

        let incoming = [
            EncoderValue::Operand(distinct_arguments[0].clone()),
            EncoderValue::Operand(distinct_arguments[1].clone()),
        ];
        assert_eq!(
            substitute_parameter_value(
                &program.functions[1].parameters,
                &incoming,
                &X64Operand::Home(duplicate),
            ),
            None
        );
        assert_eq!(
            substitute_parameter_value(
                &[X64Parameter { home: duplicate }],
                &incoming[..1],
                &X64Operand::Home(X64Home {
                    slot: X64HomeSlot(99),
                    offset: 40,
                    ..duplicate
                }),
            ),
            None
        );
        let mut aliased = program.functions[1].blocks[0].instructions[0].clone();
        aliased.result = duplicate;
        assert_eq!(
            plan_register_instruction(
                &aliased,
                X64LabelId(0),
                &[X64Parameter { home: duplicate }],
                &incoming[..1],
                1,
            ),
            None
        );
    }

    #[test]
    fn non_emittable_planned_chain_falls_back_to_the_complete_ordinary_blob() {
        let program = one_op_superblock_program();
        let entry = X64LabelId(0);
        let ordinary = encode_layout(
            &program,
            X64LabelId(4),
            X64LabelId(5),
            X64LabelId(6),
            &program.functions[0],
            entry,
            None,
        )
        .unwrap();
        let mut plan = EmissionPlan::build(&program, entry).unwrap();
        let chain = plan.chains.get_mut(&entry).unwrap();
        let PlannedExit::Tail {
            ingress,
            trigger_label,
        } = chain.exit.clone()
        else {
            unreachable!()
        };
        chain.exit = PlannedExit::Compare {
            ingress,
            target_label: X64LabelId(2),
            trigger_label,
        };
        let optimized = encode_layout(
            &program,
            X64LabelId(4),
            X64LabelId(5),
            X64LabelId(6),
            &program.functions[0],
            entry,
            Some(EmissionLayoutView::accepted(&plan)),
        );
        assert!(matches!(
            optimized,
            Err(RawEncodeError::OptimizationRefused {
                context: "planned superblock emission"
            })
        ));
        assert_eq!(
            fail_closed_optimized_layout(ordinary.clone(), optimized),
            ordinary
        );
    }

    #[test]
    fn branchmix_prospective_realization_preserves_policy_1_4_selected_output() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;
        let entry_adapter = unique_owner_label(program, X64LabelOwner::EntryAdapter).unwrap();
        let return_epilogue = unique_owner_label(program, X64LabelOwner::ReturnEpilogue).unwrap();
        let bounds_epilogue = unique_owner_label(program, X64LabelOwner::BoundsEpilogue).unwrap();
        let entry_function = function(program, program.entry).unwrap();
        let entry_block = block(entry_function, entry_function.entry_block).unwrap();
        let threaded_entry = thread_noop_tail_target(program, entry_block.label).unwrap();
        let planning =
            EmissionPlan::build_with_prospective(program, threaded_entry).expect("single planner");
        let selected_policy_1_4 = encode_layout(
            program,
            entry_adapter,
            return_epilogue,
            bounds_epilogue,
            entry_function,
            threaded_entry,
            Some(EmissionLayoutView::accepted(&planning.emission)),
        )
        .expect("accepted policy-1.4 encoding");

        let encoded = encode(program).expect("policy-1.4 output plus shadow evidence");
        assert_eq!(encoded.code, selected_policy_1_4.code);
        assert_eq!(encoded.labels, selected_policy_1_4.labels);
        assert_eq!(encoded.fixups, selected_policy_1_4.fixups);
        assert!(
            encoded
                .realization
                .prospective_shared_join_realization
                .complete
        );
        assert!(encoded.prospective_shadow.is_some());
        assert!(selected_policy_1_4.prospective_shadow.is_none());
    }

    #[test]
    fn branchmix_prospective_realization_has_exact_authority_and_receipts() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;
        let encoded = encode(program).expect("BranchMix prospective realization");
        let evidence = &encoded.realization.prospective_shared_join_realization;
        assert!(evidence.complete);
        assert_eq!(evidence.body_replicas, 11);
        assert_eq!(evidence.shared_join_authority_atoms, 31);

        let mut replica_atoms = BTreeMap::<(u32, u32, u32), Vec<_>>::new();
        for atom in &evidence.atoms {
            match atom.execution_authority {
                RawProspectiveExecutionAuthority::SemanticEvent(event) => {
                    assert_eq!(event, atom.semantic_event);
                    assert_ne!(event, RawExecutionEvent::Static);
                }
                RawProspectiveExecutionAuthority::Static => {
                    assert_eq!(atom.semantic_event, RawExecutionEvent::Static);
                    assert_eq!(atom.class, RawTemplateClass::Tombstone);
                }
                RawProspectiveExecutionAuthority::SharedJoin {
                    target,
                    root,
                    authority_trigger,
                    partition,
                } => {
                    replica_atoms
                        .entry((target.0, root.0, authority_trigger.0))
                        .or_default()
                        .push((atom.semantic_event, atom.class, partition));
                }
            }
        }
        assert_eq!(
            replica_atoms.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                (48, 29, 38),
                (48, 106, 107),
                (48, 116, 117),
                (49, 30, 39),
                (49, 31, 40),
                (92, 78, 82),
                (92, 86, 86),
                (93, 79, 83),
                (93, 87, 87),
                (121, 106, 107),
                (121, 116, 117),
            ])
        );
        for ((target, _, _), atoms) in &replica_atoms {
            let expected = if *target == 121 { 2 } else { 3 };
            assert_eq!(atoms.len(), expected);
        }
        let target_49_atoms = vec![
            (
                RawExecutionEvent::Instruction {
                    label: X64LabelId(49),
                    index: 0,
                },
                RawTemplateClass::FusedCompareInstruction,
                RawProspectiveSharedJoinPartition::All,
            ),
            (
                RawExecutionEvent::Branch {
                    label: X64LabelId(53),
                },
                RawTemplateClass::BranchCondition,
                RawProspectiveSharedJoinPartition::All,
            ),
            (
                RawExecutionEvent::BranchElse {
                    label: X64LabelId(53),
                },
                RawTemplateClass::BranchElseJump,
                RawProspectiveSharedJoinPartition::Else,
            ),
        ];
        assert_eq!(replica_atoms[&(49, 30, 39)], target_49_atoms);
        assert_eq!(replica_atoms[&(49, 31, 40)], target_49_atoms);

        let mut cursor = 0_u32;
        for atom in &evidence.atoms {
            assert_eq!(atom.start, cursor);
            assert!(atom.end > atom.start);
            cursor = atom.end;
        }
        assert_eq!(u64::from(cursor), evidence.candidate_code_bytes);

        let disposition_by_label = evidence
            .labels
            .iter()
            .map(|receipt| (receipt.label, receipt.disposition))
            .collect::<BTreeMap<_, _>>();
        let shared_tombstones = evidence
            .labels
            .iter()
            .filter_map(|receipt| {
                (receipt.disposition == RawProspectiveLabelDisposition::SharedJoinTombstone)
                    .then_some(receipt.label.0)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(shared_tombstones, BTreeSet::from([48, 49, 92, 93, 121]));
        for receipt in &evidence.labels {
            let atom = &evidence.atoms[receipt.owning_atom as usize];
            assert_eq!(receipt.code_offset, atom.start);
            assert_eq!(receipt.label, atom.physical_owner);
            if receipt.disposition == RawProspectiveLabelDisposition::Live {
                assert_ne!(atom.class, RawTemplateClass::Tombstone);
            } else {
                assert_eq!(atom.class, RawTemplateClass::Tombstone);
                assert_eq!(atom.end - atom.start, 1);
            }
        }
        for (index, receipt) in evidence.fixups.iter().enumerate() {
            assert_eq!(receipt.fixup_index as usize, index);
            let atom = &evidence.atoms[receipt.owning_atom as usize];
            assert!(receipt.patch_offset >= atom.start);
            assert!(receipt.patch_offset.checked_add(4).unwrap() <= atom.end);
            assert_eq!(
                disposition_by_label.get(&receipt.target),
                Some(&RawProspectiveLabelDisposition::Live)
            );
        }
    }

    #[test]
    fn branchmix_prospective_realization_is_deterministic() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;
        let first = encode(program).expect("first prospective build");
        let second = encode(program).expect("second prospective build");
        let first_evidence = &first.realization.prospective_shared_join_realization;
        let second_evidence = &second.realization.prospective_shared_join_realization;
        assert!(first_evidence.complete);
        assert_eq!(first_evidence, second_evidence);
        assert_eq!(first_evidence.baseline_code_hash, program.code_hash);
        assert_ne!(
            first_evidence.candidate_code_hash,
            first_evidence.baseline_code_hash
        );
        assert_eq!(
            first_evidence.candidate_code_hash.to_hex(),
            "0e392caf51dbc65f9e36e08c678118e78b8f6aed90bf1df0edbf4b5c6a5f5173"
        );
    }

    #[test]
    fn prospective_receipts_refuse_wrong_class_spurious_event_and_bad_fixup() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;
        let entry_function = function(program, program.entry).unwrap();
        let entry = thread_noop_tail_target(
            program,
            block(entry_function, entry_function.entry_block)
                .unwrap()
                .label,
        )
        .unwrap();
        let planning =
            EmissionPlan::build_with_prospective(program, entry).expect("single planner");
        let encoded = encode(program).expect("BranchMix prospective realization");
        let evidence = &encoded.realization.prospective_shared_join_realization;
        let shadow = encoded
            .prospective_shadow
            .as_ref()
            .expect("complete transient shadow");
        let labels_by_offset = shadow
            .labels
            .iter()
            .map(|label| (label.code_offset, label.id))
            .collect::<BTreeMap<_, _>>();
        let baseline_labels_by_offset = encoded
            .labels
            .iter()
            .map(|label| (label.code_offset, label.id))
            .collect::<BTreeMap<_, _>>();
        let dispositions = evidence
            .labels
            .iter()
            .map(|receipt| (receipt.label, receipt.disposition))
            .collect::<BTreeMap<_, _>>();
        let no_fixup_tail_edges =
            prospective_no_fixup_tail_edges(&planning.prospective).expect("planned compare edges");

        let shared_tombstone = evidence
            .labels
            .iter()
            .find(|receipt| receipt.label == X64LabelId(48))
            .expect("shared target tombstone");
        let mut wrong_tombstone_byte = shadow.code.clone();
        wrong_tombstone_byte[shared_tombstone.code_offset as usize] = 0xcc;
        assert!(matches!(
            prospective_label_receipts(
                program,
                &planning.emission,
                &planning.prospective,
                &shadow.labels,
                &wrong_tombstone_byte,
                &shadow.atoms,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective tombstone byte mismatch"
            })
        ));

        let mut wrong_label_order = shadow.labels.clone();
        let first_offset = wrong_label_order[0].code_offset;
        wrong_label_order[0].code_offset = wrong_label_order[1].code_offset;
        wrong_label_order[1].code_offset = first_offset;
        assert!(matches!(
            prospective_label_receipts(
                program,
                &planning.emission,
                &planning.prospective,
                &wrong_label_order,
                &shadow.code,
                &shadow.atoms,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective non-canonical label order"
            })
        ));

        let shared_instruction = evidence
            .atoms
            .iter()
            .position(|atom| {
                matches!(
                    atom.execution_authority,
                    RawProspectiveExecutionAuthority::SharedJoin {
                        target: X64LabelId(121),
                        root: X64LabelId(106),
                        ..
                    }
                ) && matches!(atom.semantic_event, RawExecutionEvent::Instruction { .. })
            })
            .expect("shared register instruction");
        let mut wrong_class = shadow.atoms.clone();
        wrong_class[shared_instruction].class = RawTemplateClass::OrdinaryInstruction;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &wrong_class,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective shared-join atom template class"
            })
        ));

        let mut unexplained_removal = shadow.atoms.clone();
        let removed = unexplained_removal
            .iter()
            .position(|atom| atom.event == RawExecutionEvent::BoundsEpilogue)
            .expect("nonselected semantic atom");
        unexplained_removal.remove(removed);
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &unexplained_removal,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective unexplained semantic atom removal"
            })
        ));

        let mut retained_eliminable_tail = shadow.atoms.clone();
        let tombstone_atom = usize::try_from(shared_tombstone.owning_atom).unwrap();
        retained_eliminable_tail[tombstone_atom].event = RawExecutionEvent::Tail {
            label: X64LabelId(107),
        };
        retained_eliminable_tail[tombstone_atom].class = RawTemplateClass::TailTransfer;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &retained_eliminable_tail,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective spurious ordinary semantic atom"
            })
        ));

        let mut wrong_semantic_class = shadow.atoms.clone();
        wrong_semantic_class[0].class = RawTemplateClass::TailTransfer;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &wrong_semantic_class,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective semantic atom template class"
            })
        ));

        let mut duplicate_semantic = shadow.atoms.clone();
        duplicate_semantic[1].event = RawExecutionEvent::Entry;
        duplicate_semantic[1].class = RawTemplateClass::EntryPrologue;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &duplicate_semantic,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective duplicate ordinary semantic atom"
            })
        ));

        let mut static_at_live_label = shadow.atoms.clone();
        static_at_live_label[0].event = RawExecutionEvent::Static;
        static_at_live_label[0].class = RawTemplateClass::Tombstone;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &static_at_live_label,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective static atom lacks tombstone label"
            })
        ));

        let mut spurious = shadow.atoms.clone();
        spurious[0].event = RawExecutionEvent::Instruction {
            label: X64LabelId(121),
            index: 0,
        };
        spurious[0].class = RawTemplateClass::RegisterInstruction;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &spurious,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective spurious shared-join semantic event"
            })
        ));

        let branch = evidence
            .atoms
            .iter()
            .position(|atom| {
                atom.physical_owner == X64LabelId(30)
                    && atom.semantic_event
                        == RawExecutionEvent::Branch {
                            label: X64LabelId(53),
                        }
            })
            .expect("target49 branch atom");
        let branch_else = branch + 1;
        let mut reordered = shadow.atoms.clone();
        let branch_event = reordered[branch].event;
        let branch_class = reordered[branch].class;
        reordered[branch].event = reordered[branch_else].event;
        reordered[branch].class = reordered[branch_else].class;
        reordered[branch_else].event = branch_event;
        reordered[branch_else].class = branch_class;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &reordered,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective shared-join atom order"
            })
        ));

        let tail_38 = evidence
            .atoms
            .iter()
            .position(|atom| {
                atom.execution_authority
                    == RawProspectiveExecutionAuthority::SemanticEvent(RawExecutionEvent::Tail {
                        label: X64LabelId(38),
                    })
            })
            .expect("ordinary tail 38");
        let tail_39 = evidence
            .atoms
            .iter()
            .position(|atom| {
                atom.execution_authority
                    == RawProspectiveExecutionAuthority::SemanticEvent(RawExecutionEvent::Tail {
                        label: X64LabelId(39),
                    })
            })
            .expect("ordinary tail 39");
        assert_ne!(
            evidence.atoms[tail_38].physical_owner,
            evidence.atoms[tail_39].physical_owner
        );
        let mut wrong_physical_owner = shadow.atoms.clone();
        let tail_38_event = wrong_physical_owner[tail_38].event;
        wrong_physical_owner[tail_38].event = wrong_physical_owner[tail_39].event;
        wrong_physical_owner[tail_39].event = tail_38_event;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &wrong_physical_owner,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective ordinary atom order"
            })
        ));

        let (ordinary_first, ordinary_second) = evidence
            .atoms
            .iter()
            .enumerate()
            .filter(|(_, atom)| {
                matches!(
                    atom.execution_authority,
                    RawProspectiveExecutionAuthority::SemanticEvent(_)
                )
            })
            .collect::<Vec<_>>()
            .windows(2)
            .find_map(|pair| {
                (pair[0].1.physical_owner == pair[1].1.physical_owner)
                    .then_some((pair[0].0, pair[1].0))
            })
            .expect("two ordinary atoms in one physical owner");
        let mut wrong_owner_order = shadow.atoms.clone();
        let first_row = (
            wrong_owner_order[ordinary_first].event,
            wrong_owner_order[ordinary_first].class,
        );
        wrong_owner_order[ordinary_first].event = wrong_owner_order[ordinary_second].event;
        wrong_owner_order[ordinary_first].class = wrong_owner_order[ordinary_second].class;
        wrong_owner_order[ordinary_second].event = first_row.0;
        wrong_owner_order[ordinary_second].class = first_row.1;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &wrong_owner_order,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective ordinary atom order"
            })
        ));

        let shared_after_tail_38 = tail_38 + 1;
        assert!(matches!(
            evidence.atoms[shared_after_tail_38].execution_authority,
            RawProspectiveExecutionAuthority::SharedJoin { .. }
        ));
        let mut shared_before_ordinary = shadow.atoms.clone();
        let ordinary_row = (
            shared_before_ordinary[tail_38].event,
            shared_before_ordinary[tail_38].class,
        );
        shared_before_ordinary[tail_38].event = shared_before_ordinary[shared_after_tail_38].event;
        shared_before_ordinary[tail_38].class = shared_before_ordinary[shared_after_tail_38].class;
        shared_before_ordinary[shared_after_tail_38].event = ordinary_row.0;
        shared_before_ordinary[shared_after_tail_38].class = ordinary_row.1;
        assert!(matches!(
            prospective_atom_receipts(
                &planning.emission,
                &encoded.realization.atoms,
                &baseline_labels_by_offset,
                &shared_before_ordinary,
                &labels_by_offset,
                &dispositions,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective shared-join suffix placement"
            })
        ));

        let mut tombstone_target = shadow.fixups.clone();
        tombstone_target[0].target = X64LabelId(48);
        assert!(matches!(
            prospective_fixup_receipts(
                program,
                &shadow.labels,
                &tombstone_target,
                &shadow.code,
                &evidence.atoms,
                &dispositions,
                &no_fixup_tail_edges,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective live fixup targets tombstone"
            })
        ));

        let mut tombstone_owner = shadow.fixups.clone();
        tombstone_owner[0].patch_offset = shared_tombstone.code_offset;
        assert!(matches!(
            prospective_fixup_receipts(
                program,
                &shadow.labels,
                &tombstone_owner,
                &shadow.code,
                &evidence.atoms,
                &dispositions,
                &no_fixup_tail_edges,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective tombstone owns live fixup"
            })
        ));

        let mut wrong_displacement = shadow.code.clone();
        let patch = shadow.fixups[0].patch_offset as usize;
        wrong_displacement[patch] ^= 1;
        assert!(matches!(
            prospective_fixup_receipts(
                program,
                &shadow.labels,
                &shadow.fixups,
                &wrong_displacement,
                &evidence.atoms,
                &dispositions,
                &no_fixup_tail_edges,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup displacement mismatch"
            })
        ));

        let mut nonzero_addend = shadow.fixups.clone();
        nonzero_addend[0].addend = 1;
        assert!(matches!(
            prospective_fixup_receipts(
                program,
                &shadow.labels,
                &nonzero_addend,
                &shadow.code,
                &evidence.atoms,
                &dispositions,
                &no_fixup_tail_edges,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup nonzero addend"
            })
        ));

        let mut wrong_live_target = shadow.fixups.clone();
        wrong_live_target[0].target = X64LabelId(29);
        assert!(matches!(
            prospective_fixup_receipts(
                program,
                &shadow.labels,
                &wrong_live_target,
                &shadow.code,
                &evidence.atoms,
                &dispositions,
                &no_fixup_tail_edges,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup semantic target"
            })
        ));

        let mut wrong_opcode = shadow.code.clone();
        let opcode = usize::try_from(shadow.fixups[0].patch_offset).unwrap() - 1;
        wrong_opcode[opcode] = 0x90;
        assert!(matches!(
            prospective_fixup_receipts(
                program,
                &shadow.labels,
                &shadow.fixups,
                &wrong_opcode,
                &evidence.atoms,
                &dispositions,
                &no_fixup_tail_edges,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup opcode site"
            })
        ));

        let mut missing_fixup = shadow.fixups.clone();
        missing_fixup.remove(0);
        assert!(matches!(
            prospective_fixup_receipts(
                program,
                &shadow.labels,
                &missing_fixup,
                &shadow.code,
                &evidence.atoms,
                &dispositions,
                &no_fixup_tail_edges,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective fixup atom cardinality"
            })
        ));

        let label_starts = shadow
            .labels
            .iter()
            .map(|label| label.code_offset)
            .collect::<BTreeSet<_>>();
        let no_fixup_tail = evidence
            .atoms
            .windows(2)
            .position(|pair| {
                matches!(pair[0].semantic_event, RawExecutionEvent::Tail { .. })
                    && pair[0].class == RawTemplateClass::TailTransfer
                    && pair[1].start == pair[0].end
                    && pair[1].physical_owner == pair[0].physical_owner
                    && pair[1].class == RawTemplateClass::FusedCompareInstruction
                    && !label_starts.contains(&pair[1].start)
            })
            .expect("composed no-fixup tail edge");
        let mut wrong_no_fixup_tail_edge = evidence.atoms.clone();
        wrong_no_fixup_tail_edge[no_fixup_tail].semantic_event = RawExecutionEvent::Tail {
            label: X64LabelId(u32::MAX),
        };
        assert!(matches!(
            prospective_fixup_receipts(
                program,
                &shadow.labels,
                &shadow.fixups,
                &shadow.code,
                &wrong_no_fixup_tail_edge,
                &dispositions,
                &no_fixup_tail_edges,
            ),
            Err(RawEncodeError::OptimizationRefused {
                context: "prospective no-fixup tail edge"
            })
        ));
    }

    #[test]
    fn prospective_cap_failure_erases_evidence_and_preserves_baseline() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix target");
        let program = &package.target().program;
        let entry_adapter = unique_owner_label(program, X64LabelOwner::EntryAdapter).unwrap();
        let return_epilogue = unique_owner_label(program, X64LabelOwner::ReturnEpilogue).unwrap();
        let bounds_epilogue = unique_owner_label(program, X64LabelOwner::BoundsEpilogue).unwrap();
        let entry_function = function(program, program.entry).unwrap();
        let entry_block = block(entry_function, entry_function.entry_block).unwrap();
        let threaded_entry = thread_noop_tail_target(program, entry_block.label).unwrap();
        let planning =
            EmissionPlan::build_with_prospective(program, threaded_entry).expect("single planner");
        let baseline = encode_layout(
            program,
            entry_adapter,
            return_epilogue,
            bounds_epilogue,
            entry_function,
            threaded_entry,
            Some(EmissionLayoutView::accepted(&planning.emission)),
        )
        .expect("accepted baseline");
        let frozen_baseline = baseline.clone();
        let refused = shadow_shared_join_realization(
            ProspectiveShadowEncodingContext {
                program,
                entry_adapter,
                return_epilogue,
                bounds_epilogue,
                entry_function,
                threaded_entry,
            },
            &planning.emission,
            &planning.prospective,
            &baseline,
            ProspectiveRealizationLimits {
                max_body_replicas: 10,
                ..ProspectiveRealizationLimits::production()
            },
        );
        let mut selected = baseline.clone();
        attach_prospective_shared_join_realization(&mut selected, refused);
        assert_eq!(
            selected.realization.prospective_shared_join_realization,
            RawProspectiveSharedJoinRealization::default()
        );
        assert!(selected.prospective_shadow.is_none());
        assert_eq!(selected.code, frozen_baseline.code);
        assert_eq!(selected.labels, frozen_baseline.labels);
        assert_eq!(selected.fixups, frozen_baseline.fixups);
        assert_eq!(baseline, frozen_baseline);
    }
}
