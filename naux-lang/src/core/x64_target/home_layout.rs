//! Canonical stack-home layout policies for the x86-64 target.
//!
//! The input model deliberately contains only the information required by a
//! layout policy.  It does not retain Machine IR control flow or operands, so
//! future policies can inspect tail-transfer topology without acquiring
//! authority to change program semantics.

use super::{MachineType, X64FrameLayout, X64Home, X64HomeSlot};
use std::fmt;

const TARGET_WORD_BYTES: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CanonicalHomeLayoutPolicy {
    DefinitionOrderV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CanonicalHomeLayoutLimits {
    pub header_bytes: u32,
    pub outgoing_alignment: u32,
    pub frame_alignment: u32,
    pub max_frame_bytes: u32,
    pub max_outgoing_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CanonicalHomeProgram {
    pub functions: Vec<CanonicalHomeFunction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CanonicalHomeFunction {
    /// Parameters first, followed by instruction results, all in canonical
    /// definition order.
    pub value_types: Vec<MachineType>,
    pub parameter_count: u32,
    pub tails: Vec<CanonicalHomeTail>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CanonicalHomeTail {
    /// Canonical source block position.  DefinitionOrderV1 preserves this
    /// metadata but does not use control-flow topology to overlay homes.
    pub block: u32,
    pub callee: u32,
    pub arguments: Vec<CanonicalHomeArgument>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CanonicalHomeArgument {
    Immediate(MachineType),
    Slot { slot: u32, ty: MachineType },
}

impl CanonicalHomeArgument {
    fn ty(self) -> MachineType {
        match self {
            Self::Immediate(ty) | Self::Slot { ty, .. } => ty,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CanonicalHomeLayout {
    pub homes: Vec<Vec<X64Home>>,
    pub frame: X64FrameLayout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CanonicalHomeLayoutError {
    ParameterCountExceedsValues {
        function: u64,
        parameter_count: u32,
        value_count: u64,
    },
    StructuralLimit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    InvalidAlignment {
        field: &'static str,
        value: u32,
    },
    MisalignedHeader {
        header_bytes: u32,
    },
}

impl fmt::Display for CanonicalHomeLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParameterCountExceedsValues {
                function,
                parameter_count,
                value_count,
            } => write!(
                formatter,
                "canonical home function {function} declares {parameter_count} parameters \
                 but only {value_count} values"
            ),
            Self::StructuralLimit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "canonical home layout {field} usage {actual} exceeds hard limit {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(
                    formatter,
                    "canonical home layout {field} accounting overflow"
                )
            }
            Self::InvalidAlignment { field, value } => write!(
                formatter,
                "canonical home layout {field} alignment {value} is not a nonzero power of two"
            ),
            Self::MisalignedHeader { header_bytes } => write!(
                formatter,
                "canonical home layout header size {header_bytes} is not aligned to \
                 {TARGET_WORD_BYTES} bytes"
            ),
        }
    }
}

impl std::error::Error for CanonicalHomeLayoutError {}

pub(super) fn allocate_canonical_home_layout(
    program: &CanonicalHomeProgram,
    policy: CanonicalHomeLayoutPolicy,
    limits: CanonicalHomeLayoutLimits,
) -> Result<CanonicalHomeLayout, CanonicalHomeLayoutError> {
    validate_limits(limits)?;
    match policy {
        CanonicalHomeLayoutPolicy::DefinitionOrderV1 => {
            allocate_definition_order_v1(program, limits)
        }
    }
}

fn allocate_definition_order_v1(
    program: &CanonicalHomeProgram,
    limits: CanonicalHomeLayoutLimits,
) -> Result<CanonicalHomeLayout, CanonicalHomeLayoutError> {
    let mut all_homes = Vec::with_capacity(program.functions.len());
    let mut max_home_bytes = 0_u32;
    let mut max_outgoing_bytes = 0_u32;

    for (function_index, function) in program.functions.iter().enumerate() {
        let function_index = u64::try_from(function_index).map_err(|_| {
            CanonicalHomeLayoutError::StructuralLimit {
                field: "function count",
                limit: u64::MAX,
                actual: u64::MAX,
            }
        })?;
        let value_count = u64::try_from(function.value_types.len()).map_err(|_| {
            CanonicalHomeLayoutError::StructuralLimit {
                field: "function value count",
                limit: u64::MAX,
                actual: u64::MAX,
            }
        })?;
        if u64::from(function.parameter_count) > value_count {
            return Err(CanonicalHomeLayoutError::ParameterCountExceedsValues {
                function: function_index,
                parameter_count: function.parameter_count,
                value_count,
            });
        }

        let mut homes = Vec::with_capacity(function.value_types.len());
        let mut next_offset = limits.header_bytes;
        for (slot, ty) in function.value_types.iter().copied().enumerate() {
            let slot =
                u32::try_from(slot).map_err(|_| CanonicalHomeLayoutError::StructuralLimit {
                    field: "home slots",
                    limit: u64::from(u32::MAX) + 1,
                    actual: value_count,
                })?;
            let width = target_width(ty);
            homes.push(X64Home {
                slot: X64HomeSlot(slot),
                offset: next_offset,
                width: width as u8,
                ty,
            });
            next_offset = next_offset.checked_add(width).ok_or(
                CanonicalHomeLayoutError::ArithmeticOverflow {
                    field: "function home extent",
                },
            )?;
        }
        let home_bytes = next_offset.checked_sub(limits.header_bytes).ok_or(
            CanonicalHomeLayoutError::ArithmeticOverflow {
                field: "function home extent",
            },
        )?;
        max_home_bytes = max_home_bytes.max(home_bytes);

        for tail in &function.tails {
            // DefinitionOrderV1 intentionally ignores topology.  Reading the
            // identity fields here makes that policy boundary explicit.
            let _tail_identity = (tail.block, tail.callee);
            let mut extent = 0_u32;
            for argument in &tail.arguments {
                if let CanonicalHomeArgument::Slot { slot, .. } = argument {
                    // Slot validity belongs to the source builder/verifier.
                    let _source_slot = slot;
                }
                extent = extent.checked_add(target_width(argument.ty())).ok_or(
                    CanonicalHomeLayoutError::ArithmeticOverflow {
                        field: "outgoing argument extent",
                    },
                )?;
            }
            max_outgoing_bytes = max_outgoing_bytes.max(extent);
        }
        all_homes.push(homes);
    }

    if max_outgoing_bytes > limits.max_outgoing_bytes {
        return Err(CanonicalHomeLayoutError::StructuralLimit {
            field: "outgoing argument bytes",
            limit: u64::from(limits.max_outgoing_bytes),
            actual: u64::from(max_outgoing_bytes),
        });
    }

    let home_end = limits.header_bytes.checked_add(max_home_bytes).ok_or(
        CanonicalHomeLayoutError::ArithmeticOverflow {
            field: "outgoing base",
        },
    )?;
    let outgoing_base = align_up(home_end, limits.outgoing_alignment, "outgoing base")?;
    let frame_end = outgoing_base.checked_add(max_outgoing_bytes).ok_or(
        CanonicalHomeLayoutError::ArithmeticOverflow {
            field: "frame extent",
        },
    )?;
    let frame_bytes = align_up(frame_end, limits.frame_alignment, "frame extent")?;

    if frame_bytes > limits.max_frame_bytes {
        return Err(CanonicalHomeLayoutError::StructuralLimit {
            field: "frame bytes",
            limit: u64::from(limits.max_frame_bytes),
            actual: u64::from(frame_bytes),
        });
    }

    Ok(CanonicalHomeLayout {
        homes: all_homes,
        frame: X64FrameLayout {
            header_bytes: limits.header_bytes,
            home_base: limits.header_bytes,
            max_home_bytes,
            outgoing_base,
            outgoing_bytes: max_outgoing_bytes,
            frame_bytes,
        },
    })
}

fn validate_limits(limits: CanonicalHomeLayoutLimits) -> Result<(), CanonicalHomeLayoutError> {
    for (field, alignment) in [
        ("outgoing", limits.outgoing_alignment),
        ("frame", limits.frame_alignment),
    ] {
        if !alignment.is_power_of_two() {
            return Err(CanonicalHomeLayoutError::InvalidAlignment {
                field,
                value: alignment,
            });
        }
    }
    if !limits.header_bytes.is_multiple_of(TARGET_WORD_BYTES) {
        return Err(CanonicalHomeLayoutError::MisalignedHeader {
            header_bytes: limits.header_bytes,
        });
    }
    Ok(())
}

fn align_up(
    value: u32,
    alignment: u32,
    field: &'static str,
) -> Result<u32, CanonicalHomeLayoutError> {
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(CanonicalHomeLayoutError::ArithmeticOverflow { field })
}

fn target_width(ty: MachineType) -> u32 {
    match ty {
        MachineType::F64Array => 16,
        MachineType::Unit | MachineType::Bool | MachineType::I64 | MachineType::F64 => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_LIMITS: CanonicalHomeLayoutLimits = CanonicalHomeLayoutLimits {
        header_bytes: 32,
        outgoing_alignment: 8,
        frame_alignment: 16,
        max_frame_bytes: 4_096,
        max_outgoing_bytes: 4_096,
    };

    fn function(
        value_types: Vec<MachineType>,
        parameter_count: u32,
        tails: Vec<CanonicalHomeTail>,
    ) -> CanonicalHomeFunction {
        CanonicalHomeFunction {
            value_types,
            parameter_count,
            tails,
        }
    }

    fn tail(arguments: Vec<CanonicalHomeArgument>) -> CanonicalHomeTail {
        CanonicalHomeTail {
            block: 0,
            callee: 0,
            arguments,
        }
    }

    fn allocate(
        functions: Vec<CanonicalHomeFunction>,
        limits: CanonicalHomeLayoutLimits,
    ) -> Result<CanonicalHomeLayout, CanonicalHomeLayoutError> {
        allocate_canonical_home_layout(
            &CanonicalHomeProgram { functions },
            CanonicalHomeLayoutPolicy::DefinitionOrderV1,
            limits,
        )
    }

    #[test]
    fn definition_order_is_dense_and_preserves_mixed_widths() {
        let layout = allocate(
            vec![
                function(
                    vec![
                        MachineType::Unit,
                        MachineType::Bool,
                        MachineType::I64,
                        MachineType::F64,
                        MachineType::F64Array,
                    ],
                    2,
                    Vec::new(),
                ),
                function(vec![MachineType::F64], 1, Vec::new()),
            ],
            CURRENT_LIMITS,
        )
        .expect("mixed-width layout must succeed");

        assert_eq!(
            layout.homes[0],
            vec![
                X64Home {
                    slot: X64HomeSlot(0),
                    offset: 32,
                    width: 8,
                    ty: MachineType::Unit,
                },
                X64Home {
                    slot: X64HomeSlot(1),
                    offset: 40,
                    width: 8,
                    ty: MachineType::Bool,
                },
                X64Home {
                    slot: X64HomeSlot(2),
                    offset: 48,
                    width: 8,
                    ty: MachineType::I64,
                },
                X64Home {
                    slot: X64HomeSlot(3),
                    offset: 56,
                    width: 8,
                    ty: MachineType::F64,
                },
                X64Home {
                    slot: X64HomeSlot(4),
                    offset: 64,
                    width: 16,
                    ty: MachineType::F64Array,
                },
            ]
        );
        assert_eq!(layout.homes[1][0].offset, 32);
        assert_eq!(
            layout.frame,
            X64FrameLayout {
                header_bytes: 32,
                home_base: 32,
                max_home_bytes: 48,
                outgoing_base: 80,
                outgoing_bytes: 0,
                frame_bytes: 80,
            }
        );
    }

    #[test]
    fn outgoing_area_uses_largest_tail_and_declared_argument_widths() {
        let layout = allocate(
            vec![function(
                vec![MachineType::F64Array, MachineType::I64],
                1,
                vec![
                    tail(vec![CanonicalHomeArgument::Immediate(MachineType::I64)]),
                    CanonicalHomeTail {
                        block: 7,
                        callee: 99,
                        arguments: vec![
                            CanonicalHomeArgument::Slot {
                                slot: 200,
                                ty: MachineType::F64Array,
                            },
                            CanonicalHomeArgument::Immediate(MachineType::Bool),
                            CanonicalHomeArgument::Slot {
                                slot: 201,
                                ty: MachineType::F64,
                            },
                        ],
                    },
                ],
            )],
            CURRENT_LIMITS,
        )
        .expect("tail metadata is layout-neutral");

        assert_eq!(layout.frame.max_home_bytes, 24);
        assert_eq!(layout.frame.outgoing_base, 56);
        assert_eq!(layout.frame.outgoing_bytes, 32);
        assert_eq!(layout.frame.frame_bytes, 96);
    }

    #[test]
    fn frame_extent_is_aligned_after_outgoing_area() {
        let layout = allocate(
            vec![function(
                vec![MachineType::I64],
                1,
                vec![tail(vec![
                    CanonicalHomeArgument::Immediate(MachineType::Unit),
                    CanonicalHomeArgument::Immediate(MachineType::F64),
                ])],
            )],
            CURRENT_LIMITS,
        )
        .expect("aligned frame must succeed");

        assert_eq!(layout.frame.outgoing_base, 40);
        assert_eq!(layout.frame.outgoing_bytes, 16);
        assert_eq!(layout.frame.frame_bytes, 64);
    }

    #[test]
    fn home_extent_overflow_is_reported_exactly() {
        let limits = CanonicalHomeLayoutLimits {
            header_bytes: u32::MAX - 7,
            max_frame_bytes: u32::MAX,
            max_outgoing_bytes: u32::MAX,
            ..CURRENT_LIMITS
        };
        let error = allocate(
            vec![function(vec![MachineType::I64], 1, Vec::new())],
            limits,
        )
        .expect_err("home extent must overflow");

        assert_eq!(
            error,
            CanonicalHomeLayoutError::ArithmeticOverflow {
                field: "function home extent",
            }
        );
    }

    #[test]
    fn frame_extent_overflow_is_reported_exactly() {
        let limits = CanonicalHomeLayoutLimits {
            header_bytes: u32::MAX - 7,
            max_frame_bytes: u32::MAX,
            max_outgoing_bytes: u32::MAX,
            ..CURRENT_LIMITS
        };
        let error = allocate(
            vec![function(
                Vec::new(),
                0,
                vec![tail(vec![CanonicalHomeArgument::Immediate(
                    MachineType::I64,
                )])],
            )],
            limits,
        )
        .expect_err("frame extent must overflow");

        assert_eq!(
            error,
            CanonicalHomeLayoutError::ArithmeticOverflow {
                field: "frame extent",
            }
        );
    }

    #[test]
    fn outgoing_limit_is_checked_before_frame_layout() {
        let limits = CanonicalHomeLayoutLimits {
            max_outgoing_bytes: 7,
            ..CURRENT_LIMITS
        };
        let error = allocate(
            vec![function(
                Vec::new(),
                0,
                vec![tail(vec![CanonicalHomeArgument::Immediate(
                    MachineType::Unit,
                )])],
            )],
            limits,
        )
        .expect_err("outgoing limit must reject one word");

        assert_eq!(
            error,
            CanonicalHomeLayoutError::StructuralLimit {
                field: "outgoing argument bytes",
                limit: 7,
                actual: 8,
            }
        );
    }

    #[test]
    fn aligned_frame_limit_uses_the_final_frame_size() {
        let limits = CanonicalHomeLayoutLimits {
            max_frame_bytes: 63,
            ..CURRENT_LIMITS
        };
        let error = allocate(
            vec![function(
                vec![MachineType::I64],
                1,
                vec![tail(vec![
                    CanonicalHomeArgument::Immediate(MachineType::Bool),
                    CanonicalHomeArgument::Immediate(MachineType::F64),
                ])],
            )],
            limits,
        )
        .expect_err("aligned frame must exceed the configured limit");

        assert_eq!(
            error,
            CanonicalHomeLayoutError::StructuralLimit {
                field: "frame bytes",
                limit: 63,
                actual: 64,
            }
        );
    }

    #[test]
    fn malformed_counts_and_alignments_fail_deterministically() {
        let count_error = allocate(
            vec![function(vec![MachineType::I64], 2, Vec::new())],
            CURRENT_LIMITS,
        )
        .expect_err("parameter count must fit the dense value space");
        assert_eq!(
            count_error,
            CanonicalHomeLayoutError::ParameterCountExceedsValues {
                function: 0,
                parameter_count: 2,
                value_count: 1,
            }
        );

        let alignment_error = allocate(
            Vec::new(),
            CanonicalHomeLayoutLimits {
                outgoing_alignment: 3,
                ..CURRENT_LIMITS
            },
        )
        .expect_err("non-power-of-two alignment must be rejected");
        assert_eq!(
            alignment_error,
            CanonicalHomeLayoutError::InvalidAlignment {
                field: "outgoing",
                value: 3,
            }
        );
    }
}
