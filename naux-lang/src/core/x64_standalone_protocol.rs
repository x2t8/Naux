//! Canonical Gate B input/output protocol for standalone x86-64 artifacts.
//!
//! The format is deliberately independent of Rust layout, host endianness,
//! text parsing, serde, and libc. Input floating-point values cross this
//! boundary only as their exact IEEE-754 bit patterns. Output NaNs have one
//! canonical representation so a successful artifact has one wire identity.

use std::fmt;

pub const X64_STANDALONE_PROTOCOL_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_MAX_ARRAY_ELEMENTS: u64 = 1_048_576;
pub const X64_STANDALONE_MAX_PAYLOAD_BYTES: u64 = 8_388_608;
pub const X64_STANDALONE_MAX_INPUT_BYTES: usize = 8_388_648;
pub const X64_STANDALONE_OUTPUT_BYTES: usize = 40;
pub const X64_STANDALONE_CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
pub const X64_STANDALONE_INPUT_MAGIC: [u8; 8] = *b"NAUXGBI1";
pub const X64_STANDALONE_OUTPUT_MAGIC: [u8; 8] = *b"NAUXGBO1";

const INPUT_PREFIX_BYTES: usize = 40;
const F64_BITS_BYTES: u64 = 8;

/// The exact lighthouse entry point declared by a standalone frame.
///
/// A standalone image bakes exactly one profile. Claim-bearing admission must
/// additionally prove that this declaration equals the image's baked profile;
/// it must never use the tag as a runtime dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneProfile {
    BranchMix,
    Bounds,
}

impl X64StandaloneProfile {
    pub const fn wire_tag(self) -> u16 {
        match self {
            Self::BranchMix => 1,
            Self::Bounds => 2,
        }
    }

    fn from_wire_tag(actual: u16) -> Result<Self, X64StandaloneProtocolError> {
        match actual {
            1 => Ok(Self::BranchMix),
            2 => Ok(Self::Bounds),
            _ => Err(X64StandaloneProtocolError::UnknownProfile { actual }),
        }
    }
}

/// One validated standalone invocation.
///
/// The array is stored as bits rather than `f64`; this preserves negative
/// zero, every NaN payload, infinities, and all subnormal encodings exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64StandaloneInput {
    profile: X64StandaloneProfile,
    array_f64_bits: Vec<u64>,
    repetitions: i64,
}

impl X64StandaloneInput {
    pub fn new(
        profile: X64StandaloneProfile,
        array_f64_bits: Vec<u64>,
        repetitions: i64,
    ) -> Result<Self, X64StandaloneProtocolError> {
        validate_input_shape(profile, array_f64_bits.len(), repetitions)?;
        Ok(Self {
            profile,
            array_f64_bits,
            repetitions,
        })
    }

    pub const fn profile(&self) -> X64StandaloneProfile {
        self.profile
    }

    pub fn array_f64_bits(&self) -> &[u64] {
        &self.array_f64_bits
    }

    pub const fn repetitions(&self) -> i64 {
        self.repetitions
    }
}

/// The only two outcomes admitted by the Gate B lighthouse ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneOutcome {
    ReturnF64 { bits: u64 },
    Bounds,
}

impl X64StandaloneOutcome {
    pub const fn returned_f64_bits(self) -> Option<u64> {
        match self {
            Self::ReturnF64 { bits } => Some(bits),
            Self::Bounds => None,
        }
    }
}

/// One canonical standalone result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneOutput {
    profile: X64StandaloneProfile,
    outcome: X64StandaloneOutcome,
}

impl X64StandaloneOutput {
    pub const fn return_f64(profile: X64StandaloneProfile, bits: u64) -> Self {
        Self {
            profile,
            outcome: X64StandaloneOutcome::ReturnF64 {
                bits: canonicalize_nan(bits),
            },
        }
    }

    pub const fn bounds(profile: X64StandaloneProfile) -> Self {
        Self {
            profile,
            outcome: X64StandaloneOutcome::Bounds,
        }
    }

    pub const fn profile(self) -> X64StandaloneProfile {
        self.profile
    }

    pub const fn outcome(self) -> X64StandaloneOutcome {
        self.outcome
    }
}

/// Fail-closed protocol rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64StandaloneProtocolError {
    FrameByteLimit {
        limit: usize,
        actual: usize,
    },
    InvalidMagic {
        frame: &'static str,
    },
    InvalidVersion {
        actual: (u16, u16, u16),
    },
    UnknownProfile {
        actual: u16,
    },
    ProfileMismatch {
        frame: &'static str,
        expected: X64StandaloneProfile,
        actual: X64StandaloneProfile,
    },
    ArrayElementLimit {
        limit: u64,
        actual: u64,
    },
    BoundsRepetitions {
        actual: i64,
    },
    PayloadByteLength {
        expected: u64,
        actual: u64,
    },
    Truncated {
        field: &'static str,
        needed: usize,
        remaining: usize,
    },
    TrailingBytes {
        actual: usize,
    },
    LengthOverflow {
        field: &'static str,
    },
    AllocationFailed {
        elements: usize,
    },
    UnknownOutcome {
        actual: u32,
    },
    NonZeroReserved {
        actual: u32,
    },
    NonZeroReturnPayload1 {
        actual: u64,
    },
    NonCanonicalReturnNan {
        actual: u64,
    },
    NonZeroBoundsPayload {
        payload0: u64,
        payload1: u64,
    },
}

impl fmt::Display for X64StandaloneProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameByteLimit { limit, actual } => write!(
                formatter,
                "standalone frame uses {actual} bytes; limit is {limit}"
            ),
            Self::InvalidMagic { frame } => {
                write!(formatter, "standalone {frame} frame has invalid magic")
            }
            Self::InvalidVersion { actual } => {
                write!(
                    formatter,
                    "standalone protocol version {actual:?} is not canonical"
                )
            }
            Self::UnknownProfile { actual } => {
                write!(formatter, "standalone frame has unknown profile {actual}")
            }
            Self::ProfileMismatch {
                frame,
                expected,
                actual,
            } => write!(
                formatter,
                "standalone {frame} frame declares {actual:?}; image requires {expected:?}"
            ),
            Self::ArrayElementLimit { limit, actual } => write!(
                formatter,
                "standalone input has {actual} array elements; limit is {limit}"
            ),
            Self::BoundsRepetitions { actual } => write!(
                formatter,
                "standalone Bounds input repetitions must be zero; found {actual}"
            ),
            Self::PayloadByteLength { expected, actual } => write!(
                formatter,
                "standalone input declares {actual} payload bytes; expected {expected}"
            ),
            Self::Truncated {
                field,
                needed,
                remaining,
            } => write!(
                formatter,
                "standalone frame field {field} needs {needed} bytes; only {remaining} remain"
            ),
            Self::TrailingBytes { actual } => {
                write!(formatter, "standalone frame has {actual} trailing bytes")
            }
            Self::LengthOverflow { field } => {
                write!(formatter, "standalone {field} length overflow")
            }
            Self::AllocationFailed { elements } => write!(
                formatter,
                "standalone input cannot allocate storage for {elements} elements"
            ),
            Self::UnknownOutcome { actual } => {
                write!(formatter, "standalone output has unknown outcome {actual}")
            }
            Self::NonZeroReserved { actual } => write!(
                formatter,
                "standalone output reserved field must be zero; found {actual}"
            ),
            Self::NonZeroReturnPayload1 { actual } => write!(
                formatter,
                "standalone ReturnF64 payload1 must be zero; found {actual:#018x}"
            ),
            Self::NonCanonicalReturnNan { actual } => write!(
                formatter,
                "standalone ReturnF64 NaN {actual:#018x} is not canonical"
            ),
            Self::NonZeroBoundsPayload { payload0, payload1 } => write!(
                formatter,
                "standalone Bounds payloads must be zero; found {payload0:#018x}, {payload1:#018x}"
            ),
        }
    }
}

impl std::error::Error for X64StandaloneProtocolError {}

/// Encode one validated invocation using the canonical big-endian input
/// format.
pub fn encode_x64_standalone_input(
    input: &X64StandaloneInput,
) -> Result<Vec<u8>, X64StandaloneProtocolError> {
    validate_input_shape(input.profile, input.array_f64_bits.len(), input.repetitions)?;
    let elements = usize_to_u64(input.array_f64_bits.len(), "array element count")?;
    let payload_bytes =
        elements
            .checked_mul(F64_BITS_BYTES)
            .ok_or(X64StandaloneProtocolError::LengthOverflow {
                field: "input payload",
            })?;
    let payload_bytes_usize = u64_to_usize(payload_bytes, "input payload")?;
    let frame_bytes = INPUT_PREFIX_BYTES.checked_add(payload_bytes_usize).ok_or(
        X64StandaloneProtocolError::LengthOverflow {
            field: "input frame",
        },
    )?;
    if frame_bytes > X64_STANDALONE_MAX_INPUT_BYTES {
        return Err(X64StandaloneProtocolError::FrameByteLimit {
            limit: X64_STANDALONE_MAX_INPUT_BYTES,
            actual: frame_bytes,
        });
    }

    let mut encoded = Vec::new();
    encoded.try_reserve_exact(frame_bytes).map_err(|_| {
        X64StandaloneProtocolError::AllocationFailed {
            elements: input.array_f64_bits.len(),
        }
    })?;
    encoded.extend_from_slice(&X64_STANDALONE_INPUT_MAGIC);
    append_version(&mut encoded);
    encoded.extend_from_slice(&input.profile.wire_tag().to_be_bytes());
    encoded.extend_from_slice(&elements.to_be_bytes());
    encoded.extend_from_slice(&input.repetitions.to_be_bytes());
    encoded.extend_from_slice(&payload_bytes.to_be_bytes());
    for bits in &input.array_f64_bits {
        encoded.extend_from_slice(&bits.to_be_bytes());
    }
    Ok(encoded)
}

/// Decode exactly one canonical big-endian input frame and EOF.
pub fn decode_x64_standalone_input(
    encoded: &[u8],
) -> Result<X64StandaloneInput, X64StandaloneProtocolError> {
    if encoded.len() > X64_STANDALONE_MAX_INPUT_BYTES {
        return Err(X64StandaloneProtocolError::FrameByteLimit {
            limit: X64_STANDALONE_MAX_INPUT_BYTES,
            actual: encoded.len(),
        });
    }

    let mut cursor = Decoder::new(encoded);
    if cursor.take_array::<8>("input magic")? != X64_STANDALONE_INPUT_MAGIC {
        return Err(X64StandaloneProtocolError::InvalidMagic { frame: "input" });
    }
    decode_version(&mut cursor)?;
    let profile = X64StandaloneProfile::from_wire_tag(cursor.u16("profile")?)?;
    let elements = cursor.u64("array_elements")?;
    let repetitions = cursor.i64("repetitions")?;
    let payload_bytes = cursor.u64("payload_bytes")?;

    if elements > X64_STANDALONE_MAX_ARRAY_ELEMENTS {
        return Err(X64StandaloneProtocolError::ArrayElementLimit {
            limit: X64_STANDALONE_MAX_ARRAY_ELEMENTS,
            actual: elements,
        });
    }
    if profile == X64StandaloneProfile::Bounds && repetitions != 0 {
        return Err(X64StandaloneProtocolError::BoundsRepetitions {
            actual: repetitions,
        });
    }
    let expected_payload =
        elements
            .checked_mul(F64_BITS_BYTES)
            .ok_or(X64StandaloneProtocolError::LengthOverflow {
                field: "input payload",
            })?;
    if payload_bytes != expected_payload {
        return Err(X64StandaloneProtocolError::PayloadByteLength {
            expected: expected_payload,
            actual: payload_bytes,
        });
    }
    let payload_bytes_usize = u64_to_usize(payload_bytes, "input payload")?;
    let expected_frame = INPUT_PREFIX_BYTES.checked_add(payload_bytes_usize).ok_or(
        X64StandaloneProtocolError::LengthOverflow {
            field: "input frame",
        },
    )?;
    if expected_frame > X64_STANDALONE_MAX_INPUT_BYTES {
        return Err(X64StandaloneProtocolError::FrameByteLimit {
            limit: X64_STANDALONE_MAX_INPUT_BYTES,
            actual: expected_frame,
        });
    }
    if encoded.len() < expected_frame {
        return Err(X64StandaloneProtocolError::Truncated {
            field: "array payload",
            needed: payload_bytes_usize,
            remaining: cursor.remaining(),
        });
    }
    if encoded.len() > expected_frame {
        return Err(X64StandaloneProtocolError::TrailingBytes {
            actual: encoded.len() - expected_frame,
        });
    }

    let elements_usize = u64_to_usize(elements, "array element count")?;
    let mut array_f64_bits = Vec::new();
    array_f64_bits
        .try_reserve_exact(elements_usize)
        .map_err(|_| X64StandaloneProtocolError::AllocationFailed {
            elements: elements_usize,
        })?;
    for _ in 0..elements_usize {
        array_f64_bits.push(cursor.u64("array element")?);
    }
    cursor.finish()?;

    X64StandaloneInput::new(profile, array_f64_bits, repetitions)
}

/// Decode a canonical input and bind its declared profile to the one profile
/// baked into the admitting image.
///
/// Standalone claim paths must use this function instead of treating the
/// frame's profile tag as a dispatch choice.
pub fn decode_x64_standalone_input_for_profile(
    encoded: &[u8],
    expected: X64StandaloneProfile,
) -> Result<X64StandaloneInput, X64StandaloneProtocolError> {
    let input = decode_x64_standalone_input(encoded)?;
    if input.profile != expected {
        return Err(X64StandaloneProtocolError::ProfileMismatch {
            frame: "input",
            expected,
            actual: input.profile,
        });
    }
    Ok(input)
}

/// Encode one result as the exact 40-byte big-endian output frame.
pub fn encode_x64_standalone_output(
    output: X64StandaloneOutput,
) -> Result<[u8; X64_STANDALONE_OUTPUT_BYTES], X64StandaloneProtocolError> {
    let (outcome, payload0, payload1) = match output.outcome {
        X64StandaloneOutcome::ReturnF64 { bits } => (0_u32, canonicalize_nan(bits), 0_u64),
        X64StandaloneOutcome::Bounds => (1_u32, 0_u64, 0_u64),
    };

    let mut encoded = [0_u8; X64_STANDALONE_OUTPUT_BYTES];
    let mut writer = FixedEncoder::new(&mut encoded);
    writer.put("output magic", &X64_STANDALONE_OUTPUT_MAGIC)?;
    writer.put(
        "version major",
        &X64_STANDALONE_PROTOCOL_VERSION.0.to_be_bytes(),
    )?;
    writer.put(
        "version minor",
        &X64_STANDALONE_PROTOCOL_VERSION.1.to_be_bytes(),
    )?;
    writer.put(
        "version patch",
        &X64_STANDALONE_PROTOCOL_VERSION.2.to_be_bytes(),
    )?;
    writer.put("profile", &output.profile.wire_tag().to_be_bytes())?;
    writer.put("outcome", &outcome.to_be_bytes())?;
    writer.put("reserved", &0_u32.to_be_bytes())?;
    writer.put("payload0", &payload0.to_be_bytes())?;
    writer.put("payload1", &payload1.to_be_bytes())?;
    writer.finish()?;
    Ok(encoded)
}

/// Decode exactly one canonical 40-byte big-endian output frame and EOF.
pub fn decode_x64_standalone_output(
    encoded: &[u8],
) -> Result<X64StandaloneOutput, X64StandaloneProtocolError> {
    let mut cursor = Decoder::new(encoded);
    if cursor.take_array::<8>("output magic")? != X64_STANDALONE_OUTPUT_MAGIC {
        return Err(X64StandaloneProtocolError::InvalidMagic { frame: "output" });
    }
    decode_version(&mut cursor)?;
    let profile = X64StandaloneProfile::from_wire_tag(cursor.u16("profile")?)?;
    let outcome = cursor.u32("outcome")?;
    let reserved = cursor.u32("reserved")?;
    let payload0 = cursor.u64("payload0")?;
    let payload1 = cursor.u64("payload1")?;
    cursor.finish()?;

    if reserved != 0 {
        return Err(X64StandaloneProtocolError::NonZeroReserved { actual: reserved });
    }
    match outcome {
        0 => {
            if payload1 != 0 {
                return Err(X64StandaloneProtocolError::NonZeroReturnPayload1 { actual: payload1 });
            }
            if is_nan_bits(payload0) && payload0 != X64_STANDALONE_CANONICAL_NAN_BITS {
                return Err(X64StandaloneProtocolError::NonCanonicalReturnNan { actual: payload0 });
            }
            Ok(X64StandaloneOutput::return_f64(profile, payload0))
        }
        1 => {
            if payload0 != 0 || payload1 != 0 {
                return Err(X64StandaloneProtocolError::NonZeroBoundsPayload {
                    payload0,
                    payload1,
                });
            }
            Ok(X64StandaloneOutput::bounds(profile))
        }
        actual => Err(X64StandaloneProtocolError::UnknownOutcome { actual }),
    }
}

/// Decode a canonical output and bind it to the profile baked into the image
/// that produced it.
pub fn decode_x64_standalone_output_for_profile(
    encoded: &[u8],
    expected: X64StandaloneProfile,
) -> Result<X64StandaloneOutput, X64StandaloneProtocolError> {
    let output = decode_x64_standalone_output(encoded)?;
    if output.profile != expected {
        return Err(X64StandaloneProtocolError::ProfileMismatch {
            frame: "output",
            expected,
            actual: output.profile,
        });
    }
    Ok(output)
}

fn validate_input_shape(
    profile: X64StandaloneProfile,
    elements: usize,
    repetitions: i64,
) -> Result<(), X64StandaloneProtocolError> {
    let elements = usize_to_u64(elements, "array element count")?;
    if elements > X64_STANDALONE_MAX_ARRAY_ELEMENTS {
        return Err(X64StandaloneProtocolError::ArrayElementLimit {
            limit: X64_STANDALONE_MAX_ARRAY_ELEMENTS,
            actual: elements,
        });
    }
    if profile == X64StandaloneProfile::Bounds && repetitions != 0 {
        return Err(X64StandaloneProtocolError::BoundsRepetitions {
            actual: repetitions,
        });
    }
    Ok(())
}

fn append_version(encoded: &mut Vec<u8>) {
    encoded.extend_from_slice(&X64_STANDALONE_PROTOCOL_VERSION.0.to_be_bytes());
    encoded.extend_from_slice(&X64_STANDALONE_PROTOCOL_VERSION.1.to_be_bytes());
    encoded.extend_from_slice(&X64_STANDALONE_PROTOCOL_VERSION.2.to_be_bytes());
}

fn decode_version(cursor: &mut Decoder<'_>) -> Result<(), X64StandaloneProtocolError> {
    let actual = (
        cursor.u16("version major")?,
        cursor.u16("version minor")?,
        cursor.u16("version patch")?,
    );
    if actual != X64_STANDALONE_PROTOCOL_VERSION {
        return Err(X64StandaloneProtocolError::InvalidVersion { actual });
    }
    Ok(())
}

const fn is_nan_bits(bits: u64) -> bool {
    bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000 && bits & 0x000f_ffff_ffff_ffff != 0
}

const fn canonicalize_nan(bits: u64) -> u64 {
    if is_nan_bits(bits) {
        X64_STANDALONE_CANONICAL_NAN_BITS
    } else {
        bits
    }
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64StandaloneProtocolError> {
    u64::try_from(value).map_err(|_| X64StandaloneProtocolError::LengthOverflow { field })
}

fn u64_to_usize(value: u64, field: &'static str) -> Result<usize, X64StandaloneProtocolError> {
    usize::try_from(value).map_err(|_| X64StandaloneProtocolError::LengthOverflow { field })
}

struct Decoder<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], X64StandaloneProtocolError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(X64StandaloneProtocolError::LengthOverflow {
                field: "decoder offset",
            })?;
        let remaining = self.remaining();
        let slice =
            self.encoded
                .get(self.offset..end)
                .ok_or(X64StandaloneProtocolError::Truncated {
                    field,
                    needed: N,
                    remaining,
                })?;
        let bytes =
            <[u8; N]>::try_from(slice).map_err(|_| X64StandaloneProtocolError::Truncated {
                field,
                needed: N,
                remaining,
            })?;
        self.offset = end;
        Ok(bytes)
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, X64StandaloneProtocolError> {
        Ok(u16::from_be_bytes(self.take_array(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, X64StandaloneProtocolError> {
        Ok(u32::from_be_bytes(self.take_array(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, X64StandaloneProtocolError> {
        Ok(u64::from_be_bytes(self.take_array(field)?))
    }

    fn i64(&mut self, field: &'static str) -> Result<i64, X64StandaloneProtocolError> {
        Ok(i64::from_be_bytes(self.take_array(field)?))
    }

    fn remaining(&self) -> usize {
        self.encoded.len().saturating_sub(self.offset)
    }

    fn finish(self) -> Result<(), X64StandaloneProtocolError> {
        let actual = self.remaining();
        if actual != 0 {
            return Err(X64StandaloneProtocolError::TrailingBytes { actual });
        }
        Ok(())
    }
}

struct FixedEncoder<'a> {
    encoded: &'a mut [u8],
    offset: usize,
}

impl<'a> FixedEncoder<'a> {
    fn new(encoded: &'a mut [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn put(&mut self, field: &'static str, value: &[u8]) -> Result<(), X64StandaloneProtocolError> {
        let end = self.offset.checked_add(value.len()).ok_or(
            X64StandaloneProtocolError::LengthOverflow {
                field: "encoder offset",
            },
        )?;
        let target = self
            .encoded
            .get_mut(self.offset..end)
            .ok_or(X64StandaloneProtocolError::LengthOverflow { field })?;
        target.copy_from_slice(value);
        self.offset = end;
        Ok(())
    }

    fn finish(self) -> Result<(), X64StandaloneProtocolError> {
        if self.offset != self.encoded.len() {
            return Err(X64StandaloneProtocolError::LengthOverflow {
                field: "output frame",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branch_input() -> X64StandaloneInput {
        X64StandaloneInput::new(
            X64StandaloneProfile::BranchMix,
            vec![
                0x8000_0000_0000_0000,
                0x7ff0_0000_0000_0001,
                0xfff8_dead_beef_cafe,
                0x0000_0000_0000_0001,
            ],
            -17,
        )
        .expect("valid BranchMix input")
    }

    #[test]
    fn input_is_exact_big_endian_and_preserves_all_f64_bits() {
        let input = branch_input();
        let encoded = encode_x64_standalone_input(&input).expect("input encodes");
        let expected = vec![
            0x4e, 0x41, 0x55, 0x58, 0x47, 0x42, 0x49, 0x31, // NAUXGBI1
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 1.0.0
            0x00, 0x01, // BranchMix
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // elements
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xef, // -17
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, // payload bytes
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // -0
            0x7f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sNaN
            0xff, 0xf8, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // negative qNaN
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // subnormal
        ];
        assert_eq!(encoded, expected);
        assert_eq!(
            decode_x64_standalone_input(&encoded).expect("canonical input decodes"),
            input
        );
    }

    #[test]
    fn input_rejects_noncanonical_shape_lengths_and_eof() {
        assert_eq!(
            X64StandaloneInput::new(X64StandaloneProfile::Bounds, vec![], 1),
            Err(X64StandaloneProtocolError::BoundsRepetitions { actual: 1 })
        );

        let encoded = encode_x64_standalone_input(&branch_input()).expect("input encodes");
        let mut wrong_payload = encoded.clone();
        wrong_payload[39] = 0x18;
        assert_eq!(
            decode_x64_standalone_input(&wrong_payload),
            Err(X64StandaloneProtocolError::PayloadByteLength {
                expected: 32,
                actual: 24,
            })
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_x64_standalone_input(&trailing),
            Err(X64StandaloneProtocolError::TrailingBytes { actual: 1 })
        );

        let truncated = &encoded[..encoded.len() - 1];
        assert_eq!(
            decode_x64_standalone_input(truncated),
            Err(X64StandaloneProtocolError::Truncated {
                field: "array payload",
                needed: 32,
                remaining: 31,
            })
        );
    }

    #[test]
    fn input_rejects_bad_identity_profile_and_limits() {
        let encoded = encode_x64_standalone_input(&branch_input()).expect("input encodes");

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_x64_standalone_input(&bad_magic),
            Err(X64StandaloneProtocolError::InvalidMagic { frame: "input" })
        );

        let mut bad_version = encoded.clone();
        bad_version[9] = 2;
        assert_eq!(
            decode_x64_standalone_input(&bad_version),
            Err(X64StandaloneProtocolError::InvalidVersion { actual: (2, 0, 0) })
        );

        let mut bad_profile = encoded.clone();
        bad_profile[15] = 3;
        assert_eq!(
            decode_x64_standalone_input(&bad_profile),
            Err(X64StandaloneProtocolError::UnknownProfile { actual: 3 })
        );

        let mut too_many = encoded;
        too_many[16..24].copy_from_slice(&(X64_STANDALONE_MAX_ARRAY_ELEMENTS + 1).to_be_bytes());
        assert_eq!(
            decode_x64_standalone_input(&too_many),
            Err(X64StandaloneProtocolError::ArrayElementLimit {
                limit: X64_STANDALONE_MAX_ARRAY_ELEMENTS,
                actual: X64_STANDALONE_MAX_ARRAY_ELEMENTS + 1,
            })
        );
    }

    #[test]
    fn input_limits_match_the_exact_maximum_frame() {
        let payload = X64_STANDALONE_MAX_ARRAY_ELEMENTS
            .checked_mul(F64_BITS_BYTES)
            .expect("fixed limit multiplication");
        assert_eq!(payload, X64_STANDALONE_MAX_PAYLOAD_BYTES);
        assert_eq!(
            u64::try_from(X64_STANDALONE_MAX_INPUT_BYTES).expect("limit fits u64"),
            u64::try_from(INPUT_PREFIX_BYTES).expect("prefix fits u64") + payload
        );
    }

    #[test]
    fn return_output_is_exact_and_nan_is_canonicalized() {
        let output =
            X64StandaloneOutput::return_f64(X64StandaloneProfile::BranchMix, 0xfff0_0000_0000_0001);
        let encoded = encode_x64_standalone_output(output).expect("output encodes");
        let expected = [
            0x4e, 0x41, 0x55, 0x58, 0x47, 0x42, 0x4f, 0x31, // NAUXGBO1
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 1.0.0
            0x00, 0x01, // BranchMix
            0x00, 0x00, 0x00, 0x00, // ReturnF64
            0x00, 0x00, 0x00, 0x00, // reserved
            0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // canonical NaN
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // payload1
        ];
        assert_eq!(encoded, expected);
        assert_eq!(
            decode_x64_standalone_output(&encoded).expect("output decodes"),
            X64StandaloneOutput::return_f64(
                X64StandaloneProfile::BranchMix,
                X64_STANDALONE_CANONICAL_NAN_BITS,
            )
        );
    }

    #[test]
    fn bounds_output_is_exact_and_roundtrips() {
        let output = X64StandaloneOutput::bounds(X64StandaloneProfile::Bounds);
        let encoded = encode_x64_standalone_output(output).expect("output encodes");
        assert_eq!(encoded.len(), X64_STANDALONE_OUTPUT_BYTES);
        assert_eq!(
            decode_x64_standalone_output(&encoded).expect("Bounds output decodes"),
            output
        );
    }

    #[test]
    fn output_rejects_reserved_payload_and_nan_malleability() {
        let canonical = encode_x64_standalone_output(X64StandaloneOutput::return_f64(
            X64StandaloneProfile::BranchMix,
            1.0_f64.to_bits(),
        ))
        .expect("output encodes");

        let mut reserved = canonical;
        reserved[23] = 1;
        assert_eq!(
            decode_x64_standalone_output(&reserved),
            Err(X64StandaloneProtocolError::NonZeroReserved { actual: 1 })
        );

        let mut payload1 = canonical;
        payload1[39] = 1;
        assert_eq!(
            decode_x64_standalone_output(&payload1),
            Err(X64StandaloneProtocolError::NonZeroReturnPayload1 { actual: 1 })
        );

        let mut noncanonical_nan = canonical;
        noncanonical_nan[24..32].copy_from_slice(&0x7ff0_0000_0000_0001_u64.to_be_bytes());
        assert_eq!(
            decode_x64_standalone_output(&noncanonical_nan),
            Err(X64StandaloneProtocolError::NonCanonicalReturnNan {
                actual: 0x7ff0_0000_0000_0001,
            })
        );

        let mut bounds_payload =
            encode_x64_standalone_output(X64StandaloneOutput::bounds(X64StandaloneProfile::Bounds))
                .expect("output encodes");
        bounds_payload[31] = 1;
        assert_eq!(
            decode_x64_standalone_output(&bounds_payload),
            Err(X64StandaloneProtocolError::NonZeroBoundsPayload {
                payload0: 1,
                payload1: 0,
            })
        );
    }

    #[test]
    fn output_rejects_unknown_outcome_and_nonexact_frame() {
        let canonical =
            encode_x64_standalone_output(X64StandaloneOutput::bounds(X64StandaloneProfile::Bounds))
                .expect("output encodes");

        let mut unknown = canonical;
        unknown[19] = 2;
        assert_eq!(
            decode_x64_standalone_output(&unknown),
            Err(X64StandaloneProtocolError::UnknownOutcome { actual: 2 })
        );

        assert!(matches!(
            decode_x64_standalone_output(&canonical[..canonical.len() - 1]),
            Err(X64StandaloneProtocolError::Truncated {
                field: "payload1",
                ..
            })
        ));

        let mut trailing = canonical.to_vec();
        trailing.push(0);
        assert_eq!(
            decode_x64_standalone_output(&trailing),
            Err(X64StandaloneProtocolError::TrailingBytes { actual: 1 })
        );
    }

    #[test]
    fn bound_admission_rejects_known_profile_substitution() {
        let bounds_input = X64StandaloneInput::new(X64StandaloneProfile::Bounds, Vec::new(), 0)
            .expect("zero-element Bounds input is canonical");
        let encoded_input =
            encode_x64_standalone_input(&bounds_input).expect("Bounds input encodes");
        assert_eq!(
            decode_x64_standalone_input_for_profile(
                &encoded_input,
                X64StandaloneProfile::BranchMix,
            ),
            Err(X64StandaloneProtocolError::ProfileMismatch {
                frame: "input",
                expected: X64StandaloneProfile::BranchMix,
                actual: X64StandaloneProfile::Bounds,
            })
        );

        let encoded_output =
            encode_x64_standalone_output(X64StandaloneOutput::bounds(X64StandaloneProfile::Bounds))
                .expect("Bounds output encodes");
        assert_eq!(
            decode_x64_standalone_output_for_profile(
                &encoded_output,
                X64StandaloneProfile::BranchMix,
            ),
            Err(X64StandaloneProtocolError::ProfileMismatch {
                frame: "output",
                expected: X64StandaloneProfile::BranchMix,
                actual: X64StandaloneProfile::Bounds,
            })
        );
    }

    #[test]
    fn every_strict_frame_prefix_is_rejected() {
        let input = encode_x64_standalone_input(&branch_input()).expect("input encodes");
        for prefix_bytes in 0..input.len() {
            assert!(
                decode_x64_standalone_input(&input[..prefix_bytes]).is_err(),
                "input prefix of {prefix_bytes} bytes was admitted"
            );
        }

        let output =
            encode_x64_standalone_output(X64StandaloneOutput::bounds(X64StandaloneProfile::Bounds))
                .expect("output encodes");
        for prefix_bytes in 0..output.len() {
            assert!(
                decode_x64_standalone_output(&output[..prefix_bytes]).is_err(),
                "output prefix of {prefix_bytes} bytes was admitted"
            );
        }
    }

    #[test]
    fn zero_inputs_and_branch_repetition_extremes_roundtrip_exactly() {
        for input in [
            X64StandaloneInput::new(X64StandaloneProfile::BranchMix, Vec::new(), i64::MIN)
                .expect("minimum BranchMix repetitions are canonical"),
            X64StandaloneInput::new(X64StandaloneProfile::BranchMix, Vec::new(), i64::MAX)
                .expect("maximum BranchMix repetitions are canonical"),
            X64StandaloneInput::new(X64StandaloneProfile::Bounds, Vec::new(), 0)
                .expect("zero-element Bounds input is canonical"),
        ] {
            let encoded = encode_x64_standalone_input(&input).expect("input encodes");
            assert_eq!(encoded.len(), INPUT_PREFIX_BYTES);
            let decoded = decode_x64_standalone_input_for_profile(&encoded, input.profile())
                .expect("bound input decodes");
            assert_eq!(decoded, input);
            assert_eq!(
                encode_x64_standalone_input(&decoded).expect("decoded input re-encodes"),
                encoded
            );
        }
    }

    #[test]
    fn exact_maximum_input_roundtrips_and_one_over_is_rejected() {
        let max_elements =
            usize::try_from(X64_STANDALONE_MAX_ARRAY_ELEMENTS).expect("limit fits usize");
        let input = X64StandaloneInput::new(
            X64StandaloneProfile::BranchMix,
            vec![0_u64; max_elements],
            1,
        )
        .expect("exact element cap is admitted");
        let encoded = encode_x64_standalone_input(&input).expect("maximum input encodes");
        assert_eq!(encoded.len(), X64_STANDALONE_MAX_INPUT_BYTES);
        assert_eq!(
            decode_x64_standalone_input_for_profile(&encoded, X64StandaloneProfile::BranchMix,)
                .expect("maximum input decodes"),
            input
        );

        let one_over = max_elements
            .checked_add(1)
            .expect("fixed cap has successor");
        assert_eq!(
            X64StandaloneInput::new(X64StandaloneProfile::BranchMix, vec![0_u64; one_over], 1,),
            Err(X64StandaloneProtocolError::ArrayElementLimit {
                limit: X64_STANDALONE_MAX_ARRAY_ELEMENTS,
                actual: X64_STANDALONE_MAX_ARRAY_ELEMENTS + 1,
            })
        );
    }

    #[test]
    fn hostile_lengths_and_over_cap_frames_fail_closed() {
        let canonical = encode_x64_standalone_input(
            &X64StandaloneInput::new(X64StandaloneProfile::BranchMix, Vec::new(), 0)
                .expect("zero input is canonical"),
        )
        .expect("input encodes");

        let mut hostile_elements = canonical.clone();
        hostile_elements[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            decode_x64_standalone_input(&hostile_elements),
            Err(X64StandaloneProtocolError::ArrayElementLimit {
                limit: X64_STANDALONE_MAX_ARRAY_ELEMENTS,
                actual: u64::MAX,
            })
        );

        let mut hostile_payload = canonical;
        hostile_payload[32..40].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            decode_x64_standalone_input(&hostile_payload),
            Err(X64StandaloneProtocolError::PayloadByteLength {
                expected: 0,
                actual: u64::MAX,
            })
        );

        let oversized = vec![0_u8; X64_STANDALONE_MAX_INPUT_BYTES + 1];
        assert_eq!(
            decode_x64_standalone_input(&oversized),
            Err(X64StandaloneProtocolError::FrameByteLimit {
                limit: X64_STANDALONE_MAX_INPUT_BYTES,
                actual: X64_STANDALONE_MAX_INPUT_BYTES + 1,
            })
        );
    }

    #[test]
    fn all_version_words_and_output_identity_are_checked() {
        let input = encode_x64_standalone_input(&branch_input()).expect("input encodes");
        for offset in [8_usize, 10, 12] {
            let mut mutated = input.clone();
            mutated[offset] = 1;
            assert!(matches!(
                decode_x64_standalone_input(&mutated),
                Err(X64StandaloneProtocolError::InvalidVersion { .. })
            ));
        }

        let output =
            encode_x64_standalone_output(X64StandaloneOutput::bounds(X64StandaloneProfile::Bounds))
                .expect("output encodes");
        let mut bad_magic = output;
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_x64_standalone_output(&bad_magic),
            Err(X64StandaloneProtocolError::InvalidMagic { frame: "output" })
        );
        for offset in [8_usize, 10, 12] {
            let mut mutated = output;
            mutated[offset] = 1;
            assert!(matches!(
                decode_x64_standalone_output(&mutated),
                Err(X64StandaloneProtocolError::InvalidVersion { .. })
            ));
        }
        let mut bad_profile = output;
        bad_profile[15] = 3;
        assert_eq!(
            decode_x64_standalone_output(&bad_profile),
            Err(X64StandaloneProtocolError::UnknownProfile { actual: 3 })
        );
    }

    #[test]
    fn floating_point_edges_preserve_input_and_non_nan_output_bits() {
        let edges = vec![
            0_u64,
            0x8000_0000_0000_0000,
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            1_u64,
            0x8000_0000_0000_0001,
            f64::MIN_POSITIVE.to_bits(),
            (-f64::MIN_POSITIVE).to_bits(),
            f64::MAX.to_bits(),
            f64::MIN.to_bits(),
            0x7ff0_0000_0000_0001,
            0xfff8_dead_beef_cafe,
        ];
        let input = X64StandaloneInput::new(X64StandaloneProfile::BranchMix, edges.clone(), 0)
            .expect("edge input is canonical");
        let encoded = encode_x64_standalone_input(&input).expect("edge input encodes");
        assert_eq!(
            decode_x64_standalone_input(&encoded)
                .expect("edge input decodes")
                .array_f64_bits(),
            edges
        );

        for bits in [
            0_u64,
            0x8000_0000_0000_0000,
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            1_u64,
            f64::MAX.to_bits(),
        ] {
            let output = X64StandaloneOutput::return_f64(X64StandaloneProfile::BranchMix, bits);
            let encoded = encode_x64_standalone_output(output).expect("output encodes");
            assert_eq!(
                decode_x64_standalone_output(&encoded)
                    .expect("output decodes")
                    .outcome(),
                X64StandaloneOutcome::ReturnF64 { bits }
            );
        }
    }
}
