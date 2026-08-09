#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    decode_x64_native_ipc_record, execute_x64_native_worker_case_r1_s7bc,
    x64_native_ipc_record_bytes, X64NativeEvidenceError, X64NativeIpcError,
    X64_NATIVE_IPC_RECORD_DOMAIN,
};
use std::path::Path;

const HASH_BYTES: usize = 32;
const VERSION_BYTES: usize = 6;
const BODY_LENGTH_OFFSET: usize =
    X64_NATIVE_IPC_RECORD_DOMAIN.len() + 2 * VERSION_BYTES + HASH_BYTES + 4;
const BODY_OFFSET: usize = BODY_LENGTH_OFFSET + 4;

// Execution-record fields before the mapping-state count:
// five versions, the frozen limits vector, four source/target hashes,
// entry offset, four ABI/input/code hashes, and the input-lane byte.
const MAPPING_COUNT_OFFSET_IN_BODY: usize =
    5 * VERSION_BYTES + (4 + 8 + 9 * 4) + 4 * HASH_BYTES + 4 + 4 * HASH_BYTES + 1;
const MAPPING_TAG_OFFSET_IN_BODY: usize = MAPPING_COUNT_OFFSET_IN_BODY + 4;
const OUTCOME_TAG_OFFSET_IN_BODY: usize = MAPPING_TAG_OFFSET_IN_BODY + 4 + 4 + 4;

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-r1-s7b-worker"))
}

fn canonical_frame(case_ordinal: u32) -> Vec<u8> {
    let record = execute_x64_native_worker_case_r1_s7bc(worker(), case_ordinal)
        .expect("the canonical worker must emit one admitted frame");
    x64_native_ipc_record_bytes(&record).expect("an admitted frame must re-encode canonically")
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("the test offset must identify one u32"),
    )
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn reseal_outer_frame(frame: &mut [u8]) {
    let hash_offset = frame
        .len()
        .checked_sub(HASH_BYTES)
        .expect("a canonical frame must contain its outer seal");
    let digest = independent_sha256(&frame[..hash_offset]);
    frame[hash_offset..].copy_from_slice(&digest);
}

fn mutate_and_reseal(frame: &[u8], offset: usize, value: u8) -> Vec<u8> {
    let mut mutated = frame.to_vec();
    mutated[offset] = value;
    reseal_outer_frame(&mut mutated);
    mutated
}

fn mutate_u32_and_reseal(frame: &[u8], offset: usize, value: u32) -> Vec<u8> {
    let mut mutated = frame.to_vec();
    write_u32(&mut mutated, offset, value);
    reseal_outer_frame(&mut mutated);
    mutated
}

#[test]
fn adversarial_ipc_lengths_tags_and_nested_seals_fail_closed() {
    let return_frame = canonical_frame(0);
    let outer_hash_offset = return_frame.len() - HASH_BYTES;
    assert_eq!(
        independent_sha256(&return_frame[..outer_hash_offset]).as_slice(),
        &return_frame[outer_hash_offset..],
        "the independent test oracle must reproduce the canonical outer seal"
    );

    let body_length = read_u32(&return_frame, BODY_LENGTH_OFFSET);
    assert_eq!(body_length, 401, "R1-S7b-c v1 case-zero body drifted");

    let mut body_under = return_frame.clone();
    write_u32(
        &mut body_under,
        BODY_LENGTH_OFFSET,
        body_length.checked_sub(1).expect("body is nonempty"),
    );
    assert!(matches!(
        decode_x64_native_ipc_record(&body_under, 0),
        Err(X64NativeIpcError::TrailingBytes {
            scope: "frame",
            actual: 1
        })
    ));

    let mut body_over = return_frame.clone();
    write_u32(
        &mut body_over,
        BODY_LENGTH_OFFSET,
        body_length.checked_add(1).expect("body length fits u32"),
    );
    assert!(matches!(
        decode_x64_native_ipc_record(&body_over, 0),
        Err(X64NativeIpcError::Truncated {
            field: "declared body and frame hash",
            ..
        })
    ));

    let mut body_max = return_frame.clone();
    write_u32(&mut body_max, BODY_LENGTH_OFFSET, u32::MAX);
    assert!(matches!(
        decode_x64_native_ipc_record(&body_max, 0),
        Err(X64NativeIpcError::Truncated {
            field: "declared body and frame hash",
            ..
        })
    ));

    for prefix_length in 0..return_frame.len() {
        assert!(
            decode_x64_native_ipc_record(&return_frame[..prefix_length], 0).is_err(),
            "every strict frame prefix must fail; admitted prefix length {prefix_length}"
        );
    }

    let schema_offset = X64_NATIVE_IPC_RECORD_DOMAIN.len();
    assert_eq!(&return_frame[schema_offset..schema_offset + 2], &[0, 1]);
    let invalid_schema = mutate_and_reseal(&return_frame, schema_offset + 1, 2);
    assert!(matches!(
        decode_x64_native_ipc_record(&invalid_schema, 0),
        Err(X64NativeIpcError::InvalidSchema { actual: (2, 0, 0) })
    ));

    let policy_offset = schema_offset + VERSION_BYTES;
    assert_eq!(&return_frame[policy_offset..policy_offset + 2], &[0, 1]);
    let invalid_policy = mutate_and_reseal(&return_frame, policy_offset + 1, 2);
    assert!(matches!(
        decode_x64_native_ipc_record(&invalid_policy, 0),
        Err(X64NativeIpcError::InvalidProcessPolicy { actual: (2, 0, 0) })
    ));

    let manifest_offset = policy_offset + VERSION_BYTES;
    let invalid_manifest = mutate_and_reseal(
        &return_frame,
        manifest_offset,
        return_frame[manifest_offset] ^ 1,
    );
    assert!(matches!(
        decode_x64_native_ipc_record(&invalid_manifest, 0),
        Err(X64NativeIpcError::CorpusManifestHashMismatch)
    ));

    let mapping_count_offset = BODY_OFFSET + MAPPING_COUNT_OFFSET_IN_BODY;
    assert_eq!(read_u32(&return_frame, mapping_count_offset), 4);
    for invalid_count in [3, 5, u32::MAX] {
        let invalid_mapping_count =
            mutate_u32_and_reseal(&return_frame, mapping_count_offset, invalid_count);
        assert!(matches!(
            decode_x64_native_ipc_record(&invalid_mapping_count, 0),
            Err(X64NativeIpcError::InvalidCount {
                field: "mapping-state",
                expected: 4,
                actual
            }) if actual == invalid_count
        ));
    }

    for mapping_index in 0..4 {
        let mapping_offset = BODY_OFFSET + MAPPING_TAG_OFFSET_IN_BODY + mapping_index;
        let invalid_mapping = mutate_and_reseal(&return_frame, mapping_offset, u8::MAX);
        assert!(matches!(
            decode_x64_native_ipc_record(&invalid_mapping, 0),
            Err(X64NativeIpcError::UnknownTag {
                field: "mapping state",
                actual: u8::MAX
            })
        ));
    }

    let outcome_offset = BODY_OFFSET + OUTCOME_TAG_OFFSET_IN_BODY;
    assert_eq!(return_frame[outcome_offset], 0);
    let invalid_outcome = mutate_and_reseal(&return_frame, outcome_offset, u8::MAX);
    assert!(matches!(
        decode_x64_native_ipc_record(&invalid_outcome, 0),
        Err(X64NativeIpcError::UnknownTag {
            field: "outcome",
            actual: u8::MAX
        })
    ));

    let return_effect_count_offset = outcome_offset + 1 + 8;
    assert_eq!(read_u32(&return_frame, return_effect_count_offset), 0);
    let fallback_offset = return_effect_count_offset + 4;
    assert_eq!(return_frame[fallback_offset], 0);
    let invalid_fallback = mutate_and_reseal(&return_frame, fallback_offset, 2);
    assert!(matches!(
        decode_x64_native_ipc_record(&invalid_fallback, 0),
        Err(X64NativeIpcError::NonCanonicalBoolean {
            field: "fallback",
            actual: 2
        })
    ));

    let nested_hash_offset = BODY_OFFSET + body_length as usize - HASH_BYTES;
    let invalid_nested_hash = mutate_and_reseal(
        &return_frame,
        nested_hash_offset,
        return_frame[nested_hash_offset] ^ 1,
    );
    assert!(matches!(
        decode_x64_native_ipc_record(&invalid_nested_hash, 0),
        Err(X64NativeIpcError::NativeEvidence(
            X64NativeEvidenceError::ExecutionRecordHashMismatch
        ))
    ));

    let bounds_frame = canonical_frame(46);
    let bounds_outcome_offset = BODY_OFFSET + OUTCOME_TAG_OFFSET_IN_BODY;
    assert_eq!(bounds_frame[bounds_outcome_offset], 2);
    let bounds_effect_count_offset = bounds_outcome_offset + 1;
    assert_eq!(read_u32(&bounds_frame, bounds_effect_count_offset), 1);
    for invalid_count in [2, u32::MAX] {
        let invalid_effect_count =
            mutate_u32_and_reseal(&bounds_frame, bounds_effect_count_offset, invalid_count);
        assert!(matches!(
            decode_x64_native_ipc_record(&invalid_effect_count, 46),
            Err(X64NativeIpcError::CountLimit {
                field: "effect",
                limit: 1,
                actual
            }) if actual == invalid_count
        ));
    }
    let effect_tag_offset = bounds_effect_count_offset + 4;
    assert_eq!(bounds_frame[effect_tag_offset], 0);
    let invalid_effect = mutate_and_reseal(&bounds_frame, effect_tag_offset, u8::MAX);
    assert!(matches!(
        decode_x64_native_ipc_record(&invalid_effect, 46),
        Err(X64NativeIpcError::UnknownTag {
            field: "effect",
            actual: u8::MAX
        })
    ));
}

// Kept independent from the private production helper so mutated frames can
// be resealed without weakening the public codec API.
fn independent_sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((input.len() + 72) & !63);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
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
            let sum1 = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ ((!e) & g))
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(sum1);
            d = c;
            c = b;
            b = a;
            a = sum0.wrapping_add(sum1);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}
