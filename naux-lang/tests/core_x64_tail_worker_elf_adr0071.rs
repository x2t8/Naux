#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    admit_x64_tail_worker_artifact, decode_x64_tail_worker_elf, emit_x64_tail_worker_elf_evidence,
    probe_x64_tail_worker_elf_evidence_mutations, verify_x64_tail_worker_elf_evidence,
    x64_tail_worker_elf_policy_hash, x64_tail_worker_expectation_from_reviewed_bytes,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_GNU_STACK: u32 = 0x6474_e551;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_NULL: i64 = 0;
const DT_RUNPATH: i64 = 29;

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-tail-enveloped-worker"))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn program_header_offset(bytes: &[u8], segment_type: u32, occurrence: usize) -> usize {
    let table = usize::try_from(read_u64(bytes, 32)).unwrap();
    let count = usize::from(read_u16(bytes, 56));
    let width = usize::from(read_u16(bytes, 54));
    let mut seen = 0;
    for ordinal in 0..count {
        let offset = table + ordinal * width;
        if read_u32(bytes, offset) == segment_type {
            if seen == occurrence {
                return offset;
            }
            seen += 1;
        }
    }
    panic!("missing program header {segment_type:#x}/{occurrence}");
}

fn dynamic_entry_offset(bytes: &[u8], tag: i64) -> usize {
    let program = program_header_offset(bytes, PT_DYNAMIC, 0);
    let table = usize::try_from(read_u64(bytes, program + 8)).unwrap();
    let size = usize::try_from(read_u64(bytes, program + 32)).unwrap();
    for offset in (table..table + size).step_by(16) {
        if read_u64(bytes, offset) as i64 == tag {
            return offset;
        }
    }
    panic!("missing dynamic tag {tag:#x}");
}

fn assert_structural_mutation_rejected(bytes: Vec<u8>, label: &str) {
    let expectation = x64_tail_worker_expectation_from_reviewed_bytes(&bytes)
        .expect("mutated artifact remains inside the outer byte cap");
    assert!(
        decode_x64_tail_worker_elf(&bytes, &expectation).is_err(),
        "structural mutation {label} must fail"
    );
}

#[test]
fn adr0071_independently_inventories_the_exact_sealed_worker() {
    let inventory_source = include_str!("../src/core/x64_tail_worker_elf.rs");
    let imports = inventory_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "x64_tail_enveloped_native",
        "emit_x64_tail_enveloped_correspondence",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "measurement",
        "std::process",
    ] {
        assert!(
            !imports.contains(forbidden),
            "inventory imports forbidden authority {forbidden}"
        );
    }

    let bytes = fs::read(worker()).expect("read reviewed worker");
    let expectation = x64_tail_worker_expectation_from_reviewed_bytes(&bytes).unwrap();
    let artifact = admit_x64_tail_worker_artifact(worker(), expectation.clone()).unwrap();
    let evidence = emit_x64_tail_worker_elf_evidence(&artifact)
        .expect("the exact reviewed worker must produce a bounded inventory");
    let verified = verify_x64_tail_worker_elf_evidence(&artifact, &evidence)
        .expect("inventory must replay from the sealed artifact");
    assert_eq!(verified.evidence(), &evidence);
    assert_eq!(evidence.artifact_hash(), expectation.artifact_hash());
    assert_eq!(evidence.policy_hash(), x64_tail_worker_elf_policy_hash());
    assert!(evidence.interpreter().starts_with('/'));
    assert!(evidence.header().program_header_count() > 0);
    assert_eq!(
        evidence.totals().program_headers(),
        evidence.header().program_header_count()
    );
    assert_eq!(
        evidence.totals().dynamic_entries(),
        u16::try_from(evidence.dynamic_entries().len()).unwrap()
    );
    assert_eq!(
        evidence.totals().dependencies(),
        u16::try_from(evidence.dependencies().len()).unwrap()
    );
    assert!(evidence.totals().load_segments() > 0);
    assert!(!evidence.dependencies().is_empty());
    let names = evidence
        .dependencies()
        .iter()
        .map(|dependency| dependency.name())
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), evidence.dependencies().len());
    assert!(names.contains("libc.so.6"));
    assert!(evidence.dynamic_flags() != 0);
    assert!(evidence.dynamic_flags_1() != 0);
    assert_eq!(
        decode_x64_tail_worker_elf(&bytes, &expectation).unwrap(),
        evidence
    );
    assert!(probe_x64_tail_worker_elf_evidence_mutations(
        &artifact, &evidence
    ));
}

#[test]
fn adr0071_rejects_identity_layout_loader_and_dynamic_mutations() {
    let original = fs::read(worker()).expect("read reviewed worker");

    let mut mutation = original.clone();
    mutation[0] ^= 1;
    assert_structural_mutation_rejected(mutation, "magic");

    let mut mutation = original.clone();
    mutation[4] = 1;
    assert_structural_mutation_rejected(mutation, "class");

    let mut mutation = original.clone();
    write_u16(&mut mutation, 18, 183);
    assert_structural_mutation_rejected(mutation, "machine");

    let mut mutation = original.clone();
    write_u16(&mut mutation, 54, 55);
    assert_structural_mutation_rejected(mutation, "program header width");

    let mut mutation = original.clone();
    write_u16(&mut mutation, 56, 65);
    assert_structural_mutation_rejected(mutation, "program header cap");

    let mut mutation = original.clone();
    let load = program_header_offset(&mutation, PT_LOAD, 0);
    write_u32(&mut mutation, load + 4, 7);
    assert_structural_mutation_rejected(mutation, "writable executable load");

    let mut mutation = original.clone();
    let stack = program_header_offset(&mutation, PT_GNU_STACK, 0);
    let stack_flags = read_u32(&mutation, stack + 4);
    write_u32(&mut mutation, stack + 4, stack_flags | 1);
    assert_structural_mutation_rejected(mutation, "executable stack");

    let mut mutation = original.clone();
    let note = program_header_offset(&mutation, PT_NOTE, 0);
    write_u32(&mut mutation, note, 0xffff_ffff);
    assert_structural_mutation_rejected(mutation, "unknown segment");

    let mut mutation = original.clone();
    let interpreter = program_header_offset(&mutation, PT_INTERP, 0);
    let interpreter_offset = usize::try_from(read_u64(&mutation, interpreter + 8)).unwrap();
    let interpreter_size = usize::try_from(read_u64(&mutation, interpreter + 32)).unwrap();
    mutation[interpreter_offset + interpreter_size - 1] = b'x';
    assert_structural_mutation_rejected(mutation, "interpreter terminator");

    let mut mutation = original.clone();
    let needed = dynamic_entry_offset(&mutation, DT_NEEDED);
    write_u64(&mut mutation, needed, DT_RUNPATH as u64);
    assert_structural_mutation_rejected(mutation, "embedded RUNPATH");

    let mut mutation = original.clone();
    let string_table = dynamic_entry_offset(&mutation, DT_STRTAB);
    write_u64(&mut mutation, string_table + 8, u64::MAX);
    assert_structural_mutation_rejected(mutation, "string table mapping");

    let mut mutation = original.clone();
    let needed = dynamic_entry_offset(&mutation, DT_NEEDED);
    write_u64(&mut mutation, needed + 8, u64::MAX);
    assert_structural_mutation_rejected(mutation, "dependency offset");

    let mut mutation = original.clone();
    let null = dynamic_entry_offset(&mutation, DT_NULL);
    write_u64(&mut mutation, null + 8, 1);
    assert_structural_mutation_rejected(mutation, "dynamic NULL value");

    let mut mutation = original;
    mutation.pop();
    assert_structural_mutation_rejected(mutation, "truncation");
}
