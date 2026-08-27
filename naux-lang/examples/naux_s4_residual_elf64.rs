//! Deterministic Machine-IR-to-x86-64/ELF64 emitter for S4-WP5D.

#[path = "support/s4_residual_machine_ir.rs"]
#[allow(dead_code)]
mod machine;
#[path = "support/s4_whole_program_residual.rs"]
mod residual;
#[path = "support/s4_residual_x64_elf.rs"]
mod target;

use machine::{lower_residual_machine_ir, MappingKind};
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use residual::lower_whole_program;
use target::{build_elf64, encode_x64, lower_x64_plan, EncodingKind};

const SOURCES: [(&str, &str); 4] = [
    (
        "sum-dense",
        include_str!("../../benchmarks/s4/naux/sum_dense.nx"),
    ),
    (
        "branch-mix",
        include_str!("../../benchmarks/s4/naux/branch_mix.nx"),
    ),
    (
        "dot-product",
        include_str!("../../benchmarks/s4/naux/dot_product.nx"),
    ),
    (
        "list-update",
        include_str!("../../benchmarks/s4/naux/list_update.nx"),
    ),
];

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: naux-s4-residual-elf64");
        std::process::exit(2);
    }
    println!("NAUX-S4-RESIDUAL-ELF64\t1");
    println!("meta\tstatus\tx86-64-elf64-structurally-admitted");
    println!("meta\texecution-status\tforbidden");
    println!("meta\ttiming-status\tforbidden");
    println!("meta\tlinker\tnone");
    println!("meta\tlibc\tnone");
    println!("meta\ttarget\tx86_64-unknown-linux-gnu");
    println!(
        "columns\tordinal\tkernel\tmachine-hash\tframe-bytes\tblock-count\toperation-count\tterminator-count\tmapping-count\ttarget-bytes\terror-offset\telf-bytes\ttarget-offset"
    );
    for (ordinal, (name, source)) in SOURCES.iter().enumerate() {
        emit_kernel(ordinal + 1, name, source);
    }
    println!("verification\tregenerated");
}

fn emit_kernel(ordinal: usize, name: &str, source: &str) {
    let tokens = lexer::lex(source)
        .unwrap_or_else(|error| fail(name, &format!("lexer rejected source: {}", error.message)));
    let statements = parser::parse_script(&tokens)
        .unwrap_or_else(|error| fail(name, &format!("parser rejected source: {}", error.message)));
    typecheck::check_program(&statements).unwrap_or_else(|error| {
        fail(
            name,
            &format!("typechecker rejected source: {}", error.message),
        )
    });
    let residual = lower_whole_program(&compile_script(&statements), 16_384, 50)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let (machine, correspondence) =
        lower_residual_machine_ir(&residual).unwrap_or_else(|error| fail(name, &error.to_string()));
    let plan = lower_x64_plan(&machine).unwrap_or_else(|error| fail(name, &error.to_string()));
    let encoded = encode_x64(&plan).unwrap_or_else(|error| fail(name, &error.to_string()));
    let elf = build_elf64(&encoded).unwrap_or_else(|error| fail(name, &error.to_string()));

    println!(
        "kernel\t{ordinal:02}\t{name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        correspondence.machine_hash,
        plan.frame_bytes,
        plan.blocks.len(),
        plan.operation_count(),
        plan.terminator_count(),
        correspondence.mapping_count,
        encoded.bytes.len(),
        encoded.error_offset,
        elf.bytes.len(),
        elf.target_offset,
    );
    for block in &plan.blocks {
        println!(
            "block\t{ordinal:02}\t{}\t{}",
            block.id,
            block.operations.len()
        );
        for (operation, value) in block.operations.iter().enumerate() {
            println!(
                "operation\t{ordinal:02}\t{}\t{}\t{}",
                block.id,
                operation,
                value.canonical_text()
            );
        }
        println!(
            "terminator\t{ordinal:02}\t{}\t{}",
            block.id,
            block.terminator.canonical_text()
        );
    }
    for range in &encoded.ranges {
        let kind = match range.kind {
            EncodingKind::Operation => "operation",
            EncodingKind::Terminator => "terminator",
        };
        println!(
            "encoding\t{ordinal:02}\t{}\t{}\t{}\t{}\t{}",
            range.block, range.ordinal, kind, range.start, range.end
        );
    }
    for mapping in &machine.source_map {
        let kind = match mapping.kind {
            MappingKind::Instruction => "operation",
            MappingKind::Terminator => "terminator",
        };
        println!(
            "correspondence\t{ordinal:02}\t{}\t{}\t{}\t{}",
            mapping.residual_ip, mapping.block, mapping.machine_ordinal, kind
        );
    }
    println!("target-hex\t{ordinal:02}\t{}", hex(&encoded.bytes));
    println!("elf-hex\t{ordinal:02}\t{}", hex(&elf.bytes));
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

fn fail(kernel: &str, message: &str) -> ! {
    eprintln!("S4 residual ELF64 failed for `{kernel}`: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use machine::{IntegerBinary, MachineInstruction};
    use target::{verify_elf64, verify_plan, verify_x64_encoding, X64ElfError};

    fn artifacts(
        source: &str,
    ) -> (
        machine::ResidualMachineProgram,
        target::X64Plan,
        target::EncodedX64,
        target::Elf64Image,
    ) {
        let tokens = lexer::lex(source).expect("source lexes");
        let statements = parser::parse_script(&tokens).expect("source parses");
        typecheck::check_program(&statements).expect("source typechecks");
        let residual =
            lower_whole_program(&compile_script(&statements), 16_384, 50).expect("residual lowers");
        let (machine, _) = lower_residual_machine_ir(&residual).expect("machine lowers");
        let plan = lower_x64_plan(&machine).expect("target plan lowers");
        let encoded = encode_x64(&plan).expect("target encodes");
        let elf = build_elf64(&encoded).expect("ELF builds");
        (machine, plan, encoded, elf)
    }

    #[test]
    fn all_frozen_kernels_lower_deterministically() {
        for (name, source) in SOURCES {
            let (_, first_plan, first_encoding, first_elf) = artifacts(source);
            let (_, second_plan, second_encoding, second_elf) = artifacts(source);
            assert_eq!(first_plan, second_plan, "{name} target-plan drift");
            assert_eq!(first_encoding, second_encoding, "{name} encoding drift");
            assert_eq!(first_elf, second_elf, "{name} ELF drift");
            assert_eq!(first_elf.bytes.get(..4), Some(b"\x7fELF".as_slice()));
            assert_eq!(first_elf.target_bytes as usize, first_encoding.bytes.len());
        }
    }

    #[test]
    fn target_byte_mutation_fails_closed() {
        let (_, plan, mut encoded, _) = artifacts(SOURCES[0].1);
        encoded.bytes[0] ^= 1;
        assert!(matches!(
            verify_x64_encoding(&plan, &encoded),
            Err(X64ElfError::Encoding(_))
        ));
    }

    #[test]
    fn elf_header_mutation_fails_closed() {
        let (_, _, encoded, mut elf) = artifacts(SOURCES[1].1);
        elf.bytes[18] ^= 1;
        assert!(matches!(
            verify_elf64(&elf, &encoded),
            Err(X64ElfError::InvalidElf(_))
        ));
    }

    #[test]
    fn executable_stack_is_rejected() {
        let (_, _, encoded, mut elf) = artifacts(SOURCES[2].1);
        let stack_flags = 64 + 56 + 4;
        elf.bytes[stack_flags..stack_flags + 4].copy_from_slice(&7_u32.to_le_bytes());
        assert!(matches!(
            verify_elf64(&elf, &encoded),
            Err(X64ElfError::InvalidElf(_))
        ));
    }

    #[test]
    fn unsupported_integer_opcode_never_sneaks_into_wp5d() {
        let (mut machine, _, _, _) = artifacts(SOURCES[0].1);
        let operation = machine
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.instructions)
            .find_map(|instruction| match instruction {
                MachineInstruction::IntegerBinary { operation, .. } => Some(operation),
                _ => None,
            })
            .expect("kernel has integer binary operation");
        *operation = IntegerBinary::Div;
        assert!(matches!(
            lower_x64_plan(&machine),
            Err(X64ElfError::Unsupported(_))
        ));
    }

    #[test]
    fn list_store_loads_the_value_after_the_bounds_check() {
        let (_, plan, encoded, _) = artifacts(SOURCES[3].1);
        let (block, ordinal, value) = plan
            .blocks
            .iter()
            .find_map(|block| {
                block
                    .operations
                    .iter()
                    .enumerate()
                    .find_map(|(ordinal, operation)| match operation {
                        target::X64Operation::ListStoreChecked { value, .. } => {
                            Some((block.id, ordinal as u32, *value))
                        }
                        _ => None,
                    })
            })
            .expect("list-update has a checked list store");
        let range = encoded
            .ranges
            .iter()
            .find(|range| {
                range.block == block
                    && range.ordinal == ordinal
                    && range.kind == target::EncodingKind::Operation
            })
            .expect("checked list store has an encoding range");
        let bytes = &encoded.bytes[range.start as usize..range.end as usize];

        assert_eq!(bytes.len(), 63, "checked store encoding length drifted");
        assert_eq!(&bytes[14..17], &[0x48, 0x85, 0xc9]);
        assert_eq!(&bytes[23..25], &[0x48, 0xba]);
        assert_eq!(&bytes[42..45], &[0x48, 0x8b, 0x95]);
        assert_eq!(&bytes[45..49], &value.displacement.to_le_bytes());
        assert_eq!(&bytes[49..53], &[0x48, 0x89, 0x14, 0xc8]);
    }

    #[test]
    fn noncanonical_or_undeclared_stack_homes_fail_closed() {
        let (_, mut plan, _, _) = artifacts(SOURCES[0].1);
        plan.register_homes[0].displacement = -1;
        assert!(matches!(
            verify_plan(&plan),
            Err(X64ElfError::InvalidPlan(_))
        ));

        let (_, mut plan, _, _) = artifacts(SOURCES[0].1);
        let target::X64Operation::ConstI64 { result, .. } = &mut plan.blocks[0].operations[0]
        else {
            panic!("first frozen operation is const-i64");
        };
        result.displacement -= 8;
        assert!(matches!(
            verify_plan(&plan),
            Err(X64ElfError::InvalidPlan(_))
        ));
    }

    #[test]
    fn encoding_verifier_rejects_bad_cfg_without_indexing_it() {
        let (_, mut plan, encoded, _) = artifacts(SOURCES[0].1);
        plan.blocks[0].terminator = target::X64Terminator::Goto { target: u32::MAX };
        assert!(matches!(
            verify_x64_encoding(&plan, &encoded),
            Err(X64ElfError::InvalidPlan(_))
        ));
    }

    #[test]
    fn elf_verifier_rejects_an_empty_target_envelope() {
        let (_, _, _, elf) = artifacts(SOURCES[0].1);
        let empty = target::EncodedX64 {
            bytes: Vec::new(),
            block_offsets: Vec::new(),
            error_offset: 0,
            ranges: Vec::new(),
        };
        assert!(matches!(
            verify_elf64(&elf, &empty),
            Err(X64ElfError::InvalidElf(_))
        ));
    }

    #[test]
    fn image_contains_no_sections_and_no_writable_code_segment() {
        let (_, _, _, elf) = artifacts(SOURCES[3].1);
        assert_eq!(&elf.bytes[40..48], &0_u64.to_le_bytes());
        assert_eq!(&elf.bytes[48..52], &0_u32.to_le_bytes());
        assert_eq!(&elf.bytes[68..72], &5_u32.to_le_bytes());
        assert_eq!(&elf.bytes[60..62], &0_u16.to_le_bytes());
    }
}
