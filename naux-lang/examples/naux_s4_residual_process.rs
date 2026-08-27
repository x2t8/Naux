//! Deterministic fresh-process artifact emitter for S4-WP5E.

#[path = "support/s4_residual_machine_ir.rs"]
#[allow(dead_code)]
mod machine;
#[path = "support/s4_residual_process_elf.rs"]
mod process;
#[path = "support/s4_whole_program_residual.rs"]
mod residual;
#[path = "support/s4_residual_x64_elf.rs"]
#[allow(dead_code)]
mod target;

use machine::lower_residual_machine_ir;
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use process::{append_completion_witness, build_process_elf64};
use residual::{lower_whole_program, verify_work};
use target::{encode_x64, lower_x64_plan};

const N: u64 = 16_384;
const REPS: u64 = 50;
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
        eprintln!("usage: naux-s4-residual-process");
        std::process::exit(2);
    }
    println!("NAUX-S4-RESIDUAL-PROCESS\t1");
    println!("meta\tstatus\tfresh-process-artifact-candidate");
    println!("meta\texecution-owner\twp5e-only");
    println!("meta\ttiming-status\tforbidden");
    println!("meta\tresult-protocol\tfixed-le48-v1");
    println!("meta\tallowed-syscalls\tmmap-munmap-write-exit");
    println!("meta\tlinker\tnone");
    println!("meta\tlibc\tnone");
    println!("meta\ttarget\tx86_64-unknown-linux-gnu");
    println!(
        "columns\tordinal\tkernel\twork-hash\tparent-target-bytes\tprocess-target-bytes\terror-offset\treturn-start\tverifier-offset\tchecksum-displacement\touter-displacement\tinner-displacement\towner-displacement\texpected-outer\texpected-inner\telf-bytes\tstartup-bytes\ttarget-offset"
    );
    for (ordinal, (name, source)) in SOURCES.iter().enumerate() {
        emit_kernel((ordinal + 1) as u64, name, source);
    }
    println!("verification\tregenerated");
}

fn emit_kernel(ordinal: u64, name: &str, source: &str) {
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
    let residual = lower_whole_program(&compile_script(&statements), N, REPS)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let work = verify_work(&residual).unwrap_or_else(|error| fail(name, &error.to_string()));
    let (machine, _) =
        lower_residual_machine_ir(&residual).unwrap_or_else(|error| fail(name, &error.to_string()));
    let plan = lower_x64_plan(&machine).unwrap_or_else(|error| fail(name, &error.to_string()));
    let parent = encode_x64(&plan).unwrap_or_else(|error| fail(name, &error.to_string()));
    let process = append_completion_witness(&plan, &parent, &work, residual.list_local)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let elf = build_process_elf64(&process, ordinal)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let witness = &process.witness;

    println!(
        "kernel\t{ordinal:02}\t{name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        work.semantic_hash(),
        parent.bytes.len(),
        process.bytes.len(),
        witness.error_offset,
        witness.return_start,
        witness.verifier_offset,
        witness.checksum_displacement,
        witness.outer_displacement,
        witness.inner_displacement,
        witness.owner_displacement,
        witness.expected_outer,
        witness.expected_inner,
        elf.bytes.len(),
        elf.startup_bytes,
        elf.target_offset,
    );
    println!("parent-target-hex\t{ordinal:02}\t{}", hex(&parent.bytes));
    println!("target-hex\t{ordinal:02}\t{}", hex(&process.bytes));
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
    eprintln!("S4 residual process failed for `{kernel}`: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use process::{verify_process_elf64, verify_process_target, ProcessElfError};

    fn artifacts(
        source: &str,
        ordinal: u64,
    ) -> (
        residual::ResidualProgram,
        residual::WorkWitness,
        target::X64Plan,
        target::EncodedX64,
        process::ProcessTarget,
        process::ProcessElf64,
    ) {
        let tokens = lexer::lex(source).expect("source lexes");
        let statements = parser::parse_script(&tokens).expect("source parses");
        typecheck::check_program(&statements).expect("source typechecks");
        let residual =
            lower_whole_program(&compile_script(&statements), N, REPS).expect("residual lowers");
        let work = verify_work(&residual).expect("work verifies");
        let (machine, _) = lower_residual_machine_ir(&residual).expect("machine lowers");
        let plan = lower_x64_plan(&machine).expect("plan lowers");
        let parent = encode_x64(&plan).expect("parent encodes");
        let process = append_completion_witness(&plan, &parent, &work, residual.list_local)
            .expect("completion witness appends");
        let elf = build_process_elf64(&process, ordinal).expect("process ELF builds");
        (residual, work, plan, parent, process, elf)
    }

    #[test]
    fn all_frozen_process_artifacts_are_deterministic() {
        for (ordinal, (name, source)) in SOURCES.iter().enumerate() {
            let first = artifacts(source, (ordinal + 1) as u64);
            let second = artifacts(source, (ordinal + 1) as u64);
            assert_eq!(first.3, second.3, "{name} parent drift");
            assert_eq!(first.4, second.4, "{name} process target drift");
            assert_eq!(first.5, second.5, "{name} process ELF drift");
            assert_eq!(first.5.bytes.get(..4), Some(b"\x7fELF".as_slice()));
        }
    }

    #[test]
    fn appendix_preserves_parent_except_for_the_admitted_return_patch() {
        let (_, _, _, parent, process, _) = artifacts(SOURCES[0].1, 1);
        let start = process.witness.return_start as usize;
        assert_eq!(&process.bytes[..start], &parent.bytes[..start]);
        assert_eq!(
            &process.bytes[start + 9..parent.bytes.len()],
            &parent.bytes[start + 9..]
        );
        assert_eq!(process.bytes[start], 0xe9);
        assert!(process.bytes[parent.bytes.len()..].ends_with(&[0xc9, 0xc3]));
    }

    #[test]
    fn target_and_elf_mutations_fail_closed() {
        let (residual, work, plan, parent, mut process, mut elf) = artifacts(SOURCES[1].1, 2);
        process.bytes[0] ^= 1;
        assert!(matches!(
            verify_process_target(&plan, &parent, &work, residual.list_local, &process),
            Err(ProcessElfError::InvalidTarget(_))
        ));

        let (_, _, _, _, process, _) = artifacts(SOURCES[1].1, 2);
        elf.bytes[18] ^= 1;
        assert!(matches!(
            verify_process_elf64(&elf, &process),
            Err(ProcessElfError::InvalidElf(_))
        ));
    }

    #[test]
    fn wrong_work_bound_and_owner_fail_closed() {
        let (residual, mut work, plan, parent, process, _) = artifacts(SOURCES[2].1, 3);
        work.outer.bound += 1;
        assert!(matches!(
            verify_process_target(&plan, &parent, &work, residual.list_local, &process),
            Err(ProcessElfError::InvalidWitness(_))
        ));

        let (residual, work, plan, parent, process, _) = artifacts(SOURCES[2].1, 3);
        assert!(matches!(
            verify_process_target(
                &plan,
                &parent,
                &work,
                residual.list_local + residual.local_count,
                &process,
            ),
            Err(ProcessElfError::InvalidWitness(_))
        ));
    }

    #[test]
    fn zero_ordinal_is_rejected() {
        let (_, _, _, _, process, _) = artifacts(SOURCES[3].1, 4);
        assert!(matches!(
            build_process_elf64(&process, 0),
            Err(ProcessElfError::InvalidElf(_))
        ));
    }
}
