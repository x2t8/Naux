//! Deterministic, non-executing S4-WP7B residual timing-carrier emitter.

#[path = "support/s4_residual_machine_ir.rs"]
#[allow(dead_code)]
mod machine;
#[path = "support/s4_residual_process_elf.rs"]
#[allow(dead_code)]
mod process;
#[path = "support/s4_whole_program_residual.rs"]
mod residual;
#[path = "support/s4_residual_x64_elf.rs"]
#[allow(dead_code)]
mod target;
#[path = "support/s4_residual_timing_elf.rs"]
mod timing;

use machine::lower_residual_machine_ir;
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use process::append_completion_witness;
use residual::{lower_whole_program, verify_work};
use target::{encode_x64, lower_x64_plan};
use timing::build_timing_elf64;

const N: u64 = 16_384;
const REPS: u64 = 50;
const SOURCES: [(&str, i64, &str); 4] = [
    (
        "sum-dense",
        6_710_476_800,
        include_str!("../../benchmarks/s4/naux/sum_dense.nx"),
    ),
    (
        "branch-mix",
        -69_189_632,
        include_str!("../../benchmarks/s4/naux/branch_mix.nx"),
    ),
    (
        "dot-product",
        73_294_064_435_200,
        include_str!("../../benchmarks/s4/naux/dot_product.nx"),
    ),
    (
        "list-update",
        6_730_547_200,
        include_str!("../../benchmarks/s4/naux/list_update.nx"),
    ),
];

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: naux-s4-residual-timing");
        std::process::exit(2);
    }
    println!("NAUX-S4-RESIDUAL-TIMING-CARRIER\t1");
    println!("meta\tstatus\tstructural-timing-carrier-candidate");
    println!("meta\texecution-status\tforbidden");
    println!("meta\tclock-source\tclock-monotonic-raw");
    println!("meta\tclock-placement\tbefore-target-after-checksum-validation");
    println!("meta\tresult-protocol\tfixed-le56-v1");
    println!("meta\tallowed-syscalls\tmmap-munmap-clock-gettime-write-exit");
    println!("meta\ttarget\tx86_64-unknown-linux-gnu");
    println!(
        "columns\tordinal\tkernel\twork-hash\toracle\tprocess-target-bytes\ttiming-elf-bytes\tstartup-bytes\ttarget-offset"
    );
    for (ordinal, (name, oracle, source)) in SOURCES.iter().enumerate() {
        emit_kernel((ordinal + 1) as u64, name, *oracle, source);
    }
    println!("verification\tregenerated-no-execution");
}

fn emit_kernel(ordinal: u64, name: &str, oracle: i64, source: &str) {
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
    let elf = build_timing_elf64(&process, ordinal, oracle)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    println!(
        "kernel\t{ordinal:02}\t{name}\t{}\t{oracle}\t{}\t{}\t{}\t{}",
        work.semantic_hash(),
        process.bytes.len(),
        elf.bytes.len(),
        elf.startup_bytes,
        elf.target_offset,
    );
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
    eprintln!("S4 residual timing carrier failed for `{kernel}`: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use timing::{verify_timing_elf64, TimingElfError, RESULT_BYTES, RESULT_MAGIC};

    fn artifacts(
        source: &str,
        ordinal: u64,
        oracle: i64,
    ) -> (process::ProcessTarget, timing::TimingElf64) {
        let tokens = lexer::lex(source).expect("source lexes");
        let statements = parser::parse_script(&tokens).expect("source parses");
        typecheck::check_program(&statements).expect("source typechecks");
        let residual =
            lower_whole_program(&compile_script(&statements), N, REPS).expect("residual lowers");
        let work = verify_work(&residual).expect("work verifies");
        let (machine, _) = lower_residual_machine_ir(&residual).expect("machine lowers");
        let plan = lower_x64_plan(&machine).expect("plan lowers");
        let parent = encode_x64(&plan).expect("target encodes");
        let process = append_completion_witness(&plan, &parent, &work, residual.list_local)
            .expect("completion witness appends");
        let elf = build_timing_elf64(&process, ordinal, oracle).expect("timing ELF builds");
        (process, elf)
    }

    #[test]
    fn all_timing_images_are_deterministic_and_never_executed() {
        for (index, (name, oracle, source)) in SOURCES.iter().enumerate() {
            let first = artifacts(source, (index + 1) as u64, *oracle);
            let second = artifacts(source, (index + 1) as u64, *oracle);
            assert_eq!(first, second, "{name} timing carrier drifted");
            let facts = verify_timing_elf64(&first.1, &first.0).expect("image verifies");
            assert_eq!(facts.clock_reads, 2);
            assert_eq!(facts.result_bytes, u64::from(RESULT_BYTES));
            assert_eq!(first.1.bytes.get(..4), Some(b"\x7fELF".as_slice()));
        }
    }

    #[test]
    fn sealed_process_target_is_embedded_byte_for_byte() {
        let (process, elf) = artifacts(SOURCES[0].2, 1, SOURCES[0].1);
        assert_eq!(
            elf.bytes.get(elf.target_offset as usize..),
            Some(process.bytes.as_slice())
        );
        let startup = &elf.bytes[0x100..elf.target_offset as usize];
        assert!(startup
            .windows(RESULT_MAGIC.len())
            .any(|window| window == RESULT_MAGIC));
        assert_eq!(
            startup
                .windows(2)
                .filter(|window| *window == [0x0f, 0x05])
                .count(),
            5
        );
    }

    #[test]
    fn image_and_receipt_mutations_fail_closed() {
        let (process, mut elf) = artifacts(SOURCES[1].2, 2, SOURCES[1].1);
        elf.bytes[18] ^= 1;
        assert!(matches!(
            verify_timing_elf64(&elf, &process),
            Err(TimingElfError::InvalidElf(_))
        ));

        let (process, mut elf) = artifacts(SOURCES[1].2, 2, SOURCES[1].1);
        elf.oracle += 1;
        assert!(matches!(
            verify_timing_elf64(&elf, &process),
            Err(TimingElfError::InvalidElf(_))
        ));
    }

    #[test]
    fn zero_ordinal_and_empty_target_are_rejected() {
        let (process, _) = artifacts(SOURCES[2].2, 3, SOURCES[2].1);
        assert!(matches!(
            build_timing_elf64(&process, 0, SOURCES[2].1),
            Err(TimingElfError::InvalidInput(_))
        ));
        let mut empty = process;
        empty.bytes.clear();
        assert!(matches!(
            build_timing_elf64(&empty, 3, SOURCES[2].1),
            Err(TimingElfError::InvalidInput(_))
        ));
    }
}
