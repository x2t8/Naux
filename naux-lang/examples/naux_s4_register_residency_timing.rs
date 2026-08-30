//! Deterministic, non-executing timing-carrier emitter for the S4-WP8J
//! register-residency candidate.

#[path = "support/s4_residual_machine_ir.rs"]
#[allow(dead_code)]
mod machine;
#[path = "support/s4_residual_process_elf.rs"]
#[allow(dead_code)]
mod process_envelope;
#[path = "support/s4_register_residency_plan.rs"]
#[allow(dead_code)]
mod residency;
#[path = "support/s4_register_residency_encoding.rs"]
#[allow(dead_code)]
mod residency_encoding;
#[path = "support/s4_register_residency_process.rs"]
#[allow(dead_code)]
mod residency_process;
#[path = "support/s4_register_residency_timing_elf.rs"]
mod residency_timing;
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
use process_envelope as process;
use residency::{lower_register_residency, Selection};
use residency_encoding::encode_register_residency;
use residency_process::append_residency_completion_witness;
use residency_timing::build_candidate_timing_elf64;
use residual::{lower_whole_program, verify_work};
use target as baseline;
use target::{encode_x64, lower_x64_plan};

const N: u64 = 16_384;
const REPS: u64 = 50;
const SOURCES: [(&str, i64, &str, Selection); 4] = [
    (
        "sum-dense",
        6_710_476_800,
        include_str!("../../benchmarks/s4/naux/sum_dense.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "branch-mix",
        -69_189_632,
        include_str!("../../benchmarks/s4/naux/branch_mix.nx"),
        Selection {
            slot: 6,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "dot-product",
        73_294_064_435_200,
        include_str!("../../benchmarks/s4/naux/dot_product.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "list-update",
        6_730_547_200,
        include_str!("../../benchmarks/s4/naux/list_update.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 4,
            expected_static_writes: 2,
        },
    ),
];

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: naux-s4-register-residency-timing");
        std::process::exit(2);
    }
    println!("NAUX-S4-REGISTER-RESIDENCY-TIMING-CARRIER\t1");
    println!("meta\tstatus\tregister-residency-timing-carrier-candidate");
    println!("meta\texecution-status\tforbidden");
    println!("meta\tclock-source\tclock-monotonic-raw");
    println!("meta\tclock-placement\tbefore-target-after-checksum-validation");
    println!("meta\tresult-protocol\tfixed-le56-v1");
    println!("meta\tresult-owner-policy\ttarget-rsi-zero-before-stop-record-role-four-after-stop");
    println!("meta\tallowed-syscalls\tmmap-munmap-clock-gettime-write-exit");
    println!("meta\ttarget\tx86_64-unknown-linux-gnu");
    println!(
        "columns\tordinal\tkernel\twork-hash\toracle\tprocess-target-bytes\ttiming-elf-bytes\tstartup-bytes\ttarget-offset"
    );
    for (index, (name, oracle, source, selection)) in SOURCES.iter().enumerate() {
        emit_kernel((index + 1) as u64, name, *oracle, source, *selection);
    }
    println!("verification\tregenerated-no-execution");
}

fn emit_kernel(ordinal: u64, name: &str, oracle: i64, source: &str, selection: Selection) {
    let (work_hash, process) = process_target(name, source, selection);
    let elf = build_candidate_timing_elf64(&process, ordinal, oracle)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    println!(
        "kernel\t{ordinal:02}\t{name}\t{work_hash}\t{oracle}\t{}\t{}\t{}\t{}",
        process.bytes.len(),
        elf.bytes.len(),
        elf.startup_bytes,
        elf.target_offset,
    );
    println!("target-hex\t{ordinal:02}\t{}", hex(&process.bytes));
    println!("elf-hex\t{ordinal:02}\t{}", hex(&elf.bytes));
}

fn process_target(
    name: &str,
    source: &str,
    selection: Selection,
) -> (String, process::ProcessTarget) {
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
    let work_hash = work.semantic_hash().to_string();
    let owner_local = residual.list_local;
    let (machine, _) =
        lower_residual_machine_ir(&residual).unwrap_or_else(|error| fail(name, &error.to_string()));
    let baseline_plan =
        lower_x64_plan(&machine).unwrap_or_else(|error| fail(name, &error.to_string()));
    let baseline =
        encode_x64(&baseline_plan).unwrap_or_else(|error| fail(name, &error.to_string()));
    let residency_plan = lower_register_residency(&machine, &baseline_plan, selection)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let candidate = encode_register_residency(&machine, &baseline_plan, &residency_plan, &baseline)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let process = append_residency_completion_witness(
        &machine,
        &baseline_plan,
        &residency_plan,
        &baseline,
        &candidate,
        &work,
        owner_local,
    )
    .unwrap_or_else(|error| fail(name, &error.to_string()));
    (work_hash, process)
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
    eprintln!("S4 register-residency timing carrier failed for `{kernel}`: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use residency_timing::{verify_candidate_timing_elf64, CandidateTimingElfError};
    use timing::{RESULT_BYTES, RESULT_MAGIC};

    fn artifact(index: usize) -> (process::ProcessTarget, timing::TimingElf64) {
        let (name, oracle, source, selection) = SOURCES[index];
        let (_, process) = process_target(name, source, selection);
        let elf = build_candidate_timing_elf64(&process, (index + 1) as u64, oracle)
            .expect("timing ELF builds");
        (process, elf)
    }

    #[test]
    fn all_four_candidate_timing_images_are_deterministic_and_unexecuted() {
        for index in 0..SOURCES.len() {
            let first = artifact(index);
            let second = artifact(index);
            assert_eq!(first, second);
            let facts = verify_candidate_timing_elf64(&first.1, &first.0).expect("image verifies");
            assert_eq!(facts.clock_reads, 2);
            assert_eq!(facts.owner_zero_checks, 1);
            assert_eq!(facts.result_bytes, u64::from(RESULT_BYTES));
            assert_eq!(facts.result_owner, 4);
            assert_eq!(first.1.bytes.get(..4), Some(b"\x7fELF".as_slice()));
        }
    }

    #[test]
    fn exact_candidate_process_is_embedded_after_the_timing_startup() {
        let (process, elf) = artifact(0);
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
    fn image_receipt_and_empty_target_mutations_fail_closed() {
        let (process, mut elf) = artifact(1);
        elf.bytes[18] ^= 1;
        assert!(matches!(
            verify_candidate_timing_elf64(&elf, &process),
            Err(CandidateTimingElfError::Specialization(_))
        ));

        let (mut process, _) = artifact(2);
        process.bytes.clear();
        assert!(matches!(
            build_candidate_timing_elf64(&process, 3, SOURCES[2].1),
            Err(CandidateTimingElfError::Parent(_))
        ));
    }
}
