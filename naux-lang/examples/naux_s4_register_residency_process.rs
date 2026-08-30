//! Deterministic fresh-process candidate emitter for S4-WP8G.

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
mod residency_process;
#[path = "support/s4_whole_program_residual.rs"]
mod residual;
#[path = "support/s4_residual_x64_elf.rs"]
#[allow(dead_code)]
mod target;

use baseline::{encode_x64, lower_x64_plan};
use machine::lower_residual_machine_ir;
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use residency::{lower_register_residency, Selection};
use residency_encoding::encode_register_residency;
use residency_process::{append_residency_completion_witness, build_residency_process_elf64};
use residual::{lower_whole_program, verify_work};
use target as baseline;

const N: u64 = 16_384;
const REPS: u64 = 50;
const SOURCES: [(&str, &str, Selection); 4] = [
    (
        "sum-dense",
        include_str!("../../benchmarks/s4/naux/sum_dense.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "branch-mix",
        include_str!("../../benchmarks/s4/naux/branch_mix.nx"),
        Selection {
            slot: 6,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "dot-product",
        include_str!("../../benchmarks/s4/naux/dot_product.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "list-update",
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
        eprintln!("usage: naux-s4-register-residency-process");
        std::process::exit(2);
    }
    println!("NAUX-S4-REGISTER-RESIDENCY-PROCESS\t1");
    println!("meta\tstatus\tfresh-process-artifact-candidate");
    println!("meta\texecution-owner\twp8g-only");
    println!("meta\ttiming-status\tforbidden");
    println!("meta\tresult-protocol\tfixed-le48-v1");
    println!("meta\tallowed-syscalls\tmmap-munmap-write-exit");
    println!("meta\tlinker\tnone");
    println!("meta\tlibc\tnone");
    println!("meta\ttarget\tx86_64-unknown-linux-gnu");
    println!(
        "columns\tordinal\tkernel\twork-hash\tcandidate-target-bytes\tprocess-target-bytes\terror-offset\treturn-start\tverifier-offset\tchecksum-displacement\touter-displacement\tinner-displacement\towner-displacement\texpected-outer\texpected-inner\telf-bytes\tstartup-bytes\ttarget-offset"
    );
    for (ordinal, (name, source, selection)) in SOURCES.iter().enumerate() {
        emit_kernel((ordinal + 1) as u64, name, source, *selection);
    }
    println!("verification\tregenerated");
}

fn emit_kernel(ordinal: u64, name: &str, source: &str, selection: Selection) {
    let artifact = artifacts(name, source, selection, ordinal);
    let witness = &artifact.process.witness;
    println!(
        "kernel\t{ordinal:02}\t{name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        artifact.work.semantic_hash(),
        artifact.candidate.bytes.len(),
        artifact.process.bytes.len(),
        witness.error_offset,
        witness.return_start,
        witness.verifier_offset,
        witness.checksum_displacement,
        witness.outer_displacement,
        witness.inner_displacement,
        witness.owner_displacement,
        witness.expected_outer,
        witness.expected_inner,
        artifact.elf.bytes.len(),
        artifact.elf.startup_bytes,
        artifact.elf.target_offset,
    );
    println!(
        "candidate-target-hex\t{ordinal:02}\t{}",
        hex(&artifact.candidate.bytes)
    );
    println!("target-hex\t{ordinal:02}\t{}", hex(&artifact.process.bytes));
    println!("elf-hex\t{ordinal:02}\t{}", hex(&artifact.elf.bytes));
}

#[cfg_attr(not(test), allow(dead_code))]
struct Artifacts {
    machine: machine::ResidualMachineProgram,
    baseline_plan: baseline::X64Plan,
    residency_plan: residency::ResidencyPlan,
    baseline: baseline::EncodedX64,
    candidate: residency_encoding::ResidencyEncodedX64,
    work: residual::WorkWitness,
    owner_local: u32,
    process: process_envelope::ProcessTarget,
    elf: process_envelope::ProcessElf64,
}

fn artifacts(name: &str, source: &str, selection: Selection, ordinal: u64) -> Artifacts {
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
    let elf = build_residency_process_elf64(&process, ordinal)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    Artifacts {
        machine,
        baseline_plan,
        residency_plan,
        baseline,
        candidate,
        work,
        owner_local,
        process,
        elf,
    }
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
    eprintln!("S4 residency process failed for `{kernel}`: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use residency_process::{verify_residency_process_target, ResidencyProcessError};

    #[test]
    fn all_four_process_images_are_deterministic() {
        for (index, (name, source, selection)) in SOURCES.iter().enumerate() {
            let ordinal = (index + 1) as u64;
            let first = artifacts(name, source, *selection, ordinal);
            let second = artifacts(name, source, *selection, ordinal);
            assert_eq!(first.candidate, second.candidate, "{name} candidate drift");
            assert_eq!(first.process, second.process, "{name} process drift");
            assert_eq!(first.elf, second.elf, "{name} ELF drift");
            assert_eq!(first.elf.bytes.get(..4), Some(b"\x7fELF".as_slice()));
        }
    }

    #[test]
    fn appendix_preserves_candidate_except_final_return_patch() {
        let artifact = artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].2, 1);
        let start = artifact.process.witness.return_start as usize;
        assert_eq!(
            &artifact.process.bytes[..start],
            &artifact.candidate.bytes[..start]
        );
        assert_eq!(
            &artifact.process.bytes[start + 16..artifact.candidate.bytes.len()],
            &artifact.candidate.bytes[start + 16..]
        );
        assert_eq!(artifact.process.bytes[start], 0xe9);
        assert!(artifact.process.bytes[start + 5..start + 16]
            .iter()
            .all(|byte| *byte == 0x90));
        assert!(artifact.process.bytes[artifact.candidate.bytes.len()..].ends_with(&[0xc9, 0xc3]));
    }

    #[test]
    fn target_candidate_and_witness_mutations_fail_closed() {
        let mut artifact = artifacts(SOURCES[1].0, SOURCES[1].1, SOURCES[1].2, 2);
        artifact.process.bytes[0] ^= 1;
        assert!(verify(&artifact).is_err());

        let mut artifact = artifacts(SOURCES[1].0, SOURCES[1].1, SOURCES[1].2, 2);
        artifact.process.witness.expected_outer += 1;
        assert!(verify(&artifact).is_err());

        let mut artifact = artifacts(SOURCES[1].0, SOURCES[1].1, SOURCES[1].2, 2);
        artifact.candidate.bytes[18] ^= 1;
        assert!(matches!(
            verify(&artifact),
            Err(ResidencyProcessError::Parent(_))
        ));
    }

    #[test]
    fn wrong_work_or_owner_identity_fails_closed() {
        let mut artifact = artifacts(SOURCES[2].0, SOURCES[2].1, SOURCES[2].2, 3);
        artifact.work.outer.bound += 1;
        assert!(verify(&artifact).is_err());

        let artifact = artifacts(SOURCES[2].0, SOURCES[2].1, SOURCES[2].2, 3);
        assert!(verify_residency_process_target(
            &artifact.machine,
            &artifact.baseline_plan,
            &artifact.residency_plan,
            &artifact.baseline,
            &artifact.candidate,
            &artifact.work,
            artifact.owner_local + artifact.baseline_plan.slot_homes.len() as u32,
            &artifact.process,
        )
        .is_err());
    }

    #[test]
    fn zero_ordinal_is_rejected() {
        let artifact = artifacts(SOURCES[3].0, SOURCES[3].1, SOURCES[3].2, 4);
        assert!(build_residency_process_elf64(&artifact.process, 0).is_err());
    }

    fn verify(artifact: &Artifacts) -> Result<(), ResidencyProcessError> {
        verify_residency_process_target(
            &artifact.machine,
            &artifact.baseline_plan,
            &artifact.residency_plan,
            &artifact.baseline,
            &artifact.candidate,
            &artifact.work,
            artifact.owner_local,
            &artifact.process,
        )
    }
}
