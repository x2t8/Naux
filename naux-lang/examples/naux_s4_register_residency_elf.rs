//! Deterministic quarantined ELF64 emitter for S4-WP8F.

#[path = "support/s4_residual_x64_elf.rs"]
#[allow(dead_code)]
mod baseline;
#[path = "support/s4_residual_machine_ir.rs"]
#[allow(dead_code)]
mod machine;
#[path = "support/s4_register_residency_plan.rs"]
#[allow(dead_code)]
mod residency;
#[path = "support/s4_register_residency_elf.rs"]
mod residency_elf;
#[path = "support/s4_register_residency_encoding.rs"]
#[allow(dead_code)]
mod residency_encoding;
#[path = "support/s4_whole_program_residual.rs"]
mod residual;

use baseline::{encode_x64, lower_x64_plan};
use machine::lower_residual_machine_ir;
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use residency::{lower_register_residency, Selection};
use residency_elf::{build_register_residency_elf, elf_report_hash};
use residency_encoding::encode_register_residency;
use residual::lower_whole_program;
use std::fmt::Write as _;

const SOURCES: [(&str, &str, Selection, usize, usize); 4] = [
    (
        "sum-dense",
        include_str!("../../benchmarks/s4/naux/sum_dense.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
        972,
        1_244,
    ),
    (
        "branch-mix",
        include_str!("../../benchmarks/s4/naux/branch_mix.nx"),
        Selection {
            slot: 6,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
        1_167,
        1_439,
    ),
    (
        "dot-product",
        include_str!("../../benchmarks/s4/naux/dot_product.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
        929,
        1_201,
    ),
    (
        "list-update",
        include_str!("../../benchmarks/s4/naux/list_update.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 4,
            expected_static_writes: 2,
        },
        1_043,
        1_315,
    ),
];

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: naux-s4-register-residency-elf");
        std::process::exit(2);
    }
    print!("{}", emit_report());
}

fn emit_report() -> String {
    let mut report = String::new();
    macro_rules! row {
        ($($argument:tt)*) => {
            writeln!(&mut report, $($argument)*).expect("writing to String cannot fail")
        };
    }
    row!("NAUX-S4-REGISTER-RESIDENCY-ELF64\t1");
    row!("meta\tstatus\tcandidate-elf-structurally-admitted");
    row!("meta\tartifact-status\treport-hex-only");
    row!("meta\tnative-execution-status\tforbidden");
    row!("meta\tmeasurement-status\tforbidden");
    row!("meta\tclaim-status\tnot-admitted");
    row!("meta\tlinker\tnone");
    row!("meta\tlibc\tnone");
    row!("meta\ttarget\tx86_64-unknown-linux-gnu");
    row!("columns\tordinal\tkernel\tmachine-hash\tplan-hash\ttarget-hash\telf-hash\ttarget-bytes\telf-bytes\ttarget-offset\tentry\tload-flags\tstack-flags");
    for (ordinal, (name, source, selection, expected_target, expected_elf)) in
        SOURCES.iter().enumerate()
    {
        let artifacts = artifacts(name, source, *selection);
        if artifacts.candidate.bytes.len() != *expected_target
            || artifacts.elf.bytes.len() != *expected_elf
        {
            fail(name, "candidate or ELF width drifted");
        }
        let facts =
            residency_elf::verify_register_residency_elf(&artifacts.elf, &artifacts.candidate)
                .unwrap_or_else(|error| fail(name, &error.to_string()));
        row!(
            "kernel\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            ordinal + 1,
            name,
            artifacts.machine.semantic_hash(),
            artifacts
                .plan
                .semantic_hash()
                .unwrap_or_else(|error| fail(name, &error.to_string())),
            facts.target_hash,
            facts.image_hash,
            facts.target_bytes,
            facts.image_bytes,
            facts.target_offset,
            facts.entry,
            facts.load_flags,
            facts.stack_flags,
        );
        row!("elf-hex\t{:02}\t{}", ordinal + 1, hex(&artifacts.elf.bytes));
    }
    row!("verification\tindependent-elf-parser-accepted");
    row!("verification\tno-file-no-execution-no-measurement");
    let root = elf_report_hash(report.as_bytes());
    row!("report-root\t{root}");
    report
}

struct Artifacts {
    machine: machine::ResidualMachineProgram,
    plan: residency::ResidencyPlan,
    candidate: residency_encoding::ResidencyEncodedX64,
    elf: residency_elf::ResidencyElf64Image,
}

fn artifacts(name: &str, source: &str, selection: Selection) -> Artifacts {
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
    let (machine, _) =
        lower_residual_machine_ir(&residual).unwrap_or_else(|error| fail(name, &error.to_string()));
    let baseline_plan =
        lower_x64_plan(&machine).unwrap_or_else(|error| fail(name, &error.to_string()));
    let baseline =
        encode_x64(&baseline_plan).unwrap_or_else(|error| fail(name, &error.to_string()));
    let plan = lower_register_residency(&machine, &baseline_plan, selection)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let candidate = encode_register_residency(&machine, &baseline_plan, &plan, &baseline)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let elf = build_register_residency_elf(&candidate)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    Artifacts {
        machine,
        plan,
        candidate,
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
    eprintln!("S4 residency ELF failed for `{kernel}`: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use residency_elf::{verify_register_residency_elf, ResidencyElfError};

    #[test]
    fn all_four_images_are_deterministic_and_parse_independently() {
        for (name, source, selection, expected_target, expected_elf) in SOURCES {
            let first = artifacts(name, source, selection);
            let second = artifacts(name, source, selection);
            assert_eq!(first.candidate, second.candidate, "{name} target drift");
            assert_eq!(first.elf, second.elf, "{name} ELF drift");
            assert_eq!(first.candidate.bytes.len(), expected_target);
            assert_eq!(first.elf.bytes.len(), expected_elf);
            let facts = verify_register_residency_elf(&first.elf, &first.candidate)
                .expect("independent parser accepts image");
            assert_eq!(facts.target_offset, 272);
            assert_eq!(facts.entry, 0x0040_0100);
            assert_eq!(facts.load_flags, 5);
            assert_eq!(facts.stack_flags, 6);
        }
    }

    #[test]
    fn header_or_program_header_mutation_fails_closed() {
        let artifact = artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].2);
        for offset in [0, 18, 24, 64 + 4, 64 + 56 + 4] {
            let mut image = artifact.elf.clone();
            image.bytes[offset] ^= 1;
            assert!(matches!(
                verify_register_residency_elf(&image, &artifact.candidate),
                Err(ResidencyElfError::InvalidElf(_))
            ));
        }
    }

    #[test]
    fn startup_target_or_hash_mutation_fails_closed() {
        let artifact = artifacts(SOURCES[1].0, SOURCES[1].1, SOURCES[1].2);
        for offset in [0x101, 0x105, artifact.elf.target_offset as usize + 17] {
            let mut image = artifact.elf.clone();
            image.bytes[offset] ^= 1;
            assert!(verify_register_residency_elf(&image, &artifact.candidate).is_err());
        }

        let mut image = artifact.elf.clone();
        image.target_hash.0[0] ^= 1;
        assert!(verify_register_residency_elf(&image, &artifact.candidate).is_err());

        let mut image = artifact.elf.clone();
        image.image_hash.0[0] ^= 1;
        assert!(verify_register_residency_elf(&image, &artifact.candidate).is_err());
    }

    #[test]
    fn receipt_or_candidate_mismatch_fails_closed() {
        let artifact = artifacts(SOURCES[2].0, SOURCES[2].1, SOURCES[2].2);
        let mut image = artifact.elf.clone();
        image.target_offset += 16;
        assert!(verify_register_residency_elf(&image, &artifact.candidate).is_err());

        let mut image = artifact.elf.clone();
        image.target_bytes -= 1;
        assert!(verify_register_residency_elf(&image, &artifact.candidate).is_err());

        let other = artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].2);
        assert!(verify_register_residency_elf(&artifact.elf, &other.candidate).is_err());
    }

    #[test]
    fn empty_or_malformed_candidate_is_rejected() {
        let mut artifact = artifacts(SOURCES[3].0, SOURCES[3].1, SOURCES[3].2);
        artifact.candidate.bytes.clear();
        assert!(matches!(
            build_register_residency_elf(&artifact.candidate),
            Err(ResidencyElfError::InvalidInput(_))
        ));
    }

    #[test]
    fn image_has_no_sections_and_no_writable_code_segment() {
        let artifact = artifacts(SOURCES[3].0, SOURCES[3].1, SOURCES[3].2);
        assert_eq!(&artifact.elf.bytes[40..48], &0_u64.to_le_bytes());
        assert_eq!(&artifact.elf.bytes[48..52], &0_u32.to_le_bytes());
        assert_eq!(&artifact.elf.bytes[68..72], &5_u32.to_le_bytes());
        assert_eq!(&artifact.elf.bytes[60..62], &0_u16.to_le_bytes());
    }
}
