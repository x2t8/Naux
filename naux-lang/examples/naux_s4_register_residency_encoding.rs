//! Deterministic candidate-byte emitter for the bounded S4-WP8E gate.

#[path = "support/s4_residual_x64_elf.rs"]
#[allow(dead_code)]
mod baseline;
#[path = "support/s4_residual_machine_ir.rs"]
#[allow(dead_code)]
mod machine;
#[path = "support/s4_register_residency_plan.rs"]
#[allow(dead_code)]
mod residency;
#[path = "support/s4_register_residency_encoding.rs"]
mod residency_encoding;
#[path = "support/s4_whole_program_residual.rs"]
mod residual;

use baseline::{encode_x64, lower_x64_plan};
use machine::lower_residual_machine_ir;
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use residency::{lower_register_residency, Selection};
use residency_encoding::{encode_register_residency, encoding_report_hash, CandidateRangeKind};
use residual::lower_whole_program;
use std::fmt::Write as _;

const SOURCES: [(&str, &str, Selection, usize, u32); 4] = [
    (
        "sum-dense",
        include_str!("../../benchmarks/s4/naux/sum_dense.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
        972,
        958,
    ),
    (
        "branch-mix",
        include_str!("../../benchmarks/s4/naux/branch_mix.nx"),
        Selection {
            slot: 6,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
        1167,
        1153,
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
        915,
    ),
    (
        "list-update",
        include_str!("../../benchmarks/s4/naux/list_update.nx"),
        Selection {
            slot: 5,
            expected_static_reads: 4,
            expected_static_writes: 2,
        },
        1043,
        1029,
    ),
];

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: naux-s4-register-residency-encoding");
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
    row!("NAUX-S4-REGISTER-RESIDENCY-ENCODING\t1");
    row!("meta\tstatus\tcandidate-function-bytes-only");
    row!("meta\telf-status\tabsent");
    row!("meta\tnative-execution-status\tforbidden");
    row!("meta\tmeasurement-status\tforbidden");
    row!("meta\tclaim-status\tnot-admitted");
    for (ordinal, (name, source, selection, expected_bytes, expected_error)) in
        SOURCES.iter().enumerate()
    {
        let (machine, baseline_plan, plan, baseline, candidate) =
            artifacts(name, source, *selection);
        if candidate.bytes.len() != *expected_bytes || candidate.error_offset != *expected_error {
            fail(
                name,
                "candidate width differs from the admitted WP8D equation",
            );
        }
        row!(
            "kernel\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            ordinal + 1,
            name,
            machine.semantic_hash(),
            plan.semantic_hash()
                .unwrap_or_else(|error| fail(name, &error.to_string())),
            baseline.bytes.len(),
            candidate.bytes.len(),
            candidate.error_offset,
            candidate.transformed_site_count(),
            candidate.return_count(),
        );
        row!(
            "abi\t{:02}\tsave-r12\t{}\t{}\trestore-every-return",
            ordinal + 1,
            candidate.save_start,
            candidate.save_end,
        );
        for range in &candidate.ranges {
            row!(
                "range\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                ordinal + 1,
                range.block,
                range.ordinal,
                range_kind(range.kind),
                range.start,
                range.end,
                range.baseline_start,
                range.baseline_end,
            );
        }
        row!("target-hex\t{:02}\t{}", ordinal + 1, hex(&candidate.bytes));
        let _ = baseline_plan;
    }
    row!("verification\tindependent-byte-parser-accepted");
    row!("verification\tno-elf-no-execution-no-measurement");
    let root = encoding_report_hash(report.as_bytes());
    row!("report-root\t{root}");
    report
}

fn artifacts(
    name: &str,
    source: &str,
    selection: Selection,
) -> (
    machine::ResidualMachineProgram,
    baseline::X64Plan,
    residency::ResidencyPlan,
    baseline::EncodedX64,
    residency_encoding::ResidencyEncodedX64,
) {
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
    let residency_plan = lower_register_residency(&machine, &baseline_plan, selection)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    let candidate = encode_register_residency(&machine, &baseline_plan, &residency_plan, &baseline)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    (machine, baseline_plan, residency_plan, baseline, candidate)
}

fn range_kind(kind: CandidateRangeKind) -> &'static str {
    match kind {
        CandidateRangeKind::PassThroughOperation => "passthrough-operation",
        CandidateRangeKind::LoadPhysical => "load-physical",
        CandidateRangeKind::StorePhysical => "store-physical",
        CandidateRangeKind::PassThroughTerminator => "passthrough-terminator",
        CandidateRangeKind::ReturnWithRestore => "return-with-restore",
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
    eprintln!("S4 residency encoding failed for `{kernel}`: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use residency_encoding::{verify_register_residency_encoding, ResidencyEncodingError};

    #[test]
    fn all_four_candidates_match_the_admitted_width_equations() {
        for (name, source, selection, expected_bytes, expected_error) in SOURCES {
            let (machine, baseline_plan, plan, baseline, first) =
                artifacts(name, source, selection);
            let second = encode_register_residency(&machine, &baseline_plan, &plan, &baseline)
                .expect("candidate re-encodes");
            assert_eq!(first, second, "{name} candidate bytes drifted");
            assert_eq!(first.bytes.len(), expected_bytes, "{name} width drifted");
            assert_eq!(
                first.error_offset, expected_error,
                "{name} error offset drifted"
            );
            assert_eq!(
                first.transformed_site_count(),
                selection.expected_static_reads + selection.expected_static_writes,
                "{name} transformed extent drifted"
            );
            assert_eq!(first.return_count(), 1, "{name} return extent drifted");
            verify_register_residency_encoding(&machine, &baseline_plan, &plan, &baseline, &first)
                .expect("independent parser accepts candidate");
        }
    }

    #[test]
    fn opcode_or_abi_mutation_fails_closed() {
        let (machine, baseline_plan, plan, baseline, mut candidate) =
            artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].2);
        candidate.bytes[candidate.save_start as usize] ^= 1;
        assert!(verify_register_residency_encoding(
            &machine,
            &baseline_plan,
            &plan,
            &baseline,
            &candidate,
        )
        .is_err());

        let (machine, baseline_plan, plan, baseline, mut candidate) =
            artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].2);
        let site = candidate
            .ranges
            .iter()
            .find(|range| range.kind == CandidateRangeKind::LoadPhysical)
            .expect("candidate has a load site");
        candidate.bytes[site.start as usize + 1] ^= 1;
        assert!(verify_register_residency_encoding(
            &machine,
            &baseline_plan,
            &plan,
            &baseline,
            &candidate,
        )
        .is_err());
    }

    #[test]
    fn external_fixup_or_receipt_mutation_fails_closed() {
        let (machine, baseline_plan, plan, baseline, mut candidate) =
            artifacts(SOURCES[1].0, SOURCES[1].1, SOURCES[1].2);
        let branch = candidate
            .ranges
            .iter()
            .find(|range| {
                range.kind == CandidateRangeKind::PassThroughTerminator
                    && range.end - range.start == 21
            })
            .expect("candidate has a branch");
        candidate.bytes[branch.start as usize + 12] ^= 1;
        assert!(verify_register_residency_encoding(
            &machine,
            &baseline_plan,
            &plan,
            &baseline,
            &candidate,
        )
        .is_err());

        let (machine, baseline_plan, plan, baseline, mut candidate) =
            artifacts(SOURCES[1].0, SOURCES[1].1, SOURCES[1].2);
        candidate.ranges[0].baseline_start += 1;
        assert!(verify_register_residency_encoding(
            &machine,
            &baseline_plan,
            &plan,
            &baseline,
            &candidate,
        )
        .is_err());
    }

    #[test]
    fn unadmitted_add_physical_template_is_rejected() {
        let (machine, baseline_plan, mut plan, baseline, _) =
            artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].2);
        let transformed = plan
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.instructions)
            .find(|instruction| {
                matches!(
                    instruction,
                    residency::ResidencyInstruction::LoadPhysical { .. }
                )
            })
            .expect("plan has transformed access");
        *transformed = residency::ResidencyInstruction::AddPhysicalConst {
            register: residency::PhysicalRegister::R12,
            value: 1,
        };
        let error = encode_register_residency(&machine, &baseline_plan, &plan, &baseline)
            .expect_err("unadmitted template must fail");
        assert!(matches!(
            error,
            ResidencyEncodingError::InvalidInput(_) | ResidencyEncodingError::Unsupported(_)
        ));
    }

    #[test]
    fn coherently_reencoded_baseline_plan_mutation_is_rejected() {
        let (machine, mut baseline_plan, plan, _, _) =
            artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].2);
        let operation = baseline_plan
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.operations)
            .find(|operation| matches!(operation, baseline::X64Operation::ConstI64 { .. }))
            .expect("baseline has a constant operation");
        let baseline::X64Operation::ConstI64 { value, .. } = operation else {
            unreachable!()
        };
        *value = value.wrapping_add(1);
        let resealed = baseline::encode_x64(&baseline_plan).expect("mutated baseline re-encodes");
        assert!(matches!(
            encode_register_residency(&machine, &baseline_plan, &plan, &resealed),
            Err(ResidencyEncodingError::InvalidInput(_))
        ));
    }
}
