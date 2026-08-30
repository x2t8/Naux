//! Deterministic contract-scoped candidate-plan emitter for S4-WP8C.

#[path = "support/s4_residual_x64_elf.rs"]
#[allow(dead_code)]
mod baseline;
#[path = "support/s4_residual_machine_ir.rs"]
#[allow(dead_code)]
mod machine;
#[path = "support/s4_register_residency_plan.rs"]
mod residency;
#[path = "support/s4_whole_program_residual.rs"]
mod residual;

use machine::lower_residual_machine_ir;
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use residency::{
    lower_register_residency, replay_register_residency, Selection, DEFAULT_REPLAY_STEP_LIMIT,
};
use residual::lower_whole_program;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

const WP8B_CONTRACT_SEAL: &str = "d380e92ae07226ff03997f80ab9a68ecf6c38f38dbd61ecaf52fd0d8f47ed893";
const WP8B_AUTHORITY_SEAL: &str =
    "61972d35d5322ee6e027dcde0b21fda1e9288804e0aa6431377df5833d0bdec8";
const FROZEN_WP5D_SOURCE_SHA256: &str =
    "1424d65d5c108095b9179b1af7280c688d64dfd5006d1249c7ef6286e5a36a0f";
const EXPECTED_REPORT_ROOT: &str =
    "8953eaeba2f3ab88d8259eae65d000b547bd50ba9dda8f1b5d73a249467fa677";
const EXPECTED_REPORT_SHA256: &str =
    "5c23016686fb1224229874afbbbca5c973adcab719fc97397c0697449703a686";
const MAX_REPORT_BYTES: u64 = 1_000_000;
const WP8B_CONTRACT_MAGIC: &str = "NAUX-S4-REGISTER-RESIDENCY-CONTRACT\t1";
const WP8B_AUTHORITY_MAGIC: &str = "NAUX-S4-REGISTER-RESIDENCY-AUTHORITY\t1";
const WP8B_CONTRACT_DOMAIN: &[u8] = b"NAUX:s4-register-residency:contract:v1\0";
const WP8B_AUTHORITY_DOMAIN: &[u8] = b"NAUX:s4-register-residency:authority:v1\0";
const WP8B_CONTRACT_BYTES: &[u8] =
    include_bytes!("../../distribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv");
const WP8B_AUTHORITY_BYTES: &[u8] =
    include_bytes!("../../distribution/s4-performance/WP8B-AUTHORITY.tsv");

const SOURCES: [(&str, &str, i64, Selection); 4] = [
    (
        "sum-dense",
        include_str!("../../benchmarks/s4/naux/sum_dense.nx"),
        6_710_476_800,
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "branch-mix",
        include_str!("../../benchmarks/s4/naux/branch_mix.nx"),
        -69_189_632,
        Selection {
            slot: 6,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "dot-product",
        include_str!("../../benchmarks/s4/naux/dot_product.nx"),
        73_294_064_435_200,
        Selection {
            slot: 5,
            expected_static_reads: 3,
            expected_static_writes: 2,
        },
    ),
    (
        "list-update",
        include_str!("../../benchmarks/s4/naux/list_update.nx"),
        6_730_547_200,
        Selection {
            slot: 5,
            expected_static_reads: 4,
            expected_static_writes: 2,
        },
    ),
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Command {
    Emit,
    Verify(PathBuf),
}

fn main() {
    match parse_command(std::env::args_os().skip(1)) {
        Ok(Command::Emit) => print!("{}", emit_report()),
        Ok(Command::Verify(path)) => verify_report_path(&path).unwrap_or_else(|message| {
            eprintln!("S4 register-residency report verification failed: {message}");
            std::process::exit(1);
        }),
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: naux-s4-register-residency-plan [--verify REPORT.tsv]");
            std::process::exit(2);
        }
    }
}

fn parse_command(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, &'static str> {
    let mut arguments = arguments.into_iter();
    match (arguments.next(), arguments.next(), arguments.next()) {
        (None, None, None) => Ok(Command::Emit),
        (Some(flag), Some(path), None) if flag == "--verify" && !path.is_empty() => {
            Ok(Command::Verify(PathBuf::from(path)))
        }
        _ => Err("invalid S4 register-residency plan arguments"),
    }
}

fn verify_report_path(path: &Path) -> Result<(), String> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect `{}`: {error}", path.display()))?;
    if !path_metadata.file_type().is_file() || path_metadata.file_type().is_symlink() {
        return Err(format!("`{}` is not a regular file", path.display()));
    }
    if path_metadata.len() > MAX_REPORT_BYTES {
        return Err(format!(
            "`{}` exceeds the {MAX_REPORT_BYTES}-byte report limit",
            path.display()
        ));
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("cannot open `{}`: {error}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened `{}`: {error}", path.display()))?;
    if !opened_metadata.file_type().is_file()
        || !same_file_identity(&path_metadata, &opened_metadata)
    {
        return Err(format!("`{}` changed before it was opened", path.display()));
    }
    let mut raw = Vec::with_capacity(opened_metadata.len() as usize);
    file.by_ref()
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("cannot read `{}`: {error}", path.display()))?;
    let read_metadata = file
        .metadata()
        .map_err(|error| format!("cannot reinspect `{}`: {error}", path.display()))?;
    if !same_file_identity(&opened_metadata, &read_metadata)
        || read_metadata.len() != opened_metadata.len()
        || raw.len() as u64 != read_metadata.len()
    {
        return Err(format!("`{}` changed while it was read", path.display()));
    }
    residency::verify_frozen_plan_report(&raw, EXPECTED_REPORT_ROOT, EXPECTED_REPORT_SHA256)
        .map_err(|error| error.to_string())?;
    println!("NAUX-S4-WP8C-PLAN-VERIFY\t1");
    println!("report-root\t{EXPECTED_REPORT_ROOT}");
    println!("document-sha256\t{EXPECTED_REPORT_SHA256}");
    println!("status\taccepted");
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.file_type().is_file()
        && right.file_type().is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

fn emit_report() -> String {
    verify_parent_chain();
    let mut report = String::new();
    macro_rules! row {
        ($($argument:tt)*) => {
            writeln!(&mut report, $($argument)*).expect("writing to String cannot fail")
        };
    }

    row!("NAUX-S4-REGISTER-RESIDENCY-PLAN\t1");
    row!("meta\tstatus\tcandidate-plan-only");
    row!("meta\tencoding-status\tunavailable");
    row!("meta\texecution-status\tsemantic-replay-only");
    row!("meta\tmeasurement-status\tforbidden");
    row!("meta\ttransform\tone-hot-loop-index-r12-v1");
    row!("meta\tparent-wp8b-contract\t{WP8B_CONTRACT_SEAL}");
    row!("meta\tparent-wp8b-authority\t{WP8B_AUTHORITY_SEAL}");
    row!("meta\tfrozen-wp5d-source-sha256\t{FROZEN_WP5D_SOURCE_SHA256}");
    row!("meta\tplan-identity\tdomain-separated-sha256-v1");
    row!("meta\treplay-identity\tdomain-separated-sha256-v1");
    row!("meta\treport-identity\tdomain-separated-sha256-v1");
    row!("meta\treplay-step-limit\t{DEFAULT_REPLAY_STEP_LIMIT}");
    for (ordinal, (name, source, oracle, selection)) in SOURCES.iter().enumerate() {
        let (machine, baseline, plan) = artifacts(name, source, *selection);
        let plan_hash = plan
            .semantic_hash()
            .unwrap_or_else(|error| fail(name, &error.to_string()));
        let replay = replay_register_residency(
            &machine,
            &plan,
            &baseline,
            *oracle,
            DEFAULT_REPLAY_STEP_LIMIT,
        )
        .unwrap_or_else(|error| fail(name, &error.to_string()));
        let replay_hash = replay.semantic_hash(plan_hash);
        row!(
            "kernel\t{:02}\t{}\t{}\t{}\t{}\ts{}\ti64\t{}\t{}\t{}\t{}",
            ordinal + 1,
            name,
            machine.semantic_hash(),
            plan_hash,
            plan.frame_bytes,
            plan.promoted_slot,
            plan.physical_register.canonical_text(),
            plan.static_reads,
            plan.static_writes,
            plan.blocks.len(),
        );
        row!(
            "abi\t{:02}\tsave-r12\trestore-r12\terror-exit-nonreturning",
            ordinal + 1
        );
        row!(
            "replay\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\tbaseline-equal",
            ordinal + 1,
            replay_hash,
            replay.candidate.result,
            replay.candidate.steps,
            replay.candidate.overflow_events,
            replay.candidate.allocations,
            replay.candidate.releases,
            replay.candidate.live_owned_lists,
            if replay.abi_restored {
                "r12-restored"
            } else {
                "r12-drifted"
            }
        );
        for block in &plan.blocks {
            row!(
                "block\t{:02}\t{}\t{}",
                ordinal + 1,
                block.id,
                block.instructions.len()
            );
            for (instruction, value) in block.instructions.iter().enumerate() {
                row!(
                    "instruction\t{:02}\t{}\t{}\t{}",
                    ordinal + 1,
                    block.id,
                    instruction,
                    value.canonical_text()
                );
            }
            row!(
                "terminator\t{:02}\t{}\t{}",
                ordinal + 1,
                block.id,
                block.terminator.canonical_text()
            );
        }
    }
    row!("verification\tcfg-must-initialize-r12-before-every-read");
    row!("verification\terasure-reconstructs-source-machine-ir");
    row!("verification\tindependent-baseline-candidate-semantic-parity");
    row!("verification\toracle-overflow-owner-state-and-r12-restore");
    let root = residency::plan_report_hash(report.as_bytes());
    row!("report-root\t{root}");
    residency::verify_frozen_plan_report(
        report.as_bytes(),
        EXPECTED_REPORT_ROOT,
        EXPECTED_REPORT_SHA256,
    )
    .unwrap_or_else(|error| fail("frozen-report", &error.to_string()));
    report
}

fn verify_parent_chain() {
    let contract = residency::sealed_document_root(
        WP8B_CONTRACT_BYTES,
        WP8B_CONTRACT_MAGIC,
        WP8B_CONTRACT_DOMAIN,
    )
    .unwrap_or_else(|error| fail("parent-chain", &error.to_string()));
    let authority = residency::sealed_document_root(
        WP8B_AUTHORITY_BYTES,
        WP8B_AUTHORITY_MAGIC,
        WP8B_AUTHORITY_DOMAIN,
    )
    .unwrap_or_else(|error| fail("parent-chain", &error.to_string()));
    if contract.to_string() != WP8B_CONTRACT_SEAL || authority.to_string() != WP8B_AUTHORITY_SEAL {
        fail("parent-chain", "WP8B parent root drifted");
    }
}

fn artifacts(
    name: &str,
    source: &str,
    selection: Selection,
) -> (
    machine::ResidualMachineProgram,
    baseline::X64Plan,
    residency::ResidencyPlan,
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
    let baseline =
        baseline::lower_x64_plan(&machine).unwrap_or_else(|error| fail(name, &error.to_string()));
    let plan = lower_register_residency(&machine, &baseline, selection)
        .unwrap_or_else(|error| fail(name, &error.to_string()));
    (machine, baseline, plan)
}

fn fail(kernel: &str, message: &str) -> ! {
    eprintln!("S4 register-residency plan failed for `{kernel}`: {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use machine::{MachineInstruction, MachineType};
    use residency::{verify_register_residency, PhysicalRegister, ResidencyError};

    #[test]
    fn command_surface_is_closed() {
        assert_eq!(parse_command([]), Ok(Command::Emit));
        assert_eq!(
            parse_command([OsString::from("--verify"), OsString::from("report.tsv")]),
            Ok(Command::Verify(PathBuf::from("report.tsv")))
        );
        assert!(parse_command([OsString::from("--verify")]).is_err());
        assert!(parse_command([OsString::from("--verify"), OsString::new()]).is_err());
        assert!(parse_command([OsString::from("--emit")]).is_err());
        assert!(parse_command([
            OsString::from("--verify"),
            OsString::from("report.tsv"),
            OsString::from("trailing"),
        ])
        .is_err());
    }

    #[test]
    fn all_frozen_kernels_lower_deterministically_and_erase_exactly() {
        for (name, source, oracle, selection) in SOURCES {
            let (first_machine, first_baseline, first) = artifacts(name, source, selection);
            let (second_machine, second_baseline, second) = artifacts(name, source, selection);
            assert_eq!(first_machine, second_machine, "{name} machine drift");
            assert_eq!(first_baseline, second_baseline, "{name} baseline drift");
            assert_eq!(first, second, "{name} residency plan drift");
            assert_eq!(
                first.semantic_hash().expect("first plan hashes"),
                second.semantic_hash().expect("second plan hashes"),
                "{name} residency identity drift"
            );
            verify_register_residency(&first, &first_machine, &first_baseline)
                .expect("residency erases exactly");
            let replay = replay_register_residency(
                &first_machine,
                &first,
                &first_baseline,
                oracle,
                DEFAULT_REPLAY_STEP_LIMIT,
            )
            .expect("semantic replay agrees");
            assert_eq!(replay.baseline, replay.candidate);
            assert_eq!(replay.candidate.result, oracle);
            assert_eq!(replay.candidate.allocations, 1);
            assert_eq!(replay.candidate.releases, 1);
            assert_eq!(replay.candidate.live_owned_lists, 0);
            assert!(replay.abi_restored);
            assert_eq!(first.frame_bytes, first_baseline.frame_bytes);
            assert_eq!(first.physical_register, PhysicalRegister::R12);
        }
    }

    #[test]
    fn wrong_type_or_unreviewed_slot_fails_closed() {
        let (machine, _, _) = artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].3);
        let baseline = baseline::lower_x64_plan(&machine).expect("baseline lowers");
        let owned_list = Selection {
            slot: 2,
            expected_static_reads: 0,
            expected_static_writes: 0,
        };
        assert!(matches!(
            lower_register_residency(&machine, &baseline, owned_list),
            Err(ResidencyError::InvalidSelection(_))
        ));

        let (machine, _, _) = artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].3);
        let baseline = baseline::lower_x64_plan(&machine).expect("baseline lowers");
        let unreviewed = Selection {
            slot: 4,
            expected_static_reads: 0,
            expected_static_writes: 0,
        };
        assert!(matches!(
            lower_register_residency(&machine, &baseline, unreviewed),
            Err(ResidencyError::InvalidSelection(_))
        ));
    }

    #[test]
    fn transformed_site_or_abi_mutation_fails_closed() {
        let (machine, baseline, mut plan) = artifacts(SOURCES[3].0, SOURCES[3].1, SOURCES[3].3);
        plan.restore_on_return = false;
        assert!(verify_register_residency(&plan, &machine, &baseline).is_err());

        let (machine, baseline, mut plan) = artifacts(SOURCES[3].0, SOURCES[3].1, SOURCES[3].3);
        let transformed = plan
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.instructions)
            .find(|instruction| {
                !matches!(instruction, residency::ResidencyInstruction::PassThrough(_))
            })
            .expect("plan has transformed site");
        *transformed = residency::ResidencyInstruction::PassThrough(MachineInstruction::ConstI64 {
            result: machine::TypedRegister {
                id: 0,
                ty: MachineType::I64,
            },
            value: 0,
        });
        assert!(verify_register_residency(&plan, &machine, &baseline).is_err());
    }

    #[test]
    fn replay_fails_closed_on_wrong_oracle_or_exhausted_step_budget() {
        let (machine, baseline, plan) = artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].3);
        assert!(replay_register_residency(
            &machine,
            &plan,
            &baseline,
            SOURCES[0].2 + 1,
            DEFAULT_REPLAY_STEP_LIMIT,
        )
        .is_err());
        assert!(replay_register_residency(&machine, &plan, &baseline, SOURCES[0].2, 1).is_err());
    }

    #[test]
    fn plan_identity_is_domain_separated_and_mutation_sensitive() {
        let (machine, _, plan) = artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].3);
        let accepted = plan.semantic_hash().expect("accepted plan hashes");
        assert_ne!(accepted, machine.semantic_hash());

        let mut mutations = Vec::new();
        let mut frame = plan.clone();
        frame.frame_bytes += 16;
        mutations.push(frame);
        let mut slot = plan.clone();
        slot.promoted_slot += 1;
        mutations.push(slot);
        let mut abi = plan.clone();
        abi.save_on_entry = false;
        mutations.push(abi);
        let mut extent = plan.clone();
        extent.static_reads += 1;
        mutations.push(extent);
        let mut block = plan.clone();
        block.blocks[0].id += 1;
        mutations.push(block);
        let mut instruction = plan.clone();
        let keep = instruction
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.instructions)
            .find_map(|instruction| match instruction {
                residency::ResidencyInstruction::StorePhysical { keep, .. } => Some(keep),
                _ => None,
            })
            .expect("plan contains a physical store");
        *keep = !*keep;
        mutations.push(instruction);

        for mutation in mutations {
            assert_ne!(
                mutation.semantic_hash().expect("mutated plan hashes"),
                accepted
            );
        }
    }

    #[test]
    fn replay_identity_binds_plan_summary_and_abi() {
        let (machine, baseline, plan) = artifacts(SOURCES[0].0, SOURCES[0].1, SOURCES[0].3);
        let replay = replay_register_residency(
            &machine,
            &plan,
            &baseline,
            SOURCES[0].2,
            DEFAULT_REPLAY_STEP_LIMIT,
        )
        .expect("accepted replay succeeds");
        let plan_hash = plan.semantic_hash().expect("accepted plan hashes");
        let accepted = replay.semantic_hash(plan_hash);
        assert_eq!(accepted, replay.semantic_hash(plan_hash));

        let mut summary = replay;
        summary.candidate.steps += 1;
        assert_ne!(accepted, summary.semantic_hash(plan_hash));
        let mut abi = replay;
        abi.abi_restored = false;
        assert_ne!(accepted, abi.semantic_hash(plan_hash));
        assert_ne!(
            accepted,
            replay.semantic_hash(naux::core::SemanticHash::ZERO)
        );
    }

    #[test]
    fn report_root_seals_the_complete_canonical_body() {
        let report = emit_report();
        residency::verify_frozen_plan_report(
            report.as_bytes(),
            EXPECTED_REPORT_ROOT,
            EXPECTED_REPORT_SHA256,
        )
        .expect("frozen report identity replays");
        let last = report.lines().last().expect("report has a root row");
        let body_bytes = report
            .len()
            .checked_sub(last.len() + 1)
            .expect("root row and newline fit the report");
        let expected = residency::plan_report_hash(&report.as_bytes()[..body_bytes]);
        assert_eq!(last, format!("report-root\t{expected}"));
        assert!(report.contains(&format!(
            "meta\tparent-wp8b-contract\t{WP8B_CONTRACT_SEAL}\n"
        )));
        assert!(report.contains(&format!(
            "meta\tparent-wp8b-authority\t{WP8B_AUTHORITY_SEAL}\n"
        )));
        assert!(report.contains(&format!(
            "meta\tfrozen-wp5d-source-sha256\t{FROZEN_WP5D_SOURCE_SHA256}\n"
        )));
        let mut mutated = report.as_bytes()[..body_bytes].to_vec();
        mutated[0] ^= 1;
        assert_ne!(residency::plan_report_hash(&mutated), expected);

        let mut coherently_resealed =
            report[..body_bytes].replacen("candidate-plan-only", "candidate-plan-open", 1);
        let replacement_root = residency::plan_report_hash(coherently_resealed.as_bytes());
        writeln!(&mut coherently_resealed, "report-root\t{replacement_root}")
            .expect("writing to String cannot fail");
        assert!(residency::verify_frozen_plan_report(
            coherently_resealed.as_bytes(),
            EXPECTED_REPORT_ROOT,
            EXPECTED_REPORT_SHA256,
        )
        .is_err());
    }
}
