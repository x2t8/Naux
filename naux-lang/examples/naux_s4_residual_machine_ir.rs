//! Deterministic residual-to-Machine-IR emitter for S4-WP5C.

#[path = "support/s4_residual_machine_ir.rs"]
mod machine;
#[path = "support/s4_whole_program_residual.rs"]
mod residual;

use machine::{lower_residual_machine_ir, MappingKind};
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use residual::lower_whole_program;

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
        eprintln!("usage: naux-s4-residual-machine-ir");
        std::process::exit(2);
    }
    println!("NAUX-S4-RESIDUAL-MACHINE-IR\t1");
    println!("meta\tstatus\tresidual-machine-ir-admitted");
    println!("meta\telf-status\tunavailable");
    println!("meta\ttiming-status\tforbidden");
    println!(
        "columns\tordinal\tkernel\tresidual-hash\twitness-hash\tmachine-hash\tcorrespondence-hash\tblock-count\tinstruction-count\tterminator-count\tregister-count\tmapping-count\ttraversal-count\tlist-loads\tlist-stores"
    );
    for (ordinal, (name, source)) in SOURCES.iter().enumerate() {
        let tokens = lexer::lex(source).unwrap_or_else(|error| {
            fail(name, &format!("lexer rejected source: {}", error.message))
        });
        let statements = parser::parse_script(&tokens).unwrap_or_else(|error| {
            fail(name, &format!("parser rejected source: {}", error.message))
        });
        typecheck::check_program(&statements).unwrap_or_else(|error| {
            fail(
                name,
                &format!("typechecker rejected source: {}", error.message),
            )
        });
        let residual = lower_whole_program(&compile_script(&statements), 16_384, 50)
            .unwrap_or_else(|error| fail(name, &error.to_string()));
        let (machine, correspondence) = lower_residual_machine_ir(&residual)
            .unwrap_or_else(|error| fail(name, &error.to_string()));
        println!(
            "kernel\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            ordinal + 1,
            name,
            correspondence.residual_hash,
            correspondence.witness_hash,
            correspondence.machine_hash,
            correspondence.semantic_hash(),
            correspondence.block_count,
            correspondence.instruction_count,
            correspondence.terminator_count,
            correspondence.register_count,
            correspondence.mapping_count,
            correspondence.traversal_count,
            correspondence.list_loads,
            correspondence.list_stores,
        );
        for (slot, ty) in machine.slot_types.iter().enumerate() {
            println!("slot\t{:02}\t{slot}\t{}", ordinal + 1, ty.canonical_text());
        }
        for block in &machine.blocks {
            println!(
                "block\t{:02}\t{}\t{}\t{}\t{}",
                ordinal + 1,
                block.id,
                block.residual_start,
                block.residual_end,
                block.instructions.len()
            );
            for (instruction, op) in block.instructions.iter().enumerate() {
                println!(
                    "instruction\t{:02}\t{}\t{}\t{}",
                    ordinal + 1,
                    block.id,
                    instruction,
                    op.canonical_text()
                );
            }
            println!(
                "terminator\t{:02}\t{}\t{}",
                ordinal + 1,
                block.id,
                block.terminator.canonical_text()
            );
        }
        for mapping in &machine.source_map {
            let kind = match mapping.kind {
                MappingKind::Instruction => "instruction",
                MappingKind::Terminator => "terminator",
            };
            println!(
                "mapping\t{:02}\t{}\t{}\t{}\t{}\t{}",
                ordinal + 1,
                mapping.residual_ip,
                mapping.block,
                mapping.machine_ordinal,
                kind,
                residual.ops[mapping.residual_ip as usize].canonical_text()
            );
        }
        println!(
            "correspondence\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            ordinal + 1,
            correspondence.machine_hash,
            correspondence.residual_hash,
            correspondence.witness_hash,
            correspondence.block_count,
            correspondence.instruction_count,
            correspondence.terminator_count,
            correspondence.register_count,
            correspondence.mapping_count,
            correspondence.allocation_block,
            correspondence.release_block,
            correspondence.outer_header_block,
            correspondence.outer_exit_block,
            correspondence.inner_header_block,
            correspondence.inner_exit_block,
            correspondence.traversal_count,
            correspondence.list_loads,
            correspondence.list_stores,
        );
    }
    println!("verification\tregenerated");
}

fn fail(kernel: &str, message: &str) -> ! {
    eprintln!("S4 residual Machine IR failed for `{kernel}`: {message}");
    std::process::exit(1);
}
