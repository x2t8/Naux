//! Deterministic structural-residual emitter for S4-WP5B.

#[path = "support/s4_whole_program_residual.rs"]
mod residual;

use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use residual::{lower_whole_program, verify_work};

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
        eprintln!("usage: naux-s4-structural-residual");
        std::process::exit(2);
    }
    println!("NAUX-S4-STRUCTURAL-RESIDUAL\t1");
    println!("meta\tstatus\tstructural-residual-admitted");
    println!("meta\tnative-status\tunavailable");
    println!("meta\ttiming-status\tforbidden");
    println!(
        "columns\tordinal\tkernel\tresidual-hash\twitness-hash\tlocal-count\tn-local\treps-local\tlist-local\tchecksum-local\tn\treps\top-count\ttraversal-count\tlist-loads\tlist-stores"
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
        let program = compile_script(&statements);
        let residual = lower_whole_program(&program, 16_384, 50)
            .unwrap_or_else(|error| fail(name, &error.to_string()));
        let witness = verify_work(&residual)
            .unwrap_or_else(|error| fail(name, &format!("witness replay: {error}")));
        println!(
            "kernel\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            ordinal + 1,
            name,
            residual.semantic_hash(),
            witness.semantic_hash(),
            residual.local_count,
            residual.n_local,
            residual.reps_local,
            residual.list_local,
            residual.checksum_local,
            residual.n,
            residual.reps,
            residual.ops.len(),
            witness.traversal_count,
            witness.list_loads,
            witness.list_stores,
        );
        for (ip, op) in residual.ops.iter().enumerate() {
            println!("op\t{:02}\t{:04}\t{}", ordinal + 1, ip, op.canonical_text());
        }
        println!(
            "witness\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            ordinal + 1,
            witness.allocation,
            witness.release,
            witness.outer.header,
            witness.outer.guard_exit,
            witness.outer.backedge,
            witness.outer.counter_local,
            witness.outer.bound,
            witness.inner.header,
            witness.inner.guard_exit,
            witness.inner.backedge,
            witness.inner.counter_local,
            witness.inner.bound,
            witness.traversal_count,
            witness.list_loads,
            witness.list_stores,
            witness.checksum_local,
        );
    }
    println!("verification\tregenerated");
}

fn fail(kernel: &str, message: &str) -> ! {
    eprintln!("S4 structural residual failed for `{kernel}`: {message}");
    std::process::exit(1);
}
