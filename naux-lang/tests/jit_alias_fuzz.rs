#![cfg(all(target_arch = "x86_64", not(windows)))]

use naux::ast::Stmt;
use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::vm::compiler::compile_script;
use naux::vm::run::run_vm;
use naux::vm::typed::TypedRunner;

const DEFAULT_CASES_PER_COLLECTION: usize = 16;
const MAX_CASES_PER_COLLECTION: usize = 256;
const BASE_SEED: u64 = 0x4e41_5558_a11a_5105;

fn parse(src: &str) -> Vec<Stmt> {
    let tokens = lex(src).expect("lex fuzz case");
    Parser::from_tokens(&tokens).expect("parse fuzz case")
}

fn next_seed(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn configured_case_count() -> usize {
    std::env::var("NAUX_ALIAS_FUZZ_CASES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CASES_PER_COLLECTION)
        .clamp(1, MAX_CASES_PER_COLLECTION)
}

fn assert_vm_jit_differential(
    src: &str,
    collection: &str,
    case_idx: usize,
    seed: u64,
    expect_branch_transition: bool,
) {
    let ast = parse(src);
    let program = compile_script(&ast);
    let (_events, expected) =
        run_vm(&ast, src, "<jit-alias-fuzz>").expect("reference VM must execute fuzz case");
    let mut runner = TypedRunner::new(&program);

    for reuse_idx in 0..2 {
        let (actual, _events) = runner.run(&program).unwrap_or_else(|err| {
            panic!(
                "{collection} fuzz case {case_idx} seed=0x{seed:016x} reuse={reuse_idx} failed: {err}\n{src}"
            )
        });
        assert_eq!(
            actual, expected,
            "{collection} fuzz mismatch case={case_idx} seed=0x{seed:016x} reuse={reuse_idx}\n{src}"
        );
    }

    let summary = runner.trace_summary();
    assert!(
        summary.trace_count > 0 && summary.total_hits > 0,
        "{collection} fuzz case did not exercise a typed trace: case={case_idx} seed=0x{seed:016x}\n{src}"
    );
    assert!(
        summary.trace_count <= 4,
        "{collection} fuzz case caused trace explosion: case={case_idx} seed=0x{seed:016x} traces={}\n{src}",
        summary.trace_count
    );
    if expect_branch_transition {
        assert!(
            summary.total_static_branches >= 3,
            "{collection} branchy fuzz case did not retain native internal control flow: case={case_idx} seed=0x{seed:016x}\n{src}"
        );
        assert_eq!(
            summary.total_internal_side_exits, 0,
            "{collection} branchy fuzz case left native control flow: case={case_idx} seed=0x{seed:016x} side_exits={}\n{src}",
            summary.total_internal_side_exits,
        );
    }
}

fn list_case(seed: u64) -> String {
    let aliases = ["$arr", "$a", "$b"];
    let read = aliases[(seed as usize) % aliases.len()];
    let write = aliases[((seed >> 8) as usize) % aliases.len()];
    let observe = aliases[((seed >> 16) as usize) % aliases.len()];
    let n = 51 + ((seed >> 24) % 46);
    let reps = 2 + ((seed >> 32) % 3);

    format!(
        r#"
~ rite
    $n = {n}
    $reps = {reps}
    $arr = list_range($n)
    $a = $arr
    $b = $a
    $digest = 0
    $r = 0
    ~ while $r < $reps
        $i = 0
        ~ while $i < len({read})
            $v = __index({read}, $i)
            $digest = $digest + $v
            $__ = __setindex({write}, $i, $v + 1)
            $i = $i + 1
        ~ end
        $r = $r + 1
    ~ end
    ^ $digest + __index({observe}, 0) + __index($arr, $n - 1) + __index($b, 0)
~ end
"#
    )
}

fn map_case(seed: u64) -> String {
    let aliases = ["$m", "$a", "$b"];
    let read = aliases[(seed as usize) % aliases.len()];
    let write = aliases[((seed >> 8) as usize) % aliases.len()];
    let observe = aliases[((seed >> 16) as usize) % aliases.len()];
    let key_idx = (seed >> 24) % 3;
    let n = 64 + ((seed >> 32) % 64);
    let reps = 2 + ((seed >> 40) % 3);

    format!(
        r#"
~ rite
    $n = {n}
    $reps = {reps}
    $m = {{k0: 1, k1: 2, k2: 3}}
    $a = $m
    $b = $a
    $key = "k{key_idx}"
    $digest = 0
    $r = 0
    ~ while $r < $reps
        $i = 0
        ~ while $i < $n
            $v = __index({read}, $key)
            $digest = $digest + $v
            $__ = __setindex({write}, $key, $v + 1)
            $i = $i + 1
        ~ end
        $r = $r + 1
    ~ end
    ^ $digest + __index({observe}, $key) + __index($m, $key) + __index($b, $key)
~ end
"#
    )
}

fn branchy_list_case(seed: u64) -> String {
    let aliases = ["$arr", "$a", "$b"];
    let read = aliases[(seed as usize) % aliases.len()];
    let write = aliases[((seed >> 8) as usize) % aliases.len()];
    let observe = aliases[((seed >> 16) as usize) % aliases.len()];
    let n = 72 + ((seed >> 24) % 25);
    let pivot = n - (3 + ((seed >> 32) % 8));
    let reps = 2 + ((seed >> 40) % 3);

    format!(
        r#"
~ rite
    $n = {n}
    $pivot = {pivot}
    $reps = {reps}
    $arr = list_range($n)
    $a = $arr
    $b = $a
    $digest = 0
    $r = 0
    ~ while $r < $reps
        $i = 0
        ~ while $i < len({read})
            $v = __index({read}, $i)
            ~ if $i < $pivot
                $digest = $digest + $v
            ~ end
            $digest = $digest + $v
            $__ = __setindex({write}, $i, $v + 1)
            $i = $i + 1
        ~ end
        $r = $r + 1
    ~ end
    ^ $digest + __index({observe}, 0) + __index($arr, $n - 1) + __index($b, 0)
~ end
"#
    )
}

fn branchy_map_case(seed: u64) -> String {
    let aliases = ["$m", "$a", "$b"];
    let read = aliases[(seed as usize) % aliases.len()];
    let write = aliases[((seed >> 8) as usize) % aliases.len()];
    let observe = aliases[((seed >> 16) as usize) % aliases.len()];
    let key_idx = (seed >> 24) % 3;
    let n = 72 + ((seed >> 32) % 25);
    let pivot = n - (3 + ((seed >> 40) % 8));
    let reps = 2 + ((seed >> 48) % 3);

    format!(
        r#"
~ rite
    $n = {n}
    $pivot = {pivot}
    $reps = {reps}
    $m = {{k0: 1, k1: 2, k2: 3}}
    $a = $m
    $b = $a
    $key = "k{key_idx}"
    $digest = 0
    $r = 0
    ~ while $r < $reps
        $i = 0
        ~ while $i < $n
            $v = __index({read}, $key)
            ~ if $i < $pivot
                $digest = $digest + $v
            ~ end
            $digest = $digest + $v
            $__ = __setindex({write}, $key, $v + 1)
            $i = $i + 1
        ~ end
        $r = $r + 1
    ~ end
    ^ $digest + __index({observe}, $key) + __index($m, $key) + __index($b, $key)
~ end
"#
    )
}

#[test]
fn deterministic_list_and_map_alias_mutation_differential_fuzz() {
    let cases = configured_case_count();
    let mut state = BASE_SEED;

    for case_idx in 0..cases {
        let seed = next_seed(&mut state);
        assert_vm_jit_differential(&list_case(seed), "list-linear", case_idx, seed, false);
    }
    for case_idx in 0..cases {
        let seed = next_seed(&mut state);
        assert_vm_jit_differential(&map_case(seed), "map-linear", case_idx, seed, false);
    }
    for case_idx in 0..cases {
        let seed = next_seed(&mut state);
        assert_vm_jit_differential(
            &branchy_list_case(seed),
            "list-branchy",
            case_idx,
            seed,
            true,
        );
    }
    for case_idx in 0..cases {
        let seed = next_seed(&mut state);
        assert_vm_jit_differential(&branchy_map_case(seed), "map-branchy", case_idx, seed, true);
    }

    eprintln!(
        "[jit-alias-fuzz] PASS base_seed=0x{BASE_SEED:016x} list_linear={cases} map_linear={cases} list_branchy={cases} map_branchy={cases} runner_reuses=2 max_traces_per_case=4"
    );
}
