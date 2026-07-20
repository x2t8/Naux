use naux::ast::Stmt;
use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::events::RuntimeEvent;
use naux::typecheck;
use naux::vm::run::{run_jit, run_vm};

struct ExampleCase {
    name: &'static str,
    source: &'static str,
    expected_say: &'static [&'static str],
}

const CASES: &[ExampleCase] = &[
    ExampleCase {
        name: "hello",
        source: include_str!("../examples/hello.nx"),
        expected_say: &["Hello, world!"],
    },
    ExampleCase {
        name: "sample",
        source: include_str!("../examples/sample.nx"),
        expected_say: &["Sample program"],
    },
    ExampleCase {
        name: "algo_lis",
        source: include_str!("../examples/algo_lis.nx"),
        expected_say: &["LIS length = 4"],
    },
    ExampleCase {
        name: "algo_knapsack",
        source: include_str!("../examples/algo_knapsack.nx"),
        expected_say: &["Knapsack best = 7"],
    },
    ExampleCase {
        name: "algorithm_bfs",
        source: include_str!("../examples/algorithm_bfs.nx"),
        expected_say: &["List [A, B, C]"],
    },
    ExampleCase {
        name: "graph_bfs",
        source: include_str!("../examples/graph_bfs.nx"),
        expected_say: &["List [A, B, C, D]"],
    },
    ExampleCase {
        name: "graph_dijkstra",
        source: include_str!("../examples/graph_dijkstra.nx"),
        expected_say: &["Map {distance:4, path:List [A, B, C, D]}"],
    },
    ExampleCase {
        name: "jit_numeric_print",
        source: include_str!("../examples/jit_numeric_print.nx"),
        expected_say: &["sum = 149995000"],
    },
    ExampleCase {
        name: "jit_numeric",
        source: include_str!("../examples/jit_numeric.nx"),
        expected_say: &["sum = 14999950000"],
    },
];

fn parse(source: &str) -> Vec<Stmt> {
    let tokens = lex(source).expect("lex failed");
    Parser::from_tokens(&tokens).expect("parse failed")
}

fn say_events(events: &[RuntimeEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            RuntimeEvent::Say(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn release_examples_have_expected_vm_output() {
    for case in CASES {
        let ast = parse(case.source);
        typecheck::check_program(&ast).unwrap_or_else(|err| {
            panic!("{} typecheck failed: {}", case.name, err.message);
        });

        let (events, _value) =
            run_vm(&ast, case.source, case.name).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(
            say_events(&events),
            case.expected_say,
            "{} output changed",
            case.name
        );
    }
}

#[test]
fn release_examples_match_between_vm_and_jit_entrypoint() {
    for case in CASES {
        let ast = parse(case.source);
        typecheck::check_program(&ast).unwrap_or_else(|err| {
            panic!("{} typecheck failed: {}", case.name, err.message);
        });

        let (vm_events, vm_value) =
            run_vm(&ast, case.source, case.name).unwrap_or_else(|err| panic!("{err}"));
        let (jit_events, jit_value, _used_jit) =
            run_jit(&ast, case.source, case.name).unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(
            say_events(&jit_events),
            say_events(&vm_events),
            "{} event parity changed",
            case.name
        );
        assert_eq!(jit_value, vm_value, "{} return parity changed", case.name);
    }
}
