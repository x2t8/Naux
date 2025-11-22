use std::collections::HashMap;
use std::time::Instant;

use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::env::Env;
use naux::runtime::eval_script;
use naux::vm::compiler::compile_script;
use naux::vm::interpreter::run_program;

fn main() {
    let cases: Vec<(&str, &str, usize)> = vec![
        (
            "bfs_small",
            r#"
            $g = graph_new()
            $_ = graph_add_edge($g, "A", "B", 1)
            $_ = graph_add_edge($g, "A", "C", 1)
            $_ = graph_add_edge($g, "B", "D", 1)
            $order = graph_bfs($g, "A")
            "#,
            200,
        ),
        (
            "dijkstra_small",
            r#"
            $g = graph_new(true)
            $_ = graph_add_edge($g, "S", "A", 1)
            $_ = graph_add_edge($g, "A", "B", 2)
            $_ = graph_add_edge($g, "B", "T", 1)
            $_ = graph_add_edge($g, "S", "C", 4)
            $_ = graph_add_edge($g, "C", "T", 10)
            $path = graph_dijkstra($g, "S", "T")
            "#,
            200,
        ),
        (
            "lis",
            r#"
            $lis = lis_length([10,9,2,5,3,7,101,18])
            "#,
            1000,
        ),
        (
            "knapsack",
            r#"
            $val = knapsack_01([2,3,4,5], [3,4,5,6], 50)
            "#,
            500,
        ),
        (
            "segtree",
            r#"
            $st = segtree_new([1,2,3,4,5,6,7,8])
            $sum = segtree_query($st, 0, 8)
            $st = segtree_update($st, 3, 10)
            $sum2 = segtree_query($st, 2, 6)
            "#,
            500,
        ),
    ];

    for (name, code, iters) in cases {
        println!("=== Case: {} ({} iters) ===", name, iters);
        let tokens = lex(code).expect("lex");
        let ast = Parser::from_tokens(&tokens).expect("parse");

        // Interpreter
        let start = Instant::now();
        for _ in 0..iters {
            let (_env, _events, errs) = eval_script(&ast);
            if !errs.is_empty() {
                eprintln!("interp error: {:?}", errs);
                break;
            }
        }
        let dur_interp = start.elapsed();

        // VM
        let mut env = Env::new();
        naux::stdlib::register_all(&mut env);
        let builtins: HashMap<String, naux::runtime::env::BuiltinFn> = env.builtins();
        let prog = compile_script(&ast);
        let start_vm = Instant::now();
        for _ in 0..iters {
            if let Err(e) = run_program(&prog, &builtins) {
                eprintln!("vm error: {}", e);
                break;
            }
        }
        let dur_vm = start_vm.elapsed();

        println!(
            "interp: {:.3?} total ({:.3?}/iter), vm: {:.3?} total ({:.3?}/iter)",
            dur_interp,
            dur_interp / iters as u32,
            dur_vm,
            dur_vm / iters as u32
        );
    }
}
