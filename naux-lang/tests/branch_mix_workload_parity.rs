use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::value::Value;
use naux::vm::run::run_vm;

fn canonical_branch_mix(values: &[f64], reps: usize) -> f64 {
    let mut sum = 0.0;
    let mut state = 0_i64;
    for _ in 0..reps {
        for value in values {
            state += 17;
            if state >= 97 {
                state -= 97;
            }
            if state < 48 {
                sum += value;
            } else {
                sum -= value;
            }
        }
    }
    sum
}

#[test]
fn surface_branch_mix_preserves_state_and_sum_across_repetitions() {
    let template = include_str!("../examples/bench_branch_mix.nx");
    assert_eq!(template.matches("$n = 100000").count(), 1);
    assert_eq!(template.matches("$reps = 50").count(), 1);

    let source =
        template
            .replacen("$n = 100000", "$n = 4", 1)
            .replacen("$reps = 50", "$reps = 2", 1);
    let tokens = lex(&source).expect("branch_mix workload must lex");
    let ast = Parser::from_tokens(&tokens).expect("branch_mix workload must parse");
    let (_events, outcome) =
        run_vm(&ast, &source, "examples/bench_branch_mix.nx").expect("branch_mix VM run");
    let Value::Float(actual) = outcome else {
        panic!("branch_mix must return an F64 result, got {outcome:?}");
    };

    let expected = canonical_branch_mix(&[0.0, 1.0, 2.0, 3.0], 2);
    assert_eq!(expected.to_bits(), 2.0_f64.to_bits());
    assert_eq!(actual.to_bits(), expected.to_bits());

    // The former reset-each-repetition workload returned -8.0 for this case.
    assert_ne!(actual.to_bits(), (-8.0_f64).to_bits());
}
