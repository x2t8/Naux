use naux::cli::format::format_stmts;
use naux::lexer;
use naux::parser::parser::Parser;

fn normalize(src: &str) -> String {
    let tokens = lexer::lex(src).expect("lexing failed");
    let ast = Parser::from_tokens(&tokens).expect("parsing failed");
    format_stmts(&ast, None)
}

#[test]
fn fmt_deterministic_main_block() {
    let messy = r#"
~ rite
 $x=1
   ~if $x>0
!say"positive"
~else
 !say"negative"
  ~end
~ end
"#;

    let normalized = normalize(messy);
    let expected = "~ rite
    $x = 1
    ~ if $x > 0
        !say \"positive\"
    ~ else
        !say \"negative\"
    ~ end
~ end
";
    assert_eq!(normalized, expected);
}

#[test]
fn fmt_idempotent_fn_and_loop() {
    let messy = r#"
~ fn add($a,$b)
    ^$a+$b
~end

~ rite
        ~loop 10
    $sum    =add(1,2)
     ~end
~end
"#;

    let first = normalize(messy);
    let second = normalize(&first);
    assert_eq!(first, second);
}

#[test]
fn fmt_preserves_t2b_function_annotations() {
    let messy = r#"
~ fn add($left:F64,$right: F64)->F64
 ^ $left+$right
~end
"#;
    let first = normalize(messy);
    assert_eq!(
        first,
        "~ fn add($left: F64, $right: F64) -> F64\n    ^ $left + $right\n~ end\n"
    );
    assert_eq!(normalize(&first), first);
}
