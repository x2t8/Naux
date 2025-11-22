use naux::lexer::lex;
use naux::parser::parser::Parser;

#[test]
fn parses_fn_block() {
    let src = r#"
~ fn add($a, $b)
    ^ $a + $b
~ end
"#;
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    assert_eq!(ast.len(), 1);
}
