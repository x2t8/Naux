use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::parser::error::format_parse_error;
use naux::runtime::eval_script;
use naux::runtime::error::format_runtime_error_with_file;

#[test]
fn parser_error_snippet_shows_caret() {
    let src = "$x =\n";
    let tokens = lex(src).unwrap();
    let err = Parser::from_tokens(&tokens).unwrap_err();

    let rendered = format_parse_error(src, &err, "sample.nx");
    assert!(rendered.contains("Expected"));
}

#[test]
fn runtime_error_undefined_var() {
    let src = "~ rite\n    !say $x\n~ end\n";
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (_env, _events, errs) = eval_script(&ast);
    let err = errs.into_iter().next().expect("should have error");

    let rendered = format_runtime_error_with_file(src, &err, "sample.nx");
    assert!(rendered.contains("Variable not found"));
}
