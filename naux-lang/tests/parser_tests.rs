use naux::ast::{BinaryOp, ExprKind, Stmt};
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
    let fn_def = match &ast[0] {
        Stmt::FnDef {
            name, params, body, ..
        } => (name, params, body),
        _ => panic!("Expected FnDef"),
    };
    assert_eq!(fn_def.0, "add");
    let param_names: Vec<&str> = fn_def.1.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(param_names, vec!["a", "b"]);
    assert_eq!(fn_def.2.len(), 1);
    let ret_stmt = match &fn_def.2[0] {
        Stmt::Return { value, .. } => value,
        _ => panic!("Expected Return"),
    };
    let ret_expr = match ret_stmt {
        Some(expr) => expr,
        None => panic!("Expected expression"),
    };
    let bin_op = match &ret_expr.kind {
        ExprKind::Binary { op, left, right } => (op, left, right),
        _ => panic!("Expected Binary"),
    };
    assert_eq!(bin_op.0, &BinaryOp::Add);
    let left = match &bin_op.1.kind {
        ExprKind::Var(name) => name,
        _ => panic!("Expected Var"),
    };
    assert_eq!(left, "a");
    let right = match &bin_op.2.kind {
        ExprKind::Var(name) => name,
        _ => panic!("Expected Var"),
    };
    assert_eq!(right, "b");
}

#[test]
fn parses_index_assignment() {
    let src = r#"
~ rite
    $arr = [1, 2, 3]
    $i = 1
    $arr[$i] = 9
~ end
"#;
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    assert_eq!(ast.len(), 1);
    let body = match &ast[0] {
        Stmt::Rite { body, .. } => body,
        _ => panic!("Expected Rite"),
    };
    assert_eq!(body.len(), 3);
    let assign = match &body[2] {
        Stmt::Assign { name, expr, .. } => (name, expr),
        _ => panic!("Expected Assign"),
    };
    assert_eq!(assign.0, "arr");
    let call = match &assign.1.kind {
        ExprKind::Call { callee, args } => (callee, args),
        _ => panic!("Expected Call"),
    };
    let callee_name = match &call.0.kind {
        ExprKind::Var(name) => name,
        _ => panic!("Expected Var callee"),
    };
    assert_eq!(callee_name, "__setindex");
    assert_eq!(call.1.len(), 3);
}

#[test]
fn parses_xor_and_shift_expr() {
    let src = r#"
~ rite
    $x = 3 ^ 1 << 2
~ end
"#;
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let body = match &ast[0] {
        Stmt::Rite { body, .. } => body,
        _ => panic!("Expected Rite"),
    };
    let assign_expr = match &body[0] {
        Stmt::Assign { expr, .. } => expr,
        _ => panic!("Expected Assign"),
    };
    let top = match &assign_expr.kind {
        ExprKind::Binary { op, left, right } => (op, left, right),
        _ => panic!("Expected Binary"),
    };
    assert_eq!(top.0, &BinaryOp::Xor);
    let right = match &top.2.kind {
        ExprKind::Binary { op, .. } => op,
        _ => panic!("Expected shift on right branch"),
    };
    assert_eq!(right, &BinaryOp::Shl);
}
