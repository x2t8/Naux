use naux::vm::bytecode::{disasm_block, disasm_window, Instr};

#[test]
fn disasm_block_lists_ops() {
    let code = vec![Instr::ConstNum(1.0), Instr::ConstNum(2.0), Instr::Add, Instr::Return];
    let text = disasm_block(&code);
    assert!(text.contains("ConstNum 1"));
    assert!(text.contains("Add"));
    assert!(text.contains("Return"));
}

#[test]
fn disasm_window_marks_ip() {
    let code = vec![Instr::ConstNum(1.0), Instr::ConstNum(2.0), Instr::Add, Instr::Return];
    let text = disasm_window(&code, 2, 1);
    assert!(text.contains("--> 0002: Add"));
    assert!(text.contains("0001: ConstNum"));
}
