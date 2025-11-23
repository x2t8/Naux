//! Dynasm-based JIT emitter using RawValue stack and helper bridge.
#![allow(dead_code)]

#[cfg(feature = "jit")]
mod enabled {
    use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi, DynamicLabel};
    use dynasmrt::x64::Assembler;
    use crate::runtime::value::{RawValue, ValueTag};
    use crate::vm::bytecode::Instr;

    const RAW_SIZE: i32 = 16;
    const TAG_OFFSET: i32 = 0;
    const PAYLOAD_OFFSET: i32 = 8;
    const RAW_STACK_SLOTS: usize = 256;
    const VALUE_TAG_FLOAT: i32 = ValueTag::Float as i32;

    extern "C" {
        fn jit_helper_len(arg: *const RawValue, out: *mut RawValue) -> i32;
        fn jit_helper_index(target: *const RawValue, idx: *const RawValue, out: *mut RawValue) -> i32;
    }

    fn emit_stack_alloc(ops: &mut Assembler, locals: usize) {
        let total_bytes = ((RAW_STACK_SLOTS + locals) * RAW_SIZE as usize) as i32;
        dynasm!(ops
            ; .arch x64
            ; push rbp
            ; mov rbp, rsp
            ; sub rsp, total_bytes
            ; mov r13, rsp
            ; lea r15, [rsp + (RAW_STACK_SLOTS * RAW_SIZE)]
            ; xor r14, r14
        );
    }

    fn emit_epilog(ops: &mut Assembler, locals: usize, end_label: &DynamicLabel) {
        let total_bytes = ((RAW_STACK_SLOTS + locals) * RAW_SIZE as usize) as i32;
        dynasm!(ops
            ; =>*end_label
            ; add rsp, total_bytes
            ; pop rbp
            ; ret
        );
    }

    fn emit_push_const(ops: &mut Assembler, bits: u64) {
        dynasm!(ops
            ; mov rax, QWORD bits as _
            ; movq [r13 + r14 * RAW_SIZE + PAYLOAD_OFFSET], rax
            ; mov BYTE [r13 + r14 * RAW_SIZE + TAG_OFFSET], VALUE_TAG_FLOAT as _
            ; inc r14
        );
    }

    fn pop_raw_to_xmm(ops: &mut Assembler, xmm: u8) {
        dynasm!(ops
            ; dec r14
            ; movq Rq(xmm)?, [r13 + r14 * RAW_SIZE + PAYLOAD_OFFSET]
        );
    }

    fn push_raw_float(ops: &mut Assembler) {
        dynasm!(ops
            ; movq [r13 + r14 * RAW_SIZE + PAYLOAD_OFFSET], xmm0
            ; mov BYTE [r13 + r14 * RAW_SIZE + TAG_OFFSET], VALUE_TAG_FLOAT as _
            ; inc r14
        );
    }

    fn emit_binop(ops: &mut Assembler, instr: &Instr) -> Result<(), String> {
        pop_raw_to_xmm(ops, 1);
        pop_raw_to_xmm(ops, 0);
        match instr {
            Instr::Add => dynasm!(ops; addsd xmm0, xmm1),
            Instr::Sub => dynasm!(ops; subsd xmm0, xmm1),
            Instr::Mul => dynasm!(ops; mulsd xmm0, xmm1),
            Instr::Div => dynasm!(ops; divsd xmm0, xmm1),
            _ => return Err("unsupported binary op".into()),
        }
        push_raw_float(ops);
        Ok(())
    }

    pub fn run_jit(code: &[Instr], locals: usize) -> Result<f64, String> {
        let mut ops = Assembler::new().map_err(|e| format!("assembler: {}", e))?;
        let mut labels = Vec::with_capacity(code.len());
        for _ in 0..code.len() {
            labels.push(ops.new_dynamic_label());
        }
        let end_label = ops.new_dynamic_label();
        emit_stack_alloc(&mut ops, locals);
        for (idx, instr) in code.iter().enumerate() {
            dynasm!(ops => labels[idx]);
            match instr {
                Instr::ConstNum(n) => emit_push_const(&mut ops, n.to_bits()),
                Instr::Add | Instr::Sub | Instr::Mul | Instr::Div => emit_binop(&mut ops, instr)?,
                Instr::Jump(target) => dynasm!(ops ; jmp =>labels[*target]),
                Instr::JumpIfFalse(target) => {
                    pop_raw_to_xmm(&mut ops, 0);
                    dynasm!(ops
                        ; xorpd xmm1, xmm1
                        ; ucomisd xmm0, xmm1
                        ; je =>labels[*target]
                    );
                }
                Instr::LoadLocal(idx) => {
                    let offset = (*idx as i32) * RAW_SIZE;
                    dynasm!(ops
                        ; mov rbx, r15
                        ; mov rax, [rbx + offset + PAYLOAD_OFFSET]
                        ; movq [r13 + r14 * RAW_SIZE + PAYLOAD_OFFSET], rax
                        ; mov BYTE [r13 + r14 * RAW_SIZE + TAG_OFFSET], VALUE_TAG_FLOAT as _
                        ; inc r14
                    );
                }
                Instr::StoreLocal(idx) => {
                    dynasm!(ops
                        ; dec r14
                        ; mov rbx, r15
                        ; mov rax, [r13 + r14 * RAW_SIZE + PAYLOAD_OFFSET]
                        ; mov [rbx + (*idx as i32) * RAW_SIZE + PAYLOAD_OFFSET], rax
                    );
                }
                Instr::CallBuiltin(name, argc) => {
                    if name == "len" && *argc == 1 {
                        dynasm!(ops
                            ; dec r14
                            ; lea rdi, [r13 + r14 * RAW_SIZE]
                            ; lea rsi, [r13 + r14 * RAW_SIZE]
                            ; call jit_helper_len
                            ; inc r14
                        );
                    } else if name == "__index" && *argc == 2 {
                        dynasm!(ops
                            ; dec r14
                            ; mov rcx, r14
                            ; dec r14
                            ; lea rdi, [r13 + r14 * RAW_SIZE]
                            ; lea rsi, [r13 + rcx * RAW_SIZE]
                            ; lea rdx, [r13 + r14 * RAW_SIZE]
                            ; call jit_helper_index
                            ; inc r14
                        );
                    } else {
                        return Err(format!("builtin {:?} not supported for JIT", name));
                    }
                }
                Instr::Return => {
                    dynasm!(ops
                        ; dec r14
                        ; movq xmm0, [r13 + r14 * RAW_SIZE + PAYLOAD_OFFSET]
                        ; jmp =>end_label
                    );
                }
                _ => return Err(format!("instr {:?} not JITable", instr)),
            }
        }
        emit_epilog(&mut ops, locals, &end_label);
        let buf = ops.finalize().map_err(|e| format!("finalize: {}", e))?;
        let entry = buf.ptr(0);
        let func: extern "C" fn() -> f64 = unsafe { std::mem::transmute(entry) };
        Ok(func())
    }
}

#[cfg(feature = "jit")]
pub use enabled::run_jit;

#[cfg(not(feature = "jit"))]
pub fn run_jit(_code: &[crate::vm::bytecode::Instr], _locals: usize) -> Result<f64, String> {
    Err("JIT feature not enabled".into())
}
