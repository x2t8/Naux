//! NXB (NAUX bytecode) stable encoding: deterministic, versioned, no external deps.
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::ast::Span;
use crate::typecheck::Type;
use crate::vm::bytecode::{FunctionBytecode, Instr, LoweringContext, Program, VmResult};

const MAGIC: &[u8; 4] = b"NXB1";
const VERSION: u8 = 2;

/// Encode a `Program` into stable NXB bytes.
pub fn encode_program(prog: &Program) -> VmResult<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);

    encode_locals(&mut buf, &prog.main_locals);
    encode_spans(&mut buf, &prog.main_spans);
    encode_types(&mut buf, &prog.main_result_types);
    encode_bool_flags(&mut buf, &prog.main_unsafe_flags);
    encode_opt_type(&mut buf, &prog.main_return);
    encode_code(&mut buf, &prog.main)?;

    // Functions serialized in sorted order for determinism.
    let mut funcs: BTreeMap<String, FunctionBytecode> = BTreeMap::new();
    for (k, v) in prog.functions.iter() {
        funcs.insert(k.clone(), v.clone());
    }
    push_u32(&mut buf, funcs.len() as u32);
    for (name, func) in funcs {
        encode_string(&mut buf, &name);
        encode_locals(&mut buf, &func.params);
        encode_locals(&mut buf, &func.locals);
        encode_spans(&mut buf, &func.spans);
        encode_types(&mut buf, &func.result_types);
        encode_bool_flags(&mut buf, &func.unsafe_flags);
        encode_opt_type(&mut buf, &func.return_type);
        encode_code(&mut buf, &func.code)?;
    }

    Ok(buf)
}

/// Decode NXB bytes back into a `Program`.
pub fn decode_program(data: &[u8]) -> VmResult<Program> {
    let mut cur = Cursor::new(data);
    if cur.read_exact(MAGIC.len()) != MAGIC {
        return Err("Invalid NXB magic".into());
    }
    let ver = cur.read_u8()?;
    if ver != 1 && ver != VERSION {
        return Err(format!("Unsupported NXB version {}", ver));
    }

    let main_locals = decode_locals(&mut cur)?;
    let main_spans = decode_spans(&mut cur)?;
    let main_result_types = decode_types(&mut cur)?;
    let main_unsafe_flags = if ver >= 2 {
        decode_bool_flags(&mut cur)?
    } else {
        vec![false; main_result_types.len()]
    };
    let main_return = decode_opt_type(&mut cur)?;
    let main = decode_code(&mut cur)?;

    let func_count = cur.read_u32()? as usize;
    let mut functions = BTreeMap::new();
    for _ in 0..func_count {
        let name = cur.read_string()?;
        let params = decode_locals(&mut cur)?;
        let locals = decode_locals(&mut cur)?;
        let spans = decode_spans(&mut cur)?;
        let result_types = decode_types(&mut cur)?;
        let unsafe_flags = if ver >= 2 {
            decode_bool_flags(&mut cur)?
        } else {
            vec![false; result_types.len()]
        };
        let return_type = decode_opt_type(&mut cur)?;
        let code = decode_code(&mut cur)?;
        functions.insert(
            name,
            FunctionBytecode {
                params,
                locals,
                code,
                spans,
                result_types,
                unsafe_flags,
                lowering_context: LoweringContext::default(),
                return_type,
            },
        );
    }

    Ok(Program {
        main,
        main_locals,
        main_spans,
        main_result_types,
        main_unsafe_flags,
        main_lowering_context: LoweringContext::default(),
        main_return,
        functions: functions.into_iter().collect(),
    })
}

pub fn write_nxb(path: &Path, prog: &Program) -> VmResult<()> {
    let bytes = encode_program(prog)?;
    fs::write(path, &bytes).map_err(|e| format!("Failed to write {}: {}", path.display(), e))
}

pub fn read_nxb(path: &Path) -> VmResult<Program> {
    let data = fs::read(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    decode_program(&data)
}

fn encode_locals(buf: &mut Vec<u8>, locals: &[String]) {
    push_u32(buf, locals.len() as u32);
    for l in locals {
        encode_string(buf, l);
    }
}

fn encode_spans(buf: &mut Vec<u8>, spans: &[Option<Span>]) {
    push_u32(buf, spans.len() as u32);
    for sp in spans {
        match sp {
            Some(s) => {
                buf.push(1);
                push_u32(buf, s.line as u32);
                push_u32(buf, s.column as u32);
            }
            None => buf.push(0),
        }
    }
}

fn encode_types(buf: &mut Vec<u8>, tys: &[Option<Type>]) {
    push_u32(buf, tys.len() as u32);
    for t in tys {
        encode_opt_type(buf, t);
    }
}

fn encode_bool_flags(buf: &mut Vec<u8>, flags: &[bool]) {
    push_u32(buf, flags.len() as u32);
    for flag in flags {
        buf.push(u8::from(*flag));
    }
}

fn encode_opt_type(buf: &mut Vec<u8>, ty: &Option<Type>) {
    match ty {
        Some(t) => {
            buf.push(1);
            encode_type(buf, t);
        }
        None => buf.push(0),
    }
}

fn encode_type(buf: &mut Vec<u8>, ty: &Type) {
    match ty {
        Type::Any => {
            buf.push(0);
        }
        Type::Num => buf.push(1),
        Type::Bool => buf.push(2),
        Type::Text => buf.push(3),
        Type::List(inner) => {
            buf.push(4);
            encode_type(buf, inner);
        }
        Type::Map(inner) => {
            buf.push(5);
            encode_type(buf, inner);
        }
        Type::Function { params } => {
            buf.push(6);
            push_u32(buf, *params as u32);
        }
        Type::Null => buf.push(7),
        Type::Bytes => buf.push(8),
    }
}

fn encode_code(buf: &mut Vec<u8>, code: &[Instr]) -> VmResult<()> {
    push_u32(buf, code.len() as u32);
    for instr in code {
        encode_instr(buf, instr)?;
    }
    Ok(())
}

fn encode_instr(buf: &mut Vec<u8>, instr: &Instr) -> VmResult<()> {
    match instr {
        Instr::ConstNum(n) => {
            buf.push(0);
            push_f64(buf, *n);
        }
        Instr::ConstText(s) => {
            buf.push(1);
            encode_string(buf, s);
        }
        Instr::ConstBool(b) => {
            buf.push(2);
            buf.push(if *b { 1 } else { 0 });
        }
        Instr::PushNull => buf.push(3),
        Instr::LoadLocal(i) => {
            buf.push(4);
            push_u32(buf, *i as u32);
        }
        Instr::StoreLocal(i) => {
            buf.push(5);
            push_u32(buf, *i as u32);
        }
        Instr::StoreLocalKeep(i) => {
            buf.push(37);
            push_u32(buf, *i as u32);
        }
        Instr::AddLocalConst(i, c) => {
            buf.push(38);
            push_u32(buf, *i as u32);
            push_f64(buf, *c);
        }
        Instr::JumpLocalIfFalse(i, t) => {
            buf.push(39);
            push_u32(buf, *i as u32);
            push_u32(buf, *t as u32);
        }
        Instr::Add => buf.push(6),
        Instr::Sub => buf.push(7),
        Instr::Mul => buf.push(8),
        Instr::Div => buf.push(9),
        Instr::Mod => buf.push(10),
        Instr::Xor => buf.push(35),
        Instr::Shl => buf.push(36),
        Instr::Eq => buf.push(11),
        Instr::Ne => buf.push(12),
        Instr::Gt => buf.push(13),
        Instr::Ge => buf.push(14),
        Instr::Lt => buf.push(15),
        Instr::Le => buf.push(16),
        Instr::And => buf.push(17),
        Instr::Or => buf.push(18),
        Instr::Jump(t) => {
            buf.push(19);
            push_u32(buf, *t as u32);
        }
        Instr::JumpIfFalse(t) => {
            buf.push(20);
            push_u32(buf, *t as u32);
        }
        Instr::CallBuiltin(name, argc) => {
            buf.push(21);
            encode_string(buf, name);
            push_u32(buf, *argc as u32);
        }
        Instr::CallFn(name, argc) => {
            buf.push(22);
            encode_string(buf, name);
            push_u32(buf, *argc as u32);
        }
        Instr::MakeList(n) => {
            buf.push(23);
            push_u32(buf, *n as u32);
        }
        Instr::MakeMap(keys) => {
            buf.push(24);
            push_u32(buf, keys.len() as u32);
            for k in keys {
                encode_string(buf, k);
            }
        }
        Instr::LoadField(f) => {
            buf.push(25);
            encode_string(buf, f);
        }
        Instr::EmitSay => buf.push(26),
        Instr::EmitAsk => buf.push(27),
        Instr::EmitFetch => buf.push(28),
        Instr::EmitUi(k) => {
            buf.push(29);
            encode_string(buf, k);
        }
        Instr::EmitText => buf.push(30),
        Instr::EmitButton => buf.push(31),
        Instr::EmitLog => buf.push(32),
        Instr::Pop => buf.push(34),
        Instr::Return => buf.push(33),
    }
    Ok(())
}

fn decode_locals(cur: &mut Cursor) -> VmResult<Vec<String>> {
    let len = cur.read_u32()? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(cur.read_string()?);
    }
    Ok(out)
}

fn decode_spans(cur: &mut Cursor) -> VmResult<Vec<Option<Span>>> {
    let len = cur.read_u32()? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let tag = cur.read_u8()?;
        if tag == 0 {
            out.push(None);
        } else {
            let line = cur.read_u32()? as usize;
            let column = cur.read_u32()? as usize;
            out.push(Some(Span { line, column }));
        }
    }
    Ok(out)
}

fn decode_types(cur: &mut Cursor) -> VmResult<Vec<Option<Type>>> {
    let len = cur.read_u32()? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(decode_opt_type(cur)?);
    }
    Ok(out)
}

fn decode_bool_flags(cur: &mut Cursor) -> VmResult<Vec<bool>> {
    let len = cur.read_u32()? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(cur.read_u8()? != 0);
    }
    Ok(out)
}

fn decode_opt_type(cur: &mut Cursor) -> VmResult<Option<Type>> {
    let tag = cur.read_u8()?;
    if tag == 0 {
        Ok(None)
    } else {
        decode_type(cur).map(Some)
    }
}

fn decode_type(cur: &mut Cursor) -> VmResult<Type> {
    match cur.read_u8()? {
        0 => Ok(Type::Any),
        1 => Ok(Type::Num),
        2 => Ok(Type::Bool),
        3 => Ok(Type::Text),
        4 => Ok(Type::List(Box::new(decode_type(cur)?))),
        5 => Ok(Type::Map(Box::new(decode_type(cur)?))),
        6 => {
            let params = cur.read_u32()? as usize;
            Ok(Type::Function { params })
        }
        7 => Ok(Type::Null),
        8 => Ok(Type::Bytes),
        other => Err(format!("Unknown type tag {}", other)),
    }
}

fn decode_code(cur: &mut Cursor) -> VmResult<Vec<Instr>> {
    let len = cur.read_u32()? as usize;
    let mut code = Vec::with_capacity(len);
    for _ in 0..len {
        code.push(decode_instr(cur)?);
    }
    Ok(code)
}

fn decode_instr(cur: &mut Cursor) -> VmResult<Instr> {
    match cur.read_u8()? {
        0 => Ok(Instr::ConstNum(cur.read_f64()?)),
        1 => Ok(Instr::ConstText(cur.read_string()?)),
        2 => Ok(Instr::ConstBool(cur.read_u8()? != 0)),
        3 => Ok(Instr::PushNull),
        4 => Ok(Instr::LoadLocal(cur.read_u32()? as usize)),
        5 => Ok(Instr::StoreLocal(cur.read_u32()? as usize)),
        37 => Ok(Instr::StoreLocalKeep(cur.read_u32()? as usize)),
        38 => Ok(Instr::AddLocalConst(
            cur.read_u32()? as usize,
            cur.read_f64()?,
        )),
        39 => Ok(Instr::JumpLocalIfFalse(
            cur.read_u32()? as usize,
            cur.read_u32()? as usize,
        )),
        6 => Ok(Instr::Add),
        7 => Ok(Instr::Sub),
        8 => Ok(Instr::Mul),
        9 => Ok(Instr::Div),
        10 => Ok(Instr::Mod),
        35 => Ok(Instr::Xor),
        36 => Ok(Instr::Shl),
        11 => Ok(Instr::Eq),
        12 => Ok(Instr::Ne),
        13 => Ok(Instr::Gt),
        14 => Ok(Instr::Ge),
        15 => Ok(Instr::Lt),
        16 => Ok(Instr::Le),
        17 => Ok(Instr::And),
        18 => Ok(Instr::Or),
        19 => Ok(Instr::Jump(cur.read_u32()? as usize)),
        20 => Ok(Instr::JumpIfFalse(cur.read_u32()? as usize)),
        21 => {
            let name = cur.read_string()?;
            let argc = cur.read_u32()? as usize;
            Ok(Instr::CallBuiltin(name, argc))
        }
        22 => {
            let name = cur.read_string()?;
            let argc = cur.read_u32()? as usize;
            Ok(Instr::CallFn(name, argc))
        }
        23 => Ok(Instr::MakeList(cur.read_u32()? as usize)),
        24 => {
            let len = cur.read_u32()? as usize;
            let mut keys = Vec::with_capacity(len);
            for _ in 0..len {
                keys.push(cur.read_string()?);
            }
            Ok(Instr::MakeMap(keys))
        }
        25 => Ok(Instr::LoadField(cur.read_string()?)),
        26 => Ok(Instr::EmitSay),
        27 => Ok(Instr::EmitAsk),
        28 => Ok(Instr::EmitFetch),
        29 => Ok(Instr::EmitUi(cur.read_string()?)),
        30 => Ok(Instr::EmitText),
        31 => Ok(Instr::EmitButton),
        32 => Ok(Instr::EmitLog),
        33 => Ok(Instr::Return),
        34 => Ok(Instr::Pop),
        other => Err(format!("Unknown instruction tag {}", other)),
    }
}

fn encode_string(buf: &mut Vec<u8>, s: &str) {
    push_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_f64(buf: &mut Vec<u8>, v: f64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Vec<u8> {
        if self.pos + len > self.data.len() {
            self.pos = self.data.len();
            Vec::new()
        } else {
            let out = self.data[self.pos..self.pos + len].to_vec();
            self.pos += len;
            out
        }
    }

    fn read_u8(&mut self) -> VmResult<u8> {
        self.read_exact(1)
            .first()
            .copied()
            .ok_or_else(|| "Unexpected EOF".into())
    }

    fn read_u32(&mut self) -> VmResult<u32> {
        let bytes = self.read_exact(4);
        if bytes.len() != 4 {
            return Err("Unexpected EOF".into());
        }
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_f64(&mut self) -> VmResult<f64> {
        let bytes = self.read_exact(8);
        if bytes.len() != 8 {
            return Err("Unexpected EOF".into());
        }
        Ok(f64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_string(&mut self) -> VmResult<String> {
        let len = self.read_u32()? as usize;
        let bytes = self.read_exact(len);
        if bytes.len() != len {
            return Err("Unexpected EOF".into());
        }
        String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn roundtrip_program() {
        let prog = Program {
            main: vec![
                Instr::ConstNum(1.0),
                Instr::StoreLocalKeep(0),
                Instr::AddLocalConst(0, 2.0),
                Instr::JumpLocalIfFalse(0, 5),
                Instr::LoadLocal(0),
                Instr::Return,
            ],
            main_locals: vec!["x".into()],
            main_spans: vec![None, None, None, None, None, None],
            main_result_types: vec![Some(Type::Num), None, None, None, Some(Type::Num), None],
            main_unsafe_flags: vec![false, false, false, false, false, false],
            main_lowering_context: LoweringContext::default(),
            main_return: Some(Type::Num),
            functions: HashMap::new(),
        };
        let bytes = encode_program(&prog).expect("encode");
        let decoded = decode_program(&bytes).expect("decode");
        assert_eq!(decoded.main.len(), prog.main.len());
        assert_eq!(decoded.main_locals, prog.main_locals);
        assert_eq!(decoded.main_return, prog.main_return);
        assert_eq!(decoded.functions.len(), 0);
        assert!(matches!(
            decoded.main.as_slice(),
            [
                Instr::ConstNum(v),
                Instr::StoreLocalKeep(0),
                Instr::AddLocalConst(0, c),
                Instr::JumpLocalIfFalse(0, 5),
                Instr::LoadLocal(0),
                Instr::Return
            ] if (*v - 1.0).abs() < f64::EPSILON && (*c - 2.0).abs() < f64::EPSILON
        ));
    }
}
