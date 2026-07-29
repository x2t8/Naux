use std::cell::RefCell;
use std::collections::HashMap;
use std::os::raw::c_long;
use std::rc::Rc;

use crate::ast::{Span, Stmt};
use crate::runtime::error::RuntimeError;
use crate::runtime::value::Value;

pub type BuiltinFn = fn(Vec<Value>) -> Result<Value, RuntimeError>;

#[derive(Debug, Clone, Default)]
pub struct Scope {
    map: HashMap<String, Value>,
}

impl Scope {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

// NOTE: Env is no longer Clone. It will be shared via Rc<RefCell<>>.
#[derive(Debug)]
pub struct Env {
    stack: Vec<Scope>,
    fn_stack: Vec<HashMap<String, FunctionDef>>,
    // The parent environment for lexical scoping (used by closures).
    parent: Option<Rc<RefCell<Env>>>,
    builtins: HashMap<String, BuiltinFn>,
    unsafe_stack: Vec<bool>,
}

#[derive(Debug, Clone)]
pub struct FunctionDef {
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
    pub span: Option<Span>,
}

impl Env {
    pub fn new() -> Self {
        let mut env = Self {
            stack: vec![Scope::new()],
            fn_stack: vec![HashMap::new()],
            parent: None,
            builtins: HashMap::new(),
            unsafe_stack: vec![false],
        };
        register_builtins(&mut env);
        env
    }

    // Creates a new environment for a function call, lexically nested inside its parent.
    pub fn new_with_parent(parent: Rc<RefCell<Env>>) -> Self {
        let inherited_unsafe = parent.borrow().unsafe_stack.clone();
        Self {
            stack: vec![Scope::new()],
            fn_stack: vec![HashMap::new()],
            parent: Some(parent),
            builtins: HashMap::new(), // Builtins are found via the parent chain.
            unsafe_stack: inherited_unsafe, // Inherit unsafe status
        }
    }

    pub fn push_scope(&mut self) {
        self.stack.push(Scope::new());
        self.fn_stack.push(HashMap::new());
    }

    pub fn pop_scope(&mut self) {
        if self.stack.len() > 1 {
            self.stack.pop();
        }
        if self.fn_stack.len() > 1 {
            self.fn_stack.pop();
        }
    }

    pub fn set(&mut self, name: &str, val: Value) {
        // In Naux, `let` defines in the current scope.
        if let Some(top) = self.stack.last_mut() {
            top.map.insert(name.to_string(), val);
        }
    }

    pub fn assign(&mut self, name: &str, val: Value) -> bool {
        for scope in self.stack.iter_mut().rev() {
            if scope.map.contains_key(name) {
                scope.map.insert(name.to_string(), val);
                return true;
            }
        }
        // If not in local scopes, try assigning to parent's scope.
        if let Some(parent) = &self.parent {
            return parent.borrow_mut().assign(name, val);
        }
        false
    }

    pub fn get(&self, name: &str) -> Option<Value> {
        // Search local scopes first, from inner to outer.
        for scope in self.stack.iter().rev() {
            if let Some(v) = scope.map.get(name) {
                return Some(v.clone());
            }
        }
        // If not found locally, traverse the parent chain.
        if let Some(parent) = &self.parent {
            return parent.borrow().get(name);
        }
        // Builtins are callable but not first-class values yet.
        None
    }

    pub fn let_def(&mut self, name: String, val: Value) {
        self.set(&name, val);
    }

    pub fn define_fn(
        &mut self,
        name: &str,
        params: Vec<String>,
        body: Vec<Stmt>,
        span: Option<Span>,
    ) {
        if let Some(top) = self.fn_stack.last_mut() {
            top.insert(name.to_string(), FunctionDef { params, body, span });
        }
    }

    pub fn get_fn(&self, name: &str) -> Option<FunctionDef> {
        for scope in self.fn_stack.iter().rev() {
            if let Some(def) = scope.get(name) {
                return Some(def.clone());
            }
        }
        if let Some(parent) = &self.parent {
            return parent.borrow().get_fn(name);
        }
        None
    }

    pub fn call_builtin(
        &self,
        name: &str,
        args: Vec<Value>,
    ) -> Option<Result<Value, RuntimeError>> {
        if let Some(f) = self.builtins.get(name) {
            return Some(f(args));
        }
        if let Some(parent) = &self.parent {
            return parent.borrow().call_builtin(name, args);
        }
        self.builtins.get(name).map(|f| f(args))
    }

    pub fn set_builtin(&mut self, name: &str, f: BuiltinFn) {
        self.builtins.insert(name.to_string(), f);
    }

    pub fn builtins(&self) -> HashMap<String, BuiltinFn> {
        self.builtins.clone()
    }

    pub fn push_unsafe(&mut self, enabled: bool) {
        let current = *self.unsafe_stack.last().unwrap_or(&false);
        self.unsafe_stack.push(current || enabled);
    }

    pub fn pop_unsafe(&mut self) {
        if self.unsafe_stack.len() > 1 {
            self.unsafe_stack.pop();
        }
    }

    pub fn is_unsafe(&self) -> bool {
        *self.unsafe_stack.last().unwrap_or(&false)
    }
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}

fn register_builtins(env: &mut Env) {
    env.builtins.insert("len".into(), builtin_len);
    env.builtins.insert("to_text".into(), builtin_to_text);
    env.builtins.insert("__index".into(), builtin_index);
    env.builtins.insert("__setindex".into(), builtin_setindex);
    env.builtins.insert("__bytes".into(), builtin_bytes);
    env.builtins.insert("__syscall".into(), builtin_syscall);
    env.builtins.insert("__bit_xor".into(), builtin_bit_xor);
    env.builtins.insert("__bit_shl".into(), builtin_bit_shl);
}

fn builtin_len(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let arg = args.first().cloned().unwrap_or(Value::Null);
    let len = match arg {
        Value::RcObj(rc) => match rc.as_ref() {
            crate::runtime::value::NauxObj::List(v) => v.borrow().len(),
            crate::runtime::value::NauxObj::Text(s) => s.chars().count(),
            crate::runtime::value::NauxObj::Bytes(v) => v.borrow().len(),
            crate::runtime::value::NauxObj::Map(m) => m.borrow().len(),
            _ => 0,
        },
        _ => 0,
    };
    Ok(Value::SmallInt(len as i64))
}

fn builtin_to_text(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let arg = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::make_text(arg.to_display_text()))
}

fn builtin_index(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("__index(list/map, key)", None));
    }
    let target = args[0].clone();
    let key = args[1].clone();
    match (target, key) {
        (Value::RcObj(rc), Value::SmallInt(n)) => match rc.as_ref() {
            crate::runtime::value::NauxObj::List(v) => {
                Ok(v.borrow().get(n as usize).cloned().unwrap_or(Value::Null))
            }
            crate::runtime::value::NauxObj::Bytes(v) => Ok(v
                .borrow()
                .get(n as usize)
                .map(|b| Value::SmallInt(*b as i64))
                .unwrap_or(Value::Null)),
            _ => Err(RuntimeError::new("invalid __index operands", None)),
        },
        (Value::RcObj(rc), Value::Float(n)) => match rc.as_ref() {
            crate::runtime::value::NauxObj::List(v) => {
                Ok(v.borrow().get(n as usize).cloned().unwrap_or(Value::Null))
            }
            crate::runtime::value::NauxObj::Bytes(v) => Ok(v
                .borrow()
                .get(n as usize)
                .map(|b| Value::SmallInt(*b as i64))
                .unwrap_or(Value::Null)),
            _ => Err(RuntimeError::new("invalid __index operands", None)),
        },
        (Value::RcObj(rc), Value::RcObj(key_rc)) => match (rc.as_ref(), key_rc.as_ref()) {
            (crate::runtime::value::NauxObj::Map(m), crate::runtime::value::NauxObj::Text(s)) => {
                Ok(m.borrow().get(s).cloned().unwrap_or(Value::Null))
            }
            _ => Err(RuntimeError::new("invalid __index operands", None)),
        },
        _ => Err(RuntimeError::new("invalid __index operands", None)),
    }
}

fn builtin_setindex(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("__setindex(list/map, key, value)", None));
    }
    let target = args[0].clone();
    let key = args[1].clone();
    let value = args[2].clone();
    match (target, key) {
        (Value::RcObj(rc), Value::SmallInt(n)) => match rc.as_ref() {
            crate::runtime::value::NauxObj::List(list) => {
                if n < 0 {
                    return Err(RuntimeError::new("index cannot be negative", None));
                }
                let rc_out = rc.clone();
                let idx = n as usize;
                let mut items = list.borrow_mut();
                if idx >= items.len() {
                    return Err(RuntimeError::new("index out of range", None));
                }
                items[idx] = value;
                Ok(Value::RcObj(rc_out))
            }
            crate::runtime::value::NauxObj::Bytes(bytes) => {
                if n < 0 {
                    return Err(RuntimeError::new("index cannot be negative", None));
                }
                let Some(byte) = value_to_byte(&value) else {
                    return Err(RuntimeError::new(
                        "byte value must be in range 0..=255",
                        None,
                    ));
                };
                let idx = n as usize;
                let rc_out = rc.clone();
                let mut buf = bytes.borrow_mut();
                if idx >= buf.len() {
                    return Err(RuntimeError::new("index out of range", None));
                }
                buf[idx] = byte;
                Ok(Value::RcObj(rc_out))
            }
            _ => Err(RuntimeError::new("invalid __setindex operands", None)),
        },
        (Value::RcObj(rc), Value::Float(n)) => match rc.as_ref() {
            crate::runtime::value::NauxObj::List(list) => {
                if n.fract() != 0.0 || n < 0.0 {
                    return Err(RuntimeError::new(
                        "index must be a non-negative integer",
                        None,
                    ));
                }
                let rc_out = rc.clone();
                let idx = n as usize;
                let mut items = list.borrow_mut();
                if idx >= items.len() {
                    return Err(RuntimeError::new("index out of range", None));
                }
                items[idx] = value;
                Ok(Value::RcObj(rc_out))
            }
            crate::runtime::value::NauxObj::Bytes(bytes) => {
                if n.fract() != 0.0 || n < 0.0 {
                    return Err(RuntimeError::new(
                        "index must be a non-negative integer",
                        None,
                    ));
                }
                let Some(byte) = value_to_byte(&value) else {
                    return Err(RuntimeError::new(
                        "byte value must be in range 0..=255",
                        None,
                    ));
                };
                let idx = n as usize;
                let rc_out = rc.clone();
                let mut buf = bytes.borrow_mut();
                if idx >= buf.len() {
                    return Err(RuntimeError::new("index out of range", None));
                }
                buf[idx] = byte;
                Ok(Value::RcObj(rc_out))
            }
            _ => Err(RuntimeError::new("invalid __setindex operands", None)),
        },
        (Value::RcObj(rc), Value::RcObj(key_rc)) => match (rc.as_ref(), key_rc.as_ref()) {
            (crate::runtime::value::NauxObj::Map(map), crate::runtime::value::NauxObj::Text(s)) => {
                let rc_out = rc.clone();
                map.borrow_mut().insert(s.clone(), value);
                Ok(Value::RcObj(rc_out))
            }
            _ => Err(RuntimeError::new("invalid __setindex operands", None)),
        },
        _ => Err(RuntimeError::new("invalid __setindex operands", None)),
    }
}

fn builtin_bytes(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("__bytes(list)", None));
    }
    let src = args.first().cloned().unwrap_or(Value::Null);
    match src {
        Value::RcObj(rc) => match rc.as_ref() {
            crate::runtime::value::NauxObj::Bytes(v) => Ok(Value::make_bytes(v.borrow().clone())),
            crate::runtime::value::NauxObj::List(list) => {
                let mut out = Vec::with_capacity(list.borrow().len());
                for item in list.borrow().iter() {
                    let Some(byte) = value_to_byte(item) else {
                        return Err(RuntimeError::new(
                            "__bytes expects numeric items in range 0..=255",
                            None,
                        ));
                    };
                    out.push(byte);
                }
                Ok(Value::make_bytes(out))
            }
            _ => Err(RuntimeError::new("__bytes expects list or bytes", None)),
        },
        _ => Err(RuntimeError::new("__bytes expects list or bytes", None)),
    }
}

fn value_to_byte(value: &Value) -> Option<u8> {
    match value {
        Value::SmallInt(n) if (0..=255).contains(n) => Some(*n as u8),
        Value::Float(n) if n.fract() == 0.0 && (0.0..=255.0).contains(n) => Some(*n as u8),
        _ => None,
    }
}

fn value_to_i64_exact(value: &Value) -> Option<i64> {
    match value {
        Value::SmallInt(n) => Some(*n),
        Value::Float(n) if n.fract() == 0.0 => Some(*n as i64),
        _ => None,
    }
}

fn builtin_bit_xor(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("__bit_xor expects 2 args", None));
    }
    let Some(lhs) = value_to_i64_exact(&args[0]) else {
        return Err(RuntimeError::new(
            "__bit_xor expects integer-compatible numbers",
            None,
        ));
    };
    let Some(rhs) = value_to_i64_exact(&args[1]) else {
        return Err(RuntimeError::new(
            "__bit_xor expects integer-compatible numbers",
            None,
        ));
    };
    Ok(Value::SmallInt(lhs ^ rhs))
}

fn builtin_bit_shl(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("__bit_shl expects 2 args", None));
    }
    let Some(lhs) = value_to_i64_exact(&args[0]) else {
        return Err(RuntimeError::new(
            "__bit_shl expects integer-compatible numbers",
            None,
        ));
    };
    let Some(rhs) = value_to_i64_exact(&args[1]) else {
        return Err(RuntimeError::new(
            "__bit_shl expects integer-compatible numbers",
            None,
        ));
    };
    if rhs < 0 {
        return Err(RuntimeError::new(
            "__bit_shl shift count must be non-negative",
            None,
        ));
    }
    Ok(Value::SmallInt(lhs << (rhs as u32)))
}

fn builtin_syscall(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.is_empty() {
        return Err(RuntimeError::new(
            "__syscall expects at least 1 argument (syscall number)",
            None,
        ));
    }
    if args.len() > 7 {
        return Err(RuntimeError::new(
            "__syscall supports at most 6 arguments",
            None,
        ));
    }
    let nr = value_to_c_long(&args[0])?;
    let mut call_args = Vec::with_capacity(args.len().saturating_sub(1));
    for arg in args.iter().skip(1) {
        call_args.push(value_to_c_long(arg)?);
    }
    let ret = invoke_raw_syscall(nr, &call_args)?;
    #[cfg(all(not(windows), target_pointer_width = "64"))]
    let ret_i64 = ret;
    #[cfg(any(windows, target_pointer_width = "32"))]
    let ret_i64 = i64::from(ret);
    Ok(Value::SmallInt(ret_i64))
}

fn value_to_c_long(value: &Value) -> Result<c_long, RuntimeError> {
    match value {
        Value::SmallInt(n) => Ok(*n as c_long),
        Value::Float(n) if n.fract() == 0.0 => Ok(*n as c_long),
        _ => Err(RuntimeError::new(
            "__syscall arguments must be integer-compatible numbers",
            None,
        )),
    }
}

fn invoke_raw_syscall(nr: c_long, args: &[c_long]) -> Result<c_long, RuntimeError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        unsafe {
            unsafe extern "C" {
                fn syscall(num: c_long, ...) -> c_long;
            }
            let ret = match args.len() {
                0 => syscall(nr),
                1 => syscall(nr, args[0]),
                2 => syscall(nr, args[0], args[1]),
                3 => syscall(nr, args[0], args[1], args[2]),
                4 => syscall(nr, args[0], args[1], args[2], args[3]),
                5 => syscall(nr, args[0], args[1], args[2], args[3], args[4]),
                6 => syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]),
                _ => {
                    return Err(RuntimeError::new(
                        "__syscall supports at most 6 arguments",
                        None,
                    ))
                }
            };
            Ok(ret)
        }
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (nr, args);
        Err(RuntimeError::new(
            "__syscall is only supported on linux x86_64",
            None,
        ))
    }
}
