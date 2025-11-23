use std::collections::HashMap;

use crate::runtime::value::{NauxObj, Value};
use crate::runtime::error::RuntimeError;
use crate::ast::Stmt;

pub type BuiltinFn = fn(Vec<Value>) -> Result<Value, RuntimeError>;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct Env {
    stack: Vec<Scope>,
    builtins: HashMap<String, BuiltinFn>,
    unsafe_stack: Vec<bool>,
    functions: HashMap<String, FnDef>,
}

#[derive(Debug, Clone)]
pub struct FnDef {
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
    pub span: Option<crate::ast::Span>,
}

impl Env {
    pub fn new() -> Self {
        let mut env = Self {
            stack: vec![Scope::new()],
            builtins: HashMap::new(),
            unsafe_stack: vec![false],
            functions: HashMap::new(),
        };
        register_builtins(&mut env);
        env
    }

    pub fn push_scope(&mut self) {
        self.stack.push(Scope::new());
    }

    pub fn pop_scope(&mut self) {
        if self.stack.len() > 1 {
            self.stack.pop();
        }
    }

    pub fn set(&mut self, name: &str, val: Value) {
        if let Some(top) = self.stack.last_mut() {
            top.map.insert(name.to_string(), val);
        }
    }

    pub fn get(&self, name: &str) -> Option<Value> {
        for scope in self.stack.iter().rev() {
            if let Some(v) = scope.map.get(name) {
                return Some(v.clone());
            }
        }
        None
    }

    pub fn set_innermost(&mut self, name: &str, val: Value) {
        self.set(name, val);
    }

    pub fn call_builtin(&self, name: &str, args: Vec<Value>) -> Option<Result<Value, RuntimeError>> {
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

    pub fn define_fn(&mut self, name: &str, params: Vec<String>, body: Vec<Stmt>, span: Option<crate::ast::Span>) {
        self.functions.insert(name.to_string(), FnDef { params, body, span });
    }

    pub fn get_fn(&self, name: &str) -> Option<FnDef> {
        self.functions.get(name).cloned()
    }
}

fn register_builtins(env: &mut Env) {
    env.builtins.insert("len".into(), builtin_len);
    env.builtins.insert("to_text".into(), builtin_to_text);
    env.builtins.insert("__index".into(), builtin_index);
}

fn builtin_len(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let arg = args.get(0).cloned().unwrap_or(Value::Null);
    let len = match arg {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::List(v) => v.borrow().len(),
            NauxObj::Text(s) => s.chars().count(),
            NauxObj::Map(m) => m.borrow().len(),
            _ => 0,
        },
        _ => 0,
    };
    Ok(Value::SmallInt(len as i64))
}

fn builtin_to_text(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let arg = args.get(0).cloned().unwrap_or(Value::Null);
    Ok(Value::make_text(format!("{:?}", arg)))
}

fn builtin_index(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("__index(list/map, key)", None));
    }
    let target = args[0].clone();
    let key = args[1].clone();
    match (target, key) {
        (Value::RcObj(rc), Value::SmallInt(n)) => match rc.as_ref() {
            NauxObj::List(v) => Ok(v.borrow().get(n as usize).cloned().unwrap_or(Value::Null)),
            _ => Err(RuntimeError::new("invalid __index operands", None)),
        },
        (Value::RcObj(rc), Value::Float(n)) => match rc.as_ref() {
            NauxObj::List(v) => Ok(v.borrow().get(n as usize).cloned().unwrap_or(Value::Null)),
            _ => Err(RuntimeError::new("invalid __index operands", None)),
        },
        (Value::RcObj(rc), Value::RcObj(key_rc)) => match (rc.as_ref(), key_rc.as_ref()) {
            (NauxObj::Map(m), NauxObj::Text(s)) => Ok(m.borrow().get(s).cloned().unwrap_or(Value::Null)),
            _ => Err(RuntimeError::new("invalid __index operands", None)),
        },
        _ => Err(RuntimeError::new("invalid __index operands", None)),
    }
}
