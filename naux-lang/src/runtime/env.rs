use std::collections::HashMap;

use crate::runtime::value::Value;
use crate::runtime::error::RuntimeError;

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
}

impl Env {
    pub fn new() -> Self {
        let mut env = Self {
            stack: vec![Scope::new()],
            builtins: HashMap::new(),
            unsafe_stack: vec![false],
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
}

fn register_builtins(env: &mut Env) {
    env.builtins.insert("len".into(), builtin_len);
    env.builtins.insert("to_text".into(), builtin_to_text);
    env.builtins.insert("__index".into(), builtin_index);
}

fn builtin_len(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let arg = args.get(0).cloned().unwrap_or(Value::Null);
    let len = match arg {
        Value::List(v) => v.len(),
        Value::Text(s) => s.chars().count(),
        Value::Map(m) => m.len(),
        _ => 0,
    };
    Ok(Value::Number(len as f64))
}

fn builtin_to_text(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let arg = args.get(0).cloned().unwrap_or(Value::Null);
    Ok(Value::Text(format!("{:?}", arg)))
}

fn builtin_index(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("__index(list/map, key)", None));
    }
    let target = args[0].clone();
    let key = args[1].clone();
    match (target, key) {
        (Value::List(v), Value::Number(n)) => {
            let i = n as usize;
            Ok(v.get(i).cloned().unwrap_or(Value::Null))
        }
        (Value::Map(m), Value::Text(s)) => Ok(m.get(&s).cloned().unwrap_or(Value::Null)),
        _ => Err(RuntimeError::new("invalid __index operands", None)),
    }
}
