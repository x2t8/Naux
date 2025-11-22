use std::collections::HashMap;

use crate::runtime::value::Value;

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
}

impl Env {
    pub fn new() -> Self {
        Self {
            stack: vec![Scope::new()],
        }
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
}
