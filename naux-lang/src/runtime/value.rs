use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::collections::BTreeSet;
use std::cmp::Ordering;
use crate::ast::Stmt;

#[derive(Debug, Clone)]
pub enum Value {
    Number(f64),
    Bool(bool),
    Text(String),
    List(Vec<Value>),
    Map(HashMap<String, Value>),
    Graph(Rc<RefCell<Graph>>),
    Set(BTreeSet<Value>),
    PriorityQueue(Vec<Value>),
    Function(Rc<Function>),
    Null,
}

#[derive(Debug, Clone)]
pub struct Graph {
    pub directed: bool,
    pub adj: HashMap<String, Vec<(String, f64)>>, // neighbor, weight
}

#[derive(Debug, Clone)]
pub struct Function {
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Number(n) => *n != 0.0,
            Value::Text(s) => !s.is_empty(),
            Value::List(v) => !v.is_empty(),
            Value::Map(m) => !m.is_empty(),
            Value::Graph(_) => true,
            Value::Set(s) => !s.is_empty(),
            Value::PriorityQueue(pq) => !pq.is_empty(),
            Value::Function(_) => true,
            Value::Null => false,
        }
    }

    pub fn add(a: &Value, b: &Value) -> Value {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => Value::Number(x + y),
            (Value::Text(x), Value::Text(y)) => Value::Text(format!("{}{}", x, y)),
            _ => Value::Null,
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Number(a), Value::Number(b)) => (*a - *b).abs() < f64::EPSILON,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Text(a), Value::Text(b)) => a == b,
            (Value::List(a), Value::List(b)) => a == b,
            (Value::Map(a), Value::Map(b)) => a == b,
            (Value::Null, Value::Null) => true,
            (Value::Graph(a), Value::Graph(b)) => Rc::ptr_eq(a, b),
            (Value::Set(a), Value::Set(b)) => a == b,
            (Value::PriorityQueue(a), Value::PriorityQueue(b)) => a == b,
            (Value::Function(a), Value::Function(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        // Basic ordering for PQ: by number if both numbers, else by Debug string
        match (self, other) {
            (Value::Number(a), Value::Number(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
            _ => format!("{:?}", self).cmp(&format!("{:?}", other)),
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
