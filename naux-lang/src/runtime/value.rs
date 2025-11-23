use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use crate::ast::Stmt;

/// Any runtime value for NAUX VM/interpreter.
#[derive(Debug, Clone)]
pub enum Value {
    SmallInt(i64),
    Float(f64),
    Bool(bool),
    RcObj(Rc<NauxObj>),
    Null,
}

/// Heap-allocated / ref-counted objects (cheap to clone).
#[derive(Debug)]
pub enum NauxObj {
    Text(String),
    List(RefCell<Vec<Value>>),
    Map(RefCell<HashMap<String, Value>>),
    Graph(RefCell<Graph>),
    Set(RefCell<BTreeSet<Value>>),
    PriorityQueue(RefCell<Vec<Value>>),
    Function(Function),
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

impl Clone for NauxObj {
    fn clone(&self) -> Self {
        match self {
            NauxObj::Text(s) => NauxObj::Text(s.clone()),
            NauxObj::List(v) => NauxObj::List(RefCell::new(v.borrow().clone())),
            NauxObj::Map(m) => NauxObj::Map(RefCell::new(m.borrow().clone())),
            NauxObj::Graph(g) => NauxObj::Graph(RefCell::new(g.borrow().clone())),
            NauxObj::Set(s) => NauxObj::Set(RefCell::new(s.borrow().clone())),
            NauxObj::PriorityQueue(pq) => NauxObj::PriorityQueue(RefCell::new(pq.borrow().clone())),
            NauxObj::Function(f) => NauxObj::Function(f.clone()),
        }
    }
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::SmallInt(n) => *n != 0,
            Value::Float(n) => *n != 0.0,
            Value::RcObj(o) => match o.as_ref() {
                NauxObj::Text(s) => !s.is_empty(),
                NauxObj::List(v) => !v.borrow().is_empty(),
                NauxObj::Map(m) => !m.borrow().is_empty(),
                NauxObj::Graph(_) => true,
                NauxObj::Set(s) => !s.borrow().is_empty(),
                NauxObj::PriorityQueue(pq) => !pq.borrow().is_empty(),
                NauxObj::Function(_) => true,
            },
            Value::Null => false,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::SmallInt(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::SmallInt(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<String> {
        match self {
            Value::RcObj(rc) => match rc.as_ref() {
                NauxObj::Text(s) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn make_text(s: impl Into<String>) -> Value {
        Value::RcObj(Rc::new(NauxObj::Text(s.into())))
    }

    pub fn make_list(items: Vec<Value>) -> Value {
        Value::RcObj(Rc::new(NauxObj::List(RefCell::new(items))))
    }

    pub fn make_map(entries: HashMap<String, Value>) -> Value {
        Value::RcObj(Rc::new(NauxObj::Map(RefCell::new(entries))))
    }

    pub fn make_graph(g: Graph) -> Value {
        Value::RcObj(Rc::new(NauxObj::Graph(RefCell::new(g))))
    }

    pub fn make_set(s: BTreeSet<Value>) -> Value {
        Value::RcObj(Rc::new(NauxObj::Set(RefCell::new(s))))
    }

    pub fn make_pq(v: Vec<Value>) -> Value {
        Value::RcObj(Rc::new(NauxObj::PriorityQueue(RefCell::new(v))))
    }

    pub fn make_function(f: Function) -> Value {
        Value::RcObj(Rc::new(NauxObj::Function(f)))
    }

    pub fn add(a: &Value, b: &Value) -> Value {
        match (a, b) {
            (Value::SmallInt(x), Value::SmallInt(y)) => Value::SmallInt(x + y),
            (Value::SmallInt(x), Value::Float(y)) => Value::Float(*x as f64 + y),
            (Value::Float(x), Value::SmallInt(y)) => Value::Float(x + *y as f64),
            (Value::Float(x), Value::Float(y)) => Value::Float(x + y),
            (Value::RcObj(x), Value::RcObj(y)) => match (x.as_ref(), y.as_ref()) {
                (NauxObj::Text(a), NauxObj::Text(b)) => Value::make_text(format!("{}{}", a, b)),
                _ => Value::Null,
            },
            _ => Value::Null,
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::SmallInt(a), Value::SmallInt(b)) => a == b,
            (Value::SmallInt(a), Value::Float(b)) | (Value::Float(b), Value::SmallInt(a)) => {
                (*a as f64 - *b).abs() < f64::EPSILON
            }
            (Value::Float(a), Value::Float(b)) => (*a - *b).abs() < f64::EPSILON,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::RcObj(a), Value::RcObj(b)) => {
                if Rc::ptr_eq(a, b) {
                    return true;
                }
                match (a.as_ref(), b.as_ref()) {
                    (NauxObj::Text(sa), NauxObj::Text(sb)) => sa == sb,
                    (NauxObj::List(la), NauxObj::List(lb)) => la.borrow().clone().eq(&lb.borrow().clone()),
                    (NauxObj::Map(ma), NauxObj::Map(mb)) => ma.borrow().clone().eq(&mb.borrow().clone()),
                    (NauxObj::Set(sa), NauxObj::Set(sb)) => sa.borrow().clone().eq(&sb.borrow().clone()),
                    (NauxObj::PriorityQueue(aq), NauxObj::PriorityQueue(bq)) => aq.borrow().clone().eq(&bq.borrow().clone()),
                    (NauxObj::Graph(_), NauxObj::Graph(_)) => false, // graphs compared by identity
                    (NauxObj::Function(_), NauxObj::Function(_)) => false,
                    _ => false,
                }
            }
            (Value::Null, Value::Null) => true,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.as_f64(), other.as_f64()) {
            (Some(a), Some(b)) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
            _ => format!("{:?}", self).cmp(&format!("{:?}", other)),
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueTag {
    SmallInt,
    Float,
    Bool,
    RcObj,
    Null,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union RawValuePayload {
    pub small_int: i64,
    pub float_val: f64,
    pub bool_val: u8,
    pub ptr: *const NauxObj,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawValue {
    pub tag: ValueTag,
    pub payload: RawValuePayload,
}

impl RawValue {
    pub fn null() -> Self {
        RawValue {
            tag: ValueTag::Null,
            payload: RawValuePayload { small_int: 0 },
        }
    }
}

impl Value {
    pub fn to_raw(&self) -> RawValue {
        match self {
            Value::SmallInt(v) => RawValue {
                tag: ValueTag::SmallInt,
                payload: RawValuePayload { small_int: *v },
            },
            Value::Float(f) => RawValue {
                tag: ValueTag::Float,
                payload: RawValuePayload { float_val: *f },
            },
            Value::Bool(b) => RawValue {
                tag: ValueTag::Bool,
                payload: RawValuePayload { bool_val: *b as u8 },
            },
            Value::RcObj(rc) => {
                let ptr = Rc::as_ptr(rc);
                RawValue {
                    tag: ValueTag::RcObj,
                    payload: RawValuePayload { ptr },
                }
            }
            Value::Null => RawValue::null(),
        }
    }

    pub fn from_raw(raw: &RawValue) -> Value {
        unsafe {
            match raw.tag {
                ValueTag::SmallInt => Value::SmallInt(raw.payload.small_int),
                ValueTag::Float => Value::Float(raw.payload.float_val),
                ValueTag::Bool => Value::Bool(raw.payload.bool_val != 0),
                ValueTag::RcObj => {
                    let rc = Rc::from_raw(raw.payload.ptr);
                    let cloned = rc.clone();
                    std::mem::forget(rc);
                    Value::RcObj(cloned)
                }
                ValueTag::Null => Value::Null,
            }
        }
    }
}
