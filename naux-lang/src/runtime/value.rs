use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use crate::ast::Stmt;
use crate::runtime::env::Env;

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
    Bytes(RefCell<Vec<u8>>),
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

#[derive(Clone)]
pub struct Function {
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
    pub env: Rc<RefCell<Env>>,
}

impl std::fmt::Debug for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Function {{ params: {:?}, body: Opaque, env: Opaque }}",
            self.params
        )
    }
}

impl Clone for NauxObj {
    fn clone(&self) -> Self {
        match self {
            NauxObj::Text(s) => NauxObj::Text(s.clone()),
            NauxObj::Bytes(v) => NauxObj::Bytes(RefCell::new(v.borrow().clone())),
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
                NauxObj::Bytes(v) => !v.borrow().is_empty(),
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

    pub fn make_bytes(bytes: Vec<u8>) -> Value {
        Value::RcObj(Rc::new(NauxObj::Bytes(RefCell::new(bytes))))
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

    #[allow(clippy::mutable_key_type)]
    pub fn make_set(s: BTreeSet<Value>) -> Value {
        Value::RcObj(Rc::new(NauxObj::Set(RefCell::new(s))))
    }

    pub fn make_pq(v: Vec<Value>) -> Value {
        Value::RcObj(Rc::new(NauxObj::PriorityQueue(RefCell::new(v))))
    }

    pub fn make_function(params: Vec<String>, body: Vec<Stmt>, env: Rc<RefCell<Env>>) -> Value {
        Value::RcObj(Rc::new(NauxObj::Function(Function { params, body, env })))
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
            (Value::RcObj(x), other) => match x.as_ref() {
                NauxObj::Text(a) => Value::make_text(format!("{}{}", a, other.to_display_text())),
                _ => Value::Null,
            },
            (other, Value::RcObj(y)) => match y.as_ref() {
                NauxObj::Text(b) => Value::make_text(format!("{}{}", other.to_display_text(), b)),
                _ => Value::Null,
            },
            _ => Value::Null,
        }
    }

    pub fn to_display_text(&self) -> String {
        match self {
            Value::SmallInt(n) => n.to_string(),
            Value::Float(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".into(),
            Value::RcObj(rc) => match rc.as_ref() {
                NauxObj::Text(s) => s.clone(),
                NauxObj::Bytes(v) => {
                    let body = v
                        .borrow()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("Bytes [{}]", body)
                }
                NauxObj::List(v) => {
                    let items = v
                        .borrow()
                        .iter()
                        .map(Value::to_display_text)
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("List [{}]", items)
                }
                NauxObj::Map(m) => {
                    let mut entries = m
                        .borrow()
                        .iter()
                        .map(|(key, value)| format!("{}:{}", key, value.to_display_text()))
                        .collect::<Vec<_>>();
                    entries.sort();
                    format!("Map {{{}}}", entries.join(", "))
                }
                NauxObj::Graph(g) => {
                    let graph = g.borrow();
                    let edges: usize = graph.adj.values().map(|v| v.len()).sum();
                    format!("Graph(nodes={}, edges={})", graph.adj.len(), edges)
                }
                NauxObj::Set(s) => {
                    let items = s
                        .borrow()
                        .iter()
                        .map(Value::to_display_text)
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("Set [{}]", items)
                }
                NauxObj::PriorityQueue(pq) => {
                    let items = pq
                        .borrow()
                        .iter()
                        .map(Value::to_display_text)
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("PriorityQueue [{}]", items)
                }
                NauxObj::Function(_) => "<fn>".into(),
            },
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_display_text())
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
                    (NauxObj::Bytes(ba), NauxObj::Bytes(bb)) => ba.borrow().eq(&*bb.borrow()),
                    (NauxObj::List(la), NauxObj::List(lb)) => la.borrow().eq(&*lb.borrow()),
                    (NauxObj::Map(ma), NauxObj::Map(mb)) => ma.borrow().eq(&*mb.borrow()),
                    (NauxObj::Set(sa), NauxObj::Set(sb)) => sa.borrow().eq(&*sb.borrow()),
                    (NauxObj::PriorityQueue(aq), NauxObj::PriorityQueue(bq)) => {
                        aq.borrow().eq(&*bq.borrow())
                    }
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
        if self == other {
            return Ordering::Equal;
        }

        match (self.as_f64(), other.as_f64()) {
            (Some(a), Some(b)) => return a.total_cmp(&b),
            _ => {}
        }

        let lhs_rank = value_type_rank(self);
        let rhs_rank = value_type_rank(other);
        lhs_rank
            .cmp(&rhs_rank)
            .then_with(|| cmp_same_rank_value(self, other))
    }
}

fn value_type_rank(value: &Value) -> u8 {
    match value {
        Value::SmallInt(_) | Value::Float(_) => 0,
        Value::Bool(_) => 1,
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Text(_) => 2,
            NauxObj::Bytes(_) => 3,
            NauxObj::List(_) => 4,
            NauxObj::Map(_) => 5,
            NauxObj::Graph(_) => 6,
            NauxObj::Set(_) => 7,
            NauxObj::PriorityQueue(_) => 8,
            NauxObj::Function(_) => 9,
        },
        Value::Null => 10,
    }
}

fn cmp_same_rank_value(lhs: &Value, rhs: &Value) -> Ordering {
    match (lhs, rhs) {
        (Value::SmallInt(a), Value::SmallInt(b)) => a.cmp(b),
        (Value::Float(a), Value::Float(b)) => a.total_cmp(b),
        (Value::SmallInt(a), Value::Float(b)) => (*a as f64).total_cmp(b),
        (Value::Float(a), Value::SmallInt(b)) => a.total_cmp(&(*b as f64)),
        (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
        (Value::RcObj(a), Value::RcObj(b)) => {
            if Rc::ptr_eq(a, b) {
                return Ordering::Equal;
            }
            cmp_same_rank_obj(a.as_ref(), b.as_ref())
                .then_with(|| Rc::as_ptr(a).cmp(&Rc::as_ptr(b)))
        }
        (Value::Null, Value::Null) => Ordering::Equal,
        _ => Ordering::Equal,
    }
}

fn cmp_same_rank_obj(lhs: &NauxObj, rhs: &NauxObj) -> Ordering {
    match (lhs, rhs) {
        (NauxObj::Text(a), NauxObj::Text(b)) => a.cmp(b),
        (NauxObj::Bytes(a), NauxObj::Bytes(b)) => a.borrow().cmp(&b.borrow()),
        (NauxObj::List(a), NauxObj::List(b)) => a.borrow().cmp(&b.borrow()),
        (NauxObj::Map(a), NauxObj::Map(b)) => {
            let mut lhs_entries: Vec<_> = a
                .borrow()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let mut rhs_entries: Vec<_> = b
                .borrow()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            lhs_entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            rhs_entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            lhs_entries.cmp(&rhs_entries)
        }
        (NauxObj::Set(a), NauxObj::Set(b)) => a.borrow().iter().cmp(b.borrow().iter()),
        (NauxObj::PriorityQueue(a), NauxObj::PriorityQueue(b)) => a.borrow().cmp(&b.borrow()),
        (NauxObj::Graph(a), NauxObj::Graph(b)) => {
            let a = a.borrow();
            let b = b.borrow();
            a.directed
                .cmp(&b.directed)
                .then_with(|| graph_sort_key(&a).cmp(&graph_sort_key(&b)))
        }
        (NauxObj::Function(a), NauxObj::Function(b)) => a.params.cmp(&b.params),
        _ => Ordering::Equal,
    }
}

fn graph_sort_key(graph: &Graph) -> Vec<(String, Vec<(String, u64)>)> {
    let mut entries: Vec<_> = graph
        .adj
        .iter()
        .map(|(node, edges)| {
            let mut edges: Vec<_> = edges
                .iter()
                .map(|(target, weight)| (target.clone(), weight.to_bits()))
                .collect();
            edges.sort();
            (node.clone(), edges)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
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
