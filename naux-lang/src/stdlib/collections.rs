use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, VecDeque};

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::Value;

pub fn register_collections(env: &mut Env) {
    env.set_builtin("set_new", set_new);
    env.set_builtin("set_add", set_add);
    env.set_builtin("set_contains", set_contains);

    env.set_builtin("queue_new", queue_new);
    env.set_builtin("queue_push", queue_push);
    env.set_builtin("queue_pop", queue_pop);

    env.set_builtin("pq_new", pq_new);
    env.set_builtin("pq_push", pq_push);
    env.set_builtin("pq_pop_min", pq_pop_min);

    env.set_builtin("stack_new", stack_new);
    env.set_builtin("stack_push", stack_push);
    env.set_builtin("stack_pop", stack_pop);

    env.set_builtin("dsu_new", dsu_new);
    env.set_builtin("dsu_find", dsu_find);
    env.set_builtin("dsu_union", dsu_union);

    env.set_builtin("segtree_new", segtree_new);
    env.set_builtin("segtree_query", segtree_query);
    env.set_builtin("segtree_update", segtree_update);
}

fn set_new(_args: Vec<Value>) -> Result<Value, RuntimeError> {
    Ok(Value::Set(BTreeSet::new()))
}

fn set_add(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("set_add(set, value)", None));
    }
    let mut s = match args[0].clone() {
        Value::Set(s) => s,
        _ => return Err(RuntimeError::new("set_add: first arg must be set", None)),
    };
    s.insert(args[1].clone());
    Ok(Value::Set(s))
}

fn set_contains(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("set_contains(set, value)", None));
    }
    let s = match &args[0] {
        Value::Set(s) => s,
        _ => return Err(RuntimeError::new("set_contains: first arg must be set", None)),
    };
    Ok(Value::Bool(s.contains(&args[1])))
}

fn queue_new(_args: Vec<Value>) -> Result<Value, RuntimeError> {
    Ok(Value::List(Vec::new())) // using List as queue storage (VecDeque not stored in Value)
}

fn queue_push(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("queue_push(queue, value)", None));
    }
    let mut q = match args[0].clone() {
        Value::List(v) => VecDeque::from(v),
        _ => return Err(RuntimeError::new("queue_push: first arg must be list/queue", None)),
    };
    q.push_back(args[1].clone());
    Ok(Value::List(q.into_iter().collect()))
}

fn queue_pop(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("queue_pop(queue)", None));
    }
    let mut q = match args[0].clone() {
        Value::List(v) => VecDeque::from(v),
        _ => return Err(RuntimeError::new("queue_pop: first arg must be list/queue", None)),
    };
    let val = q.pop_front().unwrap_or(Value::Null);
    Ok(Value::List(q.into_iter().collect::<Vec<_>>()))
        .map(|updated_queue| Value::List(vec![val, Value::List(match updated_queue {
            Value::List(v) => v,
            _ => vec![],
        })]))
}

fn pq_new(_args: Vec<Value>) -> Result<Value, RuntimeError> {
    Ok(Value::PriorityQueue(Vec::new()))
}

fn pq_push(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("pq_push(pq, value)", None));
    }
    let mut heap = to_min_heap(args[0].clone())?;
    heap.push(Reverse(args[1].clone()));
    Ok(Value::PriorityQueue(from_min_heap(heap)))
}

fn pq_pop_min(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("pq_pop_min(pq)", None));
    }
    let mut heap = to_min_heap(args[0].clone())?;
    let val = heap.pop().map(|r| r.0).unwrap_or(Value::Null);
    Ok(Value::PriorityQueue(from_min_heap(heap)))
        .map(|updated| Value::List(vec![val, updated]))
}

fn stack_new(_args: Vec<Value>) -> Result<Value, RuntimeError> {
    Ok(Value::List(Vec::new()))
}

fn stack_push(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("stack_push(stack, value)", None));
    }
    let mut v = match args[0].clone() {
        Value::List(v) => v,
        _ => return Err(RuntimeError::new("stack_push: first arg must be list/stack", None)),
    };
    v.push(args[1].clone());
    Ok(Value::List(v))
}

fn stack_pop(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("stack_pop(stack)", None));
    }
    let mut v = match args[0].clone() {
        Value::List(v) => v,
        _ => return Err(RuntimeError::new("stack_pop: first arg must be list/stack", None)),
    };
    let top = v.pop().unwrap_or(Value::Null);
    Ok(Value::List(vec![top, Value::List(v)]))
}

fn dsu_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("dsu_new(n)", None));
    }
    let n = match args[0] {
        Value::Number(n) => n as usize,
        _ => return Err(RuntimeError::new("dsu_new: n must be number", None)),
    };
    let mut parent = Vec::with_capacity(n);
    let mut rank = Vec::with_capacity(n);
    for i in 0..n {
        parent.push(Value::Number(i as f64));
        rank.push(Value::Number(0.0));
    }
    let mut map = std::collections::HashMap::new();
    map.insert("p".into(), Value::List(parent));
    map.insert("r".into(), Value::List(rank));
    Ok(Value::Map(map))
}

fn dsu_find(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("dsu_find(dsu, x)", None));
    }
    let mut dsu = match args[0].clone() {
        Value::Map(m) => m,
        _ => return Err(RuntimeError::new("dsu_find: first arg must be map", None)),
    };
    let x = match args[1] {
        Value::Number(n) => n as usize,
        _ => return Err(RuntimeError::new("dsu_find: x must be number", None)),
    };
    let mut parent = match dsu.get("p") {
        Some(Value::List(v)) => v.clone(),
        _ => return Err(RuntimeError::new("dsu_find: missing parent list", None)),
    };
    let _rank = match dsu.get("r") {
        Some(Value::List(v)) => v.clone(),
        _ => return Err(RuntimeError::new("dsu_find: missing rank list", None)),
    };
    let root = find_internal(x, &mut parent);
    dsu.insert("p".into(), Value::List(parent));
    Ok(Value::List(vec![Value::Number(root as f64), Value::Map(dsu)]))
}

fn dsu_union(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("dsu_union(dsu, a, b)", None));
    }
    let mut dsu = match args[0].clone() {
        Value::Map(m) => m,
        _ => return Err(RuntimeError::new("dsu_union: first arg must be map", None)),
    };
    let a = match args[1] {
        Value::Number(n) => n as usize,
        _ => return Err(RuntimeError::new("dsu_union: a must be number", None)),
    };
    let b = match args[2] {
        Value::Number(n) => n as usize,
        _ => return Err(RuntimeError::new("dsu_union: b must be number", None)),
    };
    let mut parent = match dsu.get("p") {
        Some(Value::List(v)) => v.clone(),
        _ => return Err(RuntimeError::new("dsu_union: missing parent list", None)),
    };
    let mut rank = match dsu.get("r") {
        Some(Value::List(v)) => v.clone(),
        _ => return Err(RuntimeError::new("dsu_union: missing rank list", None)),
    };
    union_internal(a, b, &mut parent, &mut rank);
    dsu.insert("p".into(), Value::List(parent));
    dsu.insert("r".into(), Value::List(rank));
    Ok(Value::Map(dsu))
}

fn find_internal(x: usize, parent: &mut Vec<Value>) -> usize {
    let px = parent.get(x).and_then(|v| match v {
        Value::Number(n) => Some(*n as usize),
        _ => None,
    }).unwrap_or(x);
    if px != x {
        let root = find_internal(px, parent);
        if let Some(p) = parent.get_mut(x) {
            *p = Value::Number(root as f64);
        }
        root
    } else {
        x
    }
}

fn union_internal(a: usize, b: usize, parent: &mut Vec<Value>, rank: &mut Vec<Value>) {
    let ra = find_internal(a, parent);
    let rb = find_internal(b, parent);
    if ra == rb {
        return;
    }
    let ra_rank = rank.get(ra).and_then(|v| match v { Value::Number(n) => Some(*n as i64), _ => None }).unwrap_or(0);
    let rb_rank = rank.get(rb).and_then(|v| match v { Value::Number(n) => Some(*n as i64), _ => None }).unwrap_or(0);
    if ra_rank < rb_rank {
        if let Some(p) = parent.get_mut(ra) {
            *p = Value::Number(rb as f64);
        }
    } else if ra_rank > rb_rank {
        if let Some(p) = parent.get_mut(rb) {
            *p = Value::Number(ra as f64);
        }
    } else {
        if let Some(p) = parent.get_mut(rb) {
            *p = Value::Number(ra as f64);
        }
        if let Some(r) = rank.get_mut(ra) {
            if let Value::Number(n) = r {
                *n += 1.0;
            }
        }
    }
}

fn segtree_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("segtree_new(list)", None));
    }
    let arr = match &args[0] {
        Value::List(v) => v.clone(),
        _ => return Err(RuntimeError::new("segtree_new: expected list", None)),
    };
    let n = arr.len();
    let mut size = 1;
    while size < n {
        size <<= 1;
    }
    let mut tree = vec![Value::Number(0.0); 2 * size];
    for i in 0..n {
        tree[size + i] = arr[i].clone();
    }
    for i in (1..size).rev() {
        tree[i] = add_values(&tree[i << 1], &tree[(i << 1) | 1]);
    }
    let mut map = std::collections::HashMap::new();
    map.insert("tree".into(), Value::List(tree));
    map.insert("size".into(), Value::Number(size as f64));
    Ok(Value::Map(map))
}

fn segtree_query(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_query(st, l, r)", None));
    }
    let st = match &args[0] {
        Value::Map(m) => m,
        _ => return Err(RuntimeError::new("segtree_query: st must be map", None)),
    };
    let tree = match st.get("tree") {
        Some(Value::List(v)) => v.clone(),
        _ => return Err(RuntimeError::new("segtree_query: missing tree", None)),
    };
    let size = match st.get("size") {
        Some(Value::Number(n)) => *n as usize,
        _ => return Err(RuntimeError::new("segtree_query: missing size", None)),
    };
    let mut l = match args[1] { Value::Number(n) => n as i64, _ => return Err(RuntimeError::new("l must be num", None)) } + size as i64;
    let mut r = match args[2] { Value::Number(n) => n as i64, _ => return Err(RuntimeError::new("r must be num", None)) } + size as i64;
    let mut res_left = Value::Number(0.0);
    let mut res_right = Value::Number(0.0);
    while l < r {
        if l & 1 == 1 {
            res_left = add_values(&res_left, &tree[l as usize]);
            l += 1;
        }
        if r & 1 == 1 {
            r -= 1;
            res_right = add_values(&tree[r as usize], &res_right);
        }
        l >>= 1;
        r >>= 1;
    }
    Ok(Value::add(&res_left, &res_right))
}

fn segtree_update(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_update(st, idx, val)", None));
    }
    let mut st = match args[0].clone() {
        Value::Map(m) => m,
        _ => return Err(RuntimeError::new("segtree_update: st must be map", None)),
    };
    let mut tree = match st.get("tree") {
        Some(Value::List(v)) => v.clone(),
        _ => return Err(RuntimeError::new("segtree_update: missing tree", None)),
    };
    let size = match st.get("size") {
        Some(Value::Number(n)) => *n as usize,
        _ => return Err(RuntimeError::new("segtree_update: missing size", None)),
    };
    let mut pos = match args[1] {
        Value::Number(n) => n as usize,
        _ => return Err(RuntimeError::new("idx must be number", None)),
    } + size;
    if let Some(p) = tree.get_mut(pos) {
        *p = args[2].clone();
    }
    pos >>= 1;
    while pos > 0 {
        let left = tree[pos << 1].clone();
        let right = tree[(pos << 1) | 1].clone();
        tree[pos] = add_values(&left, &right);
        pos >>= 1;
    }
    st.insert("tree".into(), Value::List(tree));
    Ok(Value::Map(st))
}

fn add_values(a: &Value, b: &Value) -> Value {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => Value::Number(x + y),
        _ => Value::Number(0.0),
    }
}

fn to_min_heap(v: Value) -> Result<BinaryHeap<Reverse<Value>>, RuntimeError> {
    match v {
        Value::PriorityQueue(data) => {
            let mut heap = BinaryHeap::new();
            for item in data {
                heap.push(Reverse(item));
            }
            Ok(heap)
        }
        _ => Err(RuntimeError::new("priority queue expected", None)),
    }
}

fn from_min_heap(mut heap: BinaryHeap<Reverse<Value>>) -> Vec<Value> {
    let mut out = Vec::new();
    while let Some(Reverse(v)) = heap.pop() {
        out.push(v);
    }
    out.reverse();
    out
}
