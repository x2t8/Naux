use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, VecDeque};

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::{NauxObj, Value};

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
    Ok(Value::make_set(BTreeSet::new()))
}

fn set_add(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("set_add(set, value)", None));
    }
    if let Value::RcObj(rc) = &args[0] {
        if let NauxObj::Set(s) = rc.as_ref() {
            s.borrow_mut().insert(args[1].clone());
            return Ok(Value::RcObj(rc.clone()));
        }
    }
    Err(RuntimeError::new("set_add: first arg must be set", None))
}

fn set_contains(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("set_contains(set, value)", None));
    }
    if let Value::RcObj(rc) = &args[0] {
        if let NauxObj::Set(s) = rc.as_ref() {
            return Ok(Value::Bool(s.borrow().contains(&args[1])));
        }
    }
    Err(RuntimeError::new("set_contains: first arg must be set", None))
}

fn queue_new(_args: Vec<Value>) -> Result<Value, RuntimeError> {
    Ok(Value::make_list(Vec::new())) // using List as queue storage (VecDeque not stored in Value)
}

fn queue_push(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("queue_push(queue, value)", None));
    }
    let mut q = VecDeque::from(expect_list(&args[0], "queue_push: first arg must be list/queue")?);
    q.push_back(args[1].clone());
    Ok(Value::make_list(q.into_iter().collect()))
}

fn queue_pop(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("queue_pop(queue)", None));
    }
    let mut q = VecDeque::from(expect_list(&args[0], "queue_pop: first arg must be list/queue")?);
    let val = q.pop_front().unwrap_or(Value::Null);
    let updated = Value::make_list(q.into_iter().collect::<Vec<_>>());
    Ok(Value::make_list(vec![val, updated]))
}

fn pq_new(_args: Vec<Value>) -> Result<Value, RuntimeError> {
    Ok(Value::make_pq(Vec::new()))
}

fn pq_push(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("pq_push(pq, value)", None));
    }
    let mut heap = to_min_heap(args[0].clone())?;
    heap.push(Reverse(args[1].clone()));
    Ok(Value::make_pq(from_min_heap(heap)))
}

fn pq_pop_min(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("pq_pop_min(pq)", None));
    }
    let mut heap = to_min_heap(args[0].clone())?;
    let val = heap.pop().map(|r| r.0).unwrap_or(Value::Null);
    let updated = Value::make_pq(from_min_heap(heap));
    Ok(Value::make_list(vec![val, updated]))
}

fn stack_new(_args: Vec<Value>) -> Result<Value, RuntimeError> {
    Ok(Value::make_list(Vec::new()))
}

fn stack_push(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("stack_push(stack, value)", None));
    }
    let mut v = expect_list(&args[0], "stack_push: first arg must be list/stack")?;
    v.push(args[1].clone());
    Ok(Value::make_list(v))
}

fn stack_pop(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("stack_pop(stack)", None));
    }
    let mut v = expect_list(&args[0], "stack_pop: first arg must be list/stack")?;
    let top = v.pop().unwrap_or(Value::Null);
    Ok(Value::make_list(vec![top, Value::make_list(v)]))
}

fn dsu_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("dsu_new(n)", None));
    }
    let n = args[0].as_i64().ok_or_else(|| RuntimeError::new("dsu_new: n must be number", None))? as usize;
    let mut parent = Vec::with_capacity(n);
    let mut rank = Vec::with_capacity(n);
    for i in 0..n {
        parent.push(Value::SmallInt(i as i64));
        rank.push(Value::SmallInt(0));
    }
    let mut map = std::collections::HashMap::new();
    map.insert("p".into(), Value::make_list(parent));
    map.insert("r".into(), Value::make_list(rank));
    Ok(Value::make_map(map))
}

fn dsu_find(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("dsu_find(dsu, x)", None));
    }
    let mut dsu = expect_map(&args[0], "dsu_find: first arg must be map")?;
    let x = args[1].as_i64().ok_or_else(|| RuntimeError::new("dsu_find: x must be number", None))? as usize;
    let mut parent = expect_list(dsu.get("p").unwrap_or(&Value::Null), "dsu_find: missing parent list")?;
    let _rank = expect_list(dsu.get("r").unwrap_or(&Value::Null), "dsu_find: missing rank list")?;
    let root = find_internal(x, &mut parent);
    dsu.insert("p".into(), Value::make_list(parent));
    Ok(Value::make_list(vec![Value::SmallInt(root as i64), Value::make_map(dsu)]))
}

fn dsu_union(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("dsu_union(dsu, a, b)", None));
    }
    let mut dsu = expect_map(&args[0], "dsu_union: first arg must be map")?;
    let a = args[1].as_i64().ok_or_else(|| RuntimeError::new("dsu_union: a must be number", None))? as usize;
    let b = args[2].as_i64().ok_or_else(|| RuntimeError::new("dsu_union: b must be number", None))? as usize;
    let mut parent = expect_list(dsu.get("p").unwrap_or(&Value::Null), "dsu_union: missing parent list")?;
    let mut rank = expect_list(dsu.get("r").unwrap_or(&Value::Null), "dsu_union: missing rank list")?;
    union_internal(a, b, &mut parent, &mut rank);
    dsu.insert("p".into(), Value::make_list(parent));
    dsu.insert("r".into(), Value::make_list(rank));
    Ok(Value::make_map(dsu))
}

fn find_internal(x: usize, parent: &mut Vec<Value>) -> usize {
    let px = parent.get(x).and_then(|v| match v {
        Value::SmallInt(n) => Some(*n as usize),
        Value::Float(n) => Some(*n as usize),
        _ => None,
    }).unwrap_or(x);
    if px != x {
        let root = find_internal(px, parent);
        if let Some(p) = parent.get_mut(x) {
            *p = Value::SmallInt(root as i64);
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
    let ra_rank = rank.get(ra).and_then(|v| v.as_i64()).unwrap_or(0);
    let rb_rank = rank.get(rb).and_then(|v| v.as_i64()).unwrap_or(0);
    if ra_rank < rb_rank {
        if let Some(p) = parent.get_mut(ra) {
            *p = Value::SmallInt(rb as i64);
        }
    } else if ra_rank > rb_rank {
        if let Some(p) = parent.get_mut(rb) {
            *p = Value::SmallInt(ra as i64);
        }
    } else {
        if let Some(p) = parent.get_mut(rb) {
            *p = Value::SmallInt(ra as i64);
        }
        if let Some(r) = rank.get_mut(ra) {
            if let Value::SmallInt(n) = r {
                *n += 1;
            }
        }
    }
}

fn segtree_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("segtree_new(list)", None));
    }
    let arr = expect_list(&args[0], "segtree_new: expected list")?;
    let n = arr.len();
    let mut size = 1;
    while size < n {
        size <<= 1;
    }
    let mut tree = vec![Value::Float(0.0); 2 * size];
    for i in 0..n {
        tree[size + i] = arr[i].clone();
    }
    for i in (1..size).rev() {
        tree[i] = add_values(&tree[i << 1], &tree[(i << 1) | 1]);
    }
    let mut map = std::collections::HashMap::new();
    map.insert("tree".into(), Value::make_list(tree));
    map.insert("size".into(), Value::SmallInt(size as i64));
    Ok(Value::make_map(map))
}

fn segtree_query(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_query(st, l, r)", None));
    }
    let st = expect_map(&args[0], "segtree_query: st must be map")?;
    let tree = expect_list(st.get("tree").unwrap_or(&Value::Null), "segtree_query: missing tree")?;
    let size = st
        .get("size")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| RuntimeError::new("segtree_query: missing size", None))? as usize;
    let mut l = args[1].as_i64().ok_or_else(|| RuntimeError::new("l must be num", None))? + size as i64;
    let mut r = args[2].as_i64().ok_or_else(|| RuntimeError::new("r must be num", None))? + size as i64;
    let mut res_left = Value::Float(0.0);
    let mut res_right = Value::Float(0.0);
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
    let mut st = expect_map(&args[0], "segtree_update: st must be map")?;
    let mut tree = expect_list(st.get("tree").unwrap_or(&Value::Null), "segtree_update: missing tree")?;
    let size = st
        .get("size")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| RuntimeError::new("segtree_update: missing size", None))? as usize;
    let mut pos = args[1].as_i64().ok_or_else(|| RuntimeError::new("idx must be number", None))? as usize + size;
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
    st.insert("tree".into(), Value::make_list(tree));
    Ok(Value::make_map(st))
}

fn expect_list(val: &Value, msg: &str) -> Result<Vec<Value>, RuntimeError> {
    if let Value::RcObj(rc) = val {
        if let NauxObj::List(list) = rc.as_ref() {
            return Ok(list.borrow().clone());
        }
    }
    Err(RuntimeError::new(msg, None))
}

fn expect_map(val: &Value, msg: &str) -> Result<HashMap<String, Value>, RuntimeError> {
    if let Value::RcObj(rc) = val {
        if let NauxObj::Map(map) = rc.as_ref() {
            return Ok(map.borrow().clone());
        }
    }
    Err(RuntimeError::new(msg, None))
}

fn add_values(a: &Value, b: &Value) -> Value {
    match (a, b) {
        (Value::SmallInt(x), Value::SmallInt(y)) => Value::SmallInt(x + y),
        (Value::SmallInt(x), Value::Float(y)) => Value::Float(*x as f64 + y),
        (Value::Float(x), Value::SmallInt(y)) => Value::Float(x + *y as f64),
        (Value::Float(x), Value::Float(y)) => Value::Float(x + y),
        _ => Value::Float(0.0),
    }
}

fn to_min_heap(v: Value) -> Result<BinaryHeap<Reverse<Value>>, RuntimeError> {
    if let Value::RcObj(rc) = v {
        if let NauxObj::PriorityQueue(data) = rc.as_ref() {
            let mut heap = BinaryHeap::new();
            for item in data.borrow().iter() {
                heap.push(Reverse(item.clone()));
            }
            return Ok(heap);
        }
    }
    Err(RuntimeError::new("priority queue expected", None))
}

fn from_min_heap(mut heap: BinaryHeap<Reverse<Value>>) -> Vec<Value> {
    let mut out = Vec::new();
    while let Some(Reverse(v)) = heap.pop() {
        out.push(v);
    }
    out.reverse();
    out
}
