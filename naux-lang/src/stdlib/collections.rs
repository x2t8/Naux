#![allow(clippy::manual_memcpy, clippy::ptr_arg, clippy::collapsible_match)]

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, VecDeque};

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
    env.set_builtin("list_range", list_range);

    env.set_builtin("pq_new", pq_new);
    env.set_builtin("pq_push", pq_push);
    env.set_builtin("pq_pop_min", pq_pop_min);

    env.set_builtin("stack_new", stack_new);
    env.set_builtin("stack_push", stack_push);
    env.set_builtin("stack_pop", stack_pop);

    // dsu_* and segtree_* are owned by stdlib::algo (register_algo), which also
    // provides the lazy/dynamic segtree variants.
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
    Err(RuntimeError::new(
        "set_contains: first arg must be set",
        None,
    ))
}

fn queue_new(_args: Vec<Value>) -> Result<Value, RuntimeError> {
    Ok(Value::make_list(Vec::new())) // using List as queue storage (VecDeque not stored in Value)
}

fn queue_push(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("queue_push(queue, value)", None));
    }
    let mut q = VecDeque::from(expect_list(
        &args[0],
        "queue_push: first arg must be list/queue",
    )?);
    q.push_back(args[1].clone());
    Ok(Value::make_list(q.into_iter().collect()))
}

fn list_range(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("list_range(n)", None));
    }
    let n = match &args[0] {
        Value::SmallInt(v) => *v,
        Value::Float(v) => *v as i64,
        _ => return Err(RuntimeError::new("list_range: expected number", None)),
    };
    if n < 0 {
        return Err(RuntimeError::new("list_range: n must be >= 0", None));
    }
    let n = n as usize;
    let mut out: Vec<Value> = Vec::with_capacity(n);
    for i in 0..n {
        out.push(Value::Float(i as f64));
    }
    Ok(Value::make_list(out))
}

fn queue_pop(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("queue_pop(queue)", None));
    }
    let mut q = VecDeque::from(expect_list(
        &args[0],
        "queue_pop: first arg must be list/queue",
    )?);
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

fn expect_list(val: &Value, msg: &str) -> Result<Vec<Value>, RuntimeError> {
    if let Value::RcObj(rc) = val {
        if let NauxObj::List(list) = rc.as_ref() {
            return Ok(list.borrow().clone());
        }
    }
    Err(RuntimeError::new(msg, None))
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
