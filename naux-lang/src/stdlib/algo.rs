#![allow(dead_code)]

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::Value;

pub fn register_algo(env: &mut Env) {
    env.set_builtin("lis_length", lis_length);
    env.set_builtin("knapsack_01", knapsack_01);
    env.set_builtin("lower_bound", lower_bound);
    env.set_builtin("upper_bound", upper_bound);
}

fn to_num_list(v: &Value) -> Result<Vec<f64>, RuntimeError> {
    match v {
        Value::List(items) => {
            let mut out = Vec::new();
            for it in items {
                if let Value::Number(n) = it {
                    out.push(*n);
                } else {
                    return Err(RuntimeError::new("expected list of numbers", None));
                }
            }
            Ok(out)
        }
        _ => Err(RuntimeError::new("expected list", None)),
    }
}

fn lis_length(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("lis_length(list)", None));
    }
    let arr = to_num_list(&args[0])?;
    let mut tails: Vec<f64> = Vec::new();
    for &x in &arr {
        match tails.binary_search_by(|v| v.partial_cmp(&x).unwrap()) {
            Ok(pos) => tails[pos] = x,
            Err(pos) => {
                if pos == tails.len() {
                    tails.push(x);
                } else {
                    tails[pos] = x;
                }
            }
        }
    }
    Ok(Value::Number(tails.len() as f64))
}

fn knapsack_01(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("knapsack_01(weights, values, cap)", None));
    }
    let w = to_num_list(&args[0])?;
    let v = to_num_list(&args[1])?;
    let cap = match args[2] {
        Value::Number(c) => c as i64,
        _ => return Err(RuntimeError::new("cap must be number", None)),
    };
    if w.len() != v.len() {
        return Err(RuntimeError::new("weights and values len mismatch", None));
    }
    let n = w.len();
    let mut dp = vec![0.0; (cap as usize) + 1];
    for i in 0..n {
        let weight = w[i] as i64;
        let value = v[i];
        for c in (weight..=cap).rev() {
            let idx = c as usize;
            let cand = value + dp[(c - weight) as usize];
            if cand > dp[idx] {
                dp[idx] = cand;
            }
        }
    }
    Ok(Value::Number(dp[cap as usize]))
}

fn lower_bound(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("lower_bound(list, x)", None));
    }
    let arr = to_num_list(&args[0])?;
    let x = match &args[1] {
        Value::Number(n) => *n,
        _ => return Err(RuntimeError::new("x must be number", None)),
    };
    // first index with value >= x
    let mut l = 0;
    let mut r = arr.len();
    while l < r {
        let m = (l + r) / 2;
        if arr[m] < x {
            l = m + 1;
        } else {
            r = m;
        }
    }
    let pos = l;
    Ok(Value::Number(pos as f64))
}

fn upper_bound(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("upper_bound(list, x)", None));
    }
    let arr = to_num_list(&args[0])?;
    let x = match &args[1] {
        Value::Number(n) => *n,
        _ => return Err(RuntimeError::new("x must be number", None)),
    };
    // binary search for first element > x
    let mut l = 0;
    let mut r = arr.len();
    while l < r {
        let m = (l + r) / 2;
        if arr[m] > x {
            r = m;
        } else {
            l = m + 1;
        }
    }
    let pos = l;
    Ok(Value::Number(pos as f64))
}
