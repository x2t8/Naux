#![allow(
    dead_code,
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::manual_memcpy,
    clippy::implicit_saturating_sub,
    clippy::needless_range_loop,
    clippy::ptr_arg
)]

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::{NauxObj, Value};
use std::collections::{HashMap, VecDeque};

pub fn register_algo(env: &mut Env) {
    env.set_builtin("lis_length", lis_length);
    env.set_builtin("knapsack_01", knapsack_01);
    env.set_builtin("window_sum_fixed", window_sum_fixed);
    env.set_builtin("window_max", window_max);
    env.set_builtin("window_min", window_min);
    env.set_builtin("lower_bound", lower_bound);
    env.set_builtin("upper_bound", upper_bound);
    env.set_builtin("kmp_search", kmp_search);
    env.set_builtin("z_function", z_function);
    env.set_builtin("suffix_array", suffix_array);
    env.set_builtin("rolling_hash_table", rolling_hash_table);
    env.set_builtin("rolling_hash_sub", rolling_hash_sub);
    env.set_builtin("rabin_karp", rabin_karp);
    env.set_builtin("manacher_lps", manacher_lps);
    env.set_builtin("fft_convolve", fft_convolve);
    env.set_builtin("ntt_convolve", ntt_convolve);
    env.set_builtin("pollard_rho", pollard_rho);
    env.set_builtin("sparse_table_new", sparse_table_new);
    env.set_builtin("sparse_table_query", sparse_table_query);
    env.set_builtin("lichao_new", lichao_new);
    env.set_builtin("lichao_add", lichao_add);
    env.set_builtin("lichao_query", lichao_query);
    env.set_builtin("dsu_new", dsu_new);
    env.set_builtin("dsu_union", dsu_union);
    env.set_builtin("dsu_find", dsu_find);
    env.set_builtin("segtree_new", segtree_new);
    env.set_builtin("segtree_query", segtree_query);
    env.set_builtin("segtree_update", segtree_update);
    env.set_builtin("segtree_lazy_new", segtree_lazy_new);
    env.set_builtin("segtree_lazy_add", segtree_lazy_add);
    env.set_builtin("segtree_lazy_query", segtree_lazy_query);
    env.set_builtin("segtree_dynamic_new", segtree_dynamic_new);
    env.set_builtin("segtree_dynamic_add", segtree_dynamic_add);
    env.set_builtin("segtree_dynamic_query", segtree_dynamic_query);
}

fn to_num_list(v: &Value) -> Result<Vec<f64>, RuntimeError> {
    if let Value::RcObj(rc) = v {
        if let NauxObj::List(items) = rc.as_ref() {
            let mut out = Vec::new();
            for it in items.borrow().iter() {
                if let Some(n) = it.as_f64() {
                    out.push(n);
                } else {
                    return Err(RuntimeError::new("expected list of numbers", None));
                }
            }
            return Ok(out);
        }
    }
    Err(RuntimeError::new("expected list", None))
}

fn to_i64_local(v: &Value) -> Result<i64, RuntimeError> {
    v.as_i64()
        .or_else(|| v.as_f64().map(|f| f as i64))
        .ok_or_else(|| RuntimeError::new("expected number", None))
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
    Ok(Value::SmallInt(tails.len() as i64))
}

fn knapsack_01(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("knapsack_01(weights, values, cap)", None));
    }
    let w = to_num_list(&args[0])?;
    let v = to_num_list(&args[1])?;
    let cap = args[2]
        .as_i64()
        .ok_or_else(|| RuntimeError::new("cap must be number", None))?;
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
    Ok(Value::Float(dp[cap as usize]))
}

fn window_sum_fixed(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("window_sum_fixed(list, k)", None));
    }
    let arr = to_num_list(&args[0])?;
    let k = to_i64_local(&args[1])?;
    if k <= 0 {
        return Err(RuntimeError::new("window_sum_fixed: k must be >= 1", None));
    }
    let k = k as usize;
    if k > arr.len() {
        return Ok(Value::make_list(Vec::new()));
    }
    let mut out = Vec::with_capacity(arr.len() - k + 1);
    let mut sum = 0.0;
    for &x in arr.iter().take(k) {
        sum += x;
    }
    out.push(Value::Float(sum));
    for i in k..arr.len() {
        sum += arr[i];
        sum -= arr[i - k];
        out.push(Value::Float(sum));
    }
    Ok(Value::make_list(out))
}

fn window_max(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("window_max(list, k)", None));
    }
    let arr = to_num_list(&args[0])?;
    let k = to_i64_local(&args[1])?;
    if k <= 0 {
        return Err(RuntimeError::new("window_max: k must be >= 1", None));
    }
    let k = k as usize;
    if k > arr.len() {
        return Ok(Value::make_list(Vec::new()));
    }

    let mut out = Vec::with_capacity(arr.len() - k + 1);
    let mut dq: VecDeque<usize> = VecDeque::new();
    for i in 0..arr.len() {
        while let Some(&idx) = dq.back() {
            if arr[idx] <= arr[i] {
                dq.pop_back();
            } else {
                break;
            }
        }
        dq.push_back(i);
        if let Some(&idx) = dq.front() {
            if idx + k <= i {
                dq.pop_front();
            }
        }
        if i + 1 >= k {
            if let Some(&idx) = dq.front() {
                out.push(Value::Float(arr[idx]));
            }
        }
    }
    Ok(Value::make_list(out))
}

fn window_min(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("window_min(list, k)", None));
    }
    let arr = to_num_list(&args[0])?;
    let k = to_i64_local(&args[1])?;
    if k <= 0 {
        return Err(RuntimeError::new("window_min: k must be >= 1", None));
    }
    let k = k as usize;
    if k > arr.len() {
        return Ok(Value::make_list(Vec::new()));
    }

    let mut out = Vec::with_capacity(arr.len() - k + 1);
    let mut dq: VecDeque<usize> = VecDeque::new();
    for i in 0..arr.len() {
        while let Some(&idx) = dq.back() {
            if arr[idx] >= arr[i] {
                dq.pop_back();
            } else {
                break;
            }
        }
        dq.push_back(i);
        if let Some(&idx) = dq.front() {
            if idx + k <= i {
                dq.pop_front();
            }
        }
        if i + 1 >= k {
            if let Some(&idx) = dq.front() {
                out.push(Value::Float(arr[idx]));
            }
        }
    }
    Ok(Value::make_list(out))
}

fn lower_bound(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("lower_bound(list, x)", None));
    }
    let arr = to_num_list(&args[0])?;
    let x = args[1]
        .as_f64()
        .ok_or_else(|| RuntimeError::new("x must be number", None))?;
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
    Ok(Value::SmallInt(pos as i64))
}

fn upper_bound(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("upper_bound(list, x)", None));
    }
    let arr = to_num_list(&args[0])?;
    let x = args[1]
        .as_f64()
        .ok_or_else(|| RuntimeError::new("x must be number", None))?;
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
    Ok(Value::SmallInt(pos as i64))
}

// --- String Algorithms ---

fn expect_text(v: &Value, msg: &str) -> Result<String, RuntimeError> {
    if let Value::RcObj(rc) = v {
        if let NauxObj::Text(s) = rc.as_ref() {
            return Ok(s.clone());
        }
    }
    Err(RuntimeError::new(msg, None))
}

fn kmp_search(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("kmp_search(text, pattern)", None));
    }
    let text = expect_text(&args[0], "text must be string")?;
    let pat = expect_text(&args[1], "pattern must be string")?;
    if pat.is_empty() {
        return Ok(Value::make_list(vec![]));
    }
    let mut lps = vec![0usize; pat.len()];
    for i in 1..pat.len() {
        let mut len = lps[i - 1];
        while len > 0 && pat.as_bytes()[i] != pat.as_bytes()[len] {
            len = lps[len - 1];
        }
        if pat.as_bytes()[i] == pat.as_bytes()[len] {
            len += 1;
        }
        lps[i] = len;
    }
    let mut res = Vec::new();
    let mut j = 0usize;
    for (i, &b) in text.as_bytes().iter().enumerate() {
        while j > 0 && b != pat.as_bytes()[j] {
            j = lps[j - 1];
        }
        if b == pat.as_bytes()[j] {
            j += 1;
            if j == pat.len() {
                res.push(Value::SmallInt((i + 1 - j) as i64));
                j = lps[j - 1];
            }
        }
    }
    Ok(Value::make_list(res))
}

fn z_function(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("z_function(s)", None));
    }
    let s = expect_text(&args[0], "s must be string")?;
    let n = s.len();
    let mut z = vec![0usize; n];
    let bytes = s.as_bytes();
    let (mut l, mut r) = (0usize, 0usize);
    for i in 1..n {
        if i <= r {
            z[i] = (r - i + 1).min(z[i - l]);
        }
        while i + z[i] < n && bytes[z[i]] == bytes[i + z[i]] {
            z[i] += 1;
        }
        if i + z[i] - 1 > r {
            l = i;
            r = i + z[i] - 1;
        }
    }
    Ok(Value::make_list(
        z.into_iter().map(|v| Value::SmallInt(v as i64)).collect(),
    ))
}

fn rolling_hash_table(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("rolling_hash_table(s)", None));
    }
    let s = expect_text(&args[0], "rolling_hash_table: expects string")?;
    const MOD: i64 = 1_000_000_007;
    const BASE: i64 = 911_382_323;
    let mut pref: Vec<i64> = vec![0; s.len() + 1];
    let mut pow: Vec<i64> = vec![1; s.len() + 1];
    for (i, b) in s.as_bytes().iter().enumerate() {
        pref[i + 1] = (pref[i] * BASE + *b as i64) % MOD;
        pow[i + 1] = (pow[i] * BASE) % MOD;
    }
    let pref_vals = pref.into_iter().map(Value::SmallInt).collect::<Vec<_>>();
    let pow_vals = pow.into_iter().map(Value::SmallInt).collect::<Vec<_>>();
    let mut map = HashMap::new();
    map.insert("pref".into(), Value::make_list(pref_vals));
    map.insert("pow".into(), Value::make_list(pow_vals));
    map.insert("mod".into(), Value::SmallInt(MOD));
    map.insert("base".into(), Value::SmallInt(BASE));
    Ok(Value::make_map(map))
}

fn list_to_i64(vec: &Value) -> Result<Vec<i64>, RuntimeError> {
    if let Value::RcObj(rc) = vec {
        if let NauxObj::List(items) = rc.as_ref() {
            return items
                .borrow()
                .iter()
                .map(|v| {
                    v.as_i64().ok_or_else(|| {
                        RuntimeError::new("rolling_hash_sub: pref/pow must be ints", None)
                    })
                })
                .collect();
        }
    }
    Err(RuntimeError::new(
        "rolling_hash_sub: pref/pow must be list",
        None,
    ))
}

fn rolling_hash_sub(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("rolling_hash_sub(table, l, r)", None));
    }
    let table = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Map(m) => m,
            _ => {
                return Err(RuntimeError::new(
                    "rolling_hash_sub: first arg must be map from rolling_hash_table",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "rolling_hash_sub: first arg must be map from rolling_hash_table",
                None,
            ))
        }
    };
    let pref = list_to_i64(table.borrow().get("pref").unwrap_or(&Value::Null))?;
    let pow = list_to_i64(table.borrow().get("pow").unwrap_or(&Value::Null))?;
    let modulo = table
        .borrow()
        .get("mod")
        .and_then(|v| v.as_i64())
        .unwrap_or(1_000_000_007);
    let l = to_i64_local(&args[1])? as usize;
    let r = to_i64_local(&args[2])? as usize;
    if r >= pref.len() || l >= pref.len() || l > r {
        return Err(RuntimeError::new("rolling_hash_sub: invalid range", None));
    }
    let len = r - l;
    if len >= pow.len() {
        return Err(RuntimeError::new(
            "rolling_hash_sub: pow table too short",
            None,
        ));
    }
    let hash = (pref[r] - (pref[l] * pow[len]) % modulo + modulo) % modulo;
    Ok(Value::SmallInt(hash))
}

fn rabin_karp(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("rabin_karp(text, pattern)", None));
    }
    let text = expect_text(&args[0], "text must be string")?;
    let pat = expect_text(&args[1], "pattern must be string")?;
    if pat.is_empty() {
        return Ok(Value::make_list(vec![]));
    }
    const MOD: i64 = 1_000_000_007;
    const BASE: i64 = 911_382_323;
    let n = text.len();
    let m = pat.len();
    if m > n {
        return Ok(Value::make_list(vec![]));
    }
    let mut pow: Vec<i64> = vec![1; m + 1];
    for i in 1..=m {
        pow[i] = (pow[i - 1] * BASE) % MOD;
    }
    let mut pat_hash = 0i64;
    for &b in pat.as_bytes() {
        pat_hash = (pat_hash * BASE + b as i64) % MOD;
    }
    let mut cur = 0i64;
    let bytes = text.as_bytes();
    for i in 0..m {
        cur = (cur * BASE + bytes[i] as i64) % MOD;
    }
    let mut res = Vec::new();
    if cur == pat_hash && &bytes[0..m] == pat.as_bytes() {
        res.push(Value::SmallInt(0));
    }
    for i in m..n {
        let lead = bytes[i - m] as i64 * pow[m - 1] % MOD;
        cur = (cur + MOD - lead) % MOD;
        cur = (cur * BASE + bytes[i] as i64) % MOD;
        if cur == pat_hash && &bytes[i + 1 - m..=i] == pat.as_bytes() {
            res.push(Value::SmallInt((i + 1 - m) as i64));
        }
    }
    Ok(Value::make_list(res))
}

fn manacher_lps(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("manacher_lps(s)", None));
    }
    let s = expect_text(&args[0], "s must be string")?;
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return Ok(Value::make_map(HashMap::new()));
    }
    // Transform string with separators to handle even/odd palindromes uniformly.
    let mut t = Vec::with_capacity(chars.len() * 2 + 1);
    for &c in &chars {
        t.push('#');
        t.push(c);
    }
    t.push('#');
    let n = t.len();
    let mut p = vec![0usize; n];
    let (mut center, mut right) = (0usize, 0usize);
    let mut best = (0usize, 0usize); // (radius, center)
    for i in 0..n {
        if i < right {
            let mirror = 2 * center - i;
            p[i] = p[mirror].min(right - i);
        }
        while i + p[i] + 1 < n && i > p[i] && t[i + p[i] + 1] == t[i - p[i] - 1] {
            p[i] += 1;
        }
        if i + p[i] > right {
            center = i;
            right = i + p[i];
        }
        if p[i] > best.0 {
            best = (p[i], i);
        }
    }
    let radius = best.0;
    let center_idx = best.1;
    let start_in_t = center_idx - radius;
    // Map back to original indices.
    let start = start_in_t / 2;
    let length = radius;
    let substring: String = chars[start..start + length].iter().collect();

    let mut out = HashMap::new();
    out.insert("start".into(), Value::SmallInt(start as i64));
    out.insert("length".into(), Value::SmallInt(length as i64));
    out.insert("substring".into(), Value::make_text(substring));
    Ok(Value::make_map(out))
}

fn sparse_table_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.is_empty() {
        return Err(RuntimeError::new(
            "sparse_table_new(list, [op=min|max])",
            None,
        ));
    }
    let arr = to_num_list(&args[0])?;
    let op = args
        .get(1)
        .and_then(|v| v.as_text())
        .unwrap_or_else(|| "min".into());
    if arr.is_empty() {
        return Err(RuntimeError::new("sparse_table_new: empty list", None));
    }
    let n = arr.len();
    let mut log = vec![0usize; n + 1];
    for i in 2..=n {
        log[i] = log[i / 2] + 1;
    }
    let k = log[n] + 1;
    let mut table: Vec<Vec<f64>> = vec![vec![0.0; n]; k];
    table[0].clone_from_slice(&arr);
    for j in 1..k {
        let len = 1usize << j;
        let half = len >> 1;
        for i in 0..=n.saturating_sub(len) {
            let a = table[j - 1][i];
            let b = table[j - 1][i + half];
            table[j][i] = match op.as_str() {
                "max" => a.max(b),
                _ => a.min(b),
            };
        }
    }
    let table_val = Value::make_list(
        table
            .into_iter()
            .map(|row| Value::make_list(row.into_iter().map(Value::Float).collect::<Vec<_>>()))
            .collect(),
    );
    let log_val = Value::make_list(log.into_iter().map(|v| Value::SmallInt(v as i64)).collect());
    let mut map = HashMap::new();
    map.insert("table".into(), table_val);
    map.insert("log".into(), log_val);
    map.insert("op".into(), Value::make_text(op));
    Ok(Value::make_map(map))
}

fn sparse_table_query(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() < 3 {
        return Err(RuntimeError::new(
            "sparse_table_query(table_map, l, r)",
            None,
        ));
    }
    let tbl = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Map(m) => m,
            _ => {
                return Err(RuntimeError::new(
                    "sparse_table_query: first arg must be map from sparse_table_new",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "sparse_table_query: first arg must be map from sparse_table_new",
                None,
            ))
        }
    };
    let l = to_i64_local(&args[1])? as usize;
    let r = to_i64_local(&args[2])? as usize;
    let op = tbl
        .borrow()
        .get("op")
        .and_then(|v| v.as_text())
        .unwrap_or_else(|| "min".into());
    let table_v = tbl.borrow().get("table").cloned().unwrap_or(Value::Null);
    let log_v = tbl.borrow().get("log").cloned().unwrap_or(Value::Null);
    let rows = match table_v {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::List(rows) => rows.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "sparse_table_query: invalid table format",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "sparse_table_query: invalid table format",
                None,
            ))
        }
    };
    let logs = list_to_i64(&log_v)?;
    let n = logs.len().saturating_sub(1);
    if l > r || r >= n {
        return Err(RuntimeError::new("sparse_table_query: invalid range", None));
    }
    let len = r - l + 1;
    let k = logs[len];
    let row = rows.borrow();
    let row_k_v = row
        .get(k as usize)
        .cloned()
        .ok_or_else(|| RuntimeError::new("sparse_table_query: table level missing", None))?;
    let row_k = match row_k_v {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::List(items) => items.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "sparse_table_query: invalid row format",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "sparse_table_query: invalid row format",
                None,
            ))
        }
    };
    let vals = row_k.borrow();
    let a = vals
        .get(l)
        .and_then(|v| v.as_f64())
        .ok_or_else(|| RuntimeError::new("sparse_table_query: index out of range", None))?;
    let b = vals
        .get(r + 1 - (1usize << k as usize))
        .and_then(|v| v.as_f64())
        .ok_or_else(|| RuntimeError::new("sparse_table_query: index out of range", None))?;
    let res = match op.as_str() {
        "max" => a.max(b),
        _ => a.min(b),
    };
    Ok(Value::Float(res))
}

fn suffix_array(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("suffix_array(s)", None));
    }
    let s = expect_text(&args[0], "s must be string")?;
    let n = s.len();
    let mut sa: Vec<usize> = (0..n).collect();
    let mut rnk: Vec<i32> = s.as_bytes().iter().map(|&c| c as i32).collect();
    rnk.push(-1);
    let mut k = 1;
    let mut tmp = vec![0i32; n];
    while k <= n {
        sa.sort_by(|&a, &b| {
            let ra = (
                rnk.get(a).copied().unwrap_or(-1),
                rnk.get(a + k).copied().unwrap_or(-1),
            );
            let rb = (
                rnk.get(b).copied().unwrap_or(-1),
                rnk.get(b + k).copied().unwrap_or(-1),
            );
            ra.cmp(&rb)
        });
        tmp[sa[0]] = 0;
        for i in 1..n {
            tmp[sa[i]] = tmp[sa[i - 1]]
                + if (
                    rnk[sa[i - 1]],
                    rnk.get(sa[i - 1] + k).copied().unwrap_or(-1),
                ) < (rnk[sa[i]], rnk.get(sa[i] + k).copied().unwrap_or(-1))
                {
                    1
                } else {
                    0
                };
        }
        for i in 0..n {
            rnk[i] = tmp[i];
        }
        if rnk[sa[n - 1]] == (n as i32 - 1) {
            break;
        }
        k <<= 1;
    }
    // LCP (Kasai)
    let mut lcp = vec![0usize; n];
    let mut inv = vec![0usize; n];
    for i in 0..n {
        inv[sa[i]] = i;
    }
    let mut k_lcp = 0usize;
    for i in 0..n {
        if inv[i] == n - 1 {
            k_lcp = 0;
            continue;
        }
        let j = sa[inv[i] + 1];
        while i + k_lcp < n && j + k_lcp < n && s.as_bytes()[i + k_lcp] == s.as_bytes()[j + k_lcp] {
            k_lcp += 1;
        }
        lcp[inv[i]] = k_lcp;
        if k_lcp > 0 {
            k_lcp -= 1;
        }
    }
    let mut res_map = std::collections::HashMap::new();
    res_map.insert(
        "sa".into(),
        Value::make_list(sa.iter().map(|&i| Value::SmallInt(i as i64)).collect()),
    );
    res_map.insert(
        "lcp".into(),
        Value::make_list(lcp.iter().map(|&i| Value::SmallInt(i as i64)).collect()),
    );
    Ok(Value::make_map(res_map))
}

// --- FFT / NTT convolution ---

#[derive(Clone, Copy, Debug)]
struct Complex {
    re: f64,
    im: f64,
}

impl Complex {
    fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }
    fn mul(self, other: Complex) -> Complex {
        Complex {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }
    fn add(self, other: Complex) -> Complex {
        Complex {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }
    fn sub(self, other: Complex) -> Complex {
        Complex {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }
}

fn fft(values: &mut [Complex], invert: bool) {
    let n = values.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            values.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let ang = 2.0 * std::f64::consts::PI / len as f64 * if invert { -1.0 } else { 1.0 };
        let wlen = Complex::new(ang.cos(), ang.sin());
        let mut i = 0;
        while i < n {
            let mut w = Complex::new(1.0, 0.0);
            for j in 0..len / 2 {
                let u = values[i + j];
                let v = values[i + j + len / 2].mul(w);
                values[i + j] = u.add(v);
                values[i + j + len / 2] = u.sub(v);
                w = w.mul(wlen);
            }
            i += len;
        }
        len <<= 1;
    }
    if invert {
        for v in values.iter_mut() {
            v.re /= n as f64;
            v.im /= n as f64;
        }
    }
}

fn fft_convolve(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("fft_convolve(a, b)", None));
    }
    let a = to_num_list(&args[0])?;
    let b = to_num_list(&args[1])?;
    let mut n = 1usize;
    while n < a.len() + b.len() {
        n <<= 1;
    }
    let mut fa: Vec<Complex> = vec![Complex::new(0.0, 0.0); n];
    let mut fb: Vec<Complex> = vec![Complex::new(0.0, 0.0); n];
    for i in 0..a.len() {
        fa[i].re = a[i];
    }
    for i in 0..b.len() {
        fb[i].re = b[i];
    }
    fft(&mut fa, false);
    fft(&mut fb, false);
    for i in 0..n {
        fa[i] = fa[i].mul(fb[i]);
    }
    fft(&mut fa, true);
    let mut res = Vec::new();
    for i in 0..(a.len() + b.len() - 1) {
        res.push(Value::Float(fa[i].re));
    }
    Ok(Value::make_list(res))
}

// NTT helpers
const MOD: i64 = 998_244_353;
const PRIM_ROOT: i64 = 3;

fn mod_pow(mut a: i64, mut e: i64, m: i64) -> i64 {
    let mut res = 1i64;
    while e > 0 {
        if e & 1 == 1 {
            res = res * a % m;
        }
        a = a * a % m;
        e >>= 1;
    }
    res
}

fn ntt(a: &mut Vec<i64>, invert: bool) {
    let n = a.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let wlen = if invert {
            mod_pow(PRIM_ROOT, MOD - 1 - (MOD - 1) / len as i64, MOD)
        } else {
            mod_pow(PRIM_ROOT, (MOD - 1) / len as i64, MOD)
        };
        let mut i = 0;
        while i < n {
            let mut w = 1i64;
            for j in 0..len / 2 {
                let u = a[i + j];
                let v = a[i + j + len / 2] * w % MOD;
                a[i + j] = (u + v) % MOD;
                a[i + j + len / 2] = (u - v + MOD) % MOD;
                w = w * wlen % MOD;
            }
            i += len;
        }
        len <<= 1;
    }
    if invert {
        let inv_n = mod_pow(n as i64, MOD - 2, MOD);
        for x in a.iter_mut() {
            *x = *x * inv_n % MOD;
        }
    }
}

fn ntt_convolve(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("ntt_convolve(a, b)", None));
    }
    let a = to_num_list(&args[0])?;
    let b = to_num_list(&args[1])?;
    let mut n = 1usize;
    while n < a.len() + b.len() {
        n <<= 1;
    }
    let mut fa: Vec<i64> = vec![0; n];
    let mut fb: Vec<i64> = vec![0; n];
    for i in 0..a.len() {
        fa[i] = (a[i] as i64 % MOD + MOD) % MOD;
    }
    for i in 0..b.len() {
        fb[i] = (b[i] as i64 % MOD + MOD) % MOD;
    }
    ntt(&mut fa, false);
    ntt(&mut fb, false);
    for i in 0..n {
        fa[i] = fa[i] * fb[i] % MOD;
    }
    ntt(&mut fa, true);
    let mut res = Vec::new();
    for i in 0..(a.len() + b.len() - 1) {
        res.push(Value::SmallInt(fa[i]));
    }
    Ok(Value::make_list(res))
}

// --- DSU ---

fn dsu_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("dsu_new(n)", None));
    }
    let n = args[0]
        .as_i64()
        .ok_or_else(|| RuntimeError::new("n must be number", None))? as usize;
    let mut parent = Vec::new();
    let mut rank = Vec::new();
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
    let mut dsu = args[0].clone();
    let x = to_i64_local(&args[1])? as usize;
    let (mut parent, rank) = extract_dsu(&dsu)?;
    let root = find_internal(x, &mut parent);
    let mut map = std::collections::HashMap::new();
    map.insert(
        "p".into(),
        Value::make_list(parent.into_iter().map(Value::SmallInt).collect()),
    );
    map.insert(
        "r".into(),
        Value::make_list(rank.into_iter().map(Value::SmallInt).collect()),
    );
    dsu = Value::make_map(map);
    Ok(Value::make_list(vec![Value::SmallInt(root as i64), dsu]))
}

fn dsu_union(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("dsu_union(dsu, a, b)", None));
    }
    let mut dsu = args[0].clone();
    let a = to_i64_local(&args[1])? as usize;
    let b = to_i64_local(&args[2])? as usize;
    let (mut parent, mut rank) = extract_dsu(&dsu)?;
    let ra = find_internal(a, &mut parent);
    let rb = find_internal(b, &mut parent);
    if ra != rb {
        if rank[ra] < rank[rb] {
            parent[ra] = rb as i64;
        } else if rank[ra] > rank[rb] {
            parent[rb] = ra as i64;
        } else {
            parent[rb] = ra as i64;
            rank[ra] += 1;
        }
    }
    let mut map = std::collections::HashMap::new();
    map.insert(
        "p".into(),
        Value::make_list(parent.into_iter().map(Value::SmallInt).collect()),
    );
    map.insert(
        "r".into(),
        Value::make_list(rank.into_iter().map(Value::SmallInt).collect()),
    );
    dsu = Value::make_map(map);
    Ok(dsu)
}

fn extract_dsu(dsu: &Value) -> Result<(Vec<i64>, Vec<i64>), RuntimeError> {
    if let Value::RcObj(rc) = dsu {
        if let NauxObj::Map(map) = rc.as_ref() {
            let mb = map.borrow();
            let p = mb
                .get("p")
                .ok_or(RuntimeError::new("dsu missing p", None))?;
            let r = mb
                .get("r")
                .ok_or(RuntimeError::new("dsu missing r", None))?;
            let parent = to_num_list(p)?.into_iter().map(|x| x as i64).collect();
            let rank = to_num_list(r)?.into_iter().map(|x| x as i64).collect();
            return Ok((parent, rank));
        }
    }
    Err(RuntimeError::new("invalid dsu", None))
}

fn find_internal(x: usize, parent: &mut Vec<i64>) -> usize {
    if parent[x] as usize != x {
        parent[x] = find_internal(parent[x] as usize, parent) as i64;
    }
    parent[x] as usize
}

// --- SEGMENT TREE FAMILY (sum) ---

fn segtree_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("segtree_new(list)", None));
    }
    let arr = to_num_list(&args[0])?;
    let (size, n, tree) = build_segtree_state_from_arr(&arr);
    Ok(make_segtree_value(size, n, tree))
}

fn segtree_query(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_query(tree, l, r)", None));
    }
    let (size, n, tree_val) = extract_segtree_meta(&args[0])?;
    let (l, r) = normalize_range_to_len(to_i64_local(&args[1])?, to_i64_local(&args[2])?, n);
    if l >= r {
        return Ok(Value::Float(0.0));
    }
    let tree = expect_value_list_ref(&tree_val, "invalid segtree: tree must be list")?;
    let tree = tree.borrow();
    if tree.len() < size * 2 {
        return Err(RuntimeError::new("invalid segtree: malformed tree", None));
    }

    let mut left = l + size;
    let mut right = r + size;
    let mut acc = 0.0;
    while left < right {
        if (left & 1) == 1 {
            acc += value_num_at(&tree, left);
            left += 1;
        }
        if (right & 1) == 1 {
            right -= 1;
            acc += value_num_at(&tree, right);
        }
        left >>= 1;
        right >>= 1;
    }
    Ok(Value::Float(acc))
}

fn segtree_update(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_update(tree, idx, val)", None));
    }
    let (size, n, tree_val) = extract_segtree_meta(&args[0])?;
    let idx = to_i64_local(&args[1])?;
    let val = args[2]
        .as_f64()
        .ok_or_else(|| RuntimeError::new("segtree_update: val must be number", None))?;
    if idx < 0 || idx as usize >= n {
        return Ok(args[0].clone());
    }
    let tree = expect_value_list_ref(&tree_val, "invalid segtree: tree must be list")?;
    let mut tree = tree.borrow_mut();
    if tree.len() < size * 2 {
        return Err(RuntimeError::new("invalid segtree: malformed tree", None));
    }

    let mut pos = idx as usize + size;
    set_value_num_at(&mut tree, pos, val);
    pos >>= 1;
    while pos > 0 {
        let sum = value_num_at(&tree, pos << 1) + value_num_at(&tree, (pos << 1) | 1);
        set_value_num_at(&mut tree, pos, sum);
        pos >>= 1;
    }
    Ok(args[0].clone())
}

fn segtree_lazy_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("segtree_lazy_new(list)", None));
    }
    let arr = to_num_list(&args[0])?;
    let (size, n, tree) = build_segtree_state_from_arr(&arr);
    let lazy = vec![0.0; tree.len()];
    Ok(make_lazy_segtree_value(size, n, tree, lazy))
}

fn segtree_lazy_add(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 4 {
        return Err(RuntimeError::new(
            "segtree_lazy_add(tree, l, r, delta)",
            None,
        ));
    }
    let (size, n, tree_val, lazy_val) = extract_lazy_segtree_meta(&args[0])?;
    let (l, r) = normalize_range_to_len(to_i64_local(&args[1])?, to_i64_local(&args[2])?, n);
    let delta = args[3]
        .as_f64()
        .ok_or_else(|| RuntimeError::new("segtree_lazy_add: delta must be number", None))?;
    let tree = expect_value_list_ref(&tree_val, "invalid lazy segtree: tree must be list")?;
    let lazy = expect_value_list_ref(&lazy_val, "invalid lazy segtree: lazy must be list")?;
    let mut tree = tree.borrow_mut();
    let mut lazy = lazy.borrow_mut();
    if tree.len() < size * 2 || lazy.len() < size * 2 {
        return Err(RuntimeError::new(
            "invalid lazy segtree: malformed buffers",
            None,
        ));
    }
    if l < r {
        segtree_lazy_add_rec(1, 0, size, l, r, delta, &mut tree, &mut lazy);
    }
    Ok(args[0].clone())
}

fn segtree_lazy_query(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_lazy_query(tree, l, r)", None));
    }
    let (size, n, tree_val, lazy_val) = extract_lazy_segtree_meta(&args[0])?;
    let (l, r) = normalize_range_to_len(to_i64_local(&args[1])?, to_i64_local(&args[2])?, n);
    if l >= r {
        return Ok(Value::Float(0.0));
    }
    let tree = expect_value_list_ref(&tree_val, "invalid lazy segtree: tree must be list")?;
    let lazy = expect_value_list_ref(&lazy_val, "invalid lazy segtree: lazy must be list")?;
    let mut tree = tree.borrow_mut();
    let mut lazy = lazy.borrow_mut();
    if tree.len() < size * 2 || lazy.len() < size * 2 {
        return Err(RuntimeError::new(
            "invalid lazy segtree: malformed buffers",
            None,
        ));
    }
    let ans = segtree_lazy_query_rec(1, 0, size, l, r, &mut tree, &mut lazy);
    Ok(Value::Float(ans))
}

fn segtree_dynamic_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("segtree_dynamic_new(lo, hi)", None));
    }
    let lo = to_i64_local(&args[0])?;
    let hi = to_i64_local(&args[1])?;
    if hi <= lo {
        return Err(RuntimeError::new(
            "segtree_dynamic_new: require lo < hi",
            None,
        ));
    }
    Ok(make_dynamic_segtree_value(
        lo,
        hi,
        vec![-1],
        vec![-1],
        vec![0.0],
    ))
}

fn segtree_dynamic_add(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new(
            "segtree_dynamic_add(tree, idx, delta)",
            None,
        ));
    }
    let (lo, hi, left_val, right_val, sum_val) = extract_dynamic_segtree_meta(&args[0])?;
    let idx = to_i64_local(&args[1])?;
    let delta = args[2]
        .as_f64()
        .ok_or_else(|| RuntimeError::new("segtree_dynamic_add: delta must be number", None))?;
    if idx < lo || idx >= hi {
        return Ok(args[0].clone());
    }
    let left = expect_value_list_ref(&left_val, "invalid dynamic segtree: left must be list")?;
    let right = expect_value_list_ref(&right_val, "invalid dynamic segtree: right must be list")?;
    let sum = expect_value_list_ref(&sum_val, "invalid dynamic segtree: sum must be list")?;
    let mut left = left.borrow_mut();
    let mut right = right.borrow_mut();
    let mut sum = sum.borrow_mut();
    if left.len() != right.len() || left.len() != sum.len() || left.is_empty() {
        return Err(RuntimeError::new(
            "invalid dynamic segtree: malformed buffers",
            None,
        ));
    }
    dyn_point_add(0, lo, hi, idx, delta, &mut left, &mut right, &mut sum);
    Ok(args[0].clone())
}

fn segtree_dynamic_query(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_dynamic_query(tree, l, r)", None));
    }
    let (lo, hi, left_val, right_val, sum_val) = extract_dynamic_segtree_meta(&args[0])?;
    let (l, r) = normalize_i64_range(to_i64_local(&args[1])?, to_i64_local(&args[2])?, lo, hi);
    if l >= r {
        return Ok(Value::Float(0.0));
    }
    let left = expect_value_list_ref(&left_val, "invalid dynamic segtree: left must be list")?;
    let right = expect_value_list_ref(&right_val, "invalid dynamic segtree: right must be list")?;
    let sum = expect_value_list_ref(&sum_val, "invalid dynamic segtree: sum must be list")?;
    let left = left.borrow();
    let right = right.borrow();
    let sum = sum.borrow();
    if left.len() != right.len() || left.len() != sum.len() || left.is_empty() {
        return Err(RuntimeError::new(
            "invalid dynamic segtree: malformed buffers",
            None,
        ));
    }
    let ans = dyn_query(0, lo, hi, l, r, &left, &right, &sum);
    Ok(Value::Float(ans))
}

fn build_segtree_state_from_arr(arr: &[f64]) -> (usize, usize, Vec<f64>) {
    let n = arr.len();
    let mut size = 1usize;
    while size < n.max(1) {
        size <<= 1;
    }
    let mut tree = vec![0.0; size * 2];
    for (i, v) in arr.iter().enumerate() {
        tree[size + i] = *v;
    }
    for i in (1..size).rev() {
        tree[i] = tree[i << 1] + tree[(i << 1) | 1];
    }
    (size, n, tree)
}

fn make_segtree_value(size: usize, n: usize, tree: Vec<f64>) -> Value {
    let mut map = std::collections::HashMap::new();
    map.insert("size".into(), Value::SmallInt(size as i64));
    map.insert("n".into(), Value::SmallInt(n as i64));
    map.insert(
        "tree".into(),
        Value::make_list(tree.into_iter().map(Value::Float).collect()),
    );
    Value::make_map(map)
}

fn make_lazy_segtree_value(size: usize, n: usize, tree: Vec<f64>, lazy: Vec<f64>) -> Value {
    let mut map = std::collections::HashMap::new();
    map.insert("size".into(), Value::SmallInt(size as i64));
    map.insert("n".into(), Value::SmallInt(n as i64));
    map.insert(
        "tree".into(),
        Value::make_list(tree.into_iter().map(Value::Float).collect()),
    );
    map.insert(
        "lazy".into(),
        Value::make_list(lazy.into_iter().map(Value::Float).collect()),
    );
    Value::make_map(map)
}

fn extract_segtree_meta(tree: &Value) -> Result<(usize, usize, Value), RuntimeError> {
    if let Value::RcObj(rc) = tree {
        if let NauxObj::Map(map) = rc.as_ref() {
            let m = map.borrow();
            let size = value_num_as_i64(
                m.get("size")
                    .ok_or_else(|| RuntimeError::new("invalid segtree: missing size", None))?,
            )
            .ok_or_else(|| RuntimeError::new("invalid segtree: invalid size", None))?;
            let n = value_num_as_i64(
                m.get("n")
                    .ok_or_else(|| RuntimeError::new("invalid segtree: missing n", None))?,
            )
            .ok_or_else(|| RuntimeError::new("invalid segtree: invalid n", None))?;
            let data = m
                .get("tree")
                .cloned()
                .ok_or_else(|| RuntimeError::new("invalid segtree: missing tree", None))?;
            return Ok((size.max(1) as usize, n.max(0) as usize, data));
        }
    }
    Err(RuntimeError::new("invalid segtree", None))
}

fn extract_lazy_segtree_meta(tree: &Value) -> Result<(usize, usize, Value, Value), RuntimeError> {
    let (size, n, base_tree) = extract_segtree_meta(tree)?;
    if let Value::RcObj(rc) = tree {
        if let NauxObj::Map(map) = rc.as_ref() {
            let lazy = map
                .borrow()
                .get("lazy")
                .cloned()
                .ok_or_else(|| RuntimeError::new("invalid lazy segtree: missing lazy", None))?;
            return Ok((size, n, base_tree, lazy));
        }
    }
    Err(RuntimeError::new("invalid lazy segtree", None))
}

fn normalize_range_to_len(l: i64, r: i64, n: usize) -> (usize, usize) {
    let n64 = n as i64;
    let left = l.max(0).min(n64);
    let right = r.max(0).min(n64);
    if left >= right {
        (left as usize, left as usize)
    } else {
        (left as usize, right as usize)
    }
}

fn segtree_lazy_apply(
    node: usize,
    seg_l: usize,
    seg_r: usize,
    delta: f64,
    tree: &mut [Value],
    lazy: &mut [Value],
) {
    let cur_tree = value_num_at(tree, node);
    let cur_lazy = value_num_at(lazy, node);
    set_value_num_at(tree, node, cur_tree + delta * (seg_r - seg_l) as f64);
    set_value_num_at(lazy, node, cur_lazy + delta);
}

fn segtree_lazy_push(
    node: usize,
    seg_l: usize,
    seg_r: usize,
    tree: &mut [Value],
    lazy: &mut [Value],
) {
    if seg_r - seg_l <= 1 {
        return;
    }
    let delta = value_num_at(lazy, node);
    if delta == 0.0 {
        return;
    }
    let mid = seg_l + (seg_r - seg_l) / 2;
    let left = node << 1;
    let right = left | 1;
    segtree_lazy_apply(left, seg_l, mid, delta, tree, lazy);
    segtree_lazy_apply(right, mid, seg_r, delta, tree, lazy);
    set_value_num_at(lazy, node, 0.0);
}

fn segtree_lazy_add_rec(
    node: usize,
    seg_l: usize,
    seg_r: usize,
    ql: usize,
    qr: usize,
    delta: f64,
    tree: &mut [Value],
    lazy: &mut [Value],
) {
    if qr <= seg_l || seg_r <= ql {
        return;
    }
    if ql <= seg_l && seg_r <= qr {
        segtree_lazy_apply(node, seg_l, seg_r, delta, tree, lazy);
        return;
    }
    segtree_lazy_push(node, seg_l, seg_r, tree, lazy);
    let mid = seg_l + (seg_r - seg_l) / 2;
    let left = node << 1;
    let right = left | 1;
    segtree_lazy_add_rec(left, seg_l, mid, ql, qr, delta, tree, lazy);
    segtree_lazy_add_rec(right, mid, seg_r, ql, qr, delta, tree, lazy);
    let sum = value_num_at(tree, left) + value_num_at(tree, right);
    set_value_num_at(tree, node, sum);
}

fn segtree_lazy_query_rec(
    node: usize,
    seg_l: usize,
    seg_r: usize,
    ql: usize,
    qr: usize,
    tree: &mut [Value],
    lazy: &mut [Value],
) -> f64 {
    if qr <= seg_l || seg_r <= ql {
        return 0.0;
    }
    if ql <= seg_l && seg_r <= qr {
        return value_num_at(tree, node);
    }
    segtree_lazy_push(node, seg_l, seg_r, tree, lazy);
    let mid = seg_l + (seg_r - seg_l) / 2;
    let left = node << 1;
    let right = left | 1;
    segtree_lazy_query_rec(left, seg_l, mid, ql, qr, tree, lazy)
        + segtree_lazy_query_rec(right, mid, seg_r, ql, qr, tree, lazy)
}

fn make_dynamic_segtree_value(
    lo: i64,
    hi: i64,
    left: Vec<i64>,
    right: Vec<i64>,
    sum: Vec<f64>,
) -> Value {
    let mut map = std::collections::HashMap::new();
    map.insert("lo".into(), Value::SmallInt(lo));
    map.insert("hi".into(), Value::SmallInt(hi));
    map.insert(
        "left".into(),
        Value::make_list(left.into_iter().map(Value::SmallInt).collect()),
    );
    map.insert(
        "right".into(),
        Value::make_list(right.into_iter().map(Value::SmallInt).collect()),
    );
    map.insert(
        "sum".into(),
        Value::make_list(sum.into_iter().map(Value::Float).collect()),
    );
    Value::make_map(map)
}

fn extract_dynamic_segtree_meta(
    tree: &Value,
) -> Result<(i64, i64, Value, Value, Value), RuntimeError> {
    if let Value::RcObj(rc) = tree {
        if let NauxObj::Map(map) = rc.as_ref() {
            let m = map.borrow();
            let lo =
                value_num_as_i64(m.get("lo").ok_or_else(|| {
                    RuntimeError::new("invalid dynamic segtree: missing lo", None)
                })?)
                .ok_or_else(|| RuntimeError::new("invalid dynamic segtree: invalid lo", None))?;
            let hi =
                value_num_as_i64(m.get("hi").ok_or_else(|| {
                    RuntimeError::new("invalid dynamic segtree: missing hi", None)
                })?)
                .ok_or_else(|| RuntimeError::new("invalid dynamic segtree: invalid hi", None))?;
            let left_values = m
                .get("left")
                .cloned()
                .ok_or_else(|| RuntimeError::new("invalid dynamic segtree: missing left", None))?;
            let right_values = m
                .get("right")
                .cloned()
                .ok_or_else(|| RuntimeError::new("invalid dynamic segtree: missing right", None))?;
            let sum_values = m
                .get("sum")
                .cloned()
                .ok_or_else(|| RuntimeError::new("invalid dynamic segtree: missing sum", None))?;
            if hi <= lo {
                return Err(RuntimeError::new("invalid dynamic segtree: lo >= hi", None));
            }
            return Ok((lo, hi, left_values, right_values, sum_values));
        }
    }
    Err(RuntimeError::new("invalid dynamic segtree", None))
}

fn normalize_i64_range(l: i64, r: i64, lo: i64, hi: i64) -> (i64, i64) {
    let left = l.max(lo).min(hi);
    let right = r.max(lo).min(hi);
    if left >= right {
        (left, left)
    } else {
        (left, right)
    }
}

fn dyn_new_node(left: &mut Vec<Value>, right: &mut Vec<Value>, sum: &mut Vec<Value>) -> i64 {
    let idx = sum.len() as i64;
    left.push(Value::SmallInt(-1));
    right.push(Value::SmallInt(-1));
    sum.push(Value::Float(0.0));
    idx
}

fn dyn_point_add(
    node: i64,
    seg_l: i64,
    seg_r: i64,
    idx: i64,
    delta: f64,
    left: &mut Vec<Value>,
    right: &mut Vec<Value>,
    sum: &mut Vec<Value>,
) {
    let node_idx = node as usize;
    if seg_r - seg_l <= 1 {
        let v = value_num_at(sum, node_idx) + delta;
        set_value_num_at(sum, node_idx, v);
        return;
    }

    let mid = seg_l + (seg_r - seg_l) / 2;
    if idx < mid {
        let mut child = value_i64_at(left, node_idx);
        if child == -1 {
            child = dyn_new_node(left, right, sum);
            set_value_i64_at(left, node_idx, child);
        }
        dyn_point_add(child, seg_l, mid, idx, delta, left, right, sum);
    } else {
        let mut child = value_i64_at(right, node_idx);
        if child == -1 {
            child = dyn_new_node(left, right, sum);
            set_value_i64_at(right, node_idx, child);
        }
        dyn_point_add(child, mid, seg_r, idx, delta, left, right, sum);
    }

    let left_child = value_i64_at(left, node_idx);
    let right_child = value_i64_at(right, node_idx);
    let lsum = if left_child == -1 {
        0.0
    } else {
        value_num_at(sum, left_child as usize)
    };
    let rsum = if right_child == -1 {
        0.0
    } else {
        value_num_at(sum, right_child as usize)
    };
    set_value_num_at(sum, node_idx, lsum + rsum);
}

fn dyn_query(
    node: i64,
    seg_l: i64,
    seg_r: i64,
    ql: i64,
    qr: i64,
    left: &[Value],
    right: &[Value],
    sum: &[Value],
) -> f64 {
    if node == -1 || qr <= seg_l || seg_r <= ql {
        return 0.0;
    }
    let node_idx = node as usize;
    if ql <= seg_l && seg_r <= qr {
        return value_num_at(sum, node_idx);
    }
    let mid = seg_l + (seg_r - seg_l) / 2;
    dyn_query(
        value_i64_at(left, node_idx),
        seg_l,
        mid,
        ql,
        qr,
        left,
        right,
        sum,
    ) + dyn_query(
        value_i64_at(right, node_idx),
        mid,
        seg_r,
        ql,
        qr,
        left,
        right,
        sum,
    )
}

fn expect_value_list_ref<'a>(
    value: &'a Value,
    err: &str,
) -> Result<&'a std::cell::RefCell<Vec<Value>>, RuntimeError> {
    if let Value::RcObj(rc) = value {
        if let NauxObj::List(list) = rc.as_ref() {
            return Ok(list);
        }
    }
    Err(RuntimeError::new(err, None))
}

fn value_num_as_i64(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

fn value_num_at(values: &[Value], idx: usize) -> f64 {
    values.get(idx).and_then(Value::as_f64).unwrap_or(0.0)
}

fn value_i64_at(values: &[Value], idx: usize) -> i64 {
    values.get(idx).and_then(value_num_as_i64).unwrap_or(-1)
}

fn set_value_num_at(values: &mut [Value], idx: usize, v: f64) {
    if let Some(slot) = values.get_mut(idx) {
        *slot = Value::Float(v);
    }
}

fn set_value_i64_at(values: &mut [Value], idx: usize, v: i64) {
    if let Some(slot) = values.get_mut(idx) {
        *slot = Value::SmallInt(v);
    }
}

// --- Pollard Rho factorization (u64) ---

fn mul_mod(a: i128, b: i128, m: i128) -> i128 {
    (a * b % m + m) % m
}

fn is_probable_prime(n: i128) -> bool {
    if n < 2 {
        return false;
    }
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23] {
        if n == p {
            return true;
        }
        if n % p == 0 {
            return false;
        }
    }
    let mut d = n - 1;
    let mut s = 0;
    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }
    for &a in [2, 3, 5, 7, 11, 13].iter() {
        if a as i128 >= n {
            continue;
        }
        let mut x = mod_pow_i128(a as i128, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        let mut witness = false;
        for _ in 0..s - 1 {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                witness = true;
                break;
            }
        }
        if !witness {
            return false;
        }
    }
    true
}

fn mod_pow_i128(mut a: i128, mut e: i128, m: i128) -> i128 {
    let mut res = 1i128;
    while e > 0 {
        if e & 1 == 1 {
            res = mul_mod(res, a, m);
        }
        a = mul_mod(a, a, m);
        e >>= 1;
    }
    res
}

fn pollard_rho_single(n: i128, seed: i128) -> i128 {
    if n % 2 == 0 {
        return 2;
    }
    let mut x = seed % n;
    let mut y = x;
    let c = (seed % (n - 1)) + 1;
    let mut d = 1i128;
    while d == 1 {
        x = (mul_mod(x, x, n) + c) % n;
        y = (mul_mod(y, y, n) + c) % n;
        y = (mul_mod(y, y, n) + c) % n;
        let diff = if x > y { x - y } else { y - x };
        d = gcd_i128(diff, n);
        if d == n {
            return pollard_rho_single(n, seed + 1);
        }
    }
    d
}

fn gcd_i128(mut a: i128, mut b: i128) -> i128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.abs()
}

fn factor(n: i128, out: &mut Vec<i128>, seed: i128) {
    if n == 1 {
        return;
    }
    if is_probable_prime(n) {
        out.push(n);
        return;
    }
    let d = pollard_rho_single(n, seed);
    factor(d, out, seed + 1);
    factor(n / d, out, seed + 1);
}

fn pollard_rho(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("pollard_rho(n)", None));
    }
    let n = to_i64_local(&args[0])?;
    if n <= 1 {
        return Ok(Value::make_list(vec![]));
    }
    let mut factors: Vec<i128> = Vec::new();
    factor(n as i128, &mut factors, 2);
    factors.sort();
    Ok(Value::make_list(
        factors
            .into_iter()
            .map(|f| Value::SmallInt(f as i64))
            .collect(),
    ))
}

// --- Li Chao tree (min) ---

#[derive(Clone)]
struct Line {
    m: f64,
    b: f64,
}

#[derive(Clone)]
struct Node {
    l: i64,
    r: i64,
    line: Line,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

fn eval_line(line: &Line, x: i64) -> f64 {
    line.m * x as f64 + line.b
}

fn add_line_node(node: &mut Node, new_line: Line) {
    let mid = (node.l + node.r) / 2;
    let (mut low, mut high) = (node.line.clone(), new_line);
    if eval_line(&low, mid) > eval_line(&high, mid) {
        std::mem::swap(&mut low, &mut high);
    }
    node.line = low;
    if node.l == node.r {
        return;
    }
    if eval_line(&high, node.l) < eval_line(&node.line, node.l) {
        if node.left.is_none() {
            node.left = Some(Box::new(Node {
                l: node.l,
                r: mid,
                line: high.clone(),
                left: None,
                right: None,
            }));
        } else if let Some(ref mut left) = node.left {
            add_line_node(left, high.clone());
        }
    } else if eval_line(&high, node.r) < eval_line(&node.line, node.r) {
        if node.right.is_none() {
            node.right = Some(Box::new(Node {
                l: mid + 1,
                r: node.r,
                line: high.clone(),
                left: None,
                right: None,
            }));
        } else if let Some(ref mut right) = node.right {
            add_line_node(right, high.clone());
        }
    }
}

fn query_node(node: &Node, x: i64) -> f64 {
    let mut res = eval_line(&node.line, x);
    let mid = (node.l + node.r) / 2;
    if x <= mid {
        if let Some(ref left) = node.left {
            res = res.min(query_node(left, x));
        }
    } else if let Some(ref right) = node.right {
        res = res.min(query_node(right, x));
    }
    res
}

fn node_to_value(node: &Node) -> Value {
    let mut map = HashMap::new();
    map.insert("l".into(), Value::SmallInt(node.l));
    map.insert("r".into(), Value::SmallInt(node.r));
    let mut line_map = HashMap::new();
    line_map.insert("m".into(), Value::Float(node.line.m));
    line_map.insert("b".into(), Value::Float(node.line.b));
    map.insert("line".into(), Value::make_map(line_map));
    map.insert(
        "left".into(),
        node.left
            .as_ref()
            .map(|n| node_to_value(n))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "right".into(),
        node.right
            .as_ref()
            .map(|n| node_to_value(n))
            .unwrap_or(Value::Null),
    );
    Value::make_map(map)
}

fn value_to_node(v: &Value) -> Result<Node, RuntimeError> {
    if let Value::RcObj(rc) = v {
        if let NauxObj::Map(m) = rc.as_ref() {
            let mb = m.borrow();
            let l = mb
                .get("l")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| RuntimeError::new("missing l", None))?;
            let r = mb
                .get("r")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| RuntimeError::new("missing r", None))?;
            let line_val = mb
                .get("line")
                .ok_or_else(|| RuntimeError::new("missing line", None))?;
            let line = if let Value::RcObj(rc_line) = line_val {
                if let NauxObj::Map(map_line) = rc_line.as_ref() {
                    let ml = map_line.borrow();
                    Line {
                        m: ml.get("m").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        b: ml.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    }
                } else {
                    return Err(RuntimeError::new("invalid line", None));
                }
            } else {
                return Err(RuntimeError::new("invalid line", None));
            };
            let left = mb
                .get("left")
                .and_then(|v| match v {
                    Value::Null => None,
                    _ => Some(value_to_node(v)),
                })
                .transpose()?;
            let right = mb
                .get("right")
                .and_then(|v| match v {
                    Value::Null => None,
                    _ => Some(value_to_node(v)),
                })
                .transpose()?;
            return Ok(Node {
                l,
                r,
                line,
                left: left.map(Box::new),
                right: right.map(Box::new),
            });
        }
    }
    Err(RuntimeError::new("invalid Li Chao tree", None))
}

fn lichao_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("lichao_new(l, r)", None));
    }
    let l = to_i64_local(&args[0])?;
    let r = to_i64_local(&args[1])?;
    if l > r {
        return Err(RuntimeError::new("l must <= r", None));
    }
    let node = Node {
        l,
        r,
        line: Line {
            m: 0.0,
            b: f64::INFINITY,
        },
        left: None,
        right: None,
    };
    Ok(node_to_value(&node))
}

fn lichao_add(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("lichao_add(tree, m, b)", None));
    }
    let mut node = value_to_node(&args[0])?;
    let m = to_i64_local(&args[1])? as f64;
    let b = args[2]
        .as_f64()
        .ok_or_else(|| RuntimeError::new("b must be number", None))?;
    add_line_node(&mut node, Line { m, b });
    Ok(node_to_value(&node))
}

fn lichao_query(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("lichao_query(tree, x)", None));
    }
    let node = value_to_node(&args[0])?;
    let x = to_i64_local(&args[1])?;
    Ok(Value::Float(query_node(&node, x)))
}
