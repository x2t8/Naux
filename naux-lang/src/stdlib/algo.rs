#![allow(dead_code)]

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::{NauxObj, Value};
use std::collections::HashMap;

pub fn register_algo(env: &mut Env) {
    env.set_builtin("lis_length", lis_length);
    env.set_builtin("knapsack_01", knapsack_01);
    env.set_builtin("lower_bound", lower_bound);
    env.set_builtin("upper_bound", upper_bound);
    env.set_builtin("kmp_search", kmp_search);
    env.set_builtin("z_function", z_function);
    env.set_builtin("suffix_array", suffix_array);
    env.set_builtin("fft_convolve", fft_convolve);
    env.set_builtin("ntt_convolve", ntt_convolve);
    env.set_builtin("pollard_rho", pollard_rho);
    env.set_builtin("lichao_new", lichao_new);
    env.set_builtin("lichao_add", lichao_add);
    env.set_builtin("lichao_query", lichao_query);
    env.set_builtin("dsu_new", dsu_new);
    env.set_builtin("dsu_union", dsu_union);
    env.set_builtin("dsu_find", dsu_find);
    env.set_builtin("segtree_new", segtree_new);
    env.set_builtin("segtree_query", segtree_query);
    env.set_builtin("segtree_update", segtree_update);
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
    let cap = args[2].as_i64().ok_or_else(|| RuntimeError::new("cap must be number", None))?;
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

fn lower_bound(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("lower_bound(list, x)", None));
    }
    let arr = to_num_list(&args[0])?;
    let x = args[1].as_f64().ok_or_else(|| RuntimeError::new("x must be number", None))?;
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
    let x = args[1].as_f64().ok_or_else(|| RuntimeError::new("x must be number", None))?;
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
    Ok(Value::make_list(z.into_iter().map(|v| Value::SmallInt(v as i64)).collect()))
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
            let ra = (rnk.get(a).copied().unwrap_or(-1), rnk.get(a + k).copied().unwrap_or(-1));
            let rb = (rnk.get(b).copied().unwrap_or(-1), rnk.get(b + k).copied().unwrap_or(-1));
            ra.cmp(&rb)
        });
        tmp[sa[0]] = 0;
        for i in 1..n {
            tmp[sa[i]] = tmp[sa[i - 1]]
                + if (rnk[sa[i - 1]], rnk.get(sa[i - 1] + k).copied().unwrap_or(-1))
                    < (rnk[sa[i]], rnk.get(sa[i] + k).copied().unwrap_or(-1))
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
    res_map.insert("sa".into(), Value::make_list(sa.iter().map(|&i| Value::SmallInt(i as i64)).collect()));
    res_map.insert("lcp".into(), Value::make_list(lcp.iter().map(|&i| Value::SmallInt(i as i64)).collect()));
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
        Complex { re: self.re + other.re, im: self.im + other.im }
    }
    fn sub(self, other: Complex) -> Complex {
        Complex { re: self.re - other.re, im: self.im - other.im }
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
        res.push(Value::SmallInt(fa[i] as i64));
    }
    Ok(Value::make_list(res))
}

// --- DSU ---

fn dsu_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("dsu_new(n)", None));
    }
    let n = args[0].as_i64().ok_or_else(|| RuntimeError::new("n must be number", None))? as usize;
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
    map.insert("p".into(), Value::make_list(parent.into_iter().map(Value::SmallInt).collect()));
    map.insert("r".into(), Value::make_list(rank.into_iter().map(Value::SmallInt).collect()));
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
    map.insert("p".into(), Value::make_list(parent.into_iter().map(Value::SmallInt).collect()));
    map.insert("r".into(), Value::make_list(rank.into_iter().map(Value::SmallInt).collect()));
    dsu = Value::make_map(map);
    Ok(dsu)
}

fn extract_dsu(dsu: &Value) -> Result<(Vec<i64>, Vec<i64>), RuntimeError> {
    if let Value::RcObj(rc) = dsu {
        if let NauxObj::Map(map) = rc.as_ref() {
            let mb = map.borrow();
            let p = mb.get("p").ok_or(RuntimeError::new("dsu missing p", None))?;
            let r = mb.get("r").ok_or(RuntimeError::new("dsu missing r", None))?;
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

// --- SEGMENT TREE (simple array-based sum) ---

fn segtree_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("segtree_new(list)", None));
    }
    let arr = to_num_list(&args[0])?;
    let mut map = std::collections::HashMap::new();
    map.insert("data".into(), Value::make_list(arr.into_iter().map(Value::Float).collect()));
    Ok(Value::make_map(map))
}

fn segtree_query(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_query(tree, l, r)", None));
    }
    let data = extract_data(&args[0])?;
    let l = to_i64_local(&args[1])? as usize;
    let r = to_i64_local(&args[2])? as usize;
    let mut sum = 0.0;
    for i in l..r.min(data.len()) {
        sum += data[i];
    }
    Ok(Value::Float(sum))
}

fn segtree_update(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("segtree_update(tree, idx, val)", None));
    }
    let mut data = extract_data(&args[0])?;
    let idx = to_i64_local(&args[1])? as usize;
    let val = to_i64_local(&args[2])? as f64;
    if idx < data.len() {
        data[idx] = val;
    }
    let mut map = std::collections::HashMap::new();
    map.insert("data".into(), Value::make_list(data.into_iter().map(Value::Float).collect()));
    Ok(Value::make_map(map))
}

fn extract_data(tree: &Value) -> Result<Vec<f64>, RuntimeError> {
    if let Value::RcObj(rc) = tree {
        if let NauxObj::Map(map) = rc.as_ref() {
            if let Some(val) = map.borrow().get("data") {
                return to_num_list(val);
            }
        }
    }
    Err(RuntimeError::new("invalid segtree", None))
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
    Ok(Value::make_list(factors.into_iter().map(|f| Value::SmallInt(f as i64)).collect()))
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
            node.left = Some(Box::new(Node { l: node.l, r: mid, line: high.clone(), left: None, right: None }));
        } else if let Some(ref mut left) = node.left {
            add_line_node(left, high.clone());
        }
    } else if eval_line(&high, node.r) < eval_line(&node.line, node.r) {
        if node.right.is_none() {
            node.right = Some(Box::new(Node { l: mid + 1, r: node.r, line: high.clone(), left: None, right: None }));
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
        node.left.as_ref().map(|n| node_to_value(n)).unwrap_or(Value::Null),
    );
    map.insert(
        "right".into(),
        node.right.as_ref().map(|n| node_to_value(n)).unwrap_or(Value::Null),
    );
    Value::make_map(map)
}

fn value_to_node(v: &Value) -> Result<Node, RuntimeError> {
    if let Value::RcObj(rc) = v {
        if let NauxObj::Map(m) = rc.as_ref() {
            let mb = m.borrow();
            let l = mb.get("l").and_then(|v| v.as_i64()).ok_or_else(|| RuntimeError::new("missing l", None))?;
            let r = mb.get("r").and_then(|v| v.as_i64()).ok_or_else(|| RuntimeError::new("missing r", None))?;
            let line_val = mb.get("line").ok_or_else(|| RuntimeError::new("missing line", None))?;
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
            let left = mb.get("left").and_then(|v| match v {
                Value::Null => None,
                _ => Some(value_to_node(v)),
            }).transpose()?;
            let right = mb.get("right").and_then(|v| match v {
                Value::Null => None,
                _ => Some(value_to_node(v)),
            }).transpose()?;
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
        line: Line { m: 0.0, b: f64::INFINITY },
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
    let b = args[2].as_f64().ok_or_else(|| RuntimeError::new("b must be number", None))?;
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
