use std::collections::HashMap;
use std::collections::{HashSet, VecDeque};

use serde::Serialize;

use crate::ast::{Action, Arg, Expr, Program, Ritual, Statement, VarRef};

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Value {
    Number(f64),
    Boolean(bool),
    String(String),
    List(Vec<Value>),
    Object(HashMap<String, Value>),
    Null,
}

impl Value {
    pub fn as_bool(&self) -> bool {
        match self {
            Value::Boolean(b) => *b,
            Value::Number(n) => *n != 0.0,
            Value::Null => false,
            _ => true,
        }
    }

    pub fn to_string_lossy(&self) -> String {
        match self {
            Value::String(s) => s.clone(),
            Value::Number(n) => {
                if n.fract() == 0.0 {
                    format!("{}", *n as i64)
                } else {
                    n.to_string()
                }
            }
            Value::Boolean(b) => b.to_string(),
            Value::Null => "null".into(),
            Value::List(_) => "[list]".into(),
            Value::Object(_) => "{object}".into(),
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool_value(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            Value::Number(n) => Some(*n != 0.0),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum RuntimeEvent {
    Say(String),
    SetVar(String, Value),
    UiStart(String),
    UiEnd,
    UiText(String),
    UiButton(String),
    OracleRequest(String),
    OracleResponse(String),
}

#[derive(Debug, Clone)]
pub enum RuntimeError {
    UnknownAction(String),
    InvalidArgument(String),
}

impl RuntimeError {
    pub fn message(&self) -> String {
        match self {
            RuntimeError::UnknownAction(name) => format!("Unknown action '!{}'", name),
            RuntimeError::InvalidArgument(msg) => msg.clone(),
        }
    }
}

pub struct Context {
    pub vars: HashMap<String, Value>,
    pub events: Vec<RuntimeEvent>,
    pub errors: Vec<RuntimeError>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            events: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn set_var_ref(&mut self, var: &VarRef, value: Value) {
        // set base or nested object
        if var.path.is_empty() {
            self.vars.insert(var.base.clone(), value.clone());
        } else {
            let mut current = self
                .vars
                .remove(&var.base)
                .unwrap_or(Value::Object(HashMap::new()));
            set_nested(&mut current, &var.path, value.clone());
            self.vars.insert(var.base.clone(), current);
        }
        self.events
            .push(RuntimeEvent::SetVar(var.base.clone(), value));
    }

    pub fn get_var_ref(&self, var: &VarRef) -> Value {
        let mut current = match self.vars.get(&var.base) {
            Some(v) => v.clone(),
            None => return Value::Null,
        };
        for key in &var.path {
            match current {
                Value::Object(ref map) => {
                    current = map.get(key).cloned().unwrap_or(Value::Null);
                }
                _ => return Value::Null,
            }
        }
        current
    }

    pub fn set_var(&mut self, name: &str, value: Value) {
        self.vars.insert(name.to_string(), value.clone());
        self.events
            .push(RuntimeEvent::SetVar(name.to_string(), value));
    }

    pub fn get_var(&self, name: &str) -> Option<Value> {
        self.vars.get(name).cloned()
    }

    pub fn report_error(&mut self, err: RuntimeError) {
        self.errors.push(err);
    }
}

fn set_nested(root: &mut Value, path: &[String], value: Value) {
    if path.is_empty() {
        *root = value;
        return;
    }
    match root {
        Value::Object(map) => {
            let key = &path[0];
            if path.len() == 1 {
                map.insert(key.clone(), value);
            } else {
                let entry = map
                    .entry(key.clone())
                    .or_insert_with(|| Value::Object(HashMap::new()));
                set_nested(entry, &path[1..], value);
            }
        }
        _ => {
            // overwrite with object chain
            let mut obj = Value::Object(HashMap::new());
            set_nested(&mut obj, path, value);
            *root = obj;
        }
    }
}

pub trait Eval {
    fn eval(&self, ctx: &mut Context);
}

impl Expr {
    pub fn eval_value(&self, ctx: &mut Context) -> Value {
        match self {
            Expr::Literal { kind, value } => literal_to_value(kind, value),
            Expr::Var(v) => ctx.get_var_ref(v),
            Expr::Ident(name) => Value::String(name.clone()),
            Expr::Binary { op, left, right } => {
                let l = left.eval_value(ctx);
                let r = right.eval_value(ctx);
                match (l, op.as_str(), r) {
                    (Value::Number(a), "+", Value::Number(b)) => Value::Number(a + b),
                    (Value::String(a), "+", Value::String(b)) => Value::String(format!("{}{}", a, b)),
                    (Value::String(a), "+", b) => Value::String(format!("{}{}", a, b.to_string_lossy())),
                    (a @ Value::Number(_), "+", b) => Value::String(format!("{}{}", a.to_string_lossy(), b.to_string_lossy())),
                    (Value::Number(a), "-", Value::Number(b)) => Value::Number(a - b),
                    (Value::Number(a), "*", Value::Number(b)) => Value::Number(a * b),
                    (Value::Number(a), "/", Value::Number(b)) => Value::Number(a / b),
                    (Value::Number(a), ">", Value::Number(b)) => Value::Boolean(a > b),
                    (Value::Number(a), "<", Value::Number(b)) => Value::Boolean(a < b),
                    (Value::Number(a), ">=", Value::Number(b)) => Value::Boolean(a >= b),
                    (Value::Number(a), "<=", Value::Number(b)) => Value::Boolean(a <= b),
                    (Value::Number(a), "==", Value::Number(b)) => Value::Boolean((a - b).abs() < f64::EPSILON),
                    (Value::Boolean(a), "==", Value::Boolean(b)) => Value::Boolean(a == b),
                    (Value::String(a), "==", Value::String(b)) => Value::Boolean(a == b),
                    _ => Value::Null,
                }
            }
            Expr::Unary { op, expr } => {
                let v = expr.eval_value(ctx);
                match (op.as_str(), v) {
                    ("-", Value::Number(n)) => Value::Number(-n),
                    _ => Value::Null,
                }
            }
            Expr::List(items) => {
                let mut vals = Vec::with_capacity(items.len());
                for e in items {
                    vals.push(e.eval_value(ctx));
                }
                Value::List(vals)
            }
            Expr::Object(entries) => {
                let mut map = HashMap::new();
                for (k, v) in entries {
                    map.insert(k.clone(), v.eval_value(ctx));
                }
                Value::Object(map)
            }
            Expr::Action(act) => eval_action(act, ctx).unwrap_or(Value::Null),
        }
    }
}

impl Eval for Statement {
    fn eval(&self, ctx: &mut Context) {
        match self {
            Statement::Action(a) => {
                let _ = eval_action(a, ctx);
            }
            Statement::Assign(a) => {
                let val = a.expr.eval_value(ctx);
                ctx.set_var_ref(&a.target, val);
            }
            Statement::Loop(l) => {
                match l.mode.as_str() {
                    "count" => {
                        if let Some(times) = l.times {
                            for _ in 0..times {
                                for stmt in &l.body {
                                    stmt.eval(ctx);
                                }
                            }
                        }
                    }
                    "over" => {
                        if let Some(src) = &l.source {
                            if let Value::List(items) = ctx.get_var_ref(src) {
                                for item in items {
                                    ctx.set_var("item", item.clone());
                                    if src.base.ends_with('s') && src.base.len() > 1 {
                                        let singular = src.base.trim_end_matches('s');
                                        ctx.set_var(singular, item.clone());
                                    }
                                    for stmt in &l.body {
                                        stmt.eval(ctx);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Statement::If(i) => {
                if i.cond.eval_value(ctx).as_bool() {
                    for stmt in &i.then_body {
                        stmt.eval(ctx);
                    }
                } else if let Some(else_body) = &i.else_body {
                    for stmt in else_body {
                        stmt.eval(ctx);
                    }
                }
            }
        }
    }
}

pub fn run_program(program: &Program, entry: Option<&str>, ctx: &mut Context) {
    if program.is_empty() {
        return;
    }
    let target = entry.unwrap_or(&program[0].name);
    if let Some(ritual) = program.iter().find(|r| r.name == target) {
        eval_ritual(ritual, ctx);
    } else {
        eval_ritual(&program[0], ctx);
    }
}

fn eval_ritual(ritual: &Ritual, ctx: &mut Context) {
    for stmt in &ritual.body {
        stmt.eval(ctx);
    }
}

fn eval_action(action: &Action, ctx: &mut Context) -> Option<Value> {
    let name = action.name.as_str();
    let (pos_args, named_args, flags) = collect_args(&action.args, ctx);

    match name {
        "say" => {
            if let Some(text) = first_arg_as_string(&action.args, ctx) {
                ctx.events.push(RuntimeEvent::Say(text.clone()));
            } else {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!say expects a message argument".to_string(),
                ));
            }
            None
        }
        "ui" => {
            if let Some(kind) = first_arg_as_string(&action.args, ctx) {
                ctx.events.push(RuntimeEvent::UiStart(kind));
            } else {
                ctx.events.push(RuntimeEvent::UiStart("ui".into()));
            }
            None
        }
        "ui_end" => {
            ctx.events.push(RuntimeEvent::UiEnd);
            None
        }
        "text" => {
            if let Some(text) = first_arg_as_string(&action.args, ctx) {
                ctx.events.push(RuntimeEvent::UiText(text));
            } else {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!text expects content".to_string(),
                ));
            }
            None
        }
        "button" => {
            if let Some(text) = first_arg_as_string(&action.args, ctx) {
                ctx.events.push(RuntimeEvent::UiButton(text));
            } else {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!button expects label".to_string(),
                ));
            }
            None
        }
        "ask" => {
            if let Some(question) = first_arg_as_string(&action.args, ctx) {
                ctx.events.push(RuntimeEvent::OracleRequest(question));
            } else {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!ask expects a prompt string".to_string(),
                ));
            }
            None
        }
        "fetch" => {
            // mock fetch returns empty list
            Some(Value::List(vec![]))
        }
        "sort" => {
            if let Some(list) = pos_args.get(0) {
                let algo = named_args
                    .get("algorithm")
                    .or_else(|| named_args.get("algo"))
                    .and_then(|v| match v {
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .or_else(|| flags.get(0).cloned())
                    .unwrap_or_else(|| "quick".to_string());
                match sort_value_list(list, &algo) {
                    Ok(sorted) => Some(Value::List(sorted)),
                    Err(e) => {
                        ctx.report_error(RuntimeError::InvalidArgument(e));
                        None
                    }
                }
            } else {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!sort expects a list".into(),
                ));
                None
            }
        }
        "search" => {
            if pos_args.len() < 2 {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!search expects list and target".into(),
                ));
                return None;
            }
            let algo = named_args
                .get("algorithm")
                .or_else(|| named_args.get("algo"))
                .and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .or_else(|| flags.get(0).cloned())
                .unwrap_or_else(|| "linear".to_string());
            match search_value(&pos_args[0], &pos_args[1], &algo) {
                Ok(idx) => Some(idx),
                Err(e) => {
                    ctx.report_error(RuntimeError::InvalidArgument(e));
                    None
                }
            }
        }
        "gcd" => {
            if pos_args.len() < 2 {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!gcd expects two numbers".into(),
                ));
                return None;
            }
            match (pos_args[0].as_f64(), pos_args[1].as_f64()) {
                (Some(a), Some(b)) => Some(Value::Number(gcd(a as i64, b as i64) as f64)),
                _ => {
                    ctx.report_error(RuntimeError::InvalidArgument(
                        "!gcd arguments must be numbers".into(),
                    ));
                    None
                }
            }
        }
        "fib" | "fibonacci" => {
            if let Some(Some(n)) = pos_args.get(0).map(|v| v.as_f64()) {
                let n_int = if n < 0.0 { 0 } else { n as usize };
                Some(Value::Number(fib(n_int) as f64))
            } else {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!fib expects a non-negative number".into(),
                ));
                None
            }
        }
        "sieve" => {
            if let Some(Some(n)) = pos_args.get(0).map(|v| v.as_f64()) {
                let n_int = if n < 0.0 { 0 } else { n as usize };
                let primes: Vec<Value> = sieve(n_int).into_iter().map(|p| Value::Number(p as f64)).collect();
                Some(Value::List(primes))
            } else {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!sieve expects a non-negative number".into(),
                ));
                None
            }
        }
        "lcs" => {
            if pos_args.len() < 2 {
                ctx.report_error(RuntimeError::InvalidArgument(
                    "!lcs expects two strings".into(),
                ));
                return None;
            }
            match (value_as_string(&pos_args[0]), value_as_string(&pos_args[1])) {
                (Some(a), Some(b)) => Some(Value::String(longest_common_subsequence(&a, &b))),
                _ => {
                    ctx.report_error(RuntimeError::InvalidArgument(
                        "!lcs arguments must be strings".into(),
                    ));
                    None
                }
            }
        }
        "dfs" | "bfs" | "dijkstra" | "bellman" | "bellman_ford" | "floyd" | "floyd_warshall"
        | "topo" | "topo_sort" | "scc" | "tarjan" | "kruskal" | "prim" | "components" => {
            match handle_graph_action(name, &pos_args, &named_args, &flags, ctx) {
                Ok(v) => v,
                Err(e) => {
                    ctx.report_error(RuntimeError::InvalidArgument(e));
                    None
                }
            }
        }
        _ => {
            ctx.report_error(RuntimeError::UnknownAction(name.to_string()));
            None
        }
    }
}

fn first_arg_as_string(args: &[Arg], ctx: &mut Context) -> Option<String> {
    for arg in args {
        match arg {
            Arg::Value { value } => {
                let v = value.eval_value(ctx);
                return Some(v.to_string_lossy());
            }
            Arg::Named { value, .. } => {
                let v = value.eval_value(ctx);
                return Some(v.to_string_lossy());
            }
            Arg::Flag { name } => return Some(name.clone()),
        }
    }
    None
}

fn collect_args(args: &[Arg], ctx: &mut Context) -> (Vec<Value>, HashMap<String, Value>, Vec<String>) {
    let mut positional = Vec::new();
    let mut named = HashMap::new();
    let mut flags = Vec::new();
    for arg in args {
        match arg {
            Arg::Value { value } => positional.push(value.eval_value(ctx)),
            Arg::Named { name, value } => {
                named.insert(name.clone(), value.eval_value(ctx));
            }
            Arg::Flag { name } => flags.push(name.clone()),
        }
    }
    (positional, named, flags)
}

fn value_as_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

fn value_list_as_numbers(list: &Value) -> Result<Vec<f64>, String> {
    if let Value::List(items) = list {
        let mut out = Vec::new();
        for v in items {
            if let Some(n) = v.as_f64() {
                out.push(n);
            } else {
                return Err("List must contain only numbers".into());
            }
        }
        Ok(out)
    } else {
        Err("Expected a list".into())
    }
}

fn value_as_bool(v: &Value) -> Option<bool> {
    v.as_bool_value()
}

fn sort_value_list(list: &Value, algo: &str) -> Result<Vec<Value>, String> {
    let mut nums = value_list_as_numbers(list)?;
    match algo {
        "bubble" => bubble_sort(&mut nums),
        "selection" => selection_sort(&mut nums),
        "insertion" => insertion_sort(&mut nums),
        "merge" | "mergesort" => merge_sort(&mut nums),
        "heap" | "heapsort" => heap_sort(&mut nums),
        "counting" | "countingsort" => counting_sort(&mut nums)?,
        "quick" | "quicksort" | _ => quick_sort(&mut nums),
    }
    Ok(nums.into_iter().map(Value::Number).collect())
}

fn search_value(haystack: &Value, target: &Value, algo: &str) -> Result<Value, String> {
    match algo {
        "binary" | "bin" => binary_search_value(haystack, target).map(|i| Value::Number(i as f64)),
        _ => linear_search_value(haystack, target).map(|i| Value::Number(i as f64)),
    }
}

fn linear_search_value(haystack: &Value, target: &Value) -> Result<usize, String> {
    if let Value::List(items) = haystack {
        for (i, v) in items.iter().enumerate() {
            if values_equal(v, target) {
                return Ok(i);
            }
        }
        Ok(usize::MAX) // not found
    } else {
        Err("!search expects list as first arg".into())
    }
}

fn binary_search_value(haystack: &Value, target: &Value) -> Result<usize, String> {
    let nums = value_list_as_numbers(haystack)?;
    let t = target
        .as_f64()
        .ok_or_else(|| "!search binary expects numeric target".to_string())?;
    let mut lo: isize = 0;
    let mut hi: isize = nums.len() as isize - 1;
    while lo <= hi {
        let mid = (lo + hi) / 2;
        let val = nums[mid as usize];
        if (val - t).abs() < f64::EPSILON {
            return Ok(mid as usize);
        } else if val < t {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    Ok(usize::MAX)
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => (x - y).abs() < f64::EPSILON,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Boolean(x), Value::Boolean(y)) => x == y,
        _ => false,
    }
}

fn bubble_sort(arr: &mut [f64]) {
    let n = arr.len();
    for i in 0..n {
        for j in 0..(n - i - 1) {
            if arr[j] > arr[j + 1] {
                arr.swap(j, j + 1);
            }
        }
    }
}

fn selection_sort(arr: &mut [f64]) {
    let n = arr.len();
    for i in 0..n {
        let mut min_idx = i;
        for j in (i + 1)..n {
            if arr[j] < arr[min_idx] {
                min_idx = j;
            }
        }
        arr.swap(i, min_idx);
    }
}

fn insertion_sort(arr: &mut [f64]) {
    let n = arr.len();
    for i in 1..n {
        let key = arr[i];
        let mut j = i as isize - 1;
        while j >= 0 && arr[j as usize] > key {
            arr[(j + 1) as usize] = arr[j as usize];
            j -= 1;
        }
        arr[(j + 1) as usize] = key;
    }
}

fn merge_sort(arr: &mut [f64]) {
    let n = arr.len();
    if n <= 1 {
        return;
    }
    let mid = n / 2;
    merge_sort(&mut arr[..mid]);
    merge_sort(&mut arr[mid..]);
    let mut merged = arr.to_vec();
    merge(&arr[..mid], &arr[mid..], &mut merged[..]);
    arr.copy_from_slice(&merged);
}

fn merge(left: &[f64], right: &[f64], out: &mut [f64]) {
    let mut i = 0;
    let mut j = 0;
    let mut k = 0;
    while i < left.len() && j < right.len() {
        if left[i] <= right[j] {
            out[k] = left[i];
            i += 1;
        } else {
            out[k] = right[j];
            j += 1;
        }
        k += 1;
    }
    while i < left.len() {
        out[k] = left[i];
        i += 1;
        k += 1;
    }
    while j < right.len() {
        out[k] = right[j];
        j += 1;
        k += 1;
    }
}

fn quick_sort(arr: &mut [f64]) {
    if arr.len() <= 1 {
        return;
    }
    let pivot = arr[arr.len() / 2];
    let (mut left, mut right) = (0usize, arr.len() - 1);
    while left <= right {
        while arr[left] < pivot {
            left += 1;
        }
        while arr[right] > pivot {
            if right == 0 {
                break;
            }
            right -= 1;
        }
        if left <= right {
            arr.swap(left, right);
            left += 1;
            if right == 0 {
                break;
            }
            right -= 1;
        }
    }
    let (l, r) = arr.split_at_mut(left);
    if right < l.len() {
        quick_sort(&mut l[..=right]);
    }
    quick_sort(r);
}

fn heap_sort(arr: &mut [f64]) {
    let n = arr.len();
    for i in (0..n / 2).rev() {
        heapify(arr, n, i);
    }
    for i in (1..n).rev() {
        arr.swap(0, i);
        heapify(arr, i, 0);
    }
}

fn heapify(arr: &mut [f64], n: usize, i: usize) {
    let mut largest = i;
    let l = 2 * i + 1;
    let r = 2 * i + 2;
    if l < n && arr[l] > arr[largest] {
        largest = l;
    }
    if r < n && arr[r] > arr[largest] {
        largest = r;
    }
    if largest != i {
        arr.swap(i, largest);
        heapify(arr, n, largest);
    }
}

fn counting_sort(arr: &mut [f64]) -> Result<(), String> {
    let ints: Vec<i64> = arr
        .iter()
        .map(|n| {
            if n.fract() == 0.0 {
                Ok(*n as i64)
            } else {
                Err(())
            }
        })
        .collect::<Result<_, _>>()
        .map_err(|_| "Counting sort requires integer values")?;
    if ints.is_empty() {
        return Ok(());
    }
    let min = *ints.iter().min().unwrap();
    let max = *ints.iter().max().unwrap();
    let range = (max - min + 1) as usize;
    if range > 100_000 {
        return Err("Counting sort range too large".into());
    }
    let mut count = vec![0usize; range];
    for &v in &ints {
        count[(v - min) as usize] += 1;
    }
    let mut idx = 0;
    for (i, &c) in count.iter().enumerate() {
        for _ in 0..c {
            arr[idx] = (i as i64 + min) as f64;
            idx += 1;
        }
    }
    Ok(())
}

fn gcd(mut a: i64, mut b: i64) -> i64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.abs()
}

fn fib(n: usize) -> u64 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }
    let mut a = 0u64;
    let mut b = 1u64;
    for _ in 2..=n {
        let c = a + b;
        a = b;
        b = c;
    }
    b
}

fn sieve(n: usize) -> Vec<usize> {
    if n < 2 {
        return vec![];
    }
    let mut is_prime = vec![true; n + 1];
    is_prime[0] = false;
    is_prime[1] = false;
    let mut p = 2;
    while p * p <= n {
        if is_prime[p] {
            let mut i = p * p;
            while i <= n {
                is_prime[i] = false;
                i += p;
            }
        }
        p += 1;
    }
    is_prime
        .iter()
        .enumerate()
        .filter_map(|(i, &prime)| if prime { Some(i) } else { None })
        .collect()
}

fn longest_common_subsequence(a: &str, b: &str) -> String {
    let bytes_a: Vec<char> = a.chars().collect();
    let bytes_b: Vec<char> = b.chars().collect();
    let m = bytes_a.len();
    let n = bytes_b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if bytes_a[i - 1] == bytes_b[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }
    // reconstruct
    let mut i = m;
    let mut j = n;
    let mut res = Vec::new();
    while i > 0 && j > 0 {
        if bytes_a[i - 1] == bytes_b[j - 1] {
            res.push(bytes_a[i - 1]);
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    res.reverse();
    res.into_iter().collect()
}

#[derive(Clone)]
struct Edge {
    u: String,
    v: String,
    w: f64,
}

fn parse_edges(val: &Value) -> Result<Vec<Edge>, String> {
    let mut edges = Vec::new();
    match val {
        Value::List(list) => {
            for item in list {
                match item {
                    Value::Object(map) => {
                        let u = map
                            .get("u")
                            .and_then(value_as_string)
                            .ok_or_else(|| "Edge missing 'u'".to_string())?;
                        let v = map
                            .get("v")
                            .and_then(value_as_string)
                            .ok_or_else(|| "Edge missing 'v'".to_string())?;
                        let w = map.get("w").and_then(|x| x.as_f64()).unwrap_or(1.0);
                        edges.push(Edge { u, v, w });
                    }
                    Value::List(items) => {
                        if items.len() < 2 {
                            return Err("Edge list needs at least [u,v]".into());
                        }
                        let u = value_as_string(&items[0])
                            .ok_or_else(|| "Edge u must be string/number".to_string())?;
                        let v = value_as_string(&items[1])
                            .ok_or_else(|| "Edge v must be string/number".to_string())?;
                        let w = items.get(2).and_then(|x| x.as_f64()).unwrap_or(1.0);
                        edges.push(Edge { u, v, w });
                    }
                    _ => return Err("Edge must be object or list".into()),
                }
            }
        }
        _ => return Err("Graph edges must be a list".into()),
    }
    Ok(edges)
}

fn nodes_from_edges(edges: &[Edge]) -> Vec<String> {
    let mut set = HashSet::new();
    for e in edges {
        set.insert(e.u.clone());
        set.insert(e.v.clone());
    }
    set.into_iter().collect()
}

fn build_adj(edges: &[Edge], directed: bool) -> HashMap<String, Vec<(String, f64)>> {
    let mut adj: HashMap<String, Vec<(String, f64)>> = HashMap::new();
    for e in edges {
        adj.entry(e.u.clone())
            .or_default()
            .push((e.v.clone(), e.w));
        if !directed {
            adj.entry(e.v.clone())
                .or_default()
                .push((e.u.clone(), e.w));
        }
    }
    adj
}

fn handle_graph_action(
    name: &str,
    pos_args: &[Value],
    named_args: &HashMap<String, Value>,
    flags: &[String],
    ctx: &mut Context,
) -> Result<Option<Value>, String> {
    if pos_args.is_empty() {
        return Err("Graph action expects at least edges list".into());
    }
    let edges = parse_edges(&pos_args[0])?;
    let directed = named_args
        .get("directed")
        .and_then(value_as_bool)
        .unwrap_or(false);

    match name {
        "dfs" => {
            let start = pos_args
                .get(1)
                .and_then(value_as_string)
                .or_else(|| named_args.get("start").and_then(value_as_string))
                .ok_or_else(|| "!dfs needs start node".to_string())?;
            let order = dfs(&edges, &start, directed);
            Ok(Some(Value::List(
                order.into_iter().map(Value::String).collect(),
            )))
        }
        "bfs" => {
            let start = pos_args
                .get(1)
                .and_then(value_as_string)
                .or_else(|| named_args.get("start").and_then(value_as_string))
                .ok_or_else(|| "!bfs needs start node".to_string())?;
            let order = bfs(&edges, &start, directed);
            Ok(Some(Value::List(
                order.into_iter().map(Value::String).collect(),
            )))
        }
        "dijkstra" => {
            let start = pos_args
                .get(1)
                .and_then(value_as_string)
                .or_else(|| named_args.get("start").and_then(value_as_string))
                .ok_or_else(|| "!dijkstra needs start node".to_string())?;
            let dist = dijkstra(&edges, &start, directed);
            Ok(Some(map_to_object(dist)))
        }
        "bellman" | "bellman_ford" => {
            let start = pos_args
                .get(1)
                .and_then(value_as_string)
                .or_else(|| named_args.get("start").and_then(value_as_string))
                .ok_or_else(|| "!bellman needs start node".to_string())?;
            let res = bellman_ford(&edges, &start, directed)
                .ok_or_else(|| "Negative cycle detected".to_string())?;
            Ok(Some(map_to_object(res)))
        }
        "floyd" | "floyd_warshall" => {
            let dist = floyd_warshall(&edges, directed);
            Ok(Some(nested_map_to_object(dist)))
        }
        "topo" | "topo_sort" => {
            let order = topo_sort(&edges)?;
            Ok(Some(Value::List(
                order.into_iter().map(Value::String).collect(),
            )))
        }
        "scc" | "tarjan" => {
            let comps = tarjan_scc(&edges);
            let list = comps
                .into_iter()
                .map(|comp| Value::List(comp.into_iter().map(Value::String).collect()))
                .collect();
            Ok(Some(Value::List(list)))
        }
        "kruskal" => {
            let mst = kruskal(&edges);
            Ok(Some(edges_to_value(mst)))
        }
        "prim" => {
            let start = pos_args
                .get(1)
                .and_then(value_as_string)
                .or_else(|| named_args.get("start").and_then(value_as_string));
            let mst = prim(&edges, start)?;
            Ok(Some(edges_to_value(mst)))
        }
        "components" => {
            let comps = connected_components(&edges);
            let list = comps
                .into_iter()
                .map(|comp| Value::List(comp.into_iter().map(Value::String).collect()))
                .collect();
            Ok(Some(Value::List(list)))
        }
        _ => Err("Unknown graph action".into()),
    }
}

fn dfs(edges: &[Edge], start: &str, directed: bool) -> Vec<String> {
    let adj = build_adj(edges, directed);
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    fn rec(
        u: &str,
        adj: &HashMap<String, Vec<(String, f64)>>,
        visited: &mut HashSet<String>,
        order: &mut Vec<String>,
    ) {
        if !visited.insert(u.to_string()) {
            return;
        }
        order.push(u.to_string());
        if let Some(nei) = adj.get(u) {
            for (v, _) in nei {
                rec(v, adj, visited, order);
            }
        }
    }
    rec(start, &adj, &mut visited, &mut order);
    order
}

fn bfs(edges: &[Edge], start: &str, directed: bool) -> Vec<String> {
    let adj = build_adj(edges, directed);
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    let mut q = VecDeque::new();
    visited.insert(start.to_string());
    q.push_back(start.to_string());
    while let Some(u) = q.pop_front() {
        order.push(u.clone());
        if let Some(nei) = adj.get(&u) {
            for (v, _) in nei {
                if visited.insert(v.clone()) {
                    q.push_back(v.clone());
                }
            }
        }
    }
    order
}

fn dijkstra(
    edges: &[Edge],
    start: &str,
    directed: bool,
) -> HashMap<String, f64> {
    use std::cmp::Ordering;
    use std::collections::BinaryHeap;
    let adj = build_adj(edges, directed);
    let mut dist: HashMap<String, f64> = HashMap::new();
    for n in nodes_from_edges(edges) {
        dist.insert(n, f64::INFINITY);
    }
    dist.insert(start.to_string(), 0.0);
    #[derive(Clone)]
    struct State {
        cost: f64,
        node: String,
    }
    impl Eq for State {}
    impl PartialEq for State {
        fn eq(&self, other: &Self) -> bool {
            self.cost == other.cost
        }
    }
    impl Ord for State {
        fn cmp(&self, other: &Self) -> Ordering {
            other.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
        }
    }
    impl PartialOrd for State {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }
    let mut heap = BinaryHeap::new();
    heap.push(State {
        cost: 0.0,
        node: start.to_string(),
    });
    while let Some(State { cost, node }) = heap.pop() {
        if cost > *dist.get(&node).unwrap_or(&f64::INFINITY) {
            continue;
        }
        if let Some(nei) = adj.get(&node) {
            for (v, w) in nei {
                let next = cost + *w;
                if next < *dist.get(v).unwrap_or(&f64::INFINITY) {
                    dist.insert(v.clone(), next);
                    heap.push(State {
                        cost: next,
                        node: v.clone(),
                    });
                }
            }
        }
    }
    dist
}

fn bellman_ford(edges: &[Edge], start: &str, directed: bool) -> Option<HashMap<String, f64>> {
    let mut nodes = nodes_from_edges(edges);
    if !nodes.contains(&start.to_string()) {
        nodes.push(start.to_string());
    }
    let mut dist: HashMap<String, f64> = nodes.iter().map(|n| (n.clone(), f64::INFINITY)).collect();
    dist.insert(start.to_string(), 0.0);
    for _ in 0..nodes.len() - 1 {
        let mut updated = false;
        for e in edges {
            if let Some(&du) = dist.get(&e.u) {
                if du + e.w < *dist.get(&e.v).unwrap_or(&f64::INFINITY) {
                    dist.insert(e.v.clone(), du + e.w);
                    updated = true;
                }
            }
            if !directed {
                if let Some(&dv) = dist.get(&e.v) {
                    if dv + e.w < *dist.get(&e.u).unwrap_or(&f64::INFINITY) {
                        dist.insert(e.u.clone(), dv + e.w);
                        updated = true;
                    }
                }
            }
        }
        if !updated {
            break;
        }
    }
    for e in edges {
        if let Some(&du) = dist.get(&e.u) {
            if du + e.w < *dist.get(&e.v).unwrap_or(&f64::INFINITY) {
                return None; // negative cycle
            }
        }
    }
    Some(dist)
}

fn floyd_warshall(edges: &[Edge], directed: bool) -> HashMap<String, HashMap<String, f64>> {
    let nodes = nodes_from_edges(edges);
    let mut dist: HashMap<(String, String), f64> = HashMap::new();
    for u in &nodes {
        for v in &nodes {
            let d = if u == v { 0.0 } else { f64::INFINITY };
            dist.insert((u.clone(), v.clone()), d);
        }
    }
    for e in edges {
        dist.insert((e.u.clone(), e.v.clone()), e.w.min(*dist.get(&(e.u.clone(), e.v.clone())).unwrap_or(&f64::INFINITY)));
        if !directed {
            dist.insert((e.v.clone(), e.u.clone()), e.w.min(*dist.get(&(e.v.clone(), e.u.clone())).unwrap_or(&f64::INFINITY)));
        }
    }
    for k in &nodes {
        for i in &nodes {
            for j in &nodes {
                let ik = *dist.get(&(i.clone(), k.clone())).unwrap_or(&f64::INFINITY);
                let kj = *dist.get(&(k.clone(), j.clone())).unwrap_or(&f64::INFINITY);
                let ij = dist.get_mut(&(i.clone(), j.clone())).unwrap();
                if ik + kj < *ij {
                    *ij = ik + kj;
                }
            }
        }
    }
    let mut out: HashMap<String, HashMap<String, f64>> = HashMap::new();
    for i in &nodes {
        let mut inner = HashMap::new();
        for j in &nodes {
            if let Some(d) = dist.get(&(i.clone(), j.clone())) {
                inner.insert(j.clone(), *d);
            }
        }
        out.insert(i.clone(), inner);
    }
    out
}

fn topo_sort(edges: &[Edge]) -> Result<Vec<String>, String> {
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    let mut indeg: HashMap<String, usize> = HashMap::new();
    for e in edges {
        adj.entry(e.u.clone()).or_default().push(e.v.clone());
        indeg.entry(e.v.clone()).and_modify(|x| *x += 1).or_insert(1);
        indeg.entry(e.u.clone()).or_insert(0);
    }
    let mut q: VecDeque<String> = indeg
        .iter()
        .filter(|(_, &d)| d == 0)
        .map(|(k, _)| k.clone())
        .collect();
    let mut order = Vec::new();
    while let Some(u) = q.pop_front() {
        order.push(u.clone());
        if let Some(nei) = adj.get(&u) {
            for v in nei {
                if let Some(d) = indeg.get_mut(v) {
                    *d -= 1;
                    if *d == 0 {
                        q.push_back(v.clone());
                    }
                }
            }
        }
    }
    if order.len() != indeg.len() {
        return Err("Graph has cycle; topo sort failed".into());
    }
    Ok(order)
}

fn tarjan_scc(edges: &[Edge]) -> Vec<Vec<String>> {
    let directed = true;
    let adj = build_adj(edges, directed);
    let mut index = 0;
    let mut indices: HashMap<String, usize> = HashMap::new();
    let mut lowlink: HashMap<String, usize> = HashMap::new();
    let mut stack: Vec<String> = Vec::new();
    let mut on_stack: HashSet<String> = HashSet::new();
    let mut comps: Vec<Vec<String>> = Vec::new();

    fn strong_connect(
        v: &str,
        index: &mut usize,
        indices: &mut HashMap<String, usize>,
        lowlink: &mut HashMap<String, usize>,
        stack: &mut Vec<String>,
        on_stack: &mut HashSet<String>,
        adj: &HashMap<String, Vec<(String, f64)>>,
        comps: &mut Vec<Vec<String>>,
    ) {
        indices.insert(v.to_string(), *index);
        lowlink.insert(v.to_string(), *index);
        *index += 1;
        stack.push(v.to_string());
        on_stack.insert(v.to_string());

        if let Some(nei) = adj.get(v) {
            for (w, _) in nei {
                if !indices.contains_key(w) {
                    strong_connect(
                        w,
                        index,
                        indices,
                        lowlink,
                        stack,
                        on_stack,
                        adj,
                        comps,
                    );
                    let lw = *lowlink.get(w).unwrap();
                    let lv = lowlink.get_mut(v).unwrap();
                    if lw < *lv {
                        *lv = lw;
                    }
                } else if on_stack.contains(w) {
                    let iw = *indices.get(w).unwrap();
                    let lv = lowlink.get_mut(v).unwrap();
                    if iw < *lv {
                        *lv = iw;
                    }
                }
            }
        }

        if lowlink.get(v) == indices.get(v) {
            let mut comp = Vec::new();
            while let Some(w) = stack.pop() {
                on_stack.remove(&w);
                comp.push(w.clone());
                if w == v {
                    break;
                }
            }
            comps.push(comp);
        }
    }

    for node in adj.keys() {
        if !indices.contains_key(node) {
            strong_connect(
                node,
                &mut index,
                &mut indices,
                &mut lowlink,
                &mut stack,
                &mut on_stack,
                &adj,
                &mut comps,
            );
        }
    }
    comps
}

fn kruskal(edges: &[Edge]) -> Vec<Edge> {
    let mut edges = edges.to_vec();
    edges.sort_by(|a, b| a.w.partial_cmp(&b.w).unwrap());
    let mut parent: HashMap<String, String> = HashMap::new();
    let mut rank: HashMap<String, usize> = HashMap::new();
    for n in nodes_from_edges(&edges) {
        parent.insert(n.clone(), n.clone());
        rank.insert(n, 0);
    }
    fn find(x: &str, parent: &mut HashMap<String, String>) -> String {
        let p = parent.get(x).cloned().unwrap();
        if &p == x {
            p
        } else {
            let root = find(&p, parent);
            parent.insert(x.to_string(), root.clone());
            root
        }
    }
    fn union(a: &str, b: &str, parent: &mut HashMap<String, String>, rank: &mut HashMap<String, usize>) {
        let mut ra = find(a, parent);
        let mut rb = find(b, parent);
        if ra == rb {
            return;
        }
        let rka = *rank.get(&ra).unwrap_or(&0);
        let rkb = *rank.get(&rb).unwrap_or(&0);
        if rka < rkb {
            std::mem::swap(&mut ra, &mut rb);
        }
        parent.insert(rb.clone(), ra.clone());
        if rka == rkb {
            rank.entry(ra).and_modify(|r| *r += 1);
        }
    }
    let mut mst = Vec::new();
    for e in edges {
        let uroot = find(&e.u, &mut parent);
        let vroot = find(&e.v, &mut parent);
        if uroot != vroot {
            union(&uroot, &vroot, &mut parent, &mut rank);
            mst.push(e);
        }
    }
    mst
}

fn prim(edges: &[Edge], start: Option<String>) -> Result<Vec<Edge>, String> {
    use std::cmp::Ordering;
    use std::collections::BinaryHeap;
    let nodes = nodes_from_edges(edges);
    if nodes.is_empty() {
        return Ok(vec![]);
    }
    let start_node = start.unwrap_or_else(|| nodes[0].clone());
    let adj = build_adj(edges, false);
    #[derive(Clone)]
    struct Item {
        w: f64,
        u: String,
        v: String,
    }
    impl Eq for Item {}
    impl PartialEq for Item {
        fn eq(&self, other: &Self) -> bool {
            self.w == other.w
        }
    }
    impl Ord for Item {
        fn cmp(&self, other: &Self) -> Ordering {
            other.w.partial_cmp(&self.w).unwrap_or(Ordering::Equal)
        }
    }
    impl PartialOrd for Item {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }
    let mut visited = HashSet::new();
    let mut heap = BinaryHeap::new();
    let mut mst = Vec::new();
    visited.insert(start_node.clone());
    if let Some(nei) = adj.get(&start_node) {
        for (v, w) in nei {
            heap.push(Item {
                w: *w,
                u: start_node.clone(),
                v: v.clone(),
            });
        }
    }
    while let Some(Item { w, u, v }) = heap.pop() {
        if visited.contains(&v) {
            continue;
        }
        visited.insert(v.clone());
        mst.push(Edge { u: u.clone(), v: v.clone(), w });
        if let Some(nei) = adj.get(&v) {
            for (next, nw) in nei {
                if !visited.contains(next) {
                    heap.push(Item {
                        w: *nw,
                        u: v.clone(),
                        v: next.clone(),
                    });
                }
            }
        }
    }
    Ok(mst)
}

fn connected_components(edges: &[Edge]) -> Vec<Vec<String>> {
    let adj = build_adj(edges, false);
    let mut visited = HashSet::new();
    let mut comps = Vec::new();
    for node in adj.keys() {
        if visited.contains(node) {
            continue;
        }
        let mut comp = Vec::new();
        let mut stack = vec![node.clone()];
        visited.insert(node.clone());
        while let Some(u) = stack.pop() {
            comp.push(u.clone());
            if let Some(nei) = adj.get(&u) {
                for (v, _) in nei {
                    if visited.insert(v.clone()) {
                        stack.push(v.clone());
                    }
                }
            }
        }
        comps.push(comp);
    }
    comps
}

fn map_to_object(map: HashMap<String, f64>) -> Value {
    let mut obj = HashMap::new();
    for (k, v) in map {
        obj.insert(k, Value::Number(v));
    }
    Value::Object(obj)
}

fn nested_map_to_object(map: HashMap<String, HashMap<String, f64>>) -> Value {
    let mut outer = HashMap::new();
    for (k, inner) in map {
        let mut inner_obj = HashMap::new();
        for (ik, iv) in inner {
            inner_obj.insert(ik, Value::Number(iv));
        }
        outer.insert(k, Value::Object(inner_obj));
    }
    Value::Object(outer)
}

fn edges_to_value(edges: Vec<Edge>) -> Value {
    let list = edges
        .into_iter()
        .map(|e| {
            let mut obj = HashMap::new();
            obj.insert("u".into(), Value::String(e.u));
            obj.insert("v".into(), Value::String(e.v));
            obj.insert("w".into(), Value::Number(e.w));
            Value::Object(obj)
        })
        .collect();
    Value::List(list)
}

fn literal_to_value(kind: &str, value: &serde_json::Value) -> Value {
    match kind {
        "number" => {
            if let Some(n) = value.as_f64() {
                Value::Number(n)
            } else {
                Value::Null
            }
        }
        "boolean" => Value::Boolean(value.as_bool().unwrap_or(false)),
        "string" => Value::String(value.as_str().unwrap_or("").to_string()),
        "color" => Value::String(value.as_str().unwrap_or("").to_string()),
        _ => Value::Null,
    }
}
