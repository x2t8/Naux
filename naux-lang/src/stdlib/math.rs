// TODO: math helpers
#![allow(dead_code)]

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::Value;

pub fn register_math(env: &mut Env) {
    env.set_builtin("gcd", gcd);
    env.set_builtin("lcm", lcm);
    env.set_builtin("pow_mod", pow_mod);
    env.set_builtin("is_prime", is_prime);
    env.set_builtin("sieve", sieve);
}

fn to_i64(v: &Value) -> Result<i64, RuntimeError> {
    match v {
        Value::Number(n) => Ok(*n as i64),
        _ => Err(RuntimeError::new("expected number", None)),
    }
}

fn gcd(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("gcd(a,b)", None));
    }
    let mut a = to_i64(&args[0])?.abs();
    let mut b = to_i64(&args[1])?.abs();
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    Ok(Value::Number(a as f64))
}

fn lcm(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("lcm(a,b)", None));
    }
    let a = to_i64(&args[0])?;
    let b = to_i64(&args[1])?;
    if a == 0 || b == 0 {
        return Ok(Value::Number(0.0));
    }
    let g = gcd(vec![Value::Number(a as f64), Value::Number(b as f64)])?;
    if let Value::Number(gv) = g {
        Ok(Value::Number(((a / gv as i64) * b).abs() as f64))
    } else {
        Ok(Value::Number(0.0))
    }
}

fn pow_mod(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("pow_mod(base, exp, mod)", None));
    }
    let mut base = to_i64(&args[0])?;
    let mut exp = to_i64(&args[1])?;
    let m = to_i64(&args[2])?;
    if m == 0 {
        return Err(RuntimeError::new("mod must be non-zero", None));
    }
    base %= m;
    let mut res: i64 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            res = (res * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1;
    }
    Ok(Value::Number(res as f64))
}

fn is_prime(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("is_prime(n)", None));
    }
    let n = to_i64(&args[0])?;
    if n < 2 {
        return Ok(Value::Bool(false));
    }
    if n == 2 || n == 3 {
        return Ok(Value::Bool(true));
    }
    if n % 2 == 0 {
        return Ok(Value::Bool(false));
    }
    let mut i = 3;
    while i * i <= n {
        if n % i == 0 {
            return Ok(Value::Bool(false));
        }
        i += 2;
    }
    Ok(Value::Bool(true))
}

fn sieve(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("sieve(n)", None));
    }
    let n = to_i64(&args[0])?;
    if n < 2 {
        return Ok(Value::List(vec![]));
    }
    let mut is_prime = vec![true; (n + 1) as usize];
    is_prime[0] = false;
    is_prime[1] = false;
    let mut p = 2;
    while (p * p) as usize <= n as usize {
        if is_prime[p as usize] {
            let mut k = p * p;
            while k <= n {
                is_prime[k as usize] = false;
                k += p;
            }
        }
        p += 1;
    }
    let mut primes = Vec::new();
    for i in 2..=n {
        if is_prime[i as usize] {
            primes.push(Value::Number(i as f64));
        }
    }
    Ok(Value::List(primes))
}
