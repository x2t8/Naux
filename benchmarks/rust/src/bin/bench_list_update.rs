use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn parse_arg(args: &[String], idx: usize, default: usize) -> usize {
    args.get(idx)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let n = parse_arg(&args, 1, 100_000);
    let iters = parse_arg(&args, 2, 200);
    let warmup_ms = parse_arg(&args, 3, 100);
    let reps = parse_arg(&args, 4, 50);

    let mut arr = vec![0.0_f64; n];

    let warmup_end = Instant::now() + Duration::from_millis(warmup_ms as u64);
    while Instant::now() < warmup_end {
        let mut s = 0.0_f64;
        for (i, item) in arr.iter_mut().enumerate() {
            *item = i as f64;
        }
        for _ in 0..reps {
            for item in &mut arr {
                let v = *item;
                s += v;
                *item = v + 1.0;
            }
        }
        black_box(s);
    }

    let mut samples: Vec<u64> = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let mut s = 0.0_f64;
        for (i, item) in arr.iter_mut().enumerate() {
            *item = i as f64;
        }
        for _ in 0..reps {
            for item in &mut arr {
                let v = *item;
                s += v;
                *item = v + 1.0;
            }
        }
        black_box(s);
        samples.push(start.elapsed().as_nanos() as u64);
    }

    samples.sort_unstable();
    let median = samples[iters / 2];
    let p95 = samples[(iters * 95) / 100];
    let ops = if median > 0 {
        1e9_f64 / (median as f64)
    } else {
        0.0_f64
    };

    println!(
        "[RUST BENCH] list_update median={} ns/op ({:.0} ops/sec), p95={} ns/op | iters={} warmup={}ms reps={}",
        median, ops, p95, iters, warmup_ms, reps
    );
}
