use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn parse_arg(args: &[String], idx: usize, default: usize) -> usize {
    args.get(idx)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn coefficient_of_variation_pct(samples: &[u64]) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let mean = samples.iter().map(|sample| *sample as f64).sum::<f64>() / samples.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let variance = samples
        .iter()
        .map(|sample| {
            let delta = *sample as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / samples.len() as f64;
    variance.sqrt() * 100.0 / mean
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let n = parse_arg(&args, 1, 100_000);
    let iters = parse_arg(&args, 2, 200);
    let warmup_ms = parse_arg(&args, 3, 100);
    let reps = parse_arg(&args, 4, 50);

    let warmup_end = Instant::now() + Duration::from_millis(warmup_ms as u64);
    while Instant::now() < warmup_end {
        let mut arr = vec![0.0_f64; n];
        let mut total = 0.0_f64;
        for (i, item) in arr.iter_mut().enumerate() {
            *item = i as f64;
        }
        for _ in 0..reps {
            let mut sum = 0.0_f64;
            for v in &arr {
                sum += *v * *v;
            }
            total += sum;
        }
        black_box(total);
    }

    let mut samples: Vec<u64> = Vec::with_capacity(iters);
    let mut checksum = 0.0_f64;
    for _ in 0..iters {
        let start = Instant::now();
        let mut arr = vec![0.0_f64; n];
        let mut total = 0.0_f64;
        for (i, item) in arr.iter_mut().enumerate() {
            *item = i as f64;
        }
        for _ in 0..reps {
            let mut sum = 0.0_f64;
            for v in &arr {
                sum += *v * *v;
            }
            total += sum;
        }
        checksum = total;
        black_box(total);
        drop(arr);
        samples.push(start.elapsed().as_nanos() as u64);
    }

    let cv_pct = coefficient_of_variation_pct(&samples);
    samples.sort_unstable();
    let median = samples[iters / 2];
    let p95 = samples[(iters * 95) / 100];
    let ops = if median > 0 {
        1e9_f64 / (median as f64)
    } else {
        0.0_f64
    };

    println!(
        "[RUST BENCH] dot_product median={} ns/op ({:.0} ops/sec), p95={} ns/op cv_pct={:.4} | iters={} warmup={}ms reps={} checksum={:.17}",
        median, ops, p95, cv_pct, iters, warmup_ms, reps, checksum
    );
}
