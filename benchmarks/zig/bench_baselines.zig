const std = @import("std");

var result_sink: f64 = 0.0;

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

fn runScenario(name: []const u8, a: []f64, reps: usize) !f64 {
    for (a, 0..) |*value, i| {
        value.* = @floatFromInt(i);
    }

    var total: f64 = 0.0;
    if (std.mem.eql(u8, name, "sum_dense")) {
        for (0..reps) |_| {
            var sum: f64 = 0.0;
            for (a) |value| {
                sum += value;
            }
            total += sum;
        }
    } else if (std.mem.eql(u8, name, "list_update")) {
        for (0..reps) |_| {
            var sum: f64 = 0.0;
            for (a) |*value| {
                const current = value.*;
                sum += current;
                value.* = current + 1.0;
            }
            total += sum;
        }
    } else if (std.mem.eql(u8, name, "dot_product")) {
        for (0..reps) |_| {
            var sum: f64 = 0.0;
            for (a) |value| {
                sum += value * value;
            }
            total += sum;
        }
    } else if (std.mem.eql(u8, name, "branch_mix")) {
        var sum: f64 = 0.0;
        var state: i64 = 0;
        for (0..reps) |_| {
            for (a) |value| {
                state += 17;
                if (state >= 97) {
                    state -= 97;
                }
                if (state < 48) {
                    sum += value;
                } else {
                    sum -= value;
                }
            }
        }
        return sum;
    } else {
        return error.UnknownBenchmark;
    }
    return total;
}

fn parseArg(arg: ?[]const u8, fallback: usize) !usize {
    const value = arg orelse return fallback;
    return std.fmt.parseInt(usize, value, 10);
}

fn coefficientOfVariationPct(samples: []const u64) f64 {
    if (samples.len < 2) return 0.0;
    var mean: f64 = 0.0;
    for (samples) |sample| {
        mean += @floatFromInt(sample);
    }
    mean /= @floatFromInt(samples.len);
    if (mean == 0.0) return 0.0;

    var variance: f64 = 0.0;
    for (samples) |sample| {
        const delta: f64 = @as(f64, @floatFromInt(sample)) - mean;
        variance += delta * delta;
    }
    variance /= @floatFromInt(samples.len);
    return @sqrt(variance) * 100.0 / mean;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();

    _ = args.next();
    const name = args.next() orelse return error.MissingBenchmark;
    const n = try parseArg(args.next(), 100_000);
    const iters = try parseArg(args.next(), 50);
    const warmup_ms = try parseArg(args.next(), 100);
    const reps = try parseArg(args.next(), 50);
    if (iters == 0) {
        return error.ZeroIterations;
    }

    const samples = try allocator.alloc(u64, iters);
    defer allocator.free(samples);

    const warmup_ns: i96 = @intCast(warmup_ms * std.time.ns_per_ms);
    const warmup_end = nowNs(init.io) + warmup_ns;
    while (nowNs(init.io) < warmup_end) {
        const a = try allocator.alloc(f64, n);
        const checksum = runScenario(name, a, reps) catch |err| {
            allocator.free(a);
            return err;
        };
        const sink: *volatile f64 = &result_sink;
        sink.* = checksum;
        allocator.free(a);
    }

    var checksum: f64 = 0.0;
    for (samples) |*sample| {
        const start = nowNs(init.io);
        const a = try allocator.alloc(f64, n);
        checksum = runScenario(name, a, reps) catch |err| {
            allocator.free(a);
            return err;
        };
        const sink: *volatile f64 = &result_sink;
        sink.* = checksum;
        allocator.free(a);
        sample.* = @intCast(nowNs(init.io) - start);
    }

    const cv_pct = coefficientOfVariationPct(samples);
    var i: usize = 0;
    while (i < samples.len) : (i += 1) {
        var j = i + 1;
        while (j < samples.len) : (j += 1) {
            if (samples[j] < samples[i]) {
                const tmp = samples[i];
                samples[i] = samples[j];
                samples[j] = tmp;
            }
        }
    }

    const median = samples[samples.len / 2];
    const p95 = samples[(samples.len * 95) / 100];
    std.debug.print(
        "[ZIG BENCH] {s} median={d} ns/op, p95={d} ns/op cv_pct={d:.4} checksum={d:.17}\n",
        .{ name, median, p95, cv_pct, checksum },
    );
}
