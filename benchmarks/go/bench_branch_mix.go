package main

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"time"
)

var sinkBranchMix float64

func parseArg(args []string, idx int, def int) int {
	if idx >= len(args) {
		return def
	}
	v, err := strconv.Atoi(args[idx])
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func coefficientOfVariationPct(samples []int64) float64 {
	if len(samples) < 2 {
		return 0
	}
	mean := 0.0
	for _, sample := range samples {
		mean += float64(sample)
	}
	mean /= float64(len(samples))
	if mean == 0 {
		return 0
	}
	variance := 0.0
	for _, sample := range samples {
		delta := float64(sample) - mean
		variance += delta * delta
	}
	variance /= float64(len(samples))
	return math.Sqrt(variance) * 100 / mean
}

func runOnce(n int, reps int) float64 {
	arr := make([]float64, n)
	for i := range arr {
		arr[i] = float64(i)
	}
	sum := 0.0
	var state int64
	for r := 0; r < reps; r++ {
		for _, value := range arr {
			state += 17
			if state >= 97 {
				state -= 97
			}
			if state < 48 {
				sum += value
			} else {
				sum -= value
			}
		}
	}
	sinkBranchMix = sum
	return sum
}

func main() {
	n := parseArg(os.Args, 1, 100000)
	iters := parseArg(os.Args, 2, 200)
	warmupMs := parseArg(os.Args, 3, 100)
	reps := parseArg(os.Args, 4, 50)

	warmupEnd := time.Now().Add(time.Duration(warmupMs) * time.Millisecond)
	for time.Now().Before(warmupEnd) {
		runOnce(n, reps)
	}

	samples := make([]int64, iters)
	checksum := 0.0
	for it := 0; it < iters; it++ {
		start := time.Now()
		checksum = runOnce(n, reps)
		samples[it] = time.Since(start).Nanoseconds()
	}

	cvPct := coefficientOfVariationPct(samples)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	median := samples[iters/2]
	p95 := samples[(iters*95)/100]
	ops := 0.0
	if median > 0 {
		ops = 1e9 / float64(median)
	}
	fmt.Printf("[GO BENCH] branch_mix median=%d ns/op (%.0f ops/sec), p95=%d ns/op cv_pct=%.4f | iters=%d warmup=%dms reps=%d checksum=%.17g\n",
		median, ops, p95, cvPct, iters, warmupMs, reps, checksum)
}
