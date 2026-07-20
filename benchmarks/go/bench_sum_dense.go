package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

var sinkSumDense float64

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

func nowNs() int64 {
	return time.Now().UnixNano()
}

func main() {
	n := parseArg(os.Args, 1, 100000)
	iters := parseArg(os.Args, 2, 200)
	warmupMs := parseArg(os.Args, 3, 100)
	reps := parseArg(os.Args, 4, 50)

	arr := make([]float64, n)
	warmupEnd := time.Now().Add(time.Duration(warmupMs) * time.Millisecond)
	for time.Now().Before(warmupEnd) {
		s := 0.0
		for i := 0; i < n; i++ {
			arr[i] = float64(i)
		}
		for r := 0; r < reps; r++ {
			for i := 0; i < n; i++ {
				s += 0.0
				s += 0.0
				s += arr[i]
			}
		}
		sinkSumDense = s
	}

	samples := make([]int64, iters)
	for it := 0; it < iters; it++ {
		start := nowNs()
		s := 0.0
		for i := 0; i < n; i++ {
			arr[i] = float64(i)
		}
		for r := 0; r < reps; r++ {
			for i := 0; i < n; i++ {
				s += 0.0
				s += 0.0
				s += arr[i]
			}
		}
		sinkSumDense = s
		end := nowNs()
		samples[it] = end - start
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	median := samples[iters/2]
	p95 := samples[(iters*95)/100]
	ops := 0.0
	if median > 0 {
		ops = 1e9 / float64(median)
	}
	fmt.Printf("[GO BENCH] sum_dense median=%d ns/op (%.0f ops/sec), p95=%d ns/op | iters=%d warmup=%dms reps=%d\n",
		median, ops, p95, iters, warmupMs, reps)
}
