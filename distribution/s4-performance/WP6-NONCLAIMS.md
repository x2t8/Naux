# S4-WP6 non-claims

WP6 admits a host-control protocol, not this development machine and not a
benchmark result. In particular, it does not claim:

- that an ordinary local machine or hosted CI runner is controlled;
- that an `eligible` ephemeral observation is accepted measurement evidence;
- any runtime, latency, throughput, speedup, code-size, or memory result;
- C, C++, Rust, LLVM, or any other performance comparison;
- isolation from the kernel, firmware, hypervisor, scheduler, interrupts, or
  other physical workloads;
- production readiness, sandboxing, portability, or toolchain sovereignty.

Actual host admission still requires an exact tracked commit, a retained
canonical attestation, independent replay, and the later measurement-runner
authority. No WP6 code is authorized to reconfigure the user's machine.
