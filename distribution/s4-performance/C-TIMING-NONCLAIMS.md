# S4-WP7B C-carrier non-claims

This package admits only source derivation and non-executing compiler audit for
two C timing-carrier roles. It does not claim:

- that any carrier was executed or timed;
- that the current machine is a controlled measurement host;
- that a compiled C binary is portable or reproducible across toolchains;
- that the C and NAUX startup, allocator implementation, or code size match;
- that any raw sample, statistic, variance gate, threshold, or speedup exists;
- performance leadership over C, C++, Rust, LLVM, or any other system;
- production readiness, sandboxing, seed-debt removal, P2/P3, or Nauxogenesis.

The compile audit is structural evidence only. It may inspect compiler output,
but it must never execute a carrier.
