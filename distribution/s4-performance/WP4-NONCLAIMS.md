# S4-WP4 non-claims

This package defines and validates a measurement boundary. It contains no raw
timing sample, derived latency, throughput, speedup, memory result, code-size
comparison, or admitted performance result.

In particular, the accepted S4-WP3 trace-native carrier is not a
whole-program residual artifact. It remains an observation role and cannot be
renamed to satisfy the required `naux-residual` role.

Local machines and hosted CI validate structure only. They do not establish a
controlled host or authorize a comparison with C, C++, Rust, LLVM, or any other
implementation.
