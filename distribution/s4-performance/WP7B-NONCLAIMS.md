# S4-WP7B non-claims

WP7B admits one structurally verified NAUX timing-carrier family. It does not
claim:

- that any generated timing artifact was executed;
- any runtime, startup, memory, code-size, throughput, or speedup result;
- equal-boundary `c-generic` or `c-specialized` timing carriers;
- a retained eligible controlled host or an admitted measurement runner;
- that checksum-oracle bytes occur in the unchanged residual target;
- that an ordinary machine or hosted CI may acquire Scope 4 samples;
- C, C++, Rust, LLVM, or any other performance leadership;
- production readiness, portability, sandboxing, or seed independence.

The oracle is admitted only in the new startup validation wrapper. Independent
replay proves that the emitted checksum record still comes from the unchanged
WP5E target and that serialization begins after the second clock read.
