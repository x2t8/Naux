# S4-WP5D non-claims

The WP5D evidence admits only deterministic WP5C-to-x86-64 lowering,
canonical raw encoding, linker-free ELF64 construction, and structural
correspondence for the four frozen S4 programs.

It does not claim:

- execution of a generated ELF or correctness of physical x86-64 execution;
- fresh-process checksum or work parity;
- admission of the `naux-residual` benchmark role;
- runtime, compile-time, latency, throughput, speedup, or performance
  leadership;
- a complete x86-64 backend outside the closed WP5D-v1 operation envelope;
- portability beyond x86-64 Linux or production readiness;
- sandboxing, seed-debt removal, P2/P3, or Nauxogenesis.

The ELF entry discards the function result after return. Unsupported integer
operations, types, ownership shapes, CFG targets, byte mutations, writable
code segments, executable stacks, sections, extra syscalls, and authority
drift remain hard failures. All clocks and generated-image execution remain
forbidden at this gate.
