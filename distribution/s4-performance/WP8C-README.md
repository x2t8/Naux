# S4-WP8C candidate-plan authority

WP8C admits the exact semantic plan selected by WP8B. Exactly one frozen
inner-loop `i64` index slot in each of four kernels is assigned to callee-saved
`r12`. The source Machine IR remains the rollback artifact.

Admission binds:

- the exact WP8B contract and authority;
- the untouched WP5D lowering source;
- four complete, domain-separated plan identities;
- four independent baseline/candidate replay identities;
- exact results, step counts, overflow events, ownership state, and ABI restore;
- forward CFG definite initialization and complete structural erasure;
- a deterministic 12,180-byte report with an exact root and document SHA-256.

The checked-in contract contains the compact authority view. CI builds the
reviewed Rust emitter, emits the full report twice, requires byte equality,
uses the emitter's closed `--verify` surface, and independently validates the
same report through the Python authority replay.

WP8C emits no candidate x86-64 bytes and reads no clock. Encoding, native
execution, measurement eligibility, threshold evaluation, and any performance
claim remain later gates.
