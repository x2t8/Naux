# S4-WP8E candidate function-byte authority

WP8E materializes the four register-residency plans admitted by WP8C under
the exact symbolic encoding contract admitted by WP8D. It emits x86-64
function bytes only; it does not construct an ELF image or execute them.

The candidate encoder is separate from the frozen WP5D encoder. It copies all
unselected ranges from the verified WP5D receipt, substitutes only admitted
seven-byte `r12` load/store templates, inserts the callee-save save/restore,
and rebinds every external `rel32` target to the new block and error offsets.

An independent parser checks the prologue, ABI templates, range partition,
passthrough bytes, decoded branch/error targets, error suffix, site counts,
and the exact WP8D width equation. CI emits the complete 20,241-byte report
twice, requires byte identity, checks its domain-separated root and SHA-256,
and runs 21 focused Rust tests plus independent authority mutation tests.

Run the local gate from the repository root:

```bash
cargo test --locked -p naux --example naux_s4_register_residency_encoding
cargo run --quiet -p naux --example naux_s4_register_residency_encoding \
  > /tmp/naux-wp8e.tsv
python3 scripts/s4_register_residency_candidate_authority.py \
  --report /tmp/naux-wp8e.tsv
```

The next gate may wrap these admitted bytes in a quarantined ELF artifact and
test native correctness. Benchmark replacement and performance claims remain
forbidden.
