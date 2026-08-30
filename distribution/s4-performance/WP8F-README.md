# S4-WP8F quarantined ELF64 authority

WP8F wraps the four function-byte candidates admitted by WP8E in the exact
linker-free ELF64 envelope frozen by WP5D. The frozen writer is reused without
modification; a separate parser checks every ELF identity field, both program
headers, the fixed startup call, the target extent and hash, and a complete
independent byte reconstruction.

The emitted artifact remains hexadecimal report data. WP8F does not write an
executable file, set executable permissions, start a process, read a clock, or
measure performance. The code segment is `R-X`, GNU stack is `R-W`, there is no
section table, and the candidate target begins at byte 272.

Run the local gate from the repository root:

```bash
cargo test --locked -p naux --example naux_s4_register_residency_elf
cargo run --quiet --locked -p naux \
  --example naux_s4_register_residency_elf > /tmp/naux-wp8f.tsv
python3 scripts/s4_register_residency_elf_authority.py \
  --report /tmp/naux-wp8f.tsv
```

The next gate may materialize the sealed report bytes into quarantined files
and test native correctness against the frozen oracle. Benchmark replacement,
timing, and performance claims remain forbidden.
