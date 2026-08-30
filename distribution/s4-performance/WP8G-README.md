# S4-WP8G fresh-process residency parity

WP8G is the first gate allowed to execute the register-residency candidate.
It remains an untimed correctness and work-completion gate; it does not admit
the candidate to any benchmark role.

The wrapper replaces the final 16-byte `r12` restore plus checksum return with
one same-width jump. Its appended verifier captures the promoted loop counter
from `r12`, checks the other counter and consumed owner in the still-live
frame, restores the original callee-saved `r12`, and returns a fixed 48-byte
record through the already verified WP5E startup envelope. No checksum oracle
is embedded in the executable bytes.

The independent replay regenerates the candidate twice, validates all parent,
target, process-target, and ELF hashes, creates owned non-symlink files in a
private temporary directory, and launches all four images in two fresh-process
passes. A timeout is only a safety bound and is never recorded as timing data.

```bash
cargo test --locked -p naux --example naux_s4_register_residency_process
cargo build --locked -p naux --example naux_s4_register_residency_process
python3 scripts/s4_register_residency_process.py \
  --binary target/debug/examples/naux_s4_register_residency_process
```

Only after this gate may a separate authority consider benchmark-role
admission. Timing and performance claims remain forbidden here.
