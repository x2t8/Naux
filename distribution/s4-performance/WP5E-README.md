# S4-WP5E — Fresh-process residual parity

WP5E is the first gate allowed to execute the linker-free ELF64 artifacts
produced from the frozen S4 kernels. It remains an **untimed correctness and
work-completion gate**. It does not admit the `naux-residual` benchmark role.

## Decision

WP5D remains byte-for-byte sealed. WP5E derives each artifact through one
generic transformation:

1. replay the WP5D target plan and canonical x86-64 bytes;
2. replace the single nine-byte checksum return with a same-sized jump;
3. append a completion verifier outside the WP5D byte envelope;
4. verify the terminal outer counter, inner counter, and consumed owner slot
   while the target frame is still live;
5. return the checksum plus those observations to a deterministic startup;
6. write one fixed 48-byte little-endian record and exit.

The completion record is:

| Offset | Width | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII magic `NAUX5E01` |
| 8 | 8 | artifact ordinal |
| 16 | 8 | signed checksum |
| 24 | 8 | terminal outer counter |
| 32 | 8 | terminal inner counter |
| 40 | 8 | consumed owner value |

The checksum oracle lives only in `WP5E-PROCESS.tsv` and the independent
Python replay. It is not embedded in the generated target or startup.

## Why this is work parity

The result combines two kinds of evidence:

- the sealed WP5B–WP5D structural proof establishes one allocation, exact
  range initialization, canonical nested counted loops, list operations inside
  the inner loop, checksum flow, teardown, and exact target bytes;
- the fresh-process record establishes that the physical completion path
  reached `outer = 50`, `inner = 16384`, owner `= 0` after `munmap`, and the
  frozen checksum oracle.

This is deliberately described as **sealed structure plus terminal frame
state**. It is not a hardware instruction counter or performance measurement.

## Replay

```bash
export CARGO_TARGET_DIR=/tmp/naux-target
cargo test --locked -p naux --example naux_s4_residual_process
cargo build --locked -p naux --example naux_s4_residual_process
python3 scripts/s4_residual_process.py \
  --binary "$CARGO_TARGET_DIR/debug/examples/naux_s4_residual_process"
```

The replay regenerates the candidate twice, reconstructs every appendix and
ELF independently, creates owned non-symlink files in a private temporary
directory, then launches all four images in two fresh-process passes. It does
not read or report a clock.

## Consequences

- `write` joins `mmap`, `munmap`, and `exit` as the complete syscall envelope.
- stdout has exactly 48 bytes; stderr is empty; exit status is zero.
- an incomplete write, failed state check, allocation failure, bounds failure,
  teardown failure, malformed result, hash drift, or timeout fails closed.
- the next gate may consider role admission, but timing remains forbidden until
  that separate decision is accepted.
