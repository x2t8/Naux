# S4-WP5F — Untimed residual-role admission

WP5F composes the already sealed WP1–WP5E evidence and admits the exact four
WP5E artifacts to the `naux-residual` role. It adds no new lowering, wrapper,
runtime, or algorithm implementation.

Role admission requires all of the following in one replay:

- the exact WP1–WP5E authority chain;
- all eight gates from the original WP5 role contract;
- the four contract-bound process-target and ELF identities;
- two fresh-process passes with exact checksums and terminal work state;
- zero fallback, diagnostic output, dynamic dependency, or abnormal exit.

Validate the static composition authority:

```bash
python3 scripts/s4_residual_role_admission.py
```

Replay the complete untimed role gate:

```bash
export CARGO_TARGET_DIR=/tmp/naux-target
cargo build --locked -p naux --example naux_s4_residual_process
python3 scripts/s4_residual_role_admission.py \
  --binary "$CARGO_TARGET_DIR/debug/examples/naux_s4_residual_process"
```

The static report is deliberately `pending-process-replay`. Only the second
form may report `untimed-naux-residual-admitted`. Neither form reads or reports
a clock.
