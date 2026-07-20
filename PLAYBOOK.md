# Naux Playbook

This file is for operating the repo, not for explaining the language.

## Daily path

1. Run `cargo run -p naux -- doctor`.
2. Run the local quality gate if you changed code:
   `cargo fmt --manifest-path naux-lang/Cargo.toml --all -- --check`
   `cargo clippy --manifest-path naux-lang/Cargo.toml --all-targets --all-features -- -D warnings`
   `cargo test --manifest-path naux-lang/Cargo.toml --all-features`
3. If your change is optimizer or runtime related, run the focused tests:
   `cargo test -p naux vm::ssa -- --nocapture`
   `cargo test -p naux vm::compiler -- --nocapture`
   `cargo test -p naux vm::egraph -- --nocapture`

## Perf path

Use this path when a change can affect runtime behavior:

1. Run `cargo run -p naux -- doctor`.
2. Check that the doctor report does not show perf drift for governor or turbo.
3. Run a single benchmark smoke if you only need quick feedback.
4. Run `bash ./scripts/perf_contract_ci.sh` before claiming perf safety.

## If perf goes red

Classify the failure before touching compiler code:

### Infra / environment
- self-hosted runner is down or not picking up jobs
- `taskset` missing
- governor or turbo policy drifted
- baseline fingerprint missing or stale

Recovery:
- run `cargo run -p naux -- doctor`
- restart the self-hosted runner if GitHub shows jobs stuck in queue
- refresh the baseline fingerprint when machine policy changes

### Measurement noise
- `ci` is green but a perf gate is flaky
- rerun clears the failure

Recovery:
- compare the slope or fixed-cost artifacts
- verify CPU pinning and policy
- do not assume a logic regression from one noisy run

### Logic regression
- `ci` is red
- perf fails consistently across reruns
- focused local tests reproduce the change

Recovery:
- reduce to a small benchmark
- compare IR / SSA / disasm before and after
- only then change optimizer logic

## If the runner dies

Typical recovery:

```bash
sudo systemctl restart actions.runner.x2t8-Naux.archlinux.service
systemctl status actions.runner.x2t8-Naux.archlinux.service --no-pager -l
journalctl -u actions.runner.x2t8-Naux.archlinux.service -f
```

Expected healthy signals:
- `Active: active (running)`
- `Connected to GitHub`
- `Listening for Jobs`

## Reports worth keeping

- `target/naux-doctor.json`
- `benchmarks/perf_fixed_cost_report.json`
- `benchmarks/perf_slope_report.json`
- GitHub Action run links for green perf checkpoints
