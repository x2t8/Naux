# S4-WP8M — Same-session paired runner

WP8M builds the retained `naux-residual` baseline and the isolated
register-residency candidate from one checkout with the same resolved Cargo and
rustc identities. It then measures both roles in pairs on one eligible WP8I
host: odd pairs run baseline then candidate (`AB`), while even pairs run
candidate then baseline (`BA`).

Static validation performs no host observation, clock read, build, or generated
artifact execution:

```bash
python3 scripts/s4_register_residency_paired_runner.py
```

Acquisition is explicit and requires a fresh eligible WP8I attestation plus a
new output path outside the checkout:

```bash
python3 scripts/s4_register_residency_paired_runner.py \
  --acquire \
  --host-attestation /path/to/WP8I-HOST-ATTESTATION.tsv \
  --output /path/to/new-paired-session
```

Every warmup is retained until both roles pass the cumulative threshold. Each
kernel then contributes exactly 30 pairs, or 60 invocations. The resulting raw
bundle contains both build identities, all 240 measured invocations, the exact
schedule, all eight ELF artifacts, and its host/toolchain receipts.
