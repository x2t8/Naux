# S4-WP8K — Candidate measurement runner

WP8K provides the explicit-only acquisition runner for the isolated
`naux-register-residency-candidate` role. It builds the exact WP8J emitter in a
temporary target directory, replays and materializes four sealed timing ELF
images, retains every warmup and exactly 30 samples per kernel, then publishes
one new atomic raw bundle outside the checkout.

Default validation performs no host observation, clock read, build, or
generated-image execution:

```bash
python3 scripts/s4_register_residency_measurement_runner.py
```

Acquisition is deliberately unavailable without an exact eligible WP8I report:

```bash
python3 scripts/s4_register_residency_measurement_runner.py \
  --acquire \
  --host-attestation /path/to/WP8I-HOST-ATTESTATION.tsv \
  --output /path/to/new-candidate-session
```

The runner re-observes the live host before build, after build, and after all
invocations. Any fact, fingerprint, commit, repository, artifact, toolchain, or
result drift fails closed and leaves no published bundle.
