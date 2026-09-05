# S4-WP8S — Exact register-residency observation

WP8S binds the owner-approved claim to the public release, exact archive and
receipt hashes, controlled host attestation, source commit, bundle, session,
WP8N evidence, and WP8O threshold roots.

Static validation records approval but admits no claim without evidence:

```bash
python3 scripts/s4_register_residency_exact_claim.py
```

Admission requires caller-supplied copies of the pinned public assets. The
checker performs no network access and replays the archive read-only:

```bash
python3 scripts/s4_register_residency_exact_claim.py \
  --archive naux-s4-register-residency-paired-56b6447a13ac648c8e35e64daa34ddabb7e0b51c.tar.gz \
  --receipt naux-s4-register-residency-paired-56b6447a13ac648c8e35e64daa34ddabb7e0b51c.tar.gz.receipt.tsv
```

Only the byte-exact text in `WP8S-APPROVED-CLAIM.txt` may receive
`claim-status admitted-exact-observation`. See `WP8S-NONCLAIMS.md` for the
boundaries that remain forbidden.
