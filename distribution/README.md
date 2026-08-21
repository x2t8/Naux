# NAUX distribution inputs

Distribution material is organized by scope, not by the identity of the whole
NAUX project.

- `s1-learn/` contains the reusable, sealed packaging inputs for Scope 1 —
  NAUX Learn.
- `s2-preview/` contains public, non-secret evidence locks for the Research
  Preview surface. `LINGUIST-SURFACE.tsv` binds the monorepo grammar mirror to
  the exact annotated `naux-grammar` tag, Git tree, file inventory, and
  language identity without claiming upstream acceptance.

The current `s1-learn` material defines the NAUX Learn 0.1.4 Linux experimental
pre-release. The preceding 0.1.3 release remains identified by Git tag
`v0.1.3-learn`; public replay found that GitHub normalized `nauxup.sh` from
local mode `0755` to `0644`, so 0.1.4 makes `0644` the canonical transport
mode. The 0.1.2 release remains at tag `v0.1.2-learn`, and historical 0.1.1
evidence remains under `../archive/releases/0.1.1/`. No prior artifact is
reused as evidence for the 0.1.4 payload.

Verify the S2 grammar lock locally with:

```bash
python3 scripts/s2_linguist_surface.py
```

An optional checkout of the canonical grammar tag can be replayed byte for
byte with `--canonical-checkout PATH`. GitHub usage observations are captured
separately by `scripts/capture_s2_linguist_usage.py`; raw `.nx` search totals
are not treated as NAUX adoption because the extension is shared by unrelated
projects.
