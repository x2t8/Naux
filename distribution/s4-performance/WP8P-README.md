# S4-WP8P — Register-residency claim boundary

WP8P freezes the boundary between a WP8O threshold candidate and a public
statement. The protocol is deliberately blocked: a local authority chain,
synthetic fixture, passing evaluator, or maintainer intent cannot admit a
claim.

```bash
python3 scripts/s4_register_residency_claim_admission.py
```

The static report names four unresolved prerequisites. This version has no
bundle, candidate, request, approval, network, clock, execution, or admission
mode. A later protocol may add an admission path only after the exact WP8B–WP8P
chain is tracked with green public CI, an eligible WP8M bundle is published,
WP8N and WP8O replay it successfully, and a distinct owner approves exact
claim text.

The only potentially permitted future statement is an observation limited to
the exact host, source commit, bundle root, threshold candidate, and all four
sealed kernels. Language-wide performance, compiler leadership, production
performance, and extrapolation remain forbidden.
