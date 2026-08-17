# NAUX Security Policy

NAUX is experimental research software. NAUX Learn is intended for programming
and algorithm study; it is not a security sandbox and is not approved for
production, security-critical, or safety-critical workloads.

## Supported releases

| Release | Status | Security support |
|---|---|---|
| NAUX Learn 0.1.2 | Experimental pre-release | Best-effort triage only |
| Withdrawn or older builds | Unsupported | Upgrade or reproduce on the current release |

Pre-1.0 syntax, semantics, CLI behavior, installation layout, and artifact
formats may change incompatibly. This policy does not create a response-time,
embargo, patch, or long-term-support guarantee.

## Report a vulnerability privately

Do not disclose an unpatched vulnerability, exploit, secret, or personal data
in a public issue. Use GitHub's
[private vulnerability report](https://github.com/x2t8/Naux/security/advisories/new)
and include:

- affected NAUX version and exact host;
- the smallest reproducer or malformed artifact;
- expected and observed behavior;
- impact and the boundary crossed;
- whether the issue affects the compiler, runtime, verifier, installer, or
  release pipeline;
- any suggested disclosure constraints.

If GitHub does not offer the private-report form, open a public issue containing
only a request for a private contact channel. Do not attach the vulnerability
details there.

## Security boundaries

- Execution budgets reduce accidental runaway computation; they are not an
  adversarial isolation boundary.
- The current Linux artifact is dynamically linked to its declared GNU/Linux
  host dependencies.
- SHA-256, sealed manifests, and ownership receipts detect substitution and
  state drift; they are not publisher signatures.
- Rust/Cargo and `egg` remain disclosed seed debt. The current release does not
  claim dependency closure or Nauxogenesis.
- A verifier rejection is fail-closed. Bypassing a verifier is not a supported
  recovery procedure.

Ordinary correctness and usability defects belong in the public
[issue tracker](https://github.com/x2t8/Naux/issues).
