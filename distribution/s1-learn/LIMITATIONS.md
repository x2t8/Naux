# NAUX Learn 0.1.2 limitations

NAUX Learn is an experimental learner profile, not a stable general-purpose
language release. Its admitted use is deterministic programming and algorithm
exercises on the one declared Linux x86-64 GNU host boundary.

## Implementation and host debt

- The distributed `naux` executable is produced by the pinned Rust/Cargo seed
  in `BUILD-SEED.tsv` and still includes the `egg` optimizer dependency. This
  is not seed independence, dependency closure, self-generation, or compiler
  generation.
- Runtime execution does not require Rust or Cargo, but the executable is
  dynamically linked. It requires the loader, libraries, and minimum symbol
  interfaces in `HOST-DEPENDENCIES.tsv`; in particular this build requires
  GLIBC 2.39 interfaces.
- Only Linux x86-64 GNU is admitted. There is no macOS, Windows, musl, other
  architecture, container-image, or cross-distribution compatibility claim.
- The bundle has a SHA-256 integrity seal, not an author signature. It proves
  internal consistency with its manifest, not publisher identity.

## Language and execution limits

- The exact learner surface is `docs/s1_learn_quick_reference_v0_1.md`; wider repository
  experiments are not compatibility promises.
- Normal execution defaults to 1,000,000 semantic work units and 128 active
  user calls. CLI overrides cannot exceed 10,000,000 units or depth 512.
- The envelope is deterministic but is not an adversarial sandbox. There is
  no OS memory cap, wall-clock limit, allocation accounting, asynchronous
  interruption, or general termination proof.
- Normal learner execution is interpreted or bytecode-VM execution. Requested
  JIT execution uses the bounded VM for this profile. WP6 makes no native-code
  or C/C++ performance claim.
- Numeric behavior is the bounded v0.1 learner contract, not arbitrary-width
  integer arithmetic or a complete floating-point stability promise.

## Operational limits

- Installation accepts only a new prefix, creates missing user-local
  directories, and refuses to overwrite existing `naux` or `nauxup`
  launchers. Sealed bundle and activation receipts bind exact ownership.
  Uninstall re-verifies the bundle, receipts, and launcher targets before
  removal; non-empty user directories are retained.
- There is no package registry, auto-update, rollback manager, release
  signature, vulnerability-response SLA, or production support commitment.
- The verifier checks the exact bounded directory artifact; it is not a
  general archive extractor and does not accept tar/zip input.
