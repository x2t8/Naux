# NAUX Learn 0.1.0 Windows limitations

NAUX Learn is an experimental learner profile, not a stable general-purpose
language release. This candidate targets deterministic programming and
algorithm exercises on the declared Windows x86-64 host boundary, but has not
yet passed its required real-Windows acceptance carrier.

## Implementation and host debt

- `naux.exe` is cross-built by the pinned Rust/Cargo and MinGW-w64 seed in
  `BUILD-SEED.tsv` and includes the `egg` optimizer dependency. This is not
  seed independence, dependency closure, self-generation, or compiler
  generation.
- Runtime execution requires no Rust, Cargo, or MinGW installation. The exact
  imported Windows system contracts are disclosed in
  `HOST-DEPENDENCIES.tsv`; no non-system runtime DLL is bundled.
- Candidate admission is bounded to 64-bit Windows 10 22H2 and Windows 11,
  pending a checked real-host replay. There is no supported-Windows claim yet,
  and no Windows 7/8/8.1, 32-bit Windows, ARM64, Wine, ReactOS, macOS, or other
  compatibility claim.
- The manifest and adjacent SHA-256 file provide integrity evidence, not an
  author signature or publisher authentication.

## Language and execution limits

- The exact learner surface is
  `docs/s1_learn_quick_reference_v0_1.md`; wider repository experiments are
  not compatibility promises.
- Normal execution defaults to 1,000,000 semantic work units and 128 active
  user calls. CLI overrides cannot exceed 10,000,000 units or depth 512.
- The envelope is deterministic but is not an adversarial sandbox. There is
  no OS memory cap, wall-clock limit, allocation accounting, asynchronous
  interruption, or general termination proof.
- Normal learner execution is interpreted or bytecode-VM execution. Requested
  JIT execution falls back to the bounded VM. This release makes no Windows
  native-code or C/C++ performance claim.

## Operational limits

- Installation accepts only a new prefix and publishes a sealed ownership
  receipt. `naux.exe` can verify and dry-run exact removal, but actual Windows
  removal requires the pending detached Setup helper.
- There is no code-signing certificate, Authenticode signature, SmartScreen
  reputation, package registry, auto-update, rollback manager, vulnerability-
  response SLA, or production support commitment.
- Cross-build and PE/archive structure can be validated on Linux. A Windows
  runtime acceptance claim additionally requires the checked carrier to pass
  on an admitted real Windows host.
