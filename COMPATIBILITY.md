# NAUX Compatibility Policy

NAUX exposes versioned, bounded profiles rather than promising that every
repository experiment is one stable language.

## NAUX Learn 0.1.4

The public pre-release supports one binary host boundary:

- target: `linux-x86_64-gnu`;
- executable format: ELF64 x86-64 PIE;
- dynamic loader: `/lib64/ld-linux-x86-64.so.2`;
- required interfaces: the exact inventory in
  `distribution/s1-learn/HOST-DEPENDENCIES.tsv`, currently through GLIBC 2.39.

Other Linux ABIs, musl-only systems, ARM64, macOS, BSD, and Windows are outside
the binary compatibility claim. Portable frontend and VM paths built from
source may work elsewhere, but that is not evidence for the released binary.

The admitted learner language is the
[NAUX Learn quick reference](docs/s1_learn_quick_reference_v0_1.md). Repository
features outside that reference may change or disappear without a compatibility
bridge. The stable execution spelling for this release is:

```text
naux run program.nx
```

The CLI does not treat `naux program.nx` as an alias. Plain execution prints
only explicit program output such as `!say`; a returned value is not implicit
stdout.

## Versioning before 1.0

- Patch releases may fix semantics or usability when preserving the old
  behavior would retain a correctness or safety defect.
- Minor releases may change source syntax, semantics, CLI shape, manifests,
  installation layout, and evidence formats.
- Every release must publish its exact scope, limitations, target, seed debt,
  and migration notes.
- A file accepted by one experimental release is not promised to compile under
  another unless the release notes say so explicitly.

Production compatibility, ABI stability, package-registry stability, and a
long-term-support window remain outside the current claim.
