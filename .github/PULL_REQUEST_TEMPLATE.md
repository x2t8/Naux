<!--
Read CONTRIBUTING.md and PROJECT_MAP.md before completing this description.
Keep answers proportional to the change: a typo can be brief; a high-risk
compiler or evidence change needs its reviewed design boundary and applicable
replay, verifier, measurement, or proof evidence.

Checked boxes record what the author inspected. They do not establish
correctness or replace review.
-->

## What is wrong or missing now?

<!--
Identify the current problem or capability gap. Name the closest existing
mechanism and explain why it does not already resolve this case.
-->

Related issue or design discussion: <!-- Closes #... / Not required for a small focused fix -->

## What exactly changes?

<!-- Describe the commit delta, not only the intended outcome. -->

## What becomes possible afterward?

<!-- State the demonstrated value. Removing a defect or complexity counts. -->

## What evidence demonstrates that?

| Claim made by this PR | Evidence | Boundary or limitation |
|---|---|---|
| <!-- exact claim --> | <!-- test, replay, diff, measurement, proof, or other check --> | <!-- what this does not establish --> |

Commands and results:

```text
# exact command
# result, including the number of tests/checks that actually ran
```

Skipped, unavailable, or failing checks:

<!-- Write "none" or explain why the missing evidence is acceptable for this risk and claim. -->

## Which contracts or invariants are affected?

- Affected subsystem:
- Risk level: <!-- low / medium / high, based on impact rather than file type -->
- Architecture route in `PROJECT_MAP.md`:
- Contracts and invariants reviewed:
- Downstream consumers or execution paths checked:

<!--
If none are affected, explain why. For semantic work, address interpreter, VM,
JIT, SSA, e-graph, native, memory, and formal paths as applicable. For a
performance claim, follow PERF_CONTRACT.md and state the exact claim scope.
-->

## What was deliberately not changed?

<!-- State exclusions, unsupported cases, remaining limits, and claims not made. -->

## Author review

- [ ] This PR contains one coherent change and no unrelated refactor.
- [ ] I searched for existing implementations and duplicate open or closed work.
- [ ] Validation is proportional to the highest-risk boundary affected.
- [ ] Tests and documentation are updated where behavior or a public boundary changes.
- [ ] Performance language is no broader than the measured and admitted evidence.
- [ ] No secret or unpatched vulnerability detail is disclosed; security reports follow `SECURITY.md`.
- [ ] Build caches, private planning files, and unreviewed local evidence are excluded.
- [ ] The change preserves the repository Apache-2.0 license and applicable notices.

<!--
Review may still require narrower scope, more evidence, design revision, or a
contract/model update. Contributor effort and passing CI are not substitutes
for architectural fit, evidence sufficiency, and contribution value.
-->
