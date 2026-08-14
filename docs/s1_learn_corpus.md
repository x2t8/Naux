# NAUX Learn exercise corpus v1

Status: accepted work package\
Date: 2026-08-12\
Scope: S1 / NAUX Learn

## Contract

The v1 corpus is a fixed set of 30 deterministic programming exercises. Each
case names one NAUX source file, one bounded input fixture, one exact output
fixture, a topic, a difficulty, and an implementation class. The canonical
manifest is
[`naux-lang/learn/corpus-v1/manifest.tsv`](../naux-lang/learn/corpus-v1/manifest.tsv).

Every accepted case executes through the ordinary public path:

```text
naux run solution.nx < input.txt
```

The carrier does not invoke the interpreter, VM, compiler, or a host algorithm
function directly. It starts the same `naux` binary and `run` command a learner
uses, supplies the fixture on standard input, and observes the process result.

## Manifest admission

The loader fails closed unless all of the following hold:

- the manifest is valid UTF-8, at most 64 KiB, uses canonical LF line endings,
  ends in LF, and has the exact v1 magic and seven-column header;
- exactly 30 non-empty rows are present;
- IDs are unique, bounded lowercase ASCII slugs;
- source, input, and expected-output paths are unique, bounded, relative
  normal paths with the required `.nx`, `.in`, and `.out` extensions;
- every resolved path remains below the canonical corpus root and names a
  regular file;
- sources are at most 128 KiB; inputs and expected outputs are at most 64 KiB;
- every artifact is valid UTF-8 and contains no NUL; expected outputs contain
  no carriage return and end in LF;
- at least ten rows are `source-algorithm`, and Search, Sorting, Graph, Greedy,
  and Dynamic Programming are all represented.

For a `source-algorithm` row, the admitted source may not import hidden source
and may not lexically call any current algorithm-specific math, algorithm, or
graph host builtin. Generic language operations such as list construction,
indexing, `len`, and deterministic input are allowed. The gate lexes source,
so names in comments or string literals do not create false call evidence.

This is a bounded anti-delegation check, not a theorem that arbitrary source
implements the algorithm named by its ID. The checked-in source, exact
fixtures, review, and executable carrier together constitute the WP3 evidence.

## Corpus inventory

| Topic | Cases |
|---|---:|
| Basics | 4 |
| Math | 4 |
| Search | 4 |
| Sorting | 4 |
| Graph | 6 |
| Greedy | 3 |
| Dynamic Programming | 5 |
| **Total** | **30** |

Eight introductory cases are classified `source-basic`. The remaining 22 are
classified `source-algorithm`, exceeding the S1 minimum of ten. The algorithm
set includes binary search and first occurrence, four source sorting methods,
BFS, DFS, unweighted shortest paths, Dijkstra, connected components,
topological sorting, three greedy exercises, and five dynamic-programming
exercises.

## Result admission

Each case has a five-second process deadline. Success requires all of the
following simultaneously:

1. `naux run` exits successfully;
2. standard output is valid UTF-8, at most 64 KiB, and byte-for-byte equal to
   the expected fixture;
3. standard error is valid UTF-8, at most 64 KiB, and empty.

A timeout, missing file, oversized or malformed artifact, nonzero exit,
diagnostic, extra byte, omitted newline, or output drift rejects the corpus.

## Executable evidence

- Six loader/admission units cover the canonical grammar plus duplicate IDs,
  unsafe paths, taxonomy drift, CR/NUL/missing-final-LF input, malformed row
  shape, hidden imports, algorithm-host delegation, missing files, byte caps,
  invalid UTF-8, unsuccessful status, diagnostics, output drift, and oversized
  process output.
- The manifest carrier verifies the exact 30-case shape, minimum source
  algorithm count, and required topic coverage.
- The CLI carrier runs all 30 cases through normal `naux run`; all 30 produce
  exact output with empty standard error.
- Default and all-feature S1 carrier groups pass 11 tests each: five batch-I/O,
  four diagnostic, and two corpus tests.
- The default library suite discovers 438 tests: 432 pass, zero fail, and six
  are intentionally ignored. The all-feature library suite discovers 444
  tests: 438 pass, zero fail, and six are intentionally ignored; its final
  run completes in 496.96 seconds.
- Strict all-target/all-feature Clippy and repository formatting pass.
- Final `cargo test --workspace --all-features` exits zero. Its accepted native
  chain includes the ADR-0073-through-ADR-0085 object/dependency replay at two
  passed in 1278.60 seconds and the independent ADR-0071 ELF carrier at two
  passed in 151.09 seconds.
- The repository documentation audit covers 158 Markdown files and 463 links
  with zero broken local links; `git diff --check` is clean.

## Explicit limits

WP3 does not claim a complete language reference, package format, installer,
prebuilt supported-host binary, native execution, native performance,
production suitability, seed independence, or completion of S1. It does not
prove the algorithms correct for every possible input or turn the finite
fixtures into a general semantic verification claim.
