# NAUX Learn corpus v1

This directory contains the versioned 30-exercise corpus used by the S1
acceptance carrier.

- `manifest.tsv` is the canonical inventory and metadata source.
- `solutions/` contains learner-scale NAUX implementations.
- `fixtures/` contains deterministic standard input and exact standard output.

Run one case from the repository root:

```bash
cargo run -q -p naux -- run \
  naux-lang/learn/corpus-v1/solutions/20-dijkstra-matrix.nx \
  < naux-lang/learn/corpus-v1/fixtures/20-dijkstra-matrix.in
```

Run the complete corpus gate:

```bash
cargo test -p naux --test s1_learn_corpus
```

The normative bounds, admission rules, evidence, and non-claims are in
[`docs/s1_learn_corpus.md`](../../../docs/s1_learn_corpus.md).
