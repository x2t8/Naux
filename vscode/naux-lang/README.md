# NAUX language support

This directory is the self-contained, MIT-licensed language-support package
for NAUX source files. It can remain in the NAUX monorepo or be exported as a
standalone grammar repository without changing its public identity.

## Locked language identity

| Field | Value |
|---|---|
| Language | `NAUX` |
| Type | `programming` |
| Primary alias | `naux` |
| Extension | `.nx` |
| TextMate scope | `source.naux` |
| Interpreter | `naux` |
| Linguist color | `#FF304D` |
| Grammar license | MIT |

The machine-readable authority is
[`linguist-language.json`](linguist-language.json). The status
`candidate-not-submitted` is deliberate: this package is technically prepared
for a future GitHub Linguist contribution, but it does not claim the external
usage threshold or GitHub acceptance.

## Contents

- `syntaxes/naux.tmLanguage.json`: TextMate grammar;
- `language-configuration.json`: editor brackets, indentation, and folding;
- `icons/`: the global NAUX project mark and VS Code file-icon theme;
- `scripts/validate.mjs`: dependency-free identity and compiler-drift checks;
- `test/fixtures/`: grammar fixtures, never part of the NAUX runtime installer;
- `LICENSE`: standalone MIT grant for the grammar package.

The grammar covers the currently executable Surface syntax: ritual blocks,
functions, actions, exact scalar annotations, Unicode variables, byte
literals, collections, operators, input operations, and every registered
public runtime/stdlib builtin. Internal double-underscore operations are
visually distinct.

## Validate

From this directory:

```bash
npm test
```

The validator checks that the package, grammar, icon theme, and Linguist
candidate identity agree. Inside the NAUX monorepo it additionally derives the
public builtin inventory from the Rust seed and rejects grammar drift.

## Install in VS Code locally

1. Open the command palette.
2. Select **Extensions: Install Extension from Location...**.
3. Select this `vscode/naux-lang` directory.
4. Open a `.nx` file. Optionally select **NAUX Icons** as the file-icon theme.

This editor package is separate from the minimal NAUX compiler/runtime
distribution. Installing NAUX must not copy grammar fixtures, package tests,
or this README into the toolchain prefix.
