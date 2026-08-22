# NAUX language support

This is the self-contained, MIT-licensed language-support package for NAUX
source files. Its canonical public home is
[`x2t8/naux-grammar`](https://github.com/x2t8/naux-grammar); the NAUX compiler
monorepo retains the synchronized source under `vscode/naux-lang` so grammar
drift can be checked against the executable language surface.

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
- `snippets/naux.json`: source-validated editor snippets;
- `icons/nauxlang.png`: the global NAUX project mark used by registries;
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

The validator checks that the package, grammar, snippets, and Linguist
candidate identity agree. It also rejects activation code, icon-theme
injection, settings overrides, and extension dependencies. Inside the NAUX
monorepo it additionally derives the public builtin inventory from the Rust
seed and rejects grammar drift.

The package has no runtime or npm dependencies. GitHub Linguist may import this
repository with its official `script/add-grammar` workflow once NAUX satisfies
Linguist's independent real-world usage requirement.

## Install

Install from
[Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=x2t8.naux-lang)
or search for **NAUX Language** in the extension view. VS Code users can run:

```bash
code --install-extension x2t8.naux-lang
```

The same VSIX is registry-portable and may be published unchanged at
[`x2t8.naux-lang` on Open VSX](https://open-vsx.org/extension/x2t8/naux-lang).

## File-icon policy

NAUX Language registers the stable language ID `naux`, but it does not include
or activate a file-icon theme, change `workbench.iconTheme`, install another
extension, or write editor settings. File-icon themes may map the public
language ID independently. Until a user's chosen theme supports NAUX, `.nx`
files retain that theme's ordinary fallback icon.

## Install from source

To install directly from a checked-out grammar repository:

1. Open the command palette.
2. Select **Extensions: Install Extension from Location...**.
3. Select this `vscode/naux-lang` directory.
4. Open a `.nx` file.

This editor package is separate from the minimal NAUX compiler/runtime
distribution. Installing NAUX must not copy grammar fixtures, package tests,
or this README into the toolchain prefix.
