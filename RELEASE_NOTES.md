# NAUX Learn 0.1.0

Status: experimental release\
Target: Linux x86-64 GNU (`linux-x86_64-gnu`)\
Scope: guided programming and algorithm study

NAUX Learn 0.1.0 is the first bounded, usable product scope of NAUX. It lets a
learner write `.nx` source, receive source-positioned diagnostics, consume
deterministic batch input, run ordinary algorithms through the interpreter or
bytecode VM, and install a prebuilt supported-host binary without installing
Rust or Cargo.

## Included

- variables, integer-valued numbers, booleans, text, conditionals, loops,
  functions, bounded recursion, lists, and map/record access;
- `read_int()`, `read_token()`, `read_line()`, and plain `!say` output;
- stable lexer, parser, type, and runtime diagnostics with source locations;
- a versioned quick reference and 30 deterministic exercises across basics,
  math, search, sorting, graph, greedy, and dynamic programming;
- backend-independent semantic-work and function-depth limits;
- a sealed NAUX Learn logo installed with the bundle;
- nine sealed installer/disclosure locales (`en-US`, `vi-VN`, `zh-CN`,
  `ja-JP`, `ko-KR`, `es`, `pt-BR`, `fr`, and `de`);
- a sealed prebuilt directory bundle with independent verification and staged
  installation;
- a fail-closed ownership receipt and exact, no-scan uninstall lifecycle.

## Install from the release archive

Verify the downloaded archive first:

```bash
sha256sum --check naux-learn-0.1.0-linux-x86_64-gnu.tar.gz.sha256
tar -xzf naux-learn-0.1.0-linux-x86_64-gnu.tar.gz
cd naux-learn-0.1.0-linux-x86_64-gnu
./bin/naux bundle verify .
./naux-learn-setup
```

Setup first asks for one of nine languages, displays the localized experimental
disclosure, asks for consent, installs, and displays the same disclosure after
success. The install report prints the sealed receipt path. Preview exact uninstallation
with `naux installation uninstall --receipt <receipt.tsv> --dry-run`, then run
the same command without `--dry-run`. Only manifest-owned paths are removed;
learner `.nx` projects outside the prefix are never scanned.

Run the installed first program:

```bash
"$HOME/.local/lib/naux-learn-0.1.0/bin/naux" run \
  "$HOME/.local/lib/naux-learn-0.1.0/examples/hello.nx"
```

## Identity and verification

The executable reports exactly `naux 0.1.0`. The internal bundle manifest
binds every member path, mode, length, and SHA-256. The outer `.sha256` file
binds the deterministic release archive. Neither mechanism is a publisher
signature.

The accepted local gate includes 30/30 exercises, VM/interpreter reference
parity, mutation rejection, a no-Rust/Cargo install-and-run replay, strict
Clippy, formatting, documentation links, and the complete existing workspace
regression suite.

## Important limitations

- This release is experimental and is not suitable for production,
  safety-critical, or security-critical use.
- It supports only the declared Linux x86-64 GNU host boundary. The binary is
  dynamically linked and currently requires interfaces through GLIBC 2.39.
- The release is built by a pinned Rust/Cargo seed and includes `egg` in that
  build path. It is not dependency closure, sovereignty, self-generation,
  or compiler generation.
- Normal learner execution uses the interpreter or bytecode VM. There is no
  native-performance, C/C++ leadership, stable ABI, or long-term compatibility
  claim.
- Resource limits prevent common accidental runaway execution but do not form
  an adversarial sandbox or an operating-system memory limit.

Read `docs/LIMITATIONS.md` and
`docs/s1_learn_quick_reference_v0_1.md` inside the extracted bundle for the
complete admitted boundary.
