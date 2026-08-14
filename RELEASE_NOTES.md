# NAUX Learn 0.1.1

Status: experimental release\
Target: Linux x86-64 GNU (`linux-x86_64-gnu`)\
Scope: guided programming and algorithm study

NAUX Learn 0.1.1 is the first maintenance release of the bounded, usable NAUX
Learn scope. It lets a
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
- a fail-closed bundle receipt plus a Linux activation receipt that binds
  stable `naux` and `nauxup` launchers;
- exact, no-scan `nauxup doctor`, dry-run, and uninstall lifecycle;
- a version-pinned one-command bootstrap for Linux; it
  validates the archive byte length, outer SHA-256, executable version, and
  sealed inner manifest before Setup runs.

## One-command install

Linux x86-64 GNU:

```bash
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.1-learn/nauxup.sh | sh
```

For unattended installation, append `| sh -s -- --yes`. The command is
intentionally pinned to `v0.1.1-learn`. NAUX Learn is a
prerelease, so GitHub's `/releases/latest/` route is not its version selector.
The bootstrap files are integrity carriers, not publisher signatures.

Windows packaging and GUI/IDE integration are outside this Linux release
slice and are not claimed by these notes.

## Manual install from the release archive

Verify the downloaded archive first:

```bash
sha256sum --check SHA256SUMS
tar -xzf naux-learn-0.1.1-linux-x86_64-gnu.tar.gz
cd naux-learn-0.1.1-linux-x86_64-gnu
./bin/naux bundle verify .
./naux-learn-setup
```

Setup detects one of nine supported locales, displays a concise experimental
plan, and asks for one confirmation. It creates clean-machine user-local
directories, installs the immutable versioned bundle, and publishes stable
`~/.local/bin/naux` and `~/.local/bin/nauxup` launchers without editing shell
startup files. Existing launchers are never overwritten.

Preview exact removal with `nauxup uninstall --dry-run`, inspect integrity
with `nauxup doctor`, then run `nauxup uninstall`. Bundle, receipt, and launcher
identity are re-verified; learner `.nx` projects are never scanned.

Run the installed first program:

```bash
naux run "$HOME/.local/share/naux/toolchains/learn/0.1.1/examples/hello.nx"
```

## Identity and verification

The executable reports exactly `naux 0.1.1`. The internal bundle manifest
binds every member path, mode, length, and SHA-256. The outer `SHA256SUMS` file
binds the deterministic release archive. Neither mechanism is a publisher
signature.

The accepted local evidence includes the existing 30/30 exercise gate,
VM/interpreter reference parity, release mutation rejection, a clean-HOME
no-Rust/Cargo install-and-run replay, strict Clippy, formatting, bundle and
release identity tests, and the relevant native/core regression gates.

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
