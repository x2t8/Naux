# NAUX Learn Tutorial

Start here to inspect the experimental learner language and its algorithm
examples. NAUX Learn 0.1.2 is available as a Linux x86-64 GNU experimental
pre-release; no Windows artifact is published for this version.

## Learning path

| Step | Guide | Outcome |
|---:|---|---|
| 1 | [Install on Linux](01-install-linux.md) | Install the prebuilt learner toolchain without Rust/Cargo |
| 2 | [Five-minute quickstart](00-quickstart.md) | Write, check, run, and enter keyboard input |
| 3 | [First-program explanation](03-first-program.md) | Understand the learner syntax |
| 4 | [Practice algorithms](04-algorithms.md) | Use input, lists, functions, loops, and the exercise corpus |
| Source route | [Build from source](../README.md#build-from-source) | Run the research tree with Rust/Cargo |
| Removal | [Uninstall](05-uninstall.md) | Remove 0.1.2 using its sealed receipt |
| Help | [Troubleshooting](06-troubleshooting.md) | Resolve common installation and command problems |

The [Windows](02-install-windows.md) page records the withdrawn Windows route;
0.1.2 publishes Linux assets only.

## What NAUX Learn is

NAUX Learn is a deliberately small language profile for guided programming and
algorithm study. It currently includes integers, booleans, text, variables,
conditionals, loops, functions, bounded recursion, lists, maps, deterministic
standard input/output, and source-positioned diagnostics.

It is not the final NAUX language. It does not claim production readiness,
security isolation, stable compatibility, seed independence, or native
performance leadership. The prebuilt bundles run without Rust or Cargo, but
they are still produced by the disclosed Rust/Cargo seed.

## Supported installer languages

Setup supports English, Tiếng Việt, 简体中文, 日本語, 한국어, Español,
Português do Brasil, Français, and Deutsch. This localizes Setup and the
experimental-release disclosure; it does not localize NAUX syntax, program
output, or compiler diagnostics.

## Source route

From the repository root, the current developer workflow is:

```text
cargo run -p naux -- check solution.nx
cargo run -p naux -- run solution.nx < input.txt
```

The source and prebuilt routes support both interactive terminal input and
deterministic redirected input.

For the exact admitted language surface, see the
[NAUX Learn quick reference](../docs/s1_learn_quick_reference_v0_1.md).
