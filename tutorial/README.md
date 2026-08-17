# NAUX Learn Tutorial

Start here to inspect the experimental learner language and its algorithm
examples. There is currently **no public binary release**. Earlier Linux and
Windows prereleases were withdrawn while interactive terminal input, CLI
scope, and onboarding are redesigned.

## Learning path

| Step | Guide | Outcome |
|---:|---|---|
| 1 | [Build from source](../README.md#build-from-source) | Run the current research tree with Rust/Cargo |
| 2 | [Five-minute quickstart](00-quickstart.md) | Write, check, run, and enter keyboard input |
| 3 | [First-program explanation](03-first-program.md) | Understand the learner syntax |
| 4 | [Practice algorithms](04-algorithms.md) | Use input, lists, functions, loops, and the exercise corpus |
| Existing installs | [Uninstall](05-uninstall.md) | Remove a withdrawn prerelease using its sealed receipt |
| Help | [Troubleshooting](06-troubleshooting.md) | Resolve common installation and command problems |

The former [Linux](01-install-linux.md) and [Windows](02-install-windows.md)
installation pages now record the withdrawal instead of publishing dead
download commands.

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

## Current source route

From the repository root, the current developer workflow is:

```text
cargo run -p naux -- check solution.nx
cargo run -p naux -- run solution.nx < input.txt
```

The current tree supports both interactive terminal input and deterministic
redirected input. The next binary release will expose the same behavior
without requiring Rust or Cargo on the learner's machine.

For the exact admitted language surface, see the
[NAUX Learn quick reference](../docs/s1_learn_quick_reference_v0_1.md).
