# NAUX Learn Tutorial

Start here if you want to install NAUX Learn and write ordinary programming or
algorithm exercises without building the compiler from source.

Current public release: **NAUX Learn 0.1.0 (Experimental)**.

## Learning path

| Step | Guide | Outcome |
|---:|---|---|
| 1 | [Install on Linux](01-install-linux.md) | Install and verify the supported Linux bundle |
| 1 | [Install on Windows](02-install-windows.md) | Try the unsigned Windows candidate |
| 2 | [Write the first program](03-first-program.md) | Check and run a `.nx` source file |
| 3 | [Practice algorithms](04-algorithms.md) | Use input, lists, functions, loops, and the exercise corpus |
| 4 | [Uninstall](05-uninstall.md) | Preview and remove exactly owned files |
| Help | [Troubleshooting](06-troubleshooting.md) | Resolve common installation and command problems |

Choose only one host guide in step 1. Linux x86-64 GNU is the supported
experimental host. Windows x86-64 is still a release candidate pending its
declared Windows 10/11 real-host gate.

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

## Fastest route

After installation, the minimum learner workflow is:

```text
naux check solution.nx
naux run solution.nx < input.txt
```

The installer deliberately does not edit shell profiles or `PATH`. Each host
guide shows the exact executable path and an optional session-local `naux`
function.

For the exact admitted language surface, see the
[NAUX Learn quick reference](../docs/s1_learn_quick_reference_v0_1.md).
