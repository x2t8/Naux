# NAUX Support and Issue Policy

NAUX is maintained as an experimental language and compiler research project.
Community reports are welcome, but there is no commercial support contract or
response-time guarantee.

## Before opening an issue

Run:

```text
naux --version
nauxup doctor
naux check program.nx
```

Search existing issues and reduce the problem to the smallest source and input
that still reproduce it.

## A useful bug report contains

- exact NAUX version and installation method;
- operating system, architecture, and relevant libc version;
- complete command line and exit status;
- minimal `.nx` source and deterministic input;
- complete stdout and stderr;
- whether `--engine vm` and `--engine interp` agree;
- whether the problem reproduces after `nauxup doctor` passes.

Use public issues for correctness, diagnostics, documentation, installation,
and reproducible performance-regression reports. Use
[SECURITY.md](SECURITY.md) for vulnerabilities; never post unpatched exploit
details publicly.

## Scope discipline

An issue may be valid while remaining outside the current NAUX Learn profile.
Unsupported platforms, production deployment, stable compatibility, native
performance leadership, dependency closure, P2/P3, and Nauxogenesis are not
promises of the current pre-release. Such requests may be discussed without
being scheduled.
