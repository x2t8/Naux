# NAUX Learn source diagnostic contract v0.1

Status: accepted work package\
Date: 2026-08-12\
Scope: S1 / NAUX Learn

## Contract

Normal `naux run` and `naux check` failures at the lexer, parser, and type
checker use one text shape. Runtime failures use the same shape, and ordinary
VM and interpreter execution must agree byte for byte for the same failure.

```text
error: Type error: `read_int` expects 0 args, got 1
 --> solution.nx:2:14
  |
2 |     $value = read_int(1)
  |              ^
```

The first line identifies exactly one stage: `Lex`, `Parse`, `Type`, or
`Runtime`. When the producing stage supplies a source span, the following
lines carry the filename, one-based scalar line and column, one source window,
and one caret. A missing upstream span is not replaced with a fabricated
location.

Failed `run` and early failed `check` commands emit no partial standard output.
The process-level `error: ` prefix remains the CLI envelope; the diagnostic
primitive owns everything after it.

## Bounds and terminal safety

- messages are limited to 512 source characters;
- filenames are limited to 512 source characters;
- source windows are limited to 160 source characters, centered with bounded
  left context and marked with `...` when truncated;
- control, bidi-formatting, and related invisible terminal characters are
  rendered as explicit Unicode escapes before output;
- caret placement is derived from the rendered bounded prefix, so escaped
  control characters cannot move or forge the caret.

These are output bounds, not permission to accept an invalid program. The
lexer, parser, type checker, and runtime continue to fail closed before the
diagnostic is rendered.

## Backend boundary

The stable S1 text contract contains one primary diagnostic. Backend-specific
VM disassembly, operand stacks, and call-stack details are not appended to
ordinary errors: those structures are neither semantically identical across
the VM and interpreter nor part of the S1 compatibility promise. Dedicated
debugger and structured IDE/LSP diagnostics remain separate future work.

## Explicit limits

This package does not define warning formatting, refinement or region reports,
multi-error recovery, source ranges, fix-its, colored output, terminal display
width for every Unicode grapheme, a structured diagnostic wire format, or a
complete IDE/LSP protocol. It changes presentation only and grants no new
language, execution, native-code, sandbox, sovereignty, or performance claim.

## Acceptance evidence

- Default and all-feature exact CLI golden carriers each pass four tests: the
  lexer, parser, and type cases prove byte-for-byte `run`/`check` agreement;
  the runtime case proves byte-for-byte VM/interpreter agreement.
- Default and all-feature diagnostic units each pass four tests covering exact
  source shape, terminal escaping, hard message/filename bounds, and the
  bounded long-line window.
- The prior S1 batch-I/O carrier remains green at five passed, zero failed;
  the complete runtime parity carrier remains green at 26 passed, zero failed.
- Final `cargo test --workspace --all-features` exits zero: the library reports
  432 passed, zero failed, and six intentionally ignored; the combined
  ADR-0073-through-ADR-0085 carrier reports two passed in 1210.57 seconds; the
  independent ADR-0071 carrier reports two passed in 137.46 seconds.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passes for NAUX source. The only future-compatibility notice remains in the
  temporary Rust-seed dependency `nom 1.2.4`; it is not hidden as an S1
  sovereignty claim.
