# NAUX Learn deterministic batch I/O v0.1

Status: accepted work package\
Date: 2026-08-11\
Scope: S1 / NAUX Learn

## Contract

`naux run solution.nx < input.txt` captures standard input once, verifies the
bounded byte stream, and gives the program one ordered input tape. The VM and
interpreter consume the same tape semantics. A requested JIT that encounters
these input operations falls back visibly at the API boundary to the ordinary
VM path; this work package makes no native-I/O or performance claim.

Normal `naux run` output is plain by default. Each `!say value` writes the
display text followed by one newline, without an engine banner or `> ` prefix.
The former ritual renderer remains available as `--mode cli`; HTML and JSON
remain explicit modes. Plain mode refuses UI, ask, and fetch events instead of
inventing a judge representation for them, and suppresses internal or explicit
log events so judge stderr remains reserved for failures and requested timing.

## Input operations

- `read_int()` consumes one Unicode-whitespace-delimited token and returns an
  exact signed 64-bit integer. End of input or an invalid token is a
  source-positioned runtime error.
- `read_token()` consumes one Unicode-whitespace-delimited token and returns
  text, or `null` at end of input.
- `read_line()` consumes from the current cursor through the next line feed,
  returns text without the line feed or an immediately preceding carriage
  return, and returns `null` at end of input.
- All three operations share one cursor. Mixing token and line reads therefore
  preserves whitespace remaining after the token, as ordinary scanner/line
  APIs do.

The captured stream must be valid UTF-8 and no larger than 8 MiB. When stdin is
an interactive terminal, v0.1 installs an empty tape rather than blocking for
prompts; interactive input is outside this batch contract.

## Minimal example

```naux
~ rite
    $count = read_int()
    $sum = 0
    ~ loop $count
        $sum = $sum + read_int()
    ~ end
    !say $sum
~ end
```

With input `4 10 -3 5 30`, the exact standard output is `42` followed by one
newline. The algorithm is expressed in NAUX; `read_int` performs only input
decoding and does not delegate the loop or sum to a host algorithm builtin.

## Explicit limits

This package does not claim interactive prompts, binary input, locale-dependent
number parsing, floating-point input, asynchronous I/O, native I/O, sandbox
authority, seed independence, or completion of S1. Exercise-corpus,
diagnostic, language-reference, packaging, and prebuilt-binary exit gates
remain separate work packages.

## Acceptance evidence

- Focused default and all-feature integration carriers: five passed, zero
  failed in each configuration.
- Input-tape unit boundary: four passed, covering shared UTF-8 cursor behavior,
  CRLF versus terminal CR, explicit EOF, bounded and escaped diagnostics.
- Final `cargo test --workspace --all-features`: exit code zero; library suite
  428 passed, zero failed, six intentionally ignored; S1 carrier five passed.
- The same full run preserved the accepted native/ADR chain: the combined
  ADR-0073-through-ADR-0085 carrier passed two tests in 1301.37 seconds and the
  independent ADR-0071 carrier passed two tests in 138.19 seconds.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passes for NAUX source. The remaining future-compatibility notice belongs to
  the temporary Rust-seed dependency `nom 1.2.4` and is not hidden as an S1
  sovereignty claim.
