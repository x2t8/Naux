# NAUX Language Specification

Status: current Surface NAUX 0.2 bridge behavior

This document describes the currently admitted public Surface language.
Observable behavior is governed by `../PARITY_CONTRACT.md` and
`../MEMORY_MODEL.md`.

## Overview
- Ritual-first syntax: programs are built from `~` blocks such as rite, function, and control-flow blocks.
- `$` prefixes locals/variables; `!` prefixes runtime actions; `^` returns a value.
- `#` starts a line comment outside string literals.

## Lexical Rules
- Identifiers: `_` or a Unicode alphabetic character first, followed by `_` or
  Unicode alphanumeric characters.
- Numbers: integer or floating literal, optional sign.
- Strings: double quoted with escapes.
- Operators: `+ - * / % == != > >= < <= && ||`.
- Newlines separate statements. Horizontal indentation is ignored outside
  literals and comments; `~` block markers may therefore be indented.

## Statements
- `~ rite ... ~ end`: top-level entry point.
- `~ fn name($a, $b, ...) ... ~ end`: defines an ordinary bridge function;
  parameters are `$`-prefixed.
- `~ fn name($a: F64, $flag: Bool) -> F64 ... ~ end`: declares the exact
  scalar signature checked by the annotated-function path.
- `~ unsafe ... ~ end`: enter the explicit unsafe boundary. Valid programs keep
  backend parity, but the programmer assumes the unchecked-access and syscall
  obligations defined in `../MEMORY_MODEL.md`.
- `$x = expr`: assignment.
- `~ if expr ... optional ~ else ... ~ end`: conditional.
- `~ loop expr ... ~ end`: repeat `expr` times.
- `~ while expr ... ~ end`: while truthy.
- `~ each var in expr ... ~ end`: iterate list/map values; the iterator name
  omits `$` in this declaration position.
- `^ expr`: return from the current function or top-level block.
- `import "module.nx"`: load an external module.

## Expressions
- Literals: numbers (SmallInt/Float), bool (`true`/`false`), strings, lists
  `[expr, ...]`, maps `{key: value}` with identifier keys.
- Variables: `$x`.
- Calls: `callee(arg1, arg2)` for builtins or user functions.
- Indexing: `expr[expr]`.
- Fields: `expr.field`.
- Unary: `!` boolean not, `-` numeric negation.
- Binary: standard arithmetic and logic.

## Actions
- `!say expr` emits an event to the renderer.
- `!ask expr`, `!fetch expr`, and `!log expr` emit bridge runtime events in
  non-plain modes. `!syscall` is parsed only inside an explicit `~ unsafe`
  block.
- Builtin functions live in stdlib collection, graph, and math families.

## Standard I/O

- `read_int()` consumes an exact signed 64-bit token.
- `read_token()` consumes one Unicode-whitespace-delimited text token and
  returns `null` at EOF.
- `read_line()` consumes through the next line feed, strips that line feed and
  one preceding carriage return, and returns `null` at EOF.
- All reads share one cursor over bounded UTF-8 input. `naux run file.nx` reads
  interactively from a terminal; `naux run file.nx < input.txt` consumes a
  deterministic batch tape.
- Normal execution uses plain output: each `!say` becomes its display text and
  one newline. `--mode cli` selects the event-oriented renderer.

The exact cap, terminal behavior, fallback, and non-claims are specified in
[`s1_learn_batch_io.md`](s1_learn_batch_io.md).

## Diagnostics

Common lexer, parser, type, and runtime failures use a single bounded text
shape with stage, message, filename, one-based line and column, source window,
and caret. Normal `run` and `check` agree for frontend failures; ordinary VM
and interpreter execution agree for the same runtime failure. Exact bounds,
terminal escaping, and exclusions are specified in
[`s1_learn_diagnostics.md`](s1_learn_diagnostics.md).

## Semantics
- Parser generates AST with spans stored for error reporting.
- Types are dynamic: `Value` enum (SmallInt/Float/Bool/RcObj/Null).
- The bridge runtime continues to execute annotated and unannotated functions
  dynamically. Exact `Bool`, `I64`, and `F64` annotations are checked where
  supported by the annotated-function path.
- Small ints are preserved until arithmetic requires float or heap values.
- Mutable collection assignment preserves backing identity; mutations are
  observable through aliases.
- Safe indexing, lifetime, check-elision, and unsafe obligations are normative
  in `../MEMORY_MODEL.md`.
- Logical `&&` and `||` short-circuit left to right. Logical `!` and logical
  results use the runtime truthiness boundary consistently in the interpreter
  and VM; the public type checker requires boolean operands when their types
  are statically known.

The narrower learner compatibility promise is versioned separately in
[`s1_learn_quick_reference_v0_1.md`](s1_learn_quick_reference_v0_1.md).

## Style Guide
- Indent with 4 spaces inside blocks.
- Indent nested block markers by four spaces; indentation is conventional, not
  semantic.
- Operators are separated by spaces: `$a + $b`.
- Lists, maps, and strings follow formatter snapshots for canonical layout.
