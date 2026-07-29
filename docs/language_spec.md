# NAUX Language Specification

Status: current Surface NAUX 0.2 bridge behavior

This document describes the currently admitted public Surface language.
Observable behavior is governed by `../PARITY_CONTRACT.md` and
`../MEMORY_MODEL.md`.

## Overview
- Ritual-first syntax: programs are built from `~` blocks such as rite, function, and control-flow blocks.
- `$` prefixes locals/variables; `!` prefixes runtime actions; `^` returns a value.
- Comments are not supported yet in spec 0.2.

## Lexical Rules
- Identifiers: ASCII letters, numbers, and underscore; must start with a letter.
- Numbers: integer or floating literal, optional sign.
- Strings: double quoted with escapes.
- Operators: `+ - * / % == != > >= < <= && ||`.
- Block markers: `~` keywords must begin at column 0 with a following space before payload.

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
- `~ each $var in expr ... ~ end`: iterate list/map values.
- `^ expr`: return from the current function or top-level block.
- `~ import "module.nx"`: load an external module.

## Expressions
- Literals: numbers (SmallInt/Float), bool (`true`/`false`), strings, lists `[expr, ...]`, maps `{ "key": value }`.
- Variables: `$x`.
- Calls: `callee(arg1, arg2)` for builtins or user functions.
- Indexing: `expr[expr]`.
- Fields: `expr.field`.
- Unary: `!` boolean not, `-` numeric negation.
- Binary: standard arithmetic and logic.

## Actions
- `!say expr` emits an event to the renderer.
- `!ask expr` emits ask/response events through the configured runtime stub.
- `!fetch expr`, `!log expr`, `!ui kind`, `!text expr`, `!button expr` emit runtime events.
- Builtin functions live in stdlib collection, graph, and math families.

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

## Style Guide
- Indent with 4 spaces inside blocks.
- `~` keywords always start at column zero with a single space before payload.
- Operators are separated by spaces: `$a + $b`.
- Lists, maps, and strings follow formatter snapshots for canonical layout.
