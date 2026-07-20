# NAUX Language Specification

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
- `~ fn name($a, $b, ...) ... ~ end`: defines a function; parameters are `$`-prefixed.
- `~ unsafe { ... }`: run without safety checks where supported.
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
- Small ints are preserved until arithmetic requires float or heap values.

## Style Guide
- Indent with 4 spaces inside blocks.
- `~` keywords always start at column zero with a single space before payload.
- Operators are separated by spaces: `$a + $b`.
- Lists, maps, and strings follow formatter snapshots for canonical layout.
