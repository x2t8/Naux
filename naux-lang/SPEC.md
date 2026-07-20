# NAUX Language Spec (core, 0.2 snapshot)

This document fixes the semantics of the current NAUX core so implementation changes do not break behavior.

## Program Structure
- A script is a list of statements.
- Blocks are delimited by `~ ... ~ end` for `rite`, `if/else`, `loop`, `each`, `while`, and `fn`.
- Leading whitespace is ignored; newlines separate statements.

## Statements
- `~ rite ... ~ end`: enters a lexical scope and executes the body.
- `~ fn name($p1, $p2, ...) ... ~ end`: defines a user function.
- `^ expr`: returns from the nearest function or rite block with the evaluated value.
- `$name = expr`: assigns in the current scope and may shadow outer bindings.
- `~ if expr ... [~ else ...] ~ end`: truthy check.
- `~ loop expr ... ~ end`: evaluate `expr`; if number > 0, run body that many times (floor to i64).
- `~ each $v in expr ... ~ end`: if `expr` evaluates to a list, iterate items with inner binding `$v`.
- `~ while expr ... ~ end`: loop while truthy.
- Actions: `!say/!ui/!text/!button/!fetch/!ask/!log` evaluate args and emit `RuntimeEvent`.

## Expressions
- Literals: number (f64), bool (`true/false`), text (`"..."`).
- Variables: `$name` style in source; parser stores bare identifier `Var(String)`.
- Unary: `-x` for numeric negation, `!x` for logical not.
- Binary precedence from high to low: `* / %`; `+ -`; comparisons `== != > < >= <=`; `&&`; `||`.
- Calls: `callee(args...)`; callee may be a builtin, user function, or function value.
- Index and field AST nodes exist; runtime supports list/map index and map field where parsed.

## Values
- `Number(f64)`, `Bool`, `Text`, `List`, `Map`, `Graph`, `Set`, `PriorityQueue`, `Function`, `Null`.
- Truthiness: bool value; number != 0; non-empty text/list/map/set/pq; graph/function always truthy; null falsy.
- Equality: numbers by f64 epsilon; graphs/functions compare by pointer identity.

## Functions
- Defined via `~ fn name($a, $b) ... ~ end`.
- On call: push new scope, bind params by position, execute body; `^` returns value; falling off body returns Null.
- Lexical scoping: lookups search innermost to outermost.
- Calls dispatch builtin by name first, then user-defined; calling non-function errors.

## Collections Stdlib
- Set: `set_new() -> Set`; `set_add(set, val) -> Set`; `set_contains(set, val) -> Bool`.
- Queue: `queue_new() -> List`; `queue_push(queue, val) -> List`; `queue_pop(queue) -> List [head, new_queue]`.
- Priority queue: `pq_new() -> PriorityQueue`; `pq_push(pq, val) -> PriorityQueue`; `pq_pop_min(pq) -> List [min, new_pq]`.

## Graph Stdlib
- `graph_new(directed? Bool=false) -> Graph`.
- `graph_add_edge(graph, from Text, to Text, weight Number=1) -> Null`.
- `graph_neighbors(graph, node) -> List<Text>`.
- `graph_bfs(graph, start) -> List<Text> order`.
- `graph_dijkstra(graph, source, target) -> List<Text> path or Null`.

## Actions -> RuntimeEvent
- `!say v` => `Say(String)`.
- Other actions emit Ui/Text/Button/Fetch/Ask/Log with evaluated args.
- `!ask` uses the configured runtime stub to attach an answer string.

## Errors
- Lexer/parser return errors with span (line/col).
- Runtime errors include variable not found, invalid index/type, and unknown function.

## Known Limitations
- Some surface syntax and VM paths are still evolving.
