# NAUX Language Spec (core, 0.2 snapshot)

This document fixes the semantics of the current NAUX core so that changes to implementation do not break behavior.

## Program structure
- A script is a list of statements.
- Blocks are delimited by `~ … ~ end` for `rite`, `if/else`, `loop`, `each`, `while`, `fn`.
- Leading whitespace is ignored; newlines separate statements.

## Statements
- `~ rite … ~ end`: enters a new lexical scope, executes body.
- `~ fn name($p1, $p2, ...) … ~ end`: defines a user function (lexical scope on call).
- `^ expr`: returns from the nearest function/rite block with the evaluated value (null if unreachable).
- `$name = expr`: assigns in current scope (shadows outer).
- `~ if expr … [~ else …] ~ end`: truthy check; nonzero numbers, non-empty strings/collections/graph/function are truthy; null is falsy.
- `~ loop expr … ~ end`: evaluate `expr`; if number > 0, run body that many times (floor to i64).
- `~ each $v in expr … ~ end`: if `expr` evaluates to `List`, iterate items with inner scope binding `$v`.
- `~ while expr … ~ end`: while truthy.
- Actions: `!say/!ui/!text/!button/!fetch/!ask/!log` evaluate their args and emit `RuntimeEvent`.

## Expressions
- Literals: number (f64), bool (`true/false`), text (`"..."`).
- Variables: `$name` style in source; parser stores bare identifier `Var(String)`.
- Unary: `-x` (numeric neg), `!x` (logical not, truthiness).
- Binary with precedence (high→low): `* / %`; `+ -`; comparisons `== != > < >= <=`; `&&`; `||`. Left-associative.
- Calls: `callee(args...)`; callee may be identifier (builtin or user fn) or expression that evaluates to `Function`.
- Index/Field AST nodes exist; if produced, runtime supports list/map index and map field. (Parser literals for list/map are future work.)

## Values
- `Number(f64)`, `Bool`, `Text`, `List`, `Map`, `Graph`, `Set`, `PriorityQueue`, `Function`, `Null`.
- Truthiness: bool value; number ≠ 0; non-empty text/list/map/set/pq; graph/function always truthy; null falsy.
- Equality: numbers by f64 epsilon; graphs/functions compare by pointer identity.

## Functions
- Defined via `~ fn name($a, $b) … ~ end`.
- On call: push new scope, bind params by position (missing args => Null), execute body; `^` returns value; falling off body returns Null.
- Lexical scoping: lookups search innermost → outer.
- Calls dispatch: builtin by name first, then user-defined; calling non-function errors.

## Collections stdlib (builtin functions)
- Set: `set_new() -> Set`; `set_add(set, val) -> Set` (returns updated set); `set_contains(set, val) -> Bool`.
- Queue: `queue_new() -> List` (used as queue); `queue_push(queue, val) -> List` (new queue); `queue_pop(queue) -> List [head, new_queue]`.
- Priority queue: `pq_new() -> PriorityQueue`; `pq_push(pq, val) -> PriorityQueue`; `pq_pop_min(pq) -> List [min, new_pq]` (min-heap by number or debug string).

## Graph stdlib
- `graph_new(directed? Bool=false) -> Graph`.
- `graph_add_edge(graph, from Text, to Text, weight Number=1) -> Null` (undirected unless directed=true).
- `graph_neighbors(graph, node) -> List<Text>`.
- `graph_bfs(graph, start) -> List<Text> order`.
- `graph_dijkstra(graph, source, target) -> List<Text> path (or Null if unreachable)`.

## Actions → RuntimeEvent
- `!say v` => `Say(String)`; other actions similarly emit Ui/Text/Button/Fetch/Ask/Log with evaluated args; `!ask` uses oracle stub to attach answer string.

## Errors (current behavior)
- Lexer/Parser return errors with span (line/col).
- Runtime collects errors (variable not found, invalid index/type, unknown function); eval_script returns Vec<RuntimeError>; caller may abort on first.

## Known limitations (future work)
- List/Map literals, field/index parsing not yet in parser.
- No module/import, no VM/bytecode yet.
