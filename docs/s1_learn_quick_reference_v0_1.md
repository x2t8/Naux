# NAUX Learn quick reference v0.1

Status: accepted\
Date: 2026-08-12\
Scope: S1 / NAUX Learn learner-facing compatibility profile

This is the short reference for programs intended to run as NAUX Learn v0.1
exercises. It deliberately describes less than the complete experimental
repository. Behavior outside the admitted profile below is not an S1
compatibility promise.

## Run and check

```text
naux check solution.nx
naux run solution.nx < input.txt
naux run solution.nx --engine interp < input.txt
naux run solution.nx --max-work 100000 --max-call-depth 64
```

Normal `run` uses the VM and plain output. `--engine interp` selects the
reference Surface interpreter. S1 examples must agree on observable output in
both. A requested JIT may visibly fall back to the VM for input operations and
is not part of the S1 performance promise.

## Source and names

- Source and batch input are UTF-8.
- `#` starts a line comment outside a string.
- A variable is written `$name`; function and builtin names omit `$` at call
  sites.
- Identifiers begin with `_` or a Unicode alphabetic character and continue
  with `_` or Unicode alphanumeric characters.
- Indent blocks by four spaces. Indentation improves readability but is not a
  scope mechanism; `~ end` closes a block.

## Complete program shape

Top-level functions precede one `~ rite` entry block:

```text
~ fn function_name($argument)
    ^ result
~ end

~ rite
    # entry statements
~ end
```

`^ expression` returns from the current function. A top-level return value is
not printed by plain mode; use `!say expression` for deterministic output.

## Values and variables

| Form | Meaning in S1 |
|---|---|
| `42`, `-7` | learner-profile integer-valued numbers |
| `true`, `false` | booleans |
| `"text"` | text; `\n`, `\t`, `\"`, and `\\` escapes are accepted |
| `[1, 2, 3]` | list |
| `{count: 3, total: 9}` | map with identifier keys |
| `null` | runtime absence value; there is no source literal in v0.1 |

Assignment creates or rebinds a variable:

```text
$answer = 42
$answer = $answer + 1
```

List and map values have shared backing identity when assigned to another
variable. Indexed assignment mutates that shared value. `queue_push(list,
value)` instead returns a new list, so assign its result.

## Operators

From tighter to looser binding:

| Operators | Meaning |
|---|---|
| unary `!`, unary `-` | boolean not, numeric negation |
| `*`, `/`, `%` | multiply, divide, remainder |
| `+`, `-` | numeric arithmetic; `+` also concatenates when text participates |
| `<<` | integer left shift |
| `^` | integer xor when used inside an expression |
| `==`, `!=`, `<`, `<=`, `>`, `>=` | numeric comparisons in the S1 profile |
| `&&` | boolean and |
| `||` | boolean or |

`&&` and `||` evaluate left to right and short-circuit the unselected right
operand. Their result is boolean. Known operands of `!`, `&&`, `||`, `~ if`,
and `~ while` must type-check as boolean.

`/` is numeric division and may produce a non-integral result. Division or
remainder by zero is a runtime error. S1 exercises use integer-valued inputs
and intermediate results small enough to avoid overflow and large-literal
rounding; overflow, NaN/infinity, and integers outside the exactly represented
learner range are not v0.1 compatibility promises.

## Control flow

```text
~ if $condition
    # then branch
~ else
    # optional else branch
~ end

~ loop $non_negative_integer_count
    # fixed repetitions
~ end

~ while $condition
    # repeated while condition is true
~ end
```

There is no admitted `break`, `continue`, `for`, or `switch` spelling in S1
v0.1. Use a boolean state variable or a function return when early exit is
needed.

Functions use call-by-value bindings. Lists and maps passed as values retain
their shared backing identity. Direct and recursive calls are accepted. Normal
`run` admits at most 1,000,000 semantic work checkpoints and 128 active user
function calls by default. Positive CLI overrides are bounded by hard ceilings
of 10,000,000 checkpoints and depth 512. A checkpoint is an executable source
statement, an entered loop iteration, or an entered user function; it is not a
VM instruction. Limit failures are source-positioned and suppress buffered
stdout. See the [bounded execution envelope](s1_learn_execution_envelope.md).
There is no general wall-clock or operating-system memory cap.

## Lists and maps

```text
$values = [3, 5, 8]
$first = $values[0]
$values[1] = 10
$size = len($values)
$values = queue_push($values, 13)

$record = {name: "NAUX", score: 42}
$name = $record.name
$score = $record["score"]
```

S1 list indices are integers. A negative or otherwise out-of-range read
returns `null`; a fractional or wrong-kind read index reports an error. A
negative, fractional, or out-of-range write reports an error. Map lookup by
text and field access return `null` for a missing key. The corpus uses
`queue_push` as the generic list-growth operation and does not present an
algorithm-specific host builtin as student-written work.

## Deterministic batch input and output

- `read_int()` consumes one signed 64-bit integer token; malformed input or EOF
  is a source-positioned runtime error.
- `read_token()` consumes one Unicode-whitespace-delimited token and returns
  text, or `null` at EOF.
- `read_line()` consumes from the shared cursor through the next LF, removes
  that LF and one preceding CR, and returns `null` at EOF.
- All reads share one cursor over a valid UTF-8 tape of at most 8 MiB.
- Each `!say value` emits its display text followed by exactly one LF in plain
  mode. Ordinary successful judge-style execution emits no stderr banner.

Exact cursor and terminal behavior is defined by the
[batch-I/O contract](s1_learn_batch_io.md). Exact error shape and terminal
safety is defined by the [diagnostic contract](s1_learn_diagnostics.md).

## Diagnostics

Normal lexer, parser, type, and runtime failures use one bounded form:

```text
error: Type error: message
 --> solution.nx:2:14
  |
2 |     source line
  |              ^
```

Failed `run` and early failed `check` do not emit partial stdout. Treat the
stage, message, filename, one-based line/column, bounded source window, and
caret as the S1 text contract; warnings, recovery, fix-its, and an IDE wire
format are outside v0.1.

## Executed reference examples

The WP4 carrier verifies that the following three source, input, and output
blocks remain byte-identical to their checked-in fixtures, then executes each
source through normal VM and interpreter CLI paths.

### Control, functions, comments, and short-circuiting

```naux
~ fn classify($value)
    ~ if $value % 2 == 0
        ^ "even"
    ~ else
        ^ "odd"
    ~ end
~ end

~ rite
    # The unselected expressions must not divide by zero.
    $and_guard = false && (1 / 0 > 0)
    $or_guard = true || (1 / 0 > 0)
    $value = read_int()
    !say classify($value)
    !say !$and_guard
    !say $or_guard
~ end
```

```stdin
7
```

```stdout
odd
true
true
```

### Lists, mutation, loops, and maps

```naux
~ rite
    $count = read_int()
    $values = []
    ~ loop $count
        $values = queue_push($values, read_int())
    ~ end
    $values[1] = 10
    $total = 0
    $i = 0
    ~ while $i < len($values)
        $total = $total + $values[$i]
        $i = $i + 1
    ~ end
    $summary = {count: $count, total: $total}
    !say $summary.count
    !say $summary["total"]
~ end
```

```stdin
4
3 4 5 6
```

```stdout
4
24
```

### Recursion

```naux
~ fn gcd($left, $right)
    ~ if $right == 0
        ^ $left
    ~ else
        ^ gcd($right, $left % $right)
    ~ end
~ end

~ rite
    !say gcd(read_int(), read_int())
~ end
```

```stdin
1071 462
```

```stdout
21
```

The larger versioned suite is the
30-exercise corpus in the source repository.

## Explicit exclusions

S1 v0.1 does not promise floating-point/scientific computing, bytes, imports,
anonymous functions, annotations, `~ each`, unsafe/syscalls, UI actions,
effects, regions, ownership, algorithm-specific host builtins, JIT/native
execution, native performance, a package format, a stable general language
ABI, production safety, seed independence, self-generation, or compiler
generation. Experimental repository surfaces do not silently enter this
learner compatibility profile.

## Acceptance evidence

The v0.1 reference carrier keeps all three source/input/output examples
byte-identical to their fixtures and executes them through both normal VM and
interpreter CLI paths. Default and all-feature S1 groups each pass 13 tests;
the backend parity carrier passes 31 tests. The final all-feature workspace
exits successfully with 439 library tests passed, zero failed, and six
intentionally ignored. Strict all-target/all-feature Clippy, formatting, diff,
and the 159-file documentation audit pass with zero broken local links.
