# Practice Algorithms with NAUX Learn

[Tutorial index](README.md) · [First program](03-first-program.md) ·
[Language reference](../docs/s1_learn_quick_reference_v0_1.md)

Learners may solve a problem in their own style. The corpus solutions are
examples, not mandatory templates; a different source algorithm is valid when
it stays inside the admitted language profile and produces the required
output.

## Deterministic input and output

- `read_int()` reads one signed integer token.
- `read_token()` reads one whitespace-delimited text token.
- `read_line()` reads through the next line ending.
- All input functions share one deterministic cursor.
- `!say value` writes the value followed by exactly one newline.

## Example: sum `n` integers

Save as `sum.nx`:

```naux
~ rite
    $n = read_int()
    $sum = 0
    ~ loop $n
        $sum = $sum + read_int()
    ~ end
    !say $sum
~ end
```

Save as `input.txt`:

```text
5
10 -3 5 30 8
```

Linux:

```sh
"$NAUX" run sum.nx < input.txt
```

Windows PowerShell:

```powershell
Get-Content -Raw input.txt | & $Naux run sum.nx
```

Expected output is `50`.

## Example: list maximum

```naux
~ rite
    $n = read_int()
    $values = []
    ~ loop $n
        $values = queue_push($values, read_int())
    ~ end

    $maximum = $values[0]
    $i = 1
    ~ while $i < len($values)
        ~ if $values[$i] > $maximum
            $maximum = $values[$i]
        ~ end
        $i = $i + 1
    ~ end
    !say $maximum
~ end
```

Lists use zero-based indexing. `queue_push` returns a new list, so assign its
result. NAUX Learn v0.1 admits `~ loop` and `~ while`, but no `for`, `break`,
`continue`, or `switch` spelling.

## Useful commands

```text
naux check solution.nx
naux run solution.nx < input.txt
naux run solution.nx --engine interp < input.txt
naux run solution.nx --max-work 100000 --max-call-depth 64
```

Normal `run` uses the bounded VM. `--engine interp` selects the reference
interpreter; both must agree on learner-visible output within this profile.

## The 30-exercise corpus

The public corpus includes:

- basics and math;
- linear search, binary search, and prefix sums;
- bubble, selection, insertion, and counting sort;
- BFS, DFS, shortest paths, Dijkstra, connected components, and topological
  sort;
- greedy algorithms;
- dynamic programming.

Browse the
[source solutions](../naux-lang/learn/corpus-v1/solutions) and
[input/output fixtures](../naux-lang/learn/corpus-v1/fixtures). Download any
`.nx` source and matching `.in` fixture and execute it through ordinary
`naux run`.

## Resource limits

Normal learner execution is bounded to reduce accidental runaway work. The
defaults are 1,000,000 semantic work checkpoints and 128 active user calls;
positive CLI overrides have hard ceilings. These limits are not a security
sandbox or an operating-system memory limit. See the
[execution envelope](../docs/s1_learn_execution_envelope.md).
