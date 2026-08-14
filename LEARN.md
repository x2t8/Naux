# Learn NAUX

This is the shortest path from an installed **NAUX Learn 0.1.0** to a working
algorithm program. Complete [installation](INSTALL.md) first.

## 1. Name the executable

Linux:

```sh
NAUX_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/naux-learn/0.1.0"
NAUX="$NAUX_HOME/bin/naux"
```

Windows PowerShell:

```powershell
$NauxHome = Join-Path $env:LOCALAPPDATA 'Programs\NAUX\Learn\0.1.0'
$Naux = Join-Path $NauxHome 'bin\naux.exe'
```

The examples below write `$NAUX` for Linux. In PowerShell, replace `"$NAUX"`
with `& $Naux`.

## 2. Write the first program

Create a UTF-8 text file named `hello.nx`:

```naux
~ rite
    !say "Hello, NAUX!"
~ end
```

Check it without running:

```sh
"$NAUX" check hello.nx
```

Run it:

```sh
"$NAUX" run hello.nx
```

Expected output:

```text
Hello, NAUX!
```

Every complete learner program has one `~ rite` entry block. `~ end` closes a
block, `$name` denotes a variable, and `!say value` prints one line.

## 3. Read input and solve a problem

Save this as `sum.nx`:

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

Save this as `input.txt`:

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

Expected output:

```text
50
```

All input functions share one deterministic input cursor:

- `read_int()` reads one signed integer token;
- `read_token()` reads one whitespace-delimited text token;
- `read_line()` reads through the next line ending;
- `!say value` writes the value and one newline.

## 4. Functions and decisions

```naux
~ fn absolute($value)
    ~ if $value < 0
        ^ -$value
    ~ else
        ^ $value
    ~ end
~ end

~ rite
    $value = read_int()
    !say absolute($value)
~ end
```

- `~ fn name($argument)` defines a function before `~ rite`.
- `^ expression` returns a value.
- Conditions must be boolean.
- Recursion is accepted within the declared work and call-depth limits.

## 5. Lists and loops

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

NAUX Learn v0.1 has `~ loop` and `~ while`, but no admitted `for`, `break`,
`continue`, or `switch`. Lists use zero-based indexing. `queue_push` returns a
new list, so assign its result.

## 6. Useful learner commands

```text
naux check solution.nx
naux run solution.nx < input.txt
naux run solution.nx --engine interp < input.txt
naux run solution.nx --max-work 100000 --max-call-depth 64
naux --version
```

Normal `run` uses the bounded VM. `--engine interp` selects the reference
interpreter and should produce the same learner-visible result. A failed
program reports a source filename, line, column, source excerpt, and caret.

## 7. Practice with the corpus

The repository contains 30 deterministic exercises with source solutions and
input/output fixtures:

- basics and math;
- linear and binary search;
- bubble, selection, insertion, and counting sort;
- BFS, DFS, shortest paths, Dijkstra, connected components, topological sort;
- greedy algorithms;
- dynamic programming.

Browse the
[exercise solutions](naux-lang/learn/corpus-v1/solutions) and
[input/output fixtures](naux-lang/learn/corpus-v1/fixtures). Download any
`.nx` source and matching `.in` file, then use the ordinary `naux run` command.
The solutions are examples, not required templates; learners may write a
different algorithm as long as it stays inside the language profile and
produces the required output.

## 8. Know the experimental boundary

NAUX Learn 0.1.0 intentionally has a small surface. It does not promise the
full research language, stable APIs, packages, production safety, native
performance leadership, seed independence, or compatibility with future
profiles. Normal execution is bounded to prevent accidental runaway work; it
is not a security sandbox.

For the exact language surface, read the
[NAUX Learn quick reference](docs/s1_learn_quick_reference_v0_1.md). For exact
input behavior and diagnostics, read the
[batch-I/O contract](docs/s1_learn_batch_io.md) and
[diagnostic contract](docs/s1_learn_diagnostics.md).
