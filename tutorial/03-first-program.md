# Write the First NAUX Program

[Tutorial index](README.md) · [Linux install](01-install-linux.md) ·
[Windows install](02-install-windows.md) · [Algorithms](04-algorithms.md)

Complete one host installation guide first.

## 1. Create `hello.nx`

Use any plain-text editor and save this UTF-8 source:

```naux
~ rite
    !say "Hello, NAUX!"
~ end
```

Every complete learner program has one `~ rite` entry block. `~ end` closes a
block, and `!say value` prints one line.

## 2. Check without running

```sh
naux check hello.nx
```

A valid program exits successfully. A malformed program reports its source
filename, line, column, source excerpt, and caret.

## 3. Run

```sh
naux run hello.nx
```

Expected output:

```text
Hello, NAUX!
```

## 4. Variables, functions, and decisions

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

- `$name` denotes a variable.
- `~ fn name($argument)` defines a function before `~ rite`.
- `^ expression` returns from a function.
- `~ if`, `~ else`, and `~ end` express a decision.
- Conditions must be boolean.
- Direct recursion is available within explicit work and call-depth limits.

Run it directly and enter `-42` when NAUX asks for input:

```sh
naux run absolute.nx
```

For judge-style input, `naux run absolute.nx < input.txt` remains deterministic.
Expected output is `42`.

Continue with [algorithm exercises](04-algorithms.md).
