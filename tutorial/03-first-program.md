# Write the First NAUX Program

[Tutorial index](README.md) · [Linux install](01-install-linux.md) ·
[Windows install](02-install-windows.md) · [Algorithms](04-algorithms.md)

Complete one host installation guide first.

## 1. Name the executable

Linux:

```sh
NAUX=naux
```

Windows PowerShell:

```powershell
$NauxHome = Join-Path $env:LOCALAPPDATA 'Programs\NAUX\Learn\0.1.0'
$Naux = Join-Path $NauxHome 'bin\naux.exe'
```

The examples below write `"$NAUX"` for Linux. In PowerShell, replace it with
`& $Naux`.

## 2. Create `hello.nx`

Use any plain-text editor and save this UTF-8 source:

```naux
~ rite
    !say "Hello, NAUX!"
~ end
```

Every complete learner program has one `~ rite` entry block. `~ end` closes a
block, and `!say value` prints one line.

## 3. Check without running

Linux:

```sh
"$NAUX" check hello.nx
```

Windows PowerShell:

```powershell
& $Naux check hello.nx
```

A valid program exits successfully. A malformed program reports its source
filename, line, column, source excerpt, and caret.

## 4. Run

Linux:

```sh
"$NAUX" run hello.nx
```

Windows PowerShell:

```powershell
& $Naux run hello.nx
```

Expected output:

```text
Hello, NAUX!
```

## 5. Variables, functions, and decisions

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

Save `-42` in `input.txt`, then run:

Linux:

```sh
"$NAUX" run absolute.nx < input.txt
```

Windows PowerShell:

```powershell
Get-Content -Raw input.txt | & $Naux run absolute.nx
```

Expected output is `42`.

Continue with [algorithm exercises](04-algorithms.md).
