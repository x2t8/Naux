# NAUX Learn in five minutes

[Tutorial index](README.md) · [Language reference](../docs/s1_learn_quick_reference_v0_1.md)

Install the Linux x86-64 GNU experimental pre-release first, or follow the
[source build](../README.md#build-from-source):

```sh
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.4-learn/nauxup.sh | sh
```

## 1. Confirm NAUX

```sh
naux --version
```

## 2. Create `hello.nx`

```naux
~ rite
    !say "Hello, NAUX!"
~ end
```

## 3. Check and run

```sh
naux check hello.nx
naux run hello.nx
```

NAUX prints only explicit program output. `^ value` returns a value to the
caller (or from the top-level entry) but does not print it. Use `!say value`
whenever the result must appear in the terminal or an online judge's stdout.

## 4. Read from the keyboard

Create `double.nx`:

```naux
~ rite
    $number = read_int()
    !say $number * 2
~ end
```

Run it, type a number at `input>`, and press Enter:

```sh
naux run double.nx
```

For an online judge or script, redirect the same input instead:

```sh
naux run double.nx < input.txt
```

NAUX owns neither source file. `nauxup uninstall` removes only the verified
toolchain, launchers, and receipts created by Setup.
