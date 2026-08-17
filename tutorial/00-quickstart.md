# NAUX Learn in five minutes

[Tutorial index](README.md) · [Language reference](../docs/s1_learn_quick_reference_v0_1.md)

There is no active public binary release yet. These commands describe the
learner experience being admitted for the next Linux bundle; repository
developers can build the same `naux` executable from source.

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
