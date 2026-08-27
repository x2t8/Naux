# S4-WP5D residual x86-64 and ELF64

WP5D lowers every admitted WP5C Machine IR program through one generic
stack-home x86-64 path. The target function uses direct Linux `mmap` and
`munmap` syscalls for the owned list, initializes all 16,384 elements at
runtime, preserves checked list accesses and explicit CFG edges, and returns
the residual checksum in `rax`.

The function is wrapped directly in a deterministic, sectionless ELF64 image.
The image has one R-X load segment, an RW-NX stack declaration, no libc, no
object writer, and no system linker. An independent Python replay parses the
target plan, checks exact Machine IR-to-byte ranges, limits syscalls to
`mmap`/`munmap`/fail-closed `exit`, reconstructs the ELF header and both
program headers, and verifies the embedded target bytes without collecting a
clock.

Validate the static authority:

```bash
python3 scripts/s4_residual_elf64.py
```

Replay a reviewed emitter without executing any generated ELF:

```bash
python3 scripts/s4_residual_elf64.py \
  --binary target/release/examples/naux_s4_residual_elf64
```

The ELF startup currently calls the target and exits successfully. It does
not serialize the checksum protocol. WP5E must add fresh-process checksum and
work parity before any generated image can enter the `naux-residual` role.
