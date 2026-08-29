# S4-WP8A performance-gap forensics

WP8A explains the first controlled S4 threshold rejection before NAUX changes
an optimizer or repeats a measurement. Default validation is static and cannot
read a bundle, inspect the host, read a clock, execute generated native code,
or use a foreign disassembler.

Explicit analysis requires both the immutable first WP7C bundle and the
reviewed WP5D emitter:

```text
python3 scripts/s4_performance_gap_forensics.py \
  --bundle benchmarks/local/s4/first-controlled-7d270a5/WP7C-EVIDENCE \
  --emitter target/debug/examples/naux_s4_residual_elf64
```

The gate first performs the complete WP7D replay. It then proves that each
measured NAUX timing artifact contains the exact WP5E process target rebuilt
from the exact WP5D parent. WP5D's independent encoder replay supplies exact
operation byte ranges and WP5C residual instruction correspondence.

A bounded target-plan interpreter evaluates those operations without launching
the generated target. It must reproduce all four checksum oracles, consume the
owned list, and produce exact block, operation, and terminator visit counts.
The report combines those counts with encoding ranges and template-level
stack/heap/bounds facts.

Candidate ranks are diagnostic priorities measured in structural dynamic
events. They are not cycle attribution, optimizer selection, or permission to
change target bytes. WP8B must freeze a separate proof-preserving transform
contract first.

## First controlled finding

Clock-free replay of the immutable first bundle reproduces all four checksum
oracles and records 17,204,168; 22,406,362; 15,565,768; and 19,661,768 bounded
target-plan steps. The exact structural ranking is:

1. register-resident hot state: 145,291,757 dynamic stack-state events;
2. loop-invariant static materialization: 10,650,200 repeated events;
3. checked-list proof hoisting: 4,096,000 dynamic checks;
4. neutral arithmetic erasure: 1,638,400 dynamic events.

The four measured artifacts share a 608-byte ELF/carrier prefix and a fixed
77-byte post-target completion verifier. Their parent target bodies are 993,
1,188, 950, and 1,071 bytes respectively. The report keeps these fixed carrier
costs separate from target-body exposure; it does not assign elapsed cycles to
any structural class.

Ten focused tests cover static admission, complete oracle replay, implicit
unsourced `goto` encoding, exact result shape, deterministic full-bundle
analysis, measured-artifact mutation, wrong-oracle rejection, and the bounded
interpreter step ceiling. Hosted CI has no private-bundle input and therefore
replays only the public clock-free structure.
