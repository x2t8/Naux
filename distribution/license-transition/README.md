# LT1 authority-preserving Apache-2.0 transition

LT1 records 11 exact legal-surface changes and 10 authority-routing workflow
changes from the pre-transition source at commit
`7d270a54c0af7530585fde7be4d9f3f67c15e142` to the current Apache-2.0 grant.
It preserves the old S2, S3, and S4 authorities byte-for-byte.

Default validation checks only bounded repository bytes. Explicit historical
replay materializes a separate snapshot view from the current source plus the
sealed `pre-apache/` files. The working tree is never rewritten.

This bridge exists because exact-file authorities must reject even a legal-only
manifest edit. It does not reinterpret that rejection as a semantic failure,
and it does not permit unrelated source drift. Current CI compiles the current
Apache tree but replays historical authorities only inside the sealed view.
