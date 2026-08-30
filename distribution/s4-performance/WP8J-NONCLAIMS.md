# S4-WP8J non-claims

WP8J admits the structure of four candidate timing carriers. It does not admit
a benchmark result, speedup, regression, threshold, optimization claim, or
replacement of the WP5F baseline role.

The two clock syscalls exist only as reviewed machine-code bytes during WP8J
validation. Default validation reads no clock. Replay runs the Rust emitter,
not the generated timing images. Timing-image execution belongs exclusively to
a later controlled-host measurement runner.
