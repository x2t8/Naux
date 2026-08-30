# S4-WP8G non-claims

WP8G admits fresh-process checksum and terminal work-state parity for exactly
four sealed Linux x86-64 candidates. It does not claim timing, speedup,
benchmark-role replacement, portability, security, sandboxing, production
readiness, or performance against C or any other implementation.

The process timeout is a safety bound, not timing evidence. Any parent drift,
hash mismatch, malformed record, nonzero exit, stderr output, wrong checksum,
wrong terminal counter, nonzero owner, or nondeterminism fails closed and keeps
the frozen WP5D target as rollback authority.
