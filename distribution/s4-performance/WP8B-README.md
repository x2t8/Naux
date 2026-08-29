# S4-WP8B bounded register-residency contract

WP8B selects one bounded slice of WP8A's highest-ranked structural class. It
does not introduce a general register allocator. Exactly one proven inner-loop
index slot per kernel may move from its stack home to the callee-saved x86-64
register `r12`.

The transform is deliberately narrow:

- four exact WP5C machine identities and four exact slot identities;
- one `i64` promotion per kernel, with no spill or heuristic selection;
- `r12` is saved on entry and restored on every normal return;
- the existing stack frame may remain the same size but cannot grow;
- each target must become strictly smaller than its frozen WP5D parent;
- any failed proof or budget retains the original stack-home target.

The selected slots account for 13,926,800 read/write events in the immutable
WP8A structural profile. That number is not a cycle estimate and does not
predict a speedup. Native execution and a new measurement remain forbidden
until a later work package admits transformed bytes and fresh eligibility.

Default validation reads only sealed repository bytes. It validates the
current LT1 bridge, exact WP8A contract and authority identities, and exact
WP5C/WP5D kernel identities. It does not execute generated code or read a
clock.
