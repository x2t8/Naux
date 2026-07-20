# Compiler and Execution Pipeline

This is the active high-level pipeline for `naux-lang`.

## Frontend
1. Lexing (`lexer.rs`)
   - Tokenization with span tracking.
2. Parsing (`parser/`)
   - Builds AST and reports syntax errors with source spans.
3. Typecheck (`typecheck.rs`)
   - Validates core typing constraints before execution paths.

## Lowering
4. AST -> IR (`vm/compiler.rs`)
   - Produces stack-oriented IR instructions.
5. IR -> Bytecode (`vm/bytecode.rs`)
   - Produces VM program for interpreter/JIT paths.

## Refinement And SEFO Proof Loop
6. Refinement -> ProofSlot -> E-graph -> Materialization
   - Refinement evidence is attached during IR lowering.
   - E-graph rewrites emit proof obligations as discharged, blocked, or deferred.
   - Proof-gated materialization rewrites executable IR only after the e-graph
     confirms the guarded equivalence.
   - `naux dev refine --strict` and `NAUX_IR_PROOF_STRICT=1` run the current
     strict proof contract.

See `phase1_proof_contract.md` for the active Phase 1 contract.

## SSA Construction (analysis/optimization path)
7. IR -> SSA preview (`vm/ssa.rs`)
   - Builds CFG with explicit terminators (no implicit fallthrough).
   - Computes dominator tree and dominance frontier.
   - Runs phi placement (Cytron-style) and rename.
   - Verifies SSA invariants (def-use, dominance, phi correctness).

## Execution Engines
8. Runtime interpreter path (`runtime/`)
   - AST-based runtime evaluation and event emission.
9. VM path (`vm/interpreter.rs`, `vm/run.rs`)
   - Bytecode interpreter with builtin bridge.
10. Typed trace JIT path (`vm/jit.rs`, `vm/typed.rs`)
   - Native execution for supported hot paths with fallback behavior.

## Tooling
11. CLI/dev commands (`cli/`)
   - `run`, `fmt`, `test`, `dev ir`, `dev disasm`, `dev bench`.

## Quality Gate
Run before commit:

```bash
cargo fmt --manifest-path naux-lang/Cargo.toml --all -- --check
cargo clippy --manifest-path naux-lang/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path naux-lang/Cargo.toml --all-features
NAUX_IR_PROOF_STRICT=1 cargo test -p naux --test refinement_closed_loop_tests
```
