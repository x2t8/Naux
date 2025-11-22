Naux Ritual Language (NRL) 0.1 – Rust parser/CLI
================================================

Rust implementation that lexes/parses `.nx` files and emits JSON AST per the 0.1 spec (UTF-8, case-sensitive, `~ rite Name ... ~ end`, statements per line, actions `!`, assignments `$`, loops `@loop`, optional `@if`, comments `#`/`#>`, strings, numbers, colors, vars, idents, symbols `= -> .`).

Quick start (Rust)
------------------

```
cd naux-rs
cargo run -- ../examples/sample.nx --mode=json   # AST/runtime events as JSON (default)
cargo run -- ../examples/sample.nx --mode=cli    # ASCII UI renderer
cargo run -- ../examples/sample.nx --mode=html   # HTML renderer
```

If `cargo` is missing on your machine, install Rust toolchain first (rustup) or drop the code into an environment with Rust.

Interpreter / runtime
---------------------

- Runtime values/events are in `naux-rs/src/runtime.rs`.
- Run the interpreter (parsing + execution) via `cargo run -- ../examples/sample.nx`; output is runtime events as JSON (e.g., `Say`, `SetVar`, `Ui*`).

Project layout
--------------

- `naux-rs/Cargo.toml` – Rust crate manifest.
- `naux-rs/src/ast.rs` – AST structures and `to_json` helpers.
- `naux-rs/src/lexer.rs` – tokenizer (comments, strings, numbers, colors, symbols, vars, idents, newline).
- `naux-rs/src/parser.rs` – recursive-descent parser for program/rituals/statements/args/expressions/conditions.
- `naux-rs/src/runtime.rs` – interpreter (Context, Value, RuntimeEvent, Eval).
- `naux-rs/src/renderer.rs` – CLI/HTML renderers from runtime events.
- `naux-rs/src/main.rs` – CLI: reads `.nx` file, runs ritual (default `Main`), prints runtime events (JSON/CLI/HTML).
- `examples/sample.nx` – sample program covering the syntax.

Notes / assumptions
-------------------

- Color literals win over comments except when the line starts with `#>` (explicit comment). `#ff00ff` inside code is treated as color, while `# comment` at line start is skipped.
- Assignment RHS accepts any expression; spec 0.1 primarily uses action expressions.
- Condition parsing is simple: `Value (==|!=|>|>=|<|<=) Value` or a single truthy `Value`.
- Callback `-> !action ...` becomes a nested `Action` on the parent action.
