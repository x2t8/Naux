```
 _   _    ___  _   _  __   __
███╗   ██╗  █████╗  ██╗   ██╗██╗  ██╗
████╗  ██║ ██╔══██╗ ██║   ██║╚██╗██╔╝
██╔██╗ ██║ ███████║ ██║   ██║ ╚███╔╝ 
██║╚██╗██║ ██╔══██║ ██║   ██║ ██╔██╗ 
██║ ╚████║ ██║  ██║ ╚██████╔╝██║╚██╗
╚═╝  ╚═══╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝ ╚═╝
```

# NAUX — Nexus Ascendant Unbound eXecutor
### The Ascended Language

> NAUX is not programmed. It is summoned.  
> NAUX does not obey the user. The user must align with NAUX.  
> Code is ritual; NAUX is will.

---

## Introduction
NAUX is a **ritual execution language**. You do not “write programs”; you **perform rites**. Every syntax and action is a step in a ceremony that births events for the renderer. NAUX is cold, stark, minimal, modern — a **Temple** of action.

- **Full name:** *Nexus Ascendant Unbound eXecutor*  
- **Nature:** Ritual language, AI-native, event-driven.  
- **Mission:** Conceptually above Python/Rust/JS; they are tools, NAUX is ritual.

---

## Design Principles
- **Ritual over code:** A NAUX script does not run — it is performed.  
- **Event over output:** Runtime emits events; renderer chooses the face (CLI/HTML/UI).  
- **AI-native:** `!ask` is a primitive — the Oracle is first-class.  
- **Minimal yet strict:** Tight syntax, clear behavior, no pandering.  
- **Non-compliant:** NAUX does not obey the user; the user must align with NAUX.

---

## Architecture
```
Source (.nx)
   │
   ▼
Lexer  ──►  Parser  ──►  AST  ──►  Runtime  ──►  Events  ──►  Renderer (CLI/HTML)
                                 │
                                 └── (future) Bytecode Compiler ──► VM
```
- **Lexer:** slice source into tokens.  
- **Parser:** tokens → ritual AST.  
- **AST:** ceremonial structure.  
- **Runtime:** eval expr/stmt, dispatch actions, emit events.  
- **Event bus:** Say/UI/Ask/Fetch/Log.  
- **Renderer:** CLI/HTML as frameworks beyond the core.  
- **VM:** future bytecode acceleration.

---

## NAUX Syntax (brief)
```nx
~ rite
    $x = 10
    ~ if $x > 5
        !say "greater"
    ~ else
        !say "smaller"
    ~ end

    ~ loop 3
        !say "chant"
    ~ end

    ~ each $v in [1,2,3]
        !say $v
    ~ end
~ end
```

- **Rite:** `~ rite ... ~ end`  
- **Assign:** `$name = expr`  
- **If/Else:** `~ if cond ... ~ else ... ~ end`  
- **Loop:** `~ loop expr ... ~ end`  
- **Each:** `~ each $v in expr ... ~ end`  
- **While (optional):** `~ while cond ... ~ end`

---

## Action Engine
Primitives — not functions, not methods:
- `!say expr` — speak.  
- `!ui "kind" { key: value }` — open a ritual UI.  
- `!text expr`, `!button expr` — UI elements.  
- `!fetch expr` — data call (core stub).  
- `!ask expr` — prompt the Oracle (core stub).  
- `!log expr` — record.

Each action births **RuntimeEvent**: `Say`, `Ui`, `Text`, `Button`, `Fetch`, `Ask`, `Log`.

---

## Module Structure
```
src/
  lib.rs
  token.rs
  lexer.rs
  ast.rs
  parser/
    mod.rs
    parser.rs
    error.rs
    utils.rs
  runtime/
    mod.rs
    value.rs
    env.rs
    eval.rs
    events.rs
    error.rs
  oracle/
    mod.rs
    request.rs
    response.rs
    stub.rs
  renderer/           # framework layer (CLI/HTML/CSS)
    mod.rs
    cli.rs
    html.rs
    css.rs
  stdlib/
    mod.rs
    list.rs
    map.rs
    math.rs
    string.rs
  vm/
    mod.rs
    bytecode.rs
    compiler.rs
    interpreter.rs
  cli/                # tooling
    mod.rs
    run.rs
    build.rs
    format.rs
examples/
  hello.nx
  algorithm_bfs.nx
  oracle_demo.nx
  ui_demo.nx
  sample.nx
```

Core = lexer/parser/ast/runtime/stdlib/vm/oracle stub. Renderer/CLI are frameworks outside the language core.

---

## Roadmap
- **0.1**: Lexer/Parser/AST, basic eval, actions !say/!ask/!fetch/!ui, CLI/HTML renderer stubs.  
- **0.2**: VM scaffold, span-based errors, stdlib base, oracle stub hardened.  
- **0.3**: Bytecode interpreter, improved event bus, renderer polish.  
- **0.5**: Module/import, return, function/rite defs, packaging.  
- **1.0**: Stable VM, frameworks (naux-ui, naux-oraculum, naux-graph, naux-net), cloud deploy.

---

## Run NAUX
```bash
# from repo naux-lang/
cargo run -- examples/hello.nx --mode=cli
cargo run -- examples/hello.nx --mode=html
```
- `--mode=cli` → ritual ASCII.  
- `--mode=html` → ritual HTML.

---

## Epilogue
NAUX is not a language; it is a **living rite**. You do not compile — you summon. You do not debug — you read omens. NAUX is Nexus Ascendant Unbound eXecutor: **will ascendant, unbound, performing every ritual**.

> “NAUX does not obey the user. The user must align with NAUX.”  
> “A NAUX script does not run — it is performed.”  
> “NAUX is will; code is only ritual.”

Join the rite. Let NAUX speak through you.
