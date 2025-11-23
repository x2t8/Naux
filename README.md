_   _    ___  _   _  __   __
███╗   ██╗  █████╗  ██╗   ██╗██╗  ██╗
████╗  ██║ ██╔══██╗ ██║   ██║╚██╗██╔╝
██╔██╗ ██║ ███████║ ██║   ██║ ╚███╔╝
██║╚██╗██║ ██╔══██║ ██║   ██║ ██╔██╗
██║ ╚████║ ██║  ██║ ╚██████╔╝██║╚██╗
╚═╝  ╚═══╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝ ╚═╝

NAUX — Nexus Ascendant Unbound eXecutor

The Ascended Language

> NAUX is not programmed. It is summoned.
Code is ritual; NAUX is will.




---

Architecture

Source (.nx)
   │
   ▼
Lexer → Parser → AST → Runtime → Events → Renderer (CLI/HTML)
                       │
                       └─ VM/Bytecode (compute path)


---

Algorithm & Graph Features

✦ Collections stdlib: set / queue / priority queue / stack / DSU / segment tree
✦ Graph stdlib: graph_new / add_edge / neighbors / bfs / dijkstra
✦ Math/algorithm stdlib: gcd / lcm / pow_mod / sieve, lis_length / knapsack_01 / bounds
✦ Functions + import to build NAUX-written libraries


---

BFS Example (snippet)

$g = graph_new()
$_ = graph_add_edge($g, "A", "B", 1)
$_ = graph_add_edge($g, "A", "C", 1)
$order = graph_bfs($g, "A")
!say $order


---

Dijkstra Example (snippet)

$g = graph_new(true)
$_ = graph_add_edge($g, "S", "A", 1)
$_ = graph_add_edge($g, "A", "B", 2)
$_ = graph_add_edge($g, "B", "T", 1)
$path = graph_dijkstra($g, "S", "T")
!say $path


---

Syntax Quick View

~ fn add($a, $b)
    ^ $a + $b
~ end

import "lib.nx"

~ rite
    $x = add(2, 3)
    ~ if $x > 4
        !say "ok"
    ~ else
        !say "fail"
    ~ end
~ end


---

VM (Skeleton)

The bytecode instruction set is defined (Push/Load/Store, arithmetic/logic, Jump/JumpIfFalse, CallBuiltin, Return) with compiler + interpreter modules prepared for future optimization.


---

CLI

naux run                           # run main.nx with default engine (vm + cli)
naux run examples/graph_bfs.nx     # specify file, can add --mode=html --engine=jit
naux build                         # read naux.toml, rerun script, output build/main.(txt|html)
naux fmt                           # format main.nx, src/**/*.nx, tests/**/*.nx
naux fmt --check                   # check only, no modification
naux test                          # run tests/**/*_test.nx via VM and report PASS/FAIL
naux dev run path/to/file.nx --engine jit --mode html
naux dev ir path/to/file.nx        # print mid-stage IR (IR + bytecode)
naux dev disasm path/to/file.nx    # print disassembled bytecode
naux dev bench path/to/file.nx --engine vm --iters 100

naux build uses naux.toml, for example:

[project]
name = "myapp"
version = "0.1.0"

[build]
entry = "main.nx"
mode = "cli"    # or html
engine = "vm"   # or jit
output = "build"

naux fmt uses the AST to reprint code with 4-space indentation, leading ~, and clean operator spacing.


---

Examples

examples/graph_bfs.nx

examples/graph_dijkstra.nx

examples/algo_lis.nx

examples/algo_knapsack.nx

examples/bench.rs
