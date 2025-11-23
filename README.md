_   _    ___  _   _  __   __
███╗   ██╗  █████╗  ██╗   ██╗██╗  ██╗
████╗  ██║ ██╔══██╗ ██║   ██║╚██╗██╔╝
██╔██╗ ██║ ███████║ ██║   ██║ ╚███╔╝ 
██║╚██╗██║ ██╔══██║ ██║   ██║ ██╔██╗ 
██║ ╚████║ ██║  ██║ ╚██████╔╝██║╚██╗ 
╚═╝  ╚═══╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝ ╚═╝ 

# NAUX — Nexus Ascendant Unbound eXecutor
### The Ascended Language

> NAUX is not programmed. It is summoned.
> Code is ritual; NAUX is will.

## Architecture
```
Source (.nx)
   │
   ▼
Lexer → Parser → AST → Runtime → Events → Renderer (CLI/HTML)
                       │
                       └─ VM/Bytecode (compute path)
```

## Algorithm & Graph features
- Collections stdlib: set/queue/priority queue/stack/dsu/segment tree.
- Graph stdlib: graph_new/add_edge/neighbors/bfs/dijkstra.
- Math/algo stdlib: gcd/lcm/pow_mod/sieve, lis_length/knapsack_01/bounds.
- Functions + import to build NAUX-written libraries.

### BFS example (snippet)
```nx
$g = graph_new()
$_ = graph_add_edge($g, "A", "B", 1)
$_ = graph_add_edge($g, "A", "C", 1)
$order = graph_bfs($g, "A")
!say $order
```

### Dijkstra example (snippet)
```nx
$g = graph_new(true)
$_ = graph_add_edge($g, "S", "A", 1)
$_ = graph_add_edge($g, "A", "B", 2)
$_ = graph_add_edge($g, "B", "T", 1)
$path = graph_dijkstra($g, "S", "T")
!say $path
```

## Syntax quick view
```nx
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
```

## VM (skeleton)
Bytecode instr set defined (Push/Load/Store, arith/logic, Jump/JumpIfFalse, CallBuiltin, Return) with compiler and interpreter modules ready for future optimization.

## CLI
```
naux run                           # chạy main.nx bằng engine mặc định (vm + cli)
naux run examples/graph_bfs.nx     # chỉ định file, có thể thêm --mode=html --engine=jit
naux build                         # đọc naux.toml, chạy lại script và xuất build/main.(txt|html)
naux fmt                           # format toàn bộ main.nx, src/**/*.nx, tests/**/*.nx
naux fmt --check                   # chỉ kiểm tra không sửa
naux test                          # chạy tests/**/*_test.nx qua VM và báo PASS/FAIL
naux dev run path/to/file.nx --engine jit --mode html
naux dev ir path/to/file.nx        # in IR giữa (IR + bytecode)
naux dev disasm path/to/file.nx    # in bytecode khung disasm
naux dev bench path/to/file.nx --engine vm --iters 100
```

`naux build` dùng `naux.toml` (ví dụ):
```toml
[project]
name = "myapp"
version = "0.1.0"

[build]
entry = "main.nx"
mode = "cli"    # hoặc html
engine = "vm"   # hoặc jit
output = "build"
```

`naux fmt` dùng AST để in lại đoạn mã theo indent 4 spaces, dấu `~` đầu dòng và chia cách toán tử.

## Examples
- `examples/graph_bfs.nx`
- `examples/graph_dijkstra.nx`
- `examples/algo_lis.nx`
- `examples/algo_knapsack.nx`
 - `examples/bench.rs`
