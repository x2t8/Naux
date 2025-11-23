# NAUX IR v0.1 — Stack-Based Spec

This is the official description of the VM-facing IR v0.1 that NAUX generates before bytecode. It is intentionally small and numeric/text-free enough to be easy to JIT later.

## Instruction Set (and stack effect)

| Instr | Stack effect | Note |
| --- | --- | --- |
| `ConstNum(f64)` | +1 | push number |
| `ConstBool(bool)` | +1 | push bool |
| `ConstText(String)` | +1 | push string |
| `PushNull` | +1 | push null |
| `LoadVar(String)` | +1 | lexical lookup by name |
| `StoreVar(String)` | -1 | pop → assign into current frame |
| `LoadLocal(u16)` | +1 | (planned) slot load |
| `StoreLocal(u16)` | -1 | (planned) slot store |
| `Add/Sub/Mul/Div/Mod` | -1 (pop 2 → push 1) | numeric ops |
| `Eq/Ne/Gt/Ge/Lt/Le` | -1 (pop 2 → push bool) | comparisons |
| `And/Or` | -1 (pop 2 → push bool) | short-circuit is encoded by jumps, so op itself is boolean OR/AND |
| `Jump(usize)` | 0 | ip = target |
| `JumpIfFalse(usize)` | -1 | pop cond; if false → ip = target |
| `CallBuiltin(name, argc)` | -argc +1 | pop args (right-to-left), call host fn, push return |
| `CallFn(name, argc)` | -argc +1 | user fn; will fallback to builtin if not found |
| `MakeList(len)` | -len +1 | pop len values, reverse, build list |
| `MakeMap(keys)` | -\|keys\| +1 | pop values in reverse order, zip with keys |
| `LoadField(field)` | -1 +1 | pop map, push value or Null |
| `EmitSay/EmitAsk/EmitFetch/EmitUi(kind)/EmitText/EmitButton/EmitLog` | varies | Emit* that needs data pops 1; `EmitUi` pops 0 |
| `Return` | 0 or -1 | if stack empty → Null; else pop top and return |

## Frame / locals model

- A frame is a `HashMap<String, Value>` (v0.1).  
- Call pushes a new frame; params are bound to `locals[0..argc)`.  
- `Return` pops frame, pushes return onto caller stack.

## Control-flow encoding

- Labels are absolute indices into the `Vec<IRInstr>`.
- `If`: `cond; JIF else; then...; Jump end; else...; end:`
- `Loop/While`: `start: cond; JIF end; body...; Jump start; end:`

## Pretty printer / disasm

Use `vm::ir::disasm_function` to view IR:

```
fn main:
  0000: ConstNum 1
  0001: ConstNum 2
  0002: Add
  0003: StoreVar x
  0004: Return
```

## Scope

v0.1 supports Number/Bool/Text/Null, control flow, fn def/call, list/map, and action emits. LLVM backend is sealed; VM is primary.
