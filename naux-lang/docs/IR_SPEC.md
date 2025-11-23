# NAUX IR v0.1 (Stack-Based)

Trái tim VM hiện tại: AST → IRInstr → Bytecode → VM.

## Instr set
- ConstNum(f64) / ConstText(String) / ConstBool(bool) / PushNull
- LoadVar(String) / StoreVar(String)
- Add/Sub/Mul/Div/Mod
- Eq/Ne/Gt/Ge/Lt/Le
- And/Or
- Jump(usize) / JumpIfFalse(usize)
- CallBuiltin(name, argc) / CallFn(name, argc)
- MakeList(len) / MakeMap(keys) / LoadField(field)
- EmitSay/EmitAsk/EmitFetch/EmitUi(kind)/EmitText/EmitButton/EmitLog
- Return

## Stack quy ước (pop → push)
- Const*/PushNull: push 1
- LoadVar: push 1
- StoreVar: pop 1
- Add/Sub/Mul/Div/Mod: pop 2 → push 1
- Eq/Ne/Gt/Ge/Lt/Le: pop 2 → push Bool
- And/Or: pop 2 → push Bool
- Jump: no stack change
- JumpIfFalse: pop 1 cond
- CallBuiltin/CallFn: pop argc → push 1 (return)
- MakeList(len): pop len → push 1 list
- MakeMap(keys): pop keys.len → push 1 map
- LoadField: pop 1 target → push 1
- Emit*: pop 0 or 1 depending (Say/Ask/Fetch/Text/Button/Log pop 1; Ui pops 0)
- Return: pop 0 or 1 (whatever on stack); exits frame

## Control flow encoding
- Jump/JIF targets = chỉ số instr trong block.
- If: cond; JIF -> else; then...; Jump end; else...; end label index patch.
- Loop/While: label start; cond; JIF end; body; Jump start; patch end.

## Frame / locals / args
- VM runtime dùng Env (hashmap) cho locals/args; CallFn push frame, bind params từ args, Return trả về value (default Null nếu thiếu).

## Pretty printer
- `vm::ir::pretty_print(&IRProgram)` in ra từng block:
```
fn main:
  0: ConstNum 1.0
  1: ConstNum 2.0
  2: Add
  3: StoreVar x
  4: Return
```
- Functions được in dạng `fn name(params):` với instr index + payload.

## Phạm vi v0.1
- Hỗ trợ Number/Bool/Null, control flow, fn, builtin math.
- Text/List/Map/Emit* tồn tại nhưng chủ yếu cho VM event; LLVM sealed.
