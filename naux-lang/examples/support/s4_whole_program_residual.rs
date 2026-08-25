//! Closed residual IR and structural work witness for S4-WP5B.
//!
//! This module deliberately lives beside the S4 examples: publishing it from
//! the library would widen an already sealed authority surface.  It accepts a
//! small, explicit bytecode subset and rejects every instruction it cannot
//! residualize without changing the admitted whole-program work contract.

use naux::core::SemanticHash;
use naux::vm::bytecode::{Instr, Program};
use std::collections::VecDeque;
use std::fmt;

const RESIDUAL_DOMAIN: &[u8] = b"NAUX:s4-whole-program-residual:program:v1\0";
const WITNESS_DOMAIN: &[u8] = b"NAUX:s4-whole-program-residual:witness:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidualOp {
    ConstI64(i64),
    LoadLocal(u32),
    StoreLocal(u32),
    StoreLocalKeep(u32),
    AddLocalConst(u32, i64),
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Xor,
    Shl,
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    And,
    Or,
    Jump(u32),
    JumpIfFalse(u32),
    RangeAllocateInit { length: u64 },
    ListLengthStatic { local: u32, length: u64 },
    ListLoad,
    ListStore,
    ReleaseList { local: u32 },
    Return,
}

impl ResidualOp {
    pub fn canonical_text(&self) -> String {
        match self {
            Self::ConstI64(value) => format!("const-i64\t{value}"),
            Self::LoadLocal(local) => format!("load-local\t{local}"),
            Self::StoreLocal(local) => format!("store-local\t{local}"),
            Self::StoreLocalKeep(local) => format!("store-local-keep\t{local}"),
            Self::AddLocalConst(local, value) => {
                format!("add-local-const\t{local}\t{value}")
            }
            Self::Add => "add".into(),
            Self::Sub => "sub".into(),
            Self::Mul => "mul".into(),
            Self::Div => "div".into(),
            Self::Mod => "mod".into(),
            Self::Xor => "xor".into(),
            Self::Shl => "shl".into(),
            Self::Eq => "eq".into(),
            Self::Ne => "ne".into(),
            Self::Gt => "gt".into(),
            Self::Ge => "ge".into(),
            Self::Lt => "lt".into(),
            Self::Le => "le".into(),
            Self::And => "and".into(),
            Self::Or => "or".into(),
            Self::Jump(target) => format!("jump\t{target}"),
            Self::JumpIfFalse(target) => format!("jump-if-false\t{target}"),
            Self::RangeAllocateInit { length } => format!("range-allocate-init\t{length}"),
            Self::ListLengthStatic { local, length } => {
                format!("list-length-static\t{local}\t{length}")
            }
            Self::ListLoad => "list-load".into(),
            Self::ListStore => "list-store".into(),
            Self::ReleaseList { local } => format!("release-list\t{local}"),
            Self::Return => "return".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidualProgram {
    pub local_count: u32,
    pub n_local: u32,
    pub reps_local: u32,
    pub list_local: u32,
    pub checksum_local: u32,
    pub n: u64,
    pub reps: u64,
    pub ops: Vec<ResidualOp>,
}

impl ResidualProgram {
    pub fn semantic_hash(&self) -> SemanticHash {
        let mut bytes = Vec::new();
        put_u32(&mut bytes, self.local_count);
        put_u32(&mut bytes, self.n_local);
        put_u32(&mut bytes, self.reps_local);
        put_u32(&mut bytes, self.list_local);
        put_u32(&mut bytes, self.checksum_local);
        put_u64(&mut bytes, self.n);
        put_u64(&mut bytes, self.reps);
        put_u32(&mut bytes, self.ops.len() as u32);
        for op in &self.ops {
            put_string(&mut bytes, &op.canonical_text());
        }
        hash_domain(RESIDUAL_DOMAIN, &bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopWitness {
    pub header: u32,
    pub guard_exit: u32,
    pub backedge: u32,
    pub counter_local: u32,
    pub bound: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkWitness {
    pub allocation: u32,
    pub release: u32,
    pub outer: LoopWitness,
    pub inner: LoopWitness,
    pub traversal_count: u64,
    pub list_loads: u32,
    pub list_stores: u32,
    pub checksum_local: u32,
}

impl WorkWitness {
    pub fn semantic_hash(&self) -> SemanticHash {
        let mut bytes = Vec::new();
        put_u32(&mut bytes, self.allocation);
        put_u32(&mut bytes, self.release);
        put_loop(&mut bytes, &self.outer);
        put_loop(&mut bytes, &self.inner);
        put_u64(&mut bytes, self.traversal_count);
        put_u32(&mut bytes, self.list_loads);
        put_u32(&mut bytes, self.list_stores);
        put_u32(&mut bytes, self.checksum_local);
        hash_domain(WITNESS_DOMAIN, &bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidualError {
    Unsupported(String),
    InvalidShape(String),
    InvalidControlFlow(String),
    WorkNotPreserved(String),
}

impl fmt::Display for ResidualError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) => {
                write!(formatter, "unsupported residual input: {message}")
            }
            Self::InvalidShape(message) => write!(formatter, "invalid residual shape: {message}"),
            Self::InvalidControlFlow(message) => {
                write!(formatter, "invalid residual control flow: {message}")
            }
            Self::WorkNotPreserved(message) => {
                write!(formatter, "residual work obligation failed: {message}")
            }
        }
    }
}

impl std::error::Error for ResidualError {}

/// Lower one already typechecked S4 program into the closed WP5B residual IR.
pub fn lower_whole_program(
    program: &Program,
    n: u64,
    reps: u64,
) -> Result<ResidualProgram, ResidualError> {
    if !program.functions.is_empty() {
        return Err(ResidualError::Unsupported(
            "function bodies are outside the WP5B subset".into(),
        ));
    }
    if n == 0 || reps == 0 || n > i64::MAX as u64 || reps > i64::MAX as u64 {
        return Err(ResidualError::InvalidShape(
            "static n and reps must be positive signed-64 values".into(),
        ));
    }
    let code = &program.main;
    if code.len() < 4 {
        return Err(ResidualError::InvalidShape("main body is too short".into()));
    }
    let n_local = unique_static_local(code, n, "n")?;
    let reps_local = unique_static_local(code, reps, "reps")?;
    if n_local == reps_local {
        return Err(ResidualError::InvalidShape(
            "n and reps resolve to the same local".into(),
        ));
    }
    let (range_load, list_local) = unique_range_allocation(code, n_local)?;
    let (terminal_load, checksum_local) = terminal_checksum(code)?;
    if range_load >= terminal_load {
        return Err(ResidualError::InvalidShape(
            "owned list allocation does not precede completion".into(),
        ));
    }

    let mut old_to_new = vec![None; code.len()];
    let mut ops = Vec::with_capacity(code.len() + 1);
    let mut old_ip = 0;
    while old_ip < code.len() {
        if old_ip == terminal_load {
            old_to_new[old_ip] = Some(ops.len());
            ops.push(ResidualOp::ReleaseList {
                local: as_u32(list_local, "list local")?,
            });
            ops.push(ResidualOp::LoadLocal(as_u32(
                checksum_local,
                "checksum local",
            )?));
            old_ip += 1;
            continue;
        }
        if old_ip == range_load {
            old_to_new[old_ip] = Some(ops.len());
            old_to_new[old_ip + 1] = None;
            ops.push(ResidualOp::RangeAllocateInit { length: n });
            old_ip += 2;
            continue;
        }
        if let Some(local) = list_length_pair(code, old_ip, list_local) {
            old_to_new[old_ip] = Some(ops.len());
            old_to_new[old_ip + 1] = None;
            ops.push(ResidualOp::ListLengthStatic {
                local: as_u32(local, "list local")?,
                length: n,
            });
            old_ip += 2;
            continue;
        }
        old_to_new[old_ip] = Some(ops.len());
        ops.push(translate_op(&code[old_ip])?);
        old_ip += 1;
    }

    for op in &mut ops {
        let target = match op {
            ResidualOp::Jump(target) | ResidualOp::JumpIfFalse(target) => target,
            _ => continue,
        };
        let old_target = *target as usize;
        let remapped = old_to_new
            .get(old_target)
            .and_then(|mapped| *mapped)
            .ok_or_else(|| {
                ResidualError::InvalidControlFlow(format!(
                    "jump target {old_target} was removed by specialization"
                ))
            })?;
        *target = as_u32(remapped, "residual jump target")?;
    }

    let residual = ResidualProgram {
        local_count: as_u32(program.main_locals.len(), "local count")?,
        n_local: as_u32(n_local, "n local")?,
        reps_local: as_u32(reps_local, "reps local")?,
        list_local: as_u32(list_local, "list local")?,
        checksum_local: as_u32(checksum_local, "checksum local")?,
        n,
        reps,
        ops,
    };
    verify_control_flow(&residual)?;
    verify_work(&residual)?;
    Ok(residual)
}

/// Replay the structural proof without consulting the source kernel name.
pub fn verify_work(residual: &ResidualProgram) -> Result<WorkWitness, ResidualError> {
    verify_control_flow(residual)?;
    let allocations: Vec<_> = residual
        .ops
        .iter()
        .enumerate()
        .filter_map(|(ip, op)| matches!(op, ResidualOp::RangeAllocateInit { .. }).then_some(ip))
        .collect();
    let releases: Vec<_> = residual
        .ops
        .iter()
        .enumerate()
        .filter_map(|(ip, op)| matches!(op, ResidualOp::ReleaseList { .. }).then_some(ip))
        .collect();
    if allocations.len() != 1 || releases.len() != 1 {
        return Err(ResidualError::WorkNotPreserved(
            "exactly one owned allocation and one release are required".into(),
        ));
    }
    match residual.ops[allocations[0]] {
        ResidualOp::RangeAllocateInit { length } if length == residual.n => {}
        _ => {
            return Err(ResidualError::WorkNotPreserved(
                "range allocation length does not equal static n".into(),
            ))
        }
    }
    match residual.ops[releases[0]] {
        ResidualOp::ReleaseList { local } if local == residual.list_local => {}
        _ => {
            return Err(ResidualError::WorkNotPreserved(
                "release does not consume the owned list local".into(),
            ))
        }
    }
    if !matches!(
        residual.ops.get(allocations[0] + 1),
        Some(ResidualOp::StoreLocal(local)) if *local == residual.list_local
    ) {
        return Err(ResidualError::WorkNotPreserved(
            "range allocation is not immediately installed in the owned local".into(),
        ));
    }

    let mut loops = Vec::new();
    for (backedge, op) in residual.ops.iter().enumerate() {
        let ResidualOp::Jump(header) = op else {
            continue;
        };
        let header = *header as usize;
        if header < backedge {
            loops.push(parse_loop(residual, header, backedge)?);
        }
    }
    if loops.len() != 2 {
        return Err(ResidualError::WorkNotPreserved(format!(
            "expected two structural loops, found {}",
            loops.len()
        )));
    }
    loops.sort_by_key(|loop_| loop_.header);
    let outer = loops.remove(0);
    let inner = loops.remove(0);
    if outer.header >= inner.header
        || inner.backedge >= inner.guard_exit
        || inner.guard_exit > outer.backedge
        || outer.backedge >= outer.guard_exit
    {
        return Err(ResidualError::WorkNotPreserved(
            "inner and outer loop intervals are not properly nested".into(),
        ));
    }
    if outer.bound != residual.reps || inner.bound != residual.n {
        return Err(ResidualError::WorkNotPreserved(
            "loop bounds do not preserve reps times n traversal".into(),
        ));
    }
    if allocations[0] >= outer.header as usize {
        return Err(ResidualError::WorkNotPreserved(
            "owned list is not initialized before traversal".into(),
        ));
    }
    if releases[0] != outer.guard_exit as usize {
        return Err(ResidualError::WorkNotPreserved(
            "outer loop exit does not enter teardown".into(),
        ));
    }
    if !has_zero_init(&residual.ops, outer.counter_local, 0, outer.header as usize)
        || !has_zero_init(
            &residual.ops,
            inner.counter_local,
            outer.header as usize + 4,
            inner.header as usize,
        )
    {
        return Err(ResidualError::WorkNotPreserved(
            "loop counter zero-initialization is absent".into(),
        ));
    }
    if !has_unit_increment(
        &residual.ops,
        outer.counter_local,
        inner.guard_exit as usize,
        outer.backedge as usize,
    ) || !has_unit_increment(
        &residual.ops,
        inner.counter_local,
        inner.header as usize + 4,
        inner.backedge as usize,
    ) {
        return Err(ResidualError::WorkNotPreserved(
            "loop counter unit increment is absent".into(),
        ));
    }

    let mut list_loads = 0_u32;
    let mut list_stores = 0_u32;
    for (ip, op) in residual.ops.iter().enumerate() {
        if matches!(op, ResidualOp::ListLoad | ResidualOp::ListStore)
            && !(inner.header as usize + 4..inner.backedge as usize).contains(&ip)
        {
            return Err(ResidualError::WorkNotPreserved(
                "list kernel operation escaped the inner traversal".into(),
            ));
        }
        match op {
            ResidualOp::ListLoad => list_loads += 1,
            ResidualOp::ListStore => list_stores += 1,
            _ => {}
        }
    }
    if list_loads == 0 {
        return Err(ResidualError::WorkNotPreserved(
            "inner traversal contains no list load".into(),
        ));
    }
    if releases[0] + 2 >= residual.ops.len()
        || !matches!(
            residual.ops[releases[0] + 1],
            ResidualOp::LoadLocal(local) if local == residual.checksum_local
        )
        || !matches!(residual.ops[releases[0] + 2], ResidualOp::Return)
        || releases[0] + 3 != residual.ops.len()
    {
        return Err(ResidualError::WorkNotPreserved(
            "teardown is not followed by the checksum return".into(),
        ));
    }
    let traversal_count = residual
        .n
        .checked_mul(residual.reps)
        .ok_or_else(|| ResidualError::WorkNotPreserved("traversal count overflowed".into()))?;
    Ok(WorkWitness {
        allocation: as_u32(allocations[0], "allocation ip")?,
        release: as_u32(releases[0], "release ip")?,
        outer,
        inner,
        traversal_count,
        list_loads,
        list_stores,
        checksum_local: residual.checksum_local,
    })
}

fn unique_static_local(code: &[Instr], value: u64, label: &str) -> Result<usize, ResidualError> {
    let expected = value as i64;
    let mut matches = Vec::new();
    for pair in code.windows(2) {
        if let [Instr::ConstNum(number), Instr::StoreLocal(local)] = pair {
            if exact_i64(*number) == Some(expected) {
                matches.push(*local);
            }
        }
    }
    matches.sort_unstable();
    matches.dedup();
    if matches.len() != 1 {
        return Err(ResidualError::InvalidShape(format!(
            "static {label} assignment is not unique"
        )));
    }
    Ok(matches[0])
}

fn unique_range_allocation(
    code: &[Instr],
    n_local: usize,
) -> Result<(usize, usize), ResidualError> {
    let mut matches = Vec::new();
    for ip in 0..code.len().saturating_sub(2) {
        if matches!(code[ip], Instr::LoadLocal(local) if local == n_local)
            && matches!(&code[ip + 1], Instr::CallBuiltin(name, 1) if name == "list_range")
        {
            if let Instr::StoreLocal(list_local) = code[ip + 2] {
                matches.push((ip, list_local));
            }
        }
    }
    if matches.len() != 1 {
        return Err(ResidualError::InvalidShape(
            "owned list_range allocation is not unique".into(),
        ));
    }
    Ok(matches[0])
}

fn terminal_checksum(code: &[Instr]) -> Result<(usize, usize), ResidualError> {
    if code.iter().filter(|op| matches!(op, Instr::Return)).count() != 1 {
        return Err(ResidualError::InvalidShape(
            "WP5B requires exactly one return".into(),
        ));
    }
    match &code[code.len() - 2..] {
        [Instr::LoadLocal(local), Instr::Return] => Ok((code.len() - 2, *local)),
        _ => Err(ResidualError::InvalidShape(
            "main does not end in a local checksum return".into(),
        )),
    }
}

fn list_length_pair(code: &[Instr], ip: usize, list_local: usize) -> Option<usize> {
    if ip + 1 < code.len()
        && matches!(code[ip], Instr::LoadLocal(local) if local == list_local)
        && matches!(&code[ip + 1], Instr::CallBuiltin(name, 1) if name == "len")
    {
        Some(list_local)
    } else {
        None
    }
}

fn translate_op(op: &Instr) -> Result<ResidualOp, ResidualError> {
    let translated = match op {
        Instr::ConstNum(value) => ResidualOp::ConstI64(exact_i64(*value).ok_or_else(|| {
            ResidualError::Unsupported(format!("non-integral numeric constant {value}"))
        })?),
        Instr::LoadLocal(local) => ResidualOp::LoadLocal(as_u32(*local, "local")?),
        Instr::StoreLocal(local) => ResidualOp::StoreLocal(as_u32(*local, "local")?),
        Instr::StoreLocalKeep(local) => ResidualOp::StoreLocalKeep(as_u32(*local, "local")?),
        Instr::AddLocalConst(local, value) => ResidualOp::AddLocalConst(
            as_u32(*local, "local")?,
            exact_i64(*value).ok_or_else(|| {
                ResidualError::Unsupported(format!("non-integral local increment {value}"))
            })?,
        ),
        Instr::Add => ResidualOp::Add,
        Instr::Sub => ResidualOp::Sub,
        Instr::Mul => ResidualOp::Mul,
        Instr::Div => ResidualOp::Div,
        Instr::Mod => ResidualOp::Mod,
        Instr::Xor => ResidualOp::Xor,
        Instr::Shl => ResidualOp::Shl,
        Instr::Eq => ResidualOp::Eq,
        Instr::Ne => ResidualOp::Ne,
        Instr::Gt => ResidualOp::Gt,
        Instr::Ge => ResidualOp::Ge,
        Instr::Lt => ResidualOp::Lt,
        Instr::Le => ResidualOp::Le,
        Instr::And => ResidualOp::And,
        Instr::Or => ResidualOp::Or,
        Instr::Jump(target) => ResidualOp::Jump(as_u32(*target, "jump target")?),
        Instr::JumpIfFalse(target) => ResidualOp::JumpIfFalse(as_u32(*target, "jump target")?),
        Instr::CallBuiltin(name, 2) if name == "__index" => ResidualOp::ListLoad,
        Instr::CallBuiltin(name, 3) if name == "__setindex" => ResidualOp::ListStore,
        Instr::Return => ResidualOp::Return,
        other => {
            return Err(ResidualError::Unsupported(format!(
                "bytecode instruction {other:?}"
            )))
        }
    };
    Ok(translated)
}

fn verify_control_flow(residual: &ResidualProgram) -> Result<(), ResidualError> {
    if residual.ops.is_empty() {
        return Err(ResidualError::InvalidControlFlow(
            "residual program is empty".into(),
        ));
    }
    for local in [
        residual.n_local,
        residual.reps_local,
        residual.list_local,
        residual.checksum_local,
    ] {
        if local >= residual.local_count {
            return Err(ResidualError::InvalidControlFlow(format!(
                "local {local} is outside the declared local count"
            )));
        }
    }
    let mut depths = vec![None; residual.ops.len()];
    depths[0] = Some(0_i32);
    let mut queue = VecDeque::from([0_usize]);
    let mut reachable_return = false;
    while let Some(ip) = queue.pop_front() {
        let depth = depths[ip].expect("queued instructions have a stack depth");
        let (required, delta) = stack_effect(&residual.ops[ip]);
        if depth < required {
            return Err(ResidualError::InvalidControlFlow(format!(
                "stack underflow at residual instruction {ip}"
            )));
        }
        let next_depth = depth + delta;
        let successors = successors(&residual.ops, ip)?;
        if matches!(residual.ops[ip], ResidualOp::Return) {
            reachable_return = true;
            if next_depth != 0 {
                return Err(ResidualError::InvalidControlFlow(
                    "return does not consume the complete operand stack".into(),
                ));
            }
        }
        for successor in successors {
            match depths[successor] {
                Some(existing) if existing != next_depth => {
                    return Err(ResidualError::InvalidControlFlow(format!(
                        "stack depth disagrees at merge instruction {successor}"
                    )))
                }
                Some(_) => {}
                None => {
                    depths[successor] = Some(next_depth);
                    queue.push_back(successor);
                }
            }
        }
    }
    if depths.iter().any(Option::is_none) {
        return Err(ResidualError::InvalidControlFlow(
            "residual program contains unreachable instructions".into(),
        ));
    }
    if !reachable_return {
        return Err(ResidualError::InvalidControlFlow(
            "no reachable return exists".into(),
        ));
    }
    Ok(())
}

fn stack_effect(op: &ResidualOp) -> (i32, i32) {
    match op {
        ResidualOp::ConstI64(_)
        | ResidualOp::LoadLocal(_)
        | ResidualOp::RangeAllocateInit { .. }
        | ResidualOp::ListLengthStatic { .. } => (0, 1),
        ResidualOp::StoreLocal(_) => (1, -1),
        ResidualOp::StoreLocalKeep(_) => (1, 0),
        ResidualOp::AddLocalConst(_, _) | ResidualOp::Jump(_) | ResidualOp::ReleaseList { .. } => {
            (0, 0)
        }
        ResidualOp::Add
        | ResidualOp::Sub
        | ResidualOp::Mul
        | ResidualOp::Div
        | ResidualOp::Mod
        | ResidualOp::Xor
        | ResidualOp::Shl
        | ResidualOp::Eq
        | ResidualOp::Ne
        | ResidualOp::Gt
        | ResidualOp::Ge
        | ResidualOp::Lt
        | ResidualOp::Le
        | ResidualOp::And
        | ResidualOp::Or
        | ResidualOp::ListLoad => (2, -1),
        ResidualOp::ListStore => (3, -2),
        ResidualOp::JumpIfFalse(_) | ResidualOp::Return => (1, -1),
    }
}

fn successors(ops: &[ResidualOp], ip: usize) -> Result<Vec<usize>, ResidualError> {
    let checked_target = |target: u32| {
        let target = target as usize;
        if target >= ops.len() {
            Err(ResidualError::InvalidControlFlow(format!(
                "jump at {ip} targets out-of-range instruction {target}"
            )))
        } else {
            Ok(target)
        }
    };
    match ops[ip] {
        ResidualOp::Jump(target) => Ok(vec![checked_target(target)?]),
        ResidualOp::JumpIfFalse(target) => {
            if ip + 1 >= ops.len() {
                return Err(ResidualError::InvalidControlFlow(
                    "conditional jump has no fallthrough".into(),
                ));
            }
            Ok(vec![checked_target(target)?, ip + 1])
        }
        ResidualOp::Return => Ok(Vec::new()),
        _ if ip + 1 < ops.len() => Ok(vec![ip + 1]),
        _ => Err(ResidualError::InvalidControlFlow(
            "residual program falls off the end".into(),
        )),
    }
}

fn parse_loop(
    residual: &ResidualProgram,
    header: usize,
    backedge: usize,
) -> Result<LoopWitness, ResidualError> {
    let Some(
        [ResidualOp::LoadLocal(counter_local), bound_op, ResidualOp::Lt, ResidualOp::JumpIfFalse(exit)],
    ) = residual.ops.get(header..header + 4)
    else {
        return Err(ResidualError::WorkNotPreserved(format!(
            "loop header {header} is not a canonical counted guard"
        )));
    };
    let bound = match bound_op {
        ResidualOp::LoadLocal(local) if *local == residual.reps_local => residual.reps,
        ResidualOp::ListLengthStatic { local, length }
            if *local == residual.list_local && *length == residual.n =>
        {
            residual.n
        }
        _ => {
            return Err(ResidualError::WorkNotPreserved(format!(
                "loop header {header} has an unbound limit"
            )))
        }
    };
    Ok(LoopWitness {
        header: as_u32(header, "loop header")?,
        guard_exit: *exit,
        backedge: as_u32(backedge, "loop backedge")?,
        counter_local: *counter_local,
        bound,
    })
}

fn has_zero_init(ops: &[ResidualOp], local: u32, start: usize, end: usize) -> bool {
    ops.get(start..end)
        .unwrap_or_default()
        .windows(2)
        .any(|pair| {
            matches!(pair, [ResidualOp::ConstI64(0), ResidualOp::StoreLocal(found)] if *found == local)
        })
}

fn has_unit_increment(ops: &[ResidualOp], local: u32, start: usize, end: usize) -> bool {
    let slice = ops.get(start..end).unwrap_or_default();
    slice
        .iter()
        .any(|op| matches!(op, ResidualOp::AddLocalConst(found, 1) if *found == local))
        || slice.windows(4).any(|quad| {
            matches!(
                quad,
                [
                    ResidualOp::LoadLocal(load),
                    ResidualOp::ConstI64(1),
                    ResidualOp::Add,
                    ResidualOp::StoreLocal(store)
                ] if *load == local && *store == local
            )
        })
}

fn exact_i64(value: f64) -> Option<i64> {
    if value.is_finite()
        && value.fract() == 0.0
        && value >= i64::MIN as f64
        && value < -(i64::MIN as f64)
    {
        Some(value as i64)
    } else {
        None
    }
}

fn as_u32(value: usize, label: &str) -> Result<u32, ResidualError> {
    u32::try_from(value).map_err(|_| ResidualError::InvalidShape(format!("{label} exceeds u32")))
}

fn put_loop(bytes: &mut Vec<u8>, loop_: &LoopWitness) {
    put_u32(bytes, loop_.header);
    put_u32(bytes, loop_.guard_exit);
    put_u32(bytes, loop_.backedge);
    put_u32(bytes, loop_.counter_local);
    put_u64(bytes, loop_.bound);
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u32(bytes, value.len() as u32);
    bytes.extend_from_slice(value.as_bytes());
}

fn hash_domain(domain: &[u8], payload: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(domain.len() + payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(payload);
    SemanticHash(sha256(&bytes))
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut output = [0_u8; 32];
    for (chunk, value) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use naux::vm::compiler::compile_script;
    use naux::{lexer, parser, typecheck};

    const SOURCES: [&str; 4] = [
        include_str!("../../../benchmarks/s4/naux/sum_dense.nx"),
        include_str!("../../../benchmarks/s4/naux/branch_mix.nx"),
        include_str!("../../../benchmarks/s4/naux/dot_product.nx"),
        include_str!("../../../benchmarks/s4/naux/list_update.nx"),
    ];

    fn compile(source: &str) -> Program {
        let tokens = lexer::lex(source).expect("source should lex");
        let statements = parser::parse_script(&tokens).expect("source should parse");
        typecheck::check_program(&statements).expect("source should typecheck");
        compile_script(&statements)
    }

    #[test]
    fn all_frozen_kernels_share_one_structural_pipeline() {
        let mut residual_hashes = Vec::new();
        for source in SOURCES {
            let residual = lower_whole_program(&compile(source), 16_384, 50)
                .expect("accepted source should residualize");
            let witness = verify_work(&residual).expect("work witness should replay");
            assert_eq!(witness.traversal_count, 819_200);
            assert_eq!(witness.outer.bound, 50);
            assert_eq!(witness.inner.bound, 16_384);
            assert!(witness.list_loads >= 1);
            assert_eq!(
                residual.ops[witness.release as usize + 2],
                ResidualOp::Return
            );
            residual_hashes.push(residual.semantic_hash());
            assert_ne!(witness.semantic_hash(), SemanticHash::ZERO);
        }
        residual_hashes.sort();
        residual_hashes.dedup();
        assert_eq!(residual_hashes.len(), 4);
    }

    #[test]
    fn lowering_is_deterministic() {
        let program = compile(SOURCES[0]);
        let first = lower_whole_program(&program, 16_384, 50).expect("first lowering");
        let second = lower_whole_program(&program, 16_384, 50).expect("second lowering");
        assert_eq!(first, second);
        assert_eq!(first.semantic_hash(), second.semantic_hash());
        assert_eq!(verify_work(&first), verify_work(&second));
    }

    #[test]
    fn unsupported_builtin_fails_closed() {
        let mut program = compile(SOURCES[0]);
        let index = program
            .main
            .iter()
            .position(|op| matches!(op, Instr::CallBuiltin(name, 2) if name == "__index"))
            .expect("source contains index");
        program.main[index] = Instr::CallBuiltin("host_escape".into(), 2);
        assert!(matches!(
            lower_whole_program(&program, 16_384, 50),
            Err(ResidualError::Unsupported(_))
        ));
    }

    #[test]
    fn removed_jump_target_fails_closed() {
        let mut program = compile(SOURCES[0]);
        program.main[14] = Instr::JumpIfFalse(21);
        assert!(matches!(
            lower_whole_program(&program, 16_384, 50),
            Err(ResidualError::InvalidControlFlow(_))
        ));
    }

    #[test]
    fn missing_counter_increment_fails_work_replay() {
        let mut program = compile(SOURCES[0]);
        program.main[45] = Instr::AddLocalConst(3, 2.0);
        assert!(matches!(
            lower_whole_program(&program, 16_384, 50),
            Err(ResidualError::WorkNotPreserved(_))
        ));
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            SemanticHash(sha256(b"abc")).to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
