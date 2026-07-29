use std::path::{Path, PathBuf};

use crate::cli::util;
use crate::vm::{bytecode, compiler};

pub fn cfg_core(path: &Path, out: Option<&PathBuf>) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;
    let program = compiler::compile_script(&ast);
    let dot = emit_program_cfg_dot(&program);
    if let Some(out) = out {
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
        }
        std::fs::write(out, &dot)
            .map_err(|e| format!("Failed to write {}: {}", out.display(), e))?;
        println!("[CFG] {} -> {}", path.display(), out.display());
    } else {
        println!("{}", dot);
    }
    Ok(())
}

fn emit_program_cfg_dot(program: &bytecode::Program) -> String {
    let mut out = String::from(
        "digraph NauxCFG {\n  rankdir=LR;\n  compound=true;\n  node [shape=box, fontname=\"monospace\"];\n",
    );
    emit_function_cfg_dot("main", &program.main, &mut out);
    let mut names: Vec<_> = program.functions.keys().cloned().collect();
    names.sort();
    for name in names {
        if let Some(func) = program.functions.get(&name) {
            emit_function_cfg_dot(&name, &func.code, &mut out);
        }
    }
    out.push_str("}\n");
    out
}

fn emit_function_cfg_dot(name: &str, code: &[bytecode::Instr], out: &mut String) {
    use std::fmt::Write;

    let blocks = build_basic_blocks(code);
    let func_id = sanitize_dot_id(name);
    let _ = writeln!(out, "  subgraph cluster_{} {{", func_id);
    let _ = writeln!(out, "    label=\"{}\";", escape_dot_label(name));
    let _ = writeln!(out, "    color=gray70;");
    let entry_id = format!("{}_entry", func_id);
    let exit_id = format!("{}_exit", func_id);
    let _ = writeln!(out, "    {} [label=\"entry\", shape=oval];", entry_id);
    let _ = writeln!(out, "    {} [label=\"exit\", shape=oval];", exit_id);

    if let Some(first) = blocks.first() {
        emit_edge(out, &entry_id, &block_node_id(name, first.start), "start");
    }

    for (block_idx, block) in blocks.iter().enumerate() {
        let block_id = block_node_id(name, block.start);
        let label = format_block_label(block_idx, block, code);
        let _ = writeln!(
            out,
            "    {} [label=\"{}\"];",
            block_id,
            escape_dot_label(&label)
        );
    }

    for block in &blocks {
        let from_id = block_node_id(name, block.start);
        match block.terminator {
            Some(bytecode::Instr::Jump(target)) => {
                if let Some(target_block) = block_for_offset(&blocks, target) {
                    let to_id = block_node_id(name, target_block.start);
                    emit_edge(out, &from_id, &to_id, "jump");
                }
            }
            Some(bytecode::Instr::JumpIfFalse(target)) => {
                if let Some(target_block) = block_for_offset(&blocks, target) {
                    let to_id = block_node_id(name, target_block.start);
                    emit_edge(out, &from_id, &to_id, "false");
                }
                if let Some(next) = block.next_block {
                    let to_id = block_node_id(name, next.start);
                    emit_edge(out, &from_id, &to_id, "true");
                } else {
                    emit_edge(out, &from_id, &exit_id, "true-exit");
                }
            }
            Some(bytecode::Instr::Return) => {
                emit_edge(out, &from_id, &exit_id, "return");
            }
            _ => {
                if let Some(next) = block.next_block {
                    let to_id = block_node_id(name, next.start);
                    emit_edge(out, &from_id, &to_id, "next");
                } else {
                    emit_edge(out, &from_id, &exit_id, "fallthrough-exit");
                }
            }
        }
    }

    let _ = writeln!(out, "  }}");
}

#[derive(Debug, Clone)]
struct BasicBlockView {
    start: usize,
    end: usize,
    terminator: Option<bytecode::Instr>,
    next_block: Option<BasicBlockRef>,
}

#[derive(Debug, Clone, Copy)]
struct BasicBlockRef {
    start: usize,
}

fn build_basic_blocks(code: &[bytecode::Instr]) -> Vec<BasicBlockView> {
    use std::collections::BTreeSet;

    if code.is_empty() {
        return Vec::new();
    }

    let mut leaders = BTreeSet::new();
    leaders.insert(0usize);
    for (idx, instr) in code.iter().enumerate() {
        match instr {
            bytecode::Instr::Jump(target) | bytecode::Instr::JumpIfFalse(target) => {
                if *target < code.len() {
                    leaders.insert(*target);
                }
                if idx + 1 < code.len() {
                    leaders.insert(idx + 1);
                }
            }
            bytecode::Instr::Return if idx + 1 < code.len() => {
                leaders.insert(idx + 1);
            }
            _ => {}
        }
    }

    let mut leader_list: Vec<_> = leaders.into_iter().collect();
    leader_list.sort_unstable();
    let mut blocks = Vec::with_capacity(leader_list.len());
    for (i, start) in leader_list.iter().enumerate() {
        let end = if i + 1 < leader_list.len() {
            leader_list[i + 1]
        } else {
            code.len()
        };
        let terminator = code.get(end.saturating_sub(1)).cloned();
        blocks.push(BasicBlockView {
            start: *start,
            end,
            terminator,
            next_block: None,
        });
    }

    for idx in 0..blocks.len() {
        let next = blocks
            .get(idx + 1)
            .map(|b| BasicBlockRef { start: b.start });
        blocks[idx].next_block = next;
    }

    blocks
}

fn block_for_offset(blocks: &[BasicBlockView], offset: usize) -> Option<&BasicBlockView> {
    blocks.iter().find(|block| block.start == offset)
}

fn format_block_label(
    block_idx: usize,
    block: &BasicBlockView,
    code: &[bytecode::Instr],
) -> String {
    let mut lines = vec![format!(
        "B{} [{}..{}]",
        block_idx,
        block.start,
        block.end.saturating_sub(1)
    )];
    if let Some(term) = &block.terminator {
        lines.push(format!("term: {}", bytecode::fmt_instr_bc(term)));
    }
    for idx in block.start..block.end {
        if let Some(instr) = code.get(idx) {
            lines.push(format!("{:04}: {}", idx, bytecode::fmt_instr_bc(instr)));
        }
    }
    lines.join("\\l") + "\\l"
}

fn emit_edge(out: &mut String, from_id: &str, to_id: &str, label: &str) {
    use std::fmt::Write;
    let _ = writeln!(out, "    {} -> {} [label=\"{}\"];", from_id, to_id, label);
}

fn block_node_id(func: &str, start: usize) -> String {
    format!("{}_bb{}", sanitize_dot_id(func), start)
}

fn sanitize_dot_id(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn escape_dot_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
