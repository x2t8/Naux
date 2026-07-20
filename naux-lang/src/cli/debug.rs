use std::collections::HashSet;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::cli::util;
use crate::runtime::env::Env;
use crate::runtime::events::RuntimeEvent;
use crate::typecheck;
use crate::vm::bytecode::{disasm_window, fmt_instr_bc};
use crate::vm::compiler;
use crate::vm::interpreter::run_program_debug;
use crate::vm::interpreter::{DebugAction, DebugState};

pub fn handle_debug(path: Option<PathBuf>) -> Result<(), String> {
    let target = path.unwrap_or_else(|| PathBuf::from("main.nx"));
    if !target.exists() {
        return Err(format!("Không tìm thấy file `{}`", target.display()));
    }
    let (src, ast) = util::load_ast(&target)?;
    if let Err(e) = typecheck::check_program(&ast) {
        let loc = e
            .span
            .map(|s| format!(" (line {}, col {})", s.line, s.column))
            .unwrap_or_default();
        return Err(format!("Type error{}: {}", loc, e.message));
    }
    let prog = compiler::compile_script(&ast);
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    let builtins = env.builtins();

    println!("NAUX DEBUGGER");
    println!("File: {}", target.display());
    println!("Commands: step/next/cont/break/stack/locals/code/quit");

    let mut debugger = Debugger::new();
    let result = run_program_debug(
        &prog,
        &builtins,
        &src,
        &target.to_string_lossy(),
        &mut |state| debugger.on_step(state),
    );

    match result {
        Ok((val, events)) => {
            if !events.is_empty() {
                render_events(&events);
            } else {
                println!("> {}", val);
            }
            Ok(())
        }
        Err(msg) => {
            if msg == "Debug quit" {
                Ok(())
            } else {
                Err(msg)
            }
        }
    }
}

fn render_events(events: &[RuntimeEvent]) {
    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => println!("> {}", msg),
            RuntimeEvent::Ask { prompt, answer } => {
                println!("? {} -> {}", prompt, answer);
            }
            RuntimeEvent::Fetch { target } => println!("fetch {}", target),
            RuntimeEvent::Ui { kind, props } => {
                println!("ui {} ({})", kind, props.len());
            }
            RuntimeEvent::Text(text) => println!("{}", text),
            RuntimeEvent::Button(label) => println!("[button] {}", label),
            RuntimeEvent::Log(msg) => println!("[log] {}", msg),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    Step,
    Continue,
}

struct Debugger {
    mode: RunMode,
    step_over_depth: Option<usize>,
    breakpoints: HashSet<(String, usize)>,
}

impl Debugger {
    fn new() -> Self {
        Self {
            mode: RunMode::Step,
            step_over_depth: None,
            breakpoints: HashSet::new(),
        }
    }

    fn should_pause(&mut self, state: &DebugState<'_>) -> bool {
        if let Some(depth) = self.step_over_depth {
            if state.frame_depth > depth {
                return false;
            }
            self.step_over_depth = None;
            return true;
        }
        if self.mode == RunMode::Step {
            return true;
        }
        self.breakpoints
            .contains(&(state.function.to_string(), state.ip))
    }

    fn on_step(&mut self, state: DebugState<'_>) -> DebugAction {
        if !self.should_pause(&state) {
            return DebugAction::Continue;
        }

        println!(
            "[{}#{}] {}",
            state.function,
            state.ip,
            fmt_instr_bc(state.instr)
        );
        println!("{}", disasm_window(state.code, state.ip, 3));

        loop {
            print!("dbg> ");
            if io::stdout().flush().is_err() {
                return DebugAction::Quit;
            }
            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_err() {
                return DebugAction::Quit;
            }
            let line = input.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let cmd = parts.next().unwrap_or("");
            match cmd {
                "s" | "step" => {
                    self.mode = RunMode::Step;
                    return DebugAction::Continue;
                }
                "n" | "next" => {
                    self.mode = RunMode::Continue;
                    self.step_over_depth = Some(state.frame_depth);
                    return DebugAction::Continue;
                }
                "c" | "cont" | "continue" => {
                    self.mode = RunMode::Continue;
                    self.step_over_depth = None;
                    return DebugAction::Continue;
                }
                "b" | "break" => {
                    if let Some(arg) = parts.next() {
                        if let Ok(ip) = arg.parse::<usize>() {
                            self.breakpoints.insert((state.function.to_string(), ip));
                            println!("breakpoint set at {}:{}", state.function, ip);
                        } else {
                            println!("Usage: break <ip>");
                        }
                    } else {
                        println!("Breakpoints:");
                        for (name, ip) in &self.breakpoints {
                            println!("  {}:{}", name, ip);
                        }
                    }
                }
                "bd" | "del" | "delete" => {
                    if let Some(arg) = parts.next() {
                        if let Ok(ip) = arg.parse::<usize>() {
                            self.breakpoints.remove(&(state.function.to_string(), ip));
                            println!("breakpoint removed {}:{}", state.function, ip);
                        } else {
                            println!("Usage: del <ip>");
                        }
                    } else {
                        println!("Usage: del <ip>");
                    }
                }
                "stack" | "st" => {
                    if state.stack.is_empty() {
                        println!("(stack empty)");
                    } else {
                        for (i, v) in state.stack.iter().enumerate() {
                            println!("{:>4} | {}", i, v);
                        }
                    }
                }
                "locals" | "l" => {
                    if state.locals.is_empty() {
                        println!("(no locals)");
                    } else {
                        for (i, v) in state.locals.iter().enumerate() {
                            let name = state.locals_names.get(i).map(|s| s.as_str()).unwrap_or("_");
                            println!("{:>4} | {} = {}", i, name, v);
                        }
                    }
                }
                "ip" | "p" => {
                    println!(
                        "[{}#{}] {}",
                        state.function,
                        state.ip,
                        fmt_instr_bc(state.instr)
                    );
                }
                "code" | "list" => {
                    let window = parts
                        .next()
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(5);
                    println!("{}", disasm_window(state.code, state.ip, window));
                }
                "q" | "quit" | "exit" => return DebugAction::Quit,
                "h" | "help" => print_debug_help(),
                _ => println!("Unknown command. Type `help`"),
            }
        }
    }
}

fn print_debug_help() {
    println!("Debugger commands:");
    println!("  step | s        step into next instruction");
    println!("  next | n        step over function calls");
    println!("  cont | c        continue until breakpoint/end");
    println!("  break | b <ip>  set breakpoint at ip");
    println!("  b               list breakpoints");
    println!("  del <ip>        remove breakpoint at ip");
    println!("  stack | st      show stack");
    println!("  locals | l      show locals");
    println!("  ip | p          show current instruction");
    println!("  code | list [n] show disasm window");
    println!("  quit | q        exit debugger");
}
