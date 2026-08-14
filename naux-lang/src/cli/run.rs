use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::time::Instant;

use crate::cli::util;
use crate::cli::{DefaultEngine, DefaultMode};
use crate::diagnostic::{format_source_diagnostic, DiagnosticStage};
use crate::renderer::{render_cli, render_html};
use crate::runtime::budget::ExecutionLimits;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::input::S1_STANDARD_INPUT_MAX_BYTES;
use crate::runtime::value::{NauxObj, Value};
use crate::typecheck;

pub fn handle_run(
    path: Option<PathBuf>,
    mode: DefaultMode,
    engine: DefaultEngine,
    time: bool,
    limits: ExecutionLimits,
) -> Result<(), String> {
    let target = path.unwrap_or_else(|| PathBuf::from("main.nx"));
    if !target.exists() {
        return Err(format!("Không tìm thấy file `{}`", target.display()));
    }
    let total_start = Instant::now();
    let load_start = Instant::now();
    let (src, ast) = util::load_ast(&target)?;
    let load_time = load_start.elapsed();
    // Type check trước khi chạy
    let type_start = Instant::now();
    if let Err(e) = typecheck::check_program(&ast) {
        return Err(format_source_diagnostic(
            DiagnosticStage::Type,
            &e.message,
            &src,
            &target.to_string_lossy(),
            e.span.as_ref(),
        ));
    }
    let type_time = type_start.elapsed();
    let input = read_standard_input()?;
    let exec_start = Instant::now();
    let (events, value) =
        util::execute_ast_with_input(engine, &ast, &src, &target, &input, false, limits)?;
    let exec_time = exec_start.elapsed();
    match mode {
        DefaultMode::Plain => {
            render_plain(&events)?;
            if time {
                print_time(load_time, type_time, exec_time, total_start.elapsed());
            }
            Ok(())
        }
        DefaultMode::Cli => {
            if events.is_empty() {
                if let Some(val) = value {
                    println!("> {}", val);
                }
            } else {
                render_cli(&events);
            }
            if time {
                eprintln!(
                    "[time] load: {:.3}ms | typecheck: {:.3}ms | exec: {:.3}ms | total: {:.3}ms",
                    load_time.as_secs_f64() * 1000.0,
                    type_time.as_secs_f64() * 1000.0,
                    exec_time.as_secs_f64() * 1000.0,
                    total_start.elapsed().as_secs_f64() * 1000.0
                );
            }
            Ok(())
        }
        DefaultMode::Html => {
            let rendered = render_html(&events, &[]);
            println!("{}", rendered);
            if time {
                eprintln!(
                    "[time] load: {:.3}ms | typecheck: {:.3}ms | exec: {:.3}ms | total: {:.3}ms",
                    load_time.as_secs_f64() * 1000.0,
                    type_time.as_secs_f64() * 1000.0,
                    exec_time.as_secs_f64() * 1000.0,
                    total_start.elapsed().as_secs_f64() * 1000.0
                );
            }
            Ok(())
        }
        DefaultMode::Json => {
            println!("{}", render_json(&events));
            if time {
                eprintln!(
                    "[time] load: {:.3}ms | typecheck: {:.3}ms | exec: {:.3}ms | total: {:.3}ms",
                    load_time.as_secs_f64() * 1000.0,
                    type_time.as_secs_f64() * 1000.0,
                    exec_time.as_secs_f64() * 1000.0,
                    total_start.elapsed().as_secs_f64() * 1000.0
                );
            }
            Ok(())
        }
    }
}

fn read_standard_input() -> Result<String, String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(String::new());
    }
    read_standard_input_bounded(&mut stdin.lock(), S1_STANDARD_INPUT_MAX_BYTES)
}

fn read_standard_input_bounded(reader: &mut impl Read, limit: usize) -> Result<String, String> {
    let byte_limit = u64::try_from(limit)
        .map_err(|_| "standard-input byte limit does not fit u64".to_string())?;
    let mut bytes = Vec::new();
    reader
        .take(byte_limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read standard input: {error}"))?;
    if bytes.len() > limit {
        return Err(format!(
            "standard input exceeds the S1 limit of {limit} bytes"
        ));
    }
    String::from_utf8(bytes).map_err(|_| "standard input must be valid UTF-8".to_string())
}

fn render_plain(events: &[RuntimeEvent]) -> Result<(), String> {
    if events
        .iter()
        .any(|event| !matches!(event, RuntimeEvent::Say(_) | RuntimeEvent::Log(_)))
    {
        return Err(
            "plain mode supports only `!say` output; use `--mode cli`, `html`, or `json` for UI actions"
                .to_string(),
        );
    }
    for event in events {
        match event {
            RuntimeEvent::Say(message) => println!("{message}"),
            RuntimeEvent::Log(_) => {}
            _ => unreachable!("plain-mode event set was preflighted"),
        }
    }
    Ok(())
}

fn print_time(
    load_time: std::time::Duration,
    type_time: std::time::Duration,
    exec_time: std::time::Duration,
    total_time: std::time::Duration,
) {
    eprintln!(
        "[time] load: {:.3}ms | typecheck: {:.3}ms | exec: {:.3}ms | total: {:.3}ms",
        load_time.as_secs_f64() * 1000.0,
        type_time.as_secs_f64() * 1000.0,
        exec_time.as_secs_f64() * 1000.0,
        total_time.as_secs_f64() * 1000.0
    );
}

fn render_json(events: &[RuntimeEvent]) -> String {
    let mut out = String::from("[");
    for (idx, ev) in events.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&event_to_json(ev));
    }
    out.push(']');
    out
}

fn event_to_json(ev: &RuntimeEvent) -> String {
    match ev {
        RuntimeEvent::Say(msg) => format!("{{\"type\":\"say\",\"message\":{}}}", json_string(msg)),
        RuntimeEvent::Ask { prompt, answer } => format!(
            "{{\"type\":\"ask\",\"prompt\":{},\"answer\":{}}}",
            json_string(prompt),
            json_string(answer)
        ),
        RuntimeEvent::Fetch { target } => {
            format!("{{\"type\":\"fetch\",\"target\":{}}}", json_string(target))
        }
        RuntimeEvent::Ui { kind, props } => {
            let mut props_json = String::from("[");
            for (idx, (key, value)) in props.iter().enumerate() {
                if idx > 0 {
                    props_json.push(',');
                }
                props_json.push_str(&format!(
                    "{{\"key\":{},\"value\":{}}}",
                    json_string(key),
                    value_to_json(value)
                ));
            }
            props_json.push(']');
            format!(
                "{{\"type\":\"ui\",\"kind\":{},\"props\":{}}}",
                json_string(kind),
                props_json
            )
        }
        RuntimeEvent::Text(text) => format!("{{\"type\":\"text\",\"text\":{}}}", json_string(text)),
        RuntimeEvent::Button(label) => {
            format!("{{\"type\":\"button\",\"label\":{}}}", json_string(label))
        }
        RuntimeEvent::Log(msg) => format!("{{\"type\":\"log\",\"message\":{}}}", json_string(msg)),
    }
}

fn value_to_json(value: &Value) -> String {
    match value {
        Value::SmallInt(n) => n.to_string(),
        Value::Float(n) => float_to_json(*n),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Text(s) => json_string(s),
            NauxObj::Bytes(bytes) => {
                let items = bytes.borrow();
                let mut out = String::from("[");
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    out.push_str(&item.to_string());
                }
                out.push(']');
                out
            }
            NauxObj::List(list) => {
                let items = list.borrow();
                let mut out = String::from("[");
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    out.push_str(&value_to_json(item));
                }
                out.push(']');
                out
            }
            NauxObj::Map(map) => {
                let items = map.borrow();
                let mut out = String::from("{");
                for (idx, (k, v)) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!("{}:{}", json_string(k), value_to_json(v)));
                }
                out.push('}');
                out
            }
            NauxObj::Set(set) => {
                let items = set.borrow();
                let mut out = String::from("[");
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    out.push_str(&value_to_json(item));
                }
                out.push(']');
                out
            }
            NauxObj::PriorityQueue(queue) => {
                let items = queue.borrow();
                let mut out = String::from("[");
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    out.push_str(&value_to_json(item));
                }
                out.push(']');
                out
            }
            NauxObj::Graph(graph) => {
                let graph = graph.borrow();
                let mut out = String::from("{\"directed\":");
                out.push_str(&graph.directed.to_string());
                out.push_str(",\"adj\":{");
                for (idx, (node, edges)) in graph.adj.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    out.push_str(&json_string(node));
                    out.push(':');
                    out.push('[');
                    for (eidx, (to, weight)) in edges.iter().enumerate() {
                        if eidx > 0 {
                            out.push(',');
                        }
                        out.push_str(&format!(
                            "{{\"to\":{},\"weight\":{}}}",
                            json_string(to),
                            float_to_json(*weight)
                        ));
                    }
                    out.push(']');
                }
                out.push_str("}}");
                out
            }
            NauxObj::Function(_) => json_string("<function>"),
        },
    }
}

fn float_to_json(value: f64) -> String {
    if value.is_finite() {
        let mut s = value.to_string();
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            s.push_str(".0");
        }
        s
    } else {
        json_string(&value.to_string())
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                write!(out, "\\u{:04x}", c as u32).ok();
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_input_is_utf8_and_hard_bounded() {
        assert_eq!(S1_STANDARD_INPUT_MAX_BYTES, 8_388_608);
        assert_eq!(
            read_standard_input_bounded(&mut "123".as_bytes(), 3).unwrap(),
            "123"
        );
        assert_eq!(
            read_standard_input_bounded(&mut "hẹllo".as_bytes(), 8).unwrap(),
            "hẹllo"
        );
        assert!(read_standard_input_bounded(&mut "1234".as_bytes(), 3)
            .unwrap_err()
            .contains("exceeds"));
        assert!(read_standard_input_bounded(&mut [0xff].as_slice(), 1)
            .unwrap_err()
            .contains("valid UTF-8"));
    }
}
