use crate::runtime::{RuntimeEvent, Value};

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                n.to_string()
            }
        }
        Value::Boolean(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::List(items) => {
            let parts: Vec<String> = items.iter().map(value_to_string).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", k, value_to_string(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

pub fn render_cli(events: &[RuntimeEvent]) {
    let mut stack: Vec<String> = Vec::new();

    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => {
                println!("> {}", msg);
            }
            RuntimeEvent::SetVar(name, val) => {
                println!("var {} = {}", name, value_to_string(val));
            }
            RuntimeEvent::OracleRequest(q) => {
                println!("? ASK: {}", q);
            }
            RuntimeEvent::OracleResponse(a) => {
                println!("= ORACLE: {}", a);
            }
            RuntimeEvent::UiStart(kind) => {
                let indent = "  ".repeat(stack.len());
                if kind.eq_ignore_ascii_case("card") {
                    println!("{}┌────────────────────────────┐", indent);
                    println!("{}│ CARD{:>22}│", indent, "");
                } else {
                    println!("{}=== UI {} START ===", indent, kind);
                }
                stack.push(kind.clone());
            }
            RuntimeEvent::UiEnd => {
                if let Some(kind) = stack.pop() {
                    let indent = "  ".repeat(stack.len());
                    if kind.eq_ignore_ascii_case("card") {
                        println!("{}└────────────────────────────┘", indent);
                    } else {
                        println!("{}=== UI END ===", indent);
                    }
                } else {
                    println!("(ui_end with no matching start)");
                }
            }
            RuntimeEvent::UiText(text) => {
                let depth = stack.len();
                let card = stack
                    .last()
                    .map(|k| k.eq_ignore_ascii_case("card"))
                    .unwrap_or(false);
                if card {
                    let indent = "  ".repeat(depth.saturating_sub(1));
                    println!("{}│   TEXT: {}", indent, text);
                } else {
                    println!("{}- TEXT: {}", "  ".repeat(depth), text);
                }
            }
            RuntimeEvent::UiButton(label) => {
                let depth = stack.len();
                let card = stack
                    .last()
                    .map(|k| k.eq_ignore_ascii_case("card"))
                    .unwrap_or(false);
                if card {
                    let indent = "  ".repeat(depth.saturating_sub(1));
                    println!("{}│   [ {} ]", indent, label);
                } else {
                    println!("{}[ {} ]", "  ".repeat(depth), label);
                }
            }
        }
    }
    // Close any unclosed UI frames in CLI view for clarity.
    while let Some(kind) = stack.pop() {
        let indent = "  ".repeat(stack.len());
        if kind.eq_ignore_ascii_case("card") {
            println!("{}└────────────────────────────┘", indent);
        } else {
            println!("{}=== UI END ===", indent);
        }
    }
}

pub fn render_html(events: &[RuntimeEvent]) -> String {
    let mut out = String::new();
    out.push_str(
        "<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\" />\n  <title>Naux UI</title>\n  <style>\n    body { background: #050510; color: #f8f8ff; font-family: 'Inter', system-ui, -apple-system, sans-serif; padding: 24px; }\n    .stack { display: flex; flex-direction: column; gap: 12px; }\n    .card { border-radius: 12px; padding: 16px; background: #111122; box-shadow: 0 0 12px rgba(255,0,102,0.3); border: 1px solid rgba(255,0,102,0.5); }\n    .text { margin: 4px 0; color: #f8f8ff; }\n    .btn { padding: 8px 16px; border-radius: 999px; border: 1px solid #ff0066; background: transparent; color: #ff79c6; cursor: pointer; }\n    .say { color: #9efcff; font-style: italic; }\n    .ask { color: #ffd166; font-weight: 600; }\n    .oracle { color: #8ef1b8; font-weight: 700; }\n  </style>\n</head>\n<body>\n",
    );

    let mut stack: Vec<String> = Vec::new();

    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => {
                out.push_str(&format!(
                    "  <p class=\"say\">{}</p>\n",
                    escape_html(msg)
                ));
            }
            RuntimeEvent::SetVar(name, val) => {
                out.push_str(&format!(
                    "  <!-- set {} = {} -->\n",
                    escape_html(name),
                    escape_html(&value_to_string(val))
                ));
            }
            RuntimeEvent::UiStart(kind) => {
                let class = match kind.as_str() {
                    "card" => "card",
                    "stack" => "stack",
                    other => other,
                };
                out.push_str(&format!("  <div class=\"{}\">\n", escape_html(class)));
                stack.push(class.to_string());
            }
            RuntimeEvent::UiEnd => {
                if stack.pop().is_some() {
                    out.push_str("  </div>\n");
                }
            }
            RuntimeEvent::UiText(text) => {
                out.push_str(&format!(
                    "    <p class=\"text\">{}</p>\n",
                    escape_html(text)
                ));
            }
            RuntimeEvent::UiButton(label) => {
                out.push_str(&format!(
                    "    <button class=\"btn\">{}</button>\n",
                    escape_html(label)
                ));
            }
            RuntimeEvent::OracleRequest(q) => {
                out.push_str(&format!(
                    "  <p class=\"ask\">? {}</p>\n",
                    escape_html(q)
                ));
            }
            RuntimeEvent::OracleResponse(a) => {
                out.push_str(&format!(
                    "  <p class=\"oracle\">= {}</p>\n",
                    escape_html(a)
                ));
            }
        }
    }

    while stack.pop().is_some() {
        out.push_str("  </div>\n");
    }

    out.push_str("</body>\n</html>\n");
    out
}

fn escape_html(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            _ => c.to_string(),
        })
        .collect()
}
