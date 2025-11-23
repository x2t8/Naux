use crate::ast::{ActionKind, BinaryOp, Expr, ExprKind, Stmt, UnaryOp};

pub fn format_stmts(stmts: &[Stmt]) -> String {
    let mut formatter = Formatter::new();
    for stmt in stmts {
        formatter.format_stmt(stmt);
    }
    formatter.finish()
}

struct Formatter {
    out: String,
    indent: usize,
}

impl Formatter {
    fn new() -> Self {
        Self {
            out: String::new(),
            indent: 0,
        }
    }

    fn finish(mut self) -> String {
        if !self.out.ends_with('\n') {
            self.out.push('\n');
        }
        self.out
    }

    fn newline(&mut self) {
        if !self.out.ends_with('\n') {
            self.out.push('\n');
        }
    }

    fn write_line(&mut self, line: &str) {
        for _ in 0..self.indent {
            self.out.push_str("    ");
        }
        self.out.push_str(line);
        self.out.push('\n');
    }

    fn format_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Rite { body, .. } => {
                self.write_line("~ rite");
                self.indent += 1;
                for stmt in body {
                    self.format_stmt(stmt);
                }
                self.indent -= 1;
                self.write_line("~ end");
            }
            Stmt::Unsafe { body, .. } => {
                self.write_line("~ unsafe");
                self.indent += 1;
                for stmt in body {
                    self.format_stmt(stmt);
                }
                self.indent -= 1;
                self.write_line("~ end");
            }
            Stmt::FnDef { name, params, body, .. } => {
                let params = params
                    .iter()
                    .map(|param| format!("${}", param))
                    .collect::<Vec<_>>()
                    .join(", ");
                self.write_line(&format!("~ fn {}({})", name, params));
                self.indent += 1;
                for stmt in body {
                    self.format_stmt(stmt);
                }
                self.indent -= 1;
                self.write_line("~ end");
            }
            Stmt::Assign { name, expr, .. } => {
                self.write_line(&format!("${} = {}", name, format_expr(expr)));
            }
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                self.write_line(&format!("~ if {}", format_expr(cond)));
                self.indent += 1;
                for stmt in then_block {
                    self.format_stmt(stmt);
                }
                self.indent -= 1;
                if !else_block.is_empty() {
                    self.write_line("~ else");
                    self.indent += 1;
                    for stmt in else_block {
                        self.format_stmt(stmt);
                    }
                    self.indent -= 1;
                }
                self.write_line("~ end");
            }
            Stmt::Loop { count, body, .. } => {
                self.write_line(&format!("~ loop {}", format_expr(count)));
                self.indent += 1;
                for stmt in body {
                    self.format_stmt(stmt);
                }
                self.indent -= 1;
                self.write_line("~ end");
            }
            Stmt::Each { var, iter, body, .. } => {
                self.write_line(&format!("~ each ${} in {}", var, format_expr(iter)));
                self.indent += 1;
                for stmt in body {
                    self.format_stmt(stmt);
                }
                self.indent -= 1;
                self.write_line("~ end");
            }
            Stmt::While { cond, body, .. } => {
                self.write_line(&format!("~ while {}", format_expr(cond)));
                self.indent += 1;
                for stmt in body {
                    self.format_stmt(stmt);
                }
                self.indent -= 1;
                self.write_line("~ end");
            }
            Stmt::Action { action, .. } => {
                self.write_line(&format!("{}", format_action(action)));
            }
            Stmt::Return { value, .. } => {
                if let Some(expr) = value {
                    self.write_line(&format!("^ {}", format_expr(expr)));
                } else {
                    self.write_line("^");
                }
            }
            Stmt::Import { module, .. } => {
                self.write_line(&format!("~ import \"{}\"", module));
            }
        }
    }
}

fn format_action(action: &ActionKind) -> String {
    match action {
        ActionKind::Say { value } => format!("!say {}", format_expr(value)),
        ActionKind::Ask { prompt } => format!("!ask {}", format_expr(prompt)),
        ActionKind::Fetch { target } => format!("!fetch {}", format_expr(target)),
        ActionKind::Ui { kind, props } => {
            if props.is_empty() {
                format!("!ui {}", kind)
            } else {
                let props = props
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, format_expr(v)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("!ui {} {{ {} }}", kind, props)
            }
        }
        ActionKind::Text { value } => format!("!text {}", format_expr(value)),
        ActionKind::Button { value } => format!("!button {}", format_expr(value)),
        ActionKind::Log { value } => format!("!log {}", format_expr(value)),
    }
}

fn format_expr(expr: &Expr) -> String {
    match &expr.kind {
        ExprKind::Number(n) => format_number(*n),
        ExprKind::Bool(b) => format!("{}", b),
        ExprKind::Text(text) => format!("\"{}\"", escape_string(text)),
        ExprKind::List(items) => {
            let inner = items.iter().map(format_expr).collect::<Vec<_>>().join(", ");
            format!("[{}]", inner)
        }
        ExprKind::Map(entries) => {
            let inner = entries
                .iter()
                .map(|(k, v)| format!("\"{}\": {}", escape_string(k), format_expr(v)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{ {} }}", inner)
        }
        ExprKind::Var(name) => format!("${}", name),
        ExprKind::Call { callee, args } => {
            let callee = format_expr(callee);
            let args = args.iter().map(format_expr).collect::<Vec<_>>().join(", ");
            format!("{}({})", callee, args)
        }
        ExprKind::Binary { op, left, right } => {
            format!(
                "{} {} {}",
                format_expr(left),
                format_binary_op(op),
                format_expr(right)
            )
        }
        ExprKind::Unary { op, expr } => match op {
            UnaryOp::Neg => format!("-{}", format_expr(expr)),
            UnaryOp::Not => format!("!{}", format_expr(expr)),
        },
        ExprKind::Index { target, index } => {
            format!("{}[{}]", format_expr(target), format_expr(index))
        }
        ExprKind::Field { target, field } => {
            format!("{}.{}", format_expr(target), field)
        }
    }
}

fn format_binary_op(op: &BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::Eq => "==",
        BinaryOp::Ne => "!=",
        BinaryOp::Gt => ">",
        BinaryOp::Ge => ">=",
        BinaryOp::Lt => "<",
        BinaryOp::Le => "<=",
        BinaryOp::And => "&&",
        BinaryOp::Or => "||",
    }
}

fn format_number(n: f64) -> String {
    if n.fract() == 0.0 {
        format!("{}", n as i64)
    } else {
        format!("{}", n)
    }
}

fn escape_string(src: &str) -> String {
    let mut out = String::new();
    for ch in src.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}
