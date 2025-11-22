use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct VarRef {
    pub base: String,
    pub path: Vec<String>,
}

impl VarRef {
    pub fn to_json(&self) -> Value {
        json!({
            "base": self.base,
            "path": self.path,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Expr {
    Literal { kind: String, value: Value },
    Var(VarRef),
    Ident(String),
    Binary { op: String, left: Box<Expr>, right: Box<Expr> },
    Unary { op: String, expr: Box<Expr> },
    List(Vec<Expr>),
    Object(Vec<(String, Expr)>),
    Action(Action),
}

impl Expr {
    pub fn to_json(&self) -> Value {
        match self {
            Expr::Literal { kind, value } => json!({"vtype": kind, "value": value}),
            Expr::Var(r) => json!({"vtype": "var", "ref": r.to_json()}),
            Expr::Ident(name) => json!({"vtype": "ident", "name": name}),
            Expr::Binary { op, left, right } => json!({
                "vtype": "binary",
                "op": op,
                "left": left.to_json(),
                "right": right.to_json(),
            }),
            Expr::Unary { op, expr } => json!({
                "vtype": "unary",
                "op": op,
                "expr": expr.to_json(),
            }),
            Expr::List(items) => json!({
                "vtype": "list",
                "items": items.iter().map(|e| e.to_json()).collect::<Vec<_>>()
            }),
            Expr::Object(entries) => json!({
                "vtype": "object",
                "entries": entries.iter().map(|(k,v)| json!({"key": k, "value": v.to_json()})).collect::<Vec<_>>()
            }),
            Expr::Action(a) => a.to_json(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Arg {
    Value { value: Expr },
    Named { name: String, value: Expr },
    Flag { name: String },
}

impl Arg {
    pub fn to_json(&self) -> Value {
        match self {
            Arg::Value { value } => json!({"kind": "value", "value": value.to_json()}),
            Arg::Named { name, value } => json!({"kind": "named", "name": name, "value": value.to_json()}),
            Arg::Flag { name } => json!({"kind": "flag", "name": name}),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Action {
    pub name: String,
    pub args: Vec<Arg>,
    pub callback: Option<Box<Action>>,
}

impl Action {
    pub fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("type".into(), json!("action"));
        map.insert("name".into(), json!(self.name));
        map.insert(
            "args".into(),
            Value::Array(self.args.iter().map(|a| a.to_json()).collect()),
        );
        if let Some(cb) = &self.callback {
            map.insert("callback".into(), cb.to_json());
        }
        Value::Object(map)
    }
}

#[derive(Debug, Clone)]
pub struct Assign {
    pub target: VarRef,
    pub expr: Expr,
}

impl Assign {
    pub fn to_json(&self) -> Value {
        json!({
            "type": "assign",
            "target": self.target.to_json(),
            "expr": self.expr.to_json(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Loop {
    pub mode: String, // "over" or "count"
    pub source: Option<VarRef>,
    pub times: Option<i64>,
    pub body: Vec<Statement>,
}

impl Loop {
    pub fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("type".into(), json!("loop"));
        map.insert("mode".into(), json!(self.mode.clone()));
        map.insert(
            "body".into(),
            Value::Array(self.body.iter().map(|s| s.to_json()).collect()),
        );
        if let Some(src) = &self.source {
            map.insert("source".into(), src.to_json());
        }
        if let Some(t) = self.times {
            map.insert("times".into(), json!(t));
        }
        Value::Object(map)
    }
}

#[derive(Debug, Clone)]
pub struct If {
    pub cond: Expr,
    pub then_body: Vec<Statement>,
    pub else_body: Option<Vec<Statement>>,
}

impl If {
    pub fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("type".into(), json!("if"));
        map.insert("cond".into(), self.cond.to_json());
        map.insert(
            "then".into(),
            Value::Array(self.then_body.iter().map(|s| s.to_json()).collect()),
        );
        if let Some(els) = &self.else_body {
            map.insert(
                "else".into(),
                Value::Array(els.iter().map(|s| s.to_json()).collect()),
            );
        }
        Value::Object(map)
    }
}

#[derive(Debug, Clone)]
pub enum Statement {
    Action(Action),
    Assign(Assign),
    Loop(Loop),
    If(If),
}

impl Statement {
    pub fn to_json(&self) -> Value {
        match self {
            Statement::Action(a) => a.to_json(),
            Statement::Assign(a) => a.to_json(),
            Statement::Loop(l) => l.to_json(),
            Statement::If(i) => i.to_json(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ritual {
    pub name: String,
    pub body: Vec<Statement>,
}

impl Ritual {
    pub fn to_json(&self) -> Value {
        json!({
            "type": "ritual",
            "name": self.name,
            "body": self.body.iter().map(|s| s.to_json()).collect::<Vec<_>>(),
        })
    }
}

pub type Program = Vec<Ritual>;
