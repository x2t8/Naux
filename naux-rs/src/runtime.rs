use std::collections::HashMap;

use naux::ast::Stmt;
use naux::runtime::events::RuntimeEvent as CoreEvent;
use naux::runtime::value::{NauxObj, Value as CoreValue};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Number(f64),
    Bool(bool),
    Text(String),
    List(Vec<Value>),
    Map(HashMap<String, Value>),
    Null,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeEvent {
    AskRequest(String),
    AskResponse(String),
    Say(String),
    Fetch(String),
    Text(String),
    Button(String),
    Log(String),
    Ui(String),
}

#[derive(Debug, Default)]
pub struct Context {
    pub events: Vec<RuntimeEvent>,
    pub errors: Vec<String>,
    env: Option<naux::runtime::env::Env>,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_var(&self, name: &str) -> Option<Value> {
        self.env
            .as_ref()
            .and_then(|env| env.get(name))
            .map(|v| convert_value(&v))
    }
}

pub fn run_program(program: &[Stmt], _entry: Option<&str>, ctx: &mut Context) {
    let (env, events, errors) = naux::runtime::eval_script(program);
    ctx.events = events
        .into_iter()
        .flat_map(convert_event)
        .collect::<Vec<RuntimeEvent>>();
    ctx.errors = errors
        .into_iter()
        .map(|e| e.message)
        .collect::<Vec<String>>();
    ctx.env = Some(env);
}

fn convert_value(value: &CoreValue) -> Value {
    match value {
        CoreValue::SmallInt(n) => Value::Number(*n as f64),
        CoreValue::Float(n) => Value::Number(*n),
        CoreValue::Bool(b) => Value::Bool(*b),
        CoreValue::Null => Value::Null,
        CoreValue::RcObj(rc) => match rc.as_ref() {
            NauxObj::Text(s) => Value::Text(s.clone()),
            NauxObj::List(items) => {
                let out = items
                    .borrow()
                    .iter()
                    .map(convert_value)
                    .collect::<Vec<Value>>();
                Value::List(out)
            }
            NauxObj::Map(map) => {
                let out = map
                    .borrow()
                    .iter()
                    .map(|(k, v)| (k.clone(), convert_value(v)))
                    .collect::<HashMap<String, Value>>();
                Value::Map(out)
            }
            _ => Value::Null,
        },
    }
}

fn convert_event(event: CoreEvent) -> Vec<RuntimeEvent> {
    match event {
        CoreEvent::Say(msg) => vec![RuntimeEvent::Say(msg)],
        CoreEvent::Ask { prompt, answer } => {
            if answer.is_empty() {
                vec![RuntimeEvent::AskRequest(prompt)]
            } else {
                vec![RuntimeEvent::AskResponse(answer)]
            }
        }
        CoreEvent::Fetch { target } => vec![RuntimeEvent::Fetch(target)],
        CoreEvent::Ui { kind, .. } => vec![RuntimeEvent::Ui(kind)],
        CoreEvent::Text(text) => vec![RuntimeEvent::Text(text)],
        CoreEvent::Button(label) => vec![RuntimeEvent::Button(label)],
        CoreEvent::Log(msg) => vec![RuntimeEvent::Log(msg)],
    }
}
