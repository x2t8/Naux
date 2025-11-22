use crate::runtime::value::Value;

#[derive(Debug, Clone)]
pub enum RuntimeEvent {
    Say(String),
    Ask { prompt: String, answer: String },
    Fetch { target: String },
    Ui { kind: String, props: Vec<(String, Value)> },
    Text(String),
    Button(String),
    Log(String),
}
