// Ask stub: returns a deterministic reply for a prompt.
pub fn query_ask(prompt: &str) -> String {
    format!("ask reply: {}", prompt)
}
