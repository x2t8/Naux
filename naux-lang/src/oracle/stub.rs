// Oracle stub: returns a deterministic reply for a prompt.
pub fn query_oracle(prompt: &str) -> String {
    format!("oracle says: {}", prompt)
}
