// Stub Oracle query. Later this can call OpenAI/local LLM.
pub fn query_oracle(prompt: &str) -> String {
    format!("(oracle says) {}", prompt)
}
