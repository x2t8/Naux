use std::cell::RefCell;
use std::io::{self, BufRead, Write};
use std::rc::Rc;

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::Value;

pub const S1_STANDARD_INPUT_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct InputTape {
    text: String,
    cursor: usize,
}

impl InputTape {
    fn new(text: String) -> Self {
        Self { text, cursor: 0 }
    }

    fn append(&mut self, text: &str) {
        self.text.push_str(text);
    }

    fn read_line(&mut self) -> Option<String> {
        if self.cursor >= self.text.len() {
            return None;
        }

        let rest = &self.text[self.cursor..];
        let (line, consumed, has_line_feed) = match rest.find('\n') {
            Some(end) => (&rest[..end], end + 1, true),
            None => (rest, rest.len(), false),
        };
        self.cursor += consumed;
        let line = if has_line_feed {
            line.strip_suffix('\r').unwrap_or(line)
        } else {
            line
        };
        Some(line.to_string())
    }

    fn read_token(&mut self) -> Option<String> {
        while self.cursor < self.text.len() {
            let rest = &self.text[self.cursor..];
            let ch = rest.chars().next()?;
            if !ch.is_whitespace() {
                break;
            }
            self.cursor += ch.len_utf8();
        }

        if self.cursor >= self.text.len() {
            return None;
        }

        let start = self.cursor;
        for (offset, ch) in self.text[start..].char_indices() {
            if ch.is_whitespace() {
                self.cursor = start + offset;
                return Some(self.text[start..self.cursor].to_string());
            }
        }
        self.cursor = self.text.len();
        Some(self.text[start..].to_string())
    }
}

pub fn register_standard_input(env: &mut Env, input: String) {
    register_input(env, InputSource::Batch(InputTape::new(input)));
}

/// Register stdin builtins that read from the controlling terminal on demand.
///
/// Batch execution intentionally uses [`register_standard_input`] instead. The
/// two sources share the same token/line cursor semantics, while terminal mode
/// refills the tape one line at a time so `read_int()` can block for keyboard
/// input without requiring an EOF keystroke first.
pub fn register_terminal_input(env: &mut Env) {
    register_input(env, InputSource::Terminal(TerminalInput::default()));
}

#[derive(Debug)]
enum InputSource {
    Batch(InputTape),
    Terminal(TerminalInput),
}

impl InputSource {
    fn read_line(&mut self) -> Result<Option<String>, RuntimeError> {
        match self {
            Self::Batch(tape) => Ok(tape.read_line()),
            Self::Terminal(input) => input.read_line(),
        }
    }

    fn read_token(&mut self) -> Result<Option<String>, RuntimeError> {
        match self {
            Self::Batch(tape) => Ok(tape.read_token()),
            Self::Terminal(input) => input.read_token(),
        }
    }
}

#[derive(Debug)]
struct TerminalInput {
    tape: InputTape,
    bytes_read: usize,
}

impl Default for TerminalInput {
    fn default() -> Self {
        Self {
            tape: InputTape::new(String::new()),
            bytes_read: 0,
        }
    }
}

impl TerminalInput {
    fn read_line(&mut self) -> Result<Option<String>, RuntimeError> {
        let stdin = io::stdin();
        let stderr = io::stderr();
        self.read_line_with_io(&mut stdin.lock(), &mut stderr.lock())
    }

    fn read_token(&mut self) -> Result<Option<String>, RuntimeError> {
        let stdin = io::stdin();
        let stderr = io::stderr();
        self.read_token_with_io(&mut stdin.lock(), &mut stderr.lock())
    }

    fn read_line_with_io(
        &mut self,
        reader: &mut impl BufRead,
        prompt: &mut impl Write,
    ) -> Result<Option<String>, RuntimeError> {
        if self.tape.cursor < self.tape.text.len() {
            return Ok(self.tape.read_line());
        }
        if !self.refill(reader, prompt)? {
            return Ok(None);
        }
        Ok(self.tape.read_line())
    }

    fn read_token_with_io(
        &mut self,
        reader: &mut impl BufRead,
        prompt: &mut impl Write,
    ) -> Result<Option<String>, RuntimeError> {
        loop {
            if let Some(token) = self.tape.read_token() {
                return Ok(Some(token));
            }
            if !self.refill(reader, prompt)? {
                return Ok(None);
            }
        }
    }

    fn refill(
        &mut self,
        reader: &mut impl BufRead,
        prompt: &mut impl Write,
    ) -> Result<bool, RuntimeError> {
        prompt
            .write_all(b"input> ")
            .and_then(|()| prompt.flush())
            .map_err(|error| {
                RuntimeError::new(format!("cannot write terminal input prompt: {error}"), None)
            })?;

        let mut line = String::new();
        let bytes = reader.read_line(&mut line).map_err(|error| {
            RuntimeError::new(format!("cannot read terminal input: {error}"), None)
        })?;
        if bytes == 0 {
            return Ok(false);
        }
        self.bytes_read = self
            .bytes_read
            .checked_add(bytes)
            .ok_or_else(|| RuntimeError::new("terminal-input byte count overflowed", None))?;
        if self.bytes_read > S1_STANDARD_INPUT_MAX_BYTES {
            return Err(RuntimeError::new(
                format!(
                    "terminal input exceeds the S1 limit of {} bytes",
                    S1_STANDARD_INPUT_MAX_BYTES
                ),
                None,
            ));
        }
        self.tape.append(&line);
        Ok(true)
    }
}

fn register_input(env: &mut Env, input: InputSource) {
    let source = Rc::new(RefCell::new(input));

    let line_source = Rc::clone(&source);
    env.set_stateful_builtin("read_line", move |args| {
        require_no_args("read_line", &args)?;
        Ok(line_source
            .borrow_mut()
            .read_line()?
            .map(Value::make_text)
            .unwrap_or(Value::Null))
    });

    let token_source = Rc::clone(&source);
    env.set_stateful_builtin("read_token", move |args| {
        require_no_args("read_token", &args)?;
        Ok(token_source
            .borrow_mut()
            .read_token()?
            .map(Value::make_text)
            .unwrap_or(Value::Null))
    });

    env.set_stateful_builtin("read_int", move |args| {
        require_no_args("read_int", &args)?;
        let token = source
            .borrow_mut()
            .read_token()?
            .ok_or_else(|| RuntimeError::new("`read_int` reached end of input", None))?;
        token.parse::<i64>().map(Value::SmallInt).map_err(|_| {
            RuntimeError::new(
                format!(
                    "`read_int` expected an i64 token, found `{}`",
                    diagnostic_token(&token)
                ),
                None,
            )
        })
    });
}

fn require_no_args(name: &str, args: &[Value]) -> Result<(), RuntimeError> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::new(
            format!("`{name}` expects 0 args, got {}", args.len()),
            None,
        ))
    }
}

fn diagnostic_token(token: &str) -> String {
    const LIMIT: usize = 32;
    let mut chars = token.chars();
    let prefix = chars
        .by_ref()
        .take(LIMIT)
        .flat_map(char::escape_default)
        .collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_line_reads_share_one_utf8_cursor() {
        let mut tape = InputTape::new("  hẹllo world\r\n42".to_string());
        assert_eq!(tape.read_token().as_deref(), Some("hẹllo"));
        assert_eq!(tape.read_line().as_deref(), Some(" world"));
        assert_eq!(tape.read_line().as_deref(), Some("42"));
        assert_eq!(tape.read_line(), None);
        assert_eq!(tape.read_token(), None);
    }

    #[test]
    fn line_read_strips_cr_only_as_part_of_crlf() {
        let mut tape = InputTape::new("first\r\nsecond\r".to_string());
        assert_eq!(tape.read_line().as_deref(), Some("first"));
        assert_eq!(tape.read_line().as_deref(), Some("second\r"));
        assert_eq!(tape.read_line(), None);
    }

    #[test]
    fn eof_is_explicit_for_all_three_input_operations() {
        let mut env = Env::new();
        register_standard_input(&mut env, String::new());

        assert!(matches!(
            env.call_builtin("read_line", Vec::new()),
            Some(Ok(Value::Null))
        ));
        assert!(matches!(
            env.call_builtin("read_token", Vec::new()),
            Some(Ok(Value::Null))
        ));
        let error = env
            .call_builtin("read_int", Vec::new())
            .expect("read_int must be registered")
            .expect_err("read_int must reject end of input");
        assert_eq!(error.message, "`read_int` reached end of input");
    }

    #[test]
    fn diagnostic_tokens_are_bounded() {
        assert_eq!(diagnostic_token("short"), "short");
        assert_eq!(
            diagnostic_token(&"x".repeat(33)),
            format!("{}…", "x".repeat(32))
        );
        let escaped = diagnostic_token("\u{1b}[31m");
        assert!(!escaped.contains('\u{1b}'));
        assert!(escaped.contains("\\u{1b}"));
    }

    #[test]
    fn terminal_input_refills_lazily_and_preserves_shared_cursor() {
        let mut input = TerminalInput::default();
        let mut reader = "17 29\nhello world\n".as_bytes();
        let mut prompts = Vec::new();

        assert_eq!(
            input
                .read_token_with_io(&mut reader, &mut prompts)
                .unwrap()
                .as_deref(),
            Some("17")
        );
        assert_eq!(
            input
                .read_token_with_io(&mut reader, &mut prompts)
                .unwrap()
                .as_deref(),
            Some("29")
        );
        assert_eq!(
            input
                .read_line_with_io(&mut reader, &mut prompts)
                .unwrap()
                .as_deref(),
            Some("")
        );
        assert_eq!(
            input
                .read_line_with_io(&mut reader, &mut prompts)
                .unwrap()
                .as_deref(),
            Some("hello world")
        );
        assert_eq!(prompts, b"input> input> ");
    }
}
