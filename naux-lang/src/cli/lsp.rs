use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};

use crate::ast::Span;
use crate::lexer;
use crate::parser;
use crate::typecheck;

pub fn handle_lsp() -> Result<(), String> {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = io::stdout();
    let mut docs: HashMap<String, String> = HashMap::new();

    loop {
        let msg = match read_message(&mut reader) {
            Ok(Some(msg)) => msg,
            Ok(None) => break,
            Err(err) => return Err(err),
        };
        let json = match parse_json(&msg) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let JsonValue::Object(ref obj) = json else {
            continue;
        };

        let method = obj
            .get("method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let id = obj.get("id");

        match method.as_deref() {
            Some("initialize") => {
                let result = "{\"capabilities\":{\"textDocumentSync\":{\"openClose\":true,\"change\":1}},\"serverInfo\":{\"name\":\"Naux LSP\",\"version\":\"0.1\"}}".to_string();
                send_response(&mut stdout, id, &result)?;
            }
            Some("shutdown") => {
                send_response(&mut stdout, id, "null")?;
            }
            Some("exit") => break,
            Some("textDocument/didOpen") => {
                if let Some(uri) = get_path_str(&json, &["params", "textDocument", "uri"]) {
                    if let Some(text) = get_path_str(&json, &["params", "textDocument", "text"]) {
                        docs.insert(uri.to_string(), text.to_string());
                        publish_diagnostics(&mut stdout, uri, text)?;
                    }
                }
            }
            Some("textDocument/didChange") => {
                if let Some(uri) = get_path_str(&json, &["params", "textDocument", "uri"]) {
                    if let Some(text) = get_path_change_text(&json) {
                        docs.insert(uri.to_string(), text.to_string());
                        publish_diagnostics(&mut stdout, uri, text)?;
                    }
                }
            }
            Some("textDocument/didClose") => {
                if let Some(uri) = get_path_str(&json, &["params", "textDocument", "uri"]) {
                    docs.remove(uri);
                    publish_diagnostics(&mut stdout, uri, "")?;
                }
            }
            Some("textDocument/hover") => {
                send_response(&mut stdout, id, "null")?;
            }
            Some("textDocument/definition") => {
                send_response(&mut stdout, id, "null")?;
            }
            _ => {
                if id.is_some() {
                    send_response(&mut stdout, id, "null")?;
                }
            }
        }
    }

    Ok(())
}

fn read_message(reader: &mut impl BufRead) -> Result<Option<String>, String> {
    let mut content_len: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(None);
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            content_len = rest.trim().parse::<usize>().ok();
        }
    }
    let len = content_len.ok_or_else(|| "Missing Content-Length".to_string())?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
    let msg = String::from_utf8_lossy(&buf).to_string();
    Ok(Some(msg))
}

fn send_response(
    out: &mut impl Write,
    id: Option<&JsonValue>,
    result_json: &str,
) -> Result<(), String> {
    let id_json = id.map(json_simple).unwrap_or_else(|| "null".to_string());
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
        id_json, result_json
    );
    write_message(out, &body)
}

fn publish_diagnostics(out: &mut impl Write, uri: &str, src: &str) -> Result<(), String> {
    let diags = collect_diagnostics(src);
    let mut items = Vec::new();
    for d in diags {
        items.push(format!(
            "{{\"range\":{{\"start\":{{\"line\":{},\"character\":{}}},\"end\":{{\"line\":{},\"character\":{}}}}},\"severity\":{},\"source\":\"naux\",\"message\":{}}}",
            d.range.start.line,
            d.range.start.character,
            d.range.end.line,
            d.range.end.character,
            d.severity,
            json_string(&d.message)
        ));
    }
    let diag_json = items.join(",");
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\",\"params\":{{\"uri\":{},\"diagnostics\":[{}]}}}}",
        json_string(uri),
        diag_json
    );
    write_message(out, &body)
}

fn write_message(out: &mut impl Write, body: &str) -> Result<(), String> {
    let bytes = body.as_bytes();
    write!(out, "Content-Length: {}\r\n\r\n", bytes.len()).map_err(|e| e.to_string())?;
    out.write_all(bytes).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Clone)]
struct Diagnostic {
    range: Range,
    severity: u32,
    message: String,
}

#[derive(Debug, Clone, Copy)]
struct Range {
    start: Position,
    end: Position,
}

#[derive(Debug, Clone, Copy)]
struct Position {
    line: usize,
    character: usize,
}

fn collect_diagnostics(src: &str) -> Vec<Diagnostic> {
    let tokens = match lexer::lex(src) {
        Ok(t) => t,
        Err(err) => {
            return vec![Diagnostic {
                range: span_to_range(err.span),
                severity: 1,
                message: format!("Lex error: {}", err.message),
            }]
        }
    };
    let ast = match parser::Parser::from_tokens(&tokens) {
        Ok(ast) => ast,
        Err(err) => {
            return vec![Diagnostic {
                range: span_to_range(err.span),
                severity: 1,
                message: format!("Parse error: {}", err.message),
            }]
        }
    };
    if let Err(err) = typecheck::check_program(&ast) {
        let range = err.span.map(span_to_range).unwrap_or(Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 0,
                character: 1,
            },
        });
        return vec![Diagnostic {
            range,
            severity: 1,
            message: format!("Type error: {}", err.message),
        }];
    }
    Vec::new()
}

fn span_to_range(span: Span) -> Range {
    let line = span.line.saturating_sub(1);
    let col = span.column.saturating_sub(1);
    Range {
        start: Position {
            line,
            character: col,
        },
        end: Position {
            line,
            character: col + 1,
        },
    }
}

fn get_path_str<'a>(value: &'a JsonValue, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str()
}

fn get_path_change_text(value: &JsonValue) -> Option<&str> {
    let changes = get_path(value, &["params", "contentChanges"])?;
    let JsonValue::Array(items) = changes else {
        return None;
    };
    let first = items.first()?;
    let JsonValue::Object(obj) = first else {
        return None;
    };
    obj.get("text")?.as_str()
}

fn get_path<'a>(value: &'a JsonValue, path: &[&str]) -> Option<&'a JsonValue> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    Some(current)
}

#[derive(Debug, Clone)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(HashMap<String, JsonValue>),
}

impl JsonValue {
    fn as_str(&self) -> Option<&str> {
        if let JsonValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(map) => map.get(key),
            _ => None,
        }
    }
}

fn json_string(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            _ => out.push(ch),
        }
    }
    out
}

fn json_simple(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => {
            if n.fract().abs() < f64::EPSILON {
                format!("{:.0}", n)
            } else {
                n.to_string()
            }
        }
        JsonValue::String(s) => json_string(s),
        _ => "null".to_string(),
    }
}

fn parse_json(input: &str) -> Result<JsonValue, String> {
    let mut parser = JsonParser::new(input);
    let value = parser.parse_value()?;
    parser.skip_ws();
    Ok(value)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\n' | b'\r' | b'\t' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.bytes.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool(false)),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            _ => Err("Invalid JSON".into()),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], value: JsonValue) -> Result<JsonValue, String> {
        if self.bytes.len() < self.pos + lit.len() {
            return Err("Unexpected EOF".into());
        }
        if &self.bytes[self.pos..self.pos + lit.len()] != lit {
            return Err("Invalid literal".into());
        }
        self.pos += lit.len();
        Ok(value)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.next() != Some(b'"') {
            return Err("Expected string".into());
        }
        let mut out = Vec::new();
        while let Some(b) = self.next() {
            match b {
                b'"' => break,
                b'\\' => {
                    let esc = self.next().ok_or("Invalid escape")?;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let code = self.parse_hex4()?;
                            if let Some(ch) = char::from_u32(code) {
                                let mut buf = [0u8; 4];
                                let s = ch.encode_utf8(&mut buf);
                                out.extend_from_slice(s.as_bytes());
                            }
                        }
                        _ => return Err("Invalid escape".into()),
                    }
                }
                _ => out.push(b),
            }
        }
        String::from_utf8(out).map_err(|_| "Invalid UTF-8".into())
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let b = self.next().ok_or("Unexpected EOF")?;
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => return Err("Invalid \\u escape".into()),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let slice = &self.bytes[start..self.pos];
        let s = std::str::from_utf8(slice).map_err(|_| "Invalid number")?;
        let num = s.parse::<f64>().map_err(|_| "Invalid number")?;
        Ok(JsonValue::Number(num))
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        if self.next() != Some(b'[') {
            return Err("Expected array".into());
        }
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                break;
            }
            let val = self.parse_value()?;
            items.push(val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("Expected , or ]".into()),
            }
        }
        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        if self.next() != Some(b'{') {
            return Err("Expected object".into());
        }
        let mut map = HashMap::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                break;
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.next() != Some(b':') {
                return Err("Expected :".into());
            }
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("Expected , or }".into()),
            }
        }
        Ok(JsonValue::Object(map))
    }
}
