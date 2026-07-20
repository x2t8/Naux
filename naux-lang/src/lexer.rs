use crate::ast::Span;
use crate::token::{LexError, Token, TokenKind};

const MAX_BYTES_LITERAL_LEN: usize = 65_536;

pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    let mut line: usize = 1;
    let mut col: usize = 1;

    while let Some((_, ch)) = chars.next() {
        // Update line/col for current char
        if ch == '\n' {
            line += 1;
            col = 1;
            tokens.push(Token {
                kind: TokenKind::Newline,
                span: Span { line, column: col },
            });
            continue;
        }

        if ch.is_whitespace() {
            col += 1;
            continue;
        }

        if ch == '#' {
            let mut cur_col = col + 1;
            let mut newline_found = false;
            for (_, ch2) in chars.by_ref() {
                if ch2 == '\n' {
                    line += 1;
                    col = 1;
                    tokens.push(Token {
                        kind: TokenKind::Newline,
                        span: Span { line, column: col },
                    });
                    newline_found = true;
                    break;
                }
                cur_col += 1;
            }
            if !newline_found {
                col = cur_col;
            }
            continue;
        }

        let span = Span { line, column: col };

        // Symbols
        match ch {
            '~' => {
                tokens.push(Token {
                    kind: TokenKind::Tilde,
                    span,
                });
                col += 1;
                continue;
            }
            '!' => {
                if let Some((_, '=')) = chars.peek() {
                    chars.next();
                    tokens.push(Token {
                        kind: TokenKind::Op("!=".into()),
                        span,
                    });
                    col += 2;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Bang,
                        span,
                    });
                    col += 1;
                }
                continue;
            }
            '$' => {
                tokens.push(Token {
                    kind: TokenKind::Dollar,
                    span,
                });
                col += 1;
                continue;
            }
            '=' => {
                if let Some((_, '=')) = chars.peek() {
                    chars.next();
                    tokens.push(Token {
                        kind: TokenKind::Op("==".into()),
                        span,
                    });
                    col += 2;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Assign,
                        span,
                    });
                    col += 1;
                }
                continue;
            }
            '.' => {
                tokens.push(Token {
                    kind: TokenKind::Dot,
                    span,
                });
                col += 1;
                continue;
            }
            ',' => {
                tokens.push(Token {
                    kind: TokenKind::Comma,
                    span,
                });
                col += 1;
                continue;
            }
            '^' => {
                tokens.push(Token {
                    kind: TokenKind::Caret,
                    span,
                });
                col += 1;
                continue;
            }
            '+' => {
                tokens.push(Token {
                    kind: TokenKind::Plus,
                    span,
                });
                col += 1;
                continue;
            }
            '*' => {
                tokens.push(Token {
                    kind: TokenKind::Star,
                    span,
                });
                col += 1;
                continue;
            }
            '%' => {
                tokens.push(Token {
                    kind: TokenKind::Percent,
                    span,
                });
                col += 1;
                continue;
            }
            '<' => {
                if let Some((bytes, consumed_cols)) = try_lex_bytes_literal(&mut chars, &span)? {
                    tokens.push(Token {
                        kind: TokenKind::BytesLit(bytes),
                        span,
                    });
                    col += consumed_cols;
                    continue;
                }
                if let Some((_, '<')) = chars.peek() {
                    chars.next();
                    tokens.push(Token {
                        kind: TokenKind::Op("<<".into()),
                        span,
                    });
                    col += 2;
                } else if let Some((_, '=')) = chars.peek() {
                    chars.next();
                    tokens.push(Token {
                        kind: TokenKind::Op("<=".into()),
                        span,
                    });
                    col += 2;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Op("<".into()),
                        span,
                    });
                    col += 1;
                }
                continue;
            }
            '>' => {
                if let Some((_, '=')) = chars.peek() {
                    chars.next();
                    tokens.push(Token {
                        kind: TokenKind::Op(">=".into()),
                        span,
                    });
                    col += 2;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Op(">".into()),
                        span,
                    });
                    col += 1;
                }
                continue;
            }
            '/' => {
                tokens.push(Token {
                    kind: TokenKind::Slash,
                    span,
                });
                col += 1;
                continue;
            }
            '(' => {
                tokens.push(Token {
                    kind: TokenKind::LParen,
                    span,
                });
                col += 1;
                continue;
            }
            ')' => {
                tokens.push(Token {
                    kind: TokenKind::RParen,
                    span,
                });
                col += 1;
                continue;
            }
            '{' => {
                tokens.push(Token {
                    kind: TokenKind::LBrace,
                    span,
                });
                col += 1;
                continue;
            }
            '}' => {
                tokens.push(Token {
                    kind: TokenKind::RBrace,
                    span,
                });
                col += 1;
                continue;
            }
            '[' => {
                tokens.push(Token {
                    kind: TokenKind::LBracket,
                    span,
                });
                col += 1;
                continue;
            }
            ']' => {
                tokens.push(Token {
                    kind: TokenKind::RBracket,
                    span,
                });
                col += 1;
                continue;
            }
            '-' => {
                // maybe arrow
                if let Some((_, '>')) = chars.peek() {
                    // consume '>'
                    chars.next();
                    tokens.push(Token {
                        kind: TokenKind::Arrow,
                        span,
                    });
                    col += 2;
                    continue;
                }
                tokens.push(Token {
                    kind: TokenKind::Minus,
                    span,
                });
                col += 1;
                continue;
            }
            ':' => {
                tokens.push(Token {
                    kind: TokenKind::Colon,
                    span,
                });
                col += 1;
                continue;
            }
            _ => {}
        }

        // String literal
        if ch == '"' {
            let mut content = String::new();
            let mut esc = false;
            let mut cur_col = col + 1;
            for (_, ch2) in chars.by_ref() {
                if esc {
                    match ch2 {
                        'n' => content.push('\n'),
                        't' => content.push('\t'),
                        '"' => content.push('"'),
                        '\\' => content.push('\\'),
                        other => content.push(other),
                    }
                    esc = false;
                } else if ch2 == '\\' {
                    esc = true;
                } else if ch2 == '"' {
                    break;
                } else {
                    content.push(ch2);
                }
                if ch2 == '\n' {
                    line += 1;
                    cur_col = 1;
                } else {
                    cur_col += 1;
                }
            }
            tokens.push(Token {
                kind: TokenKind::StringLit(content),
                span,
            });
            col = cur_col + 1;
            continue;
        }

        // Logical ops
        if ch == '&' {
            if let Some((_, '&')) = chars.peek() {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::AndAnd,
                    span,
                });
                col += 2;
                continue;
            }
        }
        if ch == '|' {
            if let Some((_, '|')) = chars.peek() {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::OrOr,
                    span,
                });
                col += 2;
                continue;
            }
        }

        // Number literal
        if ch.is_ascii_digit() || (ch == '-' && peek_is_digit(&mut chars)) {
            let mut s = String::new();
            s.push(ch);
            let mut cur_col = col + 1;
            while let Some((_, nxt)) = chars.peek() {
                if nxt.is_ascii_digit() || *nxt == '.' {
                    s.push(*nxt);
                    chars.next();
                    cur_col += 1;
                } else {
                    break;
                }
            }
            let val: f64 = s
                .parse()
                .map_err(|_| LexError::new("Invalid number", span.clone()))?;
            tokens.push(Token {
                kind: TokenKind::Number(val),
                span,
            });
            col = cur_col;
            continue;
        }

        // Identifier / keyword
        if is_ident_start(ch) {
            let mut ident = String::new();
            ident.push(ch);
            let mut cur_col = col + 1;
            while let Some((_, nxt)) = chars.peek() {
                if is_ident_part(*nxt) {
                    ident.push(*nxt);
                    chars.next();
                    cur_col += 1;
                } else {
                    break;
                }
            }
            let kind = keyword_or_ident(&ident);
            tokens.push(Token { kind, span });
            col = cur_col;
            continue;
        }

        if is_ignored_punctuation(ch) {
            col += 1;
            continue;
        }

        return Err(LexError::new(
            format!("Unexpected character '{}'", ch),
            span,
        ));
    }

    tokens.push(Token {
        kind: TokenKind::Eof,
        span: Span { line, column: col },
    });
    Ok(tokens)
}

fn keyword_or_ident(s: &str) -> TokenKind {
    match s {
        "if" => TokenKind::If,
        "else" => TokenKind::Else,
        "rite" => TokenKind::Rite,
        "unsafe" => TokenKind::Unsafe,
        "import" => TokenKind::Import,
        "fn" => TokenKind::Fn,
        "loop" => TokenKind::Loop,
        "each" => TokenKind::Each,
        "while" => TokenKind::While,
        "end" => TokenKind::End,
        "in" => TokenKind::In,
        _ => TokenKind::Ident(s.to_string()),
    }
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn is_ident_part(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

fn is_ignored_punctuation(c: char) -> bool {
    matches!(c, '?' | '\\' | '—' | '–')
}

fn peek_is_digit(iter: &mut std::iter::Peekable<std::str::CharIndices<'_>>) -> bool {
    iter.peek()
        .map(|(_, ch)| ch.is_ascii_digit())
        .unwrap_or(false)
}

fn is_inline_ws(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r')
}

fn hex_nibble(ch: char) -> Option<u8> {
    match ch {
        '0'..='9' => Some((ch as u8) - b'0'),
        'a'..='f' => Some((ch as u8) - b'a' + 10),
        'A'..='F' => Some((ch as u8) - b'A' + 10),
        _ => None,
    }
}

fn try_lex_bytes_literal(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    span: &Span,
) -> Result<Option<(Vec<u8>, usize)>, LexError> {
    let mut look = chars.clone();
    let mut consumed_cols = 1usize; // include leading '<'

    for expected in ['b', 'y', 't', 'e', 's', ':'] {
        match look.next() {
            Some((_, ch)) if ch == expected => consumed_cols += 1,
            _ => return Ok(None),
        }
    }

    let mut out = Vec::new();
    loop {
        while let Some((_, ch)) = look.peek() {
            if is_inline_ws(*ch) {
                look.next();
                consumed_cols += 1;
            } else {
                break;
            }
        }

        match look.peek().copied() {
            Some((_, '>')) => {
                look.next();
                consumed_cols += 1;
                if out.is_empty() {
                    return Err(LexError::new("Empty bytes literal", span.clone()));
                }
                *chars = look;
                return Ok(Some((out, consumed_cols)));
            }
            Some((_, '\n')) | None => {
                return Err(LexError::new("Unterminated bytes literal", span.clone()))
            }
            _ => {}
        }

        let (_, hi) = look
            .next()
            .ok_or_else(|| LexError::new("Unterminated bytes literal", span.clone()))?;
        consumed_cols += 1;
        let (_, lo) = look
            .next()
            .ok_or_else(|| LexError::new("Unterminated bytes literal", span.clone()))?;
        consumed_cols += 1;

        let hi = hex_nibble(hi)
            .ok_or_else(|| LexError::new("Invalid hex byte in bytes literal", span.clone()))?;
        let lo = hex_nibble(lo)
            .ok_or_else(|| LexError::new("Invalid hex byte in bytes literal", span.clone()))?;
        out.push((hi << 4) | lo);

        if out.len() > MAX_BYTES_LITERAL_LEN {
            return Err(LexError::new(
                format!(
                    "Bytes literal too large (max {} bytes)",
                    MAX_BYTES_LITERAL_LEN
                ),
                span.clone(),
            ));
        }

        match look.peek().copied() {
            Some((_, '>')) => {}
            Some((_, ch)) if is_inline_ws(ch) => {}
            Some((_, '\n')) | None => {
                return Err(LexError::new("Unterminated bytes literal", span.clone()))
            }
            Some((_, _)) => {
                return Err(LexError::new(
                    "Expected whitespace or '>' after byte pair",
                    span.clone(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_bytes_literal_without_space_after_colon() {
        let tokens = lex("$buf = <bytes:DE AD BE EF>").expect("lex");
        assert!(tokens.iter().any(
            |t| matches!(t.kind, TokenKind::BytesLit(ref b) if b == &[0xDE, 0xAD, 0xBE, 0xEF])
        ));
    }

    #[test]
    fn lex_bytes_literal_too_large_rejected() {
        let body = "AA ".repeat(MAX_BYTES_LITERAL_LEN + 1);
        let src = format!("$buf = <bytes:{}>", body);
        let err = lex(&src).expect_err("expected size limit error");
        assert!(err.message.contains("too large"));
    }

    #[test]
    fn lex_unicode_identifiers_and_demo_punctuation() {
        let tokens = lex("$kết_quả = 42?\n—\n\\\n").expect("lex");
        assert!(tokens
            .iter()
            .any(|t| matches!(&t.kind, TokenKind::Ident(name) if name == "kết_quả")));
        assert!(!tokens
            .iter()
            .any(|t| matches!(&t.kind, TokenKind::Op(op) if op == "?")));
    }
}
