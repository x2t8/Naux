use crate::ast::Span;
use crate::token::{LexError, Token, TokenKind};

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
                tokens.push(Token {
                    kind: TokenKind::Bang,
                    span,
                });
                col += 1;
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
                tokens.push(Token {
                    kind: TokenKind::Assign,
                    span,
                });
                col += 1;
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
            }
            _ => {}
        }

        // String literal
        if ch == '"' {
            let mut content = String::new();
            let mut esc = false;
            let mut cur_col = col + 1;
            while let Some((_, ch2)) = chars.next() {
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
            let val: f64 = s.parse().map_err(|_| LexError::new("Invalid number", span.clone()))?;
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

        return Err(LexError::new(format!("Unexpected character '{}'", ch), span));
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
        "loop" => TokenKind::Loop,
        "each" => TokenKind::Each,
        "while" => TokenKind::While,
        "end" => TokenKind::End,
        "in" => TokenKind::In,
        _ => TokenKind::Ident(s.to_string()),
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_part(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn peek_is_digit(iter: &mut std::iter::Peekable<std::str::CharIndices<'_>>) -> bool {
    iter.peek().map(|(_, ch)| ch.is_ascii_digit()).unwrap_or(false)
}
