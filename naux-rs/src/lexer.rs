use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    Tilde,
    Bang,
    At,
    Dollar,
    Caret,
    Colon,
    Assign,
    Arrow,
    Dot,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Plus,
    Minus,
    Star,
    Slash,
    Ident,
    Var,
    StringLit,
    Number,
    Color,
    Op, // == != >= <= > <
    Newline,
    Eof,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub lexeme: String,
    pub line: usize,
    pub col: usize,
}

#[derive(Error, Debug)]
pub enum LexError {
    #[error("Unexpected character '{ch}' at line {line}, col {col}")]
    UnexpectedChar { ch: char, line: usize, col: usize },
    #[error("Unterminated string at line {line}, col {col}")]
    UnterminatedString { line: usize, col: usize },
}

pub struct Lexer<'a> {
    src: &'a str,
    pos: usize, // byte offset
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            src: input,
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek_char(&self, offset: usize) -> Option<char> {
        self.src[self.pos..].chars().nth(offset)
    }

    fn advance_char(&mut self) -> Option<char> {
        let mut iter = self.src[self.pos..].char_indices();
        if let Some((_, ch)) = iter.next() {
            let len = ch.len_utf8();
            self.pos += len;
            if ch == '\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
            Some(ch)
        } else {
            None
        }
    }

    fn starts_with(&self, s: &str) -> bool {
        self.src[self.pos..].starts_with(s)
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();
        while self.pos < self.src.len() {
            let cchar = match self.peek_char(0) {
                Some(c) => c,
                None => break,
            };

            // Whitespace (non-newline)
            if cchar == ' ' || cchar == '\t' || cchar == '\r' {
                self.advance_char();
                continue;
            }

            // Newline
            if cchar == '\n' {
                tokens.push(Token {
                    kind: TokenKind::Newline,
                    lexeme: "\n".into(),
                    line: self.line,
                    col: self.col,
                });
                self.advance_char();
                continue;
            }

            // Arrow ->
            if self.starts_with("->") {
                tokens.push(Token {
                    kind: TokenKind::Arrow,
                    lexeme: "->".into(),
                    line: self.line,
                    col: self.col,
                });
                self.advance_char();
                self.advance_char();
                continue;
            }

            // Comparison ops
            if self.starts_with("==") || self.starts_with("!=") || self.starts_with(">=") || self.starts_with("<=") {
                let op = &self.src[self.pos..self.pos + 2];
                tokens.push(Token {
                    kind: TokenKind::Op,
                    lexeme: op.into(),
                    line: self.line,
                    col: self.col,
                });
                self.advance_char();
                self.advance_char();
                continue;
            }
            if cchar == '>' || cchar == '<' {
                tokens.push(Token {
                    kind: TokenKind::Op,
                    lexeme: cchar.to_string(),
                    line: self.line,
                    col: self.col,
                });
                self.advance_char();
                continue;
            }

            // Comment vs color literal
            if cchar == '#' {
                // treat #> as comment
                if self.starts_with("#>") {
                    while self.peek_char(0).is_some() && self.peek_char(0) != Some('\n') {
                        self.advance_char();
                    }
                    continue;
                }
                // color literal?
                if let Some(len) = match_color(&self.src[self.pos..]) {
                    let lex = &self.src[self.pos..self.pos + len];
                    tokens.push(Token {
                        kind: TokenKind::Color,
                        lexeme: lex.into(),
                        line: self.line,
                        col: self.col,
                    });
                    for _ in 0..lex.chars().count() {
                        self.advance_char();
                    }
                    continue;
                } else {
                    // regular comment starting with #
                    while self.peek_char(0).is_some() && self.peek_char(0) != Some('\n') {
                        self.advance_char();
                    }
                    continue;
                }
            }

            // Color literal starting with #
            if let Some(len) = match_color(&self.src[self.pos..]) {
                let lex = &self.src[self.pos..self.pos + len];
                tokens.push(Token {
                    kind: TokenKind::Color,
                    lexeme: lex.into(),
                    line: self.line,
                    col: self.col,
                });
                for _ in 0..lex.chars().count() {
                    self.advance_char();
                }
                continue;
            }

            // String literal
            if cchar == '"' {
                let start_line = self.line;
                let start_col = self.col;
                self.advance_char(); // opening quote
                let mut buf = String::new();
                while let Some(ch2) = self.peek_char(0) {
                    if ch2 == '"' {
                        break;
                    }
                    if ch2 == '\\' {
                        if let Some(esc) = self.peek_char(1) {
                            match esc {
                                'n' => buf.push('\n'),
                                't' => buf.push('\t'),
                                '"' => buf.push('"'),
                                '\\' => buf.push('\\'),
                                other => buf.push(other),
                            }
                            self.advance_char();
                            self.advance_char();
                            continue;
                        }
                    }
                    buf.push(ch2);
                    self.advance_char();
                }
                if self.peek_char(0).is_none() || self.peek_char(0) != Some('"') {
                    return Err(LexError::UnterminatedString {
                        line: start_line,
                        col: start_col,
                    });
                }
                self.advance_char(); // closing quote
                tokens.push(Token {
                    kind: TokenKind::StringLit,
                    lexeme: buf,
                    line: start_line,
                    col: start_col,
                });
                continue;
            }

            // Number literal (optional leading -)
            if cchar.is_ascii_digit() || (cchar == '-' && self.peek_char(1).map(|b| b.is_ascii_digit()).unwrap_or(false)) {
                let start = self.pos;
                let start_line = self.line;
                let start_col = self.col;
                let mut has_dot = false;
                self.advance_char();
                while let Some(ch2) = self.peek_char(0) {
                    if ch2.is_ascii_digit() {
                        self.advance_char();
                        continue;
                    }
                    if ch2 == '.' && !has_dot {
                        has_dot = true;
                        self.advance_char();
                        continue;
                    }
                    break;
                }
                let lex = &self.src[start..self.pos];
                tokens.push(Token {
                    kind: TokenKind::Number,
                    lexeme: lex.into(),
                    line: start_line,
                    col: start_col,
                });
                continue;
            }

            // Variable $ident
            if cchar == '$' && peek_is_ident_start(self.peek_char(1)) {
                let start_line = self.line;
                let start_col = self.col;
                self.advance_char(); // $
                let ident = self.read_ident();
                tokens.push(Token {
                    kind: TokenKind::Var,
                    lexeme: ident,
                    line: start_line,
                    col: start_col,
                });
                continue;
            }

            // Identifier
            if peek_is_ident_start(Some(cchar)) {
                let start_line = self.line;
                let start_col = self.col;
                let ident = self.read_ident();
                tokens.push(Token {
                    kind: TokenKind::Ident,
                    lexeme: ident,
                    line: start_line,
                    col: start_col,
                });
                continue;
            }

            // Single char tokens
            let single = match cchar {
                '~' => Some(TokenKind::Tilde),
                '!' => Some(TokenKind::Bang),
                '@' => Some(TokenKind::At),
                '$' => Some(TokenKind::Dollar),
                '^' => Some(TokenKind::Caret),
                ':' => Some(TokenKind::Colon),
                '=' => Some(TokenKind::Assign),
                '.' => Some(TokenKind::Dot),
                '[' => Some(TokenKind::LBracket),
                ']' => Some(TokenKind::RBracket),
                '{' => Some(TokenKind::LBrace),
                '}' => Some(TokenKind::RBrace),
                ',' => Some(TokenKind::Comma),
                '+' => Some(TokenKind::Plus),
                '-' => Some(TokenKind::Minus),
                '*' => Some(TokenKind::Star),
                '/' => Some(TokenKind::Slash),
                _ => None,
            };
            if let Some(kind) = single {
                tokens.push(Token {
                    kind,
                    lexeme: cchar.to_string(),
                    line: self.line,
                    col: self.col,
                });
                self.advance_char();
                continue;
            }

            return Err(LexError::UnexpectedChar {
                ch: cchar,
                line: self.line,
                col: self.col,
            });
        }

        tokens.push(Token {
            kind: TokenKind::Eof,
            lexeme: "".into(),
            line: self.line,
            col: self.col,
        });
        Ok(tokens)
    }

    fn read_ident(&mut self) -> String {
        let mut ident = String::new();
        while let Some(ch) = self.peek_char(0) {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ident.push(ch);
                self.advance_char();
            } else {
                break;
            }
        }
        ident
    }
}

fn match_color(slice: &str) -> Option<usize> {
    let s = slice;
    // #rgb or #rrggbb
    if s.len() >= 4 && s.starts_with('#') {
        let body3 = &s[1..4];
        if body3.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(4);
        }
    }
    if s.len() >= 7 && s.starts_with('#') {
        let body6 = &s[1..7];
        if body6.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(7);
        }
    }
    None
}

fn peek_is_ident_start(b: Option<char>) -> bool {
    matches!(b, Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
}
