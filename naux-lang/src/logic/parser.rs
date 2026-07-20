use crate::logic::ast::Term;

#[derive(Debug, PartialEq, Clone)]
pub enum Token {
    // Keywords
    Nat,
    Bool,
    Lambda, // λ
    Pi,     // Π
    Let,
    In,
    Eq,
    Refl,
    And,
    Pair,
    Fst,
    Snd,
    Sort, // Type0, Prop

    // Literals
    Int(u64),
    BoolLit(bool),
    Ident(String), // Variable names

    // Symbols
    Colon,  // :
    Dot,    // .
    Arrow,  // ->
    LParen, // (
    RParen, // )
    Invalid(char),
    Eof,
}

pub struct Lexer<'a> {
    input: std::iter::Peekable<std::str::Chars<'a>>,
    current_char: Option<char>,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        let mut lexer = Lexer {
            input: input.chars().peekable(),
            current_char: None,
        };
        lexer.read_char(); // Initialize current_char
        lexer
    }

    fn read_char(&mut self) {
        self.current_char = self.input.next();
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.current_char {
            if c.is_whitespace() {
                self.read_char();
            } else {
                break;
            }
        }
    }

    fn read_identifier(&mut self, first_char: char) -> String {
        let mut ident = String::new();
        ident.push(first_char);
        self.read_char();
        while let Some(c) = self.current_char {
            if c.is_alphanumeric() || c == '_' {
                ident.push(c);
                self.read_char();
            } else {
                break;
            }
        }
        ident
    }

    fn read_number(&mut self, first_char: char) -> u64 {
        let mut number_str = String::new();
        number_str.push(first_char);
        self.read_char();
        while let Some(c) = self.current_char {
            if c.is_ascii_digit() {
                number_str.push(c);
                self.read_char();
            } else {
                break;
            }
        }
        number_str.parse().unwrap_or(0) // Should handle errors more gracefully in a real parser
    }

    pub fn next_token(&mut self) -> Token {
        self.skip_whitespace();
        match self.current_char {
            Some(':') => {
                self.read_char();
                Token::Colon
            }
            Some('.') => {
                self.read_char();
                Token::Dot
            }
            Some('(') => {
                self.read_char();
                Token::LParen
            }
            Some(')') => {
                self.read_char();
                Token::RParen
            }
            Some('-') => {
                self.read_char();
                if self.current_char == Some('>') {
                    self.read_char();
                    Token::Arrow
                } else {
                    Token::Invalid('-')
                }
            }
            Some('λ') => {
                self.read_char();
                Token::Lambda
            }
            Some('Π') => {
                self.read_char();
                Token::Pi
            }
            Some(c) if c.is_alphabetic() => {
                let ident = self.read_identifier(c);
                match ident.as_str() {
                    "Nat" => Token::Nat,
                    "Bool" => Token::Bool,
                    "let" => Token::Let,
                    "in" => Token::In,
                    "Eq" => Token::Eq,
                    "Refl" => Token::Refl,
                    "And" => Token::And,
                    "Pair" => Token::Pair,
                    "Fst" => Token::Fst,
                    "Snd" => Token::Snd,
                    "Sort" => Token::Sort,
                    "true" => Token::BoolLit(true),
                    "false" => Token::BoolLit(false),
                    _ => Token::Ident(ident),
                }
            }
            Some(c) if c.is_ascii_digit() => {
                let num = self.read_number(c);
                Token::Int(num)
            }
            None => Token::Eof,
            Some(c) => {
                self.read_char();
                Token::Invalid(c)
            }
        }
    }
}

// Minimal Parser implementation
pub struct Parser<'a> {
    lexer: Lexer<'a>,
    current_token: Token,
    peek_token: Token,
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a str) -> Self {
        let mut lexer = Lexer::new(input);
        let current_token = lexer.next_token();
        let peek_token = lexer.next_token();
        Parser {
            lexer,
            current_token,
            peek_token,
        }
    }

    fn next_token(&mut self) {
        self.current_token = self.peek_token.clone();
        self.peek_token = self.lexer.next_token();
    }

    pub fn parse_term(&mut self) -> Result<Term, String> {
        let term = self.parse_arrow_type()?;
        if let Token::Invalid(c) = self.current_token {
            return Err(format!("Unexpected character: {}", c));
        }
        Ok(term)
    }

    fn parse_arrow_type(&mut self) -> Result<Term, String> {
        let left = self.parse_app_term()?;
        if self.current_token == Token::Arrow {
            self.next_token(); // Consume "->"
            let right = self.parse_arrow_type()?;
            return Ok(Term::Pi {
                ty: Box::new(left),
                body: Box::new(right),
            });
        }
        Ok(left)
    }

    fn parse_app_term(&mut self) -> Result<Term, String> {
        let mut term = self.parse_atomic_term()?;

        // This is a simplification; actual parsing for application would be more complex
        // and handle multiple arguments. For now, it only handles `f x` form.
        while matches!(
            self.current_token,
            Token::Nat
                | Token::Bool
                | Token::Int(_)
                | Token::BoolLit(_)
                | Token::Ident(_)
                | Token::Lambda
                | Token::LParen
        ) {
            let arg = self.parse_atomic_term()?;
            term = Term::App {
                fun: Box::new(term),
                arg: Box::new(arg),
            };
        }
        Ok(term)
    }

    fn parse_atomic_term(&mut self) -> Result<Term, String> {
        match self.current_token {
            Token::Nat => {
                self.next_token();
                Ok(Term::Nat)
            }
            Token::Bool => {
                self.next_token();
                Ok(Term::Bool)
            }
            Token::Int(n) => {
                self.next_token();
                Ok(Term::NatLit(n))
            }
            Token::BoolLit(b) => {
                self.next_token();
                Ok(Term::BoolLit(b))
            }
            Token::Ident(_) => {
                // This will need proper de Bruijn index resolution later
                // For now, we'll just treat any identifier as Var(0) or similar
                // This is a placeholder and will need to be replaced with a proper scope management
                self.next_token();
                // Find the index of the variable in the context.
                // For now, let's assume all idents are Var(0)
                // TODO: Implement proper variable resolution
                Ok(Term::Var(0))
            }
            Token::Lambda => self.parse_lambda_term(),
            Token::LParen => {
                self.next_token(); // Consume '('
                let term = self.parse_term()?;
                if self.current_token != Token::RParen {
                    return Err("Expected ')'".to_string());
                }
                self.next_token(); // Consume ')'
                Ok(term)
            }
            Token::Invalid(c) => Err(format!("Unexpected character: {}", c)),
            _ => Err(format!("Unexpected token: {:?}", self.current_token)),
        }
    }

    fn parse_lambda_term(&mut self) -> Result<Term, String> {
        self.next_token(); // Consume 'λ'
        let _param_name = match self.current_token {
            Token::Ident(ref s) => {
                let name = s.clone();
                self.next_token();
                name
            }
            _ => return Err("Expected identifier after λ".to_string()),
        };

        if self.current_token != Token::Colon {
            return Err("Expected ':' after parameter name".to_string());
        }
        self.next_token(); // Consume ':'

        let param_type = self.parse_term()?; // Parse the type of the parameter

        if self.current_token != Token::Dot {
            return Err("Expected '.' after parameter type".to_string());
        }
        self.next_token(); // Consume '.'

        let body = self.parse_term()?; // Parse the body of the lambda

        // This is a simplification. The 'ty' in Lambda should be the type of the bound variable,
        // but for now we are just creating the structure.
        // Proper de Bruijn indexing will handle the 'Var' within the body.
        Ok(Term::Lambda {
            ty: Box::new(param_type),
            body: Box::new(body),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexer_simple() {
        let input = "Nat Bool λ Π let in Eq Refl And Pair Fst Snd Sort 123 true false x : . -> ( )";
        let mut lexer = Lexer::new(input);
        let tokens = vec![
            Token::Nat,
            Token::Bool,
            Token::Lambda,
            Token::Pi,
            Token::Let,
            Token::In,
            Token::Eq,
            Token::Refl,
            Token::And,
            Token::Pair,
            Token::Fst,
            Token::Snd,
            Token::Sort,
            Token::Int(123),
            Token::BoolLit(true),
            Token::BoolLit(false),
            Token::Ident("x".to_string()),
            Token::Colon,
            Token::Dot,
            Token::Arrow,
            Token::LParen,
            Token::RParen,
            Token::Eof,
        ];

        for expected_token in tokens {
            assert_eq!(lexer.next_token(), expected_token);
        }
    }

    #[test]
    fn test_parser_nat() {
        let input = "Nat";
        let mut parser = Parser::new(input);
        assert_eq!(parser.parse_term().unwrap(), Term::Nat);
    }

    #[test]
    fn test_parser_bool() {
        let input = "Bool";
        let mut parser = Parser::new(input);
        assert_eq!(parser.parse_term().unwrap(), Term::Bool);
    }

    #[test]
    fn test_parser_nat_lit() {
        let input = "123";
        let mut parser = Parser::new(input);
        assert_eq!(parser.parse_term().unwrap(), Term::NatLit(123));
    }

    #[test]
    fn test_parser_bool_lit() {
        let input = "true";
        let mut parser = Parser::new(input);
        assert_eq!(parser.parse_term().unwrap(), Term::BoolLit(true));
    }

    #[test]
    fn test_parser_arrow_type() {
        let input = "Nat -> Bool";
        let mut parser = Parser::new(input);
        assert_eq!(
            parser.parse_term().unwrap(),
            Term::Pi {
                ty: Box::new(Term::Nat),
                body: Box::new(Term::Bool)
            }
        );
    }

    #[test]
    fn test_parser_nested_arrow_type() {
        let input = "Nat -> Bool -> Nat";
        let mut parser = Parser::new(input);
        // Should parse as Nat -> (Bool -> Nat)
        assert_eq!(
            parser.parse_term().unwrap(),
            Term::Pi {
                ty: Box::new(Term::Nat),
                body: Box::new(Term::Pi {
                    ty: Box::new(Term::Bool),
                    body: Box::new(Term::Nat)
                })
            }
        );
    }

    #[test]
    fn test_parser_lambda() {
        let input = "λx: Nat. x";
        let mut parser = Parser::new(input);
        assert_eq!(
            parser.parse_term().unwrap(),
            Term::Lambda {
                ty: Box::new(Term::Nat),
                body: Box::new(Term::Var(0)) // Placeholder for 'x'
            }
        );
    }

    #[test]
    fn test_parser_app() {
        let input = "f x";
        let mut parser = Parser::new(input);
        assert_eq!(
            parser.parse_term().unwrap(),
            Term::App {
                fun: Box::new(Term::Var(0)), // Placeholder for 'f'
                arg: Box::new(Term::Var(0))  // Placeholder for 'x'
            }
        );
    }
}
