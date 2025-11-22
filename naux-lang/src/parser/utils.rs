use crate::token::{Token, TokenKind};

pub fn is_action_start(tok: &Token) -> bool {
    matches!(tok.kind, TokenKind::Bang)
}
