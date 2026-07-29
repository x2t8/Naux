//! Algebraic effect type definitions.
//!
//! An **effect** is a set of named operations that represent side effects.
//! A **handler** intercepts effect operations and provides implementations.
//!
//! This maps directly to Naux's existing action system:
//! - `!say` → `EffectOp::Say` in the `IO` effect
//! - `!ask` → `EffectOp::Ask` in the `IO` effect
//! - `!fetch` → `EffectOp::Fetch` in the `Net` effect

use std::collections::HashMap;
use std::fmt;

/// Unique identifier for an effect.
pub type EffectId = u32;

/// An effect declaration: a named set of operations.
#[derive(Debug, Clone)]
pub struct EffectDecl {
    pub name: String,
    pub operations: Vec<EffectOp>,
}

/// An effect operation (one action within an effect).
#[derive(Debug, Clone)]
pub struct EffectOp {
    pub name: String,
    pub params: Vec<EffectParam>,
    pub return_type: EffectType,
}

/// Parameter for an effect operation.
#[derive(Debug, Clone)]
pub struct EffectParam {
    pub name: String,
    pub ty: EffectType,
}

/// Simple type system for effect signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectType {
    Num,
    Text,
    Bool,
    Null,
    Any,
    List(Box<EffectType>),
}

impl fmt::Display for EffectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Num => write!(f, "Num"),
            Self::Text => write!(f, "Text"),
            Self::Bool => write!(f, "Bool"),
            Self::Null => write!(f, "Null"),
            Self::Any => write!(f, "Any"),
            Self::List(inner) => write!(f, "List<{}>", inner),
        }
    }
}

/// A full effect signature: effect name + row of operations.
#[derive(Debug, Clone)]
pub struct EffectSignature {
    pub effects: Vec<String>,
}

impl EffectSignature {
    pub fn pure() -> Self {
        Self {
            effects: Vec::new(),
        }
    }

    pub fn with(mut self, effect: &str) -> Self {
        if !self.effects.contains(&effect.to_string()) {
            self.effects.push(effect.to_string());
        }
        self
    }

    pub fn is_pure(&self) -> bool {
        self.effects.is_empty()
    }
}

impl fmt::Display for EffectSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.effects.is_empty() {
            write!(f, "Pure")
        } else {
            write!(f, "{{{}}}", self.effects.join(", "))
        }
    }
}

/// An effect represents a runtime effect instance.
#[derive(Debug, Clone)]
pub struct Effect {
    pub name: String,
    pub op: String,
    pub args: Vec<EffectValue>,
}

/// Values passed through effect operations.
#[derive(Debug, Clone)]
pub enum EffectValue {
    Num(f64),
    Text(String),
    Bool(bool),
    Null,
    List(Vec<EffectValue>),
}

impl fmt::Display for EffectValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Num(n) => write!(f, "{}", n),
            Self::Text(s) => write!(f, "\"{}\"", s),
            Self::Bool(b) => write!(f, "{}", b),
            Self::Null => write!(f, "null"),
            Self::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "]")
            }
        }
    }
}

/// An effect handler: maps effect operations to implementations.
#[derive(Debug, Clone)]
pub struct EffectHandler {
    pub effect_name: String,
    pub clauses: Vec<HandlerClause>,
    pub return_clause: Option<ReturnClause>,
}

/// A single handler clause: what to do when an operation is performed.
#[derive(Debug, Clone)]
pub struct HandlerClause {
    pub op_name: String,
    pub param_names: Vec<String>,
    pub resume: bool,
    pub action: HandlerAction,
}

/// What a handler clause does.
#[derive(Debug, Clone)]
pub enum HandlerAction {
    /// Resume the computation with a value.
    Resume(EffectValue),
    /// Replace the operation result with a constant.
    Replace(EffectValue),
    /// Collect into a log/buffer.
    Collect,
    /// Forward to default handler.
    Forward,
    /// Suppress the effect entirely.
    Suppress,
}

/// What to do with the final return value.
#[derive(Debug, Clone)]
pub struct ReturnClause {
    pub param: String,
    pub transform: ReturnTransform,
}

/// Transform applied to the return value.
#[derive(Debug, Clone)]
pub enum ReturnTransform {
    Identity,
    Wrap(String),
}

/// Built-in effect registry: maps Naux actions to algebraic effects.
#[derive(Debug, Clone)]
pub struct EffectRegistry {
    pub effects: HashMap<String, EffectDecl>,
}

impl Default for EffectRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl EffectRegistry {
    pub fn new() -> Self {
        Self {
            effects: HashMap::new(),
        }
    }

    /// Create a registry with Naux's built-in effects pre-registered.
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();

        // IO effect: !say, !ask, !log
        registry.register(EffectDecl {
            name: "IO".into(),
            operations: vec![
                EffectOp {
                    name: "say".into(),
                    params: vec![EffectParam {
                        name: "value".into(),
                        ty: EffectType::Any,
                    }],
                    return_type: EffectType::Null,
                },
                EffectOp {
                    name: "ask".into(),
                    params: vec![EffectParam {
                        name: "prompt".into(),
                        ty: EffectType::Text,
                    }],
                    return_type: EffectType::Text,
                },
                EffectOp {
                    name: "log".into(),
                    params: vec![EffectParam {
                        name: "value".into(),
                        ty: EffectType::Any,
                    }],
                    return_type: EffectType::Null,
                },
            ],
        });

        // Net effect: !fetch
        registry.register(EffectDecl {
            name: "Net".into(),
            operations: vec![EffectOp {
                name: "fetch".into(),
                params: vec![EffectParam {
                    name: "target".into(),
                    ty: EffectType::Text,
                }],
                return_type: EffectType::Any,
            }],
        });

        // UI effect: !text, !button, !ui
        registry.register(EffectDecl {
            name: "UI".into(),
            operations: vec![
                EffectOp {
                    name: "text".into(),
                    params: vec![EffectParam {
                        name: "value".into(),
                        ty: EffectType::Text,
                    }],
                    return_type: EffectType::Null,
                },
                EffectOp {
                    name: "button".into(),
                    params: vec![EffectParam {
                        name: "value".into(),
                        ty: EffectType::Text,
                    }],
                    return_type: EffectType::Null,
                },
                EffectOp {
                    name: "ui".into(),
                    params: vec![EffectParam {
                        name: "kind".into(),
                        ty: EffectType::Text,
                    }],
                    return_type: EffectType::Null,
                },
            ],
        });

        // System effect: !syscall
        registry.register(EffectDecl {
            name: "Sys".into(),
            operations: vec![EffectOp {
                name: "syscall".into(),
                params: vec![
                    EffectParam {
                        name: "number".into(),
                        ty: EffectType::Num,
                    },
                    EffectParam {
                        name: "args".into(),
                        ty: EffectType::List(Box::new(EffectType::Any)),
                    },
                ],
                return_type: EffectType::Any,
            }],
        });

        registry
    }

    pub fn register(&mut self, decl: EffectDecl) {
        self.effects.insert(decl.name.clone(), decl);
    }

    pub fn lookup(&self, name: &str) -> Option<&EffectDecl> {
        self.effects.get(name)
    }

    /// Find which effect an operation belongs to.
    pub fn resolve_op(&self, op_name: &str) -> Option<(&EffectDecl, &EffectOp)> {
        for decl in self.effects.values() {
            for op in &decl.operations {
                if op.name == op_name {
                    return Some((decl, op));
                }
            }
        }
        None
    }

    /// Infer the effect signature for a list of action names.
    pub fn infer_signature(&self, action_names: &[&str]) -> EffectSignature {
        let mut sig = EffectSignature::pure();
        for name in action_names {
            if let Some((decl, _)) = self.resolve_op(name) {
                sig = sig.with(&decl.name);
            }
        }
        sig
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_registry() {
        let reg = EffectRegistry::with_builtins();
        assert!(reg.lookup("IO").is_some());
        assert!(reg.lookup("Net").is_some());
        assert!(reg.lookup("UI").is_some());
        assert!(reg.lookup("Sys").is_some());
        assert!(reg.lookup("NonExistent").is_none());
    }

    #[test]
    fn test_resolve_op() {
        let reg = EffectRegistry::with_builtins();

        let (decl, op) = reg.resolve_op("say").unwrap();
        assert_eq!(decl.name, "IO");
        assert_eq!(op.name, "say");
        assert_eq!(op.return_type, EffectType::Null);

        let (decl, op) = reg.resolve_op("fetch").unwrap();
        assert_eq!(decl.name, "Net");
        assert_eq!(op.name, "fetch");

        assert!(reg.resolve_op("nonexistent").is_none());
    }

    #[test]
    fn test_infer_signature() {
        let reg = EffectRegistry::with_builtins();

        let sig = reg.infer_signature(&["say", "ask"]);
        assert_eq!(sig.effects, vec!["IO".to_string()]);
        assert!(!sig.is_pure());

        let sig = reg.infer_signature(&["say", "fetch"]);
        assert!(sig.effects.contains(&"IO".to_string()));
        assert!(sig.effects.contains(&"Net".to_string()));

        let sig = reg.infer_signature(&[]);
        assert!(sig.is_pure());
    }

    #[test]
    fn test_pure_signature() {
        let sig = EffectSignature::pure();
        assert!(sig.is_pure());
        assert_eq!(format!("{}", sig), "Pure");
    }

    #[test]
    fn test_effect_signature_display() {
        let sig = EffectSignature::pure().with("IO").with("Net");
        assert_eq!(format!("{}", sig), "{IO, Net}");
    }

    #[test]
    fn test_effect_value_display() {
        assert_eq!(format!("{}", EffectValue::Num(42.0)), "42");
        assert_eq!(format!("{}", EffectValue::Text("hi".into())), "\"hi\"");
        assert_eq!(format!("{}", EffectValue::Bool(true)), "true");
        assert_eq!(format!("{}", EffectValue::Null), "null");
    }

    #[test]
    fn test_handler_clause() {
        let handler = EffectHandler {
            effect_name: "IO".into(),
            clauses: vec![
                HandlerClause {
                    op_name: "say".into(),
                    param_names: vec!["msg".into()],
                    resume: true,
                    action: HandlerAction::Collect,
                },
                HandlerClause {
                    op_name: "ask".into(),
                    param_names: vec!["prompt".into()],
                    resume: true,
                    action: HandlerAction::Resume(EffectValue::Text("mock".into())),
                },
            ],
            return_clause: None,
        };
        assert_eq!(handler.clauses.len(), 2);
        assert_eq!(handler.effect_name, "IO");
    }
}
