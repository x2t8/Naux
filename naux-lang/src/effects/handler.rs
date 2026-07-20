//! Effect handler: intercepts and processes algebraic effects.
//!
//! A handler wraps a computation and intercepts effect operations.
//! When an effect `!say(msg)` is performed inside a handled block,
//! the handler's clause for `say` is invoked instead of the default.
//!
//! This enables:
//! - **Testing**: mock all IO by handling `!say` → collect to buffer
//! - **Redirection**: handle `!say` → write to file instead of stdout
//! - **Composition**: stack handlers for different effects


use crate::ast::{ActionKind, Stmt};
use crate::effects::types::*;

/// Result of handling effects in a computation.
#[derive(Debug, Clone)]
pub struct HandlerResult {
    /// Effects that were handled (intercepted).
    pub handled: Vec<HandledEffect>,
    /// Effects that passed through (no handler).
    pub unhandled: Vec<Effect>,
    /// Effect signature of the computation.
    pub signature: EffectSignature,
    /// Collected output (for Collect handlers).
    pub collected: Vec<EffectValue>,
}

/// A handled effect: what was intercepted and how.
#[derive(Debug, Clone)]
pub struct HandledEffect {
    pub effect: Effect,
    pub handler_name: String,
    pub action_taken: String,
}

/// Handler stack: chain of active handlers.
#[derive(Debug, Clone, Default)]
pub struct HandlerStack {
    handlers: Vec<EffectHandler>,
}

impl HandlerStack {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a handler onto the stack.
    pub fn push(&mut self, handler: EffectHandler) {
        self.handlers.push(handler);
    }

    /// Pop the top handler.
    pub fn pop(&mut self) -> Option<EffectHandler> {
        self.handlers.pop()
    }

    /// Find a handler clause for a given operation.
    pub fn find_clause(&self, op_name: &str) -> Option<(&EffectHandler, &HandlerClause)> {
        // Search from top of stack (innermost handler first).
        for handler in self.handlers.iter().rev() {
            for clause in &handler.clauses {
                if clause.op_name == op_name {
                    return Some((handler, clause));
                }
            }
        }
        None
    }

    pub fn depth(&self) -> usize {
        self.handlers.len()
    }
}

/// Analyze a program's effect usage: which effects are used where.
pub fn handle_effects(stmts: &[Stmt]) -> HandlerResult {
    let registry = EffectRegistry::with_builtins();
    let mut result = HandlerResult {
        handled: Vec::new(),
        unhandled: Vec::new(),
        signature: EffectSignature::pure(),
        collected: Vec::new(),
    };

    let mut action_names: Vec<&str> = Vec::new();

    for stmt in stmts {
        collect_actions(stmt, &registry, &mut result, &mut action_names);
    }

    result.signature = registry.infer_signature(&action_names);
    result
}

fn collect_actions<'a>(
    stmt: &'a Stmt,
    registry: &EffectRegistry,
    result: &mut HandlerResult,
    action_names: &mut Vec<&'a str>,
) {
    match stmt {
        Stmt::Action { action, .. } => {
            let (op_name, args) = action_to_effect(action);
            let effect = if let Some((decl, _op)) = registry.resolve_op(&op_name) {
                Effect {
                    name: decl.name.clone(),
                    op: op_name.clone(),
                    args,
                }
            } else {
                Effect {
                    name: "Unknown".into(),
                    op: op_name.clone(),
                    args,
                }
            };
            // Track the action name for signature inference.
            // We use a static lifetime workaround by matching known names.
            match op_name.as_str() {
                "say" => action_names.push("say"),
                "ask" => action_names.push("ask"),
                "fetch" => action_names.push("fetch"),
                "log" => action_names.push("log"),
                "text" => action_names.push("text"),
                "button" => action_names.push("button"),
                "ui" => action_names.push("ui"),
                "syscall" => action_names.push("syscall"),
                _ => {}
            }
            result.unhandled.push(effect);
        }
        Stmt::FnDef { body, .. } => {
            for s in body {
                collect_actions(s, registry, result, action_names);
            }
        }
        Stmt::If { then_block, else_block, .. } => {
            for s in then_block {
                collect_actions(s, registry, result, action_names);
            }
            for s in else_block {
                collect_actions(s, registry, result, action_names);
            }
        }
        Stmt::Loop { body, .. }
        | Stmt::While { body, .. }
        | Stmt::Rite { body, .. }
        | Stmt::Unsafe { body, .. } => {
            for s in body {
                collect_actions(s, registry, result, action_names);
            }
        }
        Stmt::Each { body, .. } => {
            for s in body {
                collect_actions(s, registry, result, action_names);
            }
        }
        _ => {}
    }
}

/// Convert an ActionKind to an effect operation name + args.
fn action_to_effect(action: &ActionKind) -> (String, Vec<EffectValue>) {
    match action {
        ActionKind::Say { .. } => ("say".into(), vec![EffectValue::Text("<expr>".into())]),
        ActionKind::Ask { .. } => ("ask".into(), vec![EffectValue::Text("<prompt>".into())]),
        ActionKind::Fetch { .. } => ("fetch".into(), vec![EffectValue::Text("<url>".into())]),
        ActionKind::Log { .. } => ("log".into(), vec![EffectValue::Text("<expr>".into())]),
        ActionKind::Text { .. } => ("text".into(), vec![EffectValue::Text("<expr>".into())]),
        ActionKind::Button { .. } => ("button".into(), vec![EffectValue::Text("<expr>".into())]),
        ActionKind::Ui { kind, .. } => {
            ("ui".into(), vec![EffectValue::Text(kind.clone())])
        }
        ActionKind::Syscall { .. } => ("syscall".into(), vec![EffectValue::Num(0.0)]),
    }
}

/// Apply a handler stack to a list of effects (simulate handling).
pub fn apply_handlers(
    effects: &[Effect],
    stack: &HandlerStack,
) -> (Vec<HandledEffect>, Vec<Effect>) {
    let mut handled = Vec::new();
    let mut unhandled = Vec::new();

    for effect in effects {
        if let Some((handler, clause)) = stack.find_clause(&effect.op) {
            handled.push(HandledEffect {
                effect: effect.clone(),
                handler_name: handler.effect_name.clone(),
                action_taken: format!("{:?}", clause.action),
            });
        } else {
            unhandled.push(effect.clone());
        }
    }

    (handled, unhandled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::*;

    fn say_action(text: &str) -> Stmt {
        Stmt::Action {
            action: ActionKind::Say {
                value: Expr::new(ExprKind::Text(text.to_string()), None),
            },
            span: None,
        }
    }

    fn ask_action(prompt: &str) -> Stmt {
        Stmt::Action {
            action: ActionKind::Ask {
                prompt: Expr::new(ExprKind::Text(prompt.to_string()), None),
            },
            span: None,
        }
    }

    fn fetch_action(url: &str) -> Stmt {
        Stmt::Action {
            action: ActionKind::Fetch {
                target: Expr::new(ExprKind::Text(url.to_string()), None),
            },
            span: None,
        }
    }

    #[test]
    fn test_pure_program() {
        let stmts = vec![Stmt::Assign {
            name: "x".into(),
            annotation: None,
            expr: Expr::new(ExprKind::Number(42.0), None),
            span: None,
        }];
        let result = handle_effects(&stmts);
        assert!(result.signature.is_pure());
        assert!(result.unhandled.is_empty());
    }

    #[test]
    fn test_io_effects() {
        let stmts = vec![say_action("hello"), ask_action("name?")];
        let result = handle_effects(&stmts);
        assert_eq!(result.signature.effects, vec!["IO".to_string()]);
        assert_eq!(result.unhandled.len(), 2);
        assert_eq!(result.unhandled[0].op, "say");
        assert_eq!(result.unhandled[1].op, "ask");
    }

    #[test]
    fn test_mixed_effects() {
        let stmts = vec![say_action("hi"), fetch_action("https://api.example.com")];
        let result = handle_effects(&stmts);
        assert!(result.signature.effects.contains(&"IO".to_string()));
        assert!(result.signature.effects.contains(&"Net".to_string()));
    }

    #[test]
    fn test_handler_stack() {
        let mut stack = HandlerStack::new();
        assert_eq!(stack.depth(), 0);

        stack.push(EffectHandler {
            effect_name: "IO".into(),
            clauses: vec![HandlerClause {
                op_name: "say".into(),
                param_names: vec!["msg".into()],
                resume: true,
                action: HandlerAction::Collect,
            }],
            return_clause: None,
        });
        assert_eq!(stack.depth(), 1);

        // Can find the clause.
        let (handler, clause) = stack.find_clause("say").unwrap();
        assert_eq!(handler.effect_name, "IO");
        assert_eq!(clause.op_name, "say");

        // Can't find unhandled op.
        assert!(stack.find_clause("fetch").is_none());
    }

    #[test]
    fn test_apply_handlers() {
        let effects = vec![
            Effect {
                name: "IO".into(),
                op: "say".into(),
                args: vec![EffectValue::Text("hello".into())],
            },
            Effect {
                name: "Net".into(),
                op: "fetch".into(),
                args: vec![EffectValue::Text("url".into())],
            },
        ];

        let mut stack = HandlerStack::new();
        stack.push(EffectHandler {
            effect_name: "IO".into(),
            clauses: vec![HandlerClause {
                op_name: "say".into(),
                param_names: vec!["msg".into()],
                resume: true,
                action: HandlerAction::Collect,
            }],
            return_clause: None,
        });

        let (handled, unhandled) = apply_handlers(&effects, &stack);
        assert_eq!(handled.len(), 1);
        assert_eq!(handled[0].effect.op, "say");
        assert_eq!(unhandled.len(), 1);
        assert_eq!(unhandled[0].op, "fetch");
    }

    #[test]
    fn test_nested_effects_in_function() {
        let stmts = vec![Stmt::FnDef {
            name: "greet".into(),
            params: vec!["name".into()],
            body: vec![say_action("hello")],
            return_type: None,
            span: None,
        }];
        let result = handle_effects(&stmts);
        assert_eq!(result.signature.effects, vec!["IO".to_string()]);
    }

    #[test]
    fn test_effects_in_loop() {
        let stmts = vec![Stmt::Loop {
            count: Expr::new(ExprKind::Number(3.0), None),
            body: vec![say_action("tick")],
            span: None,
        }];
        let result = handle_effects(&stmts);
        assert_eq!(result.signature.effects, vec!["IO".to_string()]);
    }
}
