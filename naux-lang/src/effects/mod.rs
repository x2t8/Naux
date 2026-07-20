//! # Algebraic Effects for Naux (Tầng 3)
//!
//! Algebraic effects unify ALL side effects (IO, async, state, exceptions)
//! into a single composable abstraction.
//!
//! Naux's existing `!say`, `!ask`, `!fetch` actions are already effect
//! operations. This module formalizes them into a proper algebraic
//! effects system with:
//!
//! - **Effect declarations**: `effect IO { !say, !ask }`
//! - **Effect handlers**: `handle expr with { !say → ... }`
//! - **Evidence passing**: compile-time resolution of handler chains
//! - **Resumptions**: handlers can resume the suspended computation

pub mod handler;
pub mod types;

pub use handler::{handle_effects, HandlerResult};
pub use types::{Effect, EffectDecl, EffectHandler, EffectOp, EffectSignature};
