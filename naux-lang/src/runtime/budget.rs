use std::cell::RefCell;
use std::rc::Rc;

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::Value;

pub const S1_DEFAULT_MAX_WORK: u64 = 1_000_000;
pub const S1_HARD_MAX_WORK: u64 = 10_000_000;
pub const S1_DEFAULT_MAX_CALL_DEPTH: usize = 128;
pub const S1_HARD_MAX_CALL_DEPTH: usize = 512;

pub(crate) const WORK_CHECKPOINT_BUILTIN: &str = "__naux_s1_work_checkpoint";
pub(crate) const CALL_DEPTH_BUILTIN: &str = "__naux_s1_admit_call_depth";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub max_work: u64,
    pub max_call_depth: usize,
}

impl ExecutionLimits {
    pub fn new(max_work: u64, max_call_depth: usize) -> Result<Self, String> {
        if max_work == 0 || max_work > S1_HARD_MAX_WORK {
            return Err(format!(
                "--max-work must be between 1 and {S1_HARD_MAX_WORK}"
            ));
        }
        if max_call_depth == 0 || max_call_depth > S1_HARD_MAX_CALL_DEPTH {
            return Err(format!(
                "--max-call-depth must be between 1 and {S1_HARD_MAX_CALL_DEPTH}"
            ));
        }
        Ok(Self {
            max_work,
            max_call_depth,
        })
    }
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_work: S1_DEFAULT_MAX_WORK,
            max_call_depth: S1_DEFAULT_MAX_CALL_DEPTH,
        }
    }
}

#[derive(Debug)]
struct ExecutionBudget {
    limits: ExecutionLimits,
    work_used: u64,
}

impl ExecutionBudget {
    fn consume_work(&mut self) -> Result<(), RuntimeError> {
        if self.work_used >= self.limits.max_work {
            return Err(RuntimeError::new(
                format!(
                    "S1 work limit of {} semantic checkpoints exceeded.",
                    self.limits.max_work
                ),
                None,
            ));
        }
        self.work_used += 1;
        Ok(())
    }

    fn admit_call_depth(&self, depth: usize) -> Result<(), RuntimeError> {
        if depth > self.limits.max_call_depth {
            return Err(RuntimeError::new(
                format!(
                    "S1 function-call depth limit of {} exceeded.",
                    self.limits.max_call_depth
                ),
                None,
            ));
        }
        Ok(())
    }
}

/// Install the two internal fail-closed admission builtins used by both
/// Surface evaluation and instrumented VM bytecode. The state is deliberately
/// shared so every semantic checkpoint consumes one backend-independent
/// budget, including checkpoints reached through user functions.
pub(crate) fn install_execution_budget(env: &mut Env, limits: ExecutionLimits) {
    let state = Rc::new(RefCell::new(ExecutionBudget {
        limits,
        work_used: 0,
    }));
    let work_state = Rc::clone(&state);
    env.set_stateful_builtin(WORK_CHECKPOINT_BUILTIN, move |args| {
        if !args.is_empty() {
            return Err(RuntimeError::new(
                "internal S1 work checkpoint takes no arguments",
                None,
            ));
        }
        work_state.borrow_mut().consume_work()?;
        Ok(Value::Null)
    });
    env.set_stateful_builtin(CALL_DEPTH_BUILTIN, move |args| {
        let [Value::SmallInt(depth)] = args.as_slice() else {
            return Err(RuntimeError::new(
                "internal S1 call-depth admission requires one integer",
                None,
            ));
        };
        let depth = usize::try_from(*depth)
            .map_err(|_| RuntimeError::new("internal S1 call depth is outside usize", None))?;
        state.borrow().admit_call_depth(depth)?;
        Ok(Value::Null)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_work_limit_is_admitted_and_one_over_fails_closed() {
        let mut env = Env::new();
        install_execution_budget(&mut env, ExecutionLimits::new(2, 3).unwrap());
        for _ in 0..2 {
            assert!(env
                .call_builtin(WORK_CHECKPOINT_BUILTIN, Vec::new())
                .unwrap()
                .is_ok());
        }
        let error = env
            .call_builtin(WORK_CHECKPOINT_BUILTIN, Vec::new())
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error.message,
            "S1 work limit of 2 semantic checkpoints exceeded."
        );
    }

    #[test]
    fn exact_call_depth_is_admitted_and_one_over_fails_closed() {
        let mut env = Env::new();
        install_execution_budget(&mut env, ExecutionLimits::new(1, 3).unwrap());
        assert!(env
            .call_builtin(CALL_DEPTH_BUILTIN, vec![Value::SmallInt(3)])
            .unwrap()
            .is_ok());
        let error = env
            .call_builtin(CALL_DEPTH_BUILTIN, vec![Value::SmallInt(4)])
            .unwrap()
            .unwrap_err();
        assert_eq!(error.message, "S1 function-call depth limit of 3 exceeded.");
    }

    #[test]
    fn public_limits_are_positive_and_hard_bounded() {
        assert!(ExecutionLimits::new(0, 1).is_err());
        assert!(ExecutionLimits::new(S1_HARD_MAX_WORK + 1, 1).is_err());
        assert!(ExecutionLimits::new(1, 0).is_err());
        assert!(ExecutionLimits::new(1, S1_HARD_MAX_CALL_DEPTH + 1).is_err());
        assert_eq!(
            ExecutionLimits::default(),
            ExecutionLimits::new(S1_DEFAULT_MAX_WORK, S1_DEFAULT_MAX_CALL_DEPTH).unwrap()
        );
    }
}
