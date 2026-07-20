//! Simple RC-aware tracker to observe heap pressure and allow future GC hooks.
use std::collections::VecDeque;
use std::rc::Rc;

use crate::runtime::value::{NauxObj, Value};

/// Tracks Rc allocations and periodically drops dead Weak references.
pub struct RcTracker {
    seen: VecDeque<std::rc::Weak<NauxObj>>,
    collect_every: usize,
    ops: usize,
}

impl RcTracker {
    pub fn new(collect_every: usize) -> Self {
        Self {
            seen: VecDeque::new(),
            collect_every: collect_every.max(1),
            ops: 0,
        }
    }

    pub fn track_value(&mut self, v: &Value) {
        if let Value::RcObj(rc) = v {
            self.seen.push_back(Rc::downgrade(rc));
        }
        self.ops = self.ops.saturating_add(1);
        if self.ops.is_multiple_of(self.collect_every) {
            self.collect();
        }
    }

    pub fn collect(&mut self) {
        self.seen.retain(|w| w.strong_count() > 0);
    }
}
