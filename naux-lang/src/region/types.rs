//! Region type definitions.
//!
//! A region is a contiguous block of memory that is allocated and freed
//! as a unit. Values are placed into regions, and when a region is freed,
//! all values within it are freed simultaneously.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Unique identifier for a region.
pub type RegionId = u32;

/// Atomic counter for generating fresh region IDs.
static NEXT_REGION_ID: AtomicU32 = AtomicU32::new(1);

/// Generate a fresh, unique region ID.
pub fn fresh_region_id() -> RegionId {
    NEXT_REGION_ID.fetch_add(1, Ordering::Relaxed)
}

/// A region variable (may be concrete or unification variable).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegionVar {
    /// A concrete, resolved region.
    Concrete(RegionId),
    /// An unresolved region variable (to be unified during inference).
    Unresolved(u32),
    /// The global/static region (never freed).
    Global,
    /// The stack region for a specific scope depth.
    Stack(u32),
}

impl std::fmt::Display for RegionVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Concrete(id) => write!(f, "ρ{}", id),
            Self::Unresolved(id) => write!(f, "?ρ{}", id),
            Self::Global => write!(f, "ρ_global"),
            Self::Stack(depth) => write!(f, "ρ_stack({})", depth),
        }
    }
}

/// A region describes a memory area with a known lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub id: RegionId,
    pub kind: RegionKind,
    /// Lexical nesting depth. Global is depth zero.
    pub depth: u32,
    /// Variables allocated in this region.
    pub allocations: Vec<String>,
    /// Parent region (for nesting).
    pub parent: Option<RegionId>,
}

/// The kind of region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Top-level program region.
    Global,
    /// Function body region — freed on return.
    Function,
    /// Block scope region (if/loop/rite) — freed on block exit.
    Block,
    /// Loop iteration region — freed each iteration.
    LoopIter,
    /// Temporary expression region — freed after statement.
    Temporary,
}

impl RegionKind {
    /// Human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Function => "function",
            Self::Block => "block",
            Self::LoopIter => "loop-iter",
            Self::Temporary => "temporary",
        }
    }
}

/// Region environment: tracks which variables are in which regions.
#[derive(Debug, Clone, Default)]
pub struct RegionEnv {
    /// Stack of active regions (innermost last).
    region_stack: Vec<Region>,
    /// Map from variable name to the region it's allocated in.
    var_to_region: HashMap<String, Vec<RegionId>>,
    /// All regions created during analysis.
    all_regions: Vec<Region>,
    /// Scope depth counter.
    scope_depth: u32,
}

impl RegionEnv {
    pub fn new() -> Self {
        let global = Region {
            id: fresh_region_id(),
            kind: RegionKind::Global,
            depth: 0,
            allocations: Vec::new(),
            parent: None,
        };
        let _global_id = global.id;
        Self {
            region_stack: vec![global.clone()],
            var_to_region: HashMap::new(),
            all_regions: vec![global],
            scope_depth: 0,
        }
    }

    /// Push a new region for a scope.
    pub fn push_region(&mut self, kind: RegionKind) -> RegionId {
        self.scope_depth += 1;
        let parent_id = self.current_region_id();
        let region = Region {
            id: fresh_region_id(),
            kind,
            depth: self.scope_depth,
            allocations: Vec::new(),
            parent: Some(parent_id),
        };
        let id = region.id;
        self.region_stack.push(region.clone());
        self.all_regions.push(region);
        id
    }

    /// Pop the current region (scope exit = bulk deallocation).
    pub fn pop_region(&mut self) -> Option<Region> {
        if self.region_stack.len() > 1 {
            self.scope_depth = self.scope_depth.saturating_sub(1);
            let region = self.region_stack.pop()?;
            // Remove variable mappings for this region.
            for var in &region.allocations {
                let remove_entry = if let Some(bindings) = self.var_to_region.get_mut(var) {
                    if bindings.last() == Some(&region.id) {
                        bindings.pop();
                    }
                    bindings.is_empty()
                } else {
                    false
                };
                if remove_entry {
                    self.var_to_region.remove(var);
                }
            }
            Some(region)
        } else {
            None // Don't pop global region.
        }
    }

    /// Allocate a variable in the current (innermost) region.
    pub fn allocate(&mut self, var: &str) {
        let region_id = self.current_region_id();
        let bindings = self.var_to_region.entry(var.to_string()).or_default();
        if bindings.last() != Some(&region_id) {
            bindings.push(region_id);
        }
        if let Some(region) = self.region_stack.last_mut() {
            if !region
                .allocations
                .iter()
                .any(|allocation| allocation == var)
            {
                region.allocations.push(var.to_string());
            }
        }
        // Also update in all_regions.
        if let Some(region) = self.all_regions.iter_mut().find(|r| r.id == region_id) {
            if !region
                .allocations
                .iter()
                .any(|allocation| allocation == var)
            {
                region.allocations.push(var.to_string());
            }
        }
    }

    /// Move the active binding for `var` from a shorter-lived region to one
    /// of its ancestors. This is used by conservative escape analysis when
    /// Naux control flow does not introduce a lexical variable scope.
    pub fn promote_binding(&mut self, var: &str, source: RegionId, target: RegionId) -> bool {
        if !self.region_outlives(target, source) {
            return false;
        }
        let Some(bindings) = self.var_to_region.get_mut(var) else {
            return false;
        };
        if bindings.last() != Some(&source) {
            return false;
        }
        if bindings.len() >= 2 && bindings[bindings.len() - 2] == target {
            bindings.pop();
        } else if let Some(active) = bindings.last_mut() {
            *active = target;
        }

        for region in &mut self.region_stack {
            if region.id == source {
                region.allocations.retain(|allocation| allocation != var);
            }
            if region.id == target
                && !region
                    .allocations
                    .iter()
                    .any(|allocation| allocation == var)
            {
                region.allocations.push(var.to_string());
            }
        }
        for region in &mut self.all_regions {
            if region.id == source {
                region.allocations.retain(|allocation| allocation != var);
            }
            if region.id == target
                && !region
                    .allocations
                    .iter()
                    .any(|allocation| allocation == var)
            {
                region.allocations.push(var.to_string());
            }
        }
        true
    }

    /// Which region is a variable in?
    pub fn lookup_region(&self, var: &str) -> Option<RegionId> {
        self.var_to_region
            .get(var)
            .and_then(|bindings| bindings.last())
            .copied()
    }

    /// Current (innermost) region ID.
    pub fn current_region_id(&self) -> RegionId {
        self.region_stack.last().map(|r| r.id).unwrap_or(0)
    }

    /// Current scope depth.
    pub fn depth(&self) -> u32 {
        self.scope_depth
    }

    /// Get all regions created during analysis.
    pub fn all_regions(&self) -> &[Region] {
        &self.all_regions
    }

    /// Look up a region by ID.
    pub fn region(&self, id: RegionId) -> Option<&Region> {
        self.all_regions.iter().find(|region| region.id == id)
    }

    /// Return true when `ancestor` is the same region as `descendant` or is
    /// on its parent chain.
    pub fn region_outlives(&self, ancestor: RegionId, descendant: RegionId) -> bool {
        let mut cursor = Some(descendant);
        while let Some(id) = cursor {
            if id == ancestor {
                return true;
            }
            cursor = self.region(id).and_then(|region| region.parent);
        }
        false
    }

    /// Find the nearest active region with `kind`.
    pub fn nearest_active_region(&self, kind: RegionKind) -> Option<RegionId> {
        self.region_stack
            .iter()
            .rev()
            .find(|region| region.kind == kind)
            .map(|region| region.id)
    }

    /// Parent of a known region.
    pub fn parent_region(&self, id: RegionId) -> Option<RegionId> {
        self.region(id).and_then(|region| region.parent)
    }

    /// Get the current region stack (for diagnostics).
    pub fn region_stack(&self) -> &[Region] {
        &self.region_stack
    }
}

/// A region constraint: value `v` must outlive region `r`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionConstraint {
    pub var: String,
    pub source_region: RegionId,
    pub required_region: RegionId,
    pub reason: String,
}

impl std::fmt::Display for RegionConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "${} (ρ{}) must outlive ρ{}: {}",
            self.var, self.source_region, self.required_region, self.reason
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_env_basics() {
        let mut env = RegionEnv::new();
        assert_eq!(env.depth(), 0);

        // Allocate in global region.
        env.allocate("x");
        let global_region = env.lookup_region("x").unwrap();

        // Push a function region.
        let fn_region = env.push_region(RegionKind::Function);
        assert_eq!(env.depth(), 1);
        assert_ne!(fn_region, global_region);

        // Allocate in function region.
        env.allocate("y");
        assert_eq!(env.lookup_region("y"), Some(fn_region));

        // Pop function region — y should be gone.
        let popped = env.pop_region().unwrap();
        assert_eq!(popped.id, fn_region);
        assert_eq!(popped.allocations, vec!["y".to_string()]);
        assert_eq!(env.lookup_region("y"), None);

        // x still in global.
        assert_eq!(env.lookup_region("x"), Some(global_region));
    }

    #[test]
    fn test_nested_regions() {
        let mut env = RegionEnv::new();

        let fn_r = env.push_region(RegionKind::Function);
        env.allocate("a");

        let block_r = env.push_region(RegionKind::Block);
        env.allocate("b");

        let _loop_r = env.push_region(RegionKind::LoopIter);
        env.allocate("c");
        assert_eq!(env.depth(), 3);

        // Pop loop — c freed.
        env.pop_region();
        assert_eq!(env.lookup_region("c"), None);
        assert_eq!(env.lookup_region("b"), Some(block_r));

        // Pop block — b freed.
        env.pop_region();
        assert_eq!(env.lookup_region("b"), None);
        assert_eq!(env.lookup_region("a"), Some(fn_r));

        // Pop function — a freed.
        env.pop_region();
        assert_eq!(env.lookup_region("a"), None);
    }

    #[test]
    fn test_region_kinds() {
        assert_eq!(RegionKind::Global.as_str(), "global");
        assert_eq!(RegionKind::Function.as_str(), "function");
        assert_eq!(RegionKind::Block.as_str(), "block");
        assert_eq!(RegionKind::LoopIter.as_str(), "loop-iter");
        assert_eq!(RegionKind::Temporary.as_str(), "temporary");
    }

    #[test]
    fn test_region_display() {
        assert_eq!(format!("{}", RegionVar::Global), "ρ_global");
        assert_eq!(format!("{}", RegionVar::Stack(2)), "ρ_stack(2)");
        assert_eq!(format!("{}", RegionVar::Unresolved(7)), "?ρ7");
    }

    #[test]
    fn shadowed_binding_is_restored_when_inner_region_exits() {
        let mut env = RegionEnv::new();
        env.allocate("value");
        let outer = env.lookup_region("value").expect("outer binding");

        let inner = env.push_region(RegionKind::Block);
        env.allocate("value");
        assert_eq!(env.lookup_region("value"), Some(inner));

        env.pop_region();
        assert_eq!(env.lookup_region("value"), Some(outer));
    }

    #[test]
    fn outlives_requires_parent_ancestry_not_creation_order() {
        let mut env = RegionEnv::new();
        let global = env.current_region_id();
        let left = env.push_region(RegionKind::Block);
        env.pop_region();
        let right = env.push_region(RegionKind::Block);

        assert!(env.region_outlives(global, left));
        assert!(env.region_outlives(global, right));
        assert!(!env.region_outlives(left, right));
        assert!(!env.region_outlives(right, left));
    }

    #[test]
    fn promoted_binding_survives_source_pop_and_dies_with_target() {
        let mut env = RegionEnv::new();
        let function = env.push_region(RegionKind::Function);
        let iteration = env.push_region(RegionKind::LoopIter);
        env.allocate("result");

        assert!(env.promote_binding("result", iteration, function));
        assert_eq!(env.lookup_region("result"), Some(function));
        env.pop_region();
        assert_eq!(env.lookup_region("result"), Some(function));
        env.pop_region();
        assert_eq!(env.lookup_region("result"), None);
    }
}
