//! Region inference analysis pass.
//!
//! Walks the AST and infers which region each allocation belongs to.
//! Detects **escaping values** — values that outlive their region — and
//! promotes them to a parent region.

use std::collections::{HashMap, HashSet};

use crate::ast::{ActionKind, Expr, ExprKind, FnExpr, Stmt};
use crate::region::types::*;

/// Result from region inference.
#[derive(Debug, Clone, Default)]
pub struct RegionReport {
    /// Total regions created.
    pub regions_created: usize,
    /// Total allocations tracked.
    pub allocations_tracked: usize,
    /// Variables that escaped their initial region (promoted).
    pub promotions: Vec<RegionPromotion>,
    /// Constraints that couldn't be resolved.
    pub violations: Vec<RegionConstraint>,
    /// Detailed region map for diagnostics.
    pub region_map: HashMap<String, RegionSummary>,
    /// Heap-producing bindings considered by the experimental escape planner.
    pub heap_allocations: Vec<RegionAllocation>,
    /// Non-global heap allocations proven not to escape their region.
    pub bulk_free_eligible: usize,
}

/// A promotion: value was moved to a longer-lived region.
#[derive(Debug, Clone)]
pub struct RegionPromotion {
    pub var: String,
    pub from_region: RegionId,
    pub to_region: RegionId,
    pub reason: String,
}

/// Heap allocation kinds currently recognized by the experimental planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionAllocationKind {
    Text,
    Bytes,
    List,
    Map,
    Closure,
}

impl RegionAllocationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Bytes => "bytes",
            Self::List => "list",
            Self::Map => "map",
            Self::Closure => "closure",
        }
    }
}

/// A proof-oriented allocation decision. This is analysis evidence only; the
/// runtime does not consume it yet.
#[derive(Debug, Clone)]
pub struct RegionAllocation {
    pub var: String,
    pub region: RegionId,
    pub kind: RegionAllocationKind,
    pub escape_to: Option<RegionId>,
    pub escape_reason: Option<String>,
    /// Lexically resolved values retained by this closure. Empty for
    /// non-closure allocations.
    pub captures: Vec<RegionCapture>,
    binding_active: bool,
    aliases: Vec<RegionAlias>,
    retained_allocations: Vec<RetainedAllocation>,
}

/// A lexical closure capture resolved at the closure's allocation site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionCapture {
    pub var: String,
    pub source_region: RegionId,
    captured_allocation: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegionAlias {
    var: String,
    binding_region: RegionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedAllocation {
    var: String,
    allocation: usize,
}

impl RegionAllocation {
    pub fn bulk_free_eligible(&self, env: &RegionEnv) -> bool {
        self.kind != RegionAllocationKind::Closure
            && self.escape_to.is_none()
            && env
                .region(self.region)
                .is_some_and(|region| region.kind != RegionKind::Global)
    }
}

/// Summary of a region for diagnostics.
#[derive(Debug, Clone)]
pub struct RegionSummary {
    pub id: RegionId,
    pub kind: RegionKind,
    pub depth: u32,
    pub allocations: Vec<String>,
    pub parent: Option<RegionId>,
}

/// Infer regions for a program.
pub fn infer_regions(stmts: &[Stmt]) -> RegionReport {
    let mut env = RegionEnv::new();
    let mut constraints: Vec<RegionConstraint> = Vec::new();
    let mut promotions: Vec<RegionPromotion> = Vec::new();
    let mut heap_allocations: Vec<RegionAllocation> = Vec::new();

    for stmt in stmts {
        analyze_stmt(
            stmt,
            &mut env,
            &mut constraints,
            &mut promotions,
            &mut heap_allocations,
        );
    }

    propagate_escape_graph(&env, &mut promotions, &mut heap_allocations);

    // Build region summaries.
    let mut region_map = HashMap::new();
    for region in env.all_regions() {
        let summary = RegionSummary {
            id: region.id,
            kind: region.kind,
            depth: region.depth,
            allocations: region.allocations.clone(),
            parent: region.parent,
        };
        region_map.insert(format!("ρ{}", region.id), summary);
    }

    // Check constraints for violations.
    let mut violations = Vec::new();
    for c in &constraints {
        if !region_outlives(&env, c.source_region, c.required_region) {
            violations.push(c.clone());
        }
    }
    let bulk_free_eligible = heap_allocations
        .iter()
        .filter(|allocation| allocation.bulk_free_eligible(&env))
        .count();

    RegionReport {
        regions_created: env.all_regions().len(),
        allocations_tracked: env.all_regions().iter().map(|r| r.allocations.len()).sum(),
        promotions,
        violations,
        region_map,
        heap_allocations,
        bulk_free_eligible,
    }
}

/// Check whether region `a` outlives region `b` (i.e., `a` is freed after
/// `b`). Outlives requires parent ancestry; sibling creation order is not a
/// lifetime proof.
fn region_outlives(env: &RegionEnv, a: RegionId, b: RegionId) -> bool {
    env.region_outlives(a, b)
}

// ── AST analysis ────────────────────────────────────────────────────

fn analyze_stmt(
    stmt: &Stmt,
    env: &mut RegionEnv,
    constraints: &mut Vec<RegionConstraint>,
    promotions: &mut Vec<RegionPromotion>,
    heap_allocations: &mut Vec<RegionAllocation>,
) {
    match stmt {
        Stmt::Assign { name, expr, .. } => {
            let rhs_var = extract_var_ref(expr);
            let rhs_region = rhs_var
                .as_deref()
                .and_then(|rhs_var| env.lookup_region(rhs_var));
            let rhs_allocation =
                rhs_var
                    .as_deref()
                    .zip(rhs_region)
                    .and_then(|(rhs_var, rhs_region)| {
                        resolve_heap_binding(rhs_var, rhs_region, heap_allocations)
                    });
            let captures = match &expr.kind {
                ExprKind::Fn(fn_expr) => resolve_closure_captures(fn_expr, env, heap_allocations),
                _ => Vec::new(),
            };
            let retained_allocations = resolve_retained_allocations(expr, env, heap_allocations);
            analyze_expr(expr, env, constraints, promotions, heap_allocations);
            env.allocate(name);
            let binding_region = env.current_region_id();
            invalidate_heap_binding(name, binding_region, heap_allocations);
            if let Some(kind) = allocation_kind(expr) {
                heap_allocations.push(RegionAllocation {
                    var: name.clone(),
                    region: binding_region,
                    kind,
                    escape_to: None,
                    escape_reason: None,
                    captures,
                    binding_active: true,
                    aliases: Vec::new(),
                    retained_allocations,
                });
            } else if let Some(rhs_allocation) = rhs_allocation {
                if let Some(allocation) = heap_allocations.get_mut(rhs_allocation) {
                    allocation.aliases.push(RegionAlias {
                        var: name.clone(),
                        binding_region,
                    });
                }
            }

            // Check: if RHS references a variable from a deeper region,
            // the result escapes. For now, track simple cases.
            if let Some(rhs_var) = rhs_var {
                if let (Some(lhs_region), Some(rhs_region)) = (env.lookup_region(name), rhs_region)
                {
                    if !region_outlives(env, rhs_region, lhs_region) {
                        // RHS value may not live long enough!
                        constraints.push(RegionConstraint {
                            var: rhs_var.clone(),
                            source_region: rhs_region,
                            required_region: lhs_region,
                            reason: format!(
                                "${} references ${} from shorter-lived region",
                                name, rhs_var
                            ),
                        });
                    }
                }
            }
        }
        Stmt::FnDef {
            name: _,
            params,
            body,
            ..
        } => {
            let _fn_region = env.push_region(RegionKind::Function);
            for p in params {
                env.allocate(&p.name);
            }
            for s in body {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            env.pop_region();
        }
        Stmt::If {
            cond,
            then_block,
            else_block,
            ..
        } => {
            analyze_expr(cond, env, constraints, promotions, heap_allocations);

            let then_region = env.push_region(RegionKind::Block);
            for s in then_block {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            promote_control_flow_allocations(
                env,
                then_region,
                "assignment survives if-branch scope",
                promotions,
                heap_allocations,
            );
            env.pop_region();

            let else_region = env.push_region(RegionKind::Block);
            for s in else_block {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            promote_control_flow_allocations(
                env,
                else_region,
                "assignment survives else-branch scope",
                promotions,
                heap_allocations,
            );
            env.pop_region();
        }
        Stmt::Loop { count, body, .. } => {
            analyze_expr(count, env, constraints, promotions, heap_allocations);
            let loop_region = env.push_region(RegionKind::LoopIter);
            for s in body {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            promote_control_flow_allocations(
                env,
                loop_region,
                "assignment survives loop iteration",
                promotions,
                heap_allocations,
            );
            env.pop_region();
        }
        Stmt::While { cond, body, .. } => {
            analyze_expr(cond, env, constraints, promotions, heap_allocations);
            let loop_region = env.push_region(RegionKind::LoopIter);
            for s in body {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            promote_control_flow_allocations(
                env,
                loop_region,
                "assignment survives while iteration",
                promotions,
                heap_allocations,
            );
            env.pop_region();
        }
        Stmt::Each {
            var, iter, body, ..
        } => {
            analyze_expr(iter, env, constraints, promotions, heap_allocations);
            env.push_region(RegionKind::LoopIter);
            env.allocate(var);
            for s in body {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            env.pop_region();
        }
        Stmt::Rite { body, .. } => {
            env.push_region(RegionKind::Block);
            for s in body {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            env.pop_region();
        }
        Stmt::Unsafe { body, .. } => {
            let unsafe_region = env.push_region(RegionKind::Block);
            for s in body {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            promote_control_flow_allocations(
                env,
                unsafe_region,
                "unsafe is not a lexical variable scope",
                promotions,
                heap_allocations,
            );
            env.pop_region();
        }
        Stmt::Return { value, .. } => {
            if let Some(expr) = value {
                analyze_expr(expr, env, constraints, promotions, heap_allocations);
                // Return value escapes function region → promote to caller.
                if let Some(var_name) = extract_var_ref(expr) {
                    if let Some(var_region) = env.lookup_region(&var_name) {
                        let returned_allocation =
                            resolve_heap_binding(&var_name, var_region, heap_allocations);
                        let function_region = env.nearest_active_region(RegionKind::Function);
                        if let Some(function_region) = function_region.filter(|function_region| {
                            env.region_outlives(*function_region, var_region)
                        }) {
                            let target = env
                                .parent_region(function_region)
                                .unwrap_or(function_region);
                            let reason = "return escapes function scope".to_string();
                            promotions.push(RegionPromotion {
                                var: var_name.clone(),
                                from_region: var_region,
                                to_region: target,
                                reason: reason.clone(),
                            });
                            if let Some(allocation) = returned_allocation
                                .and_then(|allocation| heap_allocations.get_mut(allocation))
                            {
                                allocation.escape_to = Some(target);
                                allocation.escape_reason = Some(reason);
                            }
                        }
                    }
                }
            }
        }
        Stmt::Expr { expr, .. } => {
            analyze_expr(expr, env, constraints, promotions, heap_allocations);
        }
        Stmt::Action { action, .. } => {
            analyze_action(action, env, constraints, promotions, heap_allocations);
        }
        Stmt::Import { .. } => {}
    }
}

fn promote_control_flow_allocations(
    env: &mut RegionEnv,
    source: RegionId,
    reason: &str,
    promotions: &mut Vec<RegionPromotion>,
    heap_allocations: &mut [RegionAllocation],
) {
    let Some(target) = env.parent_region(source) else {
        return;
    };
    for allocation in heap_allocations.iter_mut() {
        for alias in &mut allocation.aliases {
            if alias.binding_region == source {
                env.promote_binding(&alias.var, source, target);
                alias.binding_region = target;
            }
        }
    }
    let promoted_vars: Vec<String> = heap_allocations
        .iter_mut()
        .filter(|allocation| allocation.region == source && allocation.escape_to.is_none())
        .map(|allocation| {
            allocation.escape_to = Some(target);
            allocation.escape_reason = Some(reason.to_string());
            allocation.var.clone()
        })
        .collect();
    for var in promoted_vars {
        env.promote_binding(&var, source, target);
        promotions.push(RegionPromotion {
            var,
            from_region: source,
            to_region: target,
            reason: reason.to_string(),
        });
    }
}

fn propagate_escape_graph(
    env: &RegionEnv,
    promotions: &mut Vec<RegionPromotion>,
    heap_allocations: &mut [RegionAllocation],
) {
    loop {
        let mut pending = Vec::new();
        for allocation in heap_allocations
            .iter()
            .filter(|allocation| allocation.escape_to.is_some())
        {
            let target = allocation.escape_to.expect("filtered escaping allocation");
            if allocation.kind == RegionAllocationKind::Closure {
                for capture in &allocation.captures {
                    if let Some(allocation_index) = capture.captured_allocation {
                        pending.push((
                            allocation.var.clone(),
                            target,
                            capture.var.clone(),
                            allocation_index,
                            true,
                        ));
                    }
                }
            }
            for retained in &allocation.retained_allocations {
                pending.push((
                    allocation.var.clone(),
                    target,
                    retained.var.clone(),
                    retained.allocation,
                    false,
                ));
            }
        }

        let mut changed = false;
        for (owner_var, target, retained_var, allocation_index, is_capture) in pending {
            let Some(retained) = heap_allocations.get_mut(allocation_index) else {
                continue;
            };
            let current_lifetime = retained.escape_to.unwrap_or(retained.region);
            if current_lifetime == target || !env.region_outlives(target, current_lifetime) {
                continue;
            }

            let reason = if is_capture {
                format!("captured by escaping closure ${owner_var}")
            } else {
                format!("retained by escaping allocation ${owner_var}")
            };
            retained.escape_to = Some(target);
            retained.escape_reason = Some(reason.clone());
            promotions.push(RegionPromotion {
                var: retained_var,
                from_region: current_lifetime,
                to_region: target,
                reason,
            });
            changed = true;
        }

        if !changed {
            break;
        }
    }
}

fn resolve_heap_binding(
    var: &str,
    binding_region: RegionId,
    heap_allocations: &[RegionAllocation],
) -> Option<usize> {
    heap_allocations
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, allocation)| {
            let direct_binding = allocation.binding_active
                && allocation.var == var
                && (allocation.region == binding_region
                    || allocation.escape_to == Some(binding_region));
            let alias_binding = allocation
                .aliases
                .iter()
                .any(|alias| alias.var == var && alias.binding_region == binding_region);
            (direct_binding || alias_binding).then_some(index)
        })
}

fn invalidate_heap_binding(
    var: &str,
    binding_region: RegionId,
    heap_allocations: &mut [RegionAllocation],
) {
    for allocation in heap_allocations {
        if allocation.binding_active
            && allocation.var == var
            && (allocation.region == binding_region || allocation.escape_to == Some(binding_region))
        {
            allocation.binding_active = false;
        }
        allocation
            .aliases
            .retain(|alias| alias.var != var || alias.binding_region != binding_region);
    }
}

fn resolve_retained_allocations(
    expr: &Expr,
    env: &RegionEnv,
    heap_allocations: &[RegionAllocation],
) -> Vec<RetainedAllocation> {
    if !matches!(&expr.kind, ExprKind::List(_) | ExprKind::Map(_)) {
        return Vec::new();
    }

    let mut refs = Vec::new();
    collect_expr_var_refs(expr, &mut refs);
    let mut retained = Vec::new();
    for var in refs {
        let Some(binding_region) = env.lookup_region(&var) else {
            continue;
        };
        let Some(allocation) = resolve_heap_binding(&var, binding_region, heap_allocations) else {
            continue;
        };
        if retained
            .iter()
            .any(|candidate: &RetainedAllocation| candidate.allocation == allocation)
        {
            continue;
        }
        retained.push(RetainedAllocation { var, allocation });
    }
    retained
}

fn collect_expr_var_refs(expr: &Expr, refs: &mut Vec<String>) {
    match &expr.kind {
        ExprKind::Var(var) => {
            if !refs.iter().any(|candidate| candidate == var) {
                refs.push(var.clone());
            }
        }
        ExprKind::List(items) => {
            for item in items {
                collect_expr_var_refs(item, refs);
            }
        }
        ExprKind::Map(entries) => {
            for (_, value) in entries {
                collect_expr_var_refs(value, refs);
            }
        }
        ExprKind::Call { callee, args } => {
            collect_expr_var_refs(callee, refs);
            for arg in args {
                collect_expr_var_refs(arg, refs);
            }
        }
        ExprKind::Binary { left, right, .. } => {
            collect_expr_var_refs(left, refs);
            collect_expr_var_refs(right, refs);
        }
        ExprKind::Unary { expr, .. } => collect_expr_var_refs(expr, refs),
        ExprKind::Index { target, index } => {
            collect_expr_var_refs(target, refs);
            collect_expr_var_refs(index, refs);
        }
        ExprKind::Field { target, .. } => collect_expr_var_refs(target, refs),
        ExprKind::Fn(_) => {}
        ExprKind::Number(_) | ExprKind::Bool(_) | ExprKind::Text(_) | ExprKind::Bytes(_) => {}
    }
}

fn resolve_closure_captures(
    fn_expr: &FnExpr,
    env: &RegionEnv,
    heap_allocations: &[RegionAllocation],
) -> Vec<RegionCapture> {
    let mut collector =
        CaptureCollector::new(fn_expr.params.iter().map(|param| param.name.as_str()));
    collector.visit_stmts(&fn_expr.body);
    collector
        .free
        .into_iter()
        .filter_map(|var| {
            let source_region = env.lookup_region(&var)?;
            let captured_allocation = resolve_heap_binding(&var, source_region, heap_allocations);
            Some(RegionCapture {
                var,
                source_region,
                captured_allocation,
            })
        })
        .collect()
}

#[derive(Clone)]
struct CaptureCollector {
    scopes: Vec<HashSet<String>>,
    free: Vec<String>,
}

impl CaptureCollector {
    fn new<'a>(params: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            scopes: vec![params.into_iter().map(str::to_string).collect()],
            free: Vec::new(),
        }
    }

    fn visit_stmts(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { name, expr, .. } => {
                self.visit_expr(expr);
                self.bind(name);
            }
            Stmt::FnDef { params, body, .. } => {
                self.push_scope(params.iter().map(|param| param.name.as_str()));
                self.visit_stmts(body);
                self.pop_scope();
            }
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                self.visit_expr(cond);
                self.visit_control_flow_branch(then_block);
                self.visit_control_flow_branch(else_block);
            }
            Stmt::Loop { count, body, .. } => {
                self.visit_expr(count);
                self.visit_control_flow_branch(body);
            }
            Stmt::While { cond, body, .. } => {
                self.visit_expr(cond);
                self.visit_control_flow_branch(body);
            }
            Stmt::Each {
                var, iter, body, ..
            } => {
                self.visit_expr(iter);
                self.push_scope([var.as_str()]);
                self.visit_stmts(body);
                self.pop_scope();
            }
            Stmt::Rite { body, .. } => {
                self.push_scope([]);
                self.visit_stmts(body);
                self.pop_scope();
            }
            Stmt::Unsafe { body, .. } => self.visit_stmts(body),
            Stmt::Return { value, .. } => {
                if let Some(value) = value {
                    self.visit_expr(value);
                }
            }
            Stmt::Expr { expr, .. } => self.visit_expr(expr),
            Stmt::Action { action, .. } => self.visit_action(action),
            Stmt::Import { .. } => {}
        }
    }

    fn visit_control_flow_branch(&mut self, stmts: &[Stmt]) {
        // Branches and loops may not execute. Bindings created inside them
        // therefore cannot discharge later capture requirements.
        let scopes = self.scopes.clone();
        self.visit_stmts(stmts);
        self.scopes = scopes;
    }

    fn visit_action(&mut self, action: &ActionKind) {
        match action {
            ActionKind::Say { value }
            | ActionKind::Text { value }
            | ActionKind::Button { value }
            | ActionKind::Log { value } => self.visit_expr(value),
            ActionKind::Ui { props, .. } => {
                for (_, value) in props {
                    self.visit_expr(value);
                }
            }
            ActionKind::Fetch { target } => self.visit_expr(target),
            ActionKind::Ask { prompt } => self.visit_expr(prompt),
            ActionKind::Syscall { number, args, .. } => {
                self.visit_expr(number);
                for arg in args {
                    self.visit_expr(arg);
                }
            }
        }
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Var(name) => self.reference(name),
            ExprKind::List(items) => {
                for item in items {
                    self.visit_expr(item);
                }
            }
            ExprKind::Map(entries) => {
                for (_, value) in entries {
                    self.visit_expr(value);
                }
            }
            ExprKind::Call { callee, args } => {
                self.visit_expr(callee);
                for arg in args {
                    self.visit_expr(arg);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.visit_expr(left);
                self.visit_expr(right);
            }
            ExprKind::Unary { expr, .. } => self.visit_expr(expr),
            ExprKind::Index { target, index } => {
                self.visit_expr(target);
                self.visit_expr(index);
            }
            ExprKind::Field { target, .. } => self.visit_expr(target),
            ExprKind::Fn(fn_expr) => {
                self.push_scope(fn_expr.params.iter().map(|param| param.name.as_str()));
                self.visit_stmts(&fn_expr.body);
                self.pop_scope();
            }
            ExprKind::Number(_) | ExprKind::Bool(_) | ExprKind::Text(_) | ExprKind::Bytes(_) => {}
        }
    }

    fn bind(&mut self, name: &str) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string());
        }
    }

    fn reference(&mut self, name: &str) {
        if self.scopes.iter().rev().any(|scope| scope.contains(name)) {
            return;
        }
        if !self.free.iter().any(|free| free == name) {
            self.free.push(name.to_string());
        }
    }

    fn push_scope<'a>(&mut self, names: impl IntoIterator<Item = &'a str>) {
        self.scopes
            .push(names.into_iter().map(str::to_string).collect());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }
}

fn analyze_action(
    action: &ActionKind,
    env: &mut RegionEnv,
    constraints: &mut Vec<RegionConstraint>,
    promotions: &mut Vec<RegionPromotion>,
    heap_allocations: &mut Vec<RegionAllocation>,
) {
    let mut analyze =
        |expr: &Expr| analyze_expr(expr, env, constraints, promotions, heap_allocations);
    match action {
        ActionKind::Say { value }
        | ActionKind::Text { value }
        | ActionKind::Button { value }
        | ActionKind::Log { value } => analyze(value),
        ActionKind::Ui { props, .. } => {
            for (_, value) in props {
                analyze(value);
            }
        }
        ActionKind::Fetch { target } => analyze(target),
        ActionKind::Ask { prompt } => analyze(prompt),
        ActionKind::Syscall { number, args, .. } => {
            analyze(number);
            for arg in args {
                analyze(arg);
            }
        }
    }
}

fn analyze_expr(
    expr: &Expr,
    env: &mut RegionEnv,
    constraints: &mut Vec<RegionConstraint>,
    promotions: &mut Vec<RegionPromotion>,
    heap_allocations: &mut Vec<RegionAllocation>,
) {
    match &expr.kind {
        ExprKind::List(items) => {
            for item in items {
                analyze_expr(item, env, constraints, promotions, heap_allocations);
            }
        }
        ExprKind::Map(entries) => {
            for (_, v) in entries {
                analyze_expr(v, env, constraints, promotions, heap_allocations);
            }
        }
        ExprKind::Binary { left, right, .. } => {
            analyze_expr(left, env, constraints, promotions, heap_allocations);
            analyze_expr(right, env, constraints, promotions, heap_allocations);
        }
        ExprKind::Unary { expr: inner, .. } => {
            analyze_expr(inner, env, constraints, promotions, heap_allocations);
        }
        ExprKind::Call { callee, args } => {
            analyze_expr(callee, env, constraints, promotions, heap_allocations);
            for arg in args {
                analyze_expr(arg, env, constraints, promotions, heap_allocations);
            }
        }
        ExprKind::Index { target, index } => {
            analyze_expr(target, env, constraints, promotions, heap_allocations);
            analyze_expr(index, env, constraints, promotions, heap_allocations);
        }
        ExprKind::Field { target, .. } => {
            analyze_expr(target, env, constraints, promotions, heap_allocations);
        }
        ExprKind::Fn(fn_expr) => {
            // Closure captures — variables referenced from outer scope
            // create region constraints.
            env.push_region(RegionKind::Function);
            for p in &fn_expr.params {
                env.allocate(&p.name);
            }
            for s in &fn_expr.body {
                analyze_stmt(s, env, constraints, promotions, heap_allocations);
            }
            env.pop_region();
        }
        // Leaf expressions — no allocations.
        ExprKind::Number(_)
        | ExprKind::Bool(_)
        | ExprKind::Text(_)
        | ExprKind::Bytes(_)
        | ExprKind::Var(_) => {}
    }
}

fn allocation_kind(expr: &Expr) -> Option<RegionAllocationKind> {
    match &expr.kind {
        ExprKind::Text(_) => Some(RegionAllocationKind::Text),
        ExprKind::Bytes(_) => Some(RegionAllocationKind::Bytes),
        ExprKind::List(_) => Some(RegionAllocationKind::List),
        ExprKind::Map(_) => Some(RegionAllocationKind::Map),
        ExprKind::Fn(_) => Some(RegionAllocationKind::Closure),
        _ => None,
    }
}

/// Extract a simple variable reference from an expression.
fn extract_var_ref(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Var(name) => Some(name.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::*;

    fn num(n: f64) -> Expr {
        Expr::new(ExprKind::Number(n), None)
    }

    fn var(name: &str) -> Expr {
        Expr::new(ExprKind::Var(name.to_string()), None)
    }

    #[test]
    fn test_simple_assignment() {
        let stmts = vec![
            Stmt::Assign {
                name: "x".into(),
                annotation: None,
                expr: num(42.0),
                span: None,
            },
            Stmt::Assign {
                name: "y".into(),
                annotation: None,
                expr: num(10.0),
                span: None,
            },
        ];
        let report = infer_regions(&stmts);
        assert_eq!(report.regions_created, 1); // Only global.
        assert_eq!(report.allocations_tracked, 2);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_function_region() {
        let stmts = vec![Stmt::FnDef {
            name: "foo".into(),
            params: vec!["a".into()],
            body: vec![Stmt::Assign {
                name: "local".into(),
                annotation: None,
                expr: num(1.0),
                span: None,
            }],
            return_type: None,
            span: None,
        }];
        let report = infer_regions(&stmts);
        assert_eq!(report.regions_created, 2); // Global + function.
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_if_block_regions() {
        let stmts = vec![Stmt::If {
            cond: var("x"),
            then_block: vec![Stmt::Assign {
                name: "a".into(),
                annotation: None,
                expr: num(1.0),
                span: None,
            }],
            else_block: vec![Stmt::Assign {
                name: "b".into(),
                annotation: None,
                expr: num(2.0),
                span: None,
            }],
            span: None,
        }];
        let report = infer_regions(&stmts);
        assert_eq!(report.regions_created, 3); // Global + 2 blocks.
    }

    #[test]
    fn test_loop_region() {
        let stmts = vec![Stmt::Loop {
            count: num(10.0),
            body: vec![Stmt::Assign {
                name: "i".into(),
                annotation: None,
                expr: num(0.0),
                span: None,
            }],
            span: None,
        }];
        let report = infer_regions(&stmts);
        assert_eq!(report.regions_created, 2); // Global + loop-iter.
    }

    #[test]
    fn test_nested_scopes() {
        let stmts = vec![
            Stmt::Assign {
                name: "outer".into(),
                annotation: None,
                expr: num(1.0),
                span: None,
            },
            Stmt::FnDef {
                name: "f".into(),
                params: vec![],
                body: vec![
                    Stmt::Assign {
                        name: "mid".into(),
                        annotation: None,
                        expr: num(2.0),
                        span: None,
                    },
                    Stmt::Loop {
                        count: num(5.0),
                        body: vec![Stmt::Assign {
                            name: "inner".into(),
                            annotation: None,
                            expr: num(3.0),
                            span: None,
                        }],
                        span: None,
                    },
                ],
                return_type: None,
                span: None,
            },
        ];
        let report = infer_regions(&stmts);
        // Global + function + loop-iter = 3.
        assert_eq!(report.regions_created, 3);
    }

    #[test]
    fn local_heap_allocation_is_bulk_free_eligible() {
        let stmts = vec![Stmt::FnDef {
            name: "build".into(),
            params: vec![],
            body: vec![Stmt::Assign {
                name: "scratch".into(),
                annotation: None,
                expr: Expr::new(ExprKind::List(vec![num(1.0), num(2.0)]), None),
                span: None,
            }],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        assert_eq!(report.heap_allocations.len(), 1);
        assert_eq!(report.bulk_free_eligible, 1);
        let allocation = &report.heap_allocations[0];
        assert_eq!(allocation.kind, RegionAllocationKind::List);
        assert_eq!(allocation.escape_to, None);
    }

    #[test]
    fn returned_heap_allocation_has_resolved_escape_target() {
        let stmts = vec![Stmt::FnDef {
            name: "build".into(),
            params: vec![],
            body: vec![
                Stmt::Assign {
                    name: "result".into(),
                    annotation: None,
                    expr: Expr::new(ExprKind::Map(vec![("answer".into(), num(42.0))]), None),
                    span: None,
                },
                Stmt::Return {
                    value: Some(var("result")),
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        assert_eq!(report.heap_allocations.len(), 1);
        assert_eq!(report.bulk_free_eligible, 0);
        assert_eq!(report.promotions.len(), 1);

        let allocation = &report.heap_allocations[0];
        let target = allocation.escape_to.expect("resolved caller region");
        assert_ne!(target, 0);
        assert_eq!(report.promotions[0].to_region, target);
        assert_eq!(
            report
                .region_map
                .get(&format!("ρ{target}"))
                .expect("target summary")
                .kind,
            RegionKind::Global
        );
    }

    #[test]
    fn returned_nested_allocation_escapes_past_function_region() {
        let stmts = vec![Stmt::FnDef {
            name: "build".into(),
            params: vec![],
            body: vec![Stmt::Rite {
                body: vec![
                    Stmt::Assign {
                        name: "result".into(),
                        annotation: None,
                        expr: Expr::new(ExprKind::Bytes(vec![1, 2, 3]), None),
                        span: None,
                    },
                    Stmt::Return {
                        value: Some(var("result")),
                        span: None,
                    },
                ],
                span: None,
            }],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        let allocation = &report.heap_allocations[0];
        let target = allocation.escape_to.expect("resolved caller region");
        assert_eq!(report.bulk_free_eligible, 0);
        assert_eq!(
            report.region_map[&format!("ρ{target}")].kind,
            RegionKind::Global
        );
        assert!(report.region_map[&format!("ρ{}", allocation.region)].depth > 1);
    }

    #[test]
    fn local_closure_keeps_only_its_resolved_capture_alive() {
        let stmts = vec![Stmt::FnDef {
            name: "factory".into(),
            params: vec![],
            body: vec![
                Stmt::Assign {
                    name: "captured".into(),
                    annotation: None,
                    expr: Expr::new(ExprKind::List(vec![num(1.0)]), None),
                    span: None,
                },
                Stmt::Assign {
                    name: "callback".into(),
                    annotation: None,
                    expr: Expr::new(
                        ExprKind::Fn(Box::new(FnExpr {
                            params: vec![],
                            body: vec![Stmt::Return {
                                value: Some(var("captured")),
                                span: None,
                            }],
                            span: None,
                        })),
                        None,
                    ),
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        assert_eq!(report.heap_allocations.len(), 2);
        assert_eq!(report.bulk_free_eligible, 1);
        let closure = report
            .heap_allocations
            .iter()
            .find(|allocation| allocation.var == "callback")
            .expect("closure allocation");
        assert_eq!(closure.captures.len(), 1);
        assert_eq!(closure.captures[0].var, "captured");
        assert_eq!(closure.captures[0].source_region, closure.region);
        assert!(closure.escape_to.is_none());
    }

    #[test]
    fn returned_closure_promotes_its_captured_allocation() {
        let stmts = vec![Stmt::FnDef {
            name: "factory".into(),
            params: vec![],
            body: vec![
                Stmt::Assign {
                    name: "captured".into(),
                    annotation: None,
                    expr: Expr::new(ExprKind::List(vec![num(1.0)]), None),
                    span: None,
                },
                Stmt::Assign {
                    name: "callback".into(),
                    annotation: None,
                    expr: Expr::new(
                        ExprKind::Fn(Box::new(FnExpr {
                            params: vec![],
                            body: vec![Stmt::Return {
                                value: Some(var("captured")),
                                span: None,
                            }],
                            span: None,
                        })),
                        None,
                    ),
                    span: None,
                },
                Stmt::Return {
                    value: Some(var("callback")),
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        assert_eq!(report.bulk_free_eligible, 0);
        assert_eq!(report.promotions.len(), 2);
        let captured = report
            .heap_allocations
            .iter()
            .find(|allocation| allocation.var == "captured")
            .expect("captured allocation");
        let closure = report
            .heap_allocations
            .iter()
            .find(|allocation| allocation.var == "callback")
            .expect("closure allocation");
        assert_eq!(captured.escape_to, closure.escape_to);
        assert!(report
            .promotions
            .iter()
            .any(|promotion| promotion.reason == "captured by escaping closure $callback"));
    }

    #[test]
    fn closure_parameter_shadows_outer_heap_binding() {
        let stmts = vec![Stmt::FnDef {
            name: "factory".into(),
            params: vec![],
            body: vec![
                Stmt::Assign {
                    name: "item".into(),
                    annotation: None,
                    expr: Expr::new(ExprKind::List(vec![num(1.0)]), None),
                    span: None,
                },
                Stmt::Assign {
                    name: "callback".into(),
                    annotation: None,
                    expr: Expr::new(
                        ExprKind::Fn(Box::new(FnExpr {
                            params: vec!["item".into()],
                            body: vec![Stmt::Return {
                                value: Some(var("item")),
                                span: None,
                            }],
                            span: None,
                        })),
                        None,
                    ),
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        let closure = report
            .heap_allocations
            .iter()
            .find(|allocation| allocation.var == "callback")
            .expect("closure allocation");
        assert!(closure.captures.is_empty());
        assert_eq!(report.bulk_free_eligible, 1);
    }

    #[test]
    fn closure_capture_follows_heap_alias_binding() {
        let stmts = vec![Stmt::FnDef {
            name: "factory".into(),
            params: vec![],
            body: vec![
                Stmt::Assign {
                    name: "payload".into(),
                    annotation: None,
                    expr: Expr::new(ExprKind::List(vec![num(1.0)]), None),
                    span: None,
                },
                Stmt::Assign {
                    name: "alias".into(),
                    annotation: None,
                    expr: var("payload"),
                    span: None,
                },
                Stmt::Assign {
                    name: "callback".into(),
                    annotation: None,
                    expr: Expr::new(
                        ExprKind::Fn(Box::new(FnExpr {
                            params: vec![],
                            body: vec![Stmt::Return {
                                value: Some(var("alias")),
                                span: None,
                            }],
                            span: None,
                        })),
                        None,
                    ),
                    span: None,
                },
                Stmt::Return {
                    value: Some(var("callback")),
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        let payload = report
            .heap_allocations
            .iter()
            .find(|allocation| allocation.var == "payload")
            .expect("payload allocation");
        let closure = report
            .heap_allocations
            .iter()
            .find(|allocation| allocation.var == "callback")
            .expect("closure allocation");
        assert_eq!(closure.captures[0].var, "alias");
        assert_eq!(payload.escape_to, closure.escape_to);
        assert_eq!(report.promotions.len(), 2);
    }

    #[test]
    fn scalar_reassignment_invalidates_old_heap_alias() {
        let stmts = vec![Stmt::FnDef {
            name: "factory".into(),
            params: vec![],
            body: vec![
                Stmt::Assign {
                    name: "payload".into(),
                    annotation: None,
                    expr: Expr::new(ExprKind::List(vec![num(1.0)]), None),
                    span: None,
                },
                Stmt::Assign {
                    name: "value".into(),
                    annotation: None,
                    expr: var("payload"),
                    span: None,
                },
                Stmt::Assign {
                    name: "value".into(),
                    annotation: None,
                    expr: num(7.0),
                    span: None,
                },
                Stmt::Assign {
                    name: "callback".into(),
                    annotation: None,
                    expr: Expr::new(
                        ExprKind::Fn(Box::new(FnExpr {
                            params: vec![],
                            body: vec![Stmt::Return {
                                value: Some(var("value")),
                                span: None,
                            }],
                            span: None,
                        })),
                        None,
                    ),
                    span: None,
                },
                Stmt::Return {
                    value: Some(var("callback")),
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        let payload = report
            .heap_allocations
            .iter()
            .find(|allocation| allocation.var == "payload")
            .expect("payload allocation");
        assert!(payload.escape_to.is_none());
        assert_eq!(report.bulk_free_eligible, 1);
        assert_eq!(report.promotions.len(), 1);
    }

    #[test]
    fn escaping_container_promotes_directly_retained_heap_values() {
        let stmts = vec![Stmt::FnDef {
            name: "build".into(),
            params: vec![],
            body: vec![
                Stmt::Assign {
                    name: "payload".into(),
                    annotation: None,
                    expr: Expr::new(ExprKind::Bytes(vec![1, 2, 3]), None),
                    span: None,
                },
                Stmt::Assign {
                    name: "holder".into(),
                    annotation: None,
                    expr: Expr::new(
                        ExprKind::Map(vec![("payload".into(), var("payload"))]),
                        None,
                    ),
                    span: None,
                },
                Stmt::Return {
                    value: Some(var("holder")),
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        let holder_target = report
            .heap_allocations
            .iter()
            .find(|allocation| allocation.var == "holder")
            .and_then(|allocation| allocation.escape_to)
            .expect("holder escape target");
        assert!(report
            .heap_allocations
            .iter()
            .all(|allocation| allocation.escape_to == Some(holder_target)));
        assert!(report
            .promotions
            .iter()
            .any(|promotion| promotion.reason == "retained by escaping allocation $holder"));
        assert_eq!(report.promotions.len(), 2);
        assert_eq!(report.bulk_free_eligible, 0);
    }

    #[test]
    fn escaping_nested_closures_propagate_capture_lifetime_to_fixpoint() {
        let stmts = vec![Stmt::FnDef {
            name: "factory".into(),
            params: vec![],
            body: vec![
                Stmt::Assign {
                    name: "payload".into(),
                    annotation: None,
                    expr: Expr::new(ExprKind::Bytes(vec![1, 2, 3]), None),
                    span: None,
                },
                Stmt::Assign {
                    name: "inner".into(),
                    annotation: None,
                    expr: Expr::new(
                        ExprKind::Fn(Box::new(FnExpr {
                            params: vec![],
                            body: vec![Stmt::Return {
                                value: Some(var("payload")),
                                span: None,
                            }],
                            span: None,
                        })),
                        None,
                    ),
                    span: None,
                },
                Stmt::Assign {
                    name: "outer".into(),
                    annotation: None,
                    expr: Expr::new(
                        ExprKind::Fn(Box::new(FnExpr {
                            params: vec![],
                            body: vec![Stmt::Return {
                                value: Some(var("inner")),
                                span: None,
                            }],
                            span: None,
                        })),
                        None,
                    ),
                    span: None,
                },
                Stmt::Return {
                    value: Some(var("outer")),
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];

        let report = infer_regions(&stmts);
        let escape_targets: HashSet<_> = report
            .heap_allocations
            .iter()
            .map(|allocation| allocation.escape_to)
            .collect();
        assert_eq!(escape_targets.len(), 1);
        assert!(escape_targets.contains(&Some(
            report
                .heap_allocations
                .iter()
                .find(|allocation| allocation.var == "outer")
                .and_then(|allocation| allocation.escape_to)
                .expect("outer closure escape target")
        )));
        assert_eq!(report.promotions.len(), 3);
        assert_eq!(report.bulk_free_eligible, 0);
    }
}
