//! Typed-stack VM with hot-loop trace JIT (numeric + list + text + map).
#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::ask::query_ask;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::Value;
use crate::typecheck::Type;
use crate::vm::bytecode::{FunctionBytecode, Instr, Program, VmResult};
use crate::vm::jit;
use crate::vm::value_bits as vb;

const HOT_THRESHOLD: u32 = 50;
const MIN_TRACE_LEN: usize = 20;
const SCHEDULER_MAX_LIVE_XMM: usize = 8;
const SUPER_TRACE_ITERS: usize = 4;
const SUPER_TRACE_THRESHOLD: u32 = HOT_THRESHOLD * 4;
const SUPER_TRACE_HOT_CODE_BUDGET: usize = 512;
const MAX_DEOPT: u32 = 10;
const ADAPTIVE_EPOCH_ITERS: u64 = 10_000;
const ADAPTIVE_MIN_SAMPLES: u64 = 20_000;
const ADAPTIVE_FLIP_ON: f64 = 0.99;
const ADAPTIVE_FLIP_OFF: f64 = 0.65;
const ADAPTIVE_MAX_PATCHES_PER_EPOCH: usize = 4;
const ADAPTIVE_STABILITY_PATCH_THRESHOLD_BASE: i32 = 12;
const ADAPTIVE_STABILITY_PATCH_THRESHOLD_PER_REVERT: i32 = 2;
const ADAPTIVE_STABILITY_FLIP_PENALTY_BASE: i32 = 8;
const ADAPTIVE_STABILITY_FLIP_PENALTY_PER_REVERT: i32 = 2;
const ADAPTIVE_STABILITY_RECOVERY: i32 = 1;
const ADAPTIVE_STABILITY_SCORE_MAX: i32 = 1024;
const ADAPTIVE_STABILITY_SCORE_MIN: i32 = -1024;
const ADAPTIVE_REVERT_DECAY_EPOCHS: u64 = 8;

type TraceKey = (usize, usize); // (code_ptr, loop_header)

fn trace_debug() -> bool {
    std::env::var("NAUX_TRACE_DEBUG")
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn trace_debug_log(msg: &str) {
    if trace_debug() {
        eprintln!("[trace-debug] {}", msg);
    }
}

fn trace_debug_ops() -> bool {
    std::env::var("NAUX_TRACE_DEBUG_OPS")
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn trace_debug_loopir() -> bool {
    std::env::var("NAUX_TRACE_DEBUG_LOOPIR")
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn trace_profile() -> bool {
    std::env::var("NAUX_TRACE_PROFILE")
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn strict_map_uniform_guard() -> bool {
    static STRICT: OnceLock<bool> = OnceLock::new();
    *STRICT.get_or_init(|| {
        std::env::var("NAUX_STRICT_MAP_UNIFORM_GUARD")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

fn hash_u64(mut state: u64, value: u64) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    if state == 0 {
        state = FNV_OFFSET;
    }
    for byte in value.to_le_bytes() {
        state ^= u64::from(byte);
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

fn guard_stable_id(guard: &LocalGuard) -> u64 {
    let mut h = 0u64;
    h = hash_u64(h, guard.idx as u64);
    h = hash_u64(h, guard.tag.unwrap_or(0));
    if let Some(shape) = guard.shape {
        match shape {
            ShapeGuard::List {
                elem,
                ptr,
                len,
                cap,
                version,
                data,
            } => {
                h = hash_u64(h, 1);
                h = hash_u64(h, elem.unwrap_or(0));
                h = hash_u64(h, ptr);
                h = hash_u64(h, len as u64);
                h = hash_u64(h, cap as u64);
                h = hash_u64(h, version);
                h = hash_u64(h, data);
            }
            ShapeGuard::Map {
                elem,
                ptr,
                cap,
                version,
                slots,
                slot_size,
            } => {
                h = hash_u64(h, 2);
                h = hash_u64(h, elem.unwrap_or(0));
                h = hash_u64(h, ptr);
                h = hash_u64(h, cap as u64);
                h = hash_u64(h, version);
                h = hash_u64(h, slots);
                h = hash_u64(h, slot_size as u64);
            }
        }
    } else {
        h = hash_u64(h, 0);
    }
    h
}

fn trace_stable_id(
    loop_header: usize,
    exit_target: usize,
    back_edge: usize,
    bc_len: usize,
    ops_len: usize,
) -> u64 {
    let mut h = 0u64;
    h = hash_u64(h, loop_header as u64);
    h = hash_u64(h, exit_target as u64);
    h = hash_u64(h, back_edge as u64);
    h = hash_u64(h, bc_len as u64);
    h = hash_u64(h, ops_len as u64);
    h
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct TraceProfile {
    locals: Vec<LocalGuard>,
}

#[derive(Clone, Copy)]
enum ShapeGuard {
    List {
        elem: Option<u64>,
        ptr: u64,
        len: usize,
        cap: usize,
        version: u64,
        data: u64,
    },
    Map {
        elem: Option<u64>,
        ptr: u64,
        cap: usize,
        version: u64,
        slots: u64,
        slot_size: usize,
    },
}

struct LocalGuard {
    idx: usize,
    tag: Option<u64>,
    shape: Option<ShapeGuard>,
}

#[derive(Clone, Debug)]
struct TraceStats {
    bc_len: usize,
    ops_len: usize,
    live_values: usize,
    static_calls: u64,
    static_branches: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ElemTag {
    Num,
    Tagged(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TraceTy {
    Num,
    Text,
    Null,
    List(ElemTag),
    Map(ElemTag),
    Unknown,
}

#[derive(Clone, Debug)]
struct ValueMeta {
    ty: TraceTy,
    origin: ValueOrigin,
}

#[derive(Clone, Debug)]
enum ValueOrigin {
    Local(usize),
    ConstNum(f64),
    ConstText(String),
    LenOfLocal(usize),
    Unknown,
    Compare(CmpMeta),
}

#[derive(Clone, Debug)]
struct CmpMeta {
    kind: CmpKindSimple,
    lhs: SimpleOrigin,
    rhs: SimpleOrigin,
}

#[derive(Clone, Debug)]
enum CmpKindSimple {
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Debug)]
enum SimpleOrigin {
    Local(usize),
    LenOfLocal(usize),
    ConstNum(f64),
}

struct TraceEntry {
    trace_id: u64,
    first_seen_ts_ms: u64,
    last_seen_ts_ms: u64,
    exec: jit::JitExecutable,
    exit_target: usize,
    back_edge: usize,
    profile: TraceProfile,
    stats: TraceStats,
    ops: Vec<jit::TraceOp>,
    temp_list_sources: Vec<jit::TempListSource>,
    promoted_locals: Vec<usize>,
    merge_locals: Vec<(usize, usize)>,
    tier: TraceTier,
    hits: u32,
    deopt_count: u32,
    deopts_total: u64,
    internal_side_exits: u64,
    runtime_calls: u64,
    runtime_trace_iters: u64,
    runtime_branch_taken: u64,
    runtime_branch_not_taken: u64,
    runtime_deopts: u64,
    runtime_temp_list_elided: u64,
    runtime_temp_map_elided: u64,
    runtime_temp_list_materialized: u64,
    runtime_temp_map_materialized: u64,
    fusion_hits: FusionRuleHits,
    mutated_lists: Vec<usize>,
    version_managed_lists: Vec<usize>,
    mutated_maps: Vec<usize>,
    pic_map_locals: Vec<usize>,
    adaptive_sites: Vec<AdaptiveSiteState>,
    adaptive_epoch_iters: u64,
    adaptive_epochs: u64,
    adaptive_patch_attempts: u64,
    adaptive_patch_commits: u64,
    adaptive_patch_reverts: u64,
    guard_checks: u64,
    guard_fails: u64,
    deopt_reason_counts: HashMap<String, u64>,
    guard_fail_counts: HashMap<GuardFailKey, u64>,
}

#[derive(Clone, Copy, Debug)]
struct ScalarTailListSnapshot {
    local_idx: usize,
    bits: u64,
    ptr: u64,
    len: usize,
    cap: usize,
    version: u64,
    data: u64,
    max_version_delta: u64,
}

#[derive(Clone, Debug)]
struct ScalarTailHandoff {
    key: TraceKey,
    exit_target: usize,
    lists: Vec<ScalarTailListSnapshot>,
}

#[derive(Clone, Copy, Debug)]
struct InternalBranchHandoff {
    key: TraceKey,
    exit_target: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct GuardFailKey {
    guard_id: u64,
    reason: &'static str,
}

#[derive(Clone, Debug, Default)]
struct TraceTelemetryTotals {
    hits_total: u64,
    deopts_total: u64,
    runtime_deopts_total: u64,
    guard_checks_total: u64,
    guard_fail_total: u64,
    internal_side_exits_total: u64,
    deopt_reason_counts: HashMap<String, u64>,
    guard_fail_counts: HashMap<GuardFailKey, u64>,
}

#[derive(Clone, Copy, Debug)]
struct GuardFailure {
    guard_id: u64,
    reason: GuardFailReason,
}

#[derive(Clone, Copy, Debug, Default)]
struct GuardCheckResult {
    checks: u64,
    failure: Option<GuardFailure>,
}

#[derive(Clone, Copy, Debug)]
enum GuardFailReason {
    TagMismatch,
    ListMetaMissing,
    ListLenMismatch,
    ListCapMismatch,
    ListVersionMismatch,
    ListElemTagMismatch,
    MapUniformTagMismatch,
    MapMetaMissing,
    MapPtrMismatch,
    MapCapMismatch,
    MapSlotsMismatch,
    MapSlotSizeMismatch,
    MapVersionMismatch,
}

impl GuardFailReason {
    fn as_str(self) -> &'static str {
        match self {
            GuardFailReason::TagMismatch => "tag_mismatch",
            GuardFailReason::ListMetaMissing => "list_meta_missing",
            GuardFailReason::ListLenMismatch => "list_len_mismatch",
            GuardFailReason::ListCapMismatch => "list_cap_mismatch",
            GuardFailReason::ListVersionMismatch => "list_version_mismatch",
            GuardFailReason::ListElemTagMismatch => "list_elem_tag_mismatch",
            GuardFailReason::MapUniformTagMismatch => "map_uniform_tag_mismatch",
            GuardFailReason::MapMetaMissing => "map_meta_missing",
            GuardFailReason::MapPtrMismatch => "map_ptr_mismatch",
            GuardFailReason::MapCapMismatch => "map_cap_mismatch",
            GuardFailReason::MapSlotsMismatch => "map_slots_mismatch",
            GuardFailReason::MapSlotSizeMismatch => "map_slot_size_mismatch",
            GuardFailReason::MapVersionMismatch => "map_version_mismatch",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct AdaptiveSiteState {
    taken_accum: u64,
    not_taken_accum: u64,
    cooldown_epochs: u32,
    stable_epochs: u64,
    inverted: bool,
    revert_streak: u8,
    stability_score: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceTier {
    Trace,
    Super,
}

struct TracePlan {
    ops: Vec<jit::TraceOp>,
    temp_list_sources: Vec<jit::TempListSource>,
    promoted_locals: Vec<usize>,
    merge_locals: Vec<(usize, usize)>,
    profile: TraceProfile,
    stats: TraceStats,
    mutated_lists: Vec<usize>,
    mutated_maps: Vec<usize>,
    pic_map_locals: Vec<usize>,
    fusion_hits: FusionRuleHits,
}

#[derive(Clone, Copy, Debug, Default)]
struct FusionRuleHits {
    map_const_slot_stable: u64,
    map_stable_add_local: u64,
    map_stable_cmp_branch: u64,
    map_stable_mul_acc: u64,
}

impl FusionRuleHits {
    fn scaled(self, factor: u64) -> Self {
        Self {
            map_const_slot_stable: self.map_const_slot_stable.saturating_mul(factor),
            map_stable_add_local: self.map_stable_add_local.saturating_mul(factor),
            map_stable_cmp_branch: self.map_stable_cmp_branch.saturating_mul(factor),
            map_stable_mul_acc: self.map_stable_mul_acc.saturating_mul(factor),
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug)]
enum FusionRuleId {
    MapConstSlotStable,
    MapStableAddLocal,
    MapStableCmpBranch,
    MapStableMulAcc,
}

impl FusionRuleId {
    fn name(self) -> &'static str {
        match self {
            FusionRuleId::MapConstSlotStable => "map_const_slot_stable",
            FusionRuleId::MapStableAddLocal => "map_stable_add_local",
            FusionRuleId::MapStableCmpBranch => "map_stable_cmp_branch",
            FusionRuleId::MapStableMulAcc => "map_stable_mul_acc",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct FusionTierResult {
    ops: Vec<jit::TraceOp>,
    stable_const_slot_maps: std::collections::BTreeSet<usize>,
    hits: FusionRuleHits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct BlockId(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InstIdx(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InstId {
    block: BlockId,
    idx: InstIdx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct VReg(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegClass {
    Gpr,
    Xmm,
}

#[derive(Clone, Debug)]
struct InstInfo {
    defs: Vec<VReg>,
    uses: Vec<VReg>,
    class_constraints: Vec<RegClass>,
    has_side_effect: bool,
}

#[derive(Clone, Debug)]
enum LoopInstKind {
    LoadListElemF64 {
        dst: VReg,
        list_local: usize,
        idx_local: usize,
        data_ptr: u64,
        offset: i32,
    },
    MulF64 {
        dst: VReg,
        lhs: VReg,
        rhs: VReg,
    },
    AddF64 {
        dst: VReg,
        lhs: VReg,
        rhs: VReg,
    },
    AddAssignLocalFromStack {
        local: usize,
        acc: VReg,
        rhs: VReg,
    },
    AddAssignLocalConst {
        local: usize,
        reg: VReg,
        imm: f64,
    },
    MoveToLocal {
        local: usize,
        dst: VReg,
        src: VReg,
    },
}

#[derive(Clone, Debug)]
struct LoopInst {
    id: InstId,
    kind: LoopInstKind,
    info: InstInfo,
}

#[derive(Clone, Debug)]
struct LoopBlock {
    id: BlockId,
    insts: Vec<LoopInst>,
}

#[derive(Clone, Debug)]
struct LoopIr {
    blocks: Vec<LoopBlock>,
    rpo_blocks: Vec<BlockId>,
    header: BlockId,
    latch: BlockId,
    vreg_classes: std::collections::BTreeMap<VReg, RegClass>,
}

#[derive(Clone, Debug)]
struct LinearInst {
    inst_id: InstId,
    linear_pos: u32,
    info: InstInfo,
    kind: LoopInstKind,
}

#[derive(Clone, Debug, Default)]
struct BlockLiveness {
    live_in: std::collections::BTreeSet<VReg>,
    live_out: std::collections::BTreeSet<VReg>,
}

#[derive(Clone, Debug)]
struct VRegInterval {
    vreg: VReg,
    class: RegClass,
    start: u32,
    end: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhysLoc {
    Xmm(u8),
    Gpr(u8),
    Spill(u32),
}

#[derive(Clone, Debug)]
struct VRegAlloc {
    vreg: VReg,
    class: RegClass,
    start: u32,
    end: u32,
    loc: PhysLoc,
}

#[derive(Clone, Debug, Default)]
struct LoopIntervalReport {
    interval_count: usize,
    max_live_vregs: usize,
    max_live_xmm: usize,
    max_live_gpr: usize,
    max_live_phys_xmm: usize,
    max_live_phys_gpr: usize,
    spill_count: usize,
    allocs: Vec<VRegAlloc>,
    linear: Vec<LinearInst>,
    intervals: Vec<VRegInterval>,
    block_liveness: std::collections::BTreeMap<BlockId, BlockLiveness>,
}

#[derive(Clone, Debug, Default)]
pub struct TraceSummary {
    pub trace_count: usize,
    pub super_count: usize,
    pub min_ops: usize,
    pub max_ops: usize,
    pub avg_ops: f64,
    pub min_code_bytes: usize,
    pub max_code_bytes: usize,
    pub avg_code_bytes: f64,
    pub min_hot_code_bytes: usize,
    pub max_hot_code_bytes: usize,
    pub avg_hot_code_bytes: f64,
    pub max_live: usize,
    pub max_bc_len: usize,
    pub total_hits: u64,
    pub total_deopts: u64,
    pub total_internal_side_exits: u64,
    pub total_static_calls: u64,
    pub total_static_branches: u64,
    pub total_runtime_calls: u64,
    pub total_runtime_branch_taken: u64,
    pub total_runtime_branch_not_taken: u64,
    pub total_runtime_branches: u64,
    pub total_runtime_trace_iters: u64,
    pub total_runtime_deopts: u64,
    pub total_runtime_temp_list_elided: u64,
    pub total_runtime_temp_map_elided: u64,
    pub total_runtime_temp_list_materialized: u64,
    pub total_runtime_temp_map_materialized: u64,
    pub total_runtime_avx_dot_elements: u64,
    pub total_runtime_interp_index_elements: u64,
    pub total_patch_sites: u64,
    pub max_patch_sites: usize,
    pub total_patch_attempts: u64,
    pub total_patch_commits: u64,
    pub total_patch_reverts: u64,
    pub total_adaptive_epochs: u64,
    pub max_adaptive_stable_epochs: u64,
    pub max_revert_streak: u8,
    pub site_profiles: Vec<TraceSiteProfile>,
    pub fusion_hits_by_rule: Vec<FusionRuleProfile>,
    pub max_deopt: u32,
    pub max_hot: u32,
    pub hot_trace_id: u64,
    pub guard_checks_total: u64,
    pub guard_fail_total: u64,
    pub build_fingerprint: BuildFingerprint,
    pub deopt_reasons: Vec<DeoptReasonProfile>,
    pub guard_fails_by_guard: Vec<GuardFailProfile>,
    pub by_trace: Vec<TraceTelemetryProfile>,
}

#[derive(Clone, Debug, Default)]
pub struct TraceSiteProfile {
    pub loop_header: usize,
    pub site_idx: usize,
    pub counter_idx: u32,
    pub kind: u8, // 0=generic, 1=guard, 2=exit
    pub patchable: bool,
    pub inverted: bool,
    pub stability_score: i32,
    pub revert_streak: u8,
    pub cooldown_epochs: u32,
    pub stable_epochs: u64,
    pub taken_accum: u64,
    pub not_taken_accum: u64,
}

#[derive(Clone, Debug, Default)]
pub struct FusionRuleProfile {
    pub rule: String,
    pub static_hits: u64,
    pub runtime_hits: u64,
}

#[derive(Clone, Debug, Default)]
pub struct BuildFingerprint {
    pub git_sha: String,
    pub rustc_version: String,
    pub opt_level: String,
}

#[derive(Clone, Debug, Default)]
pub struct DeoptReasonProfile {
    pub reason: String,
    pub count: u64,
}

#[derive(Clone, Debug, Default)]
pub struct GuardFailProfile {
    pub guard_id: u64,
    pub reason: String,
    pub count: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TraceTelemetryProfile {
    pub trace_id: u64,
    pub loop_header: usize,
    pub first_seen_ts_ms: u64,
    pub last_seen_ts_ms: u64,
    pub trace_lifetime_ms: u64,
    pub hits: u32,
    pub deopts: u64,
    pub internal_side_exits: u64,
    pub guard_checks: u64,
    pub guard_fails: u64,
    pub runtime_deopts: u64,
    pub is_hot: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RunTiming {
    pub total_ns: u128,
    pub setup_ns: u128,
    pub compute_ns: u128,
    pub list_range_calls: u64,
    pub avx_dot_elements: u64,
    pub interp_index_elements: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceOnlyPrep {
    pub trace_count: usize,
    pub loop_header: usize,
    pub hits: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceOnlyTiming {
    pub trace_ns: u128,
    pub avx_dot_elements: u64,
    pub interp_index_elements: u64,
}

#[derive(Clone, Debug, Default)]
struct TraceExecCapture {
    target_key: Option<TraceKey>,
    captured_key: Option<TraceKey>,
    locals: Vec<f64>,
    stack: Vec<f64>,
    sp: usize,
}

impl TraceExecCapture {
    fn for_key(target_key: Option<TraceKey>) -> Self {
        Self {
            target_key,
            captured_key: None,
            locals: Vec::new(),
            stack: Vec::new(),
            sp: 0,
        }
    }

    fn should_capture(&self, key: TraceKey) -> bool {
        self.target_key.is_none() || self.target_key == Some(key)
    }

    fn capture(&mut self, key: TraceKey, locals: &[f64], stack: &[f64], sp: usize) {
        self.captured_key = Some(key);
        self.locals.clear();
        self.locals.extend_from_slice(locals);
        self.stack.clear();
        self.stack.extend_from_slice(&stack[..sp.min(stack.len())]);
        self.sp = sp;
    }
}

#[derive(Clone, Debug)]
struct TraceReplayState {
    key: TraceKey,
    locals: Vec<f64>,
    stack: Vec<f64>,
    sp: usize,
}

fn build_fingerprint() -> BuildFingerprint {
    static FINGERPRINT: OnceLock<BuildFingerprint> = OnceLock::new();
    FINGERPRINT
        .get_or_init(|| BuildFingerprint {
            git_sha: option_env!("GIT_SHA")
                .map(str::to_string)
                .or_else(|| std::env::var("NAUX_GIT_SHA").ok())
                .unwrap_or_else(|| "unknown".to_string()),
            rustc_version: option_env!("RUSTC_VERSION")
                .map(str::to_string)
                .or_else(|| std::env::var("NAUX_RUSTC_VERSION").ok())
                .unwrap_or_else(|| "unknown".to_string()),
            opt_level: option_env!("OPT_LEVEL")
                .map(str::to_string)
                .or_else(|| std::env::var("NAUX_OPT_LEVEL").ok())
                .unwrap_or_else(|| {
                    if cfg!(debug_assertions) {
                        "debug".to_string()
                    } else {
                        "release".to_string()
                    }
                }),
        })
        .clone()
}

pub struct TypedRunner {
    runtime: jit::JitRuntime,
    trace_cache: HashMap<TraceKey, TraceEntry>,
    hot_counters: HashMap<TraceKey, u32>,
    telemetry_totals: TraceTelemetryTotals,
    stack: Vec<f64>,
    total_runtime_avx_dot_elements: u64,
    total_runtime_interp_index_elements: u64,
    last_run_timing: RunTiming,
    trace_replay: Option<TraceReplayState>,
}

impl TypedRunner {
    pub fn new(prog: &Program) -> Self {
        let stack_size = max_stack_depth_program(prog);
        let mut runtime = jit::JitRuntime::new();
        runtime.set_profile_enabled(trace_profile());
        Self {
            runtime,
            trace_cache: HashMap::new(),
            hot_counters: HashMap::new(),
            telemetry_totals: TraceTelemetryTotals::default(),
            stack: vec![0.0f64; stack_size],
            total_runtime_avx_dot_elements: 0,
            total_runtime_interp_index_elements: 0,
            last_run_timing: RunTiming::default(),
            trace_replay: None,
        }
    }

    pub fn run(&mut self, prog: &Program) -> VmResult<(Value, Vec<RuntimeEvent>)> {
        self.trace_replay = None;
        self.run_internal(prog, None)
    }

    fn run_internal(
        &mut self,
        prog: &Program,
        capture: Option<&mut TraceExecCapture>,
    ) -> VmResult<(Value, Vec<RuntimeEvent>)> {
        if !is_supported_program(prog) {
            return Err("typed VM only supports numeric/list/text/map subset".into());
        }
        let run_start = Instant::now();
        let mut run_timing = RunTiming::default();
        let mut events: Vec<RuntimeEvent> = Vec::new();
        let mut locals = vec![0.0f64; prog.main_locals.len().max(1)];
        let mut sp: usize = 0;

        self.runtime.exit_flag = 0;
        self.runtime.error = 0;
        self.runtime.reset_path_counters();

        let bits = run_block(
            prog,
            &prog.main,
            &prog.main_unsafe_flags,
            &mut locals,
            &mut self.stack,
            &mut sp,
            &mut self.runtime,
            &mut events,
            &mut self.trace_cache,
            &mut self.hot_counters,
            &mut self.telemetry_totals,
            &mut run_timing,
            capture,
        )?;

        let value = if matches!(prog.main_return, Some(Type::Bool)) {
            Value::Bool(bits_to_bool(bits))
        } else {
            self.runtime.value_from_bits(bits)
        };

        let (run_avx_dot_elements, run_interp_index_elements) = self.runtime.path_counters();
        self.total_runtime_avx_dot_elements = self
            .total_runtime_avx_dot_elements
            .saturating_add(run_avx_dot_elements);
        self.total_runtime_interp_index_elements = self
            .total_runtime_interp_index_elements
            .saturating_add(run_interp_index_elements);
        run_timing.avx_dot_elements = run_avx_dot_elements;
        run_timing.interp_index_elements = run_interp_index_elements;

        run_timing.total_ns = run_start.elapsed().as_nanos();
        run_timing.compute_ns = run_timing.total_ns.saturating_sub(run_timing.setup_ns);
        self.last_run_timing = run_timing;

        Ok((value, events))
    }

    fn hottest_trace_key(&self) -> Option<TraceKey> {
        self.trace_cache
            .iter()
            .max_by_key(|(_, entry)| (entry.hits, entry.runtime_trace_iters, entry.stats.ops_len))
            .map(|(key, _)| *key)
    }

    pub fn prepare_trace_only(&mut self, prog: &Program) -> VmResult<TraceOnlyPrep> {
        self.trace_replay = None;
        if !is_supported_program(prog) {
            return Err("typed VM only supports numeric/list/text/map subset".into());
        }

        if self.trace_cache.is_empty() {
            for _ in 0..HOT_THRESHOLD.saturating_add(4) {
                let _ = self.run_internal(prog, None)?;
                if !self.trace_cache.is_empty() {
                    break;
                }
            }
        }

        let Some(key) = self.hottest_trace_key() else {
            return Err("trace-only requires at least one compiled trace".into());
        };

        let mut capture = TraceExecCapture::for_key(Some(key));
        let _ = self.run_internal(prog, Some(&mut capture))?;
        if capture.captured_key != Some(key) {
            return Err("trace-only failed to capture trace entry state".into());
        }

        self.trace_replay = Some(TraceReplayState {
            key,
            locals: capture.locals,
            stack: capture.stack,
            sp: capture.sp,
        });

        let hits = self.trace_cache.get(&key).map(|e| e.hits).unwrap_or(0);
        Ok(TraceOnlyPrep {
            trace_count: self.trace_cache.len(),
            loop_header: key.1,
            hits,
        })
    }

    pub fn run_trace_only(&mut self) -> VmResult<TraceOnlyTiming> {
        let replay = self
            .trace_replay
            .clone()
            .ok_or_else(|| "trace-only is not prepared".to_string())?;
        let stack_len = self.stack.len();
        let mut locals = replay.locals;
        let mut stack = vec![0.0f64; stack_len.max(replay.sp).max(1)];
        let copy_len = replay.sp.min(replay.stack.len()).min(stack.len());
        stack[..copy_len].copy_from_slice(&replay.stack[..copy_len]);

        let (runtime, trace_cache) = (&mut self.runtime, &mut self.trace_cache);
        let Some(entry) = trace_cache.get_mut(&replay.key) else {
            return Err("trace-only prepared trace no longer exists".into());
        };

        runtime.exit_flag = 0;
        runtime.error = 0;
        runtime.reset_path_counters();
        if entry.exec.profile_enabled() {
            runtime.set_profile_site_count(entry.exec.patch_sites().len());
            runtime.reset_profile_counters();
        }

        let trace_start = Instant::now();
        let _ = entry.exec.run(&mut locals, &mut stack, runtime);
        let trace_ns = trace_start.elapsed().as_nanos();

        if runtime.error != 0 {
            return Err("JIT trace error".into());
        }
        if runtime.exit_flag == 2 {
            return Err("JIT trace deopt in trace-only run".into());
        }

        let (run_avx_dot_elements, run_interp_index_elements) = runtime.path_counters();
        self.total_runtime_avx_dot_elements = self
            .total_runtime_avx_dot_elements
            .saturating_add(run_avx_dot_elements);
        self.total_runtime_interp_index_elements = self
            .total_runtime_interp_index_elements
            .saturating_add(run_interp_index_elements);

        Ok(TraceOnlyTiming {
            trace_ns,
            avx_dot_elements: run_avx_dot_elements,
            interp_index_elements: run_interp_index_elements,
        })
    }

    pub fn cleanup(&mut self) {
        self.runtime.cleanup();
    }

    pub fn reset_runtime_path_totals(&mut self) {
        self.total_runtime_avx_dot_elements = 0;
        self.total_runtime_interp_index_elements = 0;
    }

    pub fn trace_summary(&self) -> TraceSummary {
        fn branch_kind_code(kind: jit::BranchKind) -> u8 {
            match kind {
                jit::BranchKind::Generic => 0,
                jit::BranchKind::Guard => 1,
                jit::BranchKind::Exit => 2,
            }
        }

        let mut summary = TraceSummary {
            trace_count: self.trace_cache.len(),
            total_hits: self.telemetry_totals.hits_total,
            total_deopts: self.telemetry_totals.deopts_total,
            total_runtime_deopts: self.telemetry_totals.runtime_deopts_total,
            total_runtime_avx_dot_elements: self.total_runtime_avx_dot_elements,
            total_runtime_interp_index_elements: self.total_runtime_interp_index_elements,
            guard_checks_total: self.telemetry_totals.guard_checks_total,
            guard_fail_total: self.telemetry_totals.guard_fail_total,
            total_internal_side_exits: self.telemetry_totals.internal_side_exits_total,
            build_fingerprint: build_fingerprint(),
            ..TraceSummary::default()
        };
        summary.deopt_reasons = self
            .telemetry_totals
            .deopt_reason_counts
            .iter()
            .map(|(reason, count)| DeoptReasonProfile {
                reason: reason.clone(),
                count: *count,
            })
            .collect();
        summary
            .deopt_reasons
            .sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
        summary.guard_fails_by_guard = self
            .telemetry_totals
            .guard_fail_counts
            .iter()
            .map(|(key, count)| GuardFailProfile {
                guard_id: key.guard_id,
                reason: key.reason.to_string(),
                count: *count,
            })
            .collect();
        summary.guard_fails_by_guard.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.guard_id.cmp(&b.guard_id))
                .then_with(|| a.reason.cmp(&b.reason))
        });
        for count in self.hot_counters.values() {
            summary.max_hot = summary.max_hot.max(*count);
        }
        if summary.trace_count == 0 {
            return summary;
        }
        let mut total_ops: usize = 0;
        let mut min_ops: usize = usize::MAX;
        let mut max_ops: usize = 0;
        let mut total_code: usize = 0;
        let mut min_code: usize = usize::MAX;
        let mut max_code: usize = 0;
        let mut total_hot_code: usize = 0;
        let mut min_hot_code: usize = usize::MAX;
        let mut max_hot_code: usize = 0;
        let mut fusion_static_map_const_slot_stable: u64 = 0;
        let mut fusion_static_map_stable_add_local: u64 = 0;
        let mut fusion_static_map_stable_cmp_branch: u64 = 0;
        let mut fusion_static_map_stable_mul_acc: u64 = 0;
        let mut fusion_runtime_map_const_slot_stable: u64 = 0;
        let mut fusion_runtime_map_stable_add_local: u64 = 0;
        let mut fusion_runtime_map_stable_cmp_branch: u64 = 0;
        let mut fusion_runtime_map_stable_mul_acc: u64 = 0;
        let mut hottest_hits: u32 = 0;
        for ((_, loop_header), entry) in self.trace_cache.iter() {
            if entry.tier == TraceTier::Super {
                summary.super_count += 1;
            }
            let ops_len = entry.stats.ops_len;
            let code_len = entry.exec.code_len();
            let hot_code_len = entry.exec.hot_code_len();
            total_ops = total_ops.saturating_add(ops_len);
            total_code = total_code.saturating_add(code_len);
            total_hot_code = total_hot_code.saturating_add(hot_code_len);
            min_ops = min_ops.min(ops_len);
            max_ops = max_ops.max(ops_len);
            min_code = min_code.min(code_len);
            max_code = max_code.max(code_len);
            min_hot_code = min_hot_code.min(hot_code_len);
            max_hot_code = max_hot_code.max(hot_code_len);
            summary.max_live = summary.max_live.max(entry.stats.live_values);
            summary.max_bc_len = summary.max_bc_len.max(entry.stats.bc_len);
            summary.total_static_calls = summary
                .total_static_calls
                .saturating_add(entry.stats.static_calls);
            summary.total_static_branches = summary
                .total_static_branches
                .saturating_add(entry.stats.static_branches);
            summary.total_runtime_calls = summary
                .total_runtime_calls
                .saturating_add(entry.runtime_calls);
            summary.total_runtime_trace_iters = summary
                .total_runtime_trace_iters
                .saturating_add(entry.runtime_trace_iters);
            summary.total_runtime_branch_taken = summary
                .total_runtime_branch_taken
                .saturating_add(entry.runtime_branch_taken);
            summary.total_runtime_branch_not_taken = summary
                .total_runtime_branch_not_taken
                .saturating_add(entry.runtime_branch_not_taken);
            summary.total_runtime_temp_list_elided = summary
                .total_runtime_temp_list_elided
                .saturating_add(entry.runtime_temp_list_elided);
            summary.total_runtime_temp_map_elided = summary
                .total_runtime_temp_map_elided
                .saturating_add(entry.runtime_temp_map_elided);
            summary.total_runtime_temp_list_materialized = summary
                .total_runtime_temp_list_materialized
                .saturating_add(entry.runtime_temp_list_materialized);
            summary.total_runtime_temp_map_materialized = summary
                .total_runtime_temp_map_materialized
                .saturating_add(entry.runtime_temp_map_materialized);
            let patch_sites = entry.exec.patch_sites().len();
            summary.total_patch_sites =
                summary.total_patch_sites.saturating_add(patch_sites as u64);
            summary.max_patch_sites = summary.max_patch_sites.max(patch_sites);
            summary.total_patch_attempts = summary
                .total_patch_attempts
                .saturating_add(entry.adaptive_patch_attempts);
            summary.total_patch_commits = summary
                .total_patch_commits
                .saturating_add(entry.adaptive_patch_commits);
            summary.total_patch_reverts = summary
                .total_patch_reverts
                .saturating_add(entry.adaptive_patch_reverts);
            summary.total_adaptive_epochs = summary
                .total_adaptive_epochs
                .saturating_add(entry.adaptive_epochs);
            let max_site_stable = entry
                .adaptive_sites
                .iter()
                .map(|s| s.stable_epochs)
                .max()
                .unwrap_or(0);
            summary.max_adaptive_stable_epochs =
                summary.max_adaptive_stable_epochs.max(max_site_stable);
            let max_site_revert = entry
                .adaptive_sites
                .iter()
                .map(|s| s.revert_streak)
                .max()
                .unwrap_or(0);
            summary.max_revert_streak = summary.max_revert_streak.max(max_site_revert);
            for (site_idx, patch) in entry.exec.patch_sites().iter().enumerate() {
                let state = entry.adaptive_sites.get(site_idx);
                summary.site_profiles.push(TraceSiteProfile {
                    loop_header: *loop_header,
                    site_idx,
                    counter_idx: patch.counter_idx,
                    kind: branch_kind_code(patch.kind),
                    patchable: patch.patchable,
                    inverted: state.map(|s| s.inverted).unwrap_or(patch.inverted),
                    stability_score: state.map(|s| s.stability_score).unwrap_or_default(),
                    revert_streak: state.map(|s| s.revert_streak).unwrap_or_default(),
                    cooldown_epochs: state.map(|s| s.cooldown_epochs).unwrap_or_default(),
                    stable_epochs: state.map(|s| s.stable_epochs).unwrap_or_default(),
                    taken_accum: state.map(|s| s.taken_accum).unwrap_or_default(),
                    not_taken_accum: state.map(|s| s.not_taken_accum).unwrap_or_default(),
                });
            }
            summary.total_runtime_branches = summary.total_runtime_branches.saturating_add(
                entry
                    .runtime_branch_taken
                    .saturating_add(entry.runtime_branch_not_taken),
            );
            if summary.hot_trace_id == 0 || entry.hits >= hottest_hits {
                hottest_hits = entry.hits;
                summary.hot_trace_id = entry.trace_id;
            }
            summary.by_trace.push(TraceTelemetryProfile {
                trace_id: entry.trace_id,
                loop_header: *loop_header,
                first_seen_ts_ms: entry.first_seen_ts_ms,
                last_seen_ts_ms: entry.last_seen_ts_ms,
                trace_lifetime_ms: entry.last_seen_ts_ms.saturating_sub(entry.first_seen_ts_ms),
                hits: entry.hits,
                deopts: entry.deopts_total,
                internal_side_exits: entry.internal_side_exits,
                guard_checks: entry.guard_checks,
                guard_fails: entry.guard_fails,
                runtime_deopts: entry.runtime_deopts,
                is_hot: false,
            });
            fusion_static_map_const_slot_stable = fusion_static_map_const_slot_stable
                .saturating_add(entry.fusion_hits.map_const_slot_stable);
            fusion_static_map_stable_add_local = fusion_static_map_stable_add_local
                .saturating_add(entry.fusion_hits.map_stable_add_local);
            fusion_static_map_stable_cmp_branch = fusion_static_map_stable_cmp_branch
                .saturating_add(entry.fusion_hits.map_stable_cmp_branch);
            fusion_static_map_stable_mul_acc = fusion_static_map_stable_mul_acc
                .saturating_add(entry.fusion_hits.map_stable_mul_acc);
            fusion_runtime_map_const_slot_stable = fusion_runtime_map_const_slot_stable
                .saturating_add(
                    entry
                        .fusion_hits
                        .map_const_slot_stable
                        .saturating_mul(entry.hits as u64),
                );
            fusion_runtime_map_stable_add_local = fusion_runtime_map_stable_add_local
                .saturating_add(
                    entry
                        .fusion_hits
                        .map_stable_add_local
                        .saturating_mul(entry.hits as u64),
                );
            fusion_runtime_map_stable_cmp_branch = fusion_runtime_map_stable_cmp_branch
                .saturating_add(
                    entry
                        .fusion_hits
                        .map_stable_cmp_branch
                        .saturating_mul(entry.hits as u64),
                );
            fusion_runtime_map_stable_mul_acc = fusion_runtime_map_stable_mul_acc.saturating_add(
                entry
                    .fusion_hits
                    .map_stable_mul_acc
                    .saturating_mul(entry.hits as u64),
            );
            summary.max_deopt = summary.max_deopt.max(entry.deopt_count);
        }
        summary.by_trace.sort_by(|a, b| {
            b.hits
                .cmp(&a.hits)
                .then_with(|| b.runtime_deopts.cmp(&a.runtime_deopts))
                .then_with(|| a.loop_header.cmp(&b.loop_header))
        });
        if summary.hot_trace_id != 0 {
            for trace in &mut summary.by_trace {
                trace.is_hot = trace.trace_id == summary.hot_trace_id;
            }
        }
        summary.min_ops = min_ops;
        summary.max_ops = max_ops;
        summary.avg_ops = total_ops as f64 / summary.trace_count as f64;
        summary.min_code_bytes = min_code;
        summary.max_code_bytes = max_code;
        summary.avg_code_bytes = total_code as f64 / summary.trace_count as f64;
        summary.min_hot_code_bytes = min_hot_code;
        summary.max_hot_code_bytes = max_hot_code;
        summary.avg_hot_code_bytes = total_hot_code as f64 / summary.trace_count as f64;
        if fusion_static_map_const_slot_stable > 0 || fusion_runtime_map_const_slot_stable > 0 {
            summary.fusion_hits_by_rule.push(FusionRuleProfile {
                rule: FusionRuleId::MapConstSlotStable.name().to_string(),
                static_hits: fusion_static_map_const_slot_stable,
                runtime_hits: fusion_runtime_map_const_slot_stable,
            });
        }
        if fusion_static_map_stable_add_local > 0 || fusion_runtime_map_stable_add_local > 0 {
            summary.fusion_hits_by_rule.push(FusionRuleProfile {
                rule: FusionRuleId::MapStableAddLocal.name().to_string(),
                static_hits: fusion_static_map_stable_add_local,
                runtime_hits: fusion_runtime_map_stable_add_local,
            });
        }
        if fusion_static_map_stable_cmp_branch > 0 || fusion_runtime_map_stable_cmp_branch > 0 {
            summary.fusion_hits_by_rule.push(FusionRuleProfile {
                rule: FusionRuleId::MapStableCmpBranch.name().to_string(),
                static_hits: fusion_static_map_stable_cmp_branch,
                runtime_hits: fusion_runtime_map_stable_cmp_branch,
            });
        }
        if fusion_static_map_stable_mul_acc > 0 || fusion_runtime_map_stable_mul_acc > 0 {
            summary.fusion_hits_by_rule.push(FusionRuleProfile {
                rule: FusionRuleId::MapStableMulAcc.name().to_string(),
                static_hits: fusion_static_map_stable_mul_acc,
                runtime_hits: fusion_runtime_map_stable_mul_acc,
            });
        }
        summary
    }

    pub fn last_run_timing(&self) -> RunTiming {
        self.last_run_timing
    }
}

struct CallContext {
    prog: *const Program,
    events: *mut Vec<RuntimeEvent>,
    trace_cache: *mut HashMap<TraceKey, TraceEntry>,
    hot_counters: *mut HashMap<TraceKey, u32>,
    telemetry_totals: *mut TraceTelemetryTotals,
}

extern "C" fn call_user_fn(
    name_ptr: *const u8,
    argc: usize,
    args_ptr: *const f64,
    rt: *mut jit::JitRuntime,
    _deopt_ip: usize,
) -> u64 {
    let Some(rt) = (unsafe { rt.as_mut() }) else {
        return vb::tag_null();
    };
    rt.error = 0;
    rt.exit_flag = 0;

    let ctx_ptr = rt.call_ctx as *mut CallContext;
    if ctx_ptr.is_null() {
        rt.exit_flag = 2;
        return vb::tag_null();
    }
    let ctx = unsafe { &mut *ctx_ptr };

    let name = unsafe { CStr::from_ptr(name_ptr as *const c_char) }
        .to_str()
        .ok();
    let Some(name) = name else {
        rt.exit_flag = 2;
        return vb::tag_null();
    };
    let prog = unsafe { &*ctx.prog };
    let Some(func) = prog.functions.get(name) else {
        rt.exit_flag = 2;
        return vb::tag_null();
    };

    let args = if argc == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(args_ptr, argc) }
    };
    let mut inner_locals = vec![0.0f64; func.locals.len().max(1)];
    for (i, v) in args.iter().enumerate() {
        if i < inner_locals.len() {
            inner_locals[i] = *v;
        }
    }

    let stack_size = max_stack_depth_code(&func.code).saturating_mul(4).max(64);
    let mut stack = vec![0.0f64; stack_size];
    let mut sp: usize = 0;

    let events = unsafe { &mut *ctx.events };
    let trace_cache = unsafe { &mut *ctx.trace_cache };
    let hot_counters = unsafe { &mut *ctx.hot_counters };
    let telemetry_totals = unsafe { &mut *ctx.telemetry_totals };
    let mut run_timing = RunTiming::default();

    match run_block(
        prog,
        &func.code,
        &func.unsafe_flags,
        &mut inner_locals,
        &mut stack,
        &mut sp,
        rt,
        events,
        trace_cache,
        hot_counters,
        telemetry_totals,
        &mut run_timing,
        None,
    ) {
        Ok(bits) => bits,
        Err(_) => {
            rt.exit_flag = 2;
            vb::tag_null()
        }
    }
}

pub fn is_supported_program(prog: &Program) -> bool {
    if !matches!(
        prog.main_return,
        Some(Type::Num)
            | Some(Type::Bool)
            | Some(Type::Text)
            | Some(Type::Null)
            | Some(Type::Any)
            | Some(Type::List(_))
            | Some(Type::Map(_))
            | None
    ) {
        return false;
    }
    if !is_supported_code(&prog.main, &prog.functions) {
        return false;
    }
    for func in prog.functions.values() {
        if !is_supported_code(&func.code, &prog.functions) {
            return false;
        }
    }
    true
}

fn is_supported_code(code: &[Instr], functions: &HashMap<String, FunctionBytecode>) -> bool {
    code.iter().all(|instr| match instr {
        Instr::ConstNum(_)
        | Instr::ConstText(_)
        | Instr::ConstBool(_)
        | Instr::PushNull
        | Instr::LoadLocal(_)
        | Instr::StoreLocal(_)
        | Instr::StoreLocalKeep(_)
        | Instr::AddLocalConst(_, _)
        | Instr::Add
        | Instr::Sub
        | Instr::Mul
        | Instr::Div
        | Instr::Eq
        | Instr::Ne
        | Instr::Lt
        | Instr::Le
        | Instr::Gt
        | Instr::Ge
        | Instr::Jump(_)
        | Instr::JumpIfFalse(_)
        | Instr::JumpLocalIfFalse(_, _)
        | Instr::MakeList(_)
        | Instr::MakeMap(_)
        | Instr::LoadField(_)
        | Instr::EmitSay
        | Instr::EmitAsk
        | Instr::EmitFetch
        | Instr::EmitUi(_)
        | Instr::EmitText
        | Instr::EmitButton
        | Instr::EmitLog
        | Instr::Pop
        | Instr::Return => true,
        Instr::CallBuiltin(name, argc) => {
            (name == "__index" && *argc == 2)
                || (name == "__setindex" && *argc == 3)
                || (name == "len" && *argc == 1)
                || (name == "to_text" && *argc == 1)
                || (name == "list_range" && *argc == 1)
        }
        Instr::CallFn(name, _argc) => functions.contains_key(name),
        _ => false,
    })
}

pub fn run_typed_with_trace(prog: &Program) -> VmResult<(Value, Vec<RuntimeEvent>)> {
    if !is_supported_program(prog) {
        return Err("typed VM only supports numeric/list/text/map subset".into());
    }

    let stack_size = max_stack_depth_program(prog);
    let mut stack = vec![0.0f64; stack_size];
    let mut sp: usize = 0;
    let mut runtime = jit::JitRuntime::new();
    runtime.set_profile_enabled(trace_profile());
    let mut events: Vec<RuntimeEvent> = Vec::new();
    let mut locals = vec![0.0f64; prog.main_locals.len().max(1)];
    let mut trace_cache: HashMap<TraceKey, TraceEntry> = HashMap::new();
    let mut hot_counters: HashMap<TraceKey, u32> = HashMap::new();
    let mut telemetry_totals = TraceTelemetryTotals::default();
    let mut run_timing = RunTiming::default();

    let mut call_ctx = Box::new(CallContext {
        prog: prog as *const Program,
        events: &mut events as *mut Vec<RuntimeEvent>,
        trace_cache: &mut trace_cache as *mut HashMap<TraceKey, TraceEntry>,
        hot_counters: &mut hot_counters as *mut HashMap<TraceKey, u32>,
        telemetry_totals: &mut telemetry_totals as *mut TraceTelemetryTotals,
    });
    runtime.call_ctx = (&mut *call_ctx) as *mut CallContext as *mut std::ffi::c_void;
    runtime.call_user = Some(call_user_fn);

    let bits = run_block(
        prog,
        &prog.main,
        &prog.main_unsafe_flags,
        &mut locals,
        &mut stack,
        &mut sp,
        &mut runtime,
        &mut events,
        &mut trace_cache,
        &mut hot_counters,
        &mut telemetry_totals,
        &mut run_timing,
        None,
    )?;

    let value = if matches!(prog.main_return, Some(Type::Bool)) {
        Value::Bool(bits_to_bool(bits))
    } else {
        runtime.value_from_bits(bits)
    };
    runtime.cleanup();

    Ok((value, events))
}

fn max_stack_depth_program(prog: &Program) -> usize {
    let mut max_depth = max_stack_depth_code(&prog.main);
    for func in prog.functions.values() {
        max_depth = max_depth.max(max_stack_depth_code(&func.code));
    }
    max_depth.saturating_mul(4).max(64)
}

fn max_stack_depth_code(code: &[Instr]) -> usize {
    let mut depth: i32 = 0;
    let mut max_depth: i32 = 0;
    for instr in code {
        let delta = match instr {
            Instr::ConstNum(_)
            | Instr::ConstBool(_)
            | Instr::ConstText(_)
            | Instr::PushNull
            | Instr::LoadLocal(_) => 1,
            Instr::StoreLocal(_) => -1,
            Instr::StoreLocalKeep(_) => 0,
            Instr::AddLocalConst(_, _) => 0,
            Instr::Add
            | Instr::Sub
            | Instr::Mul
            | Instr::Div
            | Instr::Eq
            | Instr::Ne
            | Instr::Lt
            | Instr::Le
            | Instr::Gt
            | Instr::Ge => -1,
            Instr::JumpIfFalse(_) => -1,
            Instr::JumpLocalIfFalse(_, _) => 0,
            Instr::Jump(_) => 0,
            Instr::MakeList(n) => 1 - (*n as i32),
            Instr::MakeMap(keys) => 1 - (keys.len() as i32),
            Instr::LoadField(_) => 0,
            Instr::CallBuiltin(_, argc) => 1 - (*argc as i32),
            Instr::CallFn(_, argc) => 1 - (*argc as i32),
            Instr::EmitSay
            | Instr::EmitAsk
            | Instr::EmitFetch
            | Instr::EmitText
            | Instr::EmitButton
            | Instr::EmitLog => -1,
            Instr::EmitUi(_) => 0,
            Instr::Pop => -1,
            Instr::Return => -1,
            _ => 0,
        };
        depth += delta;
        if depth > max_depth {
            max_depth = depth;
        }
    }
    usize::max(16, max_depth.max(0) as usize + 4)
}

#[allow(clippy::too_many_arguments)]
fn run_block(
    prog: &Program,
    code: &[Instr],
    unsafe_flags: &[bool],
    locals: &mut [f64],
    stack: &mut [f64],
    sp: &mut usize,
    runtime: &mut jit::JitRuntime,
    events: &mut Vec<RuntimeEvent>,
    trace_cache: &mut HashMap<TraceKey, TraceEntry>,
    hot_counters: &mut HashMap<TraceKey, u32>,
    telemetry_totals: &mut TraceTelemetryTotals,
    timing: &mut RunTiming,
    mut capture: Option<&mut TraceExecCapture>,
) -> VmResult<u64> {
    let mut ip: usize = 0;
    let code_id = code.as_ptr() as usize;
    let run_seen_ts_ms = now_unix_ms();
    let mut scalar_tail_handoff: Option<ScalarTailHandoff> = None;
    let mut internal_branch_handoff: Option<InternalBranchHandoff> = None;

    while ip < code.len() {
        match &code[ip] {
            Instr::ConstNum(n) => push(stack, sp, *n),
            Instr::ConstBool(b) => push(stack, sp, if *b { 1.0 } else { 0.0 }),
            Instr::ConstText(s) => {
                let bits = runtime.make_text(s);
                push_bits(stack, sp, bits);
            }
            Instr::PushNull => {
                push_bits(stack, sp, vb::tag_null());
            }
            Instr::LoadLocal(idx) => {
                let v = *locals.get(*idx).unwrap_or(&0.0);
                push(stack, sp, v);
            }
            Instr::StoreLocal(idx) => {
                let v = pop(stack, sp)?;
                if let Some(slot) = locals.get_mut(*idx) {
                    *slot = v;
                }
            }
            Instr::StoreLocalKeep(idx) => {
                if *sp == 0 {
                    return Err("stack underflow".into());
                }
                let v = stack[*sp - 1];
                if let Some(slot) = locals.get_mut(*idx) {
                    *slot = v;
                }
            }
            Instr::AddLocalConst(idx, c) => {
                if let Some(slot) = locals.get_mut(*idx) {
                    *slot += *c;
                }
            }
            Instr::Add => {
                let rhs_bits = pop_bits(stack, sp)?;
                let lhs_bits = pop_bits(stack, sp)?;
                if is_number(lhs_bits) && is_number(rhs_bits) {
                    let out = f64::from_bits(lhs_bits) + f64::from_bits(rhs_bits);
                    push(stack, sp, out);
                } else if vb::is_text(lhs_bits) || vb::is_text(rhs_bits) {
                    let out_bits = runtime.concat_text_bits(lhs_bits, rhs_bits);
                    push_bits(stack, sp, out_bits);
                } else {
                    return Err("Type error in Add".into());
                }
            }
            Instr::Sub => bin_num(stack, sp, |a, b| a - b)?,
            Instr::Mul => bin_num(stack, sp, |a, b| a * b)?,
            Instr::Div => bin_num(stack, sp, |a, b| a / b)?,
            Instr::Eq => cmp_eq(stack, sp, runtime, true)?,
            Instr::Ne => cmp_eq(stack, sp, runtime, false)?,
            Instr::Lt => cmp_num(stack, sp, |a, b| a < b)?,
            Instr::Le => cmp_num(stack, sp, |a, b| a <= b)?,
            Instr::Gt => cmp_num(stack, sp, |a, b| a > b)?,
            Instr::Ge => cmp_num(stack, sp, |a, b| a >= b)?,
            Instr::Jump(target) => {
                if *target < ip && *sp == 0 {
                    let key = (code_id, *target);
                    if scalar_tail_handoff
                        .as_ref()
                        .is_some_and(|handoff| handoff.key == key)
                        || internal_branch_handoff
                            .as_ref()
                            .is_some_and(|handoff| handoff.key == key)
                    {
                        // A trace has handed the rest of this loop invocation to the
                        // interpreter. Do not bounce through the same tail/side exit on
                        // every remaining scalar iteration.
                        ip = *target;
                        continue;
                    }
                    let mut exit_target: Option<usize> = None;
                    let mut can_run = false;
                    let mut should_evict = false;
                    if let Some(entry) = trace_cache.get_mut(&key) {
                        if ip != entry.back_edge {
                            // Back-edge mismatch: skip this trace.
                            trace_debug_log("trace skip: back-edge mismatch");
                        } else {
                            let guard_result = guard_profile_check(
                                &entry.profile,
                                &entry.mutated_lists,
                                &entry.mutated_maps,
                                &entry.pic_map_locals,
                                locals,
                                runtime,
                            );
                            telemetry_totals.guard_checks_total = telemetry_totals
                                .guard_checks_total
                                .saturating_add(guard_result.checks);
                            entry.guard_checks =
                                entry.guard_checks.saturating_add(guard_result.checks);
                            if let Some(failure) = guard_result.failure {
                                let reason = failure.reason.as_str();
                                let key = GuardFailKey {
                                    guard_id: failure.guard_id,
                                    reason,
                                };
                                telemetry_totals.guard_fail_total =
                                    telemetry_totals.guard_fail_total.saturating_add(1);
                                telemetry_totals
                                    .guard_fail_counts
                                    .entry(key)
                                    .and_modify(|count| *count = count.saturating_add(1))
                                    .or_insert(1);
                                entry.guard_fails = entry.guard_fails.saturating_add(1);
                                entry
                                    .guard_fail_counts
                                    .entry(key)
                                    .and_modify(|count| *count = count.saturating_add(1))
                                    .or_insert(1);
                                should_evict = true;
                            } else {
                                exit_target = Some(entry.exit_target);
                                can_run = true;
                            }
                        }
                    }
                    if should_evict {
                        trace_debug_log("trace skip: guard failed");
                        trace_cache.remove(&key);
                        hot_counters.remove(&key);
                    }

                    if can_run {
                        if let Some(entry) = trace_cache.get_mut(&key) {
                            entry.hits = entry.hits.saturating_add(1);
                            telemetry_totals.hits_total =
                                telemetry_totals.hits_total.saturating_add(1);
                            entry.last_seen_ts_ms = run_seen_ts_ms;
                            trace_debug_log("trace run: executing compiled trace");
                            if entry.tier == TraceTier::Trace && entry.hits >= SUPER_TRACE_THRESHOLD
                            {
                                if let Some(super_ops) =
                                    build_super_ops(&entry.ops, SUPER_TRACE_ITERS)
                                {
                                    let mut stats = TraceStats {
                                        bc_len: entry.stats.bc_len,
                                        ops_len: super_ops.len(),
                                        live_values: trace_live_values(&super_ops),
                                        static_calls: 0,
                                        static_branches: 0,
                                    };
                                    let super_sources = collect_temp_list_sources(&super_ops);
                                    let super_promoted = select_promoted_locals(&super_ops);
                                    if let Ok(exec) = jit::compile_trace_typed(
                                        &super_ops,
                                        &super_sources,
                                        key.1,
                                        runtime.profile_enabled(),
                                        &super_promoted,
                                        &entry.merge_locals,
                                    ) {
                                        if exec.hot_code_len() <= SUPER_TRACE_HOT_CODE_BUDGET {
                                            stats.static_calls = exec.static_call_count();
                                            stats.static_branches = exec.static_branch_count();
                                            entry.exec = exec;
                                            entry.ops = super_ops;
                                            entry.version_managed_lists =
                                                collect_version_managed_lists(&entry.ops);
                                            entry.temp_list_sources = super_sources;
                                            entry.promoted_locals = super_promoted;
                                            entry.stats = stats;
                                            entry.tier = TraceTier::Super;
                                            entry.fusion_hits =
                                                entry.fusion_hits.scaled(SUPER_TRACE_ITERS as u64);
                                            reset_adaptive_state(entry);
                                        } else {
                                            trace_debug_log(
                                                "trace promote skipped: super trace hot-path over budget",
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        runtime.exit_flag = 0;
                        runtime.error = 0;
                        if let Some(capture_ref) = capture.as_deref_mut() {
                            if capture_ref.should_capture(key) {
                                capture_ref.capture(key, locals, stack, *sp);
                            }
                        }
                        if let Some(entry) = trace_cache.get_mut(&key) {
                            if entry.exec.profile_enabled() {
                                runtime.set_profile_site_count(entry.exec.patch_sites().len());
                                runtime.reset_profile_counters();
                            }
                            let _ = entry.exec.run(locals, stack, runtime);
                            if entry.exec.profile_enabled() {
                                let prof = runtime.profile_snapshot();
                                entry.runtime_calls =
                                    entry.runtime_calls.saturating_add(prof.calls);
                                entry.runtime_trace_iters =
                                    entry.runtime_trace_iters.saturating_add(prof.trace_iters);
                                entry.runtime_branch_taken =
                                    entry.runtime_branch_taken.saturating_add(prof.branch_taken);
                                entry.runtime_branch_not_taken = entry
                                    .runtime_branch_not_taken
                                    .saturating_add(prof.branch_not_taken);
                                entry.runtime_deopts =
                                    entry.runtime_deopts.saturating_add(prof.deopts);
                                telemetry_totals.runtime_deopts_total = telemetry_totals
                                    .runtime_deopts_total
                                    .saturating_add(prof.deopts);
                                entry.runtime_temp_list_elided = entry
                                    .runtime_temp_list_elided
                                    .saturating_add(prof.temp_list_elided);
                                entry.runtime_temp_map_elided = entry
                                    .runtime_temp_map_elided
                                    .saturating_add(prof.temp_map_elided);
                                entry.runtime_temp_list_materialized = entry
                                    .runtime_temp_list_materialized
                                    .saturating_add(prof.temp_list_materialized);
                                entry.runtime_temp_map_materialized = entry
                                    .runtime_temp_map_materialized
                                    .saturating_add(prof.temp_map_materialized);
                                update_adaptive_patcher(entry, runtime, &prof);
                            }
                        }
                        if runtime.error != 0 {
                            return Err("JIT trace error".into());
                        }
                        if runtime.exit_flag == 1 {
                            // Reify temp allocations before resuming interpreter mode.
                            runtime.materialize_temps_in_frame(locals, stack, *sp);
                            if let Some(entry) = trace_cache.get_mut(&key) {
                                bump_mutated_list_versions(entry, locals, runtime);
                                refresh_mutated_list_guards(entry, locals, runtime);
                                refresh_mutated_map_guards(entry, locals, runtime);
                            }
                            *sp = 0;
                            ip = exit_target.unwrap_or(*target);
                            continue;
                        } else if runtime.exit_flag == 2 {
                            let deopt_ip = runtime.deopt_ip;
                            let deopt_sp = runtime.deopt_sp;
                            let deopt_site = runtime.deopt_site;
                            let internal_branch_deopt = is_internal_branch_deopt(
                                code,
                                key.1,
                                trace_cache
                                    .get(&key)
                                    .map(|entry| entry.back_edge)
                                    .unwrap_or(ip),
                                deopt_ip,
                            );
                            runtime.exit_flag = 0;
                            if deopt_sp <= stack.len() {
                                *sp = deopt_sp;
                            }
                            // Eager materialization: reify temp-allocated objects before
                            // returning to interpreter semantics after deopt.
                            runtime.materialize_temps_in_frame(locals, stack, *sp);
                            if let Some(entry) = trace_cache.get_mut(&key) {
                                bump_mutated_list_versions(entry, locals, runtime);
                                if trace_debug() {
                                    let checksum =
                                        temp_list_source_checksum(&entry.temp_list_sources);
                                    trace_debug_log(&format!(
                                        "deopt temp-source checksum={checksum}"
                                    ));
                                }
                                if internal_branch_deopt {
                                    entry.internal_side_exits =
                                        entry.internal_side_exits.saturating_add(1);
                                    telemetry_totals.internal_side_exits_total = telemetry_totals
                                        .internal_side_exits_total
                                        .saturating_add(1);
                                    if entry.exec.profile_enabled() {
                                        // The machine-code profiler records all exit-flag=2
                                        // paths as deopts. Reclassify this known internal
                                        // branch handoff so the speculative-deopt budget is
                                        // not poisoned by an expected side exit.
                                        entry.runtime_deopts =
                                            entry.runtime_deopts.saturating_sub(1);
                                        telemetry_totals.runtime_deopts_total =
                                            telemetry_totals.runtime_deopts_total.saturating_sub(1);
                                    }
                                    internal_branch_handoff = Some(InternalBranchHandoff {
                                        key,
                                        exit_target: entry.exit_target,
                                    });
                                    trace_debug_log(
                                        "trace side exit: handing remaining loop iterations to VM",
                                    );
                                } else {
                                    record_speculative_deopt(
                                        &mut entry.deopts_total,
                                        &mut entry.deopt_reason_counts,
                                        telemetry_totals,
                                        deopt_site,
                                    );
                                    let mut promoted =
                                        try_promote_map_pic2(entry, deopt_ip, locals, runtime);
                                    if promoted {
                                        if let Ok(exec) = jit::compile_trace_typed(
                                            &entry.ops,
                                            &entry.temp_list_sources,
                                            key.1,
                                            runtime.profile_enabled(),
                                            &entry.promoted_locals,
                                            &entry.merge_locals,
                                        ) {
                                            entry.stats.static_calls = exec.static_call_count();
                                            entry.stats.static_branches =
                                                exec.static_branch_count();
                                            entry.exec = exec;
                                            entry.deopt_count = 0;
                                            reset_adaptive_state(entry);
                                            trace_debug_log("trace promote: map PIC2");
                                        } else {
                                            promoted = false;
                                        }
                                    }
                                    if !promoted {
                                        entry.deopt_count = entry.deopt_count.saturating_add(1);
                                    }
                                    if entry.deopt_count >= MAX_DEOPT {
                                        trace_cache.remove(&key);
                                        hot_counters.remove(&key);
                                    }
                                }
                            }
                            ip = deopt_ip;
                            continue;
                        } else if runtime.exit_flag == 3 {
                            // An unrolled trace exhausted its full-width range while scalar
                            // iterations may remain. Resume at the bytecode loop header rather
                            // than treating this expected tail as a speculative deopt.
                            let resume_ip = runtime.deopt_ip;
                            let resume_sp = runtime.deopt_sp;
                            runtime.exit_flag = 0;
                            if resume_sp <= stack.len() {
                                *sp = resume_sp;
                            }
                            runtime.materialize_temps_in_frame(locals, stack, *sp);
                            let mut evict_trace = false;
                            if let Some(entry) = trace_cache.get_mut(&key) {
                                bump_mutated_list_versions(entry, locals, runtime);
                                refresh_mutated_map_guards(entry, locals, runtime);
                                scalar_tail_handoff =
                                    capture_scalar_tail_handoff(key, entry, locals, runtime);
                                evict_trace = scalar_tail_handoff.is_none();
                            }
                            if evict_trace {
                                trace_cache.remove(&key);
                                hot_counters.remove(&key);
                            }
                            ip = resume_ip;
                            continue;
                        }
                    } else {
                        let count = hot_counters.get(&key).copied().unwrap_or(0) + 1;
                        hot_counters.insert(key, count);
                        if count == HOT_THRESHOLD {
                            if let Some(exit_target) = find_loop_exit(code, *target, ip) {
                                let trace_len = ip.saturating_sub(*target) + 1;
                                if trace_len < MIN_TRACE_LEN {
                                    // Skip tiny traces.
                                } else if let Some((jump_ip, jump_target)) =
                                    find_unsupported_internal_backedge(code, *target, ip)
                                {
                                    trace_debug_log(&format!(
                                        "trace skipped: nested/internal jump in candidate (start={}, end={}, jump_ip={}, jump_target={})",
                                        *target, ip, jump_ip, jump_target
                                    ));
                                } else if let Some(plan) = build_trace_plan(
                                    code,
                                    *target,
                                    ip,
                                    locals,
                                    runtime,
                                    unsafe_flags,
                                ) {
                                    if let Ok(exec) = jit::compile_trace_typed(
                                        &plan.ops,
                                        &plan.temp_list_sources,
                                        *target,
                                        runtime.profile_enabled(),
                                        &plan.promoted_locals,
                                        &plan.merge_locals,
                                    ) {
                                        let mut stats = plan.stats.clone();
                                        stats.static_calls = exec.static_call_count();
                                        stats.static_branches = exec.static_branch_count();
                                        let adaptive_sites = init_adaptive_sites(&exec);
                                        let version_managed_lists =
                                            collect_version_managed_lists(&plan.ops);
                                        trace_debug_log("trace compiled at hot threshold");
                                        trace_cache.insert(
                                            key,
                                            TraceEntry {
                                                trace_id: trace_stable_id(
                                                    key.1,
                                                    exit_target,
                                                    ip,
                                                    stats.bc_len,
                                                    stats.ops_len,
                                                ),
                                                first_seen_ts_ms: run_seen_ts_ms,
                                                last_seen_ts_ms: run_seen_ts_ms,
                                                exec,
                                                exit_target,
                                                back_edge: ip,
                                                profile: plan.profile,
                                                stats,
                                                ops: plan.ops,
                                                temp_list_sources: plan.temp_list_sources,
                                                promoted_locals: plan.promoted_locals,
                                                merge_locals: plan.merge_locals,
                                                tier: TraceTier::Trace,
                                                hits: 0,
                                                deopt_count: 0,
                                                deopts_total: 0,
                                                internal_side_exits: 0,
                                                runtime_calls: 0,
                                                runtime_trace_iters: 0,
                                                runtime_branch_taken: 0,
                                                runtime_branch_not_taken: 0,
                                                runtime_deopts: 0,
                                                runtime_temp_list_elided: 0,
                                                runtime_temp_map_elided: 0,
                                                runtime_temp_list_materialized: 0,
                                                runtime_temp_map_materialized: 0,
                                                fusion_hits: plan.fusion_hits,
                                                mutated_lists: plan.mutated_lists,
                                                version_managed_lists,
                                                mutated_maps: plan.mutated_maps,
                                                pic_map_locals: plan.pic_map_locals,
                                                adaptive_sites,
                                                adaptive_epoch_iters: 0,
                                                adaptive_epochs: 0,
                                                adaptive_patch_attempts: 0,
                                                adaptive_patch_commits: 0,
                                                adaptive_patch_reverts: 0,
                                                guard_checks: 0,
                                                guard_fails: 0,
                                                deopt_reason_counts: HashMap::new(),
                                                guard_fail_counts: HashMap::new(),
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                ip = *target;
                continue;
            }
            Instr::JumpIfFalse(target) => {
                let cond_bits = pop_bits(stack, sp)?;
                if !is_truthy(cond_bits, runtime)? {
                    finish_scalar_tail_for_exit(
                        code_id,
                        *target,
                        &mut scalar_tail_handoff,
                        locals,
                        runtime,
                        trace_cache,
                        hot_counters,
                    );
                    finish_internal_branch_for_exit(code_id, *target, &mut internal_branch_handoff);
                    ip = *target;
                    continue;
                }
            }
            Instr::JumpLocalIfFalse(idx, target) => {
                let cond_bits = locals.get(*idx).copied().unwrap_or(0.0).to_bits();
                if !is_truthy(cond_bits, runtime)? {
                    finish_scalar_tail_for_exit(
                        code_id,
                        *target,
                        &mut scalar_tail_handoff,
                        locals,
                        runtime,
                        trace_cache,
                        hot_counters,
                    );
                    finish_internal_branch_for_exit(code_id, *target, &mut internal_branch_handoff);
                    ip = *target;
                    continue;
                }
            }
            Instr::MakeList(len) => {
                if *len > *sp {
                    return Err("stack underflow in MakeList".into());
                }
                let mut data = Vec::with_capacity(*len);
                for _ in 0..*len {
                    data.push(pop(stack, sp)?);
                }
                data.reverse();
                runtime.error = 0;
                let bits = runtime.make_list(&data);
                if runtime.error != 0 {
                    return Err("JIT runtime error".into());
                }
                push_bits(stack, sp, bits);
            }
            Instr::MakeMap(keys) => {
                if keys.len() > *sp {
                    return Err("stack underflow in MakeMap".into());
                }
                let mut values = Vec::with_capacity(keys.len());
                for _ in 0..keys.len() {
                    values.push(pop_bits(stack, sp)?);
                }
                values.reverse();
                runtime.error = 0;
                let bits = runtime.make_map(keys, &values);
                if runtime.error != 0 {
                    return Err("JIT runtime error".into());
                }
                push_bits(stack, sp, bits);
            }
            Instr::LoadField(field) => {
                let target_bits = pop_bits(stack, sp)?;
                runtime.error = 0;
                let bits = runtime.map_get_str(target_bits, field);
                if runtime.error != 0 {
                    return Err("JIT runtime error".into());
                }
                push_bits(stack, sp, bits);
            }
            Instr::CallBuiltin(name, argc) if name == "__index" && *argc == 2 => {
                let idx_bits = pop_bits(stack, sp)?;
                let target_bits = pop_bits(stack, sp)?;
                runtime.error = 0;
                if vb::tag_of(target_bits) == Some(vb::TAG_LIST) {
                    let v = runtime.index(target_bits, idx_bits);
                    if runtime.error != 0 {
                        return Err("JIT runtime error".into());
                    }
                    runtime.bump_interp_index_elements(1);
                    push(stack, sp, v);
                } else if vb::tag_of(target_bits) == Some(vb::TAG_MAP) {
                    let out_bits = runtime.map_get(target_bits, idx_bits);
                    if runtime.error != 0 {
                        return Err("JIT runtime error".into());
                    }
                    push_bits(stack, sp, out_bits);
                } else {
                    return Err("invalid __index operands".into());
                }
            }
            Instr::CallBuiltin(name, argc) if name == "__setindex" && *argc == 3 => {
                let val_bits = pop_bits(stack, sp)?;
                let idx_bits = pop_bits(stack, sp)?;
                let target_bits = pop_bits(stack, sp)?;
                runtime.error = 0;
                if vb::tag_of(target_bits) == Some(vb::TAG_LIST) {
                    let out = runtime.setindex(target_bits, idx_bits, val_bits);
                    if runtime.error != 0 {
                        return Err("JIT runtime error".into());
                    }
                    push_bits(stack, sp, out);
                } else if vb::tag_of(target_bits) == Some(vb::TAG_MAP) {
                    let out = runtime.map_set(target_bits, idx_bits, val_bits);
                    if runtime.error != 0 {
                        return Err("JIT runtime error".into());
                    }
                    push_bits(stack, sp, out);
                } else {
                    return Err("invalid __setindex operands".into());
                }
            }
            Instr::CallBuiltin(name, argc) if name == "len" && *argc == 1 => {
                let target_bits = pop_bits(stack, sp)?;
                runtime.error = 0;
                let out = runtime.len(target_bits);
                if runtime.error != 0 {
                    return Err("JIT runtime error".into());
                }
                push(stack, sp, out);
            }
            Instr::CallBuiltin(name, argc) if name == "list_range" && *argc == 1 => {
                let setup_start = Instant::now();
                let len_bits = pop_bits(stack, sp)?;
                if !is_number(len_bits) {
                    return Err("list_range expects number".into());
                }
                let len_f = f64::from_bits(len_bits);
                if len_f.fract() != 0.0 || len_f < 0.0 {
                    return Err("list_range expects non-negative integer".into());
                }
                let len = len_f as usize;
                let mut data: Vec<f64> = Vec::with_capacity(len);
                for i in 0..len {
                    data.push(i as f64);
                }
                runtime.error = 0;
                let bits = runtime.make_list(&data);
                if runtime.error != 0 {
                    return Err("JIT runtime error".into());
                }
                push_bits(stack, sp, bits);
                timing.list_range_calls = timing.list_range_calls.saturating_add(1);
                timing.setup_ns = timing
                    .setup_ns
                    .saturating_add(setup_start.elapsed().as_nanos());
            }
            Instr::CallBuiltin(name, argc) if name == "to_text" && *argc == 1 => {
                let target_bits = pop_bits(stack, sp)?;
                runtime.error = 0;
                let out_bits = runtime.to_text_bits(target_bits);
                if runtime.error != 0 {
                    return Err("JIT runtime error".into());
                }
                push_bits(stack, sp, out_bits);
            }
            Instr::CallFn(name, argc) => {
                let func = prog
                    .functions
                    .get(name)
                    .ok_or_else(|| format!("Unknown function `{}`", name))?;
                let mut args = Vec::with_capacity(*argc);
                for _ in 0..*argc {
                    args.push(pop(stack, sp)?);
                }
                args.reverse();
                let mut inner_locals = vec![0.0f64; func.locals.len().max(1)];
                for (i, val) in args.iter().enumerate() {
                    if i < inner_locals.len() {
                        inner_locals[i] = *val;
                    }
                }
                let ret_bits = run_block(
                    prog,
                    &func.code,
                    &func.unsafe_flags,
                    &mut inner_locals,
                    stack,
                    sp,
                    runtime,
                    events,
                    trace_cache,
                    hot_counters,
                    telemetry_totals,
                    timing,
                    None,
                )?;
                push_bits(stack, sp, ret_bits);
            }
            Instr::EmitSay => {
                let bits = pop_bits(stack, sp)?;
                events.push(RuntimeEvent::Say(runtime.format_bits(bits)));
            }
            Instr::EmitAsk => {
                let bits = pop_bits(stack, sp)?;
                let prompt = runtime.format_bits(bits);
                events.push(RuntimeEvent::Ask {
                    prompt: prompt.clone(),
                    answer: String::new(),
                });
                let ans = query_ask(&prompt);
                events.push(RuntimeEvent::Ask {
                    prompt,
                    answer: ans,
                });
            }
            Instr::EmitFetch => {
                let bits = pop_bits(stack, sp)?;
                events.push(RuntimeEvent::Fetch {
                    target: runtime.format_bits(bits),
                });
            }
            Instr::EmitUi(kind) => {
                events.push(RuntimeEvent::Ui {
                    kind: kind.clone(),
                    props: Vec::new(),
                });
            }
            Instr::EmitText => {
                let bits = pop_bits(stack, sp)?;
                events.push(RuntimeEvent::Text(runtime.format_bits(bits)));
            }
            Instr::EmitButton => {
                let bits = pop_bits(stack, sp)?;
                events.push(RuntimeEvent::Button(runtime.format_bits(bits)));
            }
            Instr::EmitLog => {
                let bits = pop_bits(stack, sp)?;
                events.push(RuntimeEvent::Log(runtime.format_bits(bits)));
            }
            Instr::Pop => {
                let _ = pop_bits(stack, sp)?;
            }
            Instr::Return => {
                discard_scalar_tail_handoff(scalar_tail_handoff.take(), trace_cache, hot_counters);
                discard_internal_branch_handoff(
                    internal_branch_handoff.take(),
                    trace_cache,
                    hot_counters,
                );
                let bits = if *sp == 0 {
                    vb::tag_null()
                } else {
                    pop_bits(stack, sp)?
                };
                return Ok(bits);
            }
            _ => return Err("unsupported instruction in typed VM".into()),
        }
        ip += 1;
    }
    discard_scalar_tail_handoff(scalar_tail_handoff.take(), trace_cache, hot_counters);
    discard_internal_branch_handoff(internal_branch_handoff.take(), trace_cache, hot_counters);
    let bits = if *sp == 0 {
        vb::tag_null()
    } else {
        pop_bits(stack, sp)?
    };
    Ok(bits)
}

fn push(stack: &mut [f64], sp: &mut usize, v: f64) {
    if *sp < stack.len() {
        stack[*sp] = v;
        *sp += 1;
    }
}

fn push_bits(stack: &mut [f64], sp: &mut usize, bits: u64) {
    push(stack, sp, f64::from_bits(bits));
}

fn pop(stack: &mut [f64], sp: &mut usize) -> VmResult<f64> {
    if *sp == 0 {
        return Err("stack underflow".into());
    }
    *sp -= 1;
    Ok(stack[*sp])
}

fn pop_bits(stack: &mut [f64], sp: &mut usize) -> VmResult<u64> {
    Ok(pop(stack, sp)?.to_bits())
}

fn is_number(bits: u64) -> bool {
    !vb::is_tagged(bits)
}

fn bin_num<F>(stack: &mut [f64], sp: &mut usize, f: F) -> VmResult<()>
where
    F: Fn(f64, f64) -> f64,
{
    let rhs_bits = pop_bits(stack, sp)?;
    let lhs_bits = pop_bits(stack, sp)?;
    if !is_number(lhs_bits) || !is_number(rhs_bits) {
        return Err("Type error in numeric op".into());
    }
    let out = f(f64::from_bits(lhs_bits), f64::from_bits(rhs_bits));
    push(stack, sp, out);
    Ok(())
}

fn cmp_num<F>(stack: &mut [f64], sp: &mut usize, f: F) -> VmResult<()>
where
    F: Fn(f64, f64) -> bool,
{
    let rhs_bits = pop_bits(stack, sp)?;
    let lhs_bits = pop_bits(stack, sp)?;
    if !is_number(lhs_bits) || !is_number(rhs_bits) {
        return Err("Type error in numeric comparison".into());
    }
    let out = if f(f64::from_bits(lhs_bits), f64::from_bits(rhs_bits)) {
        1.0
    } else {
        0.0
    };
    push(stack, sp, out);
    Ok(())
}

fn cmp_eq(
    stack: &mut [f64],
    sp: &mut usize,
    runtime: &jit::JitRuntime,
    is_eq: bool,
) -> VmResult<()> {
    let rhs_bits = pop_bits(stack, sp)?;
    let lhs_bits = pop_bits(stack, sp)?;
    let out = if is_number(lhs_bits) && is_number(rhs_bits) {
        let a = f64::from_bits(lhs_bits);
        let b = f64::from_bits(rhs_bits);
        (a == b) == is_eq
    } else if vb::is_text(lhs_bits) && vb::is_text(rhs_bits) {
        let a = runtime.format_bits(lhs_bits);
        let b = runtime.format_bits(rhs_bits);
        (a == b) == is_eq
    } else {
        return Err("Type error in equality".into());
    };
    push(stack, sp, if out { 1.0 } else { 0.0 });
    Ok(())
}

fn bits_to_bool(bits: u64) -> bool {
    if is_number(bits) {
        return f64::from_bits(bits) != 0.0;
    }
    false
}

fn is_truthy(bits: u64, runtime: &mut jit::JitRuntime) -> VmResult<bool> {
    if is_number(bits) {
        return Ok(f64::from_bits(bits) != 0.0);
    }
    match vb::tag_of(bits) {
        Some(tag) if tag == vb::TAG_NULL => Ok(false),
        Some(tag) if vb::is_text_tag(tag) => Ok(!runtime.format_bits(bits).is_empty()),
        Some(tag) if tag == vb::TAG_LIST => Ok(runtime.len(bits) > 0.0),
        Some(tag) if tag == vb::TAG_MAP => Ok(runtime.len(bits) > 0.0),
        _ => Ok(false),
    }
}

fn find_loop_exit(code: &[Instr], start: usize, end: usize) -> Option<usize> {
    let mut exit: Option<usize> = None;
    for instr in &code[start..=end] {
        if let Instr::JumpIfFalse(t) | Instr::JumpLocalIfFalse(_, t) = instr {
            if *t < start || *t > end {
                if let Some(prev) = exit {
                    if prev != *t {
                        return None;
                    }
                } else {
                    exit = Some(*t);
                }
            }
        }
    }
    exit
}

fn find_unsupported_internal_backedge(
    code: &[Instr],
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    for (off, instr) in code[start..=end].iter().enumerate() {
        if let Instr::Jump(target) = instr {
            let jump_ip = start + off;
            if *target >= start && *target <= end && *target != start && *target <= jump_ip {
                return Some((jump_ip, *target));
            }
        }
    }
    None
}

fn elem_tag_from_ty(ty: &TraceTy) -> Option<ElemTag> {
    match ty {
        TraceTy::Num => Some(ElemTag::Num),
        TraceTy::Text => Some(ElemTag::Tagged(vb::TAG_TEXT)),
        TraceTy::Null => Some(ElemTag::Tagged(vb::TAG_NULL)),
        TraceTy::List(_) => Some(ElemTag::Tagged(vb::TAG_LIST)),
        TraceTy::Map(_) => Some(ElemTag::Tagged(vb::TAG_MAP)),
        TraceTy::Unknown => None,
    }
}

fn elem_tag_from_option(tag: Option<u64>) -> ElemTag {
    match tag {
        Some(t) => ElemTag::Tagged(t),
        None => ElemTag::Num,
    }
}

fn ty_from_elem_tag(tag: &ElemTag) -> TraceTy {
    match tag {
        ElemTag::Num => TraceTy::Num,
        ElemTag::Tagged(t) if vb::is_text_tag(*t) => TraceTy::Text,
        ElemTag::Tagged(t) if *t == vb::TAG_NULL => TraceTy::Null,
        _ => TraceTy::Unknown,
    }
}

fn ty_from_bits(bits: u64, runtime: &jit::JitRuntime) -> TraceTy {
    if !vb::is_tagged(bits) {
        return TraceTy::Num;
    }
    match vb::tag_of(bits) {
        Some(tag) if vb::is_text_tag(tag) => TraceTy::Text,
        Some(tag) if tag == vb::TAG_NULL => TraceTy::Null,
        Some(tag) if tag == vb::TAG_LIST => runtime
            .list_uniform_tag(bits)
            .map(elem_tag_from_option)
            .map(TraceTy::List)
            .unwrap_or(TraceTy::Unknown),
        Some(tag) if tag == vb::TAG_MAP => runtime
            .map_uniform_value_tag(bits)
            .map(elem_tag_from_option)
            .map(TraceTy::Map)
            .unwrap_or(TraceTy::Unknown),
        _ => TraceTy::Unknown,
    }
}

fn fold_trace_constants(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    fn const_num(op: &jit::TraceOp) -> Option<f64> {
        match op {
            jit::TraceOp::ConstNum(n) => Some(*n),
            jit::TraceOp::ConstBool(b) => Some(if *b { 1.0 } else { 0.0 }),
            _ => None,
        }
    }

    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    for op in ops {
        let folded = match op {
            jit::TraceOp::AddNum
            | jit::TraceOp::SubNum
            | jit::TraceOp::MulNum
            | jit::TraceOp::DivNum
            | jit::TraceOp::EqNum
            | jit::TraceOp::NeNum
            | jit::TraceOp::LtNum
            | jit::TraceOp::LeNum
            | jit::TraceOp::GtNum
            | jit::TraceOp::GeNum => {
                if out.len() >= 2 {
                    let b = const_num(out.last().unwrap());
                    let a = const_num(&out[out.len() - 2]);
                    if let (Some(lhs), Some(rhs)) = (a, b) {
                        out.pop();
                        out.pop();
                        match op {
                            jit::TraceOp::AddNum => out.push(jit::TraceOp::ConstNum(lhs + rhs)),
                            jit::TraceOp::SubNum => out.push(jit::TraceOp::ConstNum(lhs - rhs)),
                            jit::TraceOp::MulNum => out.push(jit::TraceOp::ConstNum(lhs * rhs)),
                            jit::TraceOp::DivNum => out.push(jit::TraceOp::ConstNum(lhs / rhs)),
                            jit::TraceOp::EqNum => out.push(jit::TraceOp::ConstBool(lhs == rhs)),
                            jit::TraceOp::NeNum => out.push(jit::TraceOp::ConstBool(lhs != rhs)),
                            jit::TraceOp::LtNum => out.push(jit::TraceOp::ConstBool(lhs < rhs)),
                            jit::TraceOp::LeNum => out.push(jit::TraceOp::ConstBool(lhs <= rhs)),
                            jit::TraceOp::GtNum => out.push(jit::TraceOp::ConstBool(lhs > rhs)),
                            jit::TraceOp::GeNum => out.push(jit::TraceOp::ConstBool(lhs >= rhs)),
                            _ => {}
                        }
                        continue;
                    }
                }
                false
            }
            _ => false,
        };
        if !folded {
            out.push(op.clone());
        }
    }
    out
}

fn trace_stack_delta(op: &jit::TraceOp) -> i32 {
    match op {
        jit::TraceOp::ConstNum(_)
        | jit::TraceOp::ConstBool(_)
        | jit::TraceOp::ConstText(_)
        | jit::TraceOp::PushNull
        | jit::TraceOp::Dup
        | jit::TraceOp::LoadLocal(_)
        | jit::TraceOp::LenListLocal(_)
        | jit::TraceOp::IndexListNumLocal(_, _)
        | jit::TraceOp::IndexListNumLocalPtr(_, _, _)
        | jit::TraceOp::IndexListNumLocalPtrOff(_, _, _, _) => 1,
        jit::TraceOp::StoreLocal(_) => -1,
        jit::TraceOp::AddLocalConst(_, _) => 0,
        jit::TraceOp::InitLocalConst(_, _) => 0,
        jit::TraceOp::AddLocalFromStack(_) => -1,
        jit::TraceOp::AddNum
        | jit::TraceOp::SubNum
        | jit::TraceOp::MulNum
        | jit::TraceOp::DivNum
        | jit::TraceOp::EqNum
        | jit::TraceOp::NeNum
        | jit::TraceOp::LtNum
        | jit::TraceOp::LeNum
        | jit::TraceOp::GtNum
        | jit::TraceOp::GeNum => -1,
        jit::TraceOp::Label(_) | jit::TraceOp::JumpTo(_) => 0,
        jit::TraceOp::BranchFalse(_) => -1,
        jit::TraceOp::JumpStart => 0,
        jit::TraceOp::GuardFalse | jit::TraceOp::GuardFalseDeopt(_) => -1,
        jit::TraceOp::GuardIndexCmpConst(_, _, _) => 0,
        jit::TraceOp::GuardIndexRangeConst(_, _, _) => 0,
        jit::TraceOp::GuardListBounds(_, _) => 0,
        jit::TraceOp::GuardIndexNonNeg(_) => 0,
        jit::TraceOp::GuardListNoAliasSameLen(_, _) => 0,
        jit::TraceOp::MakeList(len) => 1 - (*len as i32),
        jit::TraceOp::MakeListTemp(len) => 1 - (*len as i32),
        jit::TraceOp::MakeMap(keys) => 1 - (keys.len() as i32),
        jit::TraceOp::MakeMapTemp(keys) => 1 - (keys.len() as i32),
        jit::TraceOp::LoadField(_)
        | jit::TraceOp::MapGetSlot(_)
        | jit::TraceOp::MapGetSlotPtr(_)
        | jit::TraceOp::MapGetSlotNoVerGuard(_, _, _, _, _)
        | jit::TraceOp::MapGetSlotPtrNoVer(_, _, _, _, _) => 0,
        jit::TraceOp::MapGetSmallKeyNoVer(_, _, _, _, _) => -1,
        jit::TraceOp::MapGetTextKeyNoVer(_, _, _, _, _) => -1,
        jit::TraceOp::MapGetTextKeyConstNoVer(_, _, _, _, _, _, _, _, _) => -1,
        jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(_, _, _, _, _, _, _) => -1,
        jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(_, _, _, _, _) => -1,
        jit::TraceOp::MapGetTextKeyConstSlotPtrStableAddLocalNoVer(_, _, _, _, _, _) => -2,
        jit::TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(_, _, _, _, _, _, _, _, _, _) => -1,
        jit::TraceOp::IndexListNum => -1,
        jit::TraceOp::LenList => 0,
        jit::TraceOp::SetIndexListNum
        | jit::TraceOp::SetIndexListNumLocalPtr(_, _, _)
        | jit::TraceOp::SetIndexListNumLocalNoVer(_, _)
        | jit::TraceOp::SetIndexListNumLocalPtrNoVer(_, _, _)
        | jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(_, _, _, _)
        | jit::TraceOp::MapSetSlotPtrNoVer(_, _)
        | jit::TraceOp::MapSetSlotPtrNoVerGuard(_, _, _, _, _)
        | jit::TraceOp::MapSetSlotNoVer(_, _)
        | jit::TraceOp::MapSetSlotNoVerGuard(_, _, _, _, _)
        | jit::TraceOp::MapSetSmallKeyNoVer(_, _, _, _, _)
        | jit::TraceOp::MapSetTextKeyNoVer(_, _, _, _, _)
        | jit::TraceOp::MapSetTextKeyConstNoVer(_, _, _, _, _, _, _, _, _)
        | jit::TraceOp::MapSetTextKeyConstSlotPtrNoVer(_, _, _, _, _, _, _)
        | jit::TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(_, _, _, _, _, _, _, _, _, _) => -2,
        jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(_, _, _)
        | jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(_, _, _, _) => 0,
        jit::TraceOp::ToText => 0,
        jit::TraceOp::Pop => -1,
        jit::TraceOp::Return => -1,
        jit::TraceOp::BumpListVersionLocal(_) | jit::TraceOp::BumpMapVersionLocal(_) => 0,
    }
}

fn trace_live_values(ops: &[jit::TraceOp]) -> usize {
    let mut depth: i32 = 0;
    let mut max_depth: i32 = 0;
    for op in ops {
        depth += trace_stack_delta(op);
        if depth > max_depth {
            max_depth = depth;
        }
    }
    max_depth.max(0) as usize
}

fn build_super_ops(ops: &[jit::TraceOp], iters: usize) -> Option<Vec<jit::TraceOp>> {
    if iters <= 1 {
        return None;
    }
    let jump_pos = ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))?;
    if jump_pos + 1 != ops.len() {
        return None;
    }
    if ops[..jump_pos]
        .iter()
        .any(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        return None;
    }
    let mut prelude_len = 0usize;
    while prelude_len < jump_pos {
        match ops[prelude_len] {
            jit::TraceOp::GuardListBounds(_, _)
            | jit::TraceOp::GuardIndexNonNeg(_)
            | jit::TraceOp::GuardListNoAliasSameLen(_, _)
            | jit::TraceOp::InitLocalConst(_, _) => {
                prelude_len += 1;
            }
            _ => break,
        }
    }
    let body = &ops[prelude_len..jump_pos];
    let mut out: Vec<jit::TraceOp> = Vec::new();
    out.extend(ops[..prelude_len].iter().cloned());
    for _ in 0..iters {
        out.extend(body.iter().cloned());
    }
    out.push(jit::TraceOp::JumpStart);
    Some(out)
}

fn optimize_trace_ops_pass(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    let mut i = 0usize;
    while i < ops.len() {
        if i + 4 < ops.len() {
            if let (
                jit::TraceOp::LoadLocal(a),
                jit::TraceOp::ConstNum(c),
                jit::TraceOp::AddNum,
                jit::TraceOp::Dup,
                jit::TraceOp::StoreLocal(b),
            ) = (&ops[i], &ops[i + 1], &ops[i + 2], &ops[i + 3], &ops[i + 4])
            {
                if a == b && *c == 0.0 {
                    // StoreLocalKeep after `x + 0` leaves the unchanged value on
                    // the stack. The local already contains that same value.
                    out.push(jit::TraceOp::LoadLocal(*a));
                    i += 5;
                    continue;
                }
            }
        }
        if i + 3 < ops.len() {
            match (&ops[i], &ops[i + 1], &ops[i + 2], &ops[i + 3]) {
                (
                    jit::TraceOp::LoadLocal(a),
                    jit::TraceOp::LoadLocal(b),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::StoreLocal(c),
                ) if a == c => {
                    out.push(jit::TraceOp::LoadLocal(*b));
                    out.push(jit::TraceOp::AddLocalFromStack(*a));
                    i += 4;
                    continue;
                }
                (
                    jit::TraceOp::LoadLocal(a),
                    jit::TraceOp::IndexListNumLocal(list, idx),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::StoreLocal(c),
                ) if a == c => {
                    out.push(jit::TraceOp::IndexListNumLocal(*list, *idx));
                    out.push(jit::TraceOp::AddLocalFromStack(*a));
                    i += 4;
                    continue;
                }
                (
                    jit::TraceOp::LoadLocal(a),
                    jit::TraceOp::IndexListNumLocalPtr(list, idx, data),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::StoreLocal(c),
                ) if a == c => {
                    out.push(jit::TraceOp::IndexListNumLocalPtr(*list, *idx, *data));
                    out.push(jit::TraceOp::AddLocalFromStack(*a));
                    i += 4;
                    continue;
                }
                (
                    jit::TraceOp::LoadLocal(a),
                    jit::TraceOp::IndexListNumLocalPtrOff(list, idx, data, offset),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::StoreLocal(c),
                ) if a == c => {
                    out.push(jit::TraceOp::IndexListNumLocalPtrOff(
                        *list, *idx, *data, *offset,
                    ));
                    out.push(jit::TraceOp::AddLocalFromStack(*a));
                    i += 4;
                    continue;
                }
                (
                    jit::TraceOp::LoadLocal(a),
                    jit::TraceOp::ConstNum(c),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::StoreLocal(b),
                ) if a == b => {
                    if *c != 0.0 {
                        out.push(jit::TraceOp::AddLocalConst(*a, *c));
                    }
                    i += 4;
                    continue;
                }
                (
                    jit::TraceOp::LoadLocal(a),
                    jit::TraceOp::ConstNum(c),
                    jit::TraceOp::SubNum,
                    jit::TraceOp::StoreLocal(b),
                ) if a == b => {
                    if *c != 0.0 {
                        out.push(jit::TraceOp::AddLocalConst(*a, -*c));
                    }
                    i += 4;
                    continue;
                }
                _ => {}
            }
        }
        if i + 2 < ops.len() {
            if let (
                jit::TraceOp::LoadLocal(list_idx),
                jit::TraceOp::LoadLocal(idx_idx),
                jit::TraceOp::IndexListNum,
            ) = (&ops[i], &ops[i + 1], &ops[i + 2])
            {
                out.push(jit::TraceOp::IndexListNumLocal(*list_idx, *idx_idx));
                i += 3;
                continue;
            }
        }
        if i + 1 < ops.len() {
            if let (jit::TraceOp::LoadLocal(list_idx), jit::TraceOp::LenList) =
                (&ops[i], &ops[i + 1])
            {
                out.push(jit::TraceOp::LenListLocal(*list_idx));
                i += 2;
                continue;
            }
        }
        out.push(ops[i].clone());
        i += 1;
    }
    out
}

fn optimize_trace_ops(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    let mut current = ops.to_vec();
    loop {
        let optimized = optimize_trace_ops_pass(&current);
        if optimized.len() == current.len() {
            return optimized;
        }
        current = optimized;
    }
}

fn specialize_list_data_ptr(
    ops: &[jit::TraceOp],
    locals: &[f64],
    runtime: &jit::JitRuntime,
) -> Vec<jit::TraceOp> {
    let mut out = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            jit::TraceOp::IndexListNumLocal(list_idx, idx_idx) => {
                let mut specialized = false;
                if let Some(bits) = locals.get(*list_idx).copied().map(|v| v.to_bits()) {
                    if let Some((_ptr, _len, _cap, _version, data)) = runtime.list_meta(bits) {
                        if data != 0 {
                            out.push(jit::TraceOp::IndexListNumLocalPtr(
                                *list_idx, *idx_idx, data,
                            ));
                            specialized = true;
                        }
                    }
                }
                if !specialized {
                    out.push(op.clone());
                }
            }
            jit::TraceOp::SetIndexListNumLocalNoVer(list_idx, idx_idx) => {
                let mut specialized = false;
                if let Some(bits) = locals.get(*list_idx).copied().map(|v| v.to_bits()) {
                    if let Some((_ptr, _len, _cap, _version, data)) = runtime.list_meta(bits) {
                        if data != 0 {
                            out.push(jit::TraceOp::SetIndexListNumLocalPtrNoVer(
                                *list_idx, *idx_idx, data,
                            ));
                            specialized = true;
                        }
                    }
                }
                if !specialized {
                    out.push(op.clone());
                }
            }
            _ => out.push(op.clone()),
        }
    }
    out
}

fn rewrite_lenlist_const(
    ops: &[jit::TraceOp],
    locals: &[f64],
    runtime: &jit::JitRuntime,
) -> Vec<jit::TraceOp> {
    let mut len_map: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (idx, value) in locals.iter().enumerate() {
        let bits = value.to_bits();
        if vb::tag_of(bits) != Some(vb::TAG_LIST) {
            continue;
        }
        if let Some((_ptr, len, _cap, _version, _data)) = runtime.list_meta(bits) {
            len_map.insert(idx, len);
        }
    }

    if len_map.is_empty() {
        return ops.to_vec();
    }

    let mut out = Vec::with_capacity(ops.len());
    let mut i = 0;
    while i < ops.len() {
        match &ops[i] {
            jit::TraceOp::LenListLocal(idx) => {
                if let Some(len) = len_map.get(idx) {
                    out.push(jit::TraceOp::ConstNum(*len as f64));
                    i += 1;
                    continue;
                }
            }
            jit::TraceOp::LoadLocal(idx)
                if i + 1 < ops.len() && matches!(ops[i + 1], jit::TraceOp::LenList) =>
            {
                if let Some(len) = len_map.get(idx) {
                    out.push(jit::TraceOp::ConstNum(*len as f64));
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        out.push(ops[i].clone());
        i += 1;
    }
    out
}

fn unroll_list_update_x4(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    const UNROLL: usize = 4;
    let jump_pos = match ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        Some(pos) if pos + 1 == ops.len() => pos,
        _ => return ops.to_vec(),
    };

    let mut guard_idx: Option<usize> = None;
    let mut idx_local: Option<usize> = None;
    let mut len_const: Option<f64> = None;
    for i in 3..=jump_pos {
        if !matches!(ops[i], jit::TraceOp::GuardFalse) {
            continue;
        }
        if let (jit::TraceOp::LoadLocal(idx), jit::TraceOp::ConstNum(len), cmp) =
            (&ops[i - 3], &ops[i - 2], &ops[i - 1])
        {
            if matches!(cmp, jit::TraceOp::LtNum | jit::TraceOp::LeNum) {
                guard_idx = Some(i);
                idx_local = Some(*idx);
                len_const = Some(*len);
                break;
            }
        }
    }

    let guard_idx = match guard_idx {
        Some(i) => i,
        None => return ops.to_vec(),
    };
    let idx_local = match idx_local {
        Some(i) => i,
        None => return ops.to_vec(),
    };
    let len_const = match len_const {
        Some(l) => l,
        None => return ops.to_vec(),
    };
    if len_const < UNROLL as f64 {
        return ops.to_vec();
    }
    if len_const.fract() != 0.0 {
        return ops.to_vec();
    }
    let len_adjusted = len_const - (UNROLL as f64 - 1.0);

    let body = &ops[guard_idx + 1..jump_pos];
    if body.is_empty() {
        return ops.to_vec();
    }

    let mut list_idx: Option<usize> = None;
    let mut data_ptr: Option<u64> = None;
    let mut bump_list_idx: Option<usize> = None;
    let mut bump_count: usize = 0;
    let mut incr_count: usize = 0;
    let mut mutation_count: usize = 0;

    for op in body {
        match op {
            jit::TraceOp::IndexListNumLocalPtr(list, idx, data) => {
                if *idx != idx_local {
                    return ops.to_vec();
                }
                if let Some(prev) = list_idx {
                    if prev != *list {
                        return ops.to_vec();
                    }
                }
                list_idx = Some(*list);
                if let Some(prev) = data_ptr {
                    if prev != *data {
                        return ops.to_vec();
                    }
                }
                data_ptr = Some(*data);
            }
            jit::TraceOp::SetIndexListNumLocalPtrNoVer(list, idx, data) => {
                mutation_count += 1;
                if *idx != idx_local {
                    return ops.to_vec();
                }
                if let Some(prev) = list_idx {
                    if prev != *list {
                        return ops.to_vec();
                    }
                }
                list_idx = Some(*list);
                if let Some(prev) = data_ptr {
                    if prev != *data {
                        return ops.to_vec();
                    }
                }
                data_ptr = Some(*data);
            }
            jit::TraceOp::IndexListNumLocal(_, _)
            | jit::TraceOp::IndexListNumLocalPtrOff(_, _, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtr(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalNoVer(_, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(_, _, _, _) => {
                return ops.to_vec();
            }
            jit::TraceOp::AddLocalConst(idx, c) => {
                if *idx == idx_local && (*c - 1.0).abs() < f64::EPSILON {
                    incr_count += 1;
                }
            }
            jit::TraceOp::BumpListVersionLocal(list) => {
                bump_count += 1;
                bump_list_idx = Some(*list);
            }
            jit::TraceOp::ConstNum(_)
            | jit::TraceOp::Dup
            | jit::TraceOp::LoadLocal(_)
            | jit::TraceOp::StoreLocal(_)
            | jit::TraceOp::AddLocalFromStack(_)
            | jit::TraceOp::AddNum
            | jit::TraceOp::SubNum
            | jit::TraceOp::MulNum
            | jit::TraceOp::DivNum => {}
            _ => {
                return ops.to_vec();
            }
        }
    }

    if incr_count != 1 || list_idx.is_none() || data_ptr.is_none() {
        return ops.to_vec();
    }
    if bump_count > 1 {
        return ops.to_vec();
    }
    if let Some(list) = bump_list_idx {
        if Some(list) != list_idx {
            return ops.to_vec();
        }
    }
    if mutation_count > 0 {
        if mutation_count != 1 || body.len() != 12 {
            return ops.to_vec();
        }
        match (
            &body[0], &body[1], &body[2], &body[3], &body[4], &body[5], &body[6], &body[7],
            &body[8], &body[9], &body[10], &body[11],
        ) {
            (
                jit::TraceOp::IndexListNumLocalPtr(read_list, read_idx, read_data),
                jit::TraceOp::StoreLocal(value_local),
                jit::TraceOp::LoadLocal(value_for_sum),
                jit::TraceOp::AddLocalFromStack(_),
                jit::TraceOp::LoadLocal(write_list),
                jit::TraceOp::LoadLocal(write_idx),
                jit::TraceOp::LoadLocal(value_for_write),
                jit::TraceOp::ConstNum(_),
                jit::TraceOp::AddNum,
                jit::TraceOp::SetIndexListNumLocalPtrNoVer(set_list, set_idx, set_data),
                jit::TraceOp::StoreLocal(_),
                jit::TraceOp::AddLocalConst(incr_idx, incr),
            ) if read_list == write_list
                && read_list == set_list
                && *read_list == list_idx.unwrap()
                && read_idx == write_idx
                && read_idx == set_idx
                && *read_idx == idx_local
                && read_data == set_data
                && *read_data == data_ptr.unwrap()
                && value_local == value_for_sum
                && value_local == value_for_write
                && *incr_idx == idx_local
                && (*incr - 1.0).abs() < f64::EPSILON => {}
            _ => return ops.to_vec(),
        }
    } else if body
        .iter()
        .any(|op| matches!(op, jit::TraceOp::LoadLocal(idx) if *idx == idx_local))
    {
        // Read-only lanes must derive the induction value through the offset-aware
        // list op. A raw load of the induction local would reuse lane 0 for all lanes.
        return ops.to_vec();
    }

    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len() * UNROLL);
    for (i, op) in ops.iter().enumerate().take(guard_idx + 1) {
        if i == guard_idx.saturating_sub(2) && matches!(op, jit::TraceOp::ConstNum(_)) {
            out.push(jit::TraceOp::ConstNum(len_adjusted));
            continue;
        }
        out.push(op.clone());
    }

    let mut body_core: Vec<jit::TraceOp> = Vec::with_capacity(body.len());
    for op in body {
        match op {
            jit::TraceOp::AddLocalConst(idx, c)
                if *idx == idx_local && (*c - 1.0).abs() < f64::EPSILON =>
            {
                continue;
            }
            jit::TraceOp::BumpListVersionLocal(_) => {
                continue;
            }
            _ => body_core.push(op.clone()),
        }
    }

    let list_idx = list_idx.unwrap();
    let data_ptr = data_ptr.unwrap();
    for offset in 0..UNROLL {
        for op in &body_core {
            match op {
                jit::TraceOp::IndexListNumLocalPtr(_, idx, _) if *idx == idx_local => {
                    out.push(jit::TraceOp::IndexListNumLocalPtrOff(
                        list_idx,
                        idx_local,
                        data_ptr,
                        offset as i32,
                    ));
                }
                jit::TraceOp::SetIndexListNumLocalPtrNoVer(_, idx, _) if *idx == idx_local => {
                    out.push(jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(
                        list_idx,
                        idx_local,
                        data_ptr,
                        offset as i32,
                    ));
                }
                _ => out.push(op.clone()),
            }
        }
    }

    out.push(jit::TraceOp::AddLocalConst(idx_local, UNROLL as f64));
    if let Some(list) = bump_list_idx.or_else(|| (mutation_count > 0).then_some(list_idx)) {
        out.push(jit::TraceOp::BumpListVersionLocal(list));
    }
    out.push(jit::TraceOp::JumpStart);
    out
}

fn unroll_dot_product_x4(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    const UNROLL: usize = 4;
    let jump_pos = match ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        Some(pos) if pos + 1 == ops.len() => pos,
        _ => return ops.to_vec(),
    };

    let mut guard_idx: Option<usize> = None;
    let mut idx_local: Option<usize> = None;
    for i in 3..=jump_pos {
        if !matches!(ops[i], jit::TraceOp::GuardFalse) {
            continue;
        }
        if let (jit::TraceOp::LoadLocal(idx), jit::TraceOp::ConstNum(_), cmp) =
            (&ops[i - 3], &ops[i - 2], &ops[i - 1])
        {
            if matches!(cmp, jit::TraceOp::LtNum | jit::TraceOp::LeNum) {
                guard_idx = Some(i);
                idx_local = Some(*idx);
                break;
            }
        }
    }
    let guard_idx = match guard_idx {
        Some(i) => i,
        None => return ops.to_vec(),
    };
    let idx_local = match idx_local {
        Some(i) => i,
        None => return ops.to_vec(),
    };

    let body_start = guard_idx + 1;
    let body_end = jump_pos;
    if body_start >= body_end {
        return ops.to_vec();
    }

    let body = &ops[body_start..body_end];
    if body.len() != 11 {
        return ops.to_vec();
    }

    let list_a = match &body[0] {
        jit::TraceOp::IndexListNumLocalPtr(list, idx, data) if *idx == idx_local => (*list, *data),
        _ => return ops.to_vec(),
    };
    let a_local = match &body[1] {
        jit::TraceOp::StoreLocal(v) => *v,
        _ => return ops.to_vec(),
    };
    let list_b = match &body[2] {
        jit::TraceOp::IndexListNumLocalPtr(list, idx, data) if *idx == idx_local => (*list, *data),
        _ => return ops.to_vec(),
    };
    let b_local = match &body[3] {
        jit::TraceOp::StoreLocal(v) => *v,
        _ => return ops.to_vec(),
    };
    let sum_local = match &body[4] {
        jit::TraceOp::LoadLocal(v) => *v,
        _ => return ops.to_vec(),
    };
    if !matches!(&body[5], jit::TraceOp::LoadLocal(v) if *v == a_local) {
        return ops.to_vec();
    }
    if !matches!(&body[6], jit::TraceOp::LoadLocal(v) if *v == b_local) {
        return ops.to_vec();
    }
    if !matches!(&body[7], jit::TraceOp::MulNum) {
        return ops.to_vec();
    }
    if !matches!(&body[8], jit::TraceOp::AddNum) {
        return ops.to_vec();
    }
    if !matches!(&body[9], jit::TraceOp::StoreLocal(v) if *v == sum_local) {
        return ops.to_vec();
    }
    if !matches!(
        &body[10],
        jit::TraceOp::AddLocalConst(v, c) if *v == idx_local && (*c - 1.0).abs() < f64::EPSILON
    ) {
        return ops.to_vec();
    }

    if a_local == b_local || a_local == sum_local || b_local == sum_local {
        return ops.to_vec();
    }

    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len() * UNROLL);
    for (i, op) in ops.iter().enumerate().take(guard_idx + 1) {
        if i == guard_idx.saturating_sub(2) {
            if let jit::TraceOp::ConstNum(n) = op {
                let len_adjusted = n - (UNROLL as f64 - 1.0);
                out.push(jit::TraceOp::ConstNum(len_adjusted));
                continue;
            }
        }
        out.push(op.clone());
    }

    let (list_a_idx, data_a) = list_a;
    let (list_b_idx, data_b) = list_b;
    for offset in 0..UNROLL {
        out.push(jit::TraceOp::IndexListNumLocalPtrOff(
            list_a_idx,
            idx_local,
            data_a,
            offset as i32,
        ));
        out.push(jit::TraceOp::StoreLocal(a_local));
        out.push(jit::TraceOp::IndexListNumLocalPtrOff(
            list_b_idx,
            idx_local,
            data_b,
            offset as i32,
        ));
        out.push(jit::TraceOp::StoreLocal(b_local));
        out.push(jit::TraceOp::LoadLocal(sum_local));
        out.push(jit::TraceOp::LoadLocal(a_local));
        out.push(jit::TraceOp::LoadLocal(b_local));
        out.push(jit::TraceOp::MulNum);
        out.push(jit::TraceOp::AddNum);
        out.push(jit::TraceOp::StoreLocal(sum_local));
    }

    out.push(jit::TraceOp::AddLocalConst(idx_local, UNROLL as f64));
    out.push(jit::TraceOp::JumpStart);
    out
}

fn rewrite_setindex_fast(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    let mut i = 0usize;
    while i < ops.len() {
        if i + 5 < ops.len() {
            match (
                &ops[i],
                &ops[i + 1],
                &ops[i + 2],
                &ops[i + 3],
                &ops[i + 4],
                &ops[i + 5],
            ) {
                (
                    jit::TraceOp::LoadLocal(list_idx),
                    jit::TraceOp::LoadLocal(idx_idx),
                    jit::TraceOp::LoadLocal(val_idx),
                    jit::TraceOp::ConstNum(c),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::SetIndexListNumLocalPtrNoVer(list2, idx2, data),
                ) if list_idx == list2 && idx_idx == idx2 => {
                    out.push(jit::TraceOp::LoadLocal(*val_idx));
                    out.push(jit::TraceOp::ConstNum(*c));
                    out.push(jit::TraceOp::AddNum);
                    out.push(jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(
                        *list2, *idx2, *data,
                    ));
                    i += 6;
                    continue;
                }
                (
                    jit::TraceOp::LoadLocal(list_idx),
                    jit::TraceOp::LoadLocal(idx_idx),
                    jit::TraceOp::LoadLocal(val_idx),
                    jit::TraceOp::ConstNum(c),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(list2, idx2, data, offset),
                ) if list_idx == list2 && idx_idx == idx2 => {
                    out.push(jit::TraceOp::LoadLocal(*val_idx));
                    out.push(jit::TraceOp::ConstNum(*c));
                    out.push(jit::TraceOp::AddNum);
                    out.push(jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(
                        *list2, *idx2, *data, *offset,
                    ));
                    i += 6;
                    continue;
                }
                _ => {}
            }
        }
        out.push(ops[i].clone());
        i += 1;
    }
    out
}

fn can_hoist_const_slot_ptr_map_shape_guard(
    map_idx: usize,
    mutated_maps: &std::collections::BTreeSet<usize>,
    locals: &[f64],
) -> bool {
    if mutated_maps.contains(&map_idx) {
        return false;
    }
    let Some(map_bits) = locals.get(map_idx).copied().map(|v| v.to_bits()) else {
        return false;
    };
    if vb::tag_of(map_bits) != Some(vb::TAG_MAP) {
        return false;
    }
    // Do not hoist when an alias local mutates the same backing map within the trace.
    for other in mutated_maps {
        if *other == map_idx {
            continue;
        }
        if locals.get(*other).copied().map(|v| v.to_bits()) == Some(map_bits) {
            return false;
        }
    }
    true
}

fn rewrite_map_const_slot_ptr_stable(
    ops: &[jit::TraceOp],
    mutated_maps: &std::collections::BTreeSet<usize>,
    locals: &[f64],
) -> (Vec<jit::TraceOp>, std::collections::BTreeSet<usize>, u64) {
    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    let mut stable_maps: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut rewrite_count: u64 = 0;
    for op in ops {
        match op {
            jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(
                map_idx,
                key_idx,
                key_bits,
                deopt_ip,
                _cap,
                _slots,
                value_ptr,
            ) if can_hoist_const_slot_ptr_map_shape_guard(*map_idx, mutated_maps, locals) => {
                out.push(jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                    *map_idx, *key_idx, *key_bits, *deopt_ip, *value_ptr,
                ));
                stable_maps.insert(*map_idx);
                rewrite_count = rewrite_count.saturating_add(1);
            }
            _ => out.push(op.clone()),
        }
    }
    (out, stable_maps, rewrite_count)
}

fn rewrite_map_stable_add_local(ops: &[jit::TraceOp]) -> (Vec<jit::TraceOp>, u64) {
    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    let mut i = 0usize;
    let mut rewrite_count: u64 = 0;
    while i < ops.len() {
        if i + 5 < ops.len() {
            match (
                &ops[i],
                &ops[i + 1],
                &ops[i + 2],
                &ops[i + 3],
                &ops[i + 4],
                &ops[i + 5],
            ) {
                (
                    jit::TraceOp::LoadLocal(map_local),
                    jit::TraceOp::LoadLocal(key_local),
                    jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                        map_idx,
                        key_idx,
                        key_bits,
                        deopt_ip,
                        value_ptr,
                    ),
                    jit::TraceOp::StoreLocal(tmp_local_a),
                    jit::TraceOp::LoadLocal(tmp_local_b),
                    jit::TraceOp::AddLocalFromStack(acc_local),
                ) if map_local == map_idx
                    && key_local == key_idx
                    && tmp_local_a == tmp_local_b
                    && *tmp_local_a != *acc_local
                    && !temp_local_reused_before_overwrite(ops, i + 6, *tmp_local_a) =>
                {
                    out.push(jit::TraceOp::LoadLocal(*map_local));
                    out.push(jit::TraceOp::LoadLocal(*key_local));
                    out.push(jit::TraceOp::MapGetTextKeyConstSlotPtrStableAddLocalNoVer(
                        *map_idx, *key_idx, *key_bits, *deopt_ip, *value_ptr, *acc_local,
                    ));
                    rewrite_count = rewrite_count.saturating_add(1);
                    i += 6;
                    continue;
                }
                _ => {}
            }
        }
        out.push(ops[i].clone());
        i += 1;
    }
    (out, rewrite_count)
}

fn temp_local_reused_before_overwrite(ops: &[jit::TraceOp], start: usize, tmp: usize) -> bool {
    for op in &ops[start..] {
        match op {
            jit::TraceOp::StoreLocal(idx) if *idx == tmp => return false,
            jit::TraceOp::LoadLocal(idx)
            | jit::TraceOp::AddLocalFromStack(idx)
            | jit::TraceOp::LenListLocal(idx)
            | jit::TraceOp::BumpListVersionLocal(idx)
            | jit::TraceOp::BumpMapVersionLocal(idx)
                if *idx == tmp =>
            {
                return true;
            }
            jit::TraceOp::InitLocalConst(idx, _) | jit::TraceOp::AddLocalConst(idx, _)
                if *idx == tmp =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn rewrite_map_stable_cmp_branch(ops: &[jit::TraceOp]) -> (Vec<jit::TraceOp>, u64) {
    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    let mut i = 0usize;
    let mut rewrite_count: u64 = 0;
    while i < ops.len() {
        if i + 7 < ops.len() {
            match (
                &ops[i],
                &ops[i + 1],
                &ops[i + 2],
                &ops[i + 3],
                &ops[i + 4],
                &ops[i + 5],
                &ops[i + 6],
                &ops[i + 7],
            ) {
                (
                    jit::TraceOp::LoadLocal(map_local),
                    jit::TraceOp::LoadLocal(key_local),
                    jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                        map_idx,
                        key_idx,
                        key_bits,
                        deopt_ip,
                        value_ptr,
                    ),
                    jit::TraceOp::StoreLocal(tmp_local_a),
                    jit::TraceOp::LoadLocal(tmp_local_b),
                    jit::TraceOp::ConstNum(cmp_rhs),
                    cmp_op,
                    guard_op,
                ) if map_local == map_idx
                    && key_local == key_idx
                    && tmp_local_a == tmp_local_b
                    && *tmp_local_a != *map_local
                    && *tmp_local_a != *key_local
                    && matches!(
                        cmp_op,
                        jit::TraceOp::EqNum
                            | jit::TraceOp::NeNum
                            | jit::TraceOp::LtNum
                            | jit::TraceOp::LeNum
                            | jit::TraceOp::GtNum
                            | jit::TraceOp::GeNum
                    )
                    && matches!(
                        guard_op,
                        jit::TraceOp::GuardFalse
                            | jit::TraceOp::GuardFalseDeopt(_)
                            | jit::TraceOp::BranchFalse(_)
                    )
                    && !temp_local_reused_before_overwrite(ops, i + 8, *tmp_local_a) =>
                {
                    out.push(jit::TraceOp::LoadLocal(*map_local));
                    out.push(jit::TraceOp::LoadLocal(*key_local));
                    out.push(jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                        *map_idx, *key_idx, *key_bits, *deopt_ip, *value_ptr,
                    ));
                    out.push(jit::TraceOp::ConstNum(*cmp_rhs));
                    out.push(cmp_op.clone());
                    out.push(guard_op.clone());
                    rewrite_count = rewrite_count.saturating_add(1);
                    i += 8;
                    continue;
                }
                (
                    jit::TraceOp::LoadLocal(map_local),
                    jit::TraceOp::LoadLocal(key_local),
                    jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                        map_idx,
                        key_idx,
                        key_bits,
                        deopt_ip,
                        value_ptr,
                    ),
                    jit::TraceOp::Dup,
                    jit::TraceOp::StoreLocal(tmp_local),
                    jit::TraceOp::ConstNum(cmp_rhs),
                    cmp_op,
                    guard_op,
                ) if map_local == map_idx
                    && key_local == key_idx
                    && *tmp_local != *map_local
                    && *tmp_local != *key_local
                    && matches!(
                        cmp_op,
                        jit::TraceOp::EqNum
                            | jit::TraceOp::NeNum
                            | jit::TraceOp::LtNum
                            | jit::TraceOp::LeNum
                            | jit::TraceOp::GtNum
                            | jit::TraceOp::GeNum
                    )
                    && matches!(
                        guard_op,
                        jit::TraceOp::GuardFalse
                            | jit::TraceOp::GuardFalseDeopt(_)
                            | jit::TraceOp::BranchFalse(_)
                    )
                    && !temp_local_reused_before_overwrite(ops, i + 8, *tmp_local) =>
                {
                    out.push(jit::TraceOp::LoadLocal(*map_local));
                    out.push(jit::TraceOp::LoadLocal(*key_local));
                    out.push(jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                        *map_idx, *key_idx, *key_bits, *deopt_ip, *value_ptr,
                    ));
                    out.push(jit::TraceOp::ConstNum(*cmp_rhs));
                    out.push(cmp_op.clone());
                    out.push(guard_op.clone());
                    rewrite_count = rewrite_count.saturating_add(1);
                    i += 8;
                    continue;
                }
                _ => {}
            }
        }
        out.push(ops[i].clone());
        i += 1;
    }
    (out, rewrite_count)
}

fn rewrite_map_stable_mul_acc(ops: &[jit::TraceOp]) -> (Vec<jit::TraceOp>, u64) {
    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    let mut i = 0usize;
    let mut rewrite_count: u64 = 0;
    while i < ops.len() {
        if i + 9 < ops.len() {
            match (
                &ops[i],
                &ops[i + 1],
                &ops[i + 2],
                &ops[i + 3],
                &ops[i + 4],
                &ops[i + 5],
                &ops[i + 6],
                &ops[i + 7],
                &ops[i + 8],
                &ops[i + 9],
            ) {
                (
                    jit::TraceOp::LoadLocal(map_local),
                    jit::TraceOp::LoadLocal(key_local),
                    jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                        map_idx,
                        key_idx,
                        key_bits,
                        deopt_ip,
                        value_ptr,
                    ),
                    jit::TraceOp::StoreLocal(tmp_val_a),
                    jit::TraceOp::LoadLocal(tmp_val_b),
                    jit::TraceOp::ConstNum(mul_c),
                    jit::TraceOp::MulNum,
                    jit::TraceOp::StoreLocal(tmp_mul_a),
                    jit::TraceOp::LoadLocal(tmp_mul_b),
                    jit::TraceOp::AddLocalFromStack(acc_local),
                ) if map_local == map_idx
                    && key_local == key_idx
                    && tmp_val_a == tmp_val_b
                    && tmp_mul_a == tmp_mul_b
                    && *tmp_val_a != *map_local
                    && *tmp_val_a != *key_local
                    && *tmp_mul_a != *map_local
                    && *tmp_mul_a != *key_local
                    && *tmp_val_a != *acc_local
                    && *tmp_mul_a != *acc_local
                    && !temp_local_reused_before_overwrite(ops, i + 10, *tmp_val_a)
                    && !temp_local_reused_before_overwrite(ops, i + 10, *tmp_mul_a) =>
                {
                    out.push(jit::TraceOp::LoadLocal(*map_local));
                    out.push(jit::TraceOp::LoadLocal(*key_local));
                    out.push(jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                        *map_idx, *key_idx, *key_bits, *deopt_ip, *value_ptr,
                    ));
                    out.push(jit::TraceOp::ConstNum(*mul_c));
                    out.push(jit::TraceOp::MulNum);
                    out.push(jit::TraceOp::AddLocalFromStack(*acc_local));
                    rewrite_count = rewrite_count.saturating_add(1);
                    i += 10;
                    continue;
                }
                _ => {}
            }
        }
        out.push(ops[i].clone());
        i += 1;
    }
    (out, rewrite_count)
}

fn apply_fusion_tier(
    ops: &[jit::TraceOp],
    mutated_maps: &std::collections::BTreeSet<usize>,
    locals: &[f64],
) -> FusionTierResult {
    let rules = [
        FusionRuleId::MapConstSlotStable,
        FusionRuleId::MapStableAddLocal,
        FusionRuleId::MapStableCmpBranch,
        FusionRuleId::MapStableMulAcc,
    ];
    let mut state = FusionTierResult {
        ops: ops.to_vec(),
        ..FusionTierResult::default()
    };
    for rule in rules {
        match rule {
            FusionRuleId::MapConstSlotStable => {
                let (next_ops, stable_maps, count) =
                    rewrite_map_const_slot_ptr_stable(&state.ops, mutated_maps, locals);
                state.ops = next_ops;
                state.stable_const_slot_maps.extend(stable_maps);
                state.hits.map_const_slot_stable =
                    state.hits.map_const_slot_stable.saturating_add(count);
                if trace_debug() && count > 0 {
                    trace_debug_log(&format!("fusion: {} hits={}", rule.name(), count));
                }
            }
            FusionRuleId::MapStableAddLocal => {
                let (next_ops, count) = rewrite_map_stable_add_local(&state.ops);
                state.ops = next_ops;
                state.hits.map_stable_add_local =
                    state.hits.map_stable_add_local.saturating_add(count);
                if trace_debug() && count > 0 {
                    trace_debug_log(&format!("fusion: {} hits={}", rule.name(), count));
                }
            }
            FusionRuleId::MapStableCmpBranch => {
                let (next_ops, count) = rewrite_map_stable_cmp_branch(&state.ops);
                state.ops = next_ops;
                state.hits.map_stable_cmp_branch =
                    state.hits.map_stable_cmp_branch.saturating_add(count);
                if trace_debug() && count > 0 {
                    trace_debug_log(&format!("fusion: {} hits={}", rule.name(), count));
                }
            }
            FusionRuleId::MapStableMulAcc => {
                let (next_ops, count) = rewrite_map_stable_mul_acc(&state.ops);
                state.ops = next_ops;
                state.hits.map_stable_mul_acc = state.hits.map_stable_mul_acc.saturating_add(count);
                if trace_debug() && count > 0 {
                    trace_debug_log(&format!("fusion: {} hits={}", rule.name(), count));
                }
            }
        }
    }
    state
}

fn rewrite_dup_for_list_update(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    let mut i = 0usize;
    while i < ops.len() {
        if i + 8 < ops.len() {
            match (
                &ops[i],
                &ops[i + 1],
                &ops[i + 2],
                &ops[i + 3],
                &ops[i + 4],
                &ops[i + 5],
                &ops[i + 6],
                &ops[i + 7],
                &ops[i + 8],
            ) {
                (
                    jit::TraceOp::IndexListNumLocalPtrOff(list, idx, data, offset),
                    jit::TraceOp::StoreLocal(v_store),
                    jit::TraceOp::LoadLocal(v_load1),
                    jit::TraceOp::AddLocalFromStack(sum_idx),
                    jit::TraceOp::LoadLocal(v_load2),
                    jit::TraceOp::ConstNum(c),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(list2, idx2, data2, off2),
                    jit::TraceOp::StoreLocal(tmp_idx),
                ) if list == list2
                    && idx == idx2
                    && data == data2
                    && offset == off2
                    && v_store == v_load1
                    && v_store == v_load2 =>
                {
                    out.push(jit::TraceOp::IndexListNumLocalPtrOff(
                        *list, *idx, *data, *offset,
                    ));
                    out.push(jit::TraceOp::Dup);
                    out.push(jit::TraceOp::AddLocalFromStack(*sum_idx));
                    out.push(jit::TraceOp::ConstNum(*c));
                    out.push(jit::TraceOp::AddNum);
                    out.push(jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(
                        *list2, *idx2, *data2, *off2,
                    ));
                    out.push(jit::TraceOp::StoreLocal(*tmp_idx));
                    i += 9;
                    continue;
                }
                (
                    jit::TraceOp::IndexListNumLocalPtr(list, idx, data),
                    jit::TraceOp::StoreLocal(v_store),
                    jit::TraceOp::LoadLocal(v_load1),
                    jit::TraceOp::AddLocalFromStack(sum_idx),
                    jit::TraceOp::LoadLocal(v_load2),
                    jit::TraceOp::ConstNum(c),
                    jit::TraceOp::AddNum,
                    jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(list2, idx2, data2),
                    jit::TraceOp::StoreLocal(tmp_idx),
                ) if list == list2
                    && idx == idx2
                    && data == data2
                    && v_store == v_load1
                    && v_store == v_load2 =>
                {
                    out.push(jit::TraceOp::IndexListNumLocalPtr(*list, *idx, *data));
                    out.push(jit::TraceOp::Dup);
                    out.push(jit::TraceOp::AddLocalFromStack(*sum_idx));
                    out.push(jit::TraceOp::ConstNum(*c));
                    out.push(jit::TraceOp::AddNum);
                    out.push(jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(
                        *list2, *idx2, *data2,
                    ));
                    out.push(jit::TraceOp::StoreLocal(*tmp_idx));
                    i += 9;
                    continue;
                }
                _ => {}
            }
        }
        out.push(ops[i].clone());
        i += 1;
    }
    out
}

fn rewrite_multi_accum_list_update(
    ops: &[jit::TraceOp],
) -> (Vec<jit::TraceOp>, Vec<(usize, usize)>) {
    let jump_pos = match ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        Some(pos) if pos + 1 == ops.len() => pos,
        _ => return (ops.to_vec(), Vec::new()),
    };

    let mut guard_idx: Option<usize> = None;
    let mut idx_local: Option<usize> = None;
    for i in 3..=jump_pos {
        if !matches!(ops[i], jit::TraceOp::GuardFalse) {
            continue;
        }
        if let (jit::TraceOp::LoadLocal(idx), jit::TraceOp::ConstNum(_), cmp) =
            (&ops[i - 3], &ops[i - 2], &ops[i - 1])
        {
            if matches!(cmp, jit::TraceOp::LtNum | jit::TraceOp::LeNum) {
                guard_idx = Some(i);
                idx_local = Some(*idx);
                break;
            }
        }
    }
    let guard_idx = match guard_idx {
        Some(i) => i,
        None => return (ops.to_vec(), Vec::new()),
    };
    let idx_local = match idx_local {
        Some(i) => i,
        None => return (ops.to_vec(), Vec::new()),
    };

    let body_start = guard_idx + 1;
    let body_end = jump_pos;
    if body_start >= body_end {
        return (ops.to_vec(), Vec::new());
    }

    let mut sum_idx: Option<usize> = None;
    let mut sum_count = 0usize;
    for op in &ops[body_start..body_end] {
        if let jit::TraceOp::AddLocalFromStack(idx) = op {
            sum_count += 1;
            if let Some(existing) = sum_idx {
                if existing != *idx {
                    return (ops.to_vec(), Vec::new());
                }
            } else {
                sum_idx = Some(*idx);
            }
        }
    }
    let sum_idx = match sum_idx {
        Some(idx) if sum_count >= 2 => idx,
        _ => return (ops.to_vec(), Vec::new()),
    };

    let mut acc_idx: Option<usize> = None;
    let mut store_positions: Vec<usize> = Vec::new();
    for i in body_start..body_end.saturating_sub(1) {
        if matches!(
            ops[i],
            jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(_, _, _)
                | jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(_, _, _, _)
        ) {
            if let jit::TraceOp::StoreLocal(local) = ops[i + 1] {
                if let Some(existing) = acc_idx {
                    if existing != local {
                        return (ops.to_vec(), Vec::new());
                    }
                } else {
                    acc_idx = Some(local);
                }
                store_positions.push(i + 1);
            }
        }
    }
    let acc_idx = match acc_idx {
        Some(idx) => idx,
        None => return (ops.to_vec(), Vec::new()),
    };
    if acc_idx == sum_idx || acc_idx == idx_local {
        return (ops.to_vec(), Vec::new());
    }

    let uses_local = |op: &jit::TraceOp, idx: usize| -> bool {
        match op {
            jit::TraceOp::InitLocalConst(local, _)
            | jit::TraceOp::LoadLocal(local)
            | jit::TraceOp::StoreLocal(local)
            | jit::TraceOp::AddLocalConst(local, _)
            | jit::TraceOp::AddLocalFromStack(local)
            | jit::TraceOp::LenListLocal(local)
            | jit::TraceOp::BumpListVersionLocal(local)
            | jit::TraceOp::BumpMapVersionLocal(local) => *local == idx,
            jit::TraceOp::IndexListNumLocal(list, idx_local)
            | jit::TraceOp::IndexListNumLocalPtr(list, idx_local, _)
            | jit::TraceOp::IndexListNumLocalPtrOff(list, idx_local, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtr(list, idx_local, _)
            | jit::TraceOp::SetIndexListNumLocalNoVer(list, idx_local)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVer(list, idx_local, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(list, idx_local, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(list, idx_local, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(list, idx_local, _, _) => {
                *list == idx || *idx_local == idx
            }
            jit::TraceOp::GuardListBounds(list, idx_local) => *list == idx || *idx_local == idx,
            jit::TraceOp::GuardIndexNonNeg(idx_local) => *idx_local == idx,
            jit::TraceOp::GuardIndexCmpConst(idx_local, _, _) => *idx_local == idx,
            jit::TraceOp::GuardIndexRangeConst(idx_local, _, _) => *idx_local == idx,
            jit::TraceOp::GuardListNoAliasSameLen(list_a, list_b) => {
                *list_a == idx || *list_b == idx
            }
            jit::TraceOp::MapGetSlot(map_idx)
            | jit::TraceOp::MapGetSlotNoVerGuard(map_idx, _, _, _, _)
            | jit::TraceOp::MapSetSlotPtrNoVer(map_idx, _)
            | jit::TraceOp::MapSetSlotPtrNoVerGuard(map_idx, _, _, _, _)
            | jit::TraceOp::MapSetSlotNoVer(map_idx, _) => *map_idx == idx,
            jit::TraceOp::MapGetSlotPtr(_) => false,
            jit::TraceOp::MapGetSmallKeyNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapGetTextKeyNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstNoVer(map_idx, key_idx, _, _, _, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(map_idx, key_idx, _, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(
                map_idx,
                key_idx,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
            )
            | jit::TraceOp::MapSetSmallKeyNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapSetTextKeyNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstNoVer(map_idx, key_idx, _, _, _, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstSlotPtrNoVer(map_idx, key_idx, _, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(
                map_idx,
                key_idx,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
            ) => *map_idx == idx || *key_idx == idx,
            jit::TraceOp::MapGetTextKeyConstSlotPtrStableAddLocalNoVer(
                map_idx,
                key_idx,
                _,
                _,
                _,
                acc_local,
            ) => *map_idx == idx || *key_idx == idx || *acc_local == idx,
            _ => false,
        }
    };

    for (i, op) in ops.iter().enumerate() {
        if matches!(op, jit::TraceOp::StoreLocal(local) if *local == acc_idx) {
            if !store_positions.contains(&i) {
                return (ops.to_vec(), Vec::new());
            }
            continue;
        }
        if uses_local(op, acc_idx) {
            return (ops.to_vec(), Vec::new());
        }
    }

    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len() + 1);
    out.push(jit::TraceOp::InitLocalConst(acc_idx, 0.0));
    let mut toggle = false;
    for (i, op) in ops.iter().enumerate() {
        if store_positions.contains(&i) {
            out.push(jit::TraceOp::Pop);
            continue;
        }
        if i >= body_start && i < body_end {
            if let jit::TraceOp::AddLocalFromStack(idx) = op {
                if *idx == sum_idx {
                    let target = if toggle { acc_idx } else { sum_idx };
                    toggle = !toggle;
                    out.push(jit::TraceOp::AddLocalFromStack(target));
                    continue;
                }
            }
        }
        out.push(op.clone());
    }

    (out, vec![(sum_idx, acc_idx)])
}

fn rewrite_dot_product_multi_accum(
    ops: &[jit::TraceOp],
) -> (Vec<jit::TraceOp>, Vec<(usize, usize)>) {
    let jump_pos = match ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        Some(pos) if pos + 1 == ops.len() => pos,
        _ => return (ops.to_vec(), Vec::new()),
    };

    let mut guard_idx: Option<usize> = None;
    let mut idx_local: Option<usize> = None;
    for i in 3..=jump_pos {
        if !matches!(ops[i], jit::TraceOp::GuardFalse) {
            continue;
        }
        if let (jit::TraceOp::LoadLocal(idx), jit::TraceOp::ConstNum(_), cmp) =
            (&ops[i - 3], &ops[i - 2], &ops[i - 1])
        {
            if matches!(cmp, jit::TraceOp::LtNum | jit::TraceOp::LeNum) {
                guard_idx = Some(i);
                idx_local = Some(*idx);
                break;
            }
        }
    }
    let guard_idx = match guard_idx {
        Some(i) => i,
        None => return (ops.to_vec(), Vec::new()),
    };
    let idx_local = match idx_local {
        Some(i) => i,
        None => return (ops.to_vec(), Vec::new()),
    };

    let body_start = guard_idx + 1;
    let body_end = jump_pos;
    if body_start >= body_end {
        return (ops.to_vec(), Vec::new());
    }

    let is_index_list = |op: &jit::TraceOp| -> bool {
        matches!(
            op,
            jit::TraceOp::IndexListNumLocal(_, _)
                | jit::TraceOp::IndexListNumLocalPtr(_, _, _)
                | jit::TraceOp::IndexListNumLocalPtrOff(_, _, _, _)
        )
    };
    let index_list_idx = |op: &jit::TraceOp| -> Option<usize> {
        match op {
            jit::TraceOp::IndexListNumLocal(_, idx)
            | jit::TraceOp::IndexListNumLocalPtr(_, idx, _)
            | jit::TraceOp::IndexListNumLocalPtrOff(_, idx, _, _) => Some(*idx),
            _ => None,
        }
    };
    let mut sum_idx: Option<usize> = None;
    let mut acc_idx: Option<usize> = None;
    let mut acc_alt_idx: Option<usize> = None;
    let mut matched_blocks = 0usize;
    enum DotKind {
        OneList,
        TwoList,
    }
    let mut kind: Option<DotKind> = None;

    let mut i = body_start;
    while i < body_end {
        let mut matched = false;
        if i + 9 < body_end && is_index_list(&ops[i]) && is_index_list(&ops[i + 2]) {
            let (list_a, store_a, list_b, store_b, load_sum, load_a, load_b, mul, add, store_sum) = (
                &ops[i],
                &ops[i + 1],
                &ops[i + 2],
                &ops[i + 3],
                &ops[i + 4],
                &ops[i + 5],
                &ops[i + 6],
                &ops[i + 7],
                &ops[i + 8],
                &ops[i + 9],
            );
            if index_list_idx(list_a) != Some(idx_local)
                || index_list_idx(list_b) != Some(idx_local)
            {
                i += 1;
                continue;
            }
            let a_local = match store_a {
                jit::TraceOp::StoreLocal(v) => *v,
                _ => {
                    i += 1;
                    continue;
                }
            };
            let b_local = match store_b {
                jit::TraceOp::StoreLocal(v) => *v,
                _ => {
                    i += 1;
                    continue;
                }
            };
            let sum_local = match load_sum {
                jit::TraceOp::LoadLocal(v) => *v,
                _ => {
                    i += 1;
                    continue;
                }
            };
            let loads_match = matches!(load_a, jit::TraceOp::LoadLocal(v) if *v == a_local)
                && matches!(load_b, jit::TraceOp::LoadLocal(v) if *v == b_local);
            let loads_swapped = matches!(load_a, jit::TraceOp::LoadLocal(v) if *v == b_local)
                && matches!(load_b, jit::TraceOp::LoadLocal(v) if *v == a_local);
            if (loads_match || loads_swapped)
                && matches!(mul, jit::TraceOp::MulNum)
                && matches!(add, jit::TraceOp::AddNum)
                && matches!(store_sum, jit::TraceOp::StoreLocal(v) if *v == sum_local)
            {
                match kind {
                    Some(DotKind::OneList) => return (ops.to_vec(), Vec::new()),
                    _ => kind = Some(DotKind::TwoList),
                }
                if let Some(prev_sum) = sum_idx {
                    if prev_sum != sum_local {
                        return (ops.to_vec(), Vec::new());
                    }
                } else {
                    sum_idx = Some(sum_local);
                }
                if let Some(prev_acc) = acc_idx {
                    if prev_acc != a_local {
                        return (ops.to_vec(), Vec::new());
                    }
                } else {
                    acc_idx = Some(a_local);
                }
                if let Some(prev_alt) = acc_alt_idx {
                    if prev_alt != b_local {
                        return (ops.to_vec(), Vec::new());
                    }
                } else {
                    acc_alt_idx = Some(b_local);
                }
                matched_blocks += 1;
                i += 10;
                matched = true;
            }
        }
        if !matched && i + 7 < body_end && is_index_list(&ops[i]) {
            let (list_op, store_v, load_sum, load_v1, load_v2, mul, add, store_sum) = (
                &ops[i],
                &ops[i + 1],
                &ops[i + 2],
                &ops[i + 3],
                &ops[i + 4],
                &ops[i + 5],
                &ops[i + 6],
                &ops[i + 7],
            );
            if index_list_idx(list_op) == Some(idx_local) {
                let v_local = match store_v {
                    jit::TraceOp::StoreLocal(v) => *v,
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                let sum_local = match load_sum {
                    jit::TraceOp::LoadLocal(v) => *v,
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                if matches!(load_v1, jit::TraceOp::LoadLocal(v) if *v == v_local)
                    && matches!(load_v2, jit::TraceOp::LoadLocal(v) if *v == v_local)
                    && matches!(mul, jit::TraceOp::MulNum)
                    && matches!(add, jit::TraceOp::AddNum)
                    && matches!(store_sum, jit::TraceOp::StoreLocal(v) if *v == sum_local)
                {
                    match kind {
                        Some(DotKind::TwoList) => return (ops.to_vec(), Vec::new()),
                        _ => kind = Some(DotKind::OneList),
                    }
                    if let Some(prev_sum) = sum_idx {
                        if prev_sum != sum_local {
                            return (ops.to_vec(), Vec::new());
                        }
                    } else {
                        sum_idx = Some(sum_local);
                    }
                    if let Some(prev_acc) = acc_idx {
                        if prev_acc != v_local {
                            return (ops.to_vec(), Vec::new());
                        }
                    } else {
                        acc_idx = Some(v_local);
                    }
                    matched_blocks += 1;
                    i += 8;
                    matched = true;
                }
            }
        }
        if matched {
            continue;
        }
        i += 1;
    }

    if matched_blocks == 0 {
        return (ops.to_vec(), Vec::new());
    }

    let sum_idx = match sum_idx {
        Some(idx) => idx,
        None => return (ops.to_vec(), Vec::new()),
    };
    let acc_idx = match acc_idx {
        Some(idx) => idx,
        None => return (ops.to_vec(), Vec::new()),
    };
    if acc_idx == sum_idx || acc_idx == idx_local {
        return (ops.to_vec(), Vec::new());
    }

    let uses_local = |op: &jit::TraceOp, idx: usize| -> bool {
        match op {
            jit::TraceOp::InitLocalConst(local, _)
            | jit::TraceOp::LoadLocal(local)
            | jit::TraceOp::StoreLocal(local)
            | jit::TraceOp::AddLocalConst(local, _)
            | jit::TraceOp::AddLocalFromStack(local)
            | jit::TraceOp::LenListLocal(local)
            | jit::TraceOp::BumpListVersionLocal(local)
            | jit::TraceOp::BumpMapVersionLocal(local) => *local == idx,
            jit::TraceOp::IndexListNumLocal(list, idx_local)
            | jit::TraceOp::IndexListNumLocalPtr(list, idx_local, _)
            | jit::TraceOp::IndexListNumLocalPtrOff(list, idx_local, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtr(list, idx_local, _)
            | jit::TraceOp::SetIndexListNumLocalNoVer(list, idx_local)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVer(list, idx_local, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(list, idx_local, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(list, idx_local, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(list, idx_local, _, _) => {
                *list == idx || *idx_local == idx
            }
            jit::TraceOp::GuardListBounds(list, idx_local) => *list == idx || *idx_local == idx,
            jit::TraceOp::GuardIndexNonNeg(idx_local) => *idx_local == idx,
            jit::TraceOp::GuardIndexCmpConst(idx_local, _, _) => *idx_local == idx,
            jit::TraceOp::GuardIndexRangeConst(idx_local, _, _) => *idx_local == idx,
            jit::TraceOp::GuardListNoAliasSameLen(list_a, list_b) => {
                *list_a == idx || *list_b == idx
            }
            jit::TraceOp::MapGetSlot(map_idx)
            | jit::TraceOp::MapGetSlotNoVerGuard(map_idx, _, _, _, _)
            | jit::TraceOp::MapSetSlotPtrNoVer(map_idx, _)
            | jit::TraceOp::MapSetSlotPtrNoVerGuard(map_idx, _, _, _, _)
            | jit::TraceOp::MapSetSlotNoVer(map_idx, _) => *map_idx == idx,
            jit::TraceOp::MapGetSlotPtr(_) => false,
            jit::TraceOp::MapGetSmallKeyNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapGetTextKeyNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstNoVer(map_idx, key_idx, _, _, _, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(map_idx, key_idx, _, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(
                map_idx,
                key_idx,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
            )
            | jit::TraceOp::MapSetSmallKeyNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapSetTextKeyNoVer(map_idx, key_idx, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstNoVer(map_idx, key_idx, _, _, _, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstSlotPtrNoVer(map_idx, key_idx, _, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(
                map_idx,
                key_idx,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
            ) => *map_idx == idx || *key_idx == idx,
            jit::TraceOp::MapGetTextKeyConstSlotPtrStableAddLocalNoVer(
                map_idx,
                key_idx,
                _,
                _,
                _,
                acc_local,
            ) => *map_idx == idx || *key_idx == idx || *acc_local == idx,
            _ => false,
        }
    };

    for (pos, op) in ops.iter().enumerate() {
        if pos >= body_start && pos < body_end {
            continue;
        }
        if uses_local(op, acc_idx) {
            return (ops.to_vec(), Vec::new());
        }
        if let Some(alt) = acc_alt_idx {
            if uses_local(op, alt) {
                return (ops.to_vec(), Vec::new());
            }
        }
    }

    let mut accum_targets: Vec<usize> = vec![sum_idx, acc_idx];
    if matches!(kind, Some(DotKind::TwoList)) {
        if let Some(alt) = acc_alt_idx {
            if alt != sum_idx && alt != acc_idx {
                accum_targets.push(alt);
            }
        }
    }

    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len() + accum_targets.len());
    for acc in accum_targets.iter().skip(1) {
        out.push(jit::TraceOp::InitLocalConst(*acc, 0.0));
    }
    let mut accum_cursor = 0usize;
    let mut j = 0usize;
    while j < ops.len() {
        if j >= body_start && j < body_end {
            if let Some(DotKind::OneList) = kind {
                if j + 7 < body_end
                    && is_index_list(&ops[j])
                    && index_list_idx(&ops[j]) == Some(idx_local)
                    && matches!(&ops[j + 1], jit::TraceOp::StoreLocal(v) if *v == acc_idx)
                    && matches!(&ops[j + 2], jit::TraceOp::LoadLocal(v) if *v == sum_idx)
                    && matches!(&ops[j + 3], jit::TraceOp::LoadLocal(v) if *v == acc_idx)
                    && matches!(&ops[j + 4], jit::TraceOp::LoadLocal(v) if *v == acc_idx)
                    && matches!(&ops[j + 5], jit::TraceOp::MulNum)
                    && matches!(&ops[j + 6], jit::TraceOp::AddNum)
                    && matches!(&ops[j + 7], jit::TraceOp::StoreLocal(v) if *v == sum_idx)
                {
                    out.push(ops[j].clone());
                    out.push(jit::TraceOp::Dup);
                    out.push(jit::TraceOp::MulNum);
                    let target = accum_targets[accum_cursor % accum_targets.len()];
                    accum_cursor = accum_cursor.wrapping_add(1);
                    out.push(jit::TraceOp::AddLocalFromStack(target));
                    j += 8;
                    continue;
                }
            }
            if let Some(DotKind::TwoList) = kind {
                let alt = acc_alt_idx.unwrap_or(acc_idx);
                if j + 9 < body_end
                    && is_index_list(&ops[j])
                    && index_list_idx(&ops[j]) == Some(idx_local)
                    && matches!(&ops[j + 1], jit::TraceOp::StoreLocal(v) if *v == acc_idx)
                    && is_index_list(&ops[j + 2])
                    && index_list_idx(&ops[j + 2]) == Some(idx_local)
                    && matches!(&ops[j + 3], jit::TraceOp::StoreLocal(v) if *v == alt)
                    && matches!(&ops[j + 4], jit::TraceOp::LoadLocal(v) if *v == sum_idx)
                    && ((matches!(&ops[j + 5], jit::TraceOp::LoadLocal(v) if *v == acc_idx)
                        && matches!(&ops[j + 6], jit::TraceOp::LoadLocal(v) if *v == alt))
                        || (matches!(&ops[j + 5], jit::TraceOp::LoadLocal(v) if *v == alt)
                            && matches!(&ops[j + 6], jit::TraceOp::LoadLocal(v) if *v == acc_idx)))
                    && matches!(&ops[j + 7], jit::TraceOp::MulNum)
                    && matches!(&ops[j + 8], jit::TraceOp::AddNum)
                    && matches!(&ops[j + 9], jit::TraceOp::StoreLocal(v) if *v == sum_idx)
                {
                    out.push(ops[j].clone());
                    out.push(ops[j + 2].clone());
                    out.push(jit::TraceOp::MulNum);
                    let target = accum_targets[accum_cursor % accum_targets.len()];
                    accum_cursor = accum_cursor.wrapping_add(1);
                    out.push(jit::TraceOp::AddLocalFromStack(target));
                    j += 10;
                    continue;
                }
            }
            out.push(ops[j].clone());
            j += 1;
            continue;
        }
        out.push(ops[j].clone());
        j += 1;
    }

    let mut merges: Vec<(usize, usize)> = Vec::new();
    for acc in accum_targets.iter().skip(1) {
        merges.push((sum_idx, *acc));
    }
    (out, merges)
}

fn eliminate_dead_stores(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    let mut dead_stores: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut used: std::collections::HashSet<usize> = std::collections::HashSet::new();
    if ops.iter().any(|op| matches!(op, jit::TraceOp::JumpStart)) {
        // A trace is cyclic: values read near the beginning are live across the
        // backedge, so the final store in the body must survive DSE.
        for op in ops {
            match op {
                jit::TraceOp::LoadLocal(local)
                | jit::TraceOp::AddLocalConst(local, _)
                | jit::TraceOp::AddLocalFromStack(local) => {
                    used.insert(*local);
                }
                _ => {}
            }
        }
    }
    for (idx, op) in ops.iter().enumerate().rev() {
        match op {
            jit::TraceOp::LoadLocal(local) => {
                used.insert(*local);
            }
            jit::TraceOp::AddLocalConst(local, _) | jit::TraceOp::AddLocalFromStack(local) => {
                used.insert(*local);
            }
            jit::TraceOp::StoreLocal(local) => {
                if !used.contains(local) {
                    dead_stores.insert(idx);
                }
                used.remove(local);
            }
            _ => {}
        }
    }

    if dead_stores.is_empty() {
        return ops.to_vec();
    }

    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    for (idx, op) in ops.iter().enumerate() {
        if matches!(op, jit::TraceOp::StoreLocal(_)) && dead_stores.contains(&idx) {
            out.push(jit::TraceOp::Pop);
            continue;
        }
        out.push(op.clone());
    }
    out
}

fn rewrite_loop_bounds_guard(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    let mut out = ops.to_vec();
    let mut guard_idx: Option<(usize, usize, usize)> = None;
    for (i, op) in out.iter().enumerate() {
        if let jit::TraceOp::GuardListBounds(list_idx, idx_idx) = op {
            guard_idx = Some((i, *list_idx, *idx_idx));
            break;
        }
        if !matches!(
            op,
            jit::TraceOp::GuardListBounds(_, _)
                | jit::TraceOp::GuardIndexCmpConst(_, _, _)
                | jit::TraceOp::GuardIndexRangeConst(_, _, _)
                | jit::TraceOp::GuardListNoAliasSameLen(_, _)
                | jit::TraceOp::InitLocalConst(_, _)
        ) {
            break;
        }
    }
    let (guard_pos, list_idx, idx_idx) = match guard_idx {
        Some(v) => v,
        None => return out,
    };

    let mut loop_guard_ok = false;
    for i in 3..out.len() {
        if !matches!(out[i], jit::TraceOp::GuardFalse) {
            continue;
        }
        if let (jit::TraceOp::LoadLocal(idx), jit::TraceOp::ConstNum(_), cmp) =
            (&out[i - 3], &out[i - 2], &out[i - 1])
        {
            if *idx == idx_idx && matches!(cmp, jit::TraceOp::LtNum | jit::TraceOp::LeNum) {
                loop_guard_ok = true;
                break;
            }
        }
    }
    if !loop_guard_ok {
        return out;
    }

    for op in &out {
        match op {
            jit::TraceOp::IndexListNumLocalPtr(list, idx, _)
            | jit::TraceOp::IndexListNumLocalPtrOff(list, idx, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtr(list, idx, _)
            | jit::TraceOp::SetIndexListNumLocalNoVer(list, idx)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVer(list, idx, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(list, idx, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(list, idx, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(list, idx, _, _)
                if *list != list_idx || *idx != idx_idx =>
            {
                return out;
            }
            _ => {}
        }
    }

    out[guard_pos] = jit::TraceOp::GuardIndexNonNeg(idx_idx);
    out
}

fn canonicalize_loop_form(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    let jump_pos = match ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        Some(pos) if pos + 1 == ops.len() => pos,
        _ => return ops.to_vec(),
    };
    if jump_pos < 4 {
        return ops.to_vec();
    }

    let mut cond_start = 0usize;
    while cond_start < jump_pos {
        if matches!(
            ops[cond_start],
            jit::TraceOp::GuardListBounds(_, _)
                | jit::TraceOp::GuardIndexNonNeg(_)
                | jit::TraceOp::GuardIndexCmpConst(_, _, _)
                | jit::TraceOp::GuardIndexRangeConst(_, _, _)
                | jit::TraceOp::GuardListNoAliasSameLen(_, _)
                | jit::TraceOp::InitLocalConst(_, _)
        ) {
            cond_start += 1;
            continue;
        }
        break;
    }
    if cond_start + 3 >= jump_pos {
        return ops.to_vec();
    }

    let (idx_local, limit, inclusive) = match (
        &ops[cond_start],
        &ops[cond_start + 1],
        &ops[cond_start + 2],
        &ops[cond_start + 3],
    ) {
        (
            jit::TraceOp::LoadLocal(idx),
            jit::TraceOp::ConstNum(limit),
            jit::TraceOp::LtNum,
            jit::TraceOp::GuardFalse,
        ) => (*idx, *limit, false),
        (
            jit::TraceOp::LoadLocal(idx),
            jit::TraceOp::ConstNum(limit),
            jit::TraceOp::LeNum,
            jit::TraceOp::GuardFalse,
        ) => (*idx, *limit, true),
        _ => return ops.to_vec(),
    };

    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len() - 3);
    out.extend_from_slice(&ops[..cond_start]);
    out.push(jit::TraceOp::GuardIndexCmpConst(
        idx_local, limit, inclusive,
    ));
    out.extend_from_slice(&ops[cond_start + 4..]);
    out
}

fn fuse_index_range_guards(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    if ops.len() < 2 {
        return ops.to_vec();
    }
    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    let mut i = 0usize;
    while i < ops.len() {
        if i + 1 < ops.len() {
            if let (
                jit::TraceOp::GuardIndexNonNeg(idx0),
                jit::TraceOp::GuardIndexCmpConst(idx1, limit, inclusive),
            ) = (&ops[i], &ops[i + 1])
            {
                if idx0 == idx1 {
                    out.push(jit::TraceOp::GuardIndexRangeConst(
                        *idx0, *limit, *inclusive,
                    ));
                    i += 2;
                    continue;
                }
            }
        }
        out.push(ops[i].clone());
        i += 1;
    }
    out
}

fn schedule_dot_product_load_mul_add(ops: &[jit::TraceOp]) -> (Vec<jit::TraceOp>, bool) {
    let jump_pos = match ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        Some(pos) if pos + 1 == ops.len() => pos,
        _ => return (ops.to_vec(), false),
    };

    let cond_pos = match ops
        .iter()
        .position(|op| matches!(op, jit::TraceOp::GuardIndexCmpConst(_, _, _)))
    {
        Some(pos) if pos + 1 < jump_pos => pos,
        _ => return (ops.to_vec(), false),
    };
    let idx_local = match ops[cond_pos] {
        jit::TraceOp::GuardIndexCmpConst(idx, _, _) => idx,
        _ => return (ops.to_vec(), false),
    };
    let body_start = cond_pos + 1;

    let idx_for_index = |op: &jit::TraceOp| match op {
        jit::TraceOp::IndexListNumLocal(_, idx)
        | jit::TraceOp::IndexListNumLocalPtr(_, idx, _)
        | jit::TraceOp::IndexListNumLocalPtrOff(_, idx, _, _) => Some(*idx),
        _ => None,
    };

    #[derive(Clone)]
    struct Lane {
        load_a: jit::TraceOp,
        load_b: jit::TraceOp,
        acc_local: usize,
    }

    let mut lanes: Vec<Lane> = Vec::new();
    let mut i = body_start;
    while i + 3 < jump_pos {
        let idx_a = idx_for_index(&ops[i]);
        let idx_b = idx_for_index(&ops[i + 1]);
        let Some(idx_a) = idx_a else {
            break;
        };
        let Some(idx_b) = idx_b else {
            break;
        };
        if idx_a != idx_local || idx_b != idx_local {
            break;
        }
        if !matches!(ops[i + 2], jit::TraceOp::MulNum) {
            break;
        }
        let acc_local = match ops[i + 3] {
            jit::TraceOp::AddLocalFromStack(local) => local,
            _ => break,
        };
        lanes.push(Lane {
            load_a: ops[i].clone(),
            load_b: ops[i + 1].clone(),
            acc_local,
        });
        i += 4;
    }
    let lane_end = i;
    if lanes.len() < 3 {
        return (ops.to_vec(), false);
    }

    let mut out: Vec<jit::TraceOp> = Vec::with_capacity(ops.len());
    out.extend_from_slice(&ops[..body_start]);

    // Conservative scheduler: reorder in small chunks to increase overlap while
    // keeping register pressure bounded.
    const CHUNK: usize = 2;
    let mut lane_base = 0usize;
    while lane_base < lanes.len() {
        let lane_end = (lane_base + CHUNK).min(lanes.len());
        for lane in lanes[lane_base..lane_end].iter().rev() {
            out.push(lane.load_a.clone());
            out.push(lane.load_b.clone());
        }
        for lane in &lanes[lane_base..lane_end] {
            out.push(jit::TraceOp::MulNum);
            out.push(jit::TraceOp::AddLocalFromStack(lane.acc_local));
        }
        lane_base = lane_end;
    }

    out.extend_from_slice(&ops[lane_end..]);
    (out, true)
}

fn insert_dot_product_noalias_guard(ops: &[jit::TraceOp]) -> Vec<jit::TraceOp> {
    if ops
        .iter()
        .any(|op| matches!(op, jit::TraceOp::GuardListNoAliasSameLen(_, _)))
    {
        return ops.to_vec();
    }

    let jump_pos = match ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        Some(pos) if pos + 1 == ops.len() => pos,
        _ => return ops.to_vec(),
    };

    let mut guard_idx: Option<usize> = None;
    let mut idx_local: Option<usize> = None;
    for i in 3..=jump_pos {
        if !matches!(ops[i], jit::TraceOp::GuardFalse) {
            continue;
        }
        if let (jit::TraceOp::LoadLocal(idx), jit::TraceOp::ConstNum(_), cmp) =
            (&ops[i - 3], &ops[i - 2], &ops[i - 1])
        {
            if matches!(cmp, jit::TraceOp::LtNum | jit::TraceOp::LeNum) {
                guard_idx = Some(i);
                idx_local = Some(*idx);
                break;
            }
        }
    }

    let guard_idx = match guard_idx {
        Some(i) => i,
        None => return ops.to_vec(),
    };
    let idx_local = match idx_local {
        Some(i) => i,
        None => return ops.to_vec(),
    };

    let body = &ops[guard_idx + 1..jump_pos];
    if body.is_empty() {
        return ops.to_vec();
    }

    let mut lists: Vec<usize> = Vec::new();
    for op in body {
        match op {
            jit::TraceOp::IndexListNumLocalPtr(list, idx, _)
            | jit::TraceOp::IndexListNumLocalPtrOff(list, idx, _, _) => {
                if *idx != idx_local {
                    return ops.to_vec();
                }
                if !lists.contains(list) {
                    lists.push(*list);
                }
            }
            jit::TraceOp::SetIndexListNumLocalPtr(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalNoVer(_, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVer(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(_, _, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(_, _, _, _) => {
                return ops.to_vec();
            }
            _ => {}
        }
    }

    if lists.len() != 2 {
        return ops.to_vec();
    }
    if lists[0] == lists[1] {
        return ops.to_vec();
    }

    let mut out = Vec::with_capacity(ops.len() + 1);
    out.push(jit::TraceOp::GuardListNoAliasSameLen(lists[0], lists[1]));
    out.extend_from_slice(ops);
    out
}

fn build_loop_inst_info(kind: &LoopInstKind) -> InstInfo {
    match kind {
        LoopInstKind::LoadListElemF64 { dst, .. } => InstInfo {
            defs: vec![*dst],
            uses: Vec::new(),
            class_constraints: vec![RegClass::Xmm],
            has_side_effect: false,
        },
        LoopInstKind::MulF64 { dst, lhs, rhs } => InstInfo {
            defs: vec![*dst],
            uses: vec![*lhs, *rhs],
            class_constraints: vec![RegClass::Xmm],
            has_side_effect: false,
        },
        LoopInstKind::AddF64 { dst, lhs, rhs } => InstInfo {
            defs: vec![*dst],
            uses: vec![*lhs, *rhs],
            class_constraints: vec![RegClass::Xmm],
            has_side_effect: false,
        },
        LoopInstKind::AddAssignLocalFromStack { acc, rhs, .. } => InstInfo {
            defs: vec![*acc],
            uses: vec![*acc, *rhs],
            class_constraints: vec![RegClass::Xmm],
            has_side_effect: false,
        },
        LoopInstKind::AddAssignLocalConst { reg, .. } => InstInfo {
            defs: vec![*reg],
            uses: vec![*reg],
            class_constraints: vec![RegClass::Gpr],
            has_side_effect: false,
        },
        LoopInstKind::MoveToLocal { dst, src, .. } => InstInfo {
            defs: vec![*dst],
            uses: vec![*src],
            class_constraints: Vec::new(),
            has_side_effect: false,
        },
    }
}

fn build_dot_product_loop_ir(ops: &[jit::TraceOp]) -> Option<LoopIr> {
    let jump_pos = match ops
        .iter()
        .rposition(|op| matches!(op, jit::TraceOp::JumpStart))
    {
        Some(pos) if pos + 1 == ops.len() => pos,
        _ => return None,
    };

    let guard_pos = ops
        .iter()
        .position(|op| matches!(op, jit::TraceOp::GuardIndexCmpConst(_, _, _)))?;
    if guard_pos + 1 >= jump_pos {
        return None;
    }
    let idx_local = match ops[guard_pos] {
        jit::TraceOp::GuardIndexCmpConst(idx, _, _) => idx,
        _ => return None,
    };
    let body = &ops[guard_pos + 1..jump_pos];

    let mut next_vreg: u32 = 0;
    let mut local_vregs: std::collections::BTreeMap<usize, VReg> =
        std::collections::BTreeMap::new();
    let mut local_classes: std::collections::BTreeMap<usize, RegClass> =
        std::collections::BTreeMap::new();
    local_classes.insert(idx_local, RegClass::Gpr);

    let mut vreg_classes: std::collections::BTreeMap<VReg, RegClass> =
        std::collections::BTreeMap::new();
    let mut insts: Vec<LoopInst> = Vec::new();
    let mut stack: Vec<VReg> = Vec::new();

    let new_vreg =
        |class: RegClass,
         next_vreg: &mut u32,
         vreg_classes: &mut std::collections::BTreeMap<VReg, RegClass>| {
            let id = VReg(*next_vreg);
            *next_vreg += 1;
            vreg_classes.insert(id, class);
            id
        };

    let local_vreg =
        |local: usize,
         class_hint: RegClass,
         local_vregs: &mut std::collections::BTreeMap<usize, VReg>,
         local_classes: &mut std::collections::BTreeMap<usize, RegClass>,
         next_vreg: &mut u32,
         vreg_classes: &mut std::collections::BTreeMap<VReg, RegClass>| {
            let entry = local_vregs.entry(local).or_insert_with(|| {
                let class = local_classes.get(&local).copied().unwrap_or(class_hint);
                let id = VReg(*next_vreg);
                *next_vreg += 1;
                vreg_classes.insert(id, class);
                id
            });
            let class = local_classes.entry(local).or_insert(class_hint);
            if *class != class_hint && local == idx_local {
                *class = RegClass::Gpr;
                vreg_classes.insert(*entry, RegClass::Gpr);
            }
            *entry
        };

    let block_id = BlockId(0);
    for (idx, op) in body.iter().enumerate() {
        let inst_idx = InstIdx(idx as u16);
        let id = InstId {
            block: block_id,
            idx: inst_idx,
        };

        let kind = match op {
            jit::TraceOp::IndexListNumLocalPtr(list_local, idx_local_op, data_ptr) => {
                if *idx_local_op != idx_local {
                    return None;
                }
                let dst = new_vreg(RegClass::Xmm, &mut next_vreg, &mut vreg_classes);
                stack.push(dst);
                LoopInstKind::LoadListElemF64 {
                    dst,
                    list_local: *list_local,
                    idx_local: *idx_local_op,
                    data_ptr: *data_ptr,
                    offset: 0,
                }
            }
            jit::TraceOp::IndexListNumLocalPtrOff(list_local, idx_local_op, data_ptr, offset) => {
                if *idx_local_op != idx_local {
                    return None;
                }
                let dst = new_vreg(RegClass::Xmm, &mut next_vreg, &mut vreg_classes);
                stack.push(dst);
                LoopInstKind::LoadListElemF64 {
                    dst,
                    list_local: *list_local,
                    idx_local: *idx_local_op,
                    data_ptr: *data_ptr,
                    offset: *offset,
                }
            }
            jit::TraceOp::LoadLocal(local) => {
                let class_hint = if *local == idx_local {
                    RegClass::Gpr
                } else {
                    RegClass::Xmm
                };
                let reg = local_vreg(
                    *local,
                    class_hint,
                    &mut local_vregs,
                    &mut local_classes,
                    &mut next_vreg,
                    &mut vreg_classes,
                );
                stack.push(reg);
                continue;
            }
            jit::TraceOp::StoreLocal(local) => {
                let src = stack.pop()?;
                let class_hint = vreg_classes.get(&src).copied().unwrap_or(RegClass::Xmm);
                let dst = local_vreg(
                    *local,
                    class_hint,
                    &mut local_vregs,
                    &mut local_classes,
                    &mut next_vreg,
                    &mut vreg_classes,
                );
                LoopInstKind::MoveToLocal {
                    local: *local,
                    dst,
                    src,
                }
            }
            jit::TraceOp::MulNum => {
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                let dst = new_vreg(RegClass::Xmm, &mut next_vreg, &mut vreg_classes);
                stack.push(dst);
                LoopInstKind::MulF64 { dst, lhs, rhs }
            }
            jit::TraceOp::AddNum => {
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                let dst = new_vreg(RegClass::Xmm, &mut next_vreg, &mut vreg_classes);
                stack.push(dst);
                LoopInstKind::AddF64 { dst, lhs, rhs }
            }
            jit::TraceOp::AddLocalFromStack(local) => {
                let rhs = stack.pop()?;
                let acc = local_vreg(
                    *local,
                    RegClass::Xmm,
                    &mut local_vregs,
                    &mut local_classes,
                    &mut next_vreg,
                    &mut vreg_classes,
                );
                LoopInstKind::AddAssignLocalFromStack {
                    local: *local,
                    acc,
                    rhs,
                }
            }
            jit::TraceOp::AddLocalConst(local, imm) => {
                let class_hint = if *local == idx_local {
                    RegClass::Gpr
                } else {
                    RegClass::Xmm
                };
                let reg = local_vreg(
                    *local,
                    class_hint,
                    &mut local_vregs,
                    &mut local_classes,
                    &mut next_vreg,
                    &mut vreg_classes,
                );
                LoopInstKind::AddAssignLocalConst {
                    local: *local,
                    reg,
                    imm: *imm,
                }
            }
            _ => return None,
        };
        let info = build_loop_inst_info(&kind);
        insts.push(LoopInst { id, kind, info });
    }

    if insts.is_empty() {
        return None;
    }

    Some(LoopIr {
        blocks: vec![LoopBlock {
            id: block_id,
            insts,
        }],
        rpo_blocks: vec![block_id],
        header: block_id,
        latch: block_id,
        vreg_classes,
    })
}

fn linearize_loop_ir(loop_ir: &LoopIr) -> Option<Vec<LinearInst>> {
    let mut blocks_by_id: std::collections::BTreeMap<BlockId, &LoopBlock> =
        std::collections::BTreeMap::new();
    for block in &loop_ir.blocks {
        blocks_by_id.insert(block.id, block);
    }
    let mut linear: Vec<LinearInst> = Vec::new();
    let mut linear_pos = 0u32;
    for block_id in &loop_ir.rpo_blocks {
        let block = blocks_by_id.get(block_id)?;
        for inst in &block.insts {
            linear.push(LinearInst {
                inst_id: inst.id,
                linear_pos,
                info: inst.info.clone(),
                kind: inst.kind.clone(),
            });
            linear_pos += 1;
        }
    }
    Some(linear)
}

fn compute_loop_block_liveness(
    loop_ir: &LoopIr,
) -> std::collections::BTreeMap<BlockId, BlockLiveness> {
    let mut out: std::collections::BTreeMap<BlockId, BlockLiveness> =
        std::collections::BTreeMap::new();
    for block in &loop_ir.blocks {
        let mut defs: std::collections::BTreeSet<VReg> = std::collections::BTreeSet::new();
        let mut uses_before_def: std::collections::BTreeSet<VReg> =
            std::collections::BTreeSet::new();
        for inst in &block.insts {
            for u in &inst.info.uses {
                if !defs.contains(u) {
                    uses_before_def.insert(*u);
                }
            }
            for d in &inst.info.defs {
                defs.insert(*d);
            }
        }
        out.insert(
            block.id,
            BlockLiveness {
                live_in: uses_before_def.clone(),
                // Self-loop canonical block: successor is the header itself.
                live_out: uses_before_def,
            },
        );
    }
    out
}

fn build_loop_intervals(loop_ir: &LoopIr, linear: &[LinearInst]) -> Vec<VRegInterval> {
    if linear.is_empty() {
        return Vec::new();
    }
    let header_pos = linear.first().map(|inst| inst.linear_pos).unwrap_or(0);
    let loop_end_pos = linear.last().map(|inst| inst.linear_pos).unwrap_or(0);

    let mut starts: std::collections::BTreeMap<VReg, u32> = std::collections::BTreeMap::new();
    let mut ends: std::collections::BTreeMap<VReg, u32> = std::collections::BTreeMap::new();

    for inst in linear {
        for d in &inst.info.defs {
            starts.entry(*d).or_insert(inst.linear_pos);
        }
    }
    for inst in linear.iter().rev() {
        for u in &inst.info.uses {
            let e = ends.entry(*u).or_insert(inst.linear_pos);
            *e = (*e).max(inst.linear_pos);
        }
    }

    let block_liveness = compute_loop_block_liveness(loop_ir);
    if let Some(live) = block_liveness.get(&loop_ir.header) {
        for vreg in &live.live_in {
            match starts.get_mut(vreg) {
                Some(start) => {
                    *start = (*start).min(header_pos);
                }
                None => {
                    starts.insert(*vreg, header_pos);
                }
            }
            match ends.get_mut(vreg) {
                Some(end) => {
                    *end = (*end).max(header_pos);
                }
                None => {
                    ends.insert(*vreg, header_pos);
                }
            }
        }
        for vreg in live.live_in.intersection(&live.live_out) {
            let end = ends.entry(*vreg).or_insert(loop_end_pos);
            *end = (*end).max(loop_end_pos);
        }
    }

    let mut intervals: Vec<VRegInterval> = Vec::new();
    let mut seen: std::collections::BTreeSet<VReg> = std::collections::BTreeSet::new();
    for inst in linear {
        for vreg in inst.info.defs.iter().chain(inst.info.uses.iter()) {
            if seen.contains(vreg) {
                continue;
            }
            seen.insert(*vreg);
            let start = starts.get(vreg).copied().unwrap_or(header_pos);
            let end = ends.get(vreg).copied().unwrap_or(start);
            let class = loop_ir
                .vreg_classes
                .get(vreg)
                .copied()
                .unwrap_or(RegClass::Xmm);
            intervals.push(VRegInterval {
                vreg: *vreg,
                class,
                start,
                end: end.max(start),
            });
        }
    }
    intervals.sort_by_key(|iv| iv.start);
    intervals
}

fn linear_scan_allocate_class(
    intervals: &[VRegInterval],
    class: RegClass,
    regs: &[u8],
    next_spill_slot: &mut u32,
) -> (Vec<VRegAlloc>, usize) {
    #[derive(Clone, Copy)]
    struct Active {
        alloc_idx: usize,
        end: u32,
        reg: u8,
    }

    let mut cls_intervals: Vec<VRegInterval> = intervals
        .iter()
        .filter(|iv| iv.class == class)
        .cloned()
        .collect();
    cls_intervals.sort_by_key(|iv| iv.start);

    let mut allocs: Vec<VRegAlloc> = Vec::new();
    let mut active: Vec<Active> = Vec::new();
    let mut free_regs: Vec<u8> = regs.to_vec();
    free_regs.sort_unstable();
    let mut max_live_phys = 0usize;

    for iv in cls_intervals {
        let mut i = 0usize;
        while i < active.len() {
            if active[i].end < iv.start {
                free_regs.push(active[i].reg);
                active.remove(i);
            } else {
                i += 1;
            }
        }
        free_regs.sort_unstable();
        max_live_phys = max_live_phys.max(active.len());

        let make_reg_loc = |reg: u8| match class {
            RegClass::Xmm => PhysLoc::Xmm(reg),
            RegClass::Gpr => PhysLoc::Gpr(reg),
        };

        if let Some(reg) = free_regs.first().copied() {
            free_regs.remove(0);
            let alloc_idx = allocs.len();
            allocs.push(VRegAlloc {
                vreg: iv.vreg,
                class,
                start: iv.start,
                end: iv.end,
                loc: make_reg_loc(reg),
            });
            active.push(Active {
                alloc_idx,
                end: iv.end,
                reg,
            });
            max_live_phys = max_live_phys.max(active.len());
            continue;
        }

        if active.is_empty() {
            allocs.push(VRegAlloc {
                vreg: iv.vreg,
                class,
                start: iv.start,
                end: iv.end,
                loc: PhysLoc::Spill(*next_spill_slot),
            });
            *next_spill_slot = next_spill_slot.saturating_add(1);
            continue;
        }

        let mut victim_pos = 0usize;
        for pos in 1..active.len() {
            if active[pos].end > active[victim_pos].end {
                victim_pos = pos;
            }
        }
        let victim = active[victim_pos];
        if victim.end > iv.end {
            allocs[victim.alloc_idx].loc = PhysLoc::Spill(*next_spill_slot);
            *next_spill_slot = next_spill_slot.saturating_add(1);

            let reg = victim.reg;
            active.remove(victim_pos);
            let alloc_idx = allocs.len();
            allocs.push(VRegAlloc {
                vreg: iv.vreg,
                class,
                start: iv.start,
                end: iv.end,
                loc: make_reg_loc(reg),
            });
            active.push(Active {
                alloc_idx,
                end: iv.end,
                reg,
            });
            max_live_phys = max_live_phys.max(active.len());
        } else {
            allocs.push(VRegAlloc {
                vreg: iv.vreg,
                class,
                start: iv.start,
                end: iv.end,
                loc: PhysLoc::Spill(*next_spill_slot),
            });
            *next_spill_slot = next_spill_slot.saturating_add(1);
        }
    }

    (allocs, max_live_phys)
}

fn linear_scan_allocate(intervals: &[VRegInterval]) -> (Vec<VRegAlloc>, usize, usize, usize) {
    let mut next_spill_slot = 0u32;
    let (mut xmm_allocs, max_live_phys_xmm) = linear_scan_allocate_class(
        intervals,
        RegClass::Xmm,
        &[2, 3, 4, 5, 6, 7, 8, 9],
        &mut next_spill_slot,
    );
    let (mut gpr_allocs, max_live_phys_gpr) = linear_scan_allocate_class(
        intervals,
        RegClass::Gpr,
        &[12, 13, 14, 15],
        &mut next_spill_slot,
    );
    let mut allocs = Vec::with_capacity(xmm_allocs.len() + gpr_allocs.len());
    allocs.append(&mut xmm_allocs);
    allocs.append(&mut gpr_allocs);
    allocs.sort_by_key(|a| (a.start, a.end, a.vreg.0));
    let spill_count = allocs
        .iter()
        .filter(|a| matches!(a.loc, PhysLoc::Spill(_)))
        .count();
    (allocs, spill_count, max_live_phys_xmm, max_live_phys_gpr)
}

fn report_loop_intervals(ops: &[jit::TraceOp]) -> Option<LoopIntervalReport> {
    let loop_ir = build_dot_product_loop_ir(ops)?;
    let linear = linearize_loop_ir(&loop_ir)?;
    let block_liveness = compute_loop_block_liveness(&loop_ir);
    let intervals = build_loop_intervals(&loop_ir, &linear);
    let (allocs, spill_count, max_live_phys_xmm, max_live_phys_gpr) =
        linear_scan_allocate(&intervals);
    if linear.is_empty() {
        return None;
    }

    let min_pos = linear.first().map(|inst| inst.linear_pos).unwrap_or(0);
    let max_pos = linear.last().map(|inst| inst.linear_pos).unwrap_or(0);
    let mut max_live_vregs = 0usize;
    let mut max_live_xmm = 0usize;
    let mut max_live_gpr = 0usize;
    for pos in min_pos..=max_pos {
        let mut live_any = 0usize;
        let mut live_xmm = 0usize;
        let mut live_gpr = 0usize;
        for iv in &intervals {
            if pos < iv.start || pos > iv.end {
                continue;
            }
            live_any += 1;
            match iv.class {
                RegClass::Xmm => live_xmm += 1,
                RegClass::Gpr => live_gpr += 1,
            }
        }
        max_live_vregs = max_live_vregs.max(live_any);
        max_live_xmm = max_live_xmm.max(live_xmm);
        max_live_gpr = max_live_gpr.max(live_gpr);
    }

    Some(LoopIntervalReport {
        interval_count: intervals.len(),
        max_live_vregs,
        max_live_xmm,
        max_live_gpr,
        max_live_phys_xmm,
        max_live_phys_gpr,
        spill_count,
        allocs,
        linear,
        intervals,
        block_liveness,
    })
}

fn dump_loop_interval_report(report: &LoopIntervalReport) {
    trace_debug_log("loopir linear:");
    for inst in &report.linear {
        trace_debug_log(&format!(
            "  pos={} id=({},{}) defs={:?} uses={:?} class={:?} sidefx={} kind={:?}",
            inst.linear_pos,
            inst.inst_id.block.0,
            inst.inst_id.idx.0,
            inst.info.defs,
            inst.info.uses,
            inst.info.class_constraints,
            inst.info.has_side_effect,
            inst.kind
        ));
    }
    trace_debug_log("loopir intervals:");
    for iv in &report.intervals {
        trace_debug_log(&format!(
            "  v{:?} class={:?} [{}..={}]",
            iv.vreg.0, iv.class, iv.start, iv.end
        ));
    }
    trace_debug_log("loopir alloc:");
    for alloc in &report.allocs {
        trace_debug_log(&format!(
            "  v{} class={:?} [{}..={}] -> {:?}",
            alloc.vreg.0, alloc.class, alloc.start, alloc.end, alloc.loc
        ));
    }
    for (block, live) in &report.block_liveness {
        trace_debug_log(&format!(
            "  block {} live_in={:?} live_out={:?}",
            block.0, live.live_in, live.live_out
        ));
    }
    trace_debug_log(&format!(
        "loopir metrics: intervals={} max_live={} max_live_xmm={} max_live_gpr={} max_live_phys_xmm={} max_live_phys_gpr={} spill_count={}",
        report.interval_count,
        report.max_live_vregs,
        report.max_live_xmm,
        report.max_live_gpr,
        report.max_live_phys_xmm,
        report.max_live_phys_gpr,
        report.spill_count
    ));
}

fn select_promoted_locals(ops: &[jit::TraceOp]) -> Vec<usize> {
    let mut has_call_like = false;
    for op in ops {
        if matches!(
            op,
            jit::TraceOp::MakeList(_)
                | jit::TraceOp::MakeMap(_)
                | jit::TraceOp::MakeListTemp(_)
                | jit::TraceOp::MakeMapTemp(_)
                | jit::TraceOp::LoadField(_)
                | jit::TraceOp::ToText
        ) {
            has_call_like = true;
            break;
        }
        if matches!(
            op,
            jit::TraceOp::MapGetSlot(_)
                | jit::TraceOp::MapGetSlotNoVerGuard(_, _, _, _, _)
                | jit::TraceOp::MapGetSlotPtr(_)
                | jit::TraceOp::MapGetSmallKeyNoVer(_, _, _, _, _)
                | jit::TraceOp::MapGetTextKeyNoVer(_, _, _, _, _)
                | jit::TraceOp::MapGetTextKeyConstNoVer(_, _, _, _, _, _, _, _, _)
                | jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(_, _, _, _, _, _, _)
                | jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(_, _, _, _, _)
                | jit::TraceOp::MapGetTextKeyConstSlotPtrStableAddLocalNoVer(_, _, _, _, _, _)
                | jit::TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(_, _, _, _, _, _, _, _, _, _)
                | jit::TraceOp::MapSetSlotPtrNoVer(_, _)
                | jit::TraceOp::MapSetSlotPtrNoVerGuard(_, _, _, _, _)
                | jit::TraceOp::MapSetSlotNoVer(_, _)
                | jit::TraceOp::MapSetSlotNoVerGuard(_, _, _, _, _)
                | jit::TraceOp::MapSetSmallKeyNoVer(_, _, _, _, _)
                | jit::TraceOp::MapSetTextKeyNoVer(_, _, _, _, _)
                | jit::TraceOp::MapSetTextKeyConstNoVer(_, _, _, _, _, _, _, _, _)
                | jit::TraceOp::MapSetTextKeyConstSlotPtrNoVer(_, _, _, _, _, _, _)
                | jit::TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(_, _, _, _, _, _, _, _, _, _)
        ) {
            has_call_like = true;
            break;
        }
    }
    if has_call_like {
        return Vec::new();
    }

    let mut stored: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for op in ops {
        if let jit::TraceOp::StoreLocal(idx) = op {
            stored.insert(*idx);
        }
    }

    let mut out: Vec<usize> = Vec::new();
    for op in ops {
        if let jit::TraceOp::AddLocalFromStack(idx) = op {
            if !stored.contains(idx) && !out.contains(idx) {
                out.push(*idx);
            }
        }
    }
    for op in ops {
        if let jit::TraceOp::AddLocalConst(idx, _) = op {
            if !stored.contains(idx) && !out.contains(idx) {
                out.push(*idx);
            }
        }
    }
    out.truncate(6);
    out
}

fn mark_temp_allocs(
    ops: &[jit::TraceOp],
    write_first_locals: &std::collections::BTreeSet<usize>,
) -> Vec<jit::TraceOp> {
    #[derive(Clone, Copy)]
    enum TempAllocRef {
        List(usize),
        Map(usize),
    }

    let mut out = ops.to_vec();
    let mut stack: Vec<Option<TempAllocRef>> = Vec::new();
    let mut locals: std::collections::HashMap<usize, Option<TempAllocRef>> =
        std::collections::HashMap::new();

    let mut list_make_indices: Vec<usize> = Vec::new();
    let mut list_make_lens: Vec<usize> = Vec::new();
    let mut list_escapes: Vec<bool> = Vec::new();

    let mut map_make_indices: Vec<usize> = Vec::new();
    let mut map_make_keys: Vec<Vec<String>> = Vec::new();
    let mut map_escapes: Vec<bool> = Vec::new();

    let mark_escape = |item: TempAllocRef,
                       list_escapes: &mut Vec<bool>,
                       map_escapes: &mut Vec<bool>| {
        match item {
            TempAllocRef::List(id) => {
                if let Some(slot) = list_escapes.get_mut(id) {
                    *slot = true;
                }
            }
            TempAllocRef::Map(id) => {
                if let Some(slot) = map_escapes.get_mut(id) {
                    *slot = true;
                }
            }
        }
    };

    for (idx, op) in out.iter().enumerate() {
        match op {
            jit::TraceOp::ConstNum(_)
            | jit::TraceOp::ConstBool(_)
            | jit::TraceOp::ConstText(_)
            | jit::TraceOp::PushNull
            | jit::TraceOp::LenListLocal(_)
            | jit::TraceOp::IndexListNumLocal(_, _)
            | jit::TraceOp::IndexListNumLocalPtr(_, _, _)
            | jit::TraceOp::IndexListNumLocalPtrOff(_, _, _, _) => {
                stack.push(None);
            }
            jit::TraceOp::Dup => {
                let top = stack.last().copied().unwrap_or(None);
                stack.push(top);
            }
            jit::TraceOp::LoadLocal(idx) => {
                stack.push(locals.get(idx).copied().unwrap_or(None));
            }
            jit::TraceOp::StoreLocal(_) => {
                if let jit::TraceOp::StoreLocal(local_idx) = op {
                    let value = stack.pop().unwrap_or(None);
                    locals.insert(*local_idx, value);
                }
            }
            jit::TraceOp::InitLocalConst(local_idx, _) => {
                locals.insert(*local_idx, None);
            }
            jit::TraceOp::AddLocalConst(_, _) => {}
            jit::TraceOp::AddLocalFromStack(_) => {
                let _ = stack.pop();
            }
            jit::TraceOp::MakeList(len) => {
                for _ in 0..*len {
                    let _ = stack.pop();
                }
                let id = list_make_indices.len();
                list_make_indices.push(idx);
                list_make_lens.push(*len);
                list_escapes.push(false);
                stack.push(Some(TempAllocRef::List(id)));
            }
            jit::TraceOp::MakeListTemp(len) => {
                for _ in 0..*len {
                    let _ = stack.pop();
                }
                stack.push(None);
            }
            jit::TraceOp::MakeMap(keys) => {
                for _ in 0..keys.len() {
                    let _ = stack.pop();
                }
                let id = map_make_indices.len();
                map_make_indices.push(idx);
                map_make_keys.push(keys.clone());
                map_escapes.push(false);
                stack.push(Some(TempAllocRef::Map(id)));
            }
            jit::TraceOp::MakeMapTemp(keys) => {
                for _ in 0..keys.len() {
                    let _ = stack.pop();
                }
                stack.push(None);
            }
            jit::TraceOp::AddNum
            | jit::TraceOp::SubNum
            | jit::TraceOp::MulNum
            | jit::TraceOp::DivNum
            | jit::TraceOp::EqNum
            | jit::TraceOp::NeNum
            | jit::TraceOp::LtNum
            | jit::TraceOp::LeNum
            | jit::TraceOp::GtNum
            | jit::TraceOp::GeNum => {
                let _ = stack.pop();
                let _ = stack.pop();
                stack.push(None);
            }
            jit::TraceOp::IndexListNum => {
                let _ = stack.pop();
                let _ = stack.pop();
                stack.push(None);
            }
            jit::TraceOp::SetIndexListNum => {
                let _ = stack.pop();
                let _ = stack.pop();
                let target = stack.pop().unwrap_or(None);
                stack.push(target);
            }
            jit::TraceOp::SetIndexListNumLocalPtr(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalNoVer(_, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVer(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(_, _, _, _)
            | jit::TraceOp::MapSetSlotPtrNoVer(_, _)
            | jit::TraceOp::MapSetSlotPtrNoVerGuard(_, _, _, _, _)
            | jit::TraceOp::MapSetSlotNoVer(_, _)
            | jit::TraceOp::MapSetSlotNoVerGuard(_, _, _, _, _)
            | jit::TraceOp::MapSetSmallKeyNoVer(_, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyNoVer(_, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstNoVer(_, _, _, _, _, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstSlotPtrNoVer(_, _, _, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(_, _, _, _, _, _, _, _, _, _) => {
                let _ = stack.pop();
                let _ = stack.pop();
                let target = stack.pop().unwrap_or(None);
                stack.push(target);
            }
            jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(_, _, _, _) => {
                let _ = stack.pop();
                stack.push(None);
            }
            jit::TraceOp::LenList => {
                let _ = stack.pop();
                stack.push(None);
            }
            jit::TraceOp::LoadField(_)
            | jit::TraceOp::MapGetSlot(_)
            | jit::TraceOp::MapGetSlotNoVerGuard(_, _, _, _, _)
            | jit::TraceOp::MapGetSlotPtr(_)
            | jit::TraceOp::MapGetSlotPtrNoVer(_, _, _, _, _) => {
                let _ = stack.pop();
                stack.push(None);
            }
            jit::TraceOp::MapGetSmallKeyNoVer(_, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyNoVer(_, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstNoVer(_, _, _, _, _, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(_, _, _, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(_, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(_, _, _, _, _, _, _, _, _, _) => {
                let _ = stack.pop();
                let _ = stack.pop();
                stack.push(None);
            }
            jit::TraceOp::MapGetTextKeyConstSlotPtrStableAddLocalNoVer(_, _, _, _, _, _) => {
                let _ = stack.pop();
                let _ = stack.pop();
            }
            jit::TraceOp::Pop => {
                let _ = stack.pop();
            }
            jit::TraceOp::Return => {
                if let Some(Some(item)) = stack.pop() {
                    mark_escape(item, &mut list_escapes, &mut map_escapes);
                }
            }
            jit::TraceOp::JumpStart
            | jit::TraceOp::Label(_)
            | jit::TraceOp::JumpTo(_)
            | jit::TraceOp::BranchFalse(_)
            | jit::TraceOp::GuardFalse
            | jit::TraceOp::GuardFalseDeopt(_)
            | jit::TraceOp::GuardListBounds(_, _)
            | jit::TraceOp::GuardIndexNonNeg(_)
            | jit::TraceOp::GuardIndexCmpConst(_, _, _)
            | jit::TraceOp::GuardIndexRangeConst(_, _, _)
            | jit::TraceOp::GuardListNoAliasSameLen(_, _)
            | jit::TraceOp::ToText
            | jit::TraceOp::BumpListVersionLocal(_)
            | jit::TraceOp::BumpMapVersionLocal(_) => {
                if matches!(
                    op,
                    jit::TraceOp::JumpStart
                        | jit::TraceOp::JumpTo(_)
                        | jit::TraceOp::BranchFalse(_)
                ) {
                    for (local_idx, temp) in &locals {
                        if write_first_locals.contains(local_idx) {
                            continue;
                        }
                        if let Some(item) = temp {
                            mark_escape(*item, &mut list_escapes, &mut map_escapes);
                        }
                    }
                    for item in stack.iter().flatten() {
                        mark_escape(*item, &mut list_escapes, &mut map_escapes);
                    }
                }
            }
        }
    }

    for (i, make_idx) in list_make_indices.iter().enumerate() {
        if !list_escapes.get(i).copied().unwrap_or(true) {
            out[*make_idx] = jit::TraceOp::MakeListTemp(list_make_lens[i]);
        }
    }
    for (i, make_idx) in map_make_indices.iter().enumerate() {
        if !map_escapes.get(i).copied().unwrap_or(true) {
            out[*make_idx] = jit::TraceOp::MakeMapTemp(map_make_keys[i].clone());
        }
    }

    out
}

fn collect_temp_list_sources(ops: &[jit::TraceOp]) -> Vec<jit::TempListSource> {
    fn pop_or_unknown(stack: &mut Vec<jit::TempValueSource>) -> jit::TempValueSource {
        stack.pop().unwrap_or(jit::TempValueSource::Unknown)
    }

    fn invalidate_local(stack: &mut [jit::TempValueSource], idx: usize) {
        for src in stack.iter_mut() {
            if matches!(src, jit::TempValueSource::Local(local) if *local == idx) {
                *src = jit::TempValueSource::Unknown;
            }
        }
    }

    let mut stack: Vec<jit::TempValueSource> = Vec::new();
    let mut out: Vec<jit::TempListSource> = Vec::new();

    for (op_idx, op) in ops.iter().enumerate() {
        match op {
            jit::TraceOp::ConstNum(n) => stack.push(jit::TempValueSource::ConstNum(*n)),
            jit::TraceOp::LoadLocal(idx) => stack.push(jit::TempValueSource::Local(*idx)),
            jit::TraceOp::ConstBool(_)
            | jit::TraceOp::ConstText(_)
            | jit::TraceOp::PushNull
            | jit::TraceOp::LenListLocal(_)
            | jit::TraceOp::IndexListNumLocal(_, _)
            | jit::TraceOp::IndexListNumLocalPtr(_, _, _)
            | jit::TraceOp::IndexListNumLocalPtrOff(_, _, _, _) => {
                stack.push(jit::TempValueSource::Unknown);
            }
            jit::TraceOp::Dup => {
                let top = stack
                    .last()
                    .cloned()
                    .unwrap_or(jit::TempValueSource::Unknown);
                stack.push(top);
            }
            jit::TraceOp::StoreLocal(idx) => {
                let _ = pop_or_unknown(&mut stack);
                invalidate_local(&mut stack, *idx);
            }
            jit::TraceOp::BranchFalse(_)
            | jit::TraceOp::GuardFalse
            | jit::TraceOp::GuardFalseDeopt(_)
            | jit::TraceOp::Pop => {
                let _ = pop_or_unknown(&mut stack);
            }
            jit::TraceOp::AddLocalConst(idx, _) => {
                invalidate_local(&mut stack, *idx);
            }
            jit::TraceOp::InitLocalConst(idx, _) => {
                invalidate_local(&mut stack, *idx);
            }
            jit::TraceOp::AddLocalFromStack(idx) => {
                let _ = pop_or_unknown(&mut stack);
                invalidate_local(&mut stack, *idx);
            }
            jit::TraceOp::AddNum
            | jit::TraceOp::SubNum
            | jit::TraceOp::MulNum
            | jit::TraceOp::DivNum
            | jit::TraceOp::EqNum
            | jit::TraceOp::NeNum
            | jit::TraceOp::LtNum
            | jit::TraceOp::LeNum
            | jit::TraceOp::GtNum
            | jit::TraceOp::GeNum => {
                let _ = pop_or_unknown(&mut stack);
                let _ = pop_or_unknown(&mut stack);
                stack.push(jit::TempValueSource::Unknown);
            }
            jit::TraceOp::SetIndexListNumLocalPtrNoVerFast(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOffFast(_, _, _, _) => {
                let _ = pop_or_unknown(&mut stack);
                stack.push(jit::TempValueSource::Unknown);
            }
            jit::TraceOp::MakeList(len) | jit::TraceOp::MakeListTemp(len) => {
                let pop_len = (*len).min(stack.len());
                let start = stack.len().saturating_sub(pop_len);
                let sources = stack[start..].to_vec();
                if matches!(op, jit::TraceOp::MakeListTemp(_)) {
                    out.push(jit::TempListSource {
                        trace_op_index: op_idx,
                        len: *len,
                        sources,
                    });
                }
                stack.truncate(start);
                stack.push(jit::TempValueSource::Unknown);
            }
            jit::TraceOp::MakeMap(keys) | jit::TraceOp::MakeMapTemp(keys) => {
                let pop_len = keys.len().min(stack.len());
                let start = stack.len().saturating_sub(pop_len);
                stack.truncate(start);
                stack.push(jit::TempValueSource::Unknown);
            }
            jit::TraceOp::LoadField(_)
            | jit::TraceOp::MapGetSlot(_)
            | jit::TraceOp::MapGetSlotNoVerGuard(_, _, _, _, _)
            | jit::TraceOp::MapGetSlotPtr(_)
            | jit::TraceOp::MapGetSlotPtrNoVer(_, _, _, _, _)
            | jit::TraceOp::LenList
            | jit::TraceOp::ToText => {
                if let Some(last) = stack.last_mut() {
                    *last = jit::TempValueSource::Unknown;
                } else {
                    stack.push(jit::TempValueSource::Unknown);
                }
            }
            jit::TraceOp::MapGetSmallKeyNoVer(_, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyNoVer(_, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstNoVer(_, _, _, _, _, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(_, _, _, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(_, _, _, _, _)
            | jit::TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(_, _, _, _, _, _, _, _, _, _)
            | jit::TraceOp::IndexListNum => {
                let _ = pop_or_unknown(&mut stack);
                let _ = pop_or_unknown(&mut stack);
                stack.push(jit::TempValueSource::Unknown);
            }
            jit::TraceOp::MapGetTextKeyConstSlotPtrStableAddLocalNoVer(_, _, _, _, _, _) => {
                let _ = pop_or_unknown(&mut stack);
                let _ = pop_or_unknown(&mut stack);
            }
            jit::TraceOp::SetIndexListNum
            | jit::TraceOp::SetIndexListNumLocalPtr(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalNoVer(_, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVer(_, _, _)
            | jit::TraceOp::SetIndexListNumLocalPtrNoVerOff(_, _, _, _)
            | jit::TraceOp::MapSetSlotPtrNoVer(_, _)
            | jit::TraceOp::MapSetSlotPtrNoVerGuard(_, _, _, _, _)
            | jit::TraceOp::MapSetSlotNoVer(_, _)
            | jit::TraceOp::MapSetSlotNoVerGuard(_, _, _, _, _)
            | jit::TraceOp::MapSetSmallKeyNoVer(_, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyNoVer(_, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstNoVer(_, _, _, _, _, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstSlotPtrNoVer(_, _, _, _, _, _, _)
            | jit::TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(_, _, _, _, _, _, _, _, _, _) => {
                let _ = pop_or_unknown(&mut stack);
                let _ = pop_or_unknown(&mut stack);
                let _ = pop_or_unknown(&mut stack);
                stack.push(jit::TempValueSource::Unknown);
            }
            jit::TraceOp::Return => {
                let _ = pop_or_unknown(&mut stack);
            }
            jit::TraceOp::GuardListBounds(_, _)
            | jit::TraceOp::GuardIndexNonNeg(_)
            | jit::TraceOp::GuardIndexCmpConst(_, _, _)
            | jit::TraceOp::GuardIndexRangeConst(_, _, _)
            | jit::TraceOp::GuardListNoAliasSameLen(_, _)
            | jit::TraceOp::Label(_)
            | jit::TraceOp::JumpTo(_)
            | jit::TraceOp::JumpStart
            | jit::TraceOp::BumpListVersionLocal(_)
            | jit::TraceOp::BumpMapVersionLocal(_) => {}
        }
    }

    out
}

fn temp_list_source_checksum(sources: &[jit::TempListSource]) -> u64 {
    let mut acc: u64 = 0;
    for meta in sources {
        acc = acc
            .saturating_add(meta.trace_op_index as u64)
            .saturating_add(meta.len as u64);
        for src in &meta.sources {
            match src {
                jit::TempValueSource::Local(idx) => {
                    acc = acc.saturating_add(*idx as u64);
                }
                jit::TempValueSource::ConstNum(n) => {
                    acc = acc.saturating_add(n.to_bits());
                }
                jit::TempValueSource::Unknown => {
                    acc = acc.saturating_add(1);
                }
            }
        }
    }
    acc
}

fn simple_origin(origin: &ValueOrigin) -> Option<SimpleOrigin> {
    match origin {
        ValueOrigin::Local(idx) => Some(SimpleOrigin::Local(*idx)),
        ValueOrigin::ConstNum(n) => Some(SimpleOrigin::ConstNum(*n)),
        ValueOrigin::LenOfLocal(idx) => Some(SimpleOrigin::LenOfLocal(*idx)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct UnsafePolicy {
    skip_bounds_check: bool,
    allow_ptr_arith: bool,
}

fn unsafe_policy_for_ip(unsafe_flags: &[bool], ip: usize) -> UnsafePolicy {
    let enabled = unsafe_flags.get(ip).copied().unwrap_or(false);
    UnsafePolicy {
        skip_bounds_check: enabled,
        allow_ptr_arith: enabled,
    }
}

fn analyze_bounds_guards(
    code: &[Instr],
    start: usize,
    end: usize,
    locals: &[f64],
    runtime: &jit::JitRuntime,
) -> Option<std::collections::HashSet<(usize, usize)>> {
    let mut guards = std::collections::HashSet::new();
    let mut stack: Vec<ValueMeta> = Vec::new();

    for instr in &code[start..=end] {
        match instr {
            Instr::ConstNum(n) => stack.push(ValueMeta {
                ty: TraceTy::Num,
                origin: ValueOrigin::ConstNum(*n),
            }),
            Instr::ConstBool(b) => stack.push(ValueMeta {
                ty: TraceTy::Num,
                origin: ValueOrigin::ConstNum(if *b { 1.0 } else { 0.0 }),
            }),
            Instr::ConstText(s) => stack.push(ValueMeta {
                ty: TraceTy::Text,
                origin: ValueOrigin::ConstText(s.clone()),
            }),
            Instr::PushNull => stack.push(ValueMeta {
                ty: TraceTy::Null,
                origin: ValueOrigin::Unknown,
            }),
            Instr::LoadLocal(idx) => {
                let bits = locals.get(*idx).copied().unwrap_or(0.0).to_bits();
                let ty = ty_from_bits(bits, runtime);
                if matches!(ty, TraceTy::Unknown) {
                    trace_debug_log("analyze_bounds_guards: unknown type in LoadLocal");
                    return None;
                }
                stack.push(ValueMeta {
                    ty,
                    origin: ValueOrigin::Local(*idx),
                });
            }
            Instr::StoreLocal(_) => {
                stack.pop()?;
            }
            Instr::StoreLocalKeep(idx) => {
                stack.last_mut()?.origin = ValueOrigin::Local(*idx);
            }
            Instr::AddLocalConst(_, _) => {}
            Instr::Add | Instr::Sub | Instr::Mul | Instr::Div | Instr::Eq | Instr::Ne => {
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                if !matches!(lhs.ty, TraceTy::Num) || !matches!(rhs.ty, TraceTy::Num) {
                    trace_debug_log("analyze_bounds_guards: numeric op on non-num");
                    return None;
                }
                stack.push(ValueMeta {
                    ty: TraceTy::Num,
                    origin: ValueOrigin::Unknown,
                });
            }
            Instr::Lt | Instr::Le | Instr::Gt | Instr::Ge => {
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                if !matches!(lhs.ty, TraceTy::Num) || !matches!(rhs.ty, TraceTy::Num) {
                    trace_debug_log("analyze_bounds_guards: cmp on non-num");
                    return None;
                }
                let kind = match instr {
                    Instr::Lt => CmpKindSimple::Lt,
                    Instr::Le => CmpKindSimple::Le,
                    Instr::Gt => CmpKindSimple::Gt,
                    Instr::Ge => CmpKindSimple::Ge,
                    _ => CmpKindSimple::Lt,
                };
                let origin = match (simple_origin(&lhs.origin), simple_origin(&rhs.origin)) {
                    (Some(l), Some(r)) => ValueOrigin::Compare(CmpMeta {
                        kind,
                        lhs: l,
                        rhs: r,
                    }),
                    _ => ValueOrigin::Unknown,
                };
                stack.push(ValueMeta {
                    ty: TraceTy::Num,
                    origin,
                });
            }
            Instr::JumpIfFalse(_) => {
                let cond = stack.pop()?;
                if let ValueOrigin::Compare(meta) = cond.origin {
                    match (meta.kind, meta.lhs, meta.rhs) {
                        (
                            CmpKindSimple::Lt | CmpKindSimple::Le,
                            SimpleOrigin::Local(i),
                            SimpleOrigin::LenOfLocal(list),
                        ) => {
                            guards.insert((list, i));
                        }
                        (
                            CmpKindSimple::Gt | CmpKindSimple::Ge,
                            SimpleOrigin::LenOfLocal(list),
                            SimpleOrigin::Local(i),
                        ) => {
                            guards.insert((list, i));
                        }
                        _ => {}
                    }
                }
            }
            Instr::JumpLocalIfFalse(_, _) => {}
            Instr::MakeList(len) => {
                for _ in 0..*len {
                    stack.pop()?;
                }
                stack.push(ValueMeta {
                    ty: TraceTy::Unknown,
                    origin: ValueOrigin::Unknown,
                });
            }
            Instr::MakeMap(keys) => {
                for _ in 0..keys.len() {
                    stack.pop()?;
                }
                stack.push(ValueMeta {
                    ty: TraceTy::Unknown,
                    origin: ValueOrigin::Unknown,
                });
            }
            Instr::LoadField(_) => {
                stack.pop()?;
                stack.push(ValueMeta {
                    ty: TraceTy::Unknown,
                    origin: ValueOrigin::Unknown,
                });
            }
            Instr::CallBuiltin(name, argc) if name == "__index" && *argc == 2 => {
                let idx = stack.pop()?;
                let target = stack.pop()?;
                let ty = match (target.ty, idx.ty) {
                    (TraceTy::List(ElemTag::Num), TraceTy::Num) => TraceTy::Num,
                    (TraceTy::Map(elem), TraceTy::Text) => ty_from_elem_tag(&elem),
                    _ => TraceTy::Unknown,
                };
                stack.push(ValueMeta {
                    ty,
                    origin: ValueOrigin::Unknown,
                });
            }
            Instr::CallBuiltin(name, argc) if name == "__setindex" && *argc == 3 => {
                let _val = stack.pop()?;
                let _idx = stack.pop()?;
                let target = stack.pop()?;
                stack.push(ValueMeta {
                    ty: target.ty,
                    origin: ValueOrigin::Unknown,
                });
            }
            Instr::CallBuiltin(name, argc) if name == "len" && *argc == 1 => {
                let target = stack.pop()?;
                let origin = match target.origin {
                    ValueOrigin::Local(idx) => ValueOrigin::LenOfLocal(idx),
                    _ => ValueOrigin::Unknown,
                };
                stack.push(ValueMeta {
                    ty: TraceTy::Num,
                    origin,
                });
            }
            Instr::Pop => {
                stack.pop()?;
            }
            Instr::Return => {
                stack.pop()?;
            }
            Instr::Jump(_) => {}
            _ => {}
        }
    }

    Some(guards)
}

fn bounds_guard_covers_list(
    bounds_guards: &std::collections::HashSet<(usize, usize)>,
    list_idx: usize,
    idx_local: usize,
    locals: &[f64],
) -> bool {
    if bounds_guards.contains(&(list_idx, idx_local)) {
        return true;
    }
    let Some(list_bits) = locals.get(list_idx).copied().map(f64::to_bits) else {
        return false;
    };
    bounds_guards.iter().any(|(guarded_list, guarded_idx)| {
        *guarded_idx == idx_local
            && locals.get(*guarded_list).copied().map(f64::to_bits) == Some(list_bits)
    })
}

fn build_trace_plan(
    code: &[Instr],
    start: usize,
    end: usize,
    locals: &[f64],
    runtime: &jit::JitRuntime,
    unsafe_flags: &[bool],
) -> Option<TracePlan> {
    let bounds_guards = analyze_bounds_guards(code, start, end, locals, runtime)?;
    let mut uses_bounds_guards = false;
    let mut ops: Vec<jit::TraceOp> = Vec::new();
    let mut mutated_lists: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut mutated_maps: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut pic_map_locals: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut unsafe_pic_map_locals: std::collections::BTreeSet<usize> =
        std::collections::BTreeSet::new();
    let mut mutated_locals: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut internal_targets: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut stack: Vec<ValueMeta> = Vec::new();
    let mut depth: i32 = 0;

    for (offset, instr) in code[start..=end].iter().enumerate() {
        let ip = start + offset;
        let target = match instr {
            Instr::Jump(target)
            | Instr::JumpIfFalse(target)
            | Instr::JumpLocalIfFalse(_, target) => Some(*target),
            _ => None,
        };
        if let Some(target) = target {
            if target >= start && target <= end && target != start {
                if target <= ip {
                    trace_debug_log("build_trace_plan: backward internal branch");
                    return None;
                }
                internal_targets.insert(target);
            }
        }
    }

    for (offset, instr) in code[start..=end].iter().enumerate() {
        let ip = start + offset;
        if internal_targets.contains(&ip) {
            ops.push(jit::TraceOp::Label(ip));
        }
        match instr {
            Instr::ConstNum(n) => {
                ops.push(jit::TraceOp::ConstNum(*n));
                stack.push(ValueMeta {
                    ty: TraceTy::Num,
                    origin: ValueOrigin::ConstNum(*n),
                });
                depth += 1;
            }
            Instr::ConstBool(b) => {
                ops.push(jit::TraceOp::ConstBool(*b));
                stack.push(ValueMeta {
                    ty: TraceTy::Num,
                    origin: ValueOrigin::ConstNum(if *b { 1.0 } else { 0.0 }),
                });
                depth += 1;
            }
            Instr::ConstText(s) => {
                ops.push(jit::TraceOp::ConstText(s.clone()));
                stack.push(ValueMeta {
                    ty: TraceTy::Text,
                    origin: ValueOrigin::ConstText(s.clone()),
                });
                depth += 1;
            }
            Instr::PushNull => {
                ops.push(jit::TraceOp::PushNull);
                stack.push(ValueMeta {
                    ty: TraceTy::Null,
                    origin: ValueOrigin::Unknown,
                });
                depth += 1;
            }
            Instr::LoadLocal(idx) => {
                let bits = locals.get(*idx).copied().unwrap_or(0.0).to_bits();
                let ty = ty_from_bits(bits, runtime);
                if matches!(ty, TraceTy::Unknown) {
                    trace_debug_log("build_trace_plan: unknown type in LoadLocal");
                    return None;
                }
                ops.push(jit::TraceOp::LoadLocal(*idx));
                stack.push(ValueMeta {
                    ty,
                    origin: ValueOrigin::Local(*idx),
                });
                depth += 1;
            }
            Instr::StoreLocal(idx) => {
                stack.pop()?;
                ops.push(jit::TraceOp::StoreLocal(*idx));
                mutated_locals.insert(*idx);
                depth -= 1;
            }
            Instr::StoreLocalKeep(idx) => {
                stack.last_mut()?.origin = ValueOrigin::Local(*idx);
                ops.push(jit::TraceOp::Dup);
                ops.push(jit::TraceOp::StoreLocal(*idx));
                mutated_locals.insert(*idx);
            }
            Instr::AddLocalConst(idx, c) => {
                ops.push(jit::TraceOp::AddLocalConst(*idx, *c));
                mutated_locals.insert(*idx);
            }
            Instr::Add
            | Instr::Sub
            | Instr::Mul
            | Instr::Div
            | Instr::Eq
            | Instr::Ne
            | Instr::Lt
            | Instr::Le
            | Instr::Gt
            | Instr::Ge => {
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                if !matches!(lhs.ty, TraceTy::Num) || !matches!(rhs.ty, TraceTy::Num) {
                    trace_debug_log("build_trace_plan: numeric op on non-num");
                    return None;
                }
                let op = match instr {
                    Instr::Add => jit::TraceOp::AddNum,
                    Instr::Sub => jit::TraceOp::SubNum,
                    Instr::Mul => jit::TraceOp::MulNum,
                    Instr::Div => jit::TraceOp::DivNum,
                    Instr::Eq => jit::TraceOp::EqNum,
                    Instr::Ne => jit::TraceOp::NeNum,
                    Instr::Lt => jit::TraceOp::LtNum,
                    Instr::Le => jit::TraceOp::LeNum,
                    Instr::Gt => jit::TraceOp::GtNum,
                    Instr::Ge => jit::TraceOp::GeNum,
                    _ => jit::TraceOp::AddNum,
                };
                ops.push(op);
                stack.push(ValueMeta {
                    ty: TraceTy::Num,
                    origin: ValueOrigin::Unknown,
                });
                depth -= 1;
            }
            Instr::Jump(target) => {
                if *target == start {
                    for &map_idx in &mutated_maps {
                        ops.push(jit::TraceOp::BumpMapVersionLocal(map_idx));
                    }
                    ops.push(jit::TraceOp::JumpStart);
                } else if *target > ip && *target <= end {
                    ops.push(jit::TraceOp::JumpTo(*target));
                } else {
                    trace_debug_log(&format!(
                        "build_trace_plan: unsupported internal jump target (target={}, loop_start={}, ip={})",
                        *target, start, ip
                    ));
                    return None;
                }
            }
            Instr::JumpIfFalse(target) => {
                let cond = stack.pop()?;
                if !matches!(cond.ty, TraceTy::Num) {
                    trace_debug_log("build_trace_plan: JumpIfFalse non-num cond");
                    return None;
                }
                if *target >= start && *target <= end {
                    // Allow forward internal branches by speculating the hot path and
                    // deoptimizing to the branch target when condition is false.
                    // Backward internal branches are still rejected to keep trace shape linear.
                    if *target <= ip {
                        trace_debug_log("build_trace_plan: JumpIfFalse backward inside trace");
                        return None;
                    }
                    ops.push(jit::TraceOp::BranchFalse(*target));
                } else {
                    ops.push(jit::TraceOp::GuardFalse);
                }
                depth -= 1;
            }
            Instr::JumpLocalIfFalse(idx, target) => {
                let bits = locals.get(*idx).copied().unwrap_or(0.0).to_bits();
                if !matches!(ty_from_bits(bits, runtime), TraceTy::Num) {
                    trace_debug_log("build_trace_plan: JumpLocalIfFalse non-num cond");
                    return None;
                }
                ops.push(jit::TraceOp::LoadLocal(*idx));
                if *target >= start && *target <= end {
                    if *target <= ip {
                        trace_debug_log("build_trace_plan: JumpLocalIfFalse backward inside trace");
                        return None;
                    }
                    ops.push(jit::TraceOp::BranchFalse(*target));
                } else {
                    ops.push(jit::TraceOp::GuardFalse);
                }
            }
            Instr::MakeList(len) => {
                if *len > stack.len() {
                    return None;
                }
                let mut elem_tag: Option<ElemTag> = None;
                for _ in 0..*len {
                    let meta = stack.pop()?;
                    let tag = elem_tag_from_ty(&meta.ty)?;
                    elem_tag = match elem_tag {
                        None => Some(tag),
                        Some(prev) if prev == tag => Some(prev),
                        _ => None,
                    };
                }
                let elem_tag = elem_tag?;
                ops.push(jit::TraceOp::MakeList(*len));
                stack.push(ValueMeta {
                    ty: TraceTy::List(elem_tag),
                    origin: ValueOrigin::Unknown,
                });
                depth += 1 - (*len as i32);
            }
            Instr::MakeMap(keys) => {
                if keys.len() > stack.len() {
                    return None;
                }
                let mut elem_tag: Option<ElemTag> = None;
                for _ in 0..keys.len() {
                    let meta = stack.pop()?;
                    let tag = elem_tag_from_ty(&meta.ty)?;
                    elem_tag = match elem_tag {
                        None => Some(tag),
                        Some(prev) if prev == tag => Some(prev),
                        _ => None,
                    };
                }
                let elem_tag = elem_tag?;
                ops.push(jit::TraceOp::MakeMap(keys.clone()));
                stack.push(ValueMeta {
                    ty: TraceTy::Map(elem_tag),
                    origin: ValueOrigin::Unknown,
                });
                depth += 1 - (keys.len() as i32);
            }
            Instr::LoadField(field) => {
                let target = stack.pop()?;
                let value_ty = match target.ty {
                    TraceTy::Map(elem) => ty_from_elem_tag(&elem),
                    _ => return None,
                };
                let mut specialized = false;
                if let ValueOrigin::Local(local_idx) = target.origin {
                    unsafe_pic_map_locals.insert(local_idx);
                    if let Some(bits) = locals.get(local_idx).copied().map(|v| v.to_bits()) {
                        let map_meta = runtime.map_meta(bits);
                        if let Some(ptr) = runtime.map_get_str_slot_ptr(bits, field) {
                            if let Some((_ptr, cap, _version, slots, _slot_size)) = map_meta {
                                ops.push(jit::TraceOp::MapGetSlotPtrNoVer(
                                    local_idx, ip, cap, slots, ptr,
                                ));
                                specialized = true;
                            }
                        } else if let Some(slot) = runtime.map_get_str_slot(bits, field) {
                            if let Some((_ptr, cap, _version, slots, _slot_size)) = map_meta {
                                ops.push(jit::TraceOp::MapGetSlotNoVerGuard(
                                    local_idx, ip, cap, slots, slot,
                                ));
                                specialized = true;
                            }
                        }
                    }
                }
                if !specialized {
                    ops.push(jit::TraceOp::LoadField(field.clone()));
                }
                stack.push(ValueMeta {
                    ty: value_ty,
                    origin: ValueOrigin::Unknown,
                });
            }
            Instr::CallBuiltin(name, argc) if name == "__index" && *argc == 2 => {
                let idx = stack.pop()?;
                let target = stack.pop()?;
                let unsafe_policy = unsafe_policy_for_ip(unsafe_flags, ip);
                match (target.ty, target.origin, idx.ty, idx.origin) {
                    (TraceTy::List(elem), _, TraceTy::Num, _)
                        if elem == ElemTag::Num && unsafe_policy.allow_ptr_arith =>
                    {
                        ops.push(jit::TraceOp::IndexListNum);
                        stack.push(ValueMeta {
                            ty: TraceTy::Num,
                            origin: ValueOrigin::Unknown,
                        });
                        depth -= 1;
                        continue;
                    }
                    (
                        TraceTy::List(elem),
                        ValueOrigin::Local(list_idx),
                        TraceTy::Num,
                        ValueOrigin::Local(idx_local),
                    ) if elem == ElemTag::Num
                        && bounds_guard_covers_list(
                            &bounds_guards,
                            list_idx,
                            idx_local,
                            locals,
                        )
                        && !unsafe_policy.skip_bounds_check =>
                    {
                        uses_bounds_guards = true;
                        ops.push(jit::TraceOp::IndexListNum);
                        stack.push(ValueMeta {
                            ty: TraceTy::Num,
                            origin: ValueOrigin::Unknown,
                        });
                        depth -= 1;
                    }
                    (
                        TraceTy::Map(elem),
                        ValueOrigin::Local(map_idx),
                        TraceTy::Text,
                        ValueOrigin::ConstText(key),
                    ) => {
                        unsafe_pic_map_locals.insert(map_idx);
                        let Some(bits) = locals.get(map_idx).copied().map(|v| v.to_bits()) else {
                            trace_debug_log("build_trace_plan: map local missing");
                            return None;
                        };
                        let Some((_ptr, cap, _version, slots, _slot_size)) = runtime.map_meta(bits)
                        else {
                            trace_debug_log("build_trace_plan: map meta missing");
                            return None;
                        };
                        // We drop the constant key before fast-path map-get, so deopt must
                        // restart at the preceding ConstText to rebuild [map, key] for __index.
                        let deopt_ip = ip.saturating_sub(1);
                        if let Some(ptr) = runtime.map_get_str_slot_ptr(bits, &key) {
                            ops.push(jit::TraceOp::Pop); // drop key
                            ops.push(jit::TraceOp::MapGetSlotPtrNoVer(
                                map_idx, deopt_ip, cap, slots, ptr,
                            ));
                        } else if let Some(slot) = runtime.map_get_str_slot(bits, &key) {
                            ops.push(jit::TraceOp::Pop); // drop key
                            ops.push(jit::TraceOp::MapGetSlotNoVerGuard(
                                map_idx, deopt_ip, cap, slots, slot,
                            ));
                        } else {
                            trace_debug_log("build_trace_plan: map get missing slot");
                            return None;
                        }
                        stack.push(ValueMeta {
                            ty: ty_from_elem_tag(&elem),
                            origin: ValueOrigin::Unknown,
                        });
                        depth -= 1;
                    }
                    (
                        TraceTy::Map(elem),
                        ValueOrigin::Local(map_idx),
                        TraceTy::Text,
                        ValueOrigin::Local(key_idx),
                    ) => {
                        let Some(bits) = locals.get(map_idx).copied().map(|v| v.to_bits()) else {
                            trace_debug_log("build_trace_plan: map local missing");
                            return None;
                        };
                        let Some(key_bits) = locals.get(key_idx).copied().map(|v| v.to_bits())
                        else {
                            trace_debug_log("build_trace_plan: key local missing");
                            return None;
                        };
                        match vb::tag_of(key_bits) {
                            Some(tag)
                                if tag == vb::TAG_TEXT_SMALL || tag == vb::TAG_TEXT_SMALL6 =>
                            {
                                let Some((_ptr, cap, _version, slots, _slot_size)) =
                                    runtime.map_meta(bits)
                                else {
                                    trace_debug_log("build_trace_plan: map meta missing");
                                    return None;
                                };
                                if !mutated_locals.contains(&key_idx) {
                                    let key_text = runtime.format_bits(key_bits);
                                    if let Some(value_ptr) =
                                        runtime.map_get_str_slot_ptr(bits, &key_text)
                                    {
                                        // Const small-text key fast path: keep key-bits guard +
                                        // map shape guard, then load value through cached slot ptr.
                                        // This avoids per-iteration hash/probe in MapGetSmallKeyNoVer.
                                        ops.push(jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(
                                            map_idx, key_idx, key_bits, ip, cap, slots, value_ptr,
                                        ));
                                        pic_map_locals.insert(map_idx);
                                        stack.push(ValueMeta {
                                            ty: ty_from_elem_tag(&elem),
                                            origin: ValueOrigin::Unknown,
                                        });
                                        depth -= 1;
                                        continue;
                                    }
                                }
                                ops.push(jit::TraceOp::MapGetSmallKeyNoVer(
                                    map_idx, key_idx, ip, cap, slots,
                                ));
                                stack.push(ValueMeta {
                                    ty: ty_from_elem_tag(&elem),
                                    origin: ValueOrigin::Unknown,
                                });
                                depth -= 1;
                            }
                            Some(tag) if tag == vb::TAG_TEXT => {
                                let Some((_ptr, cap, _version, slots, _slot_size)) =
                                    runtime.map_meta(bits)
                                else {
                                    trace_debug_log("build_trace_plan: map meta missing");
                                    return None;
                                };
                                if !mutated_locals.contains(&key_idx) {
                                    let key_text = runtime.format_bits(key_bits);
                                    if let Some(value_ptr) =
                                        runtime.map_get_str_slot_ptr(bits, &key_text)
                                    {
                                        ops.push(jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(
                                            map_idx, key_idx, key_bits, ip, cap, slots, value_ptr,
                                        ));
                                        pic_map_locals.insert(map_idx);
                                        stack.push(ValueMeta {
                                            ty: ty_from_elem_tag(&elem),
                                            origin: ValueOrigin::Unknown,
                                        });
                                        depth -= 1;
                                        continue;
                                    }
                                    if let Some((ptr, len, hash)) = runtime.text_meta(key_bits) {
                                        ops.push(jit::TraceOp::MapGetTextKeyConstNoVer(
                                            map_idx, key_idx, key_bits, ip, cap, slots, ptr, len,
                                            hash,
                                        ));
                                        stack.push(ValueMeta {
                                            ty: ty_from_elem_tag(&elem),
                                            origin: ValueOrigin::Unknown,
                                        });
                                        depth -= 1;
                                        continue;
                                    }
                                }
                                ops.push(jit::TraceOp::MapGetTextKeyNoVer(
                                    map_idx, key_idx, ip, cap, slots,
                                ));
                                stack.push(ValueMeta {
                                    ty: ty_from_elem_tag(&elem),
                                    origin: ValueOrigin::Unknown,
                                });
                                depth -= 1;
                            }
                            _ => {
                                trace_debug_log("build_trace_plan: map key not small text");
                                return None;
                            }
                        }
                    }
                    _ => {
                        trace_debug_log("build_trace_plan: __index pattern mismatch");
                        return None;
                    }
                }
            }
            Instr::CallBuiltin(name, argc) if name == "__setindex" && *argc == 3 => {
                let val = stack.pop()?;
                let idx = stack.pop()?;
                let target = stack.pop()?;
                let unsafe_policy = unsafe_policy_for_ip(unsafe_flags, ip);
                match (target.ty, target.origin, idx.ty, idx.origin, val.ty) {
                    (TraceTy::List(elem), _, TraceTy::Num, _, TraceTy::Num)
                        if elem == ElemTag::Num && unsafe_policy.allow_ptr_arith =>
                    {
                        ops.push(jit::TraceOp::SetIndexListNum);
                        stack.push(ValueMeta {
                            ty: TraceTy::List(elem),
                            origin: ValueOrigin::Unknown,
                        });
                        depth -= 2;
                        continue;
                    }
                    (
                        TraceTy::List(elem),
                        ValueOrigin::Local(list_idx),
                        TraceTy::Num,
                        ValueOrigin::Local(idx_local),
                        TraceTy::Num,
                    ) if elem == ElemTag::Num
                        && bounds_guard_covers_list(
                            &bounds_guards,
                            list_idx,
                            idx_local,
                            locals,
                        )
                        && !unsafe_policy.skip_bounds_check =>
                    {
                        uses_bounds_guards = true;
                        mutated_lists.insert(list_idx);
                        let mut specialized = false;
                        if let Some(bits) = locals.get(list_idx).copied().map(|v| v.to_bits()) {
                            if let Some((_ptr, _len, _cap, _version, data)) =
                                runtime.list_meta(bits)
                            {
                                if data != 0 {
                                    ops.push(jit::TraceOp::SetIndexListNumLocalPtrNoVer(
                                        list_idx, idx_local, data,
                                    ));
                                    specialized = true;
                                }
                            }
                        }
                        if !specialized {
                            ops.push(jit::TraceOp::SetIndexListNumLocalNoVer(list_idx, idx_local));
                        }
                        stack.push(ValueMeta {
                            ty: TraceTy::List(elem),
                            origin: ValueOrigin::Unknown,
                        });
                        depth -= 2;
                    }
                    (
                        TraceTy::Map(elem),
                        ValueOrigin::Local(map_idx),
                        TraceTy::Text,
                        ValueOrigin::ConstText(key),
                        val_ty,
                    ) if ty_from_elem_tag(&elem) == val_ty => {
                        mutated_maps.insert(map_idx);
                        unsafe_pic_map_locals.insert(map_idx);
                        let Some(bits) = locals.get(map_idx).copied().map(|v| v.to_bits()) else {
                            trace_debug_log("build_trace_plan: map local missing");
                            return None;
                        };
                        let Some((_ptr, cap, _version, slots, _slot_size)) = runtime.map_meta(bits)
                        else {
                            trace_debug_log("build_trace_plan: map meta missing");
                            return None;
                        };
                        if let Some(ptr) = runtime.map_get_str_slot_ptr(bits, &key) {
                            ops.push(jit::TraceOp::MapSetSlotPtrNoVerGuard(
                                map_idx, ip, cap, slots, ptr,
                            ));
                        } else if let Some(slot) = runtime.map_get_str_slot(bits, &key) {
                            ops.push(jit::TraceOp::MapSetSlotNoVerGuard(
                                map_idx, ip, cap, slots, slot,
                            ));
                        } else {
                            trace_debug_log("build_trace_plan: map set missing slot");
                            return None;
                        }
                        stack.push(ValueMeta {
                            ty: TraceTy::Map(elem),
                            origin: ValueOrigin::Unknown,
                        });
                        depth -= 2;
                    }
                    (
                        TraceTy::Map(elem),
                        ValueOrigin::Local(map_idx),
                        TraceTy::Text,
                        ValueOrigin::Local(key_idx),
                        val_ty,
                    ) if ty_from_elem_tag(&elem) == val_ty => {
                        mutated_maps.insert(map_idx);
                        let Some(bits) = locals.get(map_idx).copied().map(|v| v.to_bits()) else {
                            trace_debug_log("build_trace_plan: map local missing");
                            return None;
                        };
                        let Some(key_bits) = locals.get(key_idx).copied().map(|v| v.to_bits())
                        else {
                            trace_debug_log("build_trace_plan: key local missing");
                            return None;
                        };
                        match vb::tag_of(key_bits) {
                            Some(tag)
                                if tag == vb::TAG_TEXT_SMALL || tag == vb::TAG_TEXT_SMALL6 =>
                            {
                                let Some((_ptr, cap, _version, slots, _slot_size)) =
                                    runtime.map_meta(bits)
                                else {
                                    trace_debug_log("build_trace_plan: map meta missing");
                                    return None;
                                };
                                ops.push(jit::TraceOp::MapSetSmallKeyNoVer(
                                    map_idx, key_idx, ip, cap, slots,
                                ));
                            }
                            Some(tag) if tag == vb::TAG_TEXT => {
                                let Some((_ptr, cap, _version, slots, _slot_size)) =
                                    runtime.map_meta(bits)
                                else {
                                    trace_debug_log("build_trace_plan: map meta missing");
                                    return None;
                                };
                                if !mutated_locals.contains(&key_idx) {
                                    let key_text = runtime.format_bits(key_bits);
                                    if let Some(value_ptr) =
                                        runtime.map_get_str_slot_ptr(bits, &key_text)
                                    {
                                        ops.push(jit::TraceOp::MapSetTextKeyConstSlotPtrNoVer(
                                            map_idx, key_idx, key_bits, ip, cap, slots, value_ptr,
                                        ));
                                        pic_map_locals.insert(map_idx);
                                        stack.push(ValueMeta {
                                            ty: TraceTy::Map(elem),
                                            origin: ValueOrigin::Unknown,
                                        });
                                        depth -= 2;
                                        continue;
                                    }
                                    if let Some((ptr, len, hash)) = runtime.text_meta(key_bits) {
                                        ops.push(jit::TraceOp::MapSetTextKeyConstNoVer(
                                            map_idx, key_idx, key_bits, ip, cap, slots, ptr, len,
                                            hash,
                                        ));
                                        stack.push(ValueMeta {
                                            ty: TraceTy::Map(elem),
                                            origin: ValueOrigin::Unknown,
                                        });
                                        depth -= 2;
                                        continue;
                                    }
                                }
                                ops.push(jit::TraceOp::MapSetTextKeyNoVer(
                                    map_idx, key_idx, ip, cap, slots,
                                ));
                            }
                            _ => {
                                trace_debug_log("build_trace_plan: map key not small text");
                                return None;
                            }
                        }
                        stack.push(ValueMeta {
                            ty: TraceTy::Map(elem),
                            origin: ValueOrigin::Unknown,
                        });
                        depth -= 2;
                    }
                    _ => {
                        trace_debug_log("build_trace_plan: __setindex pattern mismatch");
                        return None;
                    }
                }
            }
            Instr::CallBuiltin(name, argc) if name == "len" && *argc == 1 => {
                let target = stack.pop()?;
                match target.ty {
                    TraceTy::List(_) => {
                        ops.push(jit::TraceOp::LenList);
                        let origin = match target.origin {
                            ValueOrigin::Local(idx) => ValueOrigin::LenOfLocal(idx),
                            _ => ValueOrigin::Unknown,
                        };
                        stack.push(ValueMeta {
                            ty: TraceTy::Num,
                            origin,
                        });
                        depth += 0;
                    }
                    _ => {
                        trace_debug_log("build_trace_plan: len on non-list");
                        return None;
                    }
                }
            }
            Instr::CallBuiltin(name, argc) if name == "to_text" && *argc == 1 => {
                trace_debug_log("build_trace_plan: to_text not supported in trace");
                return None;
            }
            Instr::Pop => {
                stack.pop()?;
                ops.push(jit::TraceOp::Pop);
                depth -= 1;
            }
            Instr::Return => {
                if stack.pop().is_none() {
                    trace_debug_log("build_trace_plan: Return stack underflow");
                    return None;
                }
                ops.push(jit::TraceOp::Return);
                depth -= 1;
            }
            _ => {
                trace_debug_log("build_trace_plan: unsupported instruction in trace");
                return None;
            }
        }
        if depth < 0 {
            trace_debug_log("build_trace_plan: negative stack depth");
            return None;
        }
    }

    if depth != 0 {
        trace_debug_log("build_trace_plan: non-zero stack depth at end");
        return None;
    }

    if !bounds_guards.is_empty() && uses_bounds_guards {
        let mut guard_ops: Vec<jit::TraceOp> = bounds_guards
            .iter()
            .map(|(list_idx, idx_idx)| jit::TraceOp::GuardListBounds(*list_idx, *idx_idx))
            .collect();
        guard_ops.sort_by_key(|op| match op {
            jit::TraceOp::GuardListBounds(list_idx, idx_idx) => (*list_idx, *idx_idx),
            _ => (0, 0),
        });
        guard_ops.extend(ops);
        ops = guard_ops;
    }

    let has_internal_control_flow = ops.iter().any(|op| {
        matches!(
            op,
            jit::TraceOp::Label(_) | jit::TraceOp::BranchFalse(_) | jit::TraceOp::JumpTo(_)
        )
    });
    if has_internal_control_flow {
        if ops.len() < MIN_TRACE_LEN {
            trace_debug_log("build_trace_plan: native-branch trace too short");
            return None;
        }
        let optimized = rewrite_lenlist_const(&ops, locals, runtime);
        let optimized = specialize_list_data_ptr(&optimized, locals, runtime);
        let fusion_result = apply_fusion_tier(&optimized, &mutated_maps, locals);
        let optimized = fusion_result.ops;
        for idx in &fusion_result.stable_const_slot_maps {
            pic_map_locals.remove(idx);
        }
        let stats = TraceStats {
            bc_len: end.saturating_sub(start) + 1,
            ops_len: optimized.len(),
            live_values: trace_live_values(&optimized),
            static_calls: 0,
            static_branches: 0,
        };
        let write_first_locals = trace_write_first_locals(code, start, end);
        let profile = build_trace_profile(code, start, end, locals, runtime, &write_first_locals)?;
        expand_profiled_mutation_aliases(&mut mutated_lists, &profile, locals, vb::TAG_LIST);
        expand_profiled_mutation_aliases(&mut mutated_maps, &profile, locals, vb::TAG_MAP);
        for idx in unsafe_pic_map_locals {
            pic_map_locals.remove(&idx);
        }
        return Some(TracePlan {
            ops: optimized,
            temp_list_sources: Vec::new(),
            promoted_locals: Vec::new(),
            merge_locals: Vec::new(),
            profile,
            stats,
            mutated_lists: mutated_lists.into_iter().collect(),
            mutated_maps: mutated_maps.into_iter().collect(),
            pic_map_locals: pic_map_locals.into_iter().collect(),
            fusion_hits: fusion_result.hits,
        });
    }

    let folded = fold_trace_constants(&ops);
    if folded.len() < MIN_TRACE_LEN {
        trace_debug_log("build_trace_plan: trace too short after fold");
        return None;
    }
    let optimized = optimize_trace_ops(&folded);
    let optimized = rewrite_lenlist_const(&optimized, locals, runtime);
    let optimized = specialize_list_data_ptr(&optimized, locals, runtime);
    if trace_debug() && trace_debug_ops() {
        trace_debug_log(&format!("trace ops pre-unroll: {:?}", optimized));
    }
    let optimized = unroll_list_update_x4(&optimized);
    let optimized = unroll_dot_product_x4(&optimized);
    let optimized = rewrite_setindex_fast(&optimized);
    let optimized = optimize_trace_ops(&optimized);
    let optimized = rewrite_dup_for_list_update(&optimized);
    let (optimized, merge_locals) = rewrite_multi_accum_list_update(&optimized);
    let (optimized, merge_locals_dot) = rewrite_dot_product_multi_accum(&optimized);
    let mut merge_locals = merge_locals;
    merge_locals.extend(merge_locals_dot);
    let fusion_result = apply_fusion_tier(&optimized, &mutated_maps, locals);
    let optimized = fusion_result.ops;
    for idx in &fusion_result.stable_const_slot_maps {
        pic_map_locals.remove(idx);
    }
    let optimized = eliminate_dead_stores(&optimized);
    let optimized = rewrite_loop_bounds_guard(&optimized);
    let optimized = insert_dot_product_noalias_guard(&optimized);
    let optimized = canonicalize_loop_form(&optimized);
    let optimized = fuse_index_range_guards(&optimized);
    let base_loop_interval_report = report_loop_intervals(&optimized);
    let (scheduled_ops, scheduler_candidate) = schedule_dot_product_load_mul_add(&optimized);
    let scheduled_report = if scheduler_candidate {
        report_loop_intervals(&scheduled_ops)
    } else {
        None
    };
    let (optimized, loop_interval_report, scheduler_applied) = if scheduler_candidate {
        match (&base_loop_interval_report, &scheduled_report) {
            (Some(base), Some(scheduled))
                if scheduled.spill_count > base.spill_count
                    || scheduled.max_live_xmm > SCHEDULER_MAX_LIVE_XMM =>
            {
                if trace_debug() {
                    trace_debug_log(&format!(
                        "loop scheduler: skipped (spill_count {} -> {}, max_live_xmm={})",
                        base.spill_count, scheduled.spill_count, scheduled.max_live_xmm
                    ));
                }
                (optimized, base_loop_interval_report, false)
            }
            _ => {
                if trace_debug() {
                    trace_debug_log("loop scheduler: applied dot-product phased load/mul/add");
                }
                (scheduled_ops, scheduled_report, true)
            }
        }
    } else {
        (optimized, base_loop_interval_report, false)
    };
    if trace_debug() && trace_debug_ops() {
        trace_debug_log(&format!("trace ops post-unroll: {:?}", optimized));
    }
    if trace_debug() && trace_debug_loopir() {
        if let Some(report) = &loop_interval_report {
            dump_loop_interval_report(report);
        }
    }
    if trace_debug() {
        trace_debug_log(&format!("loop scheduler applied={}", scheduler_applied));
    }
    let write_first_locals = trace_write_first_locals(code, start, end);
    let optimized = mark_temp_allocs(&optimized, &write_first_locals);
    let temp_list_sources = collect_temp_list_sources(&optimized);
    let promoted_locals = select_promoted_locals(&optimized);
    let stats = TraceStats {
        bc_len: end.saturating_sub(start) + 1,
        ops_len: optimized.len(),
        live_values: trace_live_values(&optimized),
        static_calls: 0,
        static_branches: 0,
    };
    let profile = build_trace_profile(code, start, end, locals, runtime, &write_first_locals)?;
    expand_profiled_mutation_aliases(&mut mutated_lists, &profile, locals, vb::TAG_LIST);
    expand_profiled_mutation_aliases(&mut mutated_maps, &profile, locals, vb::TAG_MAP);
    for idx in unsafe_pic_map_locals {
        pic_map_locals.remove(&idx);
    }

    Some(TracePlan {
        ops: optimized,
        temp_list_sources,
        promoted_locals,
        merge_locals,
        profile,
        stats,
        mutated_lists: mutated_lists.into_iter().collect(),
        mutated_maps: mutated_maps.into_iter().collect(),
        pic_map_locals: pic_map_locals.into_iter().collect(),
        fusion_hits: fusion_result.hits,
    })
}

fn build_trace_profile(
    code: &[Instr],
    start: usize,
    end: usize,
    locals: &[f64],
    runtime: &jit::JitRuntime,
    skip_locals: &std::collections::BTreeSet<usize>,
) -> Option<TraceProfile> {
    let mut indices = std::collections::BTreeSet::new();
    for instr in &code[start..=end] {
        if let Instr::LoadLocal(idx) = instr {
            indices.insert(*idx);
        }
    }
    let mut guards = Vec::new();
    for idx in indices {
        if skip_locals.contains(&idx) {
            continue;
        }
        let bits = locals.get(idx).copied().unwrap_or(0.0).to_bits();
        let tag = if vb::is_tagged(bits) {
            vb::tag_of(bits)
        } else {
            None
        };
        let shape = match tag {
            Some(t) if t == vb::TAG_LIST => {
                let elem = runtime.list_uniform_tag(bits)?;
                let (ptr, len, cap, version, data) = runtime.list_meta(bits)?;
                Some(ShapeGuard::List {
                    elem,
                    ptr,
                    len,
                    cap,
                    version,
                    data,
                })
            }
            Some(t) if t == vb::TAG_MAP => {
                let elem = runtime.map_uniform_value_tag(bits)?;
                let (ptr, cap, version, slots, slot_size) = runtime.map_meta(bits)?;
                Some(ShapeGuard::Map {
                    elem,
                    ptr,
                    cap,
                    version,
                    slots,
                    slot_size,
                })
            }
            _ => None,
        };
        guards.push(LocalGuard { idx, tag, shape });
    }
    Some(TraceProfile { locals: guards })
}

fn expand_profiled_mutation_aliases(
    mutated: &mut std::collections::BTreeSet<usize>,
    profile: &TraceProfile,
    locals: &[f64],
    expected_tag: u64,
) {
    let mutated_bits: std::collections::BTreeSet<u64> = mutated
        .iter()
        .filter_map(|idx| locals.get(*idx).copied().map(f64::to_bits))
        .filter(|bits| vb::tag_of(*bits) == Some(expected_tag))
        .collect();
    if mutated_bits.is_empty() {
        return;
    }
    for guard in &profile.locals {
        if guard.tag != Some(expected_tag) {
            continue;
        }
        let Some(bits) = locals.get(guard.idx).copied().map(f64::to_bits) else {
            continue;
        };
        if mutated_bits.contains(&bits) {
            mutated.insert(guard.idx);
        }
    }
}

fn trace_write_first_locals(
    code: &[Instr],
    start: usize,
    end: usize,
) -> std::collections::BTreeSet<usize> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FirstAccess {
        Read,
        Write,
    }

    let mut first_access: std::collections::HashMap<usize, FirstAccess> =
        std::collections::HashMap::new();
    for instr in &code[start..=end] {
        match instr {
            Instr::LoadLocal(idx) | Instr::JumpLocalIfFalse(idx, _) => {
                first_access.entry(*idx).or_insert(FirstAccess::Read);
            }
            Instr::StoreLocal(idx) | Instr::StoreLocalKeep(idx) | Instr::AddLocalConst(idx, _) => {
                first_access.entry(*idx).or_insert(FirstAccess::Write);
            }
            _ => {}
        }
    }
    first_access
        .into_iter()
        .filter_map(|(idx, access)| {
            if access == FirstAccess::Write {
                Some(idx)
            } else {
                None
            }
        })
        .collect()
}

fn init_adaptive_sites(exec: &jit::JitExecutable) -> Vec<AdaptiveSiteState> {
    exec.patch_sites()
        .iter()
        .map(|site| AdaptiveSiteState {
            inverted: site.inverted,
            ..AdaptiveSiteState::default()
        })
        .collect()
}

fn reset_adaptive_state(entry: &mut TraceEntry) {
    entry.adaptive_sites = init_adaptive_sites(&entry.exec);
    entry.adaptive_epoch_iters = 0;
}

fn apply_adaptive_epoch(entry: &mut TraceEntry) {
    fn adaptive_patch_threshold(state: &AdaptiveSiteState) -> i32 {
        ADAPTIVE_STABILITY_PATCH_THRESHOLD_BASE
            + ADAPTIVE_STABILITY_PATCH_THRESHOLD_PER_REVERT * i32::from(state.revert_streak)
    }

    fn adaptive_flip_penalty(state: &AdaptiveSiteState) -> i32 {
        ADAPTIVE_STABILITY_FLIP_PENALTY_BASE
            + ADAPTIVE_STABILITY_FLIP_PENALTY_PER_REVERT * i32::from(state.revert_streak)
    }

    fn adaptive_cooldown_epochs(state: &AdaptiveSiteState) -> u32 {
        match state.revert_streak {
            0 => 4,
            1 => 12,
            2 => 32,
            _ => 64,
        }
    }

    fn stable_tick(state: &mut AdaptiveSiteState) {
        state.stable_epochs = state.stable_epochs.saturating_add(1);
        state.stability_score = (state.stability_score + ADAPTIVE_STABILITY_RECOVERY)
            .clamp(ADAPTIVE_STABILITY_SCORE_MIN, ADAPTIVE_STABILITY_SCORE_MAX);
        if state.revert_streak > 0
            && state
                .stable_epochs
                .is_multiple_of(ADAPTIVE_REVERT_DECAY_EPOCHS)
        {
            state.revert_streak = state.revert_streak.saturating_sub(1);
        }
    }

    entry.adaptive_epochs = entry.adaptive_epochs.saturating_add(1);
    if entry.adaptive_sites.len() != entry.exec.patch_sites().len() {
        entry.adaptive_sites = init_adaptive_sites(&entry.exec);
    }
    let sites: Vec<jit::PatchSite> = entry.exec.patch_sites().to_vec();
    let mut patches_left = ADAPTIVE_MAX_PATCHES_PER_EPOCH;
    for (idx, site) in sites.iter().enumerate() {
        let Some(state) = entry.adaptive_sites.get_mut(idx) else {
            break;
        };
        if state.cooldown_epochs > 0 {
            state.cooldown_epochs -= 1;
            stable_tick(state);
            continue;
        }
        if !site.patchable || patches_left == 0 {
            stable_tick(state);
            continue;
        }
        if state.inverted != site.inverted {
            state.inverted = site.inverted;
        }
        let total = state.taken_accum.saturating_add(state.not_taken_accum);
        if total < ADAPTIVE_MIN_SAMPLES {
            stable_tick(state);
            continue;
        }
        if state.stability_score < adaptive_patch_threshold(state) {
            stable_tick(state);
            continue;
        }
        let ratio = if total > 0 {
            state.taken_accum as f64 / total as f64
        } else {
            0.0
        };
        let target_inverted = if !state.inverted && ratio > ADAPTIVE_FLIP_ON {
            Some(true)
        } else if state.inverted && ratio < ADAPTIVE_FLIP_OFF {
            Some(false)
        } else {
            None
        };
        if let Some(next_state) = target_inverted {
            if next_state != state.inverted {
                entry.adaptive_patch_attempts = entry.adaptive_patch_attempts.saturating_add(1);
                if let Ok(true) = entry.exec.patch_flip_site_opcode(idx) {
                    if state.inverted && !next_state {
                        entry.adaptive_patch_reverts =
                            entry.adaptive_patch_reverts.saturating_add(1);
                        state.revert_streak = state.revert_streak.saturating_add(1);
                    } else {
                        state.revert_streak = 0;
                    }
                    state.inverted = next_state;
                    state.cooldown_epochs = adaptive_cooldown_epochs(state);
                    state.stable_epochs = 0;
                    let penalty = adaptive_flip_penalty(state);
                    state.stability_score = (state.stability_score - penalty)
                        .clamp(ADAPTIVE_STABILITY_SCORE_MIN, ADAPTIVE_STABILITY_SCORE_MAX);
                    entry.adaptive_patch_commits = entry.adaptive_patch_commits.saturating_add(1);
                    patches_left = patches_left.saturating_sub(1);
                } else {
                    stable_tick(state);
                }
            }
        } else {
            stable_tick(state);
        }
    }
    // Epoch decay to adapt to drift without hard reset.
    for state in entry.adaptive_sites.iter_mut() {
        state.taken_accum >>= 1;
        state.not_taken_accum >>= 1;
    }
}

fn update_adaptive_patcher(
    entry: &mut TraceEntry,
    runtime: &jit::JitRuntime,
    profile: &jit::JitTraceProfile,
) {
    if entry.adaptive_sites.len() != entry.exec.patch_sites().len() {
        entry.adaptive_sites = init_adaptive_sites(&entry.exec);
    }
    for (idx, state) in entry.adaptive_sites.iter_mut().enumerate() {
        if let Some((taken, not_taken)) = runtime.profile_site_snapshot(idx) {
            state.taken_accum = state.taken_accum.saturating_add(taken);
            state.not_taken_accum = state.not_taken_accum.saturating_add(not_taken);
        }
    }
    entry.adaptive_epoch_iters = entry
        .adaptive_epoch_iters
        .saturating_add(profile.trace_iters);
    while entry.adaptive_epoch_iters >= ADAPTIVE_EPOCH_ITERS {
        entry.adaptive_epoch_iters -= ADAPTIVE_EPOCH_ITERS;
        apply_adaptive_epoch(entry);
    }
}

fn refresh_mutated_list_guards(entry: &mut TraceEntry, locals: &[f64], runtime: &jit::JitRuntime) {
    if entry.mutated_lists.is_empty() {
        return;
    }
    for &idx in &entry.mutated_lists {
        let bits = locals.get(idx).copied().unwrap_or(0.0).to_bits();
        if vb::tag_of(bits) != Some(vb::TAG_LIST) {
            continue;
        }
        let Some((ptr, len, cap, version, data)) = runtime.list_meta(bits) else {
            continue;
        };
        for guard in entry.profile.locals.iter_mut() {
            if guard.idx != idx {
                continue;
            }
            if let Some(ShapeGuard::List { elem, .. }) = guard.shape {
                guard.shape = Some(ShapeGuard::List {
                    elem,
                    ptr,
                    len,
                    cap,
                    version,
                    data,
                });
            }
        }
    }
}

fn capture_scalar_tail_handoff(
    key: TraceKey,
    entry: &TraceEntry,
    locals: &[f64],
    runtime: &jit::JitRuntime,
) -> Option<ScalarTailHandoff> {
    let mut lists = Vec::with_capacity(entry.mutated_lists.len());
    for &local_idx in &entry.mutated_lists {
        let bits = locals.get(local_idx).copied()?.to_bits();
        if vb::tag_of(bits) != Some(vb::TAG_LIST) {
            return None;
        }
        let (ptr, len, cap, version, data) = runtime.list_meta(bits)?;
        lists.push(ScalarTailListSnapshot {
            local_idx,
            bits,
            ptr,
            len,
            cap,
            version,
            data,
            max_version_delta: 3,
        });
    }
    Some(ScalarTailHandoff {
        key,
        exit_target: entry.exit_target,
        lists,
    })
}

fn record_speculative_deopt(
    trace_total: &mut u64,
    trace_reasons: &mut HashMap<String, u64>,
    telemetry_totals: &mut TraceTelemetryTotals,
    deopt_site: usize,
) {
    let reason = format!("runtime_site_{deopt_site}");
    *trace_total = trace_total.saturating_add(1);
    telemetry_totals.deopts_total = telemetry_totals.deopts_total.saturating_add(1);
    trace_reasons
        .entry(reason.clone())
        .and_modify(|count| *count = count.saturating_add(1))
        .or_insert(1);
    telemetry_totals
        .deopt_reason_counts
        .entry(reason)
        .and_modify(|count| *count = count.saturating_add(1))
        .or_insert(1);
}

fn is_internal_branch_deopt(
    code: &[Instr],
    loop_start: usize,
    back_edge: usize,
    deopt_ip: usize,
) -> bool {
    if loop_start >= code.len()
        || back_edge >= code.len()
        || loop_start > back_edge
        || deopt_ip < loop_start
        || deopt_ip > back_edge
    {
        return false;
    }
    code[loop_start..=back_edge]
        .iter()
        .enumerate()
        .any(|(offset, instr)| {
            let branch_ip = loop_start + offset;
            match instr {
                Instr::JumpIfFalse(target) | Instr::JumpLocalIfFalse(_, target) => {
                    *target == deopt_ip && *target > branch_ip && *target <= back_edge
                }
                _ => false,
            }
        })
}

fn finish_internal_branch_for_exit(
    code_id: usize,
    exit_target: usize,
    handoff: &mut Option<InternalBranchHandoff>,
) {
    if handoff
        .as_ref()
        .is_some_and(|pending| pending.key.0 == code_id && pending.exit_target == exit_target)
    {
        handoff.take();
    }
}

fn discard_internal_branch_handoff(
    handoff: Option<InternalBranchHandoff>,
    trace_cache: &mut HashMap<TraceKey, TraceEntry>,
    hot_counters: &mut HashMap<TraceKey, u32>,
) {
    let Some(handoff) = handoff else {
        return;
    };
    trace_debug_log("trace evicted: internal branch handoff left through an unexpected edge");
    trace_cache.remove(&handoff.key);
    hot_counters.remove(&handoff.key);
}

fn finish_scalar_tail_for_exit(
    code_id: usize,
    exit_target: usize,
    handoff: &mut Option<ScalarTailHandoff>,
    locals: &[f64],
    runtime: &jit::JitRuntime,
    trace_cache: &mut HashMap<TraceKey, TraceEntry>,
    hot_counters: &mut HashMap<TraceKey, u32>,
) {
    let should_finish = handoff
        .as_ref()
        .is_some_and(|pending| pending.key.0 == code_id && pending.exit_target == exit_target);
    if should_finish {
        finish_scalar_tail_handoff(handoff.take(), locals, runtime, trace_cache, hot_counters);
    }
}

fn finish_scalar_tail_handoff(
    handoff: Option<ScalarTailHandoff>,
    locals: &[f64],
    runtime: &jit::JitRuntime,
    trace_cache: &mut HashMap<TraceKey, TraceEntry>,
    hot_counters: &mut HashMap<TraceKey, u32>,
) {
    let Some(handoff) = handoff else {
        return;
    };

    let valid = handoff.lists.iter().all(|snapshot| {
        let Some(bits) = locals.get(snapshot.local_idx).copied().map(f64::to_bits) else {
            return false;
        };
        if bits != snapshot.bits {
            return false;
        }
        let Some((ptr, len, cap, version, data)) = runtime.list_meta(bits) else {
            return false;
        };
        ptr == snapshot.ptr
            && len == snapshot.len
            && cap == snapshot.cap
            && data == snapshot.data
            && version.wrapping_sub(snapshot.version) <= snapshot.max_version_delta
    });

    if valid {
        if let Some(entry) = trace_cache.get_mut(&handoff.key) {
            refresh_mutated_list_guards(entry, locals, runtime);
        }
    } else {
        trace_debug_log("trace evicted: scalar mutation tail changed list identity/shape");
        trace_cache.remove(&handoff.key);
        hot_counters.remove(&handoff.key);
    }
}

fn discard_scalar_tail_handoff(
    handoff: Option<ScalarTailHandoff>,
    trace_cache: &mut HashMap<TraceKey, TraceEntry>,
    hot_counters: &mut HashMap<TraceKey, u32>,
) {
    let Some(handoff) = handoff else {
        return;
    };
    trace_debug_log("trace evicted: scalar tail left through an unexpected control-flow edge");
    trace_cache.remove(&handoff.key);
    hot_counters.remove(&handoff.key);
}

fn collect_version_managed_lists(ops: &[jit::TraceOp]) -> Vec<usize> {
    let mut lists = std::collections::BTreeSet::new();
    for op in ops {
        if let jit::TraceOp::BumpListVersionLocal(idx) = op {
            lists.insert(*idx);
        }
    }
    lists.into_iter().collect()
}

fn bump_mutated_list_versions(entry: &TraceEntry, locals: &[f64], runtime: &mut jit::JitRuntime) {
    if entry.mutated_lists.is_empty() {
        return;
    }
    let version_managed_bits: std::collections::BTreeSet<u64> = entry
        .version_managed_lists
        .iter()
        .filter_map(|idx| locals.get(*idx).copied().map(f64::to_bits))
        .collect();
    let mut bumped_bits = std::collections::BTreeSet::new();
    for &idx in &entry.mutated_lists {
        let bits = locals.get(idx).copied().unwrap_or(0.0).to_bits();
        if version_managed_bits.contains(&bits) {
            continue;
        }
        if bumped_bits.insert(bits) {
            runtime.bump_list_version(bits);
        }
    }
}

fn refresh_mutated_map_guards(entry: &mut TraceEntry, locals: &[f64], runtime: &jit::JitRuntime) {
    if entry.mutated_maps.is_empty() {
        return;
    }
    for &idx in &entry.mutated_maps {
        let bits = locals.get(idx).copied().unwrap_or(0.0).to_bits();
        if vb::tag_of(bits) != Some(vb::TAG_MAP) {
            continue;
        }
        let Some((ptr, cap, version, slots, slot_size)) = runtime.map_meta(bits) else {
            continue;
        };
        for guard in entry.profile.locals.iter_mut() {
            if guard.idx != idx {
                continue;
            }
            if let Some(ShapeGuard::Map { elem, .. }) = guard.shape {
                guard.shape = Some(ShapeGuard::Map {
                    elem,
                    ptr,
                    cap,
                    version,
                    slots,
                    slot_size,
                });
            }
        }
    }
}

fn try_promote_map_pic2(
    entry: &mut TraceEntry,
    deopt_ip: usize,
    locals: &[f64],
    runtime: &jit::JitRuntime,
) -> bool {
    fn current_map_shape_slot(
        map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        locals: &[f64],
        runtime: &jit::JitRuntime,
    ) -> Option<(usize, u64, u64)> {
        let key_bits = locals.get(key_idx).copied()?.to_bits();
        if key_bits != expected_key_bits {
            return None;
        }
        let map_bits = locals.get(map_idx).copied()?.to_bits();
        if vb::tag_of(map_bits) != Some(vb::TAG_MAP) {
            return None;
        }
        let (_, cap, _version, slots, _slot_size) = runtime.map_meta(map_bits)?;
        let key_text = runtime.format_bits(expected_key_bits);
        let value_ptr = runtime.map_get_str_slot_ptr(map_bits, &key_text)?;
        Some((cap, slots, value_ptr))
    }

    for op in entry.ops.iter_mut() {
        match op {
            jit::TraceOp::MapGetTextKeyConstSlotPtrNoVer(
                map_idx,
                key_idx,
                key_bits,
                ip,
                cap1,
                slots1,
                value_ptr1,
            ) if *ip == deopt_ip => {
                let Some((cap2, slots2, value_ptr2)) =
                    current_map_shape_slot(*map_idx, *key_idx, *key_bits, locals, runtime)
                else {
                    continue;
                };
                if cap2 == *cap1 && slots2 == *slots1 && value_ptr2 == *value_ptr1 {
                    continue;
                }
                *op = jit::TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(
                    *map_idx,
                    *key_idx,
                    *key_bits,
                    *ip,
                    *cap1,
                    *slots1,
                    *value_ptr1,
                    cap2,
                    slots2,
                    value_ptr2,
                );
                return true;
            }
            jit::TraceOp::MapSetTextKeyConstSlotPtrNoVer(
                map_idx,
                key_idx,
                key_bits,
                ip,
                cap1,
                slots1,
                value_ptr1,
            ) if *ip == deopt_ip => {
                let Some((cap2, slots2, value_ptr2)) =
                    current_map_shape_slot(*map_idx, *key_idx, *key_bits, locals, runtime)
                else {
                    continue;
                };
                if cap2 == *cap1 && slots2 == *slots1 && value_ptr2 == *value_ptr1 {
                    continue;
                }
                *op = jit::TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(
                    *map_idx,
                    *key_idx,
                    *key_bits,
                    *ip,
                    *cap1,
                    *slots1,
                    *value_ptr1,
                    cap2,
                    slots2,
                    value_ptr2,
                );
                return true;
            }
            jit::TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(
                map_idx,
                key_idx,
                key_bits,
                ip,
                cap1,
                slots1,
                value_ptr1,
                cap2,
                slots2,
                value_ptr2,
            ) if *ip == deopt_ip => {
                let Some((new_cap, new_slots, new_value_ptr)) =
                    current_map_shape_slot(*map_idx, *key_idx, *key_bits, locals, runtime)
                else {
                    continue;
                };
                if (new_cap == *cap1 && new_slots == *slots1 && new_value_ptr == *value_ptr1)
                    || (new_cap == *cap2 && new_slots == *slots2 && new_value_ptr == *value_ptr2)
                {
                    continue;
                }
                *cap2 = new_cap;
                *slots2 = new_slots;
                *value_ptr2 = new_value_ptr;
                return true;
            }
            jit::TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(
                map_idx,
                key_idx,
                key_bits,
                ip,
                cap1,
                slots1,
                value_ptr1,
                cap2,
                slots2,
                value_ptr2,
            ) if *ip == deopt_ip => {
                let Some((new_cap, new_slots, new_value_ptr)) =
                    current_map_shape_slot(*map_idx, *key_idx, *key_bits, locals, runtime)
                else {
                    continue;
                };
                if (new_cap == *cap1 && new_slots == *slots1 && new_value_ptr == *value_ptr1)
                    || (new_cap == *cap2 && new_slots == *slots2 && new_value_ptr == *value_ptr2)
                {
                    continue;
                }
                *cap2 = new_cap;
                *slots2 = new_slots;
                *value_ptr2 = new_value_ptr;
                return true;
            }
            _ => {}
        }
    }
    false
}

fn guard_profile_check(
    profile: &TraceProfile,
    mutated_lists: &[usize],
    mutated_maps: &[usize],
    pic_map_locals: &[usize],
    locals: &[f64],
    runtime: &jit::JitRuntime,
) -> GuardCheckResult {
    let mut checks: u64 = 0;
    for guard in &profile.locals {
        checks = checks.saturating_add(1);
        let bits = locals.get(guard.idx).copied().unwrap_or(0.0).to_bits();
        let tag = if vb::is_tagged(bits) {
            vb::tag_of(bits)
        } else {
            None
        };
        if tag != guard.tag {
            return GuardCheckResult {
                checks,
                failure: Some(GuardFailure {
                    guard_id: guard_stable_id(guard),
                    reason: GuardFailReason::TagMismatch,
                }),
            };
        }
        if let Some(shape) = guard.shape {
            match shape {
                ShapeGuard::List {
                    elem,
                    len,
                    cap,
                    version,
                    ..
                } => {
                    let list_is_mutated = mutated_lists.contains(&guard.idx);
                    let Some((_, cur_len, cur_cap, cur_version, _)) = runtime.list_meta(bits)
                    else {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::ListMetaMissing,
                            }),
                        };
                    };
                    if cur_len != len {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::ListLenMismatch,
                            }),
                        };
                    }
                    if cur_cap != cap {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::ListCapMismatch,
                            }),
                        };
                    }
                    if !list_is_mutated && cur_version != version {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::ListVersionMismatch,
                            }),
                        };
                    }
                    // For non-mutated lists, a stable version guarantees element-tag uniformity
                    // did not change, so skip the O(n) uniform scan on trace entry.
                    if list_is_mutated {
                        let cur = runtime.list_uniform_tag(bits);
                        if cur != Some(elem) {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::ListElemTagMismatch,
                                }),
                            };
                        }
                    }
                }
                ShapeGuard::Map {
                    elem,
                    ptr,
                    cap,
                    version,
                    slots,
                    slot_size,
                } => {
                    if strict_map_uniform_guard() {
                        let cur = runtime.map_uniform_value_tag(bits);
                        if cur != Some(elem) {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapUniformTagMismatch,
                                }),
                            };
                        }
                        if pic_map_locals.contains(&guard.idx) {
                            continue;
                        }
                        let Some(meta) = runtime.map_meta(bits) else {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapMetaMissing,
                                }),
                            };
                        };
                        if meta.0 != ptr {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapPtrMismatch,
                                }),
                            };
                        }
                        if meta.1 != cap {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapCapMismatch,
                                }),
                            };
                        }
                        if meta.3 != slots {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapSlotsMismatch,
                                }),
                            };
                        }
                        if meta.4 != slot_size {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapSlotSizeMismatch,
                                }),
                            };
                        }
                        if !mutated_maps.contains(&guard.idx) && meta.2 != version {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapVersionMismatch,
                                }),
                            };
                        }
                        continue;
                    }
                    let map_is_mutated = mutated_maps.contains(&guard.idx);
                    let meta = runtime.map_meta(bits);
                    if pic_map_locals.contains(&guard.idx) {
                        if !map_is_mutated && meta.map(|m| m.2) != Some(version) {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapVersionMismatch,
                                }),
                            };
                        }
                        // PIC map locals are guarded at trace op sites for shape; when the map
                        // is stable by version, skip O(n) uniform-value scan on entry.
                        if map_is_mutated {
                            let cur = runtime.map_uniform_value_tag(bits);
                            if cur != Some(elem) {
                                return GuardCheckResult {
                                    checks,
                                    failure: Some(GuardFailure {
                                        guard_id: guard_stable_id(guard),
                                        reason: GuardFailReason::MapUniformTagMismatch,
                                    }),
                                };
                            }
                        }
                        continue;
                    }
                    let Some(meta) = meta else {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::MapMetaMissing,
                            }),
                        };
                    };
                    if meta.0 != ptr {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::MapPtrMismatch,
                            }),
                        };
                    }
                    if meta.1 != cap {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::MapCapMismatch,
                            }),
                        };
                    }
                    if meta.3 != slots {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::MapSlotsMismatch,
                            }),
                        };
                    }
                    if meta.4 != slot_size {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::MapSlotSizeMismatch,
                            }),
                        };
                    }
                    if !map_is_mutated && meta.2 != version {
                        return GuardCheckResult {
                            checks,
                            failure: Some(GuardFailure {
                                guard_id: guard_stable_id(guard),
                                reason: GuardFailReason::MapVersionMismatch,
                            }),
                        };
                    }
                    // For non-mutated maps, stable version is enough to guarantee uniform-value
                    // tag did not change; keep scan only for mutated map locals.
                    if map_is_mutated {
                        let cur = runtime.map_uniform_value_tag(bits);
                        if cur != Some(elem) {
                            return GuardCheckResult {
                                checks,
                                failure: Some(GuardFailure {
                                    guard_id: guard_stable_id(guard),
                                    reason: GuardFailReason::MapUniformTagMismatch,
                                }),
                            };
                        }
                    }
                }
            }
        }
    }
    GuardCheckResult {
        checks,
        failure: None,
    }
}

fn guard_profile(
    profile: &TraceProfile,
    mutated_lists: &[usize],
    mutated_maps: &[usize],
    pic_map_locals: &[usize],
    locals: &[f64],
    runtime: &jit::JitRuntime,
) -> bool {
    guard_profile_check(
        profile,
        mutated_lists,
        mutated_maps,
        pic_map_locals,
        locals,
        runtime,
    )
    .failure
    .is_none()
}

#[cfg(test)]
mod tests {
    use super::{
        analyze_bounds_guards, bounds_guard_covers_list, build_trace_plan, eliminate_dead_stores,
        expand_profiled_mutation_aliases, find_unsupported_internal_backedge, guard_profile,
        mark_temp_allocs, optimize_trace_ops, record_speculative_deopt,
        rewrite_map_stable_cmp_branch, rewrite_map_stable_mul_acc, unroll_list_update_x4,
        LocalGuard, ShapeGuard, TraceProfile, TraceTelemetryTotals,
    };
    use crate::vm::bytecode::Instr;
    use crate::vm::jit::TraceOp;
    use crate::vm::{jit, value_bits as vb};
    use std::collections::HashMap;

    fn map_profile(indices: &[usize], map_bits: u64, runtime: &jit::JitRuntime) -> TraceProfile {
        let elem = runtime
            .map_uniform_value_tag(map_bits)
            .expect("map should be uniform for guard setup");
        let (ptr, cap, version, slots, slot_size) = runtime
            .map_meta(map_bits)
            .expect("map metadata should be available");
        TraceProfile {
            locals: indices
                .iter()
                .map(|idx| LocalGuard {
                    idx: *idx,
                    tag: vb::tag_of(map_bits),
                    shape: Some(ShapeGuard::Map {
                        elem,
                        ptr,
                        cap,
                        version,
                        slots,
                        slot_size,
                    }),
                })
                .collect(),
        }
    }

    fn list_profile(indices: &[usize], list_bits: u64, runtime: &jit::JitRuntime) -> TraceProfile {
        let elem = runtime
            .list_uniform_tag(list_bits)
            .expect("list should be uniform for guard setup");
        let (ptr, len, cap, version, data) = runtime
            .list_meta(list_bits)
            .expect("list metadata should be available");
        TraceProfile {
            locals: indices
                .iter()
                .map(|idx| LocalGuard {
                    idx: *idx,
                    tag: vb::tag_of(list_bits),
                    shape: Some(ShapeGuard::List {
                        elem,
                        ptr,
                        len,
                        cap,
                        version,
                        data,
                    }),
                })
                .collect(),
        }
    }

    fn eval_guard(
        profile: &TraceProfile,
        locals_bits: &[u64],
        mutated_lists: &[usize],
        mutated_maps: &[usize],
        runtime: &jit::JitRuntime,
    ) -> bool {
        let locals: Vec<f64> = locals_bits.iter().copied().map(f64::from_bits).collect();
        guard_profile(profile, mutated_lists, mutated_maps, &[], &locals, runtime)
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn analyze_bounds_guards_propagates_uniform_map_index_value_type() {
        let mut runtime = jit::JitRuntime::new();
        let keys = vec!["k0".to_string()];
        let numeric_map = runtime.make_map(&keys, &[96.0f64.to_bits()]);
        let text_value = runtime.make_text("value");
        let text_map = runtime.make_map(&keys, &[text_value]);
        let key = runtime.make_text("k0");
        let code = vec![
            Instr::LoadLocal(0),
            Instr::LoadLocal(1),
            Instr::CallBuiltin("__index".into(), 2),
            Instr::StoreLocalKeep(2),
            Instr::ConstNum(64.0),
            Instr::Gt,
            Instr::JumpIfFalse(7),
        ];

        let numeric_locals = [f64::from_bits(numeric_map), f64::from_bits(key), 0.0f64];
        assert!(
            analyze_bounds_guards(&code, 0, code.len() - 1, &numeric_locals, &runtime).is_some(),
            "numeric uniform map values must remain numeric after __index"
        );

        let text_locals = [
            f64::from_bits(text_map),
            f64::from_bits(key),
            f64::from_bits(text_value),
        ];
        assert!(
            analyze_bounds_guards(&code, 0, code.len() - 1, &text_locals, &runtime).is_none(),
            "non-numeric map values must not be admitted into a numeric comparison"
        );
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn list_bounds_guard_covers_exact_alias_but_not_unrelated_list() {
        let mut runtime = jit::JitRuntime::new();
        let guarded_list = runtime.make_list(&[1.0, 2.0, 3.0]);
        let unrelated_list = runtime.make_list(&[1.0]);
        let locals = [
            f64::from_bits(guarded_list),
            f64::from_bits(guarded_list),
            f64::from_bits(unrelated_list),
            0.0,
        ];
        let guards = std::collections::HashSet::from([(0usize, 3usize)]);

        assert!(bounds_guard_covers_list(&guards, 0, 3, &locals));
        assert!(bounds_guard_covers_list(&guards, 1, 3, &locals));
        assert!(!bounds_guard_covers_list(&guards, 2, 3, &locals));
        assert!(!bounds_guard_covers_list(&guards, 1, 2, &locals));
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn mutation_metadata_expands_only_profiled_collection_aliases() {
        let mut runtime = jit::JitRuntime::new();
        let list_bits = runtime.make_list(&[1.0, 2.0]);
        let list_locals = [f64::from_bits(list_bits), f64::from_bits(list_bits)];
        let list_profile = list_profile(&[0, 1], list_bits, &runtime);
        let mut mutated_lists = std::collections::BTreeSet::from([1usize]);
        expand_profiled_mutation_aliases(
            &mut mutated_lists,
            &list_profile,
            &list_locals,
            vb::TAG_LIST,
        );
        assert_eq!(
            mutated_lists,
            std::collections::BTreeSet::from([0usize, 1usize])
        );

        let keys = vec!["k0".to_string()];
        let map_bits = runtime.make_map(&keys, &[1.0f64.to_bits()]);
        let map_locals = [f64::from_bits(map_bits), f64::from_bits(map_bits)];
        let map_profile = map_profile(&[0, 1], map_bits, &runtime);
        let mut mutated_maps = std::collections::BTreeSet::from([0usize]);
        expand_profiled_mutation_aliases(&mut mutated_maps, &map_profile, &map_locals, vb::TAG_MAP);
        assert_eq!(
            mutated_maps,
            std::collections::BTreeSet::from([0usize, 1usize])
        );
    }

    #[test]
    fn speculative_deopt_lifetime_totals_survive_pressure_reset() {
        let mut trace_total = 0u64;
        let mut trace_reasons = HashMap::new();
        let mut telemetry = TraceTelemetryTotals::default();
        let mut eviction_pressure = 0u32;

        record_speculative_deopt(&mut trace_total, &mut trace_reasons, &mut telemetry, 7);
        eviction_pressure = eviction_pressure.saturating_add(1);
        assert_eq!(eviction_pressure, 1);
        eviction_pressure = 0; // A successful PIC promotion resets only eviction pressure.
        record_speculative_deopt(&mut trace_total, &mut trace_reasons, &mut telemetry, 7);

        assert_eq!(eviction_pressure, 0);
        assert_eq!(trace_total, 2);
        assert_eq!(telemetry.deopts_total, 2);
        assert_eq!(trace_reasons.get("runtime_site_7"), Some(&2));
        assert_eq!(
            telemetry.deopt_reason_counts.get("runtime_site_7"),
            Some(&2)
        );
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn profiled_branch_counters_preserve_cmp_flags_and_scratch_registers() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::ConstNum(10.0),
            TraceOp::LtNum,
            TraceOp::GuardFalse,
            TraceOp::AddLocalConst(0, 1.0),
            TraceOp::JumpStart,
        ];
        let exec = jit::compile_trace_typed(&ops, &[], 0, true, &[], &[])
            .expect("profiled trace should compile");
        assert!(exec.profile_enabled());
        assert!(!exec.patch_sites().is_empty());

        let mut runtime = jit::JitRuntime::new();
        runtime.set_profile_enabled(true);
        runtime.set_profile_site_count(exec.patch_sites().len());
        runtime.reset_profile_counters();
        let mut locals = vec![0.0f64];
        let mut stack = vec![0.0f64; 16];
        let _ = exec.run(&mut locals, &mut stack, &mut runtime);

        assert_eq!(locals[0], 10.0);
        assert_eq!(runtime.exit_flag, 1);
        let profile = runtime.profile_snapshot();
        let (site_taken, site_not_taken) = (0..exec.patch_sites().len())
            .map(|site_idx| {
                runtime
                    .profile_site_snapshot(site_idx)
                    .expect("compiled patch site should have a runtime counter")
            })
            .fold(
                (0u64, 0u64),
                |(taken, not_taken), (site_taken, site_not_taken)| {
                    (
                        taken.saturating_add(site_taken),
                        not_taken.saturating_add(site_not_taken),
                    )
                },
            );
        assert!(profile.trace_iters >= 10);
        assert!(profile.branch_taken > 0);
        assert!(profile.branch_not_taken > 0);
        assert_eq!(profile.branch_taken, site_taken);
        assert_eq!(profile.branch_not_taken, site_not_taken);
    }

    #[test]
    fn mark_temp_allocs_marks_non_escaping_map() {
        let ops = vec![
            TraceOp::ConstNum(1.0),
            TraceOp::MakeMap(vec!["x".to_string()]),
            TraceOp::LoadField("x".to_string()),
            TraceOp::Pop,
            TraceOp::JumpStart,
        ];
        let out = mark_temp_allocs(&ops, &std::collections::BTreeSet::new());
        assert!(matches!(out[1], TraceOp::MakeMapTemp(_)));
    }

    #[test]
    fn list_mutation_unroll_accepts_non_multiple_length_with_scalar_tail() {
        let ops = vec![
            TraceOp::GuardListBounds(0, 1),
            TraceOp::LoadLocal(1),
            TraceOp::ConstNum(55.0),
            TraceOp::LtNum,
            TraceOp::GuardFalse,
            TraceOp::IndexListNumLocalPtr(0, 1, 0x1000),
            TraceOp::StoreLocal(2),
            TraceOp::LoadLocal(2),
            TraceOp::AddLocalFromStack(3),
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::LoadLocal(2),
            TraceOp::ConstNum(1.0),
            TraceOp::AddNum,
            TraceOp::SetIndexListNumLocalPtrNoVer(0, 1, 0x1000),
            TraceOp::StoreLocal(4),
            TraceOp::AddLocalConst(1, 1.0),
            TraceOp::JumpStart,
        ];

        let unrolled = unroll_list_update_x4(&ops);
        assert!(matches!(unrolled[2], TraceOp::ConstNum(limit) if limit == 52.0));
        assert_eq!(
            unrolled
                .iter()
                .filter(|op| matches!(op, TraceOp::IndexListNumLocalPtrOff(..)))
                .count(),
            4
        );
        assert_eq!(
            unrolled
                .iter()
                .filter(|op| matches!(op, TraceOp::SetIndexListNumLocalPtrNoVerOff(..)))
                .count(),
            4
        );
        assert!(unrolled
            .iter()
            .any(|op| matches!(op, TraceOp::AddLocalConst(1, step) if *step == 4.0)));
        assert_eq!(
            unrolled
                .iter()
                .filter(|op| matches!(op, TraceOp::BumpListVersionLocal(0)))
                .count(),
            1
        );
        let offsets: Vec<i32> = unrolled
            .iter()
            .filter_map(|op| match op {
                TraceOp::SetIndexListNumLocalPtrNoVerOff(_, _, _, offset) => Some(*offset),
                _ => None,
            })
            .collect();
        assert_eq!(offsets, vec![0, 1, 2, 3]);
    }

    #[test]
    fn list_mutation_unroll_rejects_induction_value_used_as_lane_data() {
        let ops = vec![
            TraceOp::GuardListBounds(0, 1),
            TraceOp::LoadLocal(1),
            TraceOp::ConstNum(55.0),
            TraceOp::LtNum,
            TraceOp::GuardFalse,
            TraceOp::IndexListNumLocalPtr(0, 1, 0x1000),
            TraceOp::StoreLocal(2),
            TraceOp::LoadLocal(2),
            TraceOp::AddLocalFromStack(3),
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::LoadLocal(1),
            TraceOp::ConstNum(1.0),
            TraceOp::AddNum,
            TraceOp::SetIndexListNumLocalPtrNoVer(0, 1, 0x1000),
            TraceOp::StoreLocal(4),
            TraceOp::AddLocalConst(1, 1.0),
            TraceOp::JumpStart,
        ];

        let candidate = unroll_list_update_x4(&ops);
        assert_eq!(format!("{candidate:?}"), format!("{ops:?}"));
    }

    #[test]
    fn dead_store_elimination_preserves_loop_carried_store() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::ConstNum(1.0),
            TraceOp::AddNum,
            TraceOp::StoreLocal(0),
            TraceOp::JumpStart,
        ];

        let optimized = eliminate_dead_stores(&ops);

        assert!(matches!(optimized[3], TraceOp::StoreLocal(0)));
    }

    #[test]
    fn trace_optimizer_reaches_fixed_point_for_identity_store_chain() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::ConstNum(0.0),
            TraceOp::AddNum,
            TraceOp::Dup,
            TraceOp::StoreLocal(0),
            TraceOp::ConstNum(0.0),
            TraceOp::AddNum,
            TraceOp::Dup,
            TraceOp::StoreLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::AddNum,
            TraceOp::StoreLocal(0),
        ];

        let optimized = optimize_trace_ops(&ops);

        assert_eq!(optimized.len(), 2);
        assert!(matches!(optimized[0], TraceOp::LoadLocal(1)));
        assert!(matches!(optimized[1], TraceOp::AddLocalFromStack(0)));
    }

    #[test]
    fn mark_temp_allocs_keeps_escaping_map_heap_alloc() {
        let ops = vec![
            TraceOp::ConstNum(1.0),
            TraceOp::MakeMap(vec!["x".to_string()]),
            TraceOp::StoreLocal(0),
            TraceOp::JumpStart,
        ];
        let out = mark_temp_allocs(&ops, &std::collections::BTreeSet::new());
        assert!(matches!(out[1], TraceOp::MakeMap(_)));
    }

    #[test]
    fn mark_temp_allocs_allows_write_first_local_map() {
        let ops = vec![
            TraceOp::ConstNum(1.0),
            TraceOp::MakeMap(vec!["x".to_string()]),
            TraceOp::StoreLocal(0),
            TraceOp::JumpStart,
        ];
        let mut write_first = std::collections::BTreeSet::new();
        write_first.insert(0);
        let out = mark_temp_allocs(&ops, &write_first);
        assert!(matches!(out[1], TraceOp::MakeMapTemp(_)));
    }

    #[test]
    fn unsupported_internal_backedge_detects_nested_loop() {
        let code = vec![
            Instr::LoadLocal(0),
            Instr::Jump(1),
            Instr::Jump(0),
            Instr::Return,
        ];
        assert_eq!(
            find_unsupported_internal_backedge(&code, 0, 2),
            Some((1, 1))
        );
    }

    #[test]
    fn unsupported_internal_backedge_allows_forward_branch_and_outer_loop_backedge() {
        let code = vec![
            Instr::LoadLocal(0),
            Instr::Jump(2),
            Instr::Jump(0),
            Instr::Return,
        ];
        assert_eq!(find_unsupported_internal_backedge(&code, 0, 2), None);
    }

    #[test]
    fn optimize_trace_ops_fuses_index_ptr_off_accumulate_roundtrip() {
        let ops = vec![
            TraceOp::LoadLocal(6),
            TraceOp::IndexListNumLocalPtrOff(2, 5, 0xCAFE, 3),
            TraceOp::AddNum,
            TraceOp::StoreLocal(6),
            TraceOp::JumpStart,
        ];
        let out = optimize_trace_ops(&ops);
        assert_eq!(out.len(), 3);
        assert!(matches!(
            out[0],
            TraceOp::IndexListNumLocalPtrOff(2, 5, 0xCAFE, 3)
        ));
        assert!(matches!(out[1], TraceOp::AddLocalFromStack(6)));
        assert!(matches!(out[2], TraceOp::JumpStart));
    }

    #[test]
    fn optimize_trace_ops_fuses_index_local_accumulate_roundtrip() {
        let ops = vec![
            TraceOp::LoadLocal(4),
            TraceOp::IndexListNumLocal(2, 5),
            TraceOp::AddNum,
            TraceOp::StoreLocal(4),
            TraceOp::JumpStart,
        ];
        let out = optimize_trace_ops(&ops);
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], TraceOp::IndexListNumLocal(2, 5)));
        assert!(matches!(out[1], TraceOp::AddLocalFromStack(4)));
        assert!(matches!(out[2], TraceOp::JumpStart));
    }

    #[test]
    fn rewrite_map_stable_cmp_branch_elides_tmp_local_roundtrip() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE),
            TraceOp::StoreLocal(2),
            TraceOp::LoadLocal(2),
            TraceOp::ConstNum(64.0),
            TraceOp::GtNum,
            TraceOp::GuardFalse,
            TraceOp::JumpStart,
        ];
        let (out, hits) = rewrite_map_stable_cmp_branch(&ops);
        assert_eq!(hits, 1);
        assert_eq!(out.len(), 7);
        assert!(matches!(out[0], TraceOp::LoadLocal(0)));
        assert!(matches!(out[1], TraceOp::LoadLocal(1)));
        assert!(matches!(
            out[2],
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE)
        ));
        assert!(matches!(out[3], TraceOp::ConstNum(v) if (v - 64.0).abs() < f64::EPSILON));
        assert!(matches!(out[4], TraceOp::GtNum));
        assert!(matches!(out[5], TraceOp::GuardFalse));
        assert!(matches!(out[6], TraceOp::JumpStart));
    }

    #[test]
    fn rewrite_map_stable_cmp_branch_preserves_deopt_guard_target() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE),
            TraceOp::StoreLocal(2),
            TraceOp::LoadLocal(2),
            TraceOp::ConstNum(64.0),
            TraceOp::GtNum,
            TraceOp::GuardFalseDeopt(1234),
            TraceOp::JumpStart,
        ];
        let (out, hits) = rewrite_map_stable_cmp_branch(&ops);
        assert_eq!(hits, 1);
        assert_eq!(out.len(), 7);
        assert!(matches!(out[4], TraceOp::GtNum));
        assert!(matches!(out[5], TraceOp::GuardFalseDeopt(1234)));
        assert!(matches!(out[6], TraceOp::JumpStart));
    }

    #[test]
    fn rewrite_map_stable_cmp_branch_preserves_native_branch_target() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE),
            TraceOp::StoreLocal(2),
            TraceOp::LoadLocal(2),
            TraceOp::ConstNum(64.0),
            TraceOp::GtNum,
            TraceOp::BranchFalse(1234),
            TraceOp::JumpStart,
        ];
        let (out, hits) = rewrite_map_stable_cmp_branch(&ops);
        assert_eq!(hits, 1);
        assert_eq!(out.len(), 7);
        assert!(matches!(out[4], TraceOp::GtNum));
        assert!(matches!(out[5], TraceOp::BranchFalse(1234)));
        assert!(matches!(out[6], TraceOp::JumpStart));
    }

    #[test]
    fn rewrite_map_stable_cmp_branch_accepts_store_local_keep_shape() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE),
            TraceOp::Dup,
            TraceOp::StoreLocal(2),
            TraceOp::ConstNum(64.0),
            TraceOp::GtNum,
            TraceOp::GuardFalseDeopt(1234),
            TraceOp::StoreLocal(2),
            TraceOp::JumpStart,
        ];
        let (out, hits) = rewrite_map_stable_cmp_branch(&ops);
        assert_eq!(hits, 1);
        assert_eq!(out.len(), 8);
        assert!(matches!(out[0], TraceOp::LoadLocal(0)));
        assert!(matches!(out[1], TraceOp::LoadLocal(1)));
        assert!(matches!(
            out[2],
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE)
        ));
        assert!(matches!(out[3], TraceOp::ConstNum(v) if (v - 64.0).abs() < f64::EPSILON));
        assert!(matches!(out[4], TraceOp::GtNum));
        assert!(matches!(out[5], TraceOp::GuardFalseDeopt(1234)));
        assert!(matches!(out[6], TraceOp::StoreLocal(2)));
        assert!(matches!(out[7], TraceOp::JumpStart));
    }

    #[test]
    fn rewrite_map_stable_cmp_branch_keeps_tmp_if_reused_before_overwrite() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE),
            TraceOp::StoreLocal(2),
            TraceOp::LoadLocal(2),
            TraceOp::ConstNum(64.0),
            TraceOp::GtNum,
            TraceOp::GuardFalse,
            TraceOp::LoadLocal(2),
            TraceOp::StoreLocal(2),
            TraceOp::JumpStart,
        ];
        let (out, hits) = rewrite_map_stable_cmp_branch(&ops);
        assert_eq!(hits, 0);
        assert_eq!(format!("{:?}", out), format!("{:?}", ops));
    }

    #[test]
    fn rewrite_map_stable_cmp_branch_keeps_store_local_keep_when_tmp_is_live() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE),
            TraceOp::Dup,
            TraceOp::StoreLocal(2),
            TraceOp::ConstNum(64.0),
            TraceOp::GtNum,
            TraceOp::GuardFalse,
            TraceOp::LoadLocal(2),
            TraceOp::StoreLocal(3),
            TraceOp::JumpStart,
        ];
        let (out, hits) = rewrite_map_stable_cmp_branch(&ops);
        assert_eq!(hits, 0);
        assert_eq!(format!("{out:?}"), format!("{ops:?}"));
    }

    #[test]
    fn rewrite_map_stable_mul_acc_elides_tmp_locals() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE),
            TraceOp::StoreLocal(2),
            TraceOp::LoadLocal(2),
            TraceOp::ConstNum(1.5),
            TraceOp::MulNum,
            TraceOp::StoreLocal(3),
            TraceOp::LoadLocal(3),
            TraceOp::AddLocalFromStack(4),
            TraceOp::JumpStart,
        ];
        let (out, hits) = rewrite_map_stable_mul_acc(&ops);
        assert_eq!(hits, 1);
        assert_eq!(out.len(), 7);
        assert!(matches!(out[0], TraceOp::LoadLocal(0)));
        assert!(matches!(out[1], TraceOp::LoadLocal(1)));
        assert!(matches!(
            out[2],
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE)
        ));
        assert!(matches!(out[3], TraceOp::ConstNum(v) if (v - 1.5).abs() < f64::EPSILON));
        assert!(matches!(out[4], TraceOp::MulNum));
        assert!(matches!(out[5], TraceOp::AddLocalFromStack(4)));
        assert!(matches!(out[6], TraceOp::JumpStart));
    }

    #[test]
    fn rewrite_map_stable_mul_acc_keeps_tmp_if_reused_before_overwrite() {
        let ops = vec![
            TraceOp::LoadLocal(0),
            TraceOp::LoadLocal(1),
            TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(0, 1, 123, 77, 0xCAFE),
            TraceOp::StoreLocal(2),
            TraceOp::LoadLocal(2),
            TraceOp::ConstNum(1.5),
            TraceOp::MulNum,
            TraceOp::StoreLocal(3),
            TraceOp::LoadLocal(3),
            TraceOp::AddLocalFromStack(4),
            TraceOp::LoadLocal(3),
            TraceOp::StoreLocal(3),
            TraceOp::JumpStart,
        ];
        let (out, hits) = rewrite_map_stable_mul_acc(&ops);
        assert_eq!(hits, 0);
        assert_eq!(format!("{:?}", out), format!("{:?}", ops));
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn map_guard_non_mutated_rejects_version_change() {
        let mut runtime = jit::JitRuntime::new();
        let keys = vec!["k0".to_string()];
        let values = vec![1.0f64.to_bits()];
        let map_bits = runtime.make_map(&keys, &values);
        let profile = map_profile(&[0], map_bits, &runtime);
        let locals = [map_bits];
        assert!(eval_guard(&profile, &locals, &[], &[], &runtime));

        let key = runtime.make_text("k0");
        runtime.map_set(map_bits, key, 2.0f64.to_bits());
        assert!(!eval_guard(&profile, &locals, &[], &[], &runtime));
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn map_guard_mutated_requires_uniform_value_tag() {
        let mut runtime = jit::JitRuntime::new();
        let keys = vec!["k0".to_string(), "k1".to_string()];
        let values = vec![1.0f64.to_bits(), 2.0f64.to_bits()];
        let map_bits = runtime.make_map(&keys, &values);
        let profile = map_profile(&[0], map_bits, &runtime);
        let locals = [map_bits];

        let key0 = runtime.make_text("k0");
        runtime.map_set(map_bits, key0, 3.0f64.to_bits());
        assert!(eval_guard(&profile, &locals, &[], &[0], &runtime));

        let key1 = runtime.make_text("k1");
        let text_bits = runtime.make_text("boom");
        runtime.map_set(map_bits, key1, text_bits);
        assert!(!eval_guard(&profile, &locals, &[], &[0], &runtime));
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn map_guard_alias_requires_all_aliases_marked_mutated() {
        let mut runtime = jit::JitRuntime::new();
        let keys = vec!["k0".to_string()];
        let values = vec![1.0f64.to_bits()];
        let map_bits = runtime.make_map(&keys, &values);
        let profile = map_profile(&[0, 1], map_bits, &runtime);
        let locals = [map_bits, map_bits];
        let key0 = runtime.make_text("k0");

        for i in 0..64 {
            runtime.map_set(map_bits, key0, (i as f64).to_bits());
            assert!(!eval_guard(&profile, &locals, &[], &[0], &runtime));
            assert!(eval_guard(&profile, &locals, &[], &[0, 1], &runtime));
        }
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn list_guard_non_mutated_rejects_version_change() {
        let mut runtime = jit::JitRuntime::new();
        let list_bits = runtime.make_list(&[1.0, 2.0, 3.0]);
        let profile = list_profile(&[0], list_bits, &runtime);
        let locals = [list_bits];
        assert!(eval_guard(&profile, &locals, &[], &[], &runtime));

        runtime.setindex(list_bits, 0.0f64.to_bits(), 4.0f64.to_bits());
        assert!(!eval_guard(&profile, &locals, &[], &[], &runtime));
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn list_guard_mutated_requires_uniform_tag() {
        let mut runtime = jit::JitRuntime::new();
        let list_bits = runtime.make_list(&[1.0, 2.0, 3.0]);
        let profile = list_profile(&[0], list_bits, &runtime);
        let locals = [list_bits];

        runtime.setindex(list_bits, 1.0f64.to_bits(), 5.0f64.to_bits());
        assert!(eval_guard(&profile, &locals, &[0], &[], &runtime));

        let text_bits = runtime.make_text("x");
        runtime.setindex(list_bits, 2.0f64.to_bits(), text_bits);
        assert!(!eval_guard(&profile, &locals, &[0], &[], &runtime));
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn list_guard_alias_requires_all_aliases_marked_mutated() {
        let mut runtime = jit::JitRuntime::new();
        let list_bits = runtime.make_list(&[1.0, 2.0, 3.0]);
        let profile = list_profile(&[0, 1], list_bits, &runtime);
        let locals = [list_bits, list_bits];

        for i in 0..32 {
            runtime.setindex(list_bits, 0.0f64.to_bits(), (i as f64).to_bits());
            assert!(!eval_guard(&profile, &locals, &[0], &[], &runtime));
            assert!(eval_guard(&profile, &locals, &[0, 1], &[], &runtime));
        }
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn build_trace_plan_emits_bounds_guard_outside_unsafe_index() {
        let mut runtime = jit::JitRuntime::new();
        let list_bits = runtime.make_list(&[1.0, 2.0, 3.0, 4.0]);
        let mut code = vec![
            Instr::LoadLocal(1),
            Instr::LoadLocal(0),
            Instr::CallBuiltin("len".into(), 1),
            Instr::Lt,
            Instr::JumpIfFalse(0),
            Instr::LoadLocal(0),
            Instr::LoadLocal(1),
            Instr::CallBuiltin("__index".into(), 2),
            Instr::Pop,
        ];
        for _ in 0..8 {
            code.push(Instr::LoadLocal(1));
            code.push(Instr::Pop);
        }
        let backedge = code.len();
        code.push(Instr::Jump(0));
        let exit = code.len();
        if let Instr::JumpIfFalse(target) = &mut code[4] {
            *target = exit;
        }
        let locals = [f64::from_bits(list_bits), 0.0f64];
        let unsafe_flags = vec![false; code.len()];
        let guards = analyze_bounds_guards(&code, 0, backedge, &locals, &runtime)
            .expect("guard analysis should succeed");
        assert!(
            guards.contains(&(0, 1)),
            "expected list/index guard pair, got {guards:?}"
        );
        let plan = build_trace_plan(&code, 0, backedge, &locals, &runtime, &unsafe_flags)
            .expect("trace plan should compile");
        assert!(plan.ops.iter().any(|op| {
            matches!(
                op,
                TraceOp::GuardListBounds(_, _)
                    | TraceOp::GuardIndexCmpConst(_, _, _)
                    | TraceOp::GuardIndexRangeConst(_, _, _)
                    | TraceOp::GuardIndexNonNeg(_)
            )
        }));
        assert!(plan.ops.iter().any(|op| {
            matches!(
                op,
                TraceOp::IndexListNum
                    | TraceOp::IndexListNumLocal(_, _)
                    | TraceOp::IndexListNumLocalPtr(_, _, _)
                    | TraceOp::IndexListNumLocalPtrOff(_, _, _, _)
            )
        }));
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn build_trace_plan_skips_bounds_guard_inside_unsafe_index() {
        let mut runtime = jit::JitRuntime::new();
        let list_bits = runtime.make_list(&[1.0, 2.0, 3.0, 4.0]);
        let mut code = vec![
            Instr::LoadLocal(1),
            Instr::LoadLocal(0),
            Instr::CallBuiltin("len".into(), 1),
            Instr::Lt,
            Instr::JumpIfFalse(0),
            Instr::LoadLocal(0),
            Instr::LoadLocal(1),
            Instr::CallBuiltin("__index".into(), 2),
            Instr::Pop,
        ];
        for _ in 0..8 {
            code.push(Instr::LoadLocal(1));
            code.push(Instr::Pop);
        }
        let backedge = code.len();
        code.push(Instr::Jump(0));
        let exit = code.len();
        if let Instr::JumpIfFalse(target) = &mut code[4] {
            *target = exit;
        }
        let locals = [f64::from_bits(list_bits), 0.0f64];
        let mut unsafe_flags = vec![false; code.len()];
        unsafe_flags[5] = true;
        unsafe_flags[6] = true;
        unsafe_flags[7] = true;
        let plan = build_trace_plan(&code, 0, backedge, &locals, &runtime, &unsafe_flags)
            .expect("trace plan should compile");
        assert!(!plan
            .ops
            .iter()
            .any(|op| matches!(op, TraceOp::GuardListBounds(_, _))));
        assert!(plan.ops.iter().any(|op| {
            matches!(
                op,
                TraceOp::IndexListNum
                    | TraceOp::IndexListNumLocal(_, _)
                    | TraceOp::IndexListNumLocalPtr(_, _, _)
                    | TraceOp::IndexListNumLocalPtrOff(_, _, _, _)
            )
        }));
    }

    #[cfg_attr(
        any(not(target_arch = "x86_64"), windows),
        ignore = "x64 JIT runtime is disabled on this target"
    )]
    #[test]
    fn build_trace_plan_unsafe_setindex_uses_raw_op() {
        let mut runtime = jit::JitRuntime::new();
        let list_bits = runtime.make_list(&[1.0, 2.0, 3.0, 4.0]);
        let mut code = vec![
            Instr::LoadLocal(1),
            Instr::LoadLocal(0),
            Instr::CallBuiltin("len".into(), 1),
            Instr::Lt,
            Instr::JumpIfFalse(0),
            Instr::LoadLocal(0),
            Instr::LoadLocal(1),
            Instr::ConstNum(9.0),
            Instr::CallBuiltin("__setindex".into(), 3),
            Instr::Pop,
        ];
        for _ in 0..8 {
            code.push(Instr::LoadLocal(1));
            code.push(Instr::Pop);
        }
        let backedge = code.len();
        code.push(Instr::Jump(0));
        let exit = code.len();
        if let Instr::JumpIfFalse(target) = &mut code[4] {
            *target = exit;
        }
        let locals = [f64::from_bits(list_bits), 0.0f64];
        let mut unsafe_flags = vec![false; code.len()];
        unsafe_flags[5] = true;
        unsafe_flags[6] = true;
        unsafe_flags[7] = true;
        unsafe_flags[8] = true;
        unsafe_flags[9] = true;
        let plan = build_trace_plan(&code, 0, backedge, &locals, &runtime, &unsafe_flags)
            .expect("trace plan should compile");
        assert!(plan
            .ops
            .iter()
            .any(|op| matches!(op, TraceOp::SetIndexListNum)));
        assert!(!plan
            .ops
            .iter()
            .any(|op| matches!(op, TraceOp::GuardListBounds(_, _))));
    }
}
