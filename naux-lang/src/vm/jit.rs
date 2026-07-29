//! Minimal x86_64 JIT backend (no external deps).
#![allow(dead_code)]

use crate::vm::bytecode::{Instr, Program};

#[derive(Clone, Debug)]
pub enum TraceOp {
    ConstNum(f64),
    ConstBool(bool),
    ConstText(String),
    PushNull,
    Dup,
    InitLocalConst(usize, f64),
    LoadLocal(usize),
    StoreLocal(usize),
    AddLocalConst(usize, f64),
    AddLocalFromStack(usize),
    LenListLocal(usize),
    IndexListNumLocal(usize, usize),
    IndexListNumLocalPtr(usize, usize, u64),
    IndexListNumLocalPtrOff(usize, usize, u64, i32),
    SetIndexListNumLocalPtr(usize, usize, u64),
    SetIndexListNumLocalNoVer(usize, usize),
    SetIndexListNumLocalPtrNoVer(usize, usize, u64),
    SetIndexListNumLocalPtrNoVerOff(usize, usize, u64, i32),
    SetIndexListNumLocalPtrNoVerFast(usize, usize, u64),
    SetIndexListNumLocalPtrNoVerOffFast(usize, usize, u64, i32),
    BumpListVersionLocal(usize),
    MakeListTemp(usize),
    AddNum,
    SubNum,
    MulNum,
    DivNum,
    EqNum,
    NeNum,
    LtNum,
    LeNum,
    GtNum,
    GeNum,
    Label(usize),
    BranchFalse(usize),
    JumpTo(usize),
    JumpStart,
    GuardFalse,
    GuardFalseDeopt(usize),
    GuardIndexCmpConst(usize, f64, bool),
    GuardIndexRangeConst(usize, f64, bool),
    GuardListBounds(usize, usize),
    GuardIndexNonNeg(usize),
    GuardListNoAliasSameLen(usize, usize),
    MakeList(usize),
    MakeMap(Vec<String>),
    MakeMapTemp(Vec<String>),
    LoadField(String),
    MapGetSlot(usize),
    MapGetSlotNoVerGuard(usize, usize, usize, u64, usize),
    MapGetSlotPtr(u64),
    MapGetSlotPtrNoVer(usize, usize, usize, u64, u64),
    MapGetSmallKeyNoVer(usize, usize, usize, usize, u64),
    MapGetTextKeyNoVer(usize, usize, usize, usize, u64),
    MapGetTextKeyConstNoVer(usize, usize, u64, usize, usize, u64, u64, usize, u64),
    MapGetTextKeyConstSlotPtrNoVer(usize, usize, u64, usize, usize, u64, u64),
    // Stable const-key path: map-shape guard is hoisted to trace-entry profile guard.
    // This op keeps only key-bits guard and direct value load in the hot loop body.
    MapGetTextKeyConstSlotPtrStableNoVer(usize, usize, u64, usize, u64),
    // Stable const-key map-get + accumulate directly into local accumulator.
    // Deopt semantics are preserved by consuming map/key from stack.
    MapGetTextKeyConstSlotPtrStableAddLocalNoVer(usize, usize, u64, usize, u64, usize),
    MapGetTextKeyConstSlotPtrPic2NoVer(usize, usize, u64, usize, usize, u64, u64, usize, u64, u64),
    MapSetSlotPtrNoVer(usize, u64),
    MapSetSlotPtrNoVerGuard(usize, usize, usize, u64, u64),
    MapSetSlotNoVer(usize, usize),
    MapSetSlotNoVerGuard(usize, usize, usize, u64, usize),
    MapSetSmallKeyNoVer(usize, usize, usize, usize, u64),
    MapSetTextKeyNoVer(usize, usize, usize, usize, u64),
    MapSetTextKeyConstNoVer(usize, usize, u64, usize, usize, u64, u64, usize, u64),
    MapSetTextKeyConstSlotPtrNoVer(usize, usize, u64, usize, usize, u64, u64),
    MapSetTextKeyConstSlotPtrPic2NoVer(usize, usize, u64, usize, usize, u64, u64, usize, u64, u64),
    IndexListNum,
    LenList,
    SetIndexListNum,
    ToText,
    Pop,
    Return,
    BumpMapVersionLocal(usize),
}

#[derive(Clone, Debug)]
pub enum TempValueSource {
    Local(usize),
    ConstNum(f64),
    Unknown,
}

#[derive(Clone, Debug)]
pub struct TempListSource {
    pub trace_op_index: usize,
    pub len: usize,
    pub sources: Vec<TempValueSource>,
}

pub type JitCallUserFn = extern "C" fn(
    name_ptr: *const u8,
    argc: usize,
    args_ptr: *const f64,
    rt: *mut JitRuntime,
    deopt_ip: usize,
) -> u64;

#[cfg(all(target_arch = "x86_64", not(windows)))]
mod x64 {
    use super::{Instr, JitCallUserFn, TempListSource, TempValueSource, TraceOp};
    use crate::runtime::value::Value;
    use crate::vm::value_bits as vb;
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::fmt;
    use std::sync::{
        atomic::{fence, Ordering},
        OnceLock,
    };

    pub type JitFn = unsafe extern "C" fn(*mut f64, *mut f64, *mut JitRuntime) -> f64;

    const MAX_PROFILE_BRANCH_SITES: usize = 1024;
    const INLINE_TEMP_LIST_MAX: usize = 1024;

    #[derive(Clone, Copy, Debug, Default)]
    struct CpuFeatures {
        osxsave: bool,
        xsave_ymm: bool,
        avx: bool,
        avx2: bool,
        fma: bool,
    }

    impl CpuFeatures {
        fn avx2_fma_ready(self) -> bool {
            self.avx2 && self.fma
        }
    }

    fn detect_cpu_features() -> CpuFeatures {
        unsafe {
            use std::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

            let leaf1 = __cpuid(1);
            let osxsave = (leaf1.ecx & (1 << 27)) != 0;
            let avx_hw = (leaf1.ecx & (1 << 28)) != 0;
            let fma_hw = (leaf1.ecx & (1 << 12)) != 0;

            let xsave_ymm = if osxsave {
                let xcr0 = _xgetbv(0);
                (xcr0 & 0b110) == 0b110
            } else {
                false
            };

            let avx = avx_hw && xsave_ymm;
            let leaf7 = __cpuid_count(7, 0);
            let avx2_hw = (leaf7.ebx & (1 << 5)) != 0;

            CpuFeatures {
                osxsave,
                xsave_ymm,
                avx,
                avx2: avx && avx2_hw,
                fma: avx && fma_hw,
            }
        }
    }

    fn cpu_features() -> CpuFeatures {
        static FEATURES: OnceLock<CpuFeatures> = OnceLock::new();
        *FEATURES.get_or_init(detect_cpu_features)
    }

    fn avx2_dot_kernel_enabled() -> bool {
        let disabled = std::env::var("NAUX_DISABLE_AVX_DOT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if disabled {
            return false;
        }
        let f = cpu_features();
        f.osxsave && f.xsave_ymm && f.avx && f.avx2_fma_ready()
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct JitTraceProfile {
        pub calls: u64,
        pub trace_iters: u64,
        pub branch_taken: u64,
        pub branch_not_taken: u64,
        pub deopts: u64,
        pub temp_list_elided: u64,
        pub temp_map_elided: u64,
        pub temp_list_materialized: u64,
        pub temp_map_materialized: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BranchKind {
        Generic,
        Guard,
        Exit,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct PatchSite {
        pub offset: u32,
        pub kind: BranchKind,
        pub counter_idx: u32,
        pub inverted: bool,
        pub jump_size: u8,
        pub patchable: bool,
        pub invert_taken_jmp_rel32: u32,
        pub invert_not_taken_jmp_rel32: u32,
        pub target_a: u32,
        pub target_b: u32,
    }

    pub struct JitExecutable {
        code: JitCode,
        entry: JitFn,
        hot_code_len: usize,
        temp_list_elems: usize,
        temp_list_count: usize,
        temp_map_count: usize,
        static_calls: u64,
        static_branches: u64,
        profile_enabled: bool,
        patch_sites: Vec<PatchSite>,
    }

    impl JitExecutable {
        pub fn run(&self, locals: &mut [f64], stack: &mut [f64], rt: &mut JitRuntime) -> f64 {
            if self.temp_list_count > 0 {
                rt.prepare_temp_lists(self.temp_list_elems, self.temp_list_count);
            }
            if self.temp_map_count > 0 {
                rt.prepare_temp_maps(self.temp_map_count);
            }
            unsafe {
                (self.entry)(
                    locals.as_mut_ptr(),
                    stack.as_mut_ptr(),
                    rt as *mut JitRuntime,
                )
            }
        }

        pub fn code_len(&self) -> usize {
            self.code.len
        }

        pub fn hot_code_len(&self) -> usize {
            self.hot_code_len
        }

        pub fn static_call_count(&self) -> u64 {
            self.static_calls
        }

        pub fn static_branch_count(&self) -> u64 {
            self.static_branches
        }

        pub fn profile_enabled(&self) -> bool {
            self.profile_enabled
        }

        pub fn patch_sites(&self) -> &[PatchSite] {
            &self.patch_sites
        }

        pub fn patch_flip_site_opcode(&mut self, site_idx: usize) -> Result<bool, String> {
            let Some(site) = self.patch_sites.get(site_idx).copied() else {
                return Ok(false);
            };
            if !site.patchable || site.jump_size != 6 {
                return Ok(false);
            }
            let rel32_at = site.offset as usize;
            if rel32_at < 2 || rel32_at >= self.code.len {
                return Err("invalid patch site offset".into());
            }
            let opcode_at = rel32_at - 1;
            let opcode = unsafe { *self.code.ptr.add(opcode_at) };
            let new_opcode = match opcode {
                0x84 => 0x85, // JE rel32 -> JNE rel32
                0x85 => 0x84, // JNE rel32 -> JE rel32
                _ => return Ok(false),
            };
            unsafe {
                if mprotect(
                    self.code.ptr as *mut c_void,
                    self.code.len,
                    PROT_READ | PROT_WRITE,
                ) != 0
                {
                    return Err("mprotect RW failed".into());
                }
                *self.code.ptr.add(opcode_at) = new_opcode;
                if site.invert_taken_jmp_rel32 != u32::MAX
                    && site.invert_not_taken_jmp_rel32 != u32::MAX
                    && site.target_a != u32::MAX
                    && site.target_b != u32::MAX
                {
                    let (taken_target, not_target) = if site.inverted {
                        (site.target_a as usize, site.target_b as usize)
                    } else {
                        (site.target_b as usize, site.target_a as usize)
                    };
                    Self::patch_rel32_exec(
                        self.code.ptr,
                        self.code.len,
                        site.invert_taken_jmp_rel32 as usize,
                        taken_target,
                    )?;
                    Self::patch_rel32_exec(
                        self.code.ptr,
                        self.code.len,
                        site.invert_not_taken_jmp_rel32 as usize,
                        not_target,
                    )?;
                }
                // x86_64 has coherent I-cache, but fence keeps patch ordering explicit.
                fence(Ordering::SeqCst);
                if mprotect(
                    self.code.ptr as *mut c_void,
                    self.code.len,
                    PROT_READ | PROT_EXEC,
                ) != 0
                {
                    return Err("mprotect RX failed".into());
                }
            }
            if let Some(site_mut) = self.patch_sites.get_mut(site_idx) {
                site_mut.inverted = !site_mut.inverted;
            }
            Ok(true)
        }

        fn patch_rel32_exec(
            code_ptr: *mut u8,
            code_len: usize,
            rel32_at: usize,
            target: usize,
        ) -> Result<(), String> {
            if rel32_at + 4 > code_len || target >= code_len {
                return Err("invalid patch rel32 bounds".into());
            }
            let rel = target as isize - (rel32_at as isize + 4);
            if rel < i32::MIN as isize || rel > i32::MAX as isize {
                return Err("patch rel32 out of range".into());
            }
            let bytes = (rel as i32).to_le_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), code_ptr.add(rel32_at), 4);
            }
            Ok(())
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct JitList {
        version: u64,
        len: usize,
        cap: usize,
        data: *mut u64,
    }

    impl JitList {
        const EMPTY: JitList = JitList {
            version: 0,
            len: 0,
            cap: 0,
            data: std::ptr::null_mut(),
        };
    }

    #[repr(C)]
    pub struct JitText {
        data: String,
        hash: u64,
    }

    #[repr(C)]
    #[derive(Clone, Debug)]
    enum MapKey {
        Small(u64),
        Text(String),
    }

    #[repr(C)]
    #[derive(Clone, Debug)]
    struct MapSlot {
        hash: u64,
        key_bits: u64,
        key_ptr: u64,
        key_len: usize,
        key: MapKey,
        value: u64,
        used: u8,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct TextMeta {
        ptr: u64,
        len: usize,
        hash: u64,
    }

    #[repr(C)]
    pub struct JitMap {
        version: u64,
        len: usize,
        cap: usize,
        slots_ptr: *mut MapSlot,
        slots: Vec<MapSlot>,
    }

    #[repr(C)]
    pub struct JitRuntime {
        pub error: i32,
        pub exit_flag: i32,
        pub deopt_ip: usize,
        pub deopt_sp: usize,
        pub deopt_site: usize,
        pub call_user: Option<JitCallUserFn>,
        pub call_ctx: *mut c_void,
        profile_enabled: u8,
        profile_calls: u64,
        profile_trace_iters: u64,
        profile_deopts: u64,
        profile_temp_list_elided: u64,
        profile_temp_map_elided: u64,
        profile_temp_list_materialized: u64,
        profile_temp_map_materialized: u64,
        profile_branch_sites: usize,
        profile_branch_taken_sites: [u64; MAX_PROFILE_BRANCH_SITES],
        profile_branch_not_taken_sites: [u64; MAX_PROFILE_BRANCH_SITES],
        run_avx_dot_elements: u64,
        run_interp_index_elements: u64,
        text_meta: TextMeta,
        list_allocs: Vec<*mut JitList>,
        text_allocs: Vec<*mut JitText>,
        map_allocs: Vec<*mut JitMap>,
        temp_list_data: Vec<u64>,
        temp_lists: Vec<JitList>,
        temp_data_cursor: usize,
        temp_maps: Vec<JitMap>,
        temp_small_list_count: usize,
        temp_small_list_data: [u64; INLINE_TEMP_LIST_MAX * 4],
        temp_small_lists: [JitList; INLINE_TEMP_LIST_MAX],
    }

    fn hash_bytes(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    fn hash_u64(mut x: u64) -> u64 {
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51afd7ed558ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
        x ^= x >> 33;
        x
    }

    fn hash_str_key(s: &str) -> u64 {
        if let Some(bits) = vb::encode_small_text(s) {
            hash_u64(bits)
        } else {
            hash_bytes(s.as_bytes())
        }
    }

    impl MapKey {
        fn from_str(s: &str) -> MapKey {
            if let Some(bits) = vb::encode_small_text(s) {
                MapKey::Small(bits)
            } else {
                MapKey::Text(s.to_string())
            }
        }

        fn from_bits(bits: u64, rt: &JitRuntime) -> Option<MapKey> {
            if !vb::is_text(bits) {
                return None;
            }
            match vb::tag_of(bits) {
                Some(tag) if tag == vb::TAG_TEXT_SMALL || tag == vb::TAG_TEXT_SMALL6 => {
                    Some(MapKey::Small(bits))
                }
                _ => rt.decode_text(bits).map(|s| {
                    if let Some(small) = vb::encode_small_text(s.as_ref()) {
                        MapKey::Small(small)
                    } else {
                        MapKey::Text(s.into_owned())
                    }
                }),
            }
        }

        fn hash(&self) -> u64 {
            match self {
                MapKey::Small(bits) => hash_u64(*bits),
                MapKey::Text(t) => hash_str_key(t),
            }
        }

        fn slot_bits(&self) -> u64 {
            match self {
                MapKey::Small(bits) => *bits,
                MapKey::Text(_) => 0,
            }
        }

        fn slot_ptr_len(&self) -> (u64, usize) {
            match self {
                MapKey::Small(_) => (0, 0),
                MapKey::Text(t) => (t.as_ptr() as u64, t.len()),
            }
        }

        fn matches_key(&self, other: &MapKey) -> bool {
            match (self, other) {
                (MapKey::Small(a), MapKey::Small(b)) => a == b,
                (MapKey::Text(a), MapKey::Text(b)) => a == b,
                (MapKey::Small(bits), MapKey::Text(t)) | (MapKey::Text(t), MapKey::Small(bits)) => {
                    vb::encode_small_text(t)
                        .map(|b| b == *bits)
                        .unwrap_or(false)
                }
            }
        }

        fn matches_str(&self, s: &str) -> bool {
            match self {
                MapKey::Small(bits) => vb::encode_small_text(s)
                    .map(|b| b == *bits)
                    .unwrap_or(false),
                MapKey::Text(t) => t == s,
            }
        }

        fn matches_bits(&self, bits: u64, rt: &JitRuntime) -> bool {
            if !vb::is_text(bits) {
                return false;
            }
            match self {
                MapKey::Small(b) => *b == bits,
                MapKey::Text(t) => rt
                    .decode_text(bits)
                    .map(|s| s.as_ref() == t)
                    .unwrap_or(false),
            }
        }
    }

    impl fmt::Display for MapKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                MapKey::Small(bits) => {
                    let text = vb::decode_small_text(*bits).unwrap_or_default();
                    f.write_str(&text)
                }
                MapKey::Text(t) => f.write_str(t),
            }
        }
    }

    fn map_capacity_for(len: usize) -> usize {
        let mut cap = len.max(4).saturating_mul(2).next_power_of_two();
        if cap < 8 {
            cap = 8;
        }
        cap
    }

    fn empty_map_slot() -> MapSlot {
        MapSlot {
            hash: 0,
            key_bits: 0,
            key_ptr: 0,
            key_len: 0,
            key: MapKey::Small(0),
            value: vb::tag_null(),
            used: 0,
        }
    }

    fn map_should_grow(len: usize, cap: usize) -> bool {
        len.saturating_mul(10) >= cap.saturating_mul(7)
    }

    fn map_find_slot<F>(map: &JitMap, hash: u64, matches: F) -> Option<usize>
    where
        F: Fn(&MapSlot) -> bool,
    {
        if map.cap == 0 {
            return None;
        }
        let mask = map.cap - 1;
        let mut idx = (hash as usize) & mask;
        for _ in 0..map.cap {
            let slot = &map.slots[idx];
            if slot.used == 0 {
                return None;
            }
            if slot.hash == hash && matches(slot) {
                return Some(idx);
            }
            idx = (idx + 1) & mask;
        }
        None
    }

    fn map_find_insert_slot<F>(map: &JitMap, hash: u64, matches: F) -> (usize, bool)
    where
        F: Fn(&MapSlot) -> bool,
    {
        if map.cap == 0 {
            return (0, false);
        }
        let mask = map.cap - 1;
        let mut idx = (hash as usize) & mask;
        for _ in 0..map.cap {
            let slot = &map.slots[idx];
            if slot.used == 0 {
                return (idx, false);
            }
            if slot.hash == hash && matches(slot) {
                return (idx, true);
            }
            idx = (idx + 1) & mask;
        }
        (0, false)
    }

    fn map_rehash(map: &mut JitMap, new_cap: usize) {
        let mut cap = new_cap.next_power_of_two();
        if cap < 8 {
            cap = 8;
        }
        let mut new_slots: Vec<MapSlot> = (0..cap).map(|_| empty_map_slot()).collect();
        for slot in map.slots.iter_mut().filter(|s| s.used != 0) {
            let hash = slot.hash;
            let key = slot.key.clone();
            let value = slot.value;
            let (key_ptr, key_len) = key.slot_ptr_len();
            let mask = cap - 1;
            let mut idx = (hash as usize) & mask;
            loop {
                if new_slots[idx].used == 0 {
                    new_slots[idx] = MapSlot {
                        hash,
                        key_bits: key.slot_bits(),
                        key_ptr,
                        key_len,
                        key,
                        value,
                        used: 1,
                    };
                    break;
                }
                idx = (idx + 1) & mask;
            }
        }
        map.slots = new_slots;
        map.cap = cap;
        map.slots_ptr = map.slots.as_mut_ptr();
    }

    impl Default for JitRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    impl JitRuntime {
        pub fn new() -> Self {
            Self {
                error: 0,
                exit_flag: 0,
                deopt_ip: 0,
                deopt_sp: 0,
                deopt_site: 0,
                call_user: None,
                call_ctx: std::ptr::null_mut(),
                profile_enabled: 0,
                profile_calls: 0,
                profile_trace_iters: 0,
                profile_deopts: 0,
                profile_temp_list_elided: 0,
                profile_temp_map_elided: 0,
                profile_temp_list_materialized: 0,
                profile_temp_map_materialized: 0,
                profile_branch_sites: 0,
                profile_branch_taken_sites: [0; MAX_PROFILE_BRANCH_SITES],
                profile_branch_not_taken_sites: [0; MAX_PROFILE_BRANCH_SITES],
                run_avx_dot_elements: 0,
                run_interp_index_elements: 0,
                text_meta: TextMeta::default(),
                list_allocs: Vec::new(),
                text_allocs: Vec::new(),
                map_allocs: Vec::new(),
                temp_list_data: Vec::new(),
                temp_lists: Vec::new(),
                temp_data_cursor: 0,
                temp_maps: Vec::new(),
                temp_small_list_count: 0,
                temp_small_list_data: [0; INLINE_TEMP_LIST_MAX * 4],
                temp_small_lists: [JitList::EMPTY; INLINE_TEMP_LIST_MAX],
            }
        }

        pub fn set_profile_enabled(&mut self, enabled: bool) {
            self.profile_enabled = if enabled { 1 } else { 0 };
        }

        pub fn profile_enabled(&self) -> bool {
            self.profile_enabled != 0
        }

        pub fn set_profile_site_count(&mut self, count: usize) {
            self.profile_branch_sites = count.min(MAX_PROFILE_BRANCH_SITES);
        }

        pub fn reset_profile_counters(&mut self) {
            self.profile_calls = 0;
            self.profile_trace_iters = 0;
            self.profile_deopts = 0;
            self.profile_temp_list_elided = 0;
            self.profile_temp_map_elided = 0;
            self.profile_temp_list_materialized = 0;
            self.profile_temp_map_materialized = 0;
            let n = self.profile_branch_sites.min(MAX_PROFILE_BRANCH_SITES);
            for i in 0..n {
                self.profile_branch_taken_sites[i] = 0;
                self.profile_branch_not_taken_sites[i] = 0;
            }
        }

        pub fn profile_snapshot(&self) -> JitTraceProfile {
            let n = self.profile_branch_sites.min(MAX_PROFILE_BRANCH_SITES);
            let mut taken = 0u64;
            let mut not_taken = 0u64;
            for i in 0..n {
                taken = taken.saturating_add(self.profile_branch_taken_sites[i]);
                not_taken = not_taken.saturating_add(self.profile_branch_not_taken_sites[i]);
            }
            JitTraceProfile {
                calls: self.profile_calls,
                trace_iters: self.profile_trace_iters,
                branch_taken: taken,
                branch_not_taken: not_taken,
                deopts: self.profile_deopts,
                temp_list_elided: self.profile_temp_list_elided,
                temp_map_elided: self.profile_temp_map_elided,
                temp_list_materialized: self.profile_temp_list_materialized,
                temp_map_materialized: self.profile_temp_map_materialized,
            }
        }

        pub fn profile_site_snapshot(&self, site_idx: usize) -> Option<(u64, u64)> {
            if site_idx >= self.profile_branch_sites || site_idx >= MAX_PROFILE_BRANCH_SITES {
                return None;
            }
            Some((
                self.profile_branch_taken_sites[site_idx],
                self.profile_branch_not_taken_sites[site_idx],
            ))
        }

        pub fn reset_path_counters(&mut self) {
            self.run_avx_dot_elements = 0;
            self.run_interp_index_elements = 0;
        }

        pub fn path_counters(&self) -> (u64, u64) {
            (self.run_avx_dot_elements, self.run_interp_index_elements)
        }

        pub fn bump_interp_index_elements(&mut self, count: u64) {
            self.run_interp_index_elements = self.run_interp_index_elements.saturating_add(count);
        }

        pub fn cleanup(&mut self) {
            for ptr in self.list_allocs.drain(..) {
                unsafe {
                    let list = Box::from_raw(ptr);
                    if list.cap > 0 || !list.data.is_null() {
                        let _ = Vec::from_raw_parts(list.data, list.len, list.cap);
                    }
                }
            }
            for ptr in self.text_allocs.drain(..) {
                unsafe {
                    drop(Box::from_raw(ptr));
                }
            }
            for ptr in self.map_allocs.drain(..) {
                unsafe {
                    drop(Box::from_raw(ptr));
                }
            }
            self.temp_list_data.clear();
            self.temp_lists.clear();
            self.temp_data_cursor = 0;
            self.temp_maps.clear();
            self.temp_small_list_count = 0;
        }

        pub fn prepare_temp_lists(&mut self, total_elems: usize, total_lists: usize) {
            self.temp_data_cursor = 0;
            self.temp_list_data.clear();
            self.temp_lists.clear();
            self.temp_small_list_count = 0;
            if self.temp_list_data.capacity() < total_elems {
                self.temp_list_data
                    .reserve(total_elems - self.temp_list_data.capacity());
            }
            if self.temp_lists.capacity() < total_lists {
                self.temp_lists
                    .reserve(total_lists - self.temp_lists.capacity());
            }
        }

        pub fn prepare_temp_maps(&mut self, total_maps: usize) {
            self.temp_maps.clear();
            if self.temp_maps.capacity() < total_maps {
                self.temp_maps
                    .reserve(total_maps - self.temp_maps.capacity());
            }
        }

        pub fn reset_temp_allocs(&mut self) {
            self.temp_data_cursor = 0;
            self.temp_lists.clear();
            self.temp_maps.clear();
            self.temp_small_list_count = 0;
        }

        pub fn make_list(&mut self, data: &[f64]) -> u64 {
            let mut bits: Vec<u64> = data.iter().map(|v| v.to_bits()).collect();
            let len = bits.len();
            let cap = bits.capacity();
            let ptr_data = bits.as_mut_ptr();
            std::mem::forget(bits);
            let list = Box::new(JitList {
                version: 0,
                len,
                cap,
                data: ptr_data,
            });
            let ptr = Box::into_raw(list);
            self.list_allocs.push(ptr);
            vb::tag_ptr(ptr as u64, vb::TAG_LIST)
        }

        fn make_list_temp_bits(&mut self, values: &[u64]) -> u64 {
            let len = values.len();
            let start = self.temp_data_cursor;
            let end = start + len;
            if end > self.temp_list_data.capacity() {
                self.error = 1;
                return 0;
            }
            if self.temp_list_data.len() < end {
                self.temp_list_data.resize(end, 0);
            }
            for (i, v) in values.iter().enumerate() {
                self.temp_list_data[start + i] = *v;
            }
            self.temp_data_cursor = end;
            let data_ptr = unsafe { self.temp_list_data.as_mut_ptr().add(start) };
            let list = JitList {
                version: 0,
                len,
                cap: len,
                data: data_ptr,
            };
            self.temp_lists.push(list);
            let ptr = self.temp_lists.last_mut().unwrap() as *mut JitList;
            self.profile_temp_list_elided = self.profile_temp_list_elided.saturating_add(1);
            vb::tag_ptr(ptr as u64, vb::TAG_LIST)
        }

        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub fn make_list_temp(&mut self, data: *const f64, len: usize) -> u64 {
            if data.is_null() {
                self.error = 1;
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut values = Vec::with_capacity(len);
            for v in slice {
                values.push(v.to_bits());
            }
            self.make_list_temp_bits(&values)
        }

        pub fn index(&mut self, list_bits: u64, idx_bits: u64) -> f64 {
            jit_index(list_bits, idx_bits, self as *mut JitRuntime)
        }

        pub fn setindex(&mut self, list_bits: u64, idx_bits: u64, val_bits: u64) -> u64 {
            jit_setindex(list_bits, idx_bits, val_bits, self as *mut JitRuntime)
        }

        pub fn len(&mut self, list_bits: u64) -> f64 {
            jit_len(list_bits, self as *mut JitRuntime)
        }

        pub fn make_text(&mut self, s: &str) -> u64 {
            if let Some(bits) = vb::encode_small_text(s) {
                return bits;
            }
            let hash = hash_bytes(s.as_bytes());
            let text = Box::new(JitText {
                data: s.to_string(),
                hash,
            });
            let ptr = Box::into_raw(text);
            self.text_allocs.push(ptr);
            vb::tag_ptr(ptr as u64, vb::TAG_TEXT)
        }

        pub fn make_map(&mut self, keys: &[String], values: &[u64]) -> u64 {
            if keys.len() != values.len() {
                self.error = 1;
                return vb::tag_null();
            }
            let cap = map_capacity_for(keys.len());
            let mut map = JitMap {
                version: 0,
                len: 0,
                cap,
                slots_ptr: std::ptr::null_mut(),
                slots: (0..cap).map(|_| empty_map_slot()).collect(),
            };
            map.slots_ptr = map.slots.as_mut_ptr();
            for (k, v) in keys.iter().zip(values.iter()) {
                let key = MapKey::from_str(k);
                let hash = key.hash();
                let (key_ptr, key_len) = key.slot_ptr_len();
                if map_should_grow(map.len.saturating_add(1), map.cap) {
                    let new_cap = map.cap.saturating_mul(2);
                    map_rehash(&mut map, new_cap);
                }
                let (idx, found) =
                    map_find_insert_slot(&map, hash, |slot| slot.key.matches_key(&key));
                if found {
                    map.slots[idx].value = *v;
                } else {
                    map.slots[idx] = MapSlot {
                        hash,
                        key_bits: key.slot_bits(),
                        key_ptr,
                        key_len,
                        key,
                        value: *v,
                        used: 1,
                    };
                    map.len = map.len.saturating_add(1);
                }
            }
            let boxed = Box::new(map);
            let ptr = Box::into_raw(boxed);
            self.map_allocs.push(ptr);
            vb::tag_ptr(ptr as u64, vb::TAG_MAP)
        }

        pub fn make_map_temp(&mut self, keys: &[String], values: &[u64]) -> u64 {
            if keys.len() != values.len() {
                self.error = 1;
                return vb::tag_null();
            }
            let cap = map_capacity_for(keys.len());
            let mut map = JitMap {
                version: 0,
                len: 0,
                cap,
                slots_ptr: std::ptr::null_mut(),
                slots: (0..cap).map(|_| empty_map_slot()).collect(),
            };
            for (k, v) in keys.iter().zip(values.iter()) {
                let key = MapKey::from_str(k);
                let hash = key.hash();
                let (slot_idx, exists) =
                    map_find_insert_slot(&map, hash, |slot| slot.key.matches_key(&key));
                if exists {
                    if let Some(slot) = map.slots.get_mut(slot_idx) {
                        slot.value = *v;
                    }
                } else if let Some(slot) = map.slots.get_mut(slot_idx) {
                    let (key_ptr, key_len) = key.slot_ptr_len();
                    *slot = MapSlot {
                        hash,
                        key_bits: key.slot_bits(),
                        key_ptr,
                        key_len,
                        key,
                        value: *v,
                        used: 1,
                    };
                    map.len = map.len.saturating_add(1);
                }
            }
            map.slots_ptr = map.slots.as_mut_ptr();
            self.temp_maps.push(map);
            let ptr = self.temp_maps.last_mut().unwrap() as *mut JitMap;
            self.profile_temp_map_elided = self.profile_temp_map_elided.saturating_add(1);
            vb::tag_ptr(ptr as u64, vb::TAG_MAP)
        }

        fn is_temp_list_ptr(&self, ptr: *const JitList) -> bool {
            let p = ptr as usize;
            if !self.temp_lists.is_empty() {
                let start = self.temp_lists.as_ptr() as usize;
                let end = start + self.temp_lists.len() * std::mem::size_of::<JitList>();
                if p >= start && p < end {
                    return true;
                }
            }
            if self.temp_small_list_count > 0 {
                let start = self.temp_small_lists.as_ptr() as usize;
                let end = start + self.temp_small_list_count * std::mem::size_of::<JitList>();
                if p >= start && p < end {
                    return true;
                }
            }
            false
        }

        fn is_temp_map_ptr(&self, ptr: *const JitMap) -> bool {
            if self.temp_maps.is_empty() {
                return false;
            }
            let start = self.temp_maps.as_ptr() as usize;
            let end = start + self.temp_maps.len() * std::mem::size_of::<JitMap>();
            let p = ptr as usize;
            p >= start && p < end
        }

        fn alloc_list_from_bits(&mut self, data_bits: &[u64]) -> u64 {
            let mut data = data_bits.to_vec();
            let len = data.len();
            let cap = data.capacity();
            let ptr_data = data.as_mut_ptr();
            std::mem::forget(data);
            let list = Box::new(JitList {
                version: 0,
                len,
                cap,
                data: ptr_data,
            });
            let ptr = Box::into_raw(list);
            self.list_allocs.push(ptr);
            vb::tag_ptr(ptr as u64, vb::TAG_LIST)
        }

        fn alloc_map_from_existing(&mut self, map: &JitMap) -> u64 {
            let mut cloned = JitMap {
                version: map.version,
                len: map.len,
                cap: map.cap,
                slots_ptr: std::ptr::null_mut(),
                slots: map.slots.clone(),
            };
            cloned.slots_ptr = cloned.slots.as_mut_ptr();
            let ptr = Box::into_raw(Box::new(cloned));
            self.map_allocs.push(ptr);
            vb::tag_ptr(ptr as u64, vb::TAG_MAP)
        }

        pub fn materialize_temps_in_frame(
            &mut self,
            locals: &mut [f64],
            stack: &mut [f64],
            sp: usize,
        ) {
            if self.temp_lists.is_empty() && self.temp_maps.is_empty() {
                return;
            }
            let mut list_cache: HashMap<u64, u64> = HashMap::new();
            let mut map_cache: HashMap<u64, u64> = HashMap::new();
            let limit = sp.min(stack.len());

            let mut materialize_bits = |bits: u64, this: &mut JitRuntime| -> u64 {
                match vb::tag_of(bits) {
                    Some(tag) if tag == vb::TAG_LIST => {
                        let ptr = vb::payload(bits) as *const JitList;
                        if ptr.is_null() || !this.is_temp_list_ptr(ptr) {
                            return bits;
                        }
                        let key = ptr as u64;
                        if let Some(&cached) = list_cache.get(&key) {
                            return cached;
                        }
                        let list = unsafe { &*ptr };
                        let elems = if list.len == 0 || list.data.is_null() {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(list.data, list.len) }.to_vec()
                        };
                        let heap_bits = this.alloc_list_from_bits(&elems);
                        this.profile_temp_list_materialized =
                            this.profile_temp_list_materialized.saturating_add(1);
                        list_cache.insert(key, heap_bits);
                        heap_bits
                    }
                    Some(tag) if tag == vb::TAG_MAP => {
                        let ptr = vb::payload(bits) as *const JitMap;
                        if ptr.is_null() || !this.is_temp_map_ptr(ptr) {
                            return bits;
                        }
                        let key = ptr as u64;
                        if let Some(&cached) = map_cache.get(&key) {
                            return cached;
                        }
                        let map = unsafe { &*ptr };
                        let heap_bits = this.alloc_map_from_existing(map);
                        this.profile_temp_map_materialized =
                            this.profile_temp_map_materialized.saturating_add(1);
                        map_cache.insert(key, heap_bits);
                        heap_bits
                    }
                    _ => bits,
                }
            };

            for slot in locals.iter_mut() {
                let bits = slot.to_bits();
                let new_bits = materialize_bits(bits, self);
                if new_bits != bits {
                    *slot = f64::from_bits(new_bits);
                }
            }
            for slot in stack.iter_mut().take(limit) {
                let bits = slot.to_bits();
                let new_bits = materialize_bits(bits, self);
                if new_bits != bits {
                    *slot = f64::from_bits(new_bits);
                }
            }
        }

        pub fn map_get_str(&mut self, map_bits: u64, key: &str) -> u64 {
            let Some(map) = self.decode_map(map_bits) else {
                self.error = 1;
                return vb::tag_null();
            };
            let hash = hash_str_key(key);
            let idx = map_find_slot(map, hash, |slot| slot.key.matches_str(key));
            idx.map(|i| map.slots[i].value).unwrap_or_else(vb::tag_null)
        }

        pub fn map_get(&mut self, map_bits: u64, key_bits: u64) -> u64 {
            let Some(map) = self.decode_map(map_bits) else {
                self.error = 1;
                return vb::tag_null();
            };
            if !vb::is_text(key_bits) {
                self.error = 1;
                return vb::tag_null();
            }
            match vb::tag_of(key_bits) {
                Some(tag) if tag == vb::TAG_TEXT_SMALL || tag == vb::TAG_TEXT_SMALL6 => {
                    let hash = hash_u64(key_bits);
                    let idx =
                        map_find_slot(map, hash, |slot| slot.key.matches_bits(key_bits, self));
                    idx.map(|i| map.slots[i].value).unwrap_or_else(vb::tag_null)
                }
                _ => {
                    let Some(key) = self.decode_text(key_bits) else {
                        self.error = 1;
                        return vb::tag_null();
                    };
                    let key_str = key.as_ref();
                    let hash = hash_str_key(key_str);
                    let idx = map_find_slot(map, hash, |slot| slot.key.matches_str(key_str));
                    idx.map(|i| map.slots[i].value).unwrap_or_else(vb::tag_null)
                }
            }
        }

        pub fn map_set(&mut self, map_bits: u64, key_bits: u64, val_bits: u64) -> u64 {
            let Some(key) = MapKey::from_bits(key_bits, self) else {
                self.error = 1;
                return map_bits;
            };
            let Some(map) = self.decode_map_mut(map_bits) else {
                self.error = 1;
                return map_bits;
            };
            if map_should_grow(map.len.saturating_add(1), map.cap) {
                let new_cap = map.cap.saturating_mul(2);
                map_rehash(map, new_cap);
            }
            let hash = key.hash();
            let (key_ptr, key_len) = key.slot_ptr_len();
            let (idx, found) = map_find_insert_slot(map, hash, |slot| slot.key.matches_key(&key));
            if found {
                map.slots[idx].value = val_bits;
            } else {
                map.slots[idx] = MapSlot {
                    hash,
                    key_bits: key.slot_bits(),
                    key_ptr,
                    key_len,
                    key,
                    value: val_bits,
                    used: 1,
                };
                map.len = map.len.saturating_add(1);
            }
            map.version = map.version.wrapping_add(1);
            map_bits
        }

        pub fn map_get_str_slot(&self, map_bits: u64, key: &str) -> Option<usize> {
            let map = self.decode_map(map_bits)?;
            let hash = hash_str_key(key);
            map_find_slot(map, hash, |slot| slot.key.matches_str(key))
        }

        pub fn map_get_str_slot_ptr(&self, map_bits: u64, key: &str) -> Option<u64> {
            let map = self.decode_map(map_bits)?;
            let hash = hash_str_key(key);
            let idx = map_find_slot(map, hash, |slot| slot.key.matches_str(key))?;
            let slots_ptr = map.slots_ptr as u64;
            let slot_size = std::mem::size_of::<MapSlot>() as u64;
            let value_off = std::mem::offset_of!(MapSlot, value) as u64;
            Some(slots_ptr + idx as u64 * slot_size + value_off)
        }

        pub fn map_get_slot_unchecked(&mut self, map_bits: u64, slot_idx: usize) -> u64 {
            let Some(map) = self.decode_map(map_bits) else {
                self.error = 1;
                return vb::tag_null();
            };
            if slot_idx >= map.cap {
                self.error = 1;
                return vb::tag_null();
            }
            let slot = &map.slots[slot_idx];
            if slot.used == 0 {
                self.error = 1;
                return vb::tag_null();
            }
            slot.value
        }

        pub fn list_uniform_tag(&self, list_bits: u64) -> Option<Option<u64>> {
            let list = self.decode_list(list_bits)?;
            if list.len == 0 {
                return None;
            }
            let mut tag: Option<Option<u64>> = None;
            let slice = unsafe { std::slice::from_raw_parts(list.data, list.len) };
            for bits in slice.iter() {
                let current = if vb::is_tagged(*bits) {
                    vb::tag_of(*bits)
                } else {
                    None
                };
                if let Some(prev) = tag {
                    if prev != current {
                        return None;
                    }
                } else {
                    tag = Some(current);
                }
            }
            Some(tag.unwrap_or(None))
        }

        pub fn map_uniform_value_tag(&self, map_bits: u64) -> Option<Option<u64>> {
            let map = self.decode_map(map_bits)?;
            if map.len == 0 {
                return None;
            }
            let mut tag: Option<Option<u64>> = None;
            for bits in map
                .slots
                .iter()
                .filter(|slot| slot.used != 0)
                .map(|s| s.value)
            {
                let current = if vb::is_tagged(bits) {
                    vb::tag_of(bits)
                } else {
                    None
                };
                if let Some(prev) = tag {
                    if prev != current {
                        return None;
                    }
                } else {
                    tag = Some(current);
                }
            }
            Some(tag.unwrap_or(None))
        }

        pub fn list_meta(&self, list_bits: u64) -> Option<(u64, usize, usize, u64, u64)> {
            let list = self.decode_list(list_bits)?;
            let ptr = vb::payload(list_bits);
            let data = list.data as u64;
            Some((ptr, list.len, list.cap, list.version, data))
        }

        pub fn bump_list_version(&mut self, list_bits: u64) {
            if vb::tag_of(list_bits) != Some(vb::TAG_LIST) {
                return;
            }
            let ptr = vb::payload(list_bits) as *mut JitList;
            if ptr.is_null() {
                return;
            }
            unsafe {
                (*ptr).version = (*ptr).version.wrapping_add(1);
            }
        }

        pub fn map_meta(&self, map_bits: u64) -> Option<(u64, usize, u64, u64, usize)> {
            let map = self.decode_map(map_bits)?;
            let ptr = vb::payload(map_bits);
            Some((
                ptr,
                map.cap,
                map.version,
                map.slots_ptr as u64,
                std::mem::size_of::<MapSlot>(),
            ))
        }

        pub fn text_meta(&self, bits: u64) -> Option<(u64, usize, u64)> {
            if vb::tag_of(bits) != Some(vb::TAG_TEXT) {
                return None;
            }
            let ptr = vb::payload(bits) as *const JitText;
            if ptr.is_null() {
                return None;
            }
            let text = unsafe { &*ptr };
            Some((text.data.as_ptr() as u64, text.data.len(), text.hash))
        }

        pub fn to_text_bits(&mut self, bits: u64) -> u64 {
            if vb::is_text(bits) {
                return bits;
            }
            let s = self.format_bits(bits);
            self.make_text(&s)
        }

        pub fn concat_text_bits(&mut self, a_bits: u64, b_bits: u64) -> u64 {
            let a = self.format_bits(a_bits);
            let b = self.format_bits(b_bits);
            self.make_text(&format!("{}{}", a, b))
        }

        pub fn format_bits(&self, bits: u64) -> String {
            if !vb::is_tagged(bits) {
                return f64::from_bits(bits).to_string();
            }
            match vb::tag_of(bits) {
                Some(tag)
                    if tag == vb::TAG_TEXT
                        || tag == vb::TAG_TEXT_SMALL
                        || tag == vb::TAG_TEXT_SMALL6 =>
                {
                    self.decode_text(bits)
                        .map(|s| s.into_owned())
                        .unwrap_or_default()
                }
                Some(tag) if tag == vb::TAG_LIST => {
                    let Some(list) = self.decode_list(bits) else {
                        return "List []".into();
                    };
                    let slice = unsafe { std::slice::from_raw_parts(list.data, list.len) };
                    let items: Vec<String> = slice.iter().map(|b| self.format_bits(*b)).collect();
                    format!("List [{}]", items.join(", "))
                }
                Some(tag) if tag == vb::TAG_MAP => {
                    let Some(map) = self.decode_map(bits) else {
                        return "Map {}".into();
                    };
                    let entries: Vec<String> = map
                        .slots
                        .iter()
                        .filter(|slot| slot.used != 0)
                        .map(|slot| format!("{}:{}", slot.key, self.format_bits(slot.value)))
                        .collect();
                    format!("Map {{{}}}", entries.join(", "))
                }
                Some(tag) if tag == vb::TAG_NULL => "null".into(),
                _ => "null".into(),
            }
        }

        pub fn value_from_bits(&self, bits: u64) -> Value {
            if !vb::is_tagged(bits) {
                return Value::Float(f64::from_bits(bits));
            }
            match vb::tag_of(bits) {
                Some(tag)
                    if tag == vb::TAG_TEXT
                        || tag == vb::TAG_TEXT_SMALL
                        || tag == vb::TAG_TEXT_SMALL6 =>
                {
                    let text = self
                        .decode_text(bits)
                        .map(|s| s.into_owned())
                        .unwrap_or_default();
                    Value::make_text(&text)
                }
                Some(tag) if tag == vb::TAG_LIST => {
                    let Some(list) = self.decode_list(bits) else {
                        return Value::Null;
                    };
                    let slice = unsafe { std::slice::from_raw_parts(list.data, list.len) };
                    let items: Vec<Value> =
                        slice.iter().map(|b| self.value_from_bits(*b)).collect();
                    Value::make_list(items)
                }
                Some(tag) if tag == vb::TAG_MAP => {
                    let Some(map) = self.decode_map(bits) else {
                        return Value::Null;
                    };
                    let mut out = HashMap::new();
                    for slot in map.slots.iter().filter(|s| s.used != 0) {
                        out.insert(slot.key.to_string(), self.value_from_bits(slot.value));
                    }
                    Value::make_map(out)
                }
                Some(tag) if tag == vb::TAG_NULL => Value::Null,
                _ => Value::Null,
            }
        }

        fn decode_list(&self, bits: u64) -> Option<&JitList> {
            if vb::tag_of(bits) != Some(vb::TAG_LIST) {
                return None;
            }
            let ptr = vb::payload(bits) as *const JitList;
            if ptr.is_null() {
                return None;
            }
            unsafe { ptr.as_ref() }
        }

        fn decode_map(&self, bits: u64) -> Option<&JitMap> {
            if vb::tag_of(bits) != Some(vb::TAG_MAP) {
                return None;
            }
            let ptr = vb::payload(bits) as *const JitMap;
            if ptr.is_null() {
                return None;
            }
            unsafe { ptr.as_ref() }
        }

        fn decode_map_mut(&mut self, bits: u64) -> Option<&mut JitMap> {
            if vb::tag_of(bits) != Some(vb::TAG_MAP) {
                return None;
            }
            let ptr = vb::payload(bits) as *mut JitMap;
            if ptr.is_null() {
                return None;
            }
            unsafe { ptr.as_mut() }
        }

        fn decode_text(&self, bits: u64) -> Option<Cow<'_, str>> {
            match vb::tag_of(bits) {
                Some(tag) if tag == vb::TAG_TEXT => {
                    let ptr = vb::payload(bits) as *const JitText;
                    if ptr.is_null() {
                        return None;
                    }
                    unsafe { ptr.as_ref().map(|t| Cow::Borrowed(t.data.as_str())) }
                }
                Some(tag) if tag == vb::TAG_TEXT_SMALL || tag == vb::TAG_TEXT_SMALL6 => {
                    vb::decode_small_text(bits).map(Cow::Owned)
                }
                _ => None,
            }
        }
    }

    extern "C" fn jit_make_list(data: *const f64, len: usize, rt: *mut JitRuntime) -> u64 {
        if data.is_null() {
            unsafe {
                if let Some(rt) = rt.as_mut() {
                    rt.error = 1;
                }
            }
            return 0;
        }
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        let mut bits: Vec<u64> = slice.iter().map(|v| v.to_bits()).collect();
        let cap = bits.capacity();
        let ptr_data = bits.as_mut_ptr();
        std::mem::forget(bits);
        let list = Box::new(JitList {
            version: 0,
            len,
            cap,
            data: ptr_data,
        });
        let ptr = Box::into_raw(list);
        unsafe {
            if let Some(rt) = rt.as_mut() {
                rt.list_allocs.push(ptr);
            }
        }
        vb::tag_ptr(ptr as u64, vb::TAG_LIST)
    }

    extern "C" fn jit_make_list_temp(data: *const f64, len: usize, rt: *mut JitRuntime) -> u64 {
        unsafe {
            if let Some(rt) = rt.as_mut() {
                return rt.make_list_temp(data, len);
            }
        }
        0
    }

    extern "C" fn jit_reset_temps(rt: *mut JitRuntime) {
        unsafe {
            if let Some(rt) = rt.as_mut() {
                rt.reset_temp_allocs();
            }
        }
    }

    unsafe fn read_cstr(ptr: *const u8) -> Option<(String, usize)> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        loop {
            let b = *ptr.add(len);
            if b == 0 {
                break;
            }
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        let s = String::from_utf8_lossy(slice).into_owned();
        Some((s, len + 1))
    }

    extern "C" fn jit_make_text(text_ptr: *const u8, rt: *mut JitRuntime) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        let Some((s, _)) = (unsafe { read_cstr(text_ptr) }) else {
            rt.error = 1;
            return vb::tag_null();
        };
        rt.make_text(&s)
    }

    extern "C" fn jit_call_user(
        name_ptr: *const u8,
        argc: usize,
        args_ptr: *const f64,
        rt: *mut JitRuntime,
        deopt_ip: usize,
    ) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        rt.deopt_ip = deopt_ip;
        let Some(call_user) = rt.call_user else {
            rt.exit_flag = 2;
            return vb::tag_null();
        };
        call_user(name_ptr, argc, args_ptr, rt as *mut JitRuntime, deopt_ip)
    }

    extern "C" fn jit_to_text(bits: u64, rt: *mut JitRuntime) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        rt.to_text_bits(bits)
    }

    extern "C" fn jit_map_get_str(map_bits: u64, key_ptr: *const u8, rt: *mut JitRuntime) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        let Some((key, _)) = (unsafe { read_cstr(key_ptr) }) else {
            rt.error = 1;
            return vb::tag_null();
        };
        rt.map_get_str(map_bits, &key)
    }

    extern "C" fn jit_map_get_str_typed(
        map_bits: u64,
        key_ptr: *const u8,
        rt: *mut JitRuntime,
    ) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        let Some((key, _)) = (unsafe { read_cstr(key_ptr) }) else {
            rt.error = 1;
            return vb::tag_null();
        };
        rt.map_get_str(map_bits, &key)
    }

    extern "C" fn jit_map_get_slot(map_bits: u64, slot_idx: usize, rt: *mut JitRuntime) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        rt.map_get_slot_unchecked(map_bits, slot_idx)
    }

    extern "C" fn jit_map_get_bits(map_bits: u64, key_bits: u64, rt: *mut JitRuntime) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        rt.map_get(map_bits, key_bits)
    }

    extern "C" fn jit_text_meta(bits: u64, rt: *mut JitRuntime) -> *const TextMeta {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return std::ptr::null();
        };
        if vb::tag_of(bits) != Some(vb::TAG_TEXT) {
            rt.error = 1;
            return std::ptr::null();
        }
        let text = unsafe { &*(vb::payload(bits) as *const JitText) };
        rt.text_meta.ptr = text.data.as_ptr() as u64;
        rt.text_meta.len = text.data.len();
        rt.text_meta.hash = text.hash;
        &rt.text_meta as *const TextMeta
    }

    extern "C" fn jit_text_eq(a_ptr: u64, a_len: usize, b_ptr: u64, b_len: usize) -> u8 {
        if a_len != b_len {
            return 0;
        }
        if a_len == 0 {
            return 1;
        }
        unsafe {
            let a = std::slice::from_raw_parts(a_ptr as *const u8, a_len);
            let b = std::slice::from_raw_parts(b_ptr as *const u8, b_len);
            if a == b {
                1
            } else {
                0
            }
        }
    }

    extern "C" fn jit_make_map(
        values_ptr: *const f64,
        len: usize,
        keys_ptr: *const u8,
        rt: *mut JitRuntime,
    ) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        if values_ptr.is_null() || keys_ptr.is_null() {
            rt.error = 1;
            return vb::tag_null();
        }
        let values = unsafe { std::slice::from_raw_parts(values_ptr, len) };
        let mut keys: Vec<String> = Vec::with_capacity(len);
        let mut cursor = keys_ptr;
        for _ in 0..len {
            let Some((key, advance)) = (unsafe { read_cstr(cursor) }) else {
                rt.error = 1;
                return vb::tag_null();
            };
            keys.push(key);
            unsafe {
                cursor = cursor.add(advance);
            }
        }
        let value_bits: Vec<u64> = values.iter().map(|v| v.to_bits()).collect();
        rt.make_map(&keys, &value_bits)
    }

    extern "C" fn jit_make_map_temp(
        values_ptr: *const f64,
        len: usize,
        keys_ptr: *const u8,
        rt: *mut JitRuntime,
    ) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        if values_ptr.is_null() || keys_ptr.is_null() {
            rt.error = 1;
            return vb::tag_null();
        }
        let values = unsafe { std::slice::from_raw_parts(values_ptr, len) };
        let mut keys: Vec<String> = Vec::with_capacity(len);
        let mut cursor = keys_ptr;
        for _ in 0..len {
            let Some((key, advance)) = (unsafe { read_cstr(cursor) }) else {
                rt.error = 1;
                return vb::tag_null();
            };
            keys.push(key);
            unsafe {
                cursor = cursor.add(advance);
            }
        }
        let value_bits: Vec<u64> = values.iter().map(|v| v.to_bits()).collect();
        rt.make_map_temp(&keys, &value_bits)
    }

    extern "C" fn jit_index_list_num(list_bits: u64, idx_bits: u64, rt: *mut JitRuntime) -> f64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return 0.0;
        };
        let ptr = vb::payload(list_bits) as *const JitList;
        if ptr.is_null() {
            rt.error = 1;
            return 0.0;
        }
        let list = unsafe { &*ptr };
        let idx_f = f64::from_bits(idx_bits);
        if idx_f.fract() != 0.0 || idx_f < 0.0 {
            rt.error = 1;
            return 0.0;
        }
        let idx = idx_f as usize;
        let slice = unsafe { std::slice::from_raw_parts(list.data, list.len) };
        match slice.get(idx) {
            Some(v) => f64::from_bits(*v),
            None => {
                rt.error = 1;
                0.0
            }
        }
    }

    extern "C" fn jit_setindex_list_num(
        list_bits: u64,
        idx_bits: u64,
        val_bits: u64,
        rt: *mut JitRuntime,
    ) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        let ptr = vb::payload(list_bits) as *mut JitList;
        if ptr.is_null() {
            rt.error = 1;
            return vb::tag_null();
        }
        let list = unsafe { &mut *ptr };
        let idx_f = f64::from_bits(idx_bits);
        if idx_f.fract() != 0.0 || idx_f < 0.0 {
            rt.error = 1;
            return list_bits;
        }
        let idx = idx_f as usize;
        if idx >= list.len {
            rt.error = 1;
            return list_bits;
        }
        let slice = unsafe { std::slice::from_raw_parts_mut(list.data, list.len) };
        slice[idx] = val_bits;
        list.version = list.version.wrapping_add(1);
        list_bits
    }

    extern "C" fn jit_len_list(list_bits: u64, rt: *mut JitRuntime) -> f64 {
        let Some(rt_mut) = (unsafe { rt.as_mut() }) else {
            return 0.0;
        };
        let ptr = vb::payload(list_bits) as *const JitList;
        if ptr.is_null() {
            rt_mut.error = 1;
            return 0.0;
        }
        let list = unsafe { &*ptr };
        list.len as f64
    }

    extern "C" fn jit_index(list_bits: u64, idx_bits: u64, rt: *mut JitRuntime) -> f64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return 0.0;
        };
        match vb::tag_of(list_bits) {
            Some(tag) if tag == vb::TAG_LIST => {
                let list = unsafe { &*(vb::payload(list_bits) as *const JitList) };
                let idx_f = f64::from_bits(idx_bits);
                if idx_f.fract() != 0.0 || idx_f < 0.0 {
                    rt.error = 1;
                    return 0.0;
                }
                let idx = idx_f as usize;
                let slice = unsafe { std::slice::from_raw_parts(list.data, list.len) };
                match slice.get(idx) {
                    Some(v) => f64::from_bits(*v),
                    None => {
                        rt.error = 1;
                        0.0
                    }
                }
            }
            Some(tag) if tag == vb::TAG_MAP => {
                let key = if vb::is_text(idx_bits) {
                    idx_bits
                } else {
                    rt.error = 1;
                    return 0.0;
                };
                let bits = rt.map_get(list_bits, key);
                f64::from_bits(bits)
            }
            _ => {
                rt.error = 1;
                0.0
            }
        }
    }

    extern "C" fn jit_setindex(
        list_bits: u64,
        idx_bits: u64,
        val_bits: u64,
        rt: *mut JitRuntime,
    ) -> u64 {
        let Some(rt) = (unsafe { rt.as_mut() }) else {
            return vb::tag_null();
        };
        match vb::tag_of(list_bits) {
            Some(tag) if tag == vb::TAG_LIST => {
                let list = unsafe { &mut *(vb::payload(list_bits) as *mut JitList) };
                let idx_f = f64::from_bits(idx_bits);
                if idx_f.fract() != 0.0 || idx_f < 0.0 {
                    rt.error = 1;
                    return list_bits;
                }
                let idx = idx_f as usize;
                if idx >= list.len {
                    rt.error = 1;
                    return list_bits;
                }
                let slice = unsafe { std::slice::from_raw_parts_mut(list.data, list.len) };
                slice[idx] = val_bits;
                list.version = list.version.wrapping_add(1);
                list_bits
            }
            Some(tag) if tag == vb::TAG_MAP => {
                if !vb::is_text(idx_bits) {
                    rt.error = 1;
                    return list_bits;
                }
                rt.map_set(list_bits, idx_bits, val_bits)
            }
            _ => {
                rt.error = 1;
                vb::tag_null()
            }
        }
    }

    extern "C" fn jit_len(list_bits: u64, rt: *mut JitRuntime) -> f64 {
        let Some(rt_mut) = (unsafe { rt.as_mut() }) else {
            return 0.0;
        };
        if let Some(tag) = vb::tag_of(list_bits) {
            match tag {
                t if t == vb::TAG_LIST => {
                    let list = unsafe { &*(vb::payload(list_bits) as *const JitList) };
                    return list.len as f64;
                }
                t if t == vb::TAG_TEXT => {
                    let text = unsafe { &*(vb::payload(list_bits) as *const JitText) };
                    return text.data.chars().count() as f64;
                }
                t if t == vb::TAG_TEXT_SMALL || t == vb::TAG_TEXT_SMALL6 => {
                    if let Some(len) = vb::small_text_len(list_bits) {
                        return len as f64;
                    }
                    rt_mut.error = 1;
                    return 0.0;
                }
                t if t == vb::TAG_MAP => {
                    let map = unsafe { &*(vb::payload(list_bits) as *const JitMap) };
                    return map.len as f64;
                }
                t if t == vb::TAG_NULL => return 0.0,
                _ => {
                    rt_mut.error = 1;
                    return 0.0;
                }
            }
        }
        0.0
    }

    struct JitCode {
        ptr: *mut u8,
        len: usize,
    }

    impl Drop for JitCode {
        fn drop(&mut self) {
            unsafe {
                munmap(self.ptr as *mut c_void, self.len);
            }
        }
    }

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const PROT_EXEC: i32 = 0x4;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANON: i32 = 0x20;

    const LIST_VERSION_OFFSET: i32 = 0;
    const LIST_LEN_OFFSET: i32 = 8;
    const LIST_CAP_OFFSET: i32 = 16;
    const LIST_DATA_OFFSET: i32 = 24;
    const MAP_VERSION_OFFSET: i32 = 0;
    const MAP_CAP_OFFSET: i32 = std::mem::offset_of!(JitMap, cap) as i32;
    const MAP_SLOTS_PTR_OFFSET: i32 = std::mem::offset_of!(JitMap, slots_ptr) as i32;
    const MAP_SLOT_HASH_OFFSET: i32 = std::mem::offset_of!(MapSlot, hash) as i32;
    const MAP_SLOT_KEY_BITS_OFFSET: i32 = std::mem::offset_of!(MapSlot, key_bits) as i32;
    const MAP_SLOT_KEY_PTR_OFFSET: i32 = std::mem::offset_of!(MapSlot, key_ptr) as i32;
    const MAP_SLOT_KEY_LEN_OFFSET: i32 = std::mem::offset_of!(MapSlot, key_len) as i32;
    const MAP_SLOT_VALUE_OFFSET: i32 = std::mem::offset_of!(MapSlot, value) as i32;
    const MAP_SLOT_USED_OFFSET: i32 = std::mem::offset_of!(MapSlot, used) as i32;
    const MAP_SLOT_SIZE: i32 = std::mem::size_of::<MapSlot>() as i32;
    const PROFILE_CALLS_OFFSET: i32 = std::mem::offset_of!(JitRuntime, profile_calls) as i32;
    const PROFILE_TRACE_ITERS_OFFSET: i32 =
        std::mem::offset_of!(JitRuntime, profile_trace_iters) as i32;
    const PROFILE_BRANCH_TAKEN_SITES_OFFSET: i32 =
        std::mem::offset_of!(JitRuntime, profile_branch_taken_sites) as i32;
    const PROFILE_BRANCH_NOT_TAKEN_SITES_OFFSET: i32 =
        std::mem::offset_of!(JitRuntime, profile_branch_not_taken_sites) as i32;
    const PROFILE_DEOPTS_OFFSET: i32 = std::mem::offset_of!(JitRuntime, profile_deopts) as i32;
    const PROFILE_TEMP_LIST_ELIDED_OFFSET: i32 =
        std::mem::offset_of!(JitRuntime, profile_temp_list_elided) as i32;
    const RUN_AVX_DOT_ELEMENTS_OFFSET: i32 =
        std::mem::offset_of!(JitRuntime, run_avx_dot_elements) as i32;
    const TEXT_META_PTR_OFFSET: i32 = std::mem::offset_of!(TextMeta, ptr) as i32;
    const TEXT_META_LEN_OFFSET: i32 = std::mem::offset_of!(TextMeta, len) as i32;
    const TEXT_META_HASH_OFFSET: i32 = std::mem::offset_of!(TextMeta, hash) as i32;
    const TEMP_SMALL_LIST_COUNT_OFFSET: i32 =
        std::mem::offset_of!(JitRuntime, temp_small_list_count) as i32;
    const TEMP_SMALL_LIST_DATA_OFFSET: i32 =
        std::mem::offset_of!(JitRuntime, temp_small_list_data) as i32;
    const TEMP_SMALL_LISTS_OFFSET: i32 = std::mem::offset_of!(JitRuntime, temp_small_lists) as i32;

    const TAG_LIST_BITS: u64 = vb::QNAN_MASK | ((vb::TAG_LIST & 0x7) << vb::TAG_SHIFT);

    extern "C" {
        fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: isize,
        ) -> *mut c_void;
        fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
    }

    #[derive(Clone, Debug)]
    struct BranchSiteRecord {
        rel32_at: usize,
        opcode: u8,
        kind: BranchKind,
        counter_idx: usize,
        target: Option<usize>,
        inverted: bool,
        patchable: bool,
        invert_taken_jmp_rel32: Option<usize>,
        invert_not_taken_jmp_rel32: Option<usize>,
        target_a: Option<usize>,
        target_b: Option<usize>,
    }

    #[derive(Clone, Copy)]
    struct InvertibleGuardSite {
        rel32_at: usize,
        taken_jmp_rel32: usize,
        not_taken_jmp_rel32: usize,
    }

    struct Asm {
        code: Vec<u8>,
        data: Vec<u8>,
        data_patches: Vec<(usize, usize)>, // (code_offset, data_offset)
        profile: bool,
        uses_avx: bool,
        avx_upper_dirty: bool,
        prefer_vex_scalar: bool,
        call_count: u64,
        jcc_count: u64,
        branch_sites: Vec<BranchSiteRecord>,
        branch_site_by_rel32: HashMap<usize, usize>,
    }

    impl Asm {
        fn new(profile: bool) -> Self {
            Self {
                code: Vec::new(),
                data: Vec::new(),
                data_patches: Vec::new(),
                profile,
                uses_avx: false,
                avx_upper_dirty: false,
                prefer_vex_scalar: false,
                call_count: 0,
                jcc_count: 0,
                branch_sites: Vec::new(),
                branch_site_by_rel32: HashMap::new(),
            }
        }

        fn pos(&self) -> usize {
            self.code.len()
        }

        fn emit(&mut self, bytes: &[u8]) {
            if bytes == [0xFF, 0xD0] {
                self.call_count = self.call_count.saturating_add(1);
                if self.profile {
                    self.emit_inc_qword_at_r15(PROFILE_CALLS_OFFSET);
                }
            }
            self.code.extend_from_slice(bytes);
        }

        fn emit_u8(&mut self, v: u8) {
            self.code.push(v);
        }

        fn emit_u32(&mut self, v: u32) {
            self.code.extend_from_slice(&v.to_le_bytes());
        }

        fn emit_u64(&mut self, v: u64) {
            self.code.extend_from_slice(&v.to_le_bytes());
        }

        fn emit_avx(&mut self, bytes: &[u8]) {
            self.uses_avx = true;
            self.avx_upper_dirty = true;
            self.emit(bytes);
        }

        fn emit_vzeroupper(&mut self) {
            self.emit(&[0xC5, 0xF8, 0x77]);
            self.avx_upper_dirty = false;
        }

        fn emit_call_rax(&mut self) {
            if self.avx_upper_dirty {
                self.emit_vzeroupper();
            }
            self.emit(&[0xFF, 0xD0]); // call rax
        }

        fn emit_cstr(&mut self, s: &str) -> usize {
            let offset = self.data.len();
            self.data.extend_from_slice(s.as_bytes());
            self.data.push(0);
            offset
        }

        fn emit_bytes(&mut self, bytes: &[u8]) -> usize {
            let offset = self.data.len();
            self.data.extend_from_slice(bytes);
            offset
        }

        fn emit_mov_imm64_placeholder(&mut self, opcode: &[u8]) -> usize {
            self.emit(opcode);
            let at = self.pos();
            self.emit_u64(0);
            at
        }

        fn patch_rel32_raw(&mut self, at: usize, target: usize) {
            let rel = target as isize - (at as isize + 4);
            let bytes = (rel as i32).to_le_bytes();
            self.code[at..at + 4].copy_from_slice(&bytes);
        }

        fn patch_rel32(&mut self, at: usize, target: usize) {
            if self.profile {
                if let Some(idx) = self.branch_site_by_rel32.get(&at).copied() {
                    self.branch_sites[idx].target = Some(target);
                    return;
                }
            }
            self.patch_rel32_raw(at, target);
        }

        fn emit_jmp_placeholder(&mut self) -> usize {
            self.emit_u8(0xE9);
            let at = self.pos();
            self.emit_u32(0);
            at
        }

        fn emit_jcc_placeholder(&mut self, opcode: u8) -> usize {
            self.jcc_count = self.jcc_count.saturating_add(1);
            self.emit_u8(0x0F);
            self.emit_u8(opcode);
            let at = self.pos();
            self.emit_u32(0);
            if self.profile && self.branch_sites.len() < MAX_PROFILE_BRANCH_SITES {
                let site_idx = self.branch_sites.len();
                self.branch_site_by_rel32.insert(at, site_idx);
                self.branch_sites.push(BranchSiteRecord {
                    rel32_at: at,
                    opcode,
                    kind: BranchKind::Generic,
                    counter_idx: site_idx,
                    target: None,
                    inverted: false,
                    patchable: false,
                    invert_taken_jmp_rel32: None,
                    invert_not_taken_jmp_rel32: None,
                    target_a: None,
                    target_b: None,
                });
                self.emit_inc_site_not_taken(site_idx);
            }
            at
        }

        fn emit_invertible_guard_after_cmp(&mut self, opcode: u8) -> Option<InvertibleGuardSite> {
            if !self.profile {
                return None;
            }
            let rel32_at = self.emit_jcc_placeholder(opcode);
            let jmp_not_stub = self.emit_jmp_placeholder();
            let taken_stub = self.pos();
            let taken_jmp_rel32 = self.emit_jmp_placeholder();
            let not_taken_stub = self.pos();
            let not_taken_jmp_rel32 = self.emit_jmp_placeholder();
            self.patch_rel32(rel32_at, taken_stub);
            self.patch_rel32_raw(jmp_not_stub, not_taken_stub);
            if let Some(idx) = self.branch_site_by_rel32.get(&rel32_at).copied() {
                let site = &mut self.branch_sites[idx];
                site.patchable = true;
                site.invert_taken_jmp_rel32 = Some(taken_jmp_rel32);
                site.invert_not_taken_jmp_rel32 = Some(not_taken_jmp_rel32);
            }
            Some(InvertibleGuardSite {
                rel32_at,
                taken_jmp_rel32,
                not_taken_jmp_rel32,
            })
        }

        fn set_invertible_guard_targets(
            &mut self,
            rel32_at: usize,
            target_a: usize,
            target_b: usize,
        ) {
            let Some(idx) = self.branch_site_by_rel32.get(&rel32_at).copied() else {
                return;
            };
            let Some(taken_jmp_rel32) = self.branch_sites[idx].invert_taken_jmp_rel32 else {
                return;
            };
            let Some(not_taken_jmp_rel32) = self.branch_sites[idx].invert_not_taken_jmp_rel32
            else {
                return;
            };
            self.patch_rel32_raw(taken_jmp_rel32, target_a);
            self.patch_rel32_raw(not_taken_jmp_rel32, target_b);
            let site = &mut self.branch_sites[idx];
            site.target_a = Some(target_a);
            site.target_b = Some(target_b);
        }

        fn emit_inc_qword_at_r15(&mut self, disp: i32) {
            if (-128..=127).contains(&disp) {
                self.code.extend_from_slice(&[0x49, 0xFF, 0x47, disp as u8]);
            } else {
                self.code.extend_from_slice(&[0x49, 0xFF, 0x87]);
                self.code.extend_from_slice(&disp.to_le_bytes());
            }
        }

        fn emit_add_qword_at_r15_from_reg(&mut self, disp: i32, reg: u8) {
            debug_assert!(reg < 16);
            let rex = 0x49 | if reg >= 8 { 0x04 } else { 0x00 }; // REX.W + B(r15) + optional R
            let reg_bits = (reg & 0x07) << 3;
            self.code.push(rex);
            self.code.push(0x01); // add r/m64, r64
            if (-128..=127).contains(&disp) {
                self.code.push(0x47 | reg_bits); // mod=01, rm=r15
                self.code.push(disp as u8);
            } else {
                self.code.push(0x87 | reg_bits); // mod=10, rm=r15
                self.code.extend_from_slice(&disp.to_le_bytes());
            }
        }

        fn emit_inc_qword_at_r15_preserve_flags(&mut self, disp: i32) {
            // Preserve both condition flags and the scratch register without the
            // serializing pushfq/popfq pair. MOV, LEA, PUSH and POP leave RFLAGS
            // untouched, so chained JCCs can safely consume the original CMP flags.
            self.emit(&[0x41, 0x53]); // push r11
            if (-128..=127).contains(&disp) {
                self.emit(&[0x4D, 0x8B, 0x5F, disp as u8]); // mov r11, [r15 + disp8]
            } else {
                self.emit(&[0x4D, 0x8B, 0x9F]); // mov r11, [r15 + disp32]
                self.emit(&disp.to_le_bytes());
            }
            self.emit(&[0x4D, 0x8D, 0x5B, 0x01]); // lea r11, [r11 + 1]
            if (-128..=127).contains(&disp) {
                self.emit(&[0x4D, 0x89, 0x5F, disp as u8]); // mov [r15 + disp8], r11
            } else {
                self.emit(&[0x4D, 0x89, 0x9F]); // mov [r15 + disp32], r11
                self.emit(&disp.to_le_bytes());
            }
            self.emit(&[0x41, 0x5B]); // pop r11
        }

        fn emit_inc_site_taken(&mut self, site_idx: usize) {
            let disp = PROFILE_BRANCH_TAKEN_SITES_OFFSET + (site_idx as i32) * 8;
            self.emit_inc_qword_at_r15_preserve_flags(disp);
        }

        fn emit_inc_site_not_taken(&mut self, site_idx: usize) {
            let disp = PROFILE_BRANCH_NOT_TAKEN_SITES_OFFSET + (site_idx as i32) * 8;
            self.emit_inc_qword_at_r15_preserve_flags(disp);
        }

        fn mark_branch_kind(&mut self, rel32_at: usize, kind: BranchKind) {
            if let Some(idx) = self.branch_site_by_rel32.get(&rel32_at).copied() {
                self.branch_sites[idx].kind = kind;
            }
        }

        fn finalize_profiled_branches(&mut self) {
            if !self.profile || self.branch_sites.is_empty() {
                return;
            }
            let sites: Vec<(usize, usize, usize)> = self
                .branch_sites
                .iter()
                .filter_map(|s| s.target.map(|t| (s.rel32_at, t, s.counter_idx)))
                .collect();
            let mut trampolines: Vec<(usize, usize)> = Vec::with_capacity(sites.len());
            for (rel32_at, target, counter_idx) in sites.iter() {
                let tramp = self.pos();
                self.emit_inc_site_taken(*counter_idx);
                let jmp_at = self.emit_jmp_placeholder();
                trampolines.push((jmp_at, *target));
                self.patch_rel32_raw(*rel32_at, tramp);
            }
            for (jmp_at, target) in trampolines {
                self.patch_rel32_raw(jmp_at, target);
            }
        }

        fn patch_sites_meta(&self) -> Vec<PatchSite> {
            self.branch_sites
                .iter()
                .map(|site| PatchSite {
                    offset: site.rel32_at as u32,
                    kind: site.kind,
                    counter_idx: site.counter_idx as u32,
                    inverted: site.inverted,
                    jump_size: 6,
                    patchable: site.patchable,
                    invert_taken_jmp_rel32: site
                        .invert_taken_jmp_rel32
                        .map(|v| v as u32)
                        .unwrap_or(u32::MAX),
                    invert_not_taken_jmp_rel32: site
                        .invert_not_taken_jmp_rel32
                        .map(|v| v as u32)
                        .unwrap_or(u32::MAX),
                    target_a: site.target_a.map(|v| v as u32).unwrap_or(u32::MAX),
                    target_b: site.target_b.map(|v| v as u32).unwrap_or(u32::MAX),
                })
                .collect()
        }
    }

    struct PromotedLocals {
        regs: Vec<(usize, u8)>,
    }

    impl PromotedLocals {
        fn new(locals: &[usize]) -> Self {
            let mut regs = Vec::new();
            let pool = [2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8];
            let mut pool_idx = 0usize;
            for idx in locals {
                if regs.iter().any(|(existing, _)| existing == idx) {
                    continue;
                }
                if pool_idx < pool.len() {
                    let reg = pool[pool_idx];
                    regs.push((*idx, reg));
                    pool_idx += 1;
                } else {
                    break;
                }
            }
            Self { regs }
        }

        fn empty() -> Self {
            Self { regs: Vec::new() }
        }

        fn xmm_for(&self, idx: usize) -> Option<u8> {
            self.regs
                .iter()
                .find_map(|(local, reg)| if *local == idx { Some(*reg) } else { None })
        }

        fn is_empty(&self) -> bool {
            self.regs.is_empty()
        }
    }

    #[derive(Clone, Copy)]
    enum CmpKind {
        Eq,
        Ne,
        Lt,
        Le,
        Gt,
        Ge,
    }

    pub fn is_supported(code: &[Instr]) -> bool {
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
            | Instr::Pop
            | Instr::Return => true,
            Instr::CallBuiltin(name, argc) => {
                (name == "__index" && *argc == 2)
                    || (name == "__setindex" && *argc == 3)
                    || (name == "len" && *argc == 1)
                    || (name == "to_text" && *argc == 1)
                    || (name == "__syscall" && supports_native_syscall(*argc))
            }
            Instr::CallFn(_, _) => true,
            _ => false,
        })
    }

    pub fn max_stack_depth(code: &[Instr]) -> usize {
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
                Instr::CallBuiltin(name, argc) if name == "__index" && *argc == 2 => -1,
                Instr::CallBuiltin(name, argc) if name == "__setindex" && *argc == 3 => -2,
                Instr::CallBuiltin(name, argc) if name == "len" && *argc == 1 => 0,
                Instr::CallBuiltin(name, argc) if name == "to_text" && *argc == 1 => 0,
                Instr::CallBuiltin(name, argc) if name == "__syscall" => 1 - (*argc as i32),
                Instr::CallFn(_, argc) => 1 - (*argc as i32),
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

    pub fn compile(code: &[Instr], _locals: usize) -> Result<JitExecutable, String> {
        if !is_supported(code) {
            return Err("unsupported bytecode for JIT".into());
        }

        let mut asm = Asm::new(false);
        emit_prologue(&mut asm);
        let promoted = PromotedLocals::empty();

        let mut bc_offsets = vec![0usize; code.len() + 1];
        let mut patches: Vec<(usize, usize)> = Vec::new();
        let mut exit_patches: Vec<usize> = Vec::new();
        let mut deopt_patches: Vec<usize> = Vec::new();

        for (i, instr) in code.iter().enumerate() {
            bc_offsets[i] = asm.pos();
            match instr {
                Instr::ConstNum(n) => emit_push_f64(&mut asm, *n),
                Instr::ConstText(s) => emit_make_text(&mut asm, s),
                Instr::ConstBool(b) => {
                    let v = if *b { 1.0 } else { 0.0 };
                    emit_push_f64(&mut asm, v);
                }
                Instr::PushNull => emit_push_bits(&mut asm, vb::tag_null()),
                Instr::LoadLocal(idx) => emit_load_local(&mut asm, *idx, &promoted),
                Instr::StoreLocal(idx) => emit_store_local(&mut asm, *idx, &promoted),
                Instr::StoreLocalKeep(idx) => {
                    emit_dup_top(&mut asm);
                    emit_store_local(&mut asm, *idx, &promoted);
                }
                Instr::AddLocalConst(idx, c) => emit_add_local_const(&mut asm, *idx, *c, &promoted),
                Instr::Add => emit_bin_op(&mut asm, BinOp::Add),
                Instr::Sub => emit_bin_op(&mut asm, BinOp::Sub),
                Instr::Mul => emit_bin_op(&mut asm, BinOp::Mul),
                Instr::Div => emit_bin_op(&mut asm, BinOp::Div),
                Instr::Eq => emit_cmp(&mut asm, CmpKind::Eq),
                Instr::Ne => emit_cmp(&mut asm, CmpKind::Ne),
                Instr::Lt => emit_cmp(&mut asm, CmpKind::Lt),
                Instr::Le => emit_cmp(&mut asm, CmpKind::Le),
                Instr::Gt => emit_cmp(&mut asm, CmpKind::Gt),
                Instr::Ge => emit_cmp(&mut asm, CmpKind::Ge),
                Instr::Jump(target) => {
                    let at = asm.emit_jmp_placeholder();
                    patches.push((at, *target));
                }
                Instr::JumpIfFalse(target) => {
                    let at = emit_jump_if_false(&mut asm);
                    patches.push((at, *target));
                }
                Instr::JumpLocalIfFalse(idx, target) => {
                    emit_load_local(&mut asm, *idx, &promoted);
                    let at = emit_jump_if_false(&mut asm);
                    patches.push((at, *target));
                }
                Instr::MakeList(len) => emit_make_list(&mut asm, *len),
                Instr::MakeMap(keys) => emit_make_map(&mut asm, keys),
                Instr::CallBuiltin(name, argc) if name == "__index" && *argc == 2 => {
                    emit_call_index(&mut asm)
                }
                Instr::CallBuiltin(name, argc) if name == "__setindex" && *argc == 3 => {
                    emit_call_setindex(&mut asm)
                }
                Instr::CallBuiltin(name, argc) if name == "len" && *argc == 1 => {
                    emit_call_len(&mut asm)
                }
                Instr::CallBuiltin(name, argc) if name == "to_text" && *argc == 1 => {
                    emit_call_to_text(&mut asm)
                }
                Instr::CallBuiltin(name, argc)
                    if name == "__syscall" && supports_native_syscall(*argc) =>
                {
                    emit_call_syscall(&mut asm, *argc)
                }
                Instr::LoadField(field) => emit_load_field(&mut asm, field),
                Instr::CallFn(name, argc) => {
                    let at = emit_call_user(&mut asm, name, *argc, i);
                    deopt_patches.push(at);
                }
                Instr::Pop => {
                    emit_dec_sp(&mut asm);
                }
                Instr::Return => {
                    let at = asm.emit_jmp_placeholder();
                    exit_patches.push(at);
                }
                _ => return Err("unsupported bytecode for JIT".into()),
            }
        }

        bc_offsets[code.len()] = asm.pos();
        let at = asm.emit_jmp_placeholder();
        exit_patches.push(at);

        let deopt_stub_offset = asm.pos();
        emit_set_exit_flag(&mut asm, 2);
        emit_store_deopt_sp(&mut asm);
        let deopt_jmp = asm.emit_jmp_placeholder();

        let exit_offset = asm.pos();
        emit_exit(&mut asm, &mut exit_patches, exit_offset);
        asm.patch_rel32(deopt_jmp, exit_offset);

        for (at, target) in patches {
            let dest = bc_offsets.get(target).copied().unwrap_or(exit_offset);
            asm.patch_rel32(at, dest);
        }
        for at in deopt_patches {
            asm.patch_rel32(at, deopt_stub_offset);
        }

        let hot_code_len = asm.code.len();
        let mem = unsafe {
            let code_len = hot_code_len;
            let data_len = asm.data.len();
            let total_len = code_len + data_len;
            let ptr = mmap(
                std::ptr::null_mut(),
                total_len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            );
            if ptr.is_null() {
                return Err("mmap failed".into());
            }
            let base = ptr as *mut u8;
            std::ptr::copy_nonoverlapping(asm.code.as_ptr(), base, code_len);
            if data_len > 0 {
                std::ptr::copy_nonoverlapping(asm.data.as_ptr(), base.add(code_len), data_len);
            }
            for (at, data_off) in asm.data_patches.iter() {
                let addr = base.add(code_len + *data_off) as u64;
                std::ptr::copy_nonoverlapping(&addr as *const u64 as *const u8, base.add(*at), 8);
            }
            if mprotect(ptr, total_len, PROT_READ | PROT_EXEC) != 0 {
                munmap(ptr, total_len);
                return Err("mprotect failed".into());
            }
            JitCode {
                ptr: ptr as *mut u8,
                len: total_len,
            }
        };

        let entry = unsafe { std::mem::transmute::<*mut u8, JitFn>(mem.ptr) };
        Ok(JitExecutable {
            code: mem,
            entry,
            hot_code_len,
            temp_list_elems: 0,
            temp_list_count: 0,
            temp_map_count: 0,
            static_calls: 0,
            static_branches: 0,
            profile_enabled: false,
            patch_sites: Vec::new(),
        })
    }

    pub fn compile_trace(
        code: &[Instr],
        start: usize,
        end: usize,
        exit_target: usize,
    ) -> Result<JitExecutable, String> {
        if start > end || end >= code.len() {
            return Err("invalid trace range".into());
        }

        let mut asm = Asm::new(false);
        emit_prologue(&mut asm);
        let promoted = PromotedLocals::empty();

        let slice_len = end - start + 1;
        let mut bc_offsets = vec![0usize; slice_len + 1];
        let mut patches: Vec<(usize, usize)> = Vec::new();
        let mut exit_patches: Vec<usize> = Vec::new();
        let mut exit_jump_patches: Vec<usize> = Vec::new();
        let mut deopt_patches: Vec<usize> = Vec::new();

        for (i, instr) in code[start..=end].iter().enumerate() {
            bc_offsets[i] = asm.pos();
            match instr {
                Instr::ConstNum(n) => emit_push_f64(&mut asm, *n),
                Instr::ConstText(s) => emit_make_text(&mut asm, s),
                Instr::ConstBool(b) => {
                    let v = if *b { 1.0 } else { 0.0 };
                    emit_push_f64(&mut asm, v);
                }
                Instr::PushNull => emit_push_bits(&mut asm, vb::tag_null()),
                Instr::LoadLocal(idx) => emit_load_local(&mut asm, *idx, &promoted),
                Instr::StoreLocal(idx) => emit_store_local(&mut asm, *idx, &promoted),
                Instr::StoreLocalKeep(idx) => {
                    emit_dup_top(&mut asm);
                    emit_store_local(&mut asm, *idx, &promoted);
                }
                Instr::AddLocalConst(idx, c) => emit_add_local_const(&mut asm, *idx, *c, &promoted),
                Instr::Add => emit_bin_op(&mut asm, BinOp::Add),
                Instr::Sub => emit_bin_op(&mut asm, BinOp::Sub),
                Instr::Mul => emit_bin_op(&mut asm, BinOp::Mul),
                Instr::Div => emit_bin_op(&mut asm, BinOp::Div),
                Instr::Eq => emit_cmp(&mut asm, CmpKind::Eq),
                Instr::Ne => emit_cmp(&mut asm, CmpKind::Ne),
                Instr::Lt => emit_cmp(&mut asm, CmpKind::Lt),
                Instr::Le => emit_cmp(&mut asm, CmpKind::Le),
                Instr::Gt => emit_cmp(&mut asm, CmpKind::Gt),
                Instr::Ge => emit_cmp(&mut asm, CmpKind::Ge),
                Instr::Jump(target) => {
                    let at = asm.emit_jmp_placeholder();
                    if *target >= start && *target <= end {
                        if *target == start {
                            patches.push((at, *target - start));
                        } else {
                            return Err("non-linear trace jump".into());
                        }
                    } else if *target == exit_target {
                        exit_jump_patches.push(at);
                    } else {
                        return Err("trace jump target outside range".into());
                    }
                }
                Instr::JumpIfFalse(target) => {
                    let at = emit_jump_if_false(&mut asm);
                    if *target >= start && *target <= end {
                        return Err("non-linear trace branch".into());
                    } else if *target == exit_target {
                        exit_jump_patches.push(at);
                    } else {
                        return Err("trace jump target outside range".into());
                    }
                }
                Instr::JumpLocalIfFalse(idx, target) => {
                    emit_load_local(&mut asm, *idx, &promoted);
                    let at = emit_jump_if_false(&mut asm);
                    if *target >= start && *target <= end {
                        return Err("non-linear trace branch".into());
                    } else if *target == exit_target {
                        exit_jump_patches.push(at);
                    } else {
                        return Err("trace jump target outside range".into());
                    }
                }
                Instr::MakeList(len) => emit_make_list(&mut asm, *len),
                Instr::MakeMap(keys) => emit_make_map(&mut asm, keys),
                Instr::CallBuiltin(name, argc) if name == "__index" && *argc == 2 => {
                    emit_call_index(&mut asm)
                }
                Instr::CallBuiltin(name, argc) if name == "__setindex" && *argc == 3 => {
                    emit_call_setindex(&mut asm)
                }
                Instr::CallBuiltin(name, argc) if name == "len" && *argc == 1 => {
                    emit_call_len(&mut asm)
                }
                Instr::CallBuiltin(name, argc) if name == "to_text" && *argc == 1 => {
                    emit_call_to_text(&mut asm)
                }
                Instr::CallBuiltin(name, argc)
                    if name == "__syscall" && supports_native_syscall(*argc) =>
                {
                    emit_call_syscall(&mut asm, *argc)
                }
                Instr::LoadField(field) => emit_load_field(&mut asm, field),
                Instr::CallFn(name, argc) => {
                    let ip = start + i;
                    let at = emit_call_user(&mut asm, name, *argc, ip);
                    deopt_patches.push(at);
                }
                Instr::Pop => {
                    emit_dec_sp(&mut asm);
                }
                Instr::Return => {
                    let at = asm.emit_jmp_placeholder();
                    exit_patches.push(at);
                }
                _ => return Err("unsupported instruction in trace".into()),
            }
        }

        bc_offsets[slice_len] = asm.pos();

        let hot_code_len = asm.pos();
        let exit_stub_offset = asm.pos();
        emit_set_exit_flag(&mut asm, 1);
        asm.emit(&[0x48, 0x31, 0xDB]); // xor rbx, rbx
        let stub_jmp = asm.emit_jmp_placeholder();

        let deopt_stub_offset = asm.pos();
        emit_set_exit_flag(&mut asm, 2);
        emit_store_deopt_sp(&mut asm);
        let deopt_jmp = asm.emit_jmp_placeholder();

        let exit_offset = asm.pos();
        emit_exit(&mut asm, &mut exit_patches, exit_offset);
        asm.patch_rel32(stub_jmp, exit_offset);
        asm.patch_rel32(deopt_jmp, exit_offset);

        for (at, target_idx) in patches {
            let dest = bc_offsets.get(target_idx).copied().unwrap_or(exit_offset);
            asm.patch_rel32(at, dest);
        }
        for at in exit_jump_patches {
            asm.patch_rel32(at, exit_stub_offset);
        }
        for at in deopt_patches {
            asm.patch_rel32(at, deopt_stub_offset);
        }

        let mem = unsafe {
            let code_len = asm.code.len();
            let data_len = asm.data.len();
            let total_len = code_len + data_len;
            let ptr = mmap(
                std::ptr::null_mut(),
                total_len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            );
            if ptr.is_null() {
                return Err("mmap failed".into());
            }
            let base = ptr as *mut u8;
            std::ptr::copy_nonoverlapping(asm.code.as_ptr(), base, code_len);
            if data_len > 0 {
                std::ptr::copy_nonoverlapping(asm.data.as_ptr(), base.add(code_len), data_len);
            }
            for (at, data_off) in asm.data_patches.iter() {
                let addr = base.add(code_len + *data_off) as u64;
                std::ptr::copy_nonoverlapping(&addr as *const u64 as *const u8, base.add(*at), 8);
            }
            if mprotect(ptr, total_len, PROT_READ | PROT_EXEC) != 0 {
                munmap(ptr, total_len);
                return Err("mprotect failed".into());
            }
            JitCode {
                ptr: ptr as *mut u8,
                len: total_len,
            }
        };

        let entry = unsafe { std::mem::transmute::<*mut u8, JitFn>(mem.ptr) };
        Ok(JitExecutable {
            code: mem,
            entry,
            hot_code_len,
            temp_list_elems: 0,
            temp_list_count: 0,
            temp_map_count: 0,
            static_calls: 0,
            static_branches: 0,
            profile_enabled: false,
            patch_sites: Vec::new(),
        })
    }

    #[derive(Clone, Copy)]
    struct ListUpdateLanePattern {
        list_idx: usize,
        idx_idx: usize,
        data_ptr: u64,
        offset: i32,
        acc_local: usize,
    }

    #[derive(Clone, Copy)]
    struct DotSquareLanePattern {
        list_idx: usize,
        idx_idx: usize,
        data_ptr: u64,
        offset: i32,
        acc_local: usize,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DotSquareQuadAccum {
        Single {
            acc_local: usize,
        },
        Split {
            even_acc_local: usize,
            odd_acc_local: usize,
        },
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct DotSquareQuadPattern {
        list_idx: usize,
        idx_idx: usize,
        data_ptr: u64,
        base_offset: i32,
        accum: DotSquareQuadAccum,
    }

    struct DotSquareAvxLoopPattern {
        list_idx: usize,
        idx_idx: usize,
        limit: f64,
        inclusive: bool,
        step: i32,
        accum: DotSquareQuadAccum,
        quads: Vec<DotSquareQuadPattern>,
        repeat: usize,
    }

    fn match_list_update_lane_pattern(ops: &[TraceOp], at: usize) -> Option<ListUpdateLanePattern> {
        if at + 6 >= ops.len() {
            return None;
        }
        let (
            TraceOp::IndexListNumLocalPtrOff(list_idx, idx_idx, data_ptr, offset),
            TraceOp::Dup,
            TraceOp::AddLocalFromStack(acc_local),
            TraceOp::ConstNum(one),
            TraceOp::AddNum,
            set_op,
            TraceOp::Pop,
        ) = (
            &ops[at],
            &ops[at + 1],
            &ops[at + 2],
            &ops[at + 3],
            &ops[at + 4],
            &ops[at + 5],
            &ops[at + 6],
        )
        else {
            return None;
        };
        if one.to_bits() != 1.0f64.to_bits() {
            return None;
        }
        let set_matches = match set_op {
            TraceOp::SetIndexListNumLocalPtrNoVerOffFast(
                list_idx2,
                idx_idx2,
                data_ptr2,
                offset2,
            )
            | TraceOp::SetIndexListNumLocalPtrNoVerOff(list_idx2, idx_idx2, data_ptr2, offset2) => {
                *list_idx2 == *list_idx
                    && *idx_idx2 == *idx_idx
                    && *data_ptr2 == *data_ptr
                    && *offset2 == *offset
            }
            _ => false,
        };
        if !set_matches {
            return None;
        }
        Some(ListUpdateLanePattern {
            list_idx: *list_idx,
            idx_idx: *idx_idx,
            data_ptr: *data_ptr,
            offset: *offset,
            acc_local: *acc_local,
        })
    }

    fn match_dot_square_lane_pattern(ops: &[TraceOp], at: usize) -> Option<DotSquareLanePattern> {
        if at + 3 >= ops.len() {
            return None;
        }

        let (list_idx, idx_idx, data_ptr, offset) = match &ops[at] {
            TraceOp::IndexListNumLocalPtr(list_idx, idx_idx, data_ptr) => {
                (*list_idx, *idx_idx, *data_ptr, 0)
            }
            TraceOp::IndexListNumLocalPtrOff(_list_idx, idx_idx, data_ptr, offset) => {
                (*_list_idx, *idx_idx, *data_ptr, *offset)
            }
            _ => return None,
        };
        let (TraceOp::Dup, TraceOp::MulNum, TraceOp::AddLocalFromStack(acc_local)) =
            (&ops[at + 1], &ops[at + 2], &ops[at + 3])
        else {
            return None;
        };

        Some(DotSquareLanePattern {
            list_idx,
            idx_idx,
            data_ptr,
            offset,
            acc_local: *acc_local,
        })
    }

    fn match_dot_square_quad_pattern(ops: &[TraceOp], at: usize) -> Option<DotSquareQuadPattern> {
        let l0 = match_dot_square_lane_pattern(ops, at)?;
        let l1 = match_dot_square_lane_pattern(ops, at + 4)?;
        let l2 = match_dot_square_lane_pattern(ops, at + 8)?;
        let l3 = match_dot_square_lane_pattern(ops, at + 12)?;

        if l1.list_idx != l0.list_idx
            || l2.list_idx != l0.list_idx
            || l3.list_idx != l0.list_idx
            || l1.idx_idx != l0.idx_idx
            || l2.idx_idx != l0.idx_idx
            || l3.idx_idx != l0.idx_idx
            || l1.data_ptr != l0.data_ptr
            || l2.data_ptr != l0.data_ptr
            || l3.data_ptr != l0.data_ptr
        {
            return None;
        }

        let off1 = l0.offset.checked_add(1)?;
        let off2 = l0.offset.checked_add(2)?;
        let off3 = l0.offset.checked_add(3)?;
        if l1.offset != off1 || l2.offset != off2 || l3.offset != off3 {
            return None;
        }

        let accum = if l0.acc_local == l1.acc_local
            && l0.acc_local == l2.acc_local
            && l0.acc_local == l3.acc_local
        {
            DotSquareQuadAccum::Single {
                acc_local: l0.acc_local,
            }
        } else if l0.acc_local == l2.acc_local && l1.acc_local == l3.acc_local {
            DotSquareQuadAccum::Split {
                even_acc_local: l0.acc_local,
                odd_acc_local: l1.acc_local,
            }
        } else {
            return None;
        };

        Some(DotSquareQuadPattern {
            list_idx: l0.list_idx,
            idx_idx: l0.idx_idx,
            data_ptr: l0.data_ptr,
            base_offset: l0.offset,
            accum,
        })
    }

    fn match_dot_square_avx_loop_pattern(
        ops: &[TraceOp],
        at: usize,
    ) -> Option<(DotSquareAvxLoopPattern, usize)> {
        let (idx_idx, limit, inclusive) = match ops.get(at)? {
            TraceOp::GuardIndexRangeConst(idx_idx, limit, inclusive) => {
                (*idx_idx, *limit, *inclusive)
            }
            _ => return None,
        };

        let mut cursor = at;
        let mut repeat = 0usize;
        let mut list_idx: Option<usize> = None;
        let mut accum: Option<DotSquareQuadAccum> = None;
        let mut quads: Option<Vec<DotSquareQuadPattern>> = None;
        let mut step_i32: Option<i32> = None;
        loop {
            let (seg_idx, seg_limit, seg_inclusive) = match ops.get(cursor)? {
                TraceOp::GuardIndexRangeConst(seg_idx, seg_limit, seg_inclusive) => {
                    (*seg_idx, *seg_limit, *seg_inclusive)
                }
                _ => return None,
            };
            if seg_idx != idx_idx
                || seg_inclusive != inclusive
                || seg_limit.to_bits() != limit.to_bits()
            {
                return None;
            }

            let mut lane_idx = cursor + 1;
            let mut seg_quads: Vec<DotSquareQuadPattern> = Vec::new();
            let mut seg_list_idx: Option<usize> = None;
            let mut seg_accum: Option<DotSquareQuadAccum> = None;
            while let Some(quad) = match_dot_square_quad_pattern(ops, lane_idx) {
                if quad.idx_idx != idx_idx {
                    break;
                }
                if let Some(list) = seg_list_idx {
                    if quad.list_idx != list {
                        break;
                    }
                } else {
                    seg_list_idx = Some(quad.list_idx);
                }
                if let Some(a) = seg_accum {
                    if quad.accum != a {
                        break;
                    }
                } else {
                    seg_accum = Some(quad.accum);
                }
                seg_quads.push(quad);
                lane_idx += 16;
            }
            if seg_quads.is_empty() {
                return None;
            }

            let (seg_step_idx, seg_step) = match ops.get(lane_idx)? {
                TraceOp::AddLocalConst(seg_step_idx, seg_step) => (*seg_step_idx, *seg_step),
                _ => return None,
            };
            if seg_step_idx != idx_idx
                || !seg_step.is_finite()
                || seg_step <= 0.0
                || seg_step.fract() != 0.0
            {
                return None;
            }
            let seg_step_i32 = seg_step as i32;
            if seg_step_i32 <= 0 {
                return None;
            }
            // Expect x4-unrolled lanes represented as one or more contiguous quads.
            if seg_step_i32 as usize != seg_quads.len() * 4 {
                return None;
            }

            if repeat == 0 {
                list_idx = seg_list_idx;
                accum = seg_accum;
                quads = Some(seg_quads);
                step_i32 = Some(seg_step_i32);
            } else if list_idx != seg_list_idx
                || accum != seg_accum
                || quads.as_ref() != Some(&seg_quads)
                || step_i32 != Some(seg_step_i32)
            {
                return None;
            }

            repeat += 1;
            cursor = lane_idx + 1;
            if matches!(ops.get(cursor), Some(TraceOp::JumpStart)) {
                break;
            }
        }

        Some((
            DotSquareAvxLoopPattern {
                list_idx: list_idx?,
                idx_idx,
                limit,
                inclusive,
                step: step_i32?,
                accum: accum?,
                quads: quads?,
                repeat,
            },
            cursor + 1,
        ))
    }

    pub fn compile_trace_typed(
        ops: &[TraceOp],
        temp_list_sources: &[TempListSource],
        tail_resume_ip: usize,
        profile_enabled: bool,
        promoted_locals: &[usize],
        merge_locals: &[(usize, usize)],
    ) -> Result<JitExecutable, String> {
        let mut temp_list_elems: usize = 0;
        let mut temp_list_count: usize = 0;
        let mut temp_map_count: usize = 0;
        for op in ops {
            if let TraceOp::MakeListTemp(len) = op {
                temp_list_elems = temp_list_elems.saturating_add(*len);
                temp_list_count = temp_list_count.saturating_add(1);
            }
            if let TraceOp::MakeMapTemp(_) = op {
                temp_map_count = temp_map_count.saturating_add(1);
            }
        }
        let has_temp_allocs = temp_list_count > 0 || temp_map_count > 0;
        let mut asm = Asm::new(profile_enabled);
        emit_prologue(&mut asm);
        let use_avx2_dot = avx2_dot_kernel_enabled();
        let has_dot_square_pattern =
            (0..ops.len()).any(|idx| match_dot_square_lane_pattern(ops, idx).is_some());
        asm.prefer_vex_scalar = use_avx2_dot && has_dot_square_pattern;
        let promoted = PromotedLocals::new(promoted_locals);
        emit_load_promoted_locals(&mut asm, &promoted);
        let mut temp_list_sources_by_op: HashMap<usize, &TempListSource> = HashMap::new();
        for meta in temp_list_sources {
            temp_list_sources_by_op.insert(meta.trace_op_index, meta);
        }
        let mut start_patches: Vec<usize> = Vec::new();
        let mut exit_patches: Vec<usize> = Vec::new();
        let mut exit_jump_patches: Vec<usize> = Vec::new();
        let mut deopt_patches: Vec<usize> = Vec::new();
        let mut tail_resume_patches: Vec<usize> = Vec::new();
        let mut internal_labels: HashMap<usize, usize> = HashMap::new();
        let mut internal_branch_patches: Vec<(usize, usize)> = Vec::new();
        let mut internal_jump_patches: Vec<(usize, usize)> = Vec::new();

        let mut pre_idx = 0;
        while pre_idx < ops.len() {
            if let TraceOp::GuardListBounds(list_idx, idx_idx) = ops[pre_idx] {
                let mut at = emit_guard_list_bounds(&mut asm, list_idx, idx_idx);
                exit_jump_patches.append(&mut at);
                pre_idx += 1;
                continue;
            }
            if let TraceOp::GuardIndexNonNeg(idx_idx) = ops[pre_idx] {
                let mut at = emit_guard_index_nonneg(&mut asm, idx_idx, &promoted);
                exit_jump_patches.append(&mut at);
                pre_idx += 1;
                continue;
            }
            if let TraceOp::GuardListNoAliasSameLen(list_a, list_b) = ops[pre_idx] {
                let mut at = emit_guard_list_noalias_same_len(&mut asm, list_a, list_b);
                exit_jump_patches.append(&mut at);
                pre_idx += 1;
                continue;
            }
            if let TraceOp::InitLocalConst(idx, value) = ops[pre_idx] {
                emit_init_local_const(&mut asm, idx, value, &promoted);
                pre_idx += 1;
                continue;
            }
            break;
        }

        let trace_start = asm.pos();
        if profile_enabled {
            asm.emit_inc_qword_at_r15(PROFILE_TRACE_ITERS_OFFSET);
        }

        let mut op_index = pre_idx;
        while op_index < ops.len() {
            if use_avx2_dot {
                if let Some((pattern, next_index)) =
                    match_dot_square_avx_loop_pattern(ops, op_index)
                {
                    if let Some(exit_patch) =
                        emit_dot_square_avx2_loop_vectorized(&mut asm, &pattern, &promoted)
                    {
                        tail_resume_patches.push(exit_patch);
                        op_index = next_index;
                        continue;
                    }
                }
            }
            if let Some(first_lane) = match_list_update_lane_pattern(ops, op_index) {
                // Keep +1.0 in a dedicated XMM register so fused lanes can reuse it
                // instead of rematerializing the immediate for each lane.
                const LIST_UPDATE_ONE_REG: u8 = 1;
                asm.emit(&[0x48, 0xB8]);
                asm.emit_u64(1.0f64.to_bits());
                emit_movq_xmm_from_rax(&mut asm, LIST_UPDATE_ONE_REG);

                if let Some(reg) = promoted.xmm_for(first_lane.idx_idx) {
                    emit_cvttsd2si_rcx_from_xmm(&mut asm, reg);
                } else {
                    let idx_disp = (first_lane.idx_idx as i32) * 8;
                    asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
                    asm.emit_u32(idx_disp as u32);
                    asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
                }
                // Hoist list data pointer once for consecutive fused lanes.
                emit_load_list_data_ptr_r10_from_local(&mut asm, first_lane.list_idx);

                let mut lane_idx = op_index;
                while let Some(lane) = match_list_update_lane_pattern(ops, lane_idx) {
                    if lane.list_idx != first_lane.list_idx
                        || lane.idx_idx != first_lane.idx_idx
                        || lane.data_ptr != first_lane.data_ptr
                    {
                        break;
                    }
                    emit_list_update_lane_fused(
                        &mut asm,
                        lane.offset,
                        lane.acc_local,
                        &promoted,
                        LIST_UPDATE_ONE_REG,
                    );
                    lane_idx += 7;
                }
                op_index = lane_idx;
                continue;
            }
            if let Some(first_lane) = match_dot_square_lane_pattern(ops, op_index) {
                if let Some(reg) = promoted.xmm_for(first_lane.idx_idx) {
                    emit_cvttsd2si_rcx_from_xmm(&mut asm, reg);
                } else {
                    let idx_disp = (first_lane.idx_idx as i32) * 8;
                    asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
                    asm.emit_u32(idx_disp as u32);
                    asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
                }
                // Hoist list data pointer once for consecutive square lanes.
                emit_load_list_data_ptr_r10_from_local(&mut asm, first_lane.list_idx);

                let mut lane_idx = op_index;
                while let Some(lane) = match_dot_square_lane_pattern(ops, lane_idx) {
                    if lane.list_idx != first_lane.list_idx
                        || lane.idx_idx != first_lane.idx_idx
                        || lane.data_ptr != first_lane.data_ptr
                    {
                        break;
                    }
                    if use_avx2_dot {
                        if let Some(quad) = match_dot_square_quad_pattern(ops, lane_idx) {
                            if quad.list_idx == first_lane.list_idx
                                && quad.idx_idx == first_lane.idx_idx
                                && quad.data_ptr == first_lane.data_ptr
                                && emit_dot_square_quad_avx2_fma(
                                    &mut asm,
                                    quad.base_offset,
                                    quad.accum,
                                    &promoted,
                                )
                            {
                                lane_idx += 16;
                                continue;
                            }
                        }
                    }
                    emit_dot_square_lane_fused(&mut asm, lane.offset, lane.acc_local, &promoted);
                    lane_idx += 4;
                }
                op_index = lane_idx;
                continue;
            }

            let op = &ops[op_index];
            match op {
                TraceOp::ConstNum(n) => emit_push_f64(&mut asm, *n),
                TraceOp::ConstBool(b) => {
                    let v = if *b { 1.0 } else { 0.0 };
                    emit_push_f64(&mut asm, v);
                }
                TraceOp::ConstText(s) => emit_make_text(&mut asm, s),
                TraceOp::PushNull => emit_push_bits(&mut asm, vb::tag_null()),
                TraceOp::Dup => emit_dup_top(&mut asm),
                TraceOp::InitLocalConst(idx, value) => {
                    emit_init_local_const(&mut asm, *idx, *value, &promoted)
                }
                TraceOp::LoadLocal(idx) => emit_load_local(&mut asm, *idx, &promoted),
                TraceOp::StoreLocal(idx) => emit_store_local(&mut asm, *idx, &promoted),
                TraceOp::AddLocalConst(idx, c) => {
                    emit_add_local_const(&mut asm, *idx, *c, &promoted)
                }
                TraceOp::AddLocalFromStack(idx) => {
                    emit_add_local_from_stack(&mut asm, *idx, &promoted)
                }
                TraceOp::LenListLocal(idx) => emit_len_list_local(&mut asm, *idx),
                TraceOp::IndexListNumLocal(list_idx, idx_idx) => {
                    emit_index_list_num_local(&mut asm, *list_idx, *idx_idx)
                }
                TraceOp::IndexListNumLocalPtr(list_idx, idx_idx, data_ptr) => {
                    emit_index_list_num_local_ptr(
                        &mut asm, *list_idx, *idx_idx, *data_ptr, &promoted,
                    )
                }
                TraceOp::IndexListNumLocalPtrOff(list_idx, idx_idx, data_ptr, offset) => {
                    emit_index_list_num_local_ptr_off(
                        &mut asm, *list_idx, *idx_idx, *data_ptr, *offset, &promoted,
                    )
                }
                TraceOp::SetIndexListNumLocalPtr(list_idx, idx_idx, data_ptr) => {
                    emit_setindex_list_num_local_ptr(
                        &mut asm, *list_idx, *idx_idx, *data_ptr, &promoted,
                    )
                }
                TraceOp::SetIndexListNumLocalNoVer(list_idx, idx_idx) => {
                    emit_setindex_list_num_local_nover(&mut asm, *list_idx, *idx_idx, &promoted)
                }
                TraceOp::SetIndexListNumLocalPtrNoVer(list_idx, idx_idx, data_ptr) => {
                    emit_setindex_list_num_local_ptr_nover(
                        &mut asm, *list_idx, *idx_idx, *data_ptr, &promoted,
                    )
                }
                TraceOp::SetIndexListNumLocalPtrNoVerOff(list_idx, idx_idx, data_ptr, offset) => {
                    emit_setindex_list_num_local_ptr_nover_off(
                        &mut asm, *list_idx, *idx_idx, *data_ptr, *offset, &promoted,
                    )
                }
                TraceOp::SetIndexListNumLocalPtrNoVerFast(list_idx, idx_idx, data_ptr) => {
                    emit_setindex_list_num_local_ptr_nover_fast(
                        &mut asm, *list_idx, *idx_idx, *data_ptr, &promoted,
                    )
                }
                TraceOp::SetIndexListNumLocalPtrNoVerOffFast(
                    list_idx,
                    idx_idx,
                    data_ptr,
                    offset,
                ) => emit_setindex_list_num_local_ptr_nover_off_fast(
                    &mut asm, *list_idx, *idx_idx, *data_ptr, *offset, &promoted,
                ),
                TraceOp::BumpListVersionLocal(list_idx) => {
                    emit_bump_list_version_local(&mut asm, *list_idx)
                }
                TraceOp::MakeListTemp(len) => {
                    if let Some(meta) = temp_list_sources_by_op.get(&op_index) {
                        if !emit_make_list_temp_inline_sources(&mut asm, *len, &meta.sources) {
                            emit_make_list_temp(&mut asm, *len);
                        }
                    } else {
                        emit_make_list_temp(&mut asm, *len);
                    }
                }
                TraceOp::AddNum => emit_bin_op(&mut asm, BinOp::Add),
                TraceOp::SubNum => emit_bin_op(&mut asm, BinOp::Sub),
                TraceOp::MulNum => emit_bin_op(&mut asm, BinOp::Mul),
                TraceOp::DivNum => emit_bin_op(&mut asm, BinOp::Div),
                TraceOp::EqNum => emit_cmp(&mut asm, CmpKind::Eq),
                TraceOp::NeNum => emit_cmp(&mut asm, CmpKind::Ne),
                TraceOp::LtNum => emit_cmp(&mut asm, CmpKind::Lt),
                TraceOp::LeNum => emit_cmp(&mut asm, CmpKind::Le),
                TraceOp::GtNum => emit_cmp(&mut asm, CmpKind::Gt),
                TraceOp::GeNum => emit_cmp(&mut asm, CmpKind::Ge),
                TraceOp::Label(label) => {
                    if internal_labels.insert(*label, asm.pos()).is_some() {
                        return Err(format!("duplicate internal trace label {label}"));
                    }
                }
                TraceOp::BranchFalse(label) => {
                    let at = emit_jump_if_false(&mut asm);
                    asm.mark_branch_kind(at, BranchKind::Generic);
                    internal_branch_patches.push((at, *label));
                }
                TraceOp::JumpTo(label) => {
                    let at = asm.emit_jmp_placeholder();
                    internal_jump_patches.push((at, *label));
                }
                TraceOp::JumpStart => {
                    if has_temp_allocs {
                        emit_call_reset_temps(&mut asm);
                    }
                    let at = asm.emit_jmp_placeholder();
                    start_patches.push(at);
                }
                TraceOp::GuardFalse => {
                    let at = emit_jump_if_false(&mut asm);
                    exit_jump_patches.push(at);
                }
                TraceOp::GuardFalseDeopt(deopt_ip) => {
                    let at = emit_deopt_if_false(&mut asm, *deopt_ip);
                    deopt_patches.push(at);
                }
                TraceOp::GuardIndexCmpConst(idx_idx, limit, inclusive) => {
                    let mut at = emit_guard_index_cmp_const(
                        &mut asm, *idx_idx, *limit, *inclusive, &promoted,
                    );
                    exit_jump_patches.append(&mut at);
                }
                TraceOp::GuardIndexRangeConst(idx_idx, limit, inclusive) => {
                    let mut at = emit_guard_index_range_const(
                        &mut asm, *idx_idx, *limit, *inclusive, &promoted,
                    );
                    tail_resume_patches.append(&mut at);
                }
                TraceOp::GuardListBounds(list_idx, idx_idx) => {
                    let mut at = emit_guard_list_bounds(&mut asm, *list_idx, *idx_idx);
                    exit_jump_patches.append(&mut at);
                }
                TraceOp::GuardIndexNonNeg(_) => {
                    return Err("GuardIndexNonNeg must be in prelude".into());
                }
                TraceOp::GuardListNoAliasSameLen(_, _) => {
                    return Err("GuardListNoAliasSameLen must be in prelude".into());
                }
                TraceOp::MakeList(len) => emit_make_list(&mut asm, *len),
                TraceOp::MakeMap(keys) => emit_make_map(&mut asm, keys),
                TraceOp::MakeMapTemp(keys) => emit_make_map_temp(&mut asm, keys),
                TraceOp::LoadField(field) => emit_load_field_typed(&mut asm, field),
                TraceOp::MapGetSlot(slot) => emit_map_get_slot(&mut asm, *slot),
                TraceOp::MapGetSlotNoVerGuard(map_idx, deopt_ip, cap, slots_ptr, slot_idx) => {
                    let mut guards = emit_map_get_slot_nover_guard(
                        &mut asm, *map_idx, *deopt_ip, *cap, *slots_ptr, *slot_idx,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapGetSlotPtr(ptr) => emit_map_get_slot_ptr(&mut asm, *ptr),
                TraceOp::MapGetSlotPtrNoVer(map_idx, deopt_ip, cap, slots_ptr, value_ptr) => {
                    let mut guards = emit_map_get_slot_ptr_nover(
                        &mut asm, *map_idx, *deopt_ip, *cap, *slots_ptr, *value_ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapGetSmallKeyNoVer(map_idx, key_idx, deopt_ip, cap, slots_ptr) => {
                    let mut guards = emit_map_get_small_key_nover(
                        &mut asm, *map_idx, *key_idx, *deopt_ip, *cap, *slots_ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapGetTextKeyNoVer(map_idx, key_idx, deopt_ip, cap, slots_ptr) => {
                    let mut guards = emit_map_get_text_key_nover(
                        &mut asm, *map_idx, *key_idx, *deopt_ip, *cap, *slots_ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapGetTextKeyConstNoVer(
                    map_idx,
                    key_idx,
                    key_bits,
                    deopt_ip,
                    cap,
                    slots_ptr,
                    key_ptr,
                    key_len,
                    key_hash,
                ) => {
                    let mut guards = emit_map_get_text_key_const_nover(
                        &mut asm, *map_idx, *key_idx, *key_bits, *deopt_ip, *cap, *slots_ptr,
                        *key_ptr, *key_len, *key_hash,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapGetTextKeyConstSlotPtrNoVer(
                    map_idx,
                    key_idx,
                    key_bits,
                    deopt_ip,
                    cap,
                    slots_ptr,
                    value_ptr,
                ) => {
                    let mut guards = emit_map_get_text_key_const_slot_ptr_nover(
                        &mut asm, *map_idx, *key_idx, *key_bits, *deopt_ip, *cap, *slots_ptr,
                        *value_ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapGetTextKeyConstSlotPtrStableNoVer(
                    map_idx,
                    key_idx,
                    key_bits,
                    deopt_ip,
                    value_ptr,
                ) => {
                    let mut guards = emit_map_get_text_key_const_slot_ptr_stable_nover(
                        &mut asm, *map_idx, *key_idx, *key_bits, *deopt_ip, *value_ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapGetTextKeyConstSlotPtrStableAddLocalNoVer(
                    map_idx,
                    key_idx,
                    key_bits,
                    deopt_ip,
                    value_ptr,
                    acc_local,
                ) => {
                    let mut guards = emit_map_get_text_key_const_slot_ptr_stable_add_local_nover(
                        &mut asm, *map_idx, *key_idx, *key_bits, *deopt_ip, *value_ptr, *acc_local,
                        &promoted,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapGetTextKeyConstSlotPtrPic2NoVer(
                    map_idx,
                    key_idx,
                    key_bits,
                    deopt_ip,
                    cap1,
                    slots1,
                    value_ptr1,
                    cap2,
                    slots2,
                    value_ptr2,
                ) => {
                    let mut guards = emit_map_get_text_key_const_slot_ptr_pic2_nover(
                        &mut asm,
                        *map_idx,
                        *key_idx,
                        *key_bits,
                        *deopt_ip,
                        *cap1,
                        *slots1,
                        *value_ptr1,
                        *cap2,
                        *slots2,
                        *value_ptr2,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapSetSlotPtrNoVer(map_idx, ptr) => {
                    emit_map_set_slot_ptr_nover(&mut asm, *map_idx, *ptr)
                }
                TraceOp::MapSetSlotPtrNoVerGuard(map_idx, deopt_ip, cap, slots_ptr, ptr) => {
                    let mut guards = emit_map_set_slot_ptr_nover_guard(
                        &mut asm, *map_idx, *deopt_ip, *cap, *slots_ptr, *ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapSetSlotNoVer(map_idx, slot_idx) => {
                    emit_map_set_slot_nover(&mut asm, *map_idx, *slot_idx)
                }
                TraceOp::MapSetSlotNoVerGuard(map_idx, deopt_ip, cap, slots_ptr, slot_idx) => {
                    let mut guards = emit_map_set_slot_nover_guard(
                        &mut asm, *map_idx, *deopt_ip, *cap, *slots_ptr, *slot_idx,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapSetSmallKeyNoVer(map_idx, key_idx, deopt_ip, cap, slots_ptr) => {
                    let mut guards = emit_map_set_small_key_nover(
                        &mut asm, *map_idx, *key_idx, *deopt_ip, *cap, *slots_ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapSetTextKeyNoVer(map_idx, key_idx, deopt_ip, cap, slots_ptr) => {
                    let mut guards = emit_map_set_text_key_nover(
                        &mut asm, *map_idx, *key_idx, *deopt_ip, *cap, *slots_ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapSetTextKeyConstNoVer(
                    map_idx,
                    key_idx,
                    key_bits,
                    deopt_ip,
                    cap,
                    slots_ptr,
                    key_ptr,
                    key_len,
                    key_hash,
                ) => {
                    let mut guards = emit_map_set_text_key_const_nover(
                        &mut asm, *map_idx, *key_idx, *key_bits, *deopt_ip, *cap, *slots_ptr,
                        *key_ptr, *key_len, *key_hash,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapSetTextKeyConstSlotPtrNoVer(
                    map_idx,
                    key_idx,
                    key_bits,
                    deopt_ip,
                    cap,
                    slots_ptr,
                    value_ptr,
                ) => {
                    let mut guards = emit_map_set_text_key_const_slot_ptr_nover(
                        &mut asm, *map_idx, *key_idx, *key_bits, *deopt_ip, *cap, *slots_ptr,
                        *value_ptr,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::MapSetTextKeyConstSlotPtrPic2NoVer(
                    map_idx,
                    key_idx,
                    key_bits,
                    deopt_ip,
                    cap1,
                    slots1,
                    value_ptr1,
                    cap2,
                    slots2,
                    value_ptr2,
                ) => {
                    let mut guards = emit_map_set_text_key_const_slot_ptr_pic2_nover(
                        &mut asm,
                        *map_idx,
                        *key_idx,
                        *key_bits,
                        *deopt_ip,
                        *cap1,
                        *slots1,
                        *value_ptr1,
                        *cap2,
                        *slots2,
                        *value_ptr2,
                    );
                    deopt_patches.append(&mut guards);
                }
                TraceOp::IndexListNum => emit_index_list_num_unchecked(&mut asm),
                TraceOp::LenList => emit_len_list_unchecked(&mut asm),
                TraceOp::SetIndexListNum => emit_setindex_list_num_unchecked(&mut asm),
                TraceOp::ToText => emit_call_to_text(&mut asm),
                TraceOp::Pop => emit_dec_sp(&mut asm),
                TraceOp::Return => {
                    let at = asm.emit_jmp_placeholder();
                    exit_patches.push(at);
                }
                TraceOp::BumpMapVersionLocal(map_idx) => {
                    emit_bump_map_version_local(&mut asm, *map_idx)
                }
            }
            op_index += 1;
        }

        for at in start_patches {
            asm.patch_rel32(at, trace_start);
        }
        for (at, label) in internal_branch_patches {
            let target = internal_labels
                .get(&label)
                .copied()
                .ok_or_else(|| format!("missing internal trace label {label}"))?;
            asm.patch_rel32(at, target);
        }
        for (at, label) in internal_jump_patches {
            let target = internal_labels
                .get(&label)
                .copied()
                .ok_or_else(|| format!("missing internal trace label {label}"))?;
            asm.patch_rel32(at, target);
        }
        let hot_code_len = asm.pos();
        let mut deopt_site_jmps: Vec<usize> = Vec::with_capacity(deopt_patches.len());
        for (site_id, at) in deopt_patches.into_iter().enumerate() {
            let site_stub_offset = asm.pos();
            emit_store_deopt_site(&mut asm, site_id);
            let site_jmp = asm.emit_jmp_placeholder();
            deopt_site_jmps.push(site_jmp);
            asm.mark_branch_kind(at, BranchKind::Guard);
            asm.patch_rel32(at, site_stub_offset);
        }

        let tail_resume_stub_offset = asm.pos();
        emit_store_deopt_ip(&mut asm, tail_resume_ip);
        emit_set_exit_flag(&mut asm, 3);
        emit_store_deopt_sp(&mut asm);
        let tail_resume_jmp = asm.emit_jmp_placeholder();

        let exit_stub_offset = asm.pos();
        emit_set_exit_flag(&mut asm, 1);
        asm.emit(&[0x48, 0x31, 0xDB]); // xor rbx, rbx
        let stub_jmp = asm.emit_jmp_placeholder();

        let deopt_stub_offset = asm.pos();
        if profile_enabled {
            asm.emit_inc_qword_at_r15(PROFILE_DEOPTS_OFFSET);
        }
        emit_set_exit_flag(&mut asm, 2);
        emit_store_deopt_sp(&mut asm);
        let deopt_jmp = asm.emit_jmp_placeholder();

        let exit_offset = asm.pos();
        if asm.avx_upper_dirty && (!merge_locals.is_empty() || !promoted.is_empty()) {
            asm.emit_vzeroupper();
        }
        if !merge_locals.is_empty() {
            emit_merge_locals(&mut asm, merge_locals, &promoted);
        }
        if !promoted.is_empty() {
            emit_store_promoted_locals(&mut asm, &promoted);
        }
        emit_exit(&mut asm, &mut exit_patches, exit_offset);
        asm.patch_rel32(stub_jmp, exit_offset);
        asm.patch_rel32(deopt_jmp, exit_offset);
        asm.patch_rel32(tail_resume_jmp, exit_offset);
        for at in deopt_site_jmps {
            asm.patch_rel32(at, deopt_stub_offset);
        }

        for at in tail_resume_patches {
            asm.mark_branch_kind(at, BranchKind::Exit);
            asm.patch_rel32(at, tail_resume_stub_offset);
        }
        for at in exit_jump_patches {
            asm.mark_branch_kind(at, BranchKind::Exit);
            asm.patch_rel32(at, exit_stub_offset);
        }
        asm.finalize_profiled_branches();

        if let Ok(path) = std::env::var("NAUX_TRACE_DUMP_BIN") {
            let full_len = asm.code.len();
            let _ = std::fs::write(&path, &asm.code);
            if std::env::var("NAUX_TRACE_DEBUG")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                eprintln!(
                    "[trace-debug] dumped full trace code to {} ({} bytes, hot {} bytes)",
                    path, full_len, hot_code_len
                );
            }
        }

        let mem = unsafe {
            let code_len = asm.code.len();
            let data_len = asm.data.len();
            let total_len = code_len + data_len;
            let ptr = mmap(
                std::ptr::null_mut(),
                total_len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            );
            if ptr.is_null() {
                return Err("mmap failed".into());
            }
            let base = ptr as *mut u8;
            std::ptr::copy_nonoverlapping(asm.code.as_ptr(), base, code_len);
            if data_len > 0 {
                std::ptr::copy_nonoverlapping(asm.data.as_ptr(), base.add(code_len), data_len);
            }
            for (at, data_off) in asm.data_patches.iter() {
                let addr = base.add(code_len + *data_off) as u64;
                std::ptr::copy_nonoverlapping(&addr as *const u64 as *const u8, base.add(*at), 8);
            }
            if mprotect(ptr, total_len, PROT_READ | PROT_EXEC) != 0 {
                munmap(ptr, total_len);
                return Err("mprotect failed".into());
            }
            JitCode {
                ptr: ptr as *mut u8,
                len: total_len,
            }
        };

        let entry = unsafe { std::mem::transmute::<*mut u8, JitFn>(mem.ptr) };
        Ok(JitExecutable {
            code: mem,
            entry,
            hot_code_len,
            temp_list_elems,
            temp_list_count,
            temp_map_count,
            static_calls: asm.call_count,
            static_branches: asm.jcc_count,
            profile_enabled,
            patch_sites: asm.patch_sites_meta(),
        })
    }

    #[derive(Clone, Copy)]
    enum BinOp {
        Add,
        Sub,
        Mul,
        Div,
    }

    fn emit_prologue(asm: &mut Asm) {
        asm.emit(&[0x55]); // push rbp
        asm.emit(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
        asm.emit(&[0x53]); // push rbx
        asm.emit(&[0x41, 0x54]); // push r12
        asm.emit(&[0x41, 0x55]); // push r13
        asm.emit(&[0x41, 0x56]); // push r14
        asm.emit(&[0x41, 0x57]); // push r15
        asm.emit(&[0x48, 0x83, 0xEC, 0x08]); // sub rsp, 8 (align)
        asm.emit(&[0x48, 0x31, 0xDB]); // xor rbx, rbx
        asm.emit(&[0x49, 0x89, 0xFD]); // mov r13, rdi
        asm.emit(&[0x49, 0x89, 0xF6]); // mov r14, rsi
        asm.emit(&[0x49, 0x89, 0xD7]); // mov r15, rdx
    }

    fn emit_movsd_xmm_from_local(asm: &mut Asm, reg: u8, disp: i32) {
        let modrm = 0x80 | ((reg & 0x7) << 3) | 0x05;
        let rex = 0x40 | 0x01 | if reg >= 8 { 0x04 } else { 0x00 }; // base r13 + reg ext
        asm.emit(&[0xF2, rex, 0x0F, 0x10, modrm]);
        asm.emit_u32(disp as u32);
    }

    fn emit_movsd_local_from_xmm(asm: &mut Asm, reg: u8, disp: i32) {
        let modrm = 0x80 | ((reg & 0x7) << 3) | 0x05;
        let rex = 0x40 | 0x01 | if reg >= 8 { 0x04 } else { 0x00 }; // base r13 + reg ext
        asm.emit(&[0xF2, rex, 0x0F, 0x11, modrm]);
        asm.emit_u32(disp as u32);
    }

    fn emit_cvttsd2si_rcx_from_xmm(asm: &mut Asm, reg: u8) {
        if asm.prefer_vex_scalar || asm.avx_upper_dirty {
            emit_vcvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let modrm = 0xC0 | (1 << 3) | (reg & 0x7);
            let rex = 0x48 | if reg >= 8 { 0x01 } else { 0x00 }; // W + src ext
            asm.emit(&[0xF2, rex, 0x0F, 0x2C, modrm]);
        }
    }

    fn emit_vcvttsd2si_rcx_from_xmm(asm: &mut Asm, reg: u8) {
        let b_bit = if reg >= 8 { 0x00 } else { 0x20 }; // VEX.B is inverted
        let byte2 = 0xC0 | b_bit | 0x01; // R=1, X=1, m-mmmm=00001 (0F map)
        let modrm = 0xC0 | (1 << 3) | (reg & 0x7);
        asm.emit_avx(&[0xC4, byte2, 0xFB, 0x2C, modrm]);
    }

    fn emit_cvtsi2sd_xmm_from_rcx(asm: &mut Asm, reg: u8) {
        let modrm = 0xC0 | ((reg & 0x7) << 3) | 0x01;
        let rex = 0x48 | if reg >= 8 { 0x04 } else { 0x00 }; // W + dst ext
        asm.emit(&[0xF2, rex, 0x0F, 0x2A, modrm]);
    }

    #[inline]
    fn supports_native_syscall(argc: usize) -> bool {
        cfg!(target_os = "linux") && (1..=7).contains(&argc)
    }

    fn emit_movq_xmm_from_rax(asm: &mut Asm, reg: u8) {
        let modrm = 0xC0 | ((reg & 0x7) << 3);
        let rex = 0x48 | if reg >= 8 { 0x04 } else { 0x00 }; // W + reg ext
        asm.emit(&[0x66, rex, 0x0F, 0x6E, modrm]);
    }

    fn emit_vmovq_xmm_from_rax(asm: &mut Asm, reg: u8) {
        let r_bit = if reg >= 8 { 0x00 } else { 0x80 }; // VEX.R is inverted
        let byte2 = r_bit | 0x40 | 0x20 | 0x01; // X=1, B=1, map=0F
        let modrm = 0xC0 | ((reg & 0x7) << 3);
        asm.emit_avx(&[0xC4, byte2, 0xF9, 0x6E, modrm]);
    }

    fn emit_addsd_xmm_xmm(asm: &mut Asm, dst: u8, src: u8) {
        let modrm = 0xC0 | ((dst & 0x7) << 3) | (src & 0x7);
        let rex = 0x40 | if dst >= 8 { 0x04 } else { 0x00 } | if src >= 8 { 0x01 } else { 0x00 };
        if rex != 0x40 {
            asm.emit(&[0xF2, rex, 0x0F, 0x58, modrm]);
        } else {
            asm.emit(&[0xF2, 0x0F, 0x58, modrm]);
        }
    }

    fn emit_load_promoted_locals(asm: &mut Asm, promoted: &PromotedLocals) {
        for (idx, reg) in &promoted.regs {
            let disp = (*idx as i32) * 8;
            emit_movsd_xmm_from_local(asm, *reg, disp);
        }
    }

    fn emit_store_promoted_locals(asm: &mut Asm, promoted: &PromotedLocals) {
        for (idx, reg) in &promoted.regs {
            let disp = (*idx as i32) * 8;
            emit_movsd_local_from_xmm(asm, *reg, disp);
        }
    }

    fn emit_merge_locals(asm: &mut Asm, merges: &[(usize, usize)], promoted: &PromotedLocals) {
        for (dst, src) in merges {
            if dst == src {
                continue;
            }
            let dst_reg = promoted.xmm_for(*dst);
            let src_reg = promoted.xmm_for(*src);
            match (dst_reg, src_reg) {
                (Some(dreg), Some(sreg)) => {
                    emit_addsd_xmm_xmm(asm, dreg, sreg);
                }
                (Some(dreg), None) => {
                    let src_disp = (*src as i32) * 8;
                    emit_movsd_xmm_from_local(asm, 0, src_disp);
                    emit_addsd_xmm_xmm(asm, dreg, 0);
                }
                (None, Some(sreg)) => {
                    let dst_disp = (*dst as i32) * 8;
                    emit_movsd_xmm_from_local(asm, 0, dst_disp);
                    emit_addsd_xmm_xmm(asm, 0, sreg);
                    emit_movsd_local_from_xmm(asm, 0, dst_disp);
                }
                (None, None) => {
                    let dst_disp = (*dst as i32) * 8;
                    let src_disp = (*src as i32) * 8;
                    emit_movsd_xmm_from_local(asm, 0, dst_disp);
                    emit_movsd_xmm_from_local(asm, 1, src_disp);
                    asm.emit(&[0xF2, 0x0F, 0x58, 0xC1]); // addsd xmm0, xmm1
                    emit_movsd_local_from_xmm(asm, 0, dst_disp);
                }
            }
        }
    }

    fn emit_exit(asm: &mut Asm, exit_patches: &mut Vec<usize>, exit_offset: usize) {
        // cmp rbx, 0
        asm.emit(&[0x48, 0x83, 0xFB, 0x00]);
        let je_at = asm.emit_jcc_placeholder(0x84); // JE
                                                    // dec rbx
        asm.emit(&[0x48, 0xFF, 0xCB]);
        // movsd xmm0, [r14 + rbx*8]
        emit_movsd_xmm_from_stack(asm, 0);
        let jmp_epilogue = asm.emit_jmp_placeholder();

        let zero_offset = asm.pos();
        // xorpd xmm0, xmm0
        asm.emit(&[0x66, 0x0F, 0x57, 0xC0]);

        let epilogue_offset = asm.pos();
        if asm.avx_upper_dirty {
            asm.emit_vzeroupper();
        }
        // add rsp, 8 (undo align)
        asm.emit(&[0x48, 0x83, 0xC4, 0x08]);
        // pop r15, r14, r13, r12, rbx, rbp, ret
        asm.emit(&[0x41, 0x5F]);
        asm.emit(&[0x41, 0x5E]);
        asm.emit(&[0x41, 0x5D]);
        asm.emit(&[0x41, 0x5C]);
        asm.emit(&[0x5B]);
        asm.emit(&[0x5D]);
        asm.emit(&[0xC3]);

        asm.patch_rel32(je_at, zero_offset);
        asm.patch_rel32(jmp_epilogue, epilogue_offset);

        for at in exit_patches.drain(..) {
            asm.patch_rel32(at, exit_offset);
        }
    }

    const EXIT_FLAG_OFFSET: i32 = 4;
    const DEOPT_IP_OFFSET: i32 = 8;
    const DEOPT_SP_OFFSET: i32 = 16;
    const DEOPT_SITE_OFFSET: i32 = 24;

    fn emit_set_exit_flag(asm: &mut Asm, value: i32) {
        // mov dword ptr [r15 + 4], imm32
        asm.emit(&[0x41, 0xC7, 0x47, EXIT_FLAG_OFFSET as u8]);
        asm.emit_u32(value as u32);
    }

    fn emit_store_deopt_sp(asm: &mut Asm) {
        // mov [r15 + deopt_sp], rbx
        asm.emit(&[0x49, 0x89, 0x9F]);
        asm.emit_u32(DEOPT_SP_OFFSET as u32);
    }

    fn emit_store_deopt_ip(asm: &mut Asm, ip: usize) {
        // mov rax, imm64
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(ip as u64);
        // mov [r15 + deopt_ip], rax
        asm.emit(&[0x49, 0x89, 0x87]);
        asm.emit_u32(DEOPT_IP_OFFSET as u32);
    }

    fn emit_store_deopt_site(asm: &mut Asm, site: usize) {
        // mov rax, imm64
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(site as u64);
        // mov [r15 + deopt_site], rax
        asm.emit(&[0x49, 0x89, 0x87]);
        asm.emit_u32(DEOPT_SITE_OFFSET as u32);
    }

    fn emit_push_f64(asm: &mut Asm, v: f64) {
        let bits = v.to_bits();
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(bits);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_push_bits(asm: &mut Asm, bits: u64) {
        emit_push_f64(asm, f64::from_bits(bits));
    }

    fn emit_dup_top(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        emit_inc_sp(asm);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_make_text(asm: &mut Asm, s: &str) {
        if let Some(bits) = vb::encode_small_text(s) {
            emit_push_bits(asm, bits);
            return;
        }
        let data_off = asm.emit_cstr(s);
        let at = asm.emit_mov_imm64_placeholder(&[0x48, 0xBF]); // mov rdi, imm64
        asm.data_patches.push((at, data_off));
        asm.emit(&[0x4C, 0x89, 0xFE]); // mov rsi, r15
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_make_text as *const () as usize as u64);
        asm.emit_call_rax();
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_make_map(asm: &mut Asm, keys: &[String]) {
        let mut blob = Vec::new();
        for key in keys {
            blob.extend_from_slice(key.as_bytes());
            blob.push(0);
        }
        let data_off = asm.emit_bytes(&blob);

        // rax = rbx - len
        asm.emit(&[0x48, 0x89, 0xD8]); // mov rax, rbx
        if keys.len() <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xE8, keys.len() as u8]);
        } else {
            asm.emit(&[0x48, 0x2D]);
            asm.emit_u32(keys.len() as u32);
        }
        // lea rdi, [r14 + rax*8]
        asm.emit(&[0x49, 0x8D, 0x3C, 0xC6]);
        // mov rsi, len
        asm.emit(&[0x48, 0xC7, 0xC6]);
        asm.emit_u32(keys.len() as u32);
        // mov rdx, keys_blob_ptr
        let at = asm.emit_mov_imm64_placeholder(&[0x48, 0xBA]); // mov rdx, imm64
        asm.data_patches.push((at, data_off));
        // mov rcx, r15 (runtime)
        asm.emit(&[0x4C, 0x89, 0xF9]);
        // call jit_make_map
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_make_map as *const () as usize as u64);
        asm.emit_call_rax();
        // rbx = rbx - len
        if keys.len() <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xEB, keys.len() as u8]);
        } else {
            asm.emit(&[0x48, 0x81, 0xEB]);
            asm.emit_u32(keys.len() as u32);
        }
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_make_map_temp(asm: &mut Asm, keys: &[String]) {
        let mut blob = Vec::new();
        for key in keys {
            blob.extend_from_slice(key.as_bytes());
            blob.push(0);
        }
        let data_off = asm.emit_bytes(&blob);

        // rax = rbx - len
        asm.emit(&[0x48, 0x89, 0xD8]); // mov rax, rbx
        if keys.len() <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xE8, keys.len() as u8]);
        } else {
            asm.emit(&[0x48, 0x2D]);
            asm.emit_u32(keys.len() as u32);
        }
        // lea rdi, [r14 + rax*8]
        asm.emit(&[0x49, 0x8D, 0x3C, 0xC6]);
        // mov rsi, len
        asm.emit(&[0x48, 0xC7, 0xC6]);
        asm.emit_u32(keys.len() as u32);
        // mov rdx, keys_blob_ptr
        let at = asm.emit_mov_imm64_placeholder(&[0x48, 0xBA]); // mov rdx, imm64
        asm.data_patches.push((at, data_off));
        // mov rcx, r15 (runtime)
        asm.emit(&[0x4C, 0x89, 0xF9]);
        // call jit_make_map_temp
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_make_map_temp as *const () as usize as u64);
        asm.emit_call_rax();
        // rbx = rbx - len
        if keys.len() <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xEB, keys.len() as u8]);
        } else {
            asm.emit(&[0x48, 0x81, 0xEB]);
            asm.emit_u32(keys.len() as u32);
        }
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_load_field(asm: &mut Asm, field: &str) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (map bits)
        let data_off = asm.emit_cstr(field);
        let at = asm.emit_mov_imm64_placeholder(&[0x48, 0xBE]); // mov rsi, imm64
        asm.data_patches.push((at, data_off));
        asm.emit(&[0x4C, 0x89, 0xFA]); // mov rdx, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_map_get_str as *const () as usize as u64);
        asm.emit_call_rax();
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_load_field_typed(asm: &mut Asm, field: &str) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (map bits)
        let data_off = asm.emit_cstr(field);
        let at = asm.emit_mov_imm64_placeholder(&[0x48, 0xBE]); // mov rsi, imm64
        asm.data_patches.push((at, data_off));
        asm.emit(&[0x4C, 0x89, 0xFA]); // mov rdx, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_map_get_str_typed as *const () as usize as u64);
        asm.emit_call_rax();
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_map_get_slot(asm: &mut Asm, slot: usize) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        emit_mask_payload_rax(asm);
        // mov rdx, [rax + MAP_SLOTS_PTR_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x90]);
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        // mov rcx, imm64 (slot index)
        asm.emit(&[0x48, 0xB9]);
        asm.emit_u64(slot as u64);
        // imul rcx, rcx, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xC9]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rdx, rcx
        asm.emit(&[0x48, 0x01, 0xCA]);
        // mov rax, [rdx + MAP_SLOT_VALUE_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x82]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_map_get_slot_nover_guard(
        asm: &mut Asm,
        map_idx: usize,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
        slot_idx: usize,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();
        emit_store_deopt_ip(asm, deopt_ip);

        // guard map has not resized/rehashed
        let map_disp = (map_idx as i32) * 8;
        asm.emit(&[0x4D, 0x8B, 0x9D]); // mov r11, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        asm.emit(&[0x48, 0xB8]); // mov rax, PAYLOAD_MASK
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x49, 0x21, 0xC3]); // and r11, rax

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_cap
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_slots
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm); // drop map bits
                          // mov rcx, slot_idx
        asm.emit(&[0x48, 0xB9]);
        asm.emit_u64(slot_idx as u64);
        // imul rcx, rcx, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xC9]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rax, rcx
        asm.emit(&[0x48, 0x01, 0xC8]);
        // mov rax, [rax + MAP_SLOT_VALUE_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x80]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        deopt_patches
    }

    fn emit_map_get_slot_ptr(asm: &mut Asm, value_ptr: u64) {
        emit_dec_sp(asm);
        // mov rax, imm64 (value ptr)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(value_ptr);
        // mov rax, [rax]
        asm.emit(&[0x48, 0x8B, 0x00]);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_map_get_slot_ptr_nover(
        asm: &mut Asm,
        map_idx: usize,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
        value_ptr: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        // guard map has not resized/rehashed
        let map_disp = (map_idx as i32) * 8;
        asm.emit(&[0x4D, 0x8B, 0x9D]); // mov r11, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        asm.emit(&[0x48, 0xB8]); // mov rax, PAYLOAD_MASK
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x49, 0x21, 0xC3]); // and r11, rax

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_cap
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_slots
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm); // drop map
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr
        asm.emit_u64(value_ptr);
        asm.emit(&[0x48, 0x8B, 0x00]); // mov rax, [rax]
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        deopt_patches
    }

    fn emit_map_get_text_key_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // mov rdi, [r13 + key_disp] (key bits)
        asm.emit(&[0x49, 0x8B, 0xBD]);
        asm.emit_u32(key_disp as u32);
        // mov rsi, r15 (runtime)
        asm.emit(&[0x4C, 0x89, 0xFE]);
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_text_meta as *const () as usize as u64);
        asm.emit_call_rax();
        // test rax, rax
        asm.emit(&[0x48, 0x85, 0xC0]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt

        // load key ptr/len/hash
        // mov r12, [rax + TEXT_META_PTR_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0xA0]);
        asm.emit_u32(TEXT_META_PTR_OFFSET as u32);
        // mov rsi, [rax + TEXT_META_LEN_OFFSET]
        asm.emit(&[0x48, 0x8B, 0xB0]);
        asm.emit_u32(TEXT_META_LEN_OFFSET as u32);
        // mov r10, [rax + TEXT_META_HASH_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x90]);
        asm.emit_u32(TEXT_META_HASH_OFFSET as u32);

        // map ptr in r11
        let map_disp = (map_idx as i32) * 8;
        // mov r11, [r13 + map_disp]
        asm.emit(&[0x4D, 0x8B, 0x9D]);
        asm.emit_u32(map_disp as u32);
        // rax = PAYLOAD_MASK
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(vb::PAYLOAD_MASK);
        // and r11, rax
        asm.emit(&[0x49, 0x21, 0xC3]);

        // load cap
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        // test rax, rax
        asm.emit(&[0x48, 0x85, 0xC0]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // guard cap matches expected
        asm.emit(&[0x48, 0xBA]); // mov rdx, imm64
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt
                                                            // r9 = cap - 1
        asm.emit(&[0x49, 0x89, 0xC1]); // mov r9, rax
        asm.emit(&[0x49, 0xFF, 0xC9]); // dec r9

        // rax = slots_ptr
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        // guard slots_ptr matches expected
        asm.emit(&[0x48, 0xBA]); // mov rdx, imm64
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // idx in r8 = hash & mask
        asm.emit(&[0x4D, 0x89, 0xD0]); // mov r8, r10
        asm.emit(&[0x4D, 0x21, 0xC8]); // and r8, r9

        let loop_start = asm.pos();
        // rdi = r8
        asm.emit(&[0x4C, 0x89, 0xC7]); // mov rdi, r8
                                       // imul rdi, rdi, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xFF]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rdi, rax
        asm.emit(&[0x48, 0x01, 0xC7]);
        // movzx r11d, byte ptr [rdi + USED_OFFSET]
        asm.emit(&[0x44, 0x0F, 0xB6, 0x9F]);
        asm.emit_u32(MAP_SLOT_USED_OFFSET as u32);
        // test r11d, r11d
        asm.emit(&[0x45, 0x85, 0xDB]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // mov r11, [rdi + HASH_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_HASH_OFFSET as u32);
        // cmp r11, r10
        asm.emit(&[0x4D, 0x39, 0xD3]);
        let jne_next = asm.emit_jcc_placeholder(0x85);
        // mov r11, [rdi + KEY_LEN_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_KEY_LEN_OFFSET as u32);
        // cmp r11, rsi
        asm.emit(&[0x4C, 0x39, 0xDE]);
        let jne_next_len = asm.emit_jcc_placeholder(0x85);

        // load slot key ptr into rdx
        asm.emit(&[0x48, 0x8B, 0x97]);
        asm.emit_u32(MAP_SLOT_KEY_PTR_OFFSET as u32);
        // cmp rdx, r12 (fast-path same text buffer)
        asm.emit(&[0x4C, 0x39, 0xE2]);
        let je_found_ptr = asm.emit_jcc_placeholder(0x84); // JE -> found
                                                           // rcx = key_len
        asm.emit(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
                                       // test rcx, rcx
        asm.emit(&[0x48, 0x85, 0xC9]);
        let je_found = asm.emit_jcc_placeholder(0x84); // JE -> found (len == 0)
                                                       // r11 = key_ptr (lookup)
        asm.emit(&[0x4D, 0x89, 0xE3]);
        let cmp_loop = asm.pos();
        // mov al, [rdx]
        asm.emit(&[0x8A, 0x02]);
        // cmp al, [r11]
        asm.emit(&[0x41, 0x3A, 0x03]);
        let jne_next_cmp = asm.emit_jcc_placeholder(0x85);
        // inc rdx
        asm.emit(&[0x48, 0xFF, 0xC2]);
        // inc r11
        asm.emit(&[0x49, 0xFF, 0xC3]);
        // dec rcx
        asm.emit(&[0x48, 0xFF, 0xC9]);
        let jne_cmp = asm.emit_jcc_placeholder(0x85);
        let jmp_found = asm.emit_jmp_placeholder();

        let next_offset = asm.pos();
        // inc r8
        asm.emit(&[0x49, 0xFF, 0xC0]);
        // and r8, r9
        asm.emit(&[0x4D, 0x21, 0xC8]);
        let loop_jmp = asm.emit_jmp_placeholder();

        let found_offset = asm.pos();
        // mov rax, [rdi + VALUE_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x87]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);
        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        asm.patch_rel32(jne_next, next_offset);
        asm.patch_rel32(jne_next_len, next_offset);
        asm.patch_rel32(jne_next_cmp, next_offset);
        asm.patch_rel32(jne_cmp, cmp_loop);
        asm.patch_rel32(jmp_found, found_offset);
        asm.patch_rel32(je_found_ptr, found_offset);
        asm.patch_rel32(je_found, found_offset);
        asm.patch_rel32(loop_jmp, loop_start);

        deopt_patches
    }

    fn emit_map_set_slot_ptr_nover(asm: &mut Asm, map_idx: usize, value_ptr: u64) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop idx bits
        emit_dec_sp(asm); // drop map bits

        // store value
        asm.emit(&[0x48, 0xB8]); // mov rax, imm64 (value ptr)
        asm.emit_u64(value_ptr);
        asm.emit(&[0x48, 0x89, 0x10]); // mov [rax], rdx

        let map_disp = (map_idx as i32) * 8;
        // mov rax, [r13 + map_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(map_disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_map_set_slot_ptr_nover_guard(
        asm: &mut Asm,
        map_idx: usize,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
        value_ptr: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        // guard map has not resized/rehashed
        let map_disp = (map_idx as i32) * 8;
        asm.emit(&[0x4D, 0x8B, 0x9D]); // mov r11, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        asm.emit(&[0x48, 0xB8]); // mov rax, PAYLOAD_MASK
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x49, 0x21, 0xC3]); // and r11, rax

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_cap
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_slots
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop key bits
        emit_dec_sp(asm); // drop map bits

        // store value
        asm.emit(&[0x48, 0xB8]); // mov rax, value ptr
        asm.emit_u64(value_ptr);
        asm.emit(&[0x48, 0x89, 0x10]); // mov [rax], rdx

        // push map bits back
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        deopt_patches
    }

    fn emit_map_set_slot_nover(asm: &mut Asm, map_idx: usize, slot_idx: usize) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop idx bits
        emit_dec_sp(asm); // drop map bits

        let map_disp = (map_idx as i32) * 8;
        // mov rsi, [r13 + map_disp]
        asm.emit(&[0x49, 0x8B, 0xB5]);
        asm.emit_u32(map_disp as u32);

        // rax = map bits, mask payload
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_mask_payload_rax(asm);

        // mov r8, [rax + MAP_SLOTS_PTR_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        // mov rcx, imm64 (slot index)
        asm.emit(&[0x48, 0xB9]);
        asm.emit_u64(slot_idx as u64);
        // imul rcx, rcx, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xC9]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add r8, rcx
        asm.emit(&[0x49, 0x01, 0xC8]);
        // mov [r8 + MAP_SLOT_VALUE_OFFSET], rdx
        asm.emit(&[0x49, 0x89, 0x90]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);

        // push map bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_map_set_slot_nover_guard(
        asm: &mut Asm,
        map_idx: usize,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
        slot_idx: usize,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();
        emit_store_deopt_ip(asm, deopt_ip);

        // guard map has not resized/rehashed
        let map_disp = (map_idx as i32) * 8;
        asm.emit(&[0x4D, 0x8B, 0x9D]); // mov r11, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        asm.emit(&[0x48, 0xB8]); // mov rax, PAYLOAD_MASK
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x49, 0x21, 0xC3]); // and r11, rax

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_cap
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_slots
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop key bits
        emit_dec_sp(asm); // drop map bits

        // mov rcx, slot_idx
        asm.emit(&[0x48, 0xB9]);
        asm.emit_u64(slot_idx as u64);
        // imul rcx, rcx, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xC9]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rax, rcx
        asm.emit(&[0x48, 0x01, 0xC8]);
        // mov [rax + MAP_SLOT_VALUE_OFFSET], rdx
        asm.emit(&[0x48, 0x89, 0x90]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);

        // push map bits back
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        deopt_patches
    }

    fn emit_map_set_small_key_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let map_disp = (map_idx as i32) * 8;
        // mov rsi, [r13 + map_disp]
        asm.emit(&[0x49, 0x8B, 0xB5]);
        asm.emit_u32(map_disp as u32);

        let key_disp = (key_idx as i32) * 8;
        // mov rcx, [r13 + key_disp]
        asm.emit(&[0x49, 0x8B, 0x8D]);
        asm.emit_u32(key_disp as u32);

        // guard: key is tagged small text
        // rax = rcx
        asm.emit(&[0x48, 0x89, 0xC8]); // mov rax, rcx
                                       // r11 = QNAN_MASK
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(vb::QNAN_MASK);
        // and rax, r11
        asm.emit(&[0x4C, 0x21, 0xD8]);
        // cmp rax, r11
        asm.emit(&[0x4C, 0x39, 0xD8]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // rax = rcx
        asm.emit(&[0x48, 0x89, 0xC8]);
        // r11 = TAG_MASK
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(vb::TAG_MASK);
        // and rax, r11
        asm.emit(&[0x4C, 0x21, 0xD8]);
        // r11 = TAG_TEXT_SMALL << TAG_SHIFT
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64((vb::TAG_TEXT_SMALL & 0x7) << vb::TAG_SHIFT);
        // cmp rax, r11
        asm.emit(&[0x4C, 0x39, 0xD8]);
        let tag_small_ok = asm.emit_jcc_placeholder(0x84); // JE
                                                           // r11 = TAG_TEXT_SMALL6 << TAG_SHIFT
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64((vb::TAG_TEXT_SMALL6 & 0x7) << vb::TAG_SHIFT);
        // cmp rax, r11
        asm.emit(&[0x4C, 0x39, 0xD8]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt
        let tag_ok = asm.pos();
        asm.patch_rel32(tag_small_ok, tag_ok);

        // map ptr in r11
        asm.emit(&[0x49, 0x89, 0xF3]); // mov r11, rsi
                                       // rax = PAYLOAD_MASK
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(vb::PAYLOAD_MASK);
        // and r11, rax
        asm.emit(&[0x49, 0x21, 0xC3]);

        // load cap
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        // test rax, rax
        asm.emit(&[0x48, 0x85, 0xC0]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt

        // guard cap matches expected (no resize)
        asm.emit(&[0x49, 0xBA]); // mov r10, imm64
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x4C, 0x39, 0xD0]); // cmp rax, r10
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // r9 = cap - 1
        asm.emit(&[0x49, 0x89, 0xC1]); // mov r9, rax
        asm.emit(&[0x49, 0xFF, 0xC9]); // dec r9

        // rax = slots_ptr
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        // guard slots_ptr matches expected (no resize)
        asm.emit(&[0x49, 0xBA]); // mov r10, imm64
        asm.emit_u64(expected_slots);
        asm.emit(&[0x4C, 0x39, 0xD0]); // cmp rax, r10
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // hash = hash_u64(key_bits) into r10
        // mov r10, rcx
        asm.emit(&[0x49, 0x89, 0xCA]);
        // mov r11, r10
        asm.emit(&[0x4D, 0x89, 0xD3]);
        // shr r11, 33
        asm.emit(&[0x49, 0xC1, 0xEB, 0x21]);
        // xor r10, r11
        asm.emit(&[0x4D, 0x31, 0xDA]);
        // r11 = const1
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(0xff51afd7ed558ccd);
        // imul r10, r11
        asm.emit(&[0x4D, 0x0F, 0xAF, 0xD3]);
        // mov r11, r10
        asm.emit(&[0x4D, 0x89, 0xD3]);
        // shr r11, 33
        asm.emit(&[0x49, 0xC1, 0xEB, 0x21]);
        // xor r10, r11
        asm.emit(&[0x4D, 0x31, 0xDA]);
        // r11 = const2
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(0xc4ceb9fe1a85ec53);
        // imul r10, r11
        asm.emit(&[0x4D, 0x0F, 0xAF, 0xD3]);
        // mov r11, r10
        asm.emit(&[0x4D, 0x89, 0xD3]);
        // shr r11, 33
        asm.emit(&[0x49, 0xC1, 0xEB, 0x21]);
        // xor r10, r11
        asm.emit(&[0x4D, 0x31, 0xDA]);

        // idx in r8 = hash & mask
        asm.emit(&[0x4D, 0x89, 0xD0]); // mov r8, r10
        asm.emit(&[0x4D, 0x21, 0xC8]); // and r8, r9

        let loop_start = asm.pos();
        // rdi = r8
        asm.emit(&[0x4C, 0x89, 0xC7]); // mov rdi, r8
                                       // imul rdi, rdi, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xFF]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rdi, rax
        asm.emit(&[0x48, 0x01, 0xC7]);
        // movzx r11d, byte ptr [rdi + USED_OFFSET]
        asm.emit(&[0x44, 0x0F, 0xB6, 0x9F]);
        asm.emit_u32(MAP_SLOT_USED_OFFSET as u32);
        // test r11d, r11d
        asm.emit(&[0x45, 0x85, 0xDB]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // mov r11, [rdi + HASH_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_HASH_OFFSET as u32);
        // cmp r11, r10
        asm.emit(&[0x4D, 0x39, 0xD3]);
        let jne_next = asm.emit_jcc_placeholder(0x85);
        // mov r11, [rdi + KEY_BITS_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_KEY_BITS_OFFSET as u32);
        // cmp r11, rcx
        asm.emit(&[0x49, 0x39, 0xCB]);
        let je_found = asm.emit_jcc_placeholder(0x84);

        let next_offset = asm.pos();
        // inc r8
        asm.emit(&[0x49, 0xFF, 0xC0]);
        // and r8, r9
        asm.emit(&[0x4D, 0x21, 0xC8]);
        let loop_jmp = asm.emit_jmp_placeholder();

        let found_offset = asm.pos();
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop key bits
        emit_dec_sp(asm); // drop map bits
                          // mov [rdi + VALUE_OFFSET], rdx
        asm.emit(&[0x48, 0x89, 0x97]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);

        // push map bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        asm.patch_rel32(jne_next, next_offset);
        asm.patch_rel32(je_found, found_offset);
        asm.patch_rel32(loop_jmp, loop_start);

        deopt_patches
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_map_get_text_key_const_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
        key_ptr: u64,
        key_len: usize,
        key_hash: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // mov rax, [r13 + key_disp] (key bits)
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(key_disp as u32);
        // mov r11, imm64 (expected key bits)
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(expected_key_bits);
        // cmp rax, r11
        asm.emit(&[0x4C, 0x39, 0xD8]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // load key ptr/len/hash constants
        asm.emit(&[0x49, 0xBC]); // mov r12, imm64
        asm.emit_u64(key_ptr);
        asm.emit(&[0x48, 0xBE]); // mov rsi, imm64
        asm.emit_u64(key_len as u64);
        asm.emit(&[0x49, 0xBA]); // mov r10, imm64
        asm.emit_u64(key_hash);

        // map ptr in r11
        let map_disp = (map_idx as i32) * 8;
        // mov r11, [r13 + map_disp]
        asm.emit(&[0x4D, 0x8B, 0x9D]);
        asm.emit_u32(map_disp as u32);
        // rax = PAYLOAD_MASK
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(vb::PAYLOAD_MASK);
        // and r11, rax
        asm.emit(&[0x49, 0x21, 0xC3]);

        // load cap
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        // test rax, rax
        asm.emit(&[0x48, 0x85, 0xC0]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // guard cap matches expected
        asm.emit(&[0x48, 0xBA]); // mov rdx, imm64
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt
                                                            // r9 = cap - 1
        asm.emit(&[0x49, 0x89, 0xC1]); // mov r9, rax
        asm.emit(&[0x49, 0xFF, 0xC9]); // dec r9

        // rax = slots_ptr
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        // guard slots_ptr matches expected
        asm.emit(&[0x48, 0xBA]); // mov rdx, imm64
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // idx in r8 = hash & mask
        asm.emit(&[0x4D, 0x89, 0xD0]); // mov r8, r10
        asm.emit(&[0x4D, 0x21, 0xC8]); // and r8, r9

        let loop_start = asm.pos();
        // rdi = r8
        asm.emit(&[0x4C, 0x89, 0xC7]); // mov rdi, r8
                                       // imul rdi, rdi, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xFF]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rdi, rax
        asm.emit(&[0x48, 0x01, 0xC7]);
        // movzx r11d, byte ptr [rdi + USED_OFFSET]
        asm.emit(&[0x44, 0x0F, 0xB6, 0x9F]);
        asm.emit_u32(MAP_SLOT_USED_OFFSET as u32);
        // test r11d, r11d
        asm.emit(&[0x45, 0x85, 0xDB]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // mov r11, [rdi + HASH_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_HASH_OFFSET as u32);
        // cmp r11, r10
        asm.emit(&[0x4D, 0x39, 0xD3]);
        let jne_next = asm.emit_jcc_placeholder(0x85);
        // mov r11, [rdi + KEY_LEN_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_KEY_LEN_OFFSET as u32);
        // cmp r11, rsi
        asm.emit(&[0x4C, 0x39, 0xDE]);
        let jne_next_len = asm.emit_jcc_placeholder(0x85);

        // load slot key ptr into rdx
        asm.emit(&[0x48, 0x8B, 0x97]);
        asm.emit_u32(MAP_SLOT_KEY_PTR_OFFSET as u32);
        // cmp rdx, r12 (fast-path same text buffer)
        asm.emit(&[0x4C, 0x39, 0xE2]);
        let je_found_ptr = asm.emit_jcc_placeholder(0x84); // JE -> found
                                                           // rcx = key_len
        asm.emit(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
                                       // test rcx, rcx
        asm.emit(&[0x48, 0x85, 0xC9]);
        let je_found = asm.emit_jcc_placeholder(0x84); // JE -> found (len == 0)
                                                       // r11 = key_ptr (lookup)
        asm.emit(&[0x4D, 0x89, 0xE3]);
        let cmp_loop = asm.pos();
        // mov al, [rdx]
        asm.emit(&[0x8A, 0x02]);
        // cmp al, [r11]
        asm.emit(&[0x41, 0x3A, 0x03]);
        let jne_next_cmp = asm.emit_jcc_placeholder(0x85);
        // inc rdx
        asm.emit(&[0x48, 0xFF, 0xC2]);
        // inc r11
        asm.emit(&[0x49, 0xFF, 0xC3]);
        // dec rcx
        asm.emit(&[0x48, 0xFF, 0xC9]);
        let jne_cmp = asm.emit_jcc_placeholder(0x85);
        let jmp_found = asm.emit_jmp_placeholder();

        let next_offset = asm.pos();
        // inc r8
        asm.emit(&[0x49, 0xFF, 0xC0]);
        // and r8, r9
        asm.emit(&[0x4D, 0x21, 0xC8]);
        let loop_jmp = asm.emit_jmp_placeholder();

        let found_offset = asm.pos();
        // mov rax, [rdi + VALUE_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x87]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);
        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        asm.patch_rel32(jne_next, next_offset);
        asm.patch_rel32(jne_next_len, next_offset);
        asm.patch_rel32(jne_next_cmp, next_offset);
        asm.patch_rel32(jne_cmp, cmp_loop);
        asm.patch_rel32(jmp_found, found_offset);
        asm.patch_rel32(je_found_ptr, found_offset);
        asm.patch_rel32(je_found, found_offset);
        asm.patch_rel32(loop_jmp, loop_start);

        deopt_patches
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_map_get_text_key_const_slot_ptr_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
        value_ptr: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // guard key bits are unchanged
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + key_disp]
        asm.emit_u32(key_disp as u32);
        asm.emit(&[0x49, 0xBB]); // mov r11, imm64
        asm.emit_u64(expected_key_bits);
        asm.emit(&[0x4C, 0x39, 0xD8]); // cmp rax, r11
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // guard map has not resized/rehashed
        let map_disp = (map_idx as i32) * 8;
        asm.emit(&[0x4D, 0x8B, 0x9D]); // mov r11, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        asm.emit(&[0x48, 0xB8]); // mov rax, PAYLOAD_MASK
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x49, 0x21, 0xC3]); // and r11, rax

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_cap
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_slots
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr
        asm.emit_u64(value_ptr);
        asm.emit(&[0x48, 0x8B, 0x00]); // mov rax, [rax]
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        deopt_patches
    }

    fn emit_map_get_text_key_const_slot_ptr_stable_nover(
        asm: &mut Asm,
        _map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        deopt_ip: usize,
        value_ptr: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // Guard that key local still matches the specialized const-key snapshot.
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + key_disp]
        asm.emit_u32(key_disp as u32);
        asm.emit(&[0x49, 0xBB]); // mov r11, imm64
        asm.emit_u64(expected_key_bits);
        asm.emit(&[0x4C, 0x39, 0xD8]); // cmp rax, r11
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr
        asm.emit_u64(value_ptr);
        asm.emit(&[0x48, 0x8B, 0x00]); // mov rax, [rax]
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        deopt_patches
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_map_get_text_key_const_slot_ptr_stable_add_local_nover(
        asm: &mut Asm,
        _map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        deopt_ip: usize,
        value_ptr: u64,
        acc_local: usize,
        promoted: &PromotedLocals,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // Guard that key local still matches the specialized const-key snapshot.
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + key_disp]
        asm.emit_u32(key_disp as u32);
        asm.emit(&[0x49, 0xBB]); // mov r11, imm64
        asm.emit_u64(expected_key_bits);
        asm.emit(&[0x4C, 0x39, 0xD8]); // cmp rax, r11
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // Preserve interpreter/deopt semantics: consume map/key operands from stack.
        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map

        // Load map value bits from cached slot pointer.
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr
        asm.emit_u64(value_ptr);
        asm.emit(&[0x48, 0x8B, 0x00]); // mov rax, [rax]

        // Convert bits -> scalar fp register.
        if asm.avx_upper_dirty {
            emit_vmovq_xmm_from_rax(asm, 1);
        } else {
            asm.emit(&[0x66, 0x48, 0x0F, 0x6E, 0xC8]); // movq xmm1, rax
        }

        // Accumulate directly into local accumulator.
        if let Some(reg) = promoted.xmm_for(acc_local) {
            if asm.avx_upper_dirty {
                emit_vaddsd_acc_from_xmm(asm, reg, 1);
            } else {
                emit_addsd_xmm_xmm(asm, reg, 1);
            }
        } else {
            let disp = (acc_local as i32) * 8;
            // movsd xmm0, [r13 + disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(disp as u32);
            // addsd xmm0, xmm1
            asm.emit(&[0xF2, 0x0F, 0x58, 0xC1]);
            // movsd [r13 + disp], xmm0
            asm.emit(&[0xF2, 0x41, 0x0F, 0x11, 0x85]);
            asm.emit_u32(disp as u32);
        }

        deopt_patches
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_map_get_text_key_const_slot_ptr_pic2_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        deopt_ip: usize,
        expected_cap1: usize,
        expected_slots1: u64,
        value_ptr1: u64,
        expected_cap2: usize,
        expected_slots2: u64,
        value_ptr2: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // guard key bits are unchanged
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + key_disp]
        asm.emit_u32(key_disp as u32);
        asm.emit(&[0x49, 0xBB]); // mov r11, imm64
        asm.emit_u64(expected_key_bits);
        asm.emit(&[0x4C, 0x39, 0xD8]); // cmp rax, r11
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // map ptr in r11 (payload)
        let map_disp = (map_idx as i32) * 8;
        asm.emit(&[0x4D, 0x8B, 0x9D]); // mov r11, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        asm.emit(&[0x48, 0xB8]); // mov rax, PAYLOAD_MASK
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x49, 0x21, 0xC3]); // and r11, rax

        // load cap
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt

        // try entry 1
        asm.emit(&[0x48, 0xBA]); // mov rdx, cap1
        asm.emit_u64(expected_cap1 as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        let cap_dispatch = asm.emit_invertible_guard_after_cmp(0x84); // JE -> entry1 (patchable)
        let jne_cap1 = if cap_dispatch.is_none() {
            Some(asm.emit_jcc_placeholder(0x85)) // JNE -> try entry2
        } else {
            None
        };
        let entry1_offset = asm.pos();

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, slots1
        asm.emit_u64(expected_slots1);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        let jne_slots1 = asm.emit_jcc_placeholder(0x85); // JNE -> try entry2

        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr1
        asm.emit_u64(value_ptr1);
        asm.emit(&[0x48, 0x8B, 0x00]); // mov rax, [rax]
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
        let jmp_done = asm.emit_jmp_placeholder();

        let entry2_offset = asm.pos();
        if let Some(site) = cap_dispatch {
            asm.set_invertible_guard_targets(site.rel32_at, entry1_offset, entry2_offset);
        } else if let Some(jne_cap1) = jne_cap1 {
            asm.patch_rel32(jne_cap1, entry2_offset);
        }
        asm.patch_rel32(jne_slots1, entry2_offset);

        // reload cap and try entry 2
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, cap2
        asm.emit_u64(expected_cap2 as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, slots2
        asm.emit_u64(expected_slots2);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr2
        asm.emit_u64(value_ptr2);
        asm.emit(&[0x48, 0x8B, 0x00]); // mov rax, [rax]
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        let done_offset = asm.pos();
        asm.patch_rel32(jmp_done, done_offset);

        deopt_patches
    }

    fn emit_map_set_text_key_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // mov rdi, [r13 + key_disp] (key bits)
        asm.emit(&[0x49, 0x8B, 0xBD]);
        asm.emit_u32(key_disp as u32);
        // mov rsi, r15 (runtime)
        asm.emit(&[0x4C, 0x89, 0xFE]);
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_text_meta as *const () as usize as u64);
        asm.emit_call_rax();
        // test rax, rax
        asm.emit(&[0x48, 0x85, 0xC0]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt

        // load key ptr/len/hash
        // mov r12, [rax + TEXT_META_PTR_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0xA0]);
        asm.emit_u32(TEXT_META_PTR_OFFSET as u32);
        // mov rsi, [rax + TEXT_META_LEN_OFFSET]
        asm.emit(&[0x48, 0x8B, 0xB0]);
        asm.emit_u32(TEXT_META_LEN_OFFSET as u32);
        // mov r10, [rax + TEXT_META_HASH_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x90]);
        asm.emit_u32(TEXT_META_HASH_OFFSET as u32);

        // map ptr in r11
        let map_disp = (map_idx as i32) * 8;
        // mov r11, [r13 + map_disp]
        asm.emit(&[0x4D, 0x8B, 0x9D]);
        asm.emit_u32(map_disp as u32);
        // rax = PAYLOAD_MASK
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(vb::PAYLOAD_MASK);
        // and r11, rax
        asm.emit(&[0x49, 0x21, 0xC3]);

        // load cap
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        // test rax, rax
        asm.emit(&[0x48, 0x85, 0xC0]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // guard cap matches expected
        asm.emit(&[0x48, 0xBA]); // mov rdx, imm64
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt
                                                            // r9 = cap - 1
        asm.emit(&[0x49, 0x89, 0xC1]); // mov r9, rax
        asm.emit(&[0x49, 0xFF, 0xC9]); // dec r9

        // rax = slots_ptr
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        // guard slots_ptr matches expected
        asm.emit(&[0x48, 0xBA]); // mov rdx, imm64
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // idx in r8 = hash & mask
        asm.emit(&[0x4D, 0x89, 0xD0]); // mov r8, r10
        asm.emit(&[0x4D, 0x21, 0xC8]); // and r8, r9

        let loop_start = asm.pos();
        // rdi = r8
        asm.emit(&[0x4C, 0x89, 0xC7]); // mov rdi, r8
                                       // imul rdi, rdi, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xFF]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rdi, rax
        asm.emit(&[0x48, 0x01, 0xC7]);
        // movzx r11d, byte ptr [rdi + USED_OFFSET]
        asm.emit(&[0x44, 0x0F, 0xB6, 0x9F]);
        asm.emit_u32(MAP_SLOT_USED_OFFSET as u32);
        // test r11d, r11d
        asm.emit(&[0x45, 0x85, 0xDB]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // mov r11, [rdi + HASH_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_HASH_OFFSET as u32);
        // cmp r11, r10
        asm.emit(&[0x4D, 0x39, 0xD3]);
        let jne_next = asm.emit_jcc_placeholder(0x85);
        // mov r11, [rdi + KEY_LEN_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_KEY_LEN_OFFSET as u32);
        // cmp r11, rsi
        asm.emit(&[0x4C, 0x39, 0xDE]);
        let jne_next_len = asm.emit_jcc_placeholder(0x85);

        // load slot key ptr into rdx
        asm.emit(&[0x48, 0x8B, 0x97]);
        asm.emit_u32(MAP_SLOT_KEY_PTR_OFFSET as u32);
        // cmp rdx, r12 (fast-path same text buffer)
        asm.emit(&[0x4C, 0x39, 0xE2]);
        let je_found_ptr = asm.emit_jcc_placeholder(0x84); // JE -> found
                                                           // rcx = key_len
        asm.emit(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
                                       // test rcx, rcx
        asm.emit(&[0x48, 0x85, 0xC9]);
        let je_found = asm.emit_jcc_placeholder(0x84); // JE -> found (len == 0)
                                                       // r11 = key_ptr (lookup)
        asm.emit(&[0x4D, 0x89, 0xE3]);
        let cmp_loop = asm.pos();
        // mov al, [rdx]
        asm.emit(&[0x8A, 0x02]);
        // cmp al, [r11]
        asm.emit(&[0x41, 0x3A, 0x03]);
        let jne_next_cmp = asm.emit_jcc_placeholder(0x85);
        // inc rdx
        asm.emit(&[0x48, 0xFF, 0xC2]);
        // inc r11
        asm.emit(&[0x49, 0xFF, 0xC3]);
        // dec rcx
        asm.emit(&[0x48, 0xFF, 0xC9]);
        let jne_cmp = asm.emit_jcc_placeholder(0x85);
        let jmp_found = asm.emit_jmp_placeholder();

        let next_offset = asm.pos();
        // inc r8
        asm.emit(&[0x49, 0xFF, 0xC0]);
        // and r8, r9
        asm.emit(&[0x4D, 0x21, 0xC8]);
        let loop_jmp = asm.emit_jmp_placeholder();

        let found_offset = asm.pos();
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop key bits
        emit_dec_sp(asm); // drop map bits
                          // mov [rdi + VALUE_OFFSET], rdx
        asm.emit(&[0x48, 0x89, 0x97]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);

        // push map bits back
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        asm.patch_rel32(jne_next, next_offset);
        asm.patch_rel32(jne_next_len, next_offset);
        asm.patch_rel32(jne_next_cmp, next_offset);
        asm.patch_rel32(jne_cmp, cmp_loop);
        asm.patch_rel32(jmp_found, found_offset);
        asm.patch_rel32(je_found_ptr, found_offset);
        asm.patch_rel32(je_found, found_offset);
        asm.patch_rel32(loop_jmp, loop_start);

        deopt_patches
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_map_set_text_key_const_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
        key_ptr: u64,
        key_len: usize,
        key_hash: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // mov rax, [r13 + key_disp] (key bits)
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(key_disp as u32);
        // mov r11, imm64 (expected key bits)
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(expected_key_bits);
        // cmp rax, r11
        asm.emit(&[0x4C, 0x39, 0xD8]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // load key ptr/len/hash constants
        asm.emit(&[0x49, 0xBC]); // mov r12, imm64
        asm.emit_u64(key_ptr);
        asm.emit(&[0x48, 0xBE]); // mov rsi, imm64
        asm.emit_u64(key_len as u64);
        asm.emit(&[0x49, 0xBA]); // mov r10, imm64
        asm.emit_u64(key_hash);

        // map ptr in r11
        let map_disp = (map_idx as i32) * 8;
        // mov r11, [r13 + map_disp]
        asm.emit(&[0x4D, 0x8B, 0x9D]);
        asm.emit_u32(map_disp as u32);
        // rax = PAYLOAD_MASK
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(vb::PAYLOAD_MASK);
        // and r11, rax
        asm.emit(&[0x49, 0x21, 0xC3]);

        // load cap
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        // test rax, rax
        asm.emit(&[0x48, 0x85, 0xC0]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // guard cap matches expected
        asm.emit(&[0x48, 0xBA]); // mov rdx, imm64
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt
                                                            // r9 = cap - 1
        asm.emit(&[0x49, 0x89, 0xC1]); // mov r9, rax
        asm.emit(&[0x49, 0xFF, 0xC9]); // dec r9

        // rax = slots_ptr
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        // guard slots_ptr matches expected
        asm.emit(&[0x48, 0xBA]); // mov rdx, imm64
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // idx in r8 = hash & mask
        asm.emit(&[0x4D, 0x89, 0xD0]); // mov r8, r10
        asm.emit(&[0x4D, 0x21, 0xC8]); // and r8, r9

        let loop_start = asm.pos();
        // rdi = r8
        asm.emit(&[0x4C, 0x89, 0xC7]); // mov rdi, r8
                                       // imul rdi, rdi, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xFF]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rdi, rax
        asm.emit(&[0x48, 0x01, 0xC7]);
        // movzx r11d, byte ptr [rdi + USED_OFFSET]
        asm.emit(&[0x44, 0x0F, 0xB6, 0x9F]);
        asm.emit_u32(MAP_SLOT_USED_OFFSET as u32);
        // test r11d, r11d
        asm.emit(&[0x45, 0x85, 0xDB]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // mov r11, [rdi + HASH_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_HASH_OFFSET as u32);
        // cmp r11, r10
        asm.emit(&[0x4D, 0x39, 0xD3]);
        let jne_next = asm.emit_jcc_placeholder(0x85);
        // mov r11, [rdi + KEY_LEN_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_KEY_LEN_OFFSET as u32);
        // cmp r11, rsi
        asm.emit(&[0x4C, 0x39, 0xDE]);
        let jne_next_len = asm.emit_jcc_placeholder(0x85);

        // load slot key ptr into rdx
        asm.emit(&[0x48, 0x8B, 0x97]);
        asm.emit_u32(MAP_SLOT_KEY_PTR_OFFSET as u32);
        // cmp rdx, r12 (fast-path same text buffer)
        asm.emit(&[0x4C, 0x39, 0xE2]);
        let je_found_ptr = asm.emit_jcc_placeholder(0x84); // JE -> found
                                                           // rcx = key_len
        asm.emit(&[0x48, 0x89, 0xF1]); // mov rcx, rsi
                                       // test rcx, rcx
        asm.emit(&[0x48, 0x85, 0xC9]);
        let je_found = asm.emit_jcc_placeholder(0x84); // JE -> found (len == 0)
                                                       // r11 = key_ptr (lookup)
        asm.emit(&[0x4D, 0x89, 0xE3]);
        let cmp_loop = asm.pos();
        // mov al, [rdx]
        asm.emit(&[0x8A, 0x02]);
        // cmp al, [r11]
        asm.emit(&[0x41, 0x3A, 0x03]);
        let jne_next_cmp = asm.emit_jcc_placeholder(0x85);
        // inc rdx
        asm.emit(&[0x48, 0xFF, 0xC2]);
        // inc r11
        asm.emit(&[0x49, 0xFF, 0xC3]);
        // dec rcx
        asm.emit(&[0x48, 0xFF, 0xC9]);
        let jne_cmp = asm.emit_jcc_placeholder(0x85);
        let jmp_found = asm.emit_jmp_placeholder();

        let next_offset = asm.pos();
        // inc r8
        asm.emit(&[0x49, 0xFF, 0xC0]);
        // and r8, r9
        asm.emit(&[0x4D, 0x21, 0xC8]);
        let loop_jmp = asm.emit_jmp_placeholder();

        let found_offset = asm.pos();
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop key bits
        emit_dec_sp(asm); // drop map bits
                          // mov [rdi + VALUE_OFFSET], rdx
        asm.emit(&[0x48, 0x89, 0x97]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);

        // push map bits back
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        asm.patch_rel32(jne_next, next_offset);
        asm.patch_rel32(jne_next_len, next_offset);
        asm.patch_rel32(jne_next_cmp, next_offset);
        asm.patch_rel32(jne_cmp, cmp_loop);
        asm.patch_rel32(jmp_found, found_offset);
        asm.patch_rel32(je_found_ptr, found_offset);
        asm.patch_rel32(je_found, found_offset);
        asm.patch_rel32(loop_jmp, loop_start);

        deopt_patches
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_map_set_text_key_const_slot_ptr_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
        value_ptr: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // guard key bits are unchanged
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + key_disp]
        asm.emit_u32(key_disp as u32);
        asm.emit(&[0x49, 0xBB]); // mov r11, imm64
        asm.emit_u64(expected_key_bits);
        asm.emit(&[0x4C, 0x39, 0xD8]); // cmp rax, r11
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // guard map has not resized/rehashed
        let map_disp = (map_idx as i32) * 8;
        asm.emit(&[0x4D, 0x8B, 0x9D]); // mov r11, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        asm.emit(&[0x48, 0xB8]); // mov rax, PAYLOAD_MASK
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x49, 0x21, 0xC3]); // and r11, rax

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_cap
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, expected_slots
        asm.emit_u64(expected_slots);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr
        asm.emit_u64(value_ptr);
        asm.emit(&[0x48, 0x89, 0x10]); // mov [rax], rdx

        // push map bits back
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        deopt_patches
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_map_set_text_key_const_slot_ptr_pic2_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        expected_key_bits: u64,
        deopt_ip: usize,
        expected_cap1: usize,
        expected_slots1: u64,
        value_ptr1: u64,
        expected_cap2: usize,
        expected_slots2: u64,
        value_ptr2: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let key_disp = (key_idx as i32) * 8;
        // guard key bits are unchanged
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + key_disp]
        asm.emit_u32(key_disp as u32);
        asm.emit(&[0x49, 0xBB]); // mov r11, imm64
        asm.emit_u64(expected_key_bits);
        asm.emit(&[0x4C, 0x39, 0xD8]); // cmp rax, r11
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // map ptr in r11 (payload)
        let map_disp = (map_idx as i32) * 8;
        asm.emit(&[0x4D, 0x8B, 0x9D]); // mov r11, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        asm.emit(&[0x48, 0xB8]); // mov rax, PAYLOAD_MASK
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x49, 0x21, 0xC3]); // and r11, rax

        // load cap
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0x85, 0xC0]); // test rax, rax
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt

        // try entry 1
        asm.emit(&[0x48, 0xBA]); // mov rdx, cap1
        asm.emit_u64(expected_cap1 as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        let cap_dispatch = asm.emit_invertible_guard_after_cmp(0x84); // JE -> entry1 (patchable)
        let jne_cap1 = if cap_dispatch.is_none() {
            Some(asm.emit_jcc_placeholder(0x85)) // JNE -> try entry2
        } else {
            None
        };
        let entry1_offset = asm.pos();

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, slots1
        asm.emit_u64(expected_slots1);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        let jne_slots1 = asm.emit_jcc_placeholder(0x85); // JNE -> try entry2

        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr1
        asm.emit_u64(value_ptr1);
        asm.emit(&[0x48, 0x89, 0x10]); // mov [rax], rdx
                                       // push map bits back
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
        let jmp_done = asm.emit_jmp_placeholder();

        let entry2_offset = asm.pos();
        if let Some(site) = cap_dispatch {
            asm.set_invertible_guard_targets(site.rel32_at, entry1_offset, entry2_offset);
        } else if let Some(jne_cap1) = jne_cap1 {
            asm.patch_rel32(jne_cap1, entry2_offset);
        }
        asm.patch_rel32(jne_slots1, entry2_offset);

        // reload cap and try entry 2
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, cap2
        asm.emit_u64(expected_cap2 as u64);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        asm.emit(&[0x48, 0xBA]); // mov rdx, slots2
        asm.emit_u64(expected_slots2);
        asm.emit(&[0x48, 0x39, 0xD0]); // cmp rax, rdx
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        asm.emit(&[0x48, 0xB8]); // mov rax, value_ptr2
        asm.emit_u64(value_ptr2);
        asm.emit(&[0x48, 0x89, 0x10]); // mov [rax], rdx
                                       // push map bits back
        asm.emit(&[0x49, 0x8B, 0x85]); // mov rax, [r13 + map_disp]
        asm.emit_u32(map_disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        let done_offset = asm.pos();
        asm.patch_rel32(jmp_done, done_offset);

        deopt_patches
    }

    fn emit_map_get_small_key_nover(
        asm: &mut Asm,
        map_idx: usize,
        key_idx: usize,
        deopt_ip: usize,
        expected_cap: usize,
        expected_slots: u64,
    ) -> Vec<usize> {
        let mut deopt_patches: Vec<usize> = Vec::new();

        emit_store_deopt_ip(asm, deopt_ip);

        let map_disp = (map_idx as i32) * 8;
        // mov rsi, [r13 + map_disp]
        asm.emit(&[0x49, 0x8B, 0xB5]);
        asm.emit_u32(map_disp as u32);

        let key_disp = (key_idx as i32) * 8;
        // mov rcx, [r13 + key_disp]
        asm.emit(&[0x49, 0x8B, 0x8D]);
        asm.emit_u32(key_disp as u32);

        // guard: key is tagged small text
        // rax = rcx
        asm.emit(&[0x48, 0x89, 0xC8]); // mov rax, rcx
                                       // r11 = QNAN_MASK
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(vb::QNAN_MASK);
        // and rax, r11
        asm.emit(&[0x4C, 0x21, 0xD8]);
        // cmp rax, r11
        asm.emit(&[0x4C, 0x39, 0xD8]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // rax = rcx
        asm.emit(&[0x48, 0x89, 0xC8]);
        // r11 = TAG_MASK
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(vb::TAG_MASK);
        // and rax, r11
        asm.emit(&[0x4C, 0x21, 0xD8]);
        // r11 = TAG_TEXT_SMALL << TAG_SHIFT
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64((vb::TAG_TEXT_SMALL & 0x7) << vb::TAG_SHIFT);
        // cmp rax, r11
        asm.emit(&[0x4C, 0x39, 0xD8]);
        let tag_small_ok = asm.emit_jcc_placeholder(0x84); // JE
                                                           // r11 = TAG_TEXT_SMALL6 << TAG_SHIFT
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64((vb::TAG_TEXT_SMALL6 & 0x7) << vb::TAG_SHIFT);
        // cmp rax, r11
        asm.emit(&[0x4C, 0x39, 0xD8]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt
        let tag_ok = asm.pos();
        asm.patch_rel32(tag_small_ok, tag_ok);

        // map ptr in r11
        asm.emit(&[0x49, 0x89, 0xF3]); // mov r11, rsi
                                       // rax = PAYLOAD_MASK
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(vb::PAYLOAD_MASK);
        // and r11, rax
        asm.emit(&[0x49, 0x21, 0xC3]);

        // load cap
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_CAP_OFFSET]
        asm.emit_u32(MAP_CAP_OFFSET as u32);
        // test rax, rax
        asm.emit(&[0x48, 0x85, 0xC0]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt

        // guard cap matches expected (no resize)
        asm.emit(&[0x49, 0xBA]); // mov r10, imm64
        asm.emit_u64(expected_cap as u64);
        asm.emit(&[0x4C, 0x39, 0xD0]); // cmp rax, r10
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // r9 = cap - 1
        asm.emit(&[0x49, 0x89, 0xC1]); // mov r9, rax
        asm.emit(&[0x49, 0xFF, 0xC9]); // dec r9

        // rax = slots_ptr
        asm.emit(&[0x49, 0x8B, 0x83]); // mov rax, [r11 + MAP_SLOTS_PTR_OFFSET]
        asm.emit_u32(MAP_SLOTS_PTR_OFFSET as u32);
        // guard slots_ptr matches expected (no resize)
        asm.emit(&[0x49, 0xBA]); // mov r10, imm64
        asm.emit_u64(expected_slots);
        asm.emit(&[0x4C, 0x39, 0xD0]); // cmp rax, r10
        deopt_patches.push(asm.emit_jcc_placeholder(0x85)); // JNE -> deopt

        // hash = hash_u64(key_bits) into r10
        // mov r10, rcx
        asm.emit(&[0x49, 0x89, 0xCA]);
        // mov r11, r10
        asm.emit(&[0x4D, 0x89, 0xD3]);
        // shr r11, 33
        asm.emit(&[0x49, 0xC1, 0xEB, 0x21]);
        // xor r10, r11
        asm.emit(&[0x4D, 0x31, 0xDA]);
        // r11 = const1
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(0xff51afd7ed558ccd);
        // imul r10, r11
        asm.emit(&[0x4D, 0x0F, 0xAF, 0xD3]);
        // mov r11, r10
        asm.emit(&[0x4D, 0x89, 0xD3]);
        // shr r11, 33
        asm.emit(&[0x49, 0xC1, 0xEB, 0x21]);
        // xor r10, r11
        asm.emit(&[0x4D, 0x31, 0xDA]);
        // r11 = const2
        asm.emit(&[0x49, 0xBB]);
        asm.emit_u64(0xc4ceb9fe1a85ec53);
        // imul r10, r11
        asm.emit(&[0x4D, 0x0F, 0xAF, 0xD3]);
        // mov r11, r10
        asm.emit(&[0x4D, 0x89, 0xD3]);
        // shr r11, 33
        asm.emit(&[0x49, 0xC1, 0xEB, 0x21]);
        // xor r10, r11
        asm.emit(&[0x4D, 0x31, 0xDA]);

        // idx in r8 = hash & mask
        asm.emit(&[0x4D, 0x89, 0xD0]); // mov r8, r10
        asm.emit(&[0x4D, 0x21, 0xC8]); // and r8, r9

        let loop_start = asm.pos();
        // rdi = r8
        asm.emit(&[0x4C, 0x89, 0xC7]); // mov rdi, r8
                                       // imul rdi, rdi, MAP_SLOT_SIZE
        asm.emit(&[0x48, 0x69, 0xFF]);
        asm.emit_u32(MAP_SLOT_SIZE as u32);
        // add rdi, rax
        asm.emit(&[0x48, 0x01, 0xC7]);
        // movzx r11d, byte ptr [rdi + USED_OFFSET]
        asm.emit(&[0x44, 0x0F, 0xB6, 0x9F]);
        asm.emit_u32(MAP_SLOT_USED_OFFSET as u32);
        // test r11d, r11d
        asm.emit(&[0x45, 0x85, 0xDB]);
        deopt_patches.push(asm.emit_jcc_placeholder(0x84)); // JE -> deopt
                                                            // mov r11, [rdi + HASH_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_HASH_OFFSET as u32);
        // cmp r11, r10
        asm.emit(&[0x4D, 0x39, 0xD3]);
        let jne_next = asm.emit_jcc_placeholder(0x85);
        // mov r11, [rdi + KEY_BITS_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x9F]);
        asm.emit_u32(MAP_SLOT_KEY_BITS_OFFSET as u32);
        // cmp r11, rcx
        asm.emit(&[0x49, 0x39, 0xCB]);
        let je_found = asm.emit_jcc_placeholder(0x84);

        let next_offset = asm.pos();
        // inc r8
        asm.emit(&[0x49, 0xFF, 0xC0]);
        // and r8, r9
        asm.emit(&[0x4D, 0x21, 0xC8]);
        let loop_jmp = asm.emit_jmp_placeholder();

        let found_offset = asm.pos();
        // mov rax, [rdi + VALUE_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x87]);
        asm.emit_u32(MAP_SLOT_VALUE_OFFSET as u32);
        emit_dec_sp(asm); // drop key
        emit_dec_sp(asm); // drop map
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        asm.patch_rel32(jne_next, next_offset);
        asm.patch_rel32(je_found, found_offset);
        asm.patch_rel32(loop_jmp, loop_start);

        deopt_patches
    }

    fn emit_bump_map_version_local(asm: &mut Asm, map_idx: usize) {
        let map_disp = (map_idx as i32) * 8;
        // mov rax, [r13 + map_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(map_disp as u32);
        emit_mask_payload_rax(asm);
        // bump version
        asm.emit(&[0x4C, 0x8B, 0x88]); // mov r9, [rax + MAP_VERSION_OFFSET]
        asm.emit_u32(MAP_VERSION_OFFSET as u32);
        asm.emit(&[0x49, 0x83, 0xC1, 0x01]); // add r9, 1
        asm.emit(&[0x4C, 0x89, 0x88]); // mov [rax + MAP_VERSION_OFFSET], r9
        asm.emit_u32(MAP_VERSION_OFFSET as u32);
    }

    fn emit_call_to_text(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (bits)
        asm.emit(&[0x4C, 0x89, 0xFE]); // mov rsi, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_to_text as *const () as usize as u64);
        asm.emit_call_rax();
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_load_local(asm: &mut Asm, idx: usize, promoted: &PromotedLocals) {
        if let Some(reg) = promoted.xmm_for(idx) {
            emit_movsd_stack_from_xmm(asm, reg);
            emit_inc_sp(asm);
            return;
        }
        let disp = (idx as i32) * 8;
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(disp as u32);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_store_local(asm: &mut Asm, idx: usize, promoted: &PromotedLocals) {
        if let Some(reg) = promoted.xmm_for(idx) {
            emit_dec_sp(asm);
            emit_load_rax_from_stack(asm);
            emit_movq_xmm_from_rax(asm, reg);
            return;
        }
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        let disp = (idx as i32) * 8;
        asm.emit(&[0x49, 0x89, 0x85]);
        asm.emit_u32(disp as u32);
    }

    fn emit_init_local_const(asm: &mut Asm, idx: usize, value: f64, promoted: &PromotedLocals) {
        let bits = value.to_bits();
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(bits);
        if let Some(reg) = promoted.xmm_for(idx) {
            emit_movq_xmm_from_rax(asm, reg);
        }
        let disp = (idx as i32) * 8;
        asm.emit(&[0x49, 0x89, 0x85]);
        asm.emit_u32(disp as u32);
    }

    fn emit_add_local_const(asm: &mut Asm, idx: usize, c: f64, promoted: &PromotedLocals) {
        if c == 0.0 {
            return;
        }
        if let Some(reg) = promoted.xmm_for(idx) {
            asm.emit(&[0x48, 0xB8]);
            asm.emit_u64(c.to_bits());
            if asm.avx_upper_dirty {
                emit_vmovq_xmm_from_rax(asm, 1);
                emit_vaddsd_acc_from_xmm(asm, reg, 1);
            } else {
                asm.emit(&[0x66, 0x48, 0x0F, 0x6E, 0xC8]); // movq xmm1, rax
                emit_addsd_xmm_xmm(asm, reg, 1);
            }
            return;
        }
        let disp = (idx as i32) * 8;
        // movsd xmm0, [r13 + disp]
        asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
        asm.emit_u32(disp as u32);
        // mov rax, imm64
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(c.to_bits());
        // movq xmm1, rax
        asm.emit(&[0x66, 0x48, 0x0F, 0x6E, 0xC8]);
        // addsd xmm0, xmm1
        asm.emit(&[0xF2, 0x0F, 0x58, 0xC1]);
        // movsd [r13 + disp], xmm0
        asm.emit(&[0xF2, 0x41, 0x0F, 0x11, 0x85]);
        asm.emit_u32(disp as u32);
    }

    fn emit_add_local_from_stack(asm: &mut Asm, idx: usize, promoted: &PromotedLocals) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
                                       // movq xmm1, rax
        if asm.avx_upper_dirty {
            emit_vmovq_xmm_from_rax(asm, 1);
        } else {
            asm.emit(&[0x66, 0x48, 0x0F, 0x6E, 0xC8]);
        }
        if let Some(reg) = promoted.xmm_for(idx) {
            if asm.avx_upper_dirty {
                emit_vaddsd_acc_from_xmm(asm, reg, 1);
            } else {
                emit_addsd_xmm_xmm(asm, reg, 1);
            }
            return;
        }
        let disp = (idx as i32) * 8;
        // movsd xmm0, [r13 + disp]
        asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
        asm.emit_u32(disp as u32);
        // addsd xmm0, xmm1
        asm.emit(&[0xF2, 0x0F, 0x58, 0xC1]);
        // movsd [r13 + disp], xmm0
        asm.emit(&[0xF2, 0x41, 0x0F, 0x11, 0x85]);
        asm.emit_u32(disp as u32);
    }

    // Fused lane for:
    // IndexListNumLocalPtrOff + Dup + AddLocalFromStack + ConstNum(1.0) + AddNum
    // + SetIndexListNumLocalPtrNoVerOffFast + Pop
    // Preconditions:
    // - r10 holds pinned list data_ptr.
    // - rcx holds base integer index for current unrolled block.
    fn emit_list_update_lane_fused(
        asm: &mut Asm,
        offset: i32,
        acc_local: usize,
        promoted: &PromotedLocals,
        one_reg: u8,
    ) {
        // r11 = rcx (+ lane offset)
        asm.emit(&[0x49, 0x89, 0xCB]); // mov r11, rcx
        if offset != 0 {
            if (-128..=127).contains(&offset) {
                asm.emit(&[0x49, 0x83, 0xC3, offset as u8]); // add r11, imm8
            } else {
                asm.emit(&[0x49, 0x81, 0xC3]); // add r11, imm32
                asm.emit_u32(offset as u32);
            }
        }

        // xmm0 = old value at [r10 + r11*8]
        asm.emit(&[0xF2, 0x43, 0x0F, 0x10, 0x04, 0xDA]); // movsd xmm0, [r10 + r11*8]

        // acc += old_value
        if let Some(acc_reg) = promoted.xmm_for(acc_local) {
            emit_addsd_xmm_xmm(asm, acc_reg, 0);
        } else {
            let disp = (acc_local as i32) * 8;
            // xmm2 = acc_local
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x8D]);
            asm.emit_u32(disp as u32);
            // xmm2 += xmm0
            asm.emit(&[0xF2, 0x0F, 0x58, 0xD0]); // addsd xmm2, xmm0
                                                 // acc_local = xmm2
            asm.emit(&[0xF2, 0x41, 0x0F, 0x11, 0x8D]);
            asm.emit_u32(disp as u32);
        }

        // xmm0 = old_value + 1.0 (constant is preloaded once per fused block).
        emit_addsd_xmm_xmm(asm, 0, one_reg);

        // store back to [r10 + r11*8]
        asm.emit(&[0xF2, 0x43, 0x0F, 0x11, 0x04, 0xDA]); // movsd [r10 + r11*8], xmm0
    }

    // Fused lane for:
    // IndexListNumLocalPtrOff + Dup + MulNum + AddLocalFromStack
    // Preconditions:
    // - r10 holds pinned list data_ptr.
    // - rcx holds base integer index for current unrolled block.
    fn emit_dot_square_lane_fused(
        asm: &mut Asm,
        offset: i32,
        acc_local: usize,
        promoted: &PromotedLocals,
    ) {
        // r11 = rcx (+ lane offset)
        asm.emit(&[0x49, 0x89, 0xCB]); // mov r11, rcx
        if offset != 0 {
            if (-128..=127).contains(&offset) {
                asm.emit(&[0x49, 0x83, 0xC3, offset as u8]); // add r11, imm8
            } else {
                asm.emit(&[0x49, 0x81, 0xC3]); // add r11, imm32
                asm.emit_u32(offset as u32);
            }
        }

        // xmm0 = elem at [r10 + r11*8]
        asm.emit(&[0xF2, 0x43, 0x0F, 0x10, 0x04, 0xDA]); // movsd xmm0, [r10 + r11*8]
                                                         // xmm0 = xmm0 * xmm0
        asm.emit(&[0xF2, 0x0F, 0x59, 0xC0]); // mulsd xmm0, xmm0

        // acc += elem*elem
        if let Some(acc_reg) = promoted.xmm_for(acc_local) {
            emit_addsd_xmm_xmm(asm, acc_reg, 0);
        } else {
            let disp = (acc_local as i32) * 8;
            // xmm1 = acc_local
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x8D]);
            asm.emit_u32(disp as u32);
            // xmm1 += xmm0
            asm.emit(&[0xF2, 0x0F, 0x58, 0xC8]); // addsd xmm1, xmm0
                                                 // acc_local = xmm1
            asm.emit(&[0xF2, 0x41, 0x0F, 0x11, 0x8D]);
            asm.emit_u32(disp as u32);
        }
    }

    fn emit_vaddsd_acc_from_xmm(asm: &mut Asm, dst: u8, src: u8) {
        debug_assert!(src < 8);
        let r_bit = if dst >= 8 { 0x00 } else { 0x80 };
        let vvvv_inv = ((!dst) & 0x0F) << 3; // src1 = dst
        let vex2 = r_bit | vvvv_inv | 0x03; // L=0, pp=F2
        let modrm = 0xC0 | ((dst & 0x07) << 3) | (src & 0x07);
        asm.emit_avx(&[0xC5, vex2, 0x58, modrm]); // vaddsd dst, dst, src
    }

    fn emit_vxorpd_ymm_self(asm: &mut Asm, reg: u8) {
        debug_assert!(reg < 16);
        let r_bit = if reg >= 8 { 0x00 } else { 0x80 };
        let b_bit = if reg >= 8 { 0x00 } else { 0x20 };
        let byte2 = r_bit | 0x40 | b_bit | 0x01; // map 0F
        let vvvv_inv = ((!reg) & 0x0F) << 3; // src1 = reg
        let byte3 = vvvv_inv | 0x05; // L=1, pp=66
        let modrm = 0xC0 | ((reg & 0x07) << 3) | (reg & 0x07); // src2 = reg
        asm.emit_avx(&[0xC4, byte2, byte3, 0x57, modrm]); // vxorpd reg, reg, reg
    }

    fn emit_vfmadd231pd_ymm(asm: &mut Asm, dst: u8, src1: u8, src2: u8) {
        debug_assert!(dst < 16);
        debug_assert!(src1 < 16);
        debug_assert!(src2 < 16);
        let r_bit = if dst >= 8 { 0x00 } else { 0x80 };
        let b_bit = if src2 >= 8 { 0x00 } else { 0x20 };
        let byte2 = r_bit | 0x40 | b_bit | 0x02; // map 0F 38
        let vvvv_inv = ((!src1) & 0x0F) << 3;
        let byte3 = 0x80 | vvvv_inv | 0x04 | 0x01; // W=1, L=1, pp=66
        let modrm = 0xC0 | ((dst & 0x07) << 3) | (src2 & 0x07);
        asm.emit_avx(&[0xC4, byte2, byte3, 0xB8, modrm]); // vfmadd231pd dst, src1, src2
    }

    fn emit_vextractf128_xmm_from_ymm(asm: &mut Asm, dst: u8, src: u8, imm8: u8) {
        debug_assert!(dst < 16);
        debug_assert!(src < 16);
        let r_bit = if src >= 8 { 0x00 } else { 0x80 };
        let b_bit = if dst >= 8 { 0x00 } else { 0x20 };
        let byte2 = r_bit | 0x40 | b_bit | 0x03; // map 0F 3A
        let modrm = 0xC0 | ((src & 0x07) << 3) | (dst & 0x07);
        asm.emit_avx(&[0xC4, byte2, 0x7D, 0x19, modrm, imm8]); // vextractf128 dst, src, imm8
    }

    fn emit_reduce_dot_acc_pair_from_ymm(asm: &mut Asm, vec_reg: u8) {
        emit_vextractf128_xmm_from_ymm(asm, 0, vec_reg, 1); // xmm0 = high lanes
        emit_vextractf128_xmm_from_ymm(asm, 1, vec_reg, 0); // xmm1 = low lanes
        asm.emit_avx(&[0xC5, 0xF1, 0x58, 0xC0]); // vaddpd xmm0, xmm1, xmm0
    }

    fn emit_vmovupd_ymm_from_r10_rcx8_off(asm: &mut Asm, dst: u8, elem_offset: i32) -> bool {
        debug_assert!(dst < 16);
        let byte_off_i64 = i64::from(elem_offset).checked_mul(8).unwrap_or(i64::MAX);
        if byte_off_i64 < i64::from(i32::MIN) || byte_off_i64 > i64::from(i32::MAX) {
            return false;
        }
        let byte_off = byte_off_i64 as i32;
        let r_bit = if dst >= 8 { 0x00 } else { 0x80 };
        let byte2 = r_bit | 0x40 | 0x01; // X=1 (rcx), B=0 (r10), map 0F
        let modrm_reg = (dst & 0x07) << 3;
        if byte_off == 0 {
            // vmovupd dst, [r10 + rcx*8]
            asm.emit_avx(&[0xC4, byte2, 0x7D, 0x10, 0x04 | modrm_reg, 0xCA]);
        } else if (-128..=127).contains(&byte_off) {
            // vmovupd dst, [r10 + rcx*8 + disp8]
            asm.emit_avx(&[
                0xC4,
                byte2,
                0x7D,
                0x10,
                0x44 | modrm_reg,
                0xCA,
                byte_off as u8,
            ]);
        } else {
            // vmovupd dst, [r10 + rcx*8 + disp32]
            asm.emit_avx(&[0xC4, byte2, 0x7D, 0x10, 0x84 | modrm_reg, 0xCA]);
            asm.emit_u32(byte_off as u32);
        }
        true
    }

    fn emit_vmovupd_ymm_from_rdx_off_bytes(asm: &mut Asm, dst: u8, byte_off: i32) {
        debug_assert!(dst < 16);
        let r_bit = if dst >= 8 { 0x00 } else { 0x80 };
        let byte2 = r_bit | 0x40 | 0x20 | 0x01; // X=1, B=1, map 0F
        let modrm_reg = (dst & 0x07) << 3;
        if byte_off == 0 {
            // vmovupd dst, [rdx]
            asm.emit_avx(&[0xC4, byte2, 0x7D, 0x10, 0x02 | modrm_reg]);
        } else if (-128..=127).contains(&byte_off) {
            // vmovupd dst, [rdx + disp8]
            asm.emit_avx(&[0xC4, byte2, 0x7D, 0x10, 0x42 | modrm_reg, byte_off as u8]);
        } else {
            // vmovupd dst, [rdx + disp32]
            asm.emit_avx(&[0xC4, byte2, 0x7D, 0x10, 0x82 | modrm_reg]);
            asm.emit_u32(byte_off as u32);
        }
    }

    fn emit_dot_square_avx2_loop_vectorized(
        asm: &mut Asm,
        pattern: &DotSquareAvxLoopPattern,
        promoted: &PromotedLocals,
    ) -> Option<usize> {
        enum AccRegs {
            Single(u8),
            Split(u8, u8),
        }

        let acc_regs = match pattern.accum {
            DotSquareQuadAccum::Single { acc_local } => {
                let acc_reg = promoted.xmm_for(acc_local)?;
                if acc_reg <= 1 {
                    return None;
                }
                AccRegs::Single(acc_reg)
            }
            DotSquareQuadAccum::Split {
                even_acc_local,
                odd_acc_local,
            } => {
                let even_reg = promoted.xmm_for(even_acc_local)?;
                let odd_reg = promoted.xmm_for(odd_acc_local)?;
                if even_reg <= 1 || odd_reg <= 1 {
                    return None;
                }
                AccRegs::Split(even_reg, odd_reg)
            }
        };

        let idx_reg = promoted.xmm_for(pattern.idx_idx);
        let total_fma_ops = pattern.repeat.saturating_mul(pattern.quads.len());
        let vec_acc_count = total_fma_ops.clamp(1, 4);
        let vec_acc_pool = [10u8, 11u8, 12u8, 13u8];
        let vec_accs = &vec_acc_pool[..vec_acc_count];
        let load_regs = [0u8, 1u8, 14u8, 15u8];

        // Hoist list data pointer and initialize vector accumulator once per trace run.
        emit_load_list_data_ptr_r10_from_local(asm, pattern.list_idx);
        for &vec_acc in vec_accs {
            emit_vxorpd_ymm_self(asm, vec_acc);
        }

        // Seed integer induction variable in rcx from idx local.
        if let Some(reg) = idx_reg {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (pattern.idx_idx as i32) * 8;
            emit_movsd_xmm_from_local(asm, 0, idx_disp);
            emit_cvttsd2si_rcx_from_xmm(asm, 0);
        }
        // Snapshot rcx so AVX element counter can be updated once outside the hot loop.
        asm.emit(&[0x49, 0x89, 0xCB]); // mov r11, rcx

        let mut block_load_offsets: Vec<i32> = Vec::with_capacity(total_fma_ops);
        for rep in 0..pattern.repeat {
            let rep_step_i64 = i64::from(pattern.step)
                .checked_mul(rep as i64)
                .unwrap_or(i64::MAX);
            for quad in &pattern.quads {
                let off_i64 = rep_step_i64
                    .checked_add(i64::from(quad.base_offset))
                    .unwrap_or(i64::MAX);
                if off_i64 < i64::from(i32::MIN) || off_i64 > i64::from(i32::MAX) {
                    return None;
                }
                block_load_offsets.push(off_i64 as i32);
            }
        }
        let block_max_extra = block_load_offsets.iter().copied().max().unwrap_or(0) as i64;

        let hoisted_block_limit = if pattern.limit.is_finite()
            && pattern.limit.fract() == 0.0
            && pattern.limit >= i64::MIN as f64
            && pattern.limit <= i64::MAX as f64
        {
            let limit_i64 = pattern.limit as i64;
            limit_i64.checked_sub(block_max_extra).filter(|v| *v >= 0)
        } else {
            None
        };

        let block_step_i32 = i64::from(pattern.step)
            .checked_mul(pattern.repeat as i64)
            .and_then(|v| i32::try_from(v).ok());
        let block_step_bytes_i32 = block_step_i32.and_then(|s| s.checked_mul(8));
        let use_ptr_bump = hoisted_block_limit.is_some()
            && block_step_i32.is_some()
            && block_step_bytes_i32.is_some();

        if use_ptr_bump {
            // rdx = data_ptr + rcx*8 (byte pointer induction var lives through the loop).
            asm.emit(&[0x49, 0x8D, 0x14, 0xCA]); // lea rdx, [r10 + rcx*8]
                                                 // r8 = start pointer snapshot.
            asm.emit(&[0x49, 0x89, 0xD0]); // mov r8, rdx
                                           // r9 = end pointer = data_ptr + block_limit*8.
            let block_limit = hoisted_block_limit.expect("checked by use_ptr_bump");
            let block_limit_bytes = block_limit.checked_mul(8)?;
            asm.emit(&[0x48, 0xB8]); // mov rax, imm64
            asm.emit_u64(block_limit_bytes as u64);
            asm.emit(&[0x4C, 0x01, 0xD0]); // add rax, r10
            asm.emit(&[0x49, 0x89, 0xC1]); // mov r9, rax
        }

        let loop_start = asm.pos();
        let exit_opcode = if pattern.inclusive { 0x87 } else { 0x83 }; // JA / JAE
        let mut exit_jccs: Vec<usize> = Vec::with_capacity(pattern.repeat.max(1));

        if let Some(block_limit) = hoisted_block_limit {
            if use_ptr_bump {
                // cmp rdx, r9
                asm.emit(&[0x4C, 0x39, 0xCA]);
            } else if block_limit <= u32::MAX as i64 {
                // cmp rcx, imm32
                asm.emit(&[0x48, 0x81, 0xF9]);
                asm.emit_u32(block_limit as u32);
            } else {
                // mov rax, limit_u64; cmp rcx, rax
                asm.emit(&[0x48, 0xB8]);
                asm.emit_u64(block_limit as u64);
                asm.emit(&[0x48, 0x39, 0xC1]);
            }
            let exit_jcc = asm.emit_jcc_placeholder(exit_opcode);
            asm.mark_branch_kind(exit_jcc, BranchKind::Exit);
            exit_jccs.push(exit_jcc);
        }

        let mut fma_slot = 0usize;
        if hoisted_block_limit.is_some()
            && block_step_i32.is_some()
            && block_step_bytes_i32.is_some()
        {
            let mut load_i = 0usize;
            while load_i < block_load_offsets.len() {
                let chunk = (block_load_offsets.len() - load_i).min(load_regs.len());
                for (lane, load_reg) in load_regs.iter().copied().enumerate().take(chunk) {
                    let elem_off = block_load_offsets[load_i + lane];
                    let byte_off = elem_off.checked_mul(8)?;
                    emit_vmovupd_ymm_from_rdx_off_bytes(asm, load_reg, byte_off);
                }
                for load_reg in load_regs.iter().copied().take(chunk) {
                    let vec_acc = vec_accs[fma_slot % vec_accs.len()];
                    emit_vfmadd231pd_ymm(asm, vec_acc, load_reg, load_reg); // vec_acc += load_reg^2
                    fma_slot = fma_slot.saturating_add(1);
                }
                load_i += chunk;
            }
            let block_step_bytes = block_step_bytes_i32?;
            if (-128..=127).contains(&block_step_bytes) {
                asm.emit(&[0x48, 0x83, 0xC2, block_step_bytes as u8]); // add rdx, imm8
            } else {
                asm.emit(&[0x48, 0x81, 0xC2]); // add rdx, imm32
                asm.emit_u32(block_step_bytes as u32);
            }
        } else {
            for _ in 0..pattern.repeat {
                if pattern.limit.fract() == 0.0
                    && pattern.limit >= 0.0
                    && pattern.limit <= u32::MAX as f64
                {
                    // cmp rcx, imm32
                    asm.emit(&[0x48, 0x81, 0xF9]);
                    asm.emit_u32(pattern.limit as u32);
                } else {
                    // mov rax, limit_u64; cmp rcx, rax
                    asm.emit(&[0x48, 0xB8]);
                    asm.emit_u64(pattern.limit as u64);
                    asm.emit(&[0x48, 0x39, 0xC1]);
                }
                let exit_jcc = asm.emit_jcc_placeholder(exit_opcode);
                asm.mark_branch_kind(exit_jcc, BranchKind::Exit);
                exit_jccs.push(exit_jcc);

                let mut quad_i = 0usize;
                while quad_i < pattern.quads.len() {
                    let chunk = (pattern.quads.len() - quad_i).min(load_regs.len());
                    for (lane, load_reg) in load_regs.iter().copied().enumerate().take(chunk) {
                        let elem_off = pattern.quads[quad_i + lane].base_offset;
                        if !emit_vmovupd_ymm_from_r10_rcx8_off(asm, load_reg, elem_off) {
                            return None;
                        }
                    }
                    for load_reg in load_regs.iter().copied().take(chunk) {
                        let vec_acc = vec_accs[fma_slot % vec_accs.len()];
                        emit_vfmadd231pd_ymm(asm, vec_acc, load_reg, load_reg); // vec_acc += load_reg^2
                        fma_slot = fma_slot.saturating_add(1);
                    }
                    quad_i += chunk;
                }

                // rcx += step
                if (-128..=127).contains(&pattern.step) {
                    asm.emit(&[0x48, 0x83, 0xC1, pattern.step as u8]); // add rcx, imm8
                } else {
                    asm.emit(&[0x48, 0x81, 0xC1]); // add rcx, imm32
                    asm.emit_u32(pattern.step as u32);
                }
            }
        }
        let back_jmp = asm.emit_jmp_placeholder();
        asm.patch_rel32(back_jmp, loop_start);

        let reduce_offset = asm.pos();
        for exit_jcc in exit_jccs {
            asm.patch_rel32(exit_jcc, reduce_offset);
        }

        // Update AVX element counter once per trace run and recover idx for writeback.
        if use_ptr_bump {
            // rax = (rdx - r8) / 8  (processed elements)
            asm.emit(&[0x48, 0x89, 0xD0]); // mov rax, rdx
            asm.emit(&[0x4C, 0x29, 0xC0]); // sub rax, r8
            asm.emit(&[0x48, 0xC1, 0xE8, 0x03]); // shr rax, 3
                                                 // rcx = r11 + processed_elements (idx_end)
            asm.emit(&[0x4C, 0x89, 0xD9]); // mov rcx, r11
            asm.emit(&[0x48, 0x01, 0xC1]); // add rcx, rax
            asm.emit_add_qword_at_r15_from_reg(RUN_AVX_DOT_ELEMENTS_OFFSET, 0); // add [r15+off], rax
        } else {
            // rax = rcx_end - rcx_start (processed elements)
            asm.emit(&[0x48, 0x89, 0xC8]); // mov rax, rcx
            asm.emit(&[0x4C, 0x29, 0xD8]); // sub rax, r11
            asm.emit_add_qword_at_r15_from_reg(RUN_AVX_DOT_ELEMENTS_OFFSET, 0); // add [r15+off], rax
        }

        // Reduce vector accumulators once on loop exit.
        match acc_regs {
            AccRegs::Single(acc_reg) => {
                for &vec_acc in vec_accs {
                    emit_reduce_dot_acc_pair_from_ymm(asm, vec_acc);
                    asm.emit_avx(&[0xC5, 0xF9, 0x7C, 0xC0]); // vhaddpd xmm0, xmm0, xmm0
                    emit_vaddsd_acc_from_xmm(asm, acc_reg, 0);
                }
            }
            AccRegs::Split(even_reg, odd_reg) => {
                for &vec_acc in vec_accs {
                    emit_reduce_dot_acc_pair_from_ymm(asm, vec_acc);
                    asm.emit_avx(&[0xC4, 0xE3, 0x79, 0x05, 0xC8, 0x01]); // vpermilpd xmm1, xmm0, 1
                    emit_vaddsd_acc_from_xmm(asm, even_reg, 0);
                    emit_vaddsd_acc_from_xmm(asm, odd_reg, 1);
                }
            }
        }

        // Write the current integer induction value back to idx local as f64.
        if let Some(reg) = idx_reg {
            emit_cvtsi2sd_xmm_from_rcx(asm, reg);
        } else {
            let idx_disp = (pattern.idx_idx as i32) * 8;
            emit_cvtsi2sd_xmm_from_rcx(asm, 0);
            emit_movsd_local_from_xmm(asm, 0, idx_disp);
        }

        Some(asm.emit_jmp_placeholder())
    }

    // 4-lane fused square-dot update using AVX2+FMA.
    // Preconditions:
    // - r10 holds pinned list data_ptr.
    // - rcx holds base integer index for current unrolled block.
    // - accumulators must be promoted locals in XMM registers.
    fn emit_dot_square_quad_avx2_fma(
        asm: &mut Asm,
        base_offset: i32,
        accum: DotSquareQuadAccum,
        promoted: &PromotedLocals,
    ) -> bool {
        match accum {
            DotSquareQuadAccum::Single { acc_local } => {
                let Some(acc_reg) = promoted.xmm_for(acc_local) else {
                    return false;
                };
                if acc_reg <= 1 {
                    return false;
                }

                // r11 = rcx (+ base offset)
                asm.emit(&[0x49, 0x89, 0xCB]); // mov r11, rcx
                if base_offset != 0 {
                    if (-128..=127).contains(&base_offset) {
                        asm.emit(&[0x49, 0x83, 0xC3, base_offset as u8]); // add r11, imm8
                    } else {
                        asm.emit(&[0x49, 0x81, 0xC3]); // add r11, imm32
                        asm.emit_u32(base_offset as u32);
                    }
                }

                // ymm1 = [x0^2, x1^2, x2^2, x3^2]
                asm.emit_avx(&[0xC4, 0x81, 0x7D, 0x10, 0x04, 0xDA]); // vmovupd ymm0, [r10+r11*8]
                asm.emit_avx(&[0xC5, 0xF5, 0x57, 0xC9]); // vxorpd ymm1, ymm1, ymm1
                asm.emit_avx(&[0xC4, 0xE2, 0xFD, 0xB8, 0xC8]); // vfmadd231pd ymm1, ymm0, ymm0

                // xmm0 = [x0^2 + x2^2, x1^2 + x3^2]
                asm.emit_avx(&[0xC4, 0xE3, 0x7D, 0x19, 0xC8, 0x01]); // vextractf128 xmm0, ymm1, 1
                asm.emit_avx(&[0xC5, 0xF1, 0x58, 0xC0]); // vaddpd xmm0, xmm1, xmm0
                                                         // xmm0[0] = x0^2 + x1^2 + x2^2 + x3^2
                asm.emit_avx(&[0xC5, 0xF9, 0x7C, 0xC0]); // vhaddpd xmm0, xmm0, xmm0
                emit_vaddsd_acc_from_xmm(asm, acc_reg, 0);
            }
            DotSquareQuadAccum::Split {
                even_acc_local,
                odd_acc_local,
            } => {
                let Some(even_reg) = promoted.xmm_for(even_acc_local) else {
                    return false;
                };
                let Some(odd_reg) = promoted.xmm_for(odd_acc_local) else {
                    return false;
                };
                if even_reg <= 1 || odd_reg <= 1 {
                    return false;
                }

                // r11 = rcx (+ base offset)
                asm.emit(&[0x49, 0x89, 0xCB]); // mov r11, rcx
                if base_offset != 0 {
                    if (-128..=127).contains(&base_offset) {
                        asm.emit(&[0x49, 0x83, 0xC3, base_offset as u8]); // add r11, imm8
                    } else {
                        asm.emit(&[0x49, 0x81, 0xC3]); // add r11, imm32
                        asm.emit_u32(base_offset as u32);
                    }
                }

                // ymm1 = [x0^2, x1^2, x2^2, x3^2]
                asm.emit_avx(&[0xC4, 0x81, 0x7D, 0x10, 0x04, 0xDA]); // vmovupd ymm0, [r10+r11*8]
                asm.emit_avx(&[0xC5, 0xF5, 0x57, 0xC9]); // vxorpd ymm1, ymm1, ymm1
                asm.emit_avx(&[0xC4, 0xE2, 0xFD, 0xB8, 0xC8]); // vfmadd231pd ymm1, ymm0, ymm0

                // xmm0 = [x0^2 + x2^2, x1^2 + x3^2]
                asm.emit_avx(&[0xC4, 0xE3, 0x7D, 0x19, 0xC8, 0x01]); // vextractf128 xmm0, ymm1, 1
                asm.emit_avx(&[0xC5, 0xF1, 0x58, 0xC0]); // vaddpd xmm0, xmm1, xmm0
                                                         // xmm1[0] = odd lane sum
                asm.emit_avx(&[0xC4, 0xE3, 0x79, 0x05, 0xC8, 0x01]); // vpermilpd xmm1, xmm0, 1

                emit_vaddsd_acc_from_xmm(asm, even_reg, 0);
                emit_vaddsd_acc_from_xmm(asm, odd_reg, 1);
            }
        }
        true
    }

    fn emit_len_list_local(asm: &mut Asm, idx: usize) {
        let disp = (idx as i32) * 8;
        // mov rax, [r13 + disp] (list bits)
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(disp as u32);
        emit_mask_payload_rax(asm);
        // mov rax, [rax + LIST_LEN_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x80]);
        asm.emit_u32(LIST_LEN_OFFSET as u32);
        // cvtsi2sd xmm0, rax
        asm.emit(&[0xF2, 0x48, 0x0F, 0x2A, 0xC0]);
        emit_movsd_stack_from_xmm(asm, 0);
        emit_inc_sp(asm);
    }

    fn emit_load_list_data_ptr_r10_from_rax(asm: &mut Asm) {
        // mov r10, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x90]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
    }

    fn emit_load_list_data_ptr_r10_from_local(asm: &mut Asm, list_idx: usize) {
        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        emit_mask_payload_rax(asm);
        emit_load_list_data_ptr_r10_from_rax(asm);
    }

    fn emit_index_list_num_local(asm: &mut Asm, list_idx: usize, idx_idx: usize) {
        let idx_disp = (idx_idx as i32) * 8;
        // movsd xmm0, [r13 + idx_disp]
        asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
        asm.emit_u32(idx_disp as u32);
        // cvttsd2si rcx, xmm0
        asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        emit_mask_payload_rax(asm);
        // mov rdx, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x90]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov rax, [rdx + rcx*8]
        asm.emit(&[0x48, 0x8B, 0x04, 0xCA]);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_index_list_num_local_ptr(
        asm: &mut Asm,
        list_idx: usize,
        idx_idx: usize,
        _data_ptr: u64,
        promoted: &PromotedLocals,
    ) {
        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        emit_load_list_data_ptr_r10_from_local(asm, list_idx);
        // mov rax, [r10 + rcx*8]
        asm.emit(&[0x49, 0x8B, 0x04, 0xCA]);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_index_list_num_local_ptr_off(
        asm: &mut Asm,
        list_idx: usize,
        idx_idx: usize,
        _data_ptr: u64,
        offset: i32,
        promoted: &PromotedLocals,
    ) {
        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        if offset != 0 {
            if (-128..=127).contains(&offset) {
                asm.emit(&[0x48, 0x83, 0xC1, offset as u8]); // add rcx, imm8
            } else {
                asm.emit(&[0x48, 0x81, 0xC1]); // add rcx, imm32
                asm.emit_u32(offset as u32);
            }
        }
        emit_load_list_data_ptr_r10_from_local(asm, list_idx);
        // mov rax, [r10 + rcx*8]
        asm.emit(&[0x49, 0x8B, 0x04, 0xCA]);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_bin_op(asm: &mut Asm, op: BinOp) {
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 0);
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 1);
        match op {
            BinOp::Add => asm.emit(&[0xF2, 0x0F, 0x58, 0xC8]),
            BinOp::Sub => asm.emit(&[0xF2, 0x0F, 0x5C, 0xC8]),
            BinOp::Mul => asm.emit(&[0xF2, 0x0F, 0x59, 0xC8]),
            BinOp::Div => asm.emit(&[0xF2, 0x0F, 0x5E, 0xC8]),
        }
        emit_movsd_stack_from_xmm(asm, 1);
        emit_inc_sp(asm);
    }

    fn emit_cmp(asm: &mut Asm, kind: CmpKind) {
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 0);
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 1);
        // ucomisd xmm1, xmm0
        asm.emit(&[0x66, 0x0F, 0x2E, 0xC8]);
        let setcc = match kind {
            CmpKind::Eq => 0x94,
            CmpKind::Ne => 0x95,
            CmpKind::Lt => 0x92,
            CmpKind::Le => 0x96,
            CmpKind::Gt => 0x97,
            CmpKind::Ge => 0x93,
        };
        // setcc al
        asm.emit(&[0x0F, setcc, 0xC0]);
        // setp dl
        asm.emit(&[0x0F, 0x9A, 0xC2]);
        match kind {
            CmpKind::Ne => {
                // or al, dl
                asm.emit(&[0x08, 0xD0]);
            }
            _ => {
                // xor dl, 1
                asm.emit(&[0x80, 0xF2, 0x01]);
                // and al, dl
                asm.emit(&[0x20, 0xD0]);
            }
        }
        // movzx rax, al
        asm.emit(&[0x48, 0x0F, 0xB6, 0xC0]);
        // cvtsi2sd xmm0, rax
        asm.emit(&[0xF2, 0x48, 0x0F, 0x2A, 0xC0]);
        emit_movsd_stack_from_xmm(asm, 0);
        emit_inc_sp(asm);
    }

    fn emit_jump_if_false(asm: &mut Asm) -> usize {
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 0);
        // xorpd xmm1, xmm1
        asm.emit(&[0x66, 0x0F, 0x57, 0xC9]);
        // ucomisd xmm0, xmm1
        asm.emit(&[0x66, 0x0F, 0x2E, 0xC1]);
        let jp_at = asm.emit_jcc_placeholder(0x8A); // JP
        let je_at = asm.emit_jcc_placeholder(0x84); // JE
        let after = asm.pos();
        asm.patch_rel32(jp_at, after);
        je_at
    }

    fn emit_deopt_if_false(asm: &mut Asm, deopt_ip: usize) -> usize {
        emit_store_deopt_ip(asm, deopt_ip);
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 0);
        // xorpd xmm1, xmm1
        asm.emit(&[0x66, 0x0F, 0x57, 0xC9]);
        // ucomisd xmm0, xmm1
        asm.emit(&[0x66, 0x0F, 0x2E, 0xC1]);
        let jp_at = asm.emit_jcc_placeholder(0x8A); // JP
        let je_at = asm.emit_jcc_placeholder(0x84); // JE -> deopt
        let after = asm.pos();
        asm.patch_rel32(jp_at, after);
        je_at
    }

    fn emit_make_list(asm: &mut Asm, len: usize) {
        // rax = rbx
        asm.emit(&[0x48, 0x89, 0xD8]); // mov rax, rbx
        if len <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xE8, len as u8]); // sub rax, imm8
        } else {
            asm.emit(&[0x48, 0x2D]); // sub rax, imm32
            asm.emit_u32(len as u32);
        }
        // lea rdi, [r14 + rax*8]
        asm.emit(&[0x49, 0x8D, 0x3C, 0xC6]);
        // mov rsi, len
        asm.emit(&[0x48, 0xC7, 0xC6]);
        asm.emit_u32(len as u32);
        // mov rdx, r15
        asm.emit(&[0x4C, 0x89, 0xFA]);
        // call jit_make_list
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_make_list as *const () as usize as u64);
        asm.emit_call_rax();
        // rbx = rbx - len
        if len <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xEB, len as u8]);
        } else {
            asm.emit(&[0x48, 0x81, 0xEB]);
            asm.emit_u32(len as u32);
        }
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_make_list_temp(asm: &mut Asm, len: usize) {
        if len <= 4 {
            // rcx = temp_small_list_count
            asm.emit(&[0x49, 0x8B, 0x8F]);
            asm.emit_u32(TEMP_SMALL_LIST_COUNT_OFFSET as u32);
            // cmp rcx, INLINE_TEMP_LIST_MAX
            asm.emit(&[0x48, 0x81, 0xF9]);
            asm.emit_u32(INLINE_TEMP_LIST_MAX as u32);
            let slow_jcc = asm.emit_jcc_placeholder(0x8D); // JGE -> slow path

            // rdx = rcx (index)
            asm.emit(&[0x48, 0x89, 0xCA]);
            // rax = rcx + 1
            asm.emit(&[0x48, 0x8D, 0x41, 0x01]); // lea rax, [rcx+1]
                                                 // store temp_small_list_count
            asm.emit(&[0x49, 0x89, 0x87]);
            asm.emit_u32(TEMP_SMALL_LIST_COUNT_OFFSET as u32);

            // rdx *= 32 (size of JitList / 4 elems)
            asm.emit(&[0x48, 0x6B, 0xD2, 0x20]); // imul rdx, rdx, 32

            // rdi = &temp_small_list_data
            asm.emit(&[0x49, 0x8D, 0xBF]);
            asm.emit_u32(TEMP_SMALL_LIST_DATA_OFFSET as u32);
            // rdi += rdx
            asm.emit(&[0x48, 0x01, 0xD7]);

            // r8 = &temp_small_lists
            asm.emit(&[0x4D, 0x8D, 0x87]);
            asm.emit_u32(TEMP_SMALL_LISTS_OFFSET as u32);
            // r8 += rdx
            asm.emit(&[0x49, 0x01, 0xD0]);

            // r9 = data_ptr (preserve before rep movsq)
            asm.emit(&[0x49, 0x89, 0xF9]); // mov r9, rdi

            // rax = rbx - len
            asm.emit(&[0x48, 0x89, 0xD8]); // mov rax, rbx
            if len <= 0x7F {
                asm.emit(&[0x48, 0x83, 0xE8, len as u8]); // sub rax, imm8
            } else {
                asm.emit(&[0x48, 0x2D]); // sub rax, imm32
                asm.emit_u32(len as u32);
            }
            // rsi = [r14 + rax*8]
            asm.emit(&[0x49, 0x8D, 0x34, 0xC6]);
            // rcx = len
            asm.emit(&[0x48, 0xC7, 0xC1]);
            asm.emit_u32(len as u32);
            // rep movsq
            asm.emit(&[0xF3, 0xA5]);

            // list.version = 0
            asm.emit(&[0x48, 0x31, 0xC0]); // xor rax, rax
            asm.emit(&[0x49, 0x89, 0x80]); // mov [r8 + disp], rax
            asm.emit_u32(LIST_VERSION_OFFSET as u32);
            // list.len = len
            asm.emit(&[0x48, 0xC7, 0xC0]);
            asm.emit_u32(len as u32);
            asm.emit(&[0x49, 0x89, 0x80]);
            asm.emit_u32(LIST_LEN_OFFSET as u32);
            // list.cap = len
            asm.emit(&[0x49, 0x89, 0x80]);
            asm.emit_u32(LIST_CAP_OFFSET as u32);
            // list.data = data_ptr (r9)
            asm.emit(&[0x4D, 0x89, 0x88]);
            asm.emit_u32(LIST_DATA_OFFSET as u32);

            // rax = list_ptr (r8)
            asm.emit(&[0x4C, 0x89, 0xC0]); // mov rax, r8
                                           // rdx = PAYLOAD_MASK; rax &= rdx
            asm.emit(&[0x48, 0xBA]);
            asm.emit_u64(vb::PAYLOAD_MASK);
            asm.emit(&[0x48, 0x21, 0xD0]); // and rax, rdx
                                           // rdx = TAG_LIST_BITS; rax |= rdx
            asm.emit(&[0x48, 0xBA]);
            asm.emit_u64(TAG_LIST_BITS);
            asm.emit(&[0x48, 0x09, 0xD0]); // or rax, rdx

            // rbx = rbx - len
            if len <= 0x7F {
                asm.emit(&[0x48, 0x83, 0xEB, len as u8]);
            } else {
                asm.emit(&[0x48, 0x81, 0xEB]);
                asm.emit_u32(len as u32);
            }
            emit_store_rax_to_stack(asm);
            emit_inc_sp(asm);
            if asm.profile {
                asm.emit_inc_qword_at_r15(PROFILE_TEMP_LIST_ELIDED_OFFSET);
            }

            let done_jmp = asm.emit_jmp_placeholder();
            let slow_offset = asm.pos();
            emit_make_list_temp_call(asm, len);
            let done_offset = asm.pos();
            asm.patch_rel32(slow_jcc, slow_offset);
            asm.patch_rel32(done_jmp, done_offset);
            return;
        }

        emit_make_list_temp_call(asm, len);
    }

    fn emit_make_list_temp_inline_sources(
        asm: &mut Asm,
        len: usize,
        sources: &[TempValueSource],
    ) -> bool {
        if len > 4 {
            return false;
        }
        if sources.len() < len {
            return false;
        }
        if sources
            .iter()
            .take(len)
            .any(|src| matches!(src, TempValueSource::Unknown))
        {
            return false;
        }

        // rcx = temp_small_list_count
        asm.emit(&[0x49, 0x8B, 0x8F]);
        asm.emit_u32(TEMP_SMALL_LIST_COUNT_OFFSET as u32);
        // cmp rcx, INLINE_TEMP_LIST_MAX
        asm.emit(&[0x48, 0x81, 0xF9]);
        asm.emit_u32(INLINE_TEMP_LIST_MAX as u32);
        let slow_jcc = asm.emit_jcc_placeholder(0x8D); // JGE -> slow path

        // rdx = rcx (index)
        asm.emit(&[0x48, 0x89, 0xCA]);
        // rax = rcx + 1
        asm.emit(&[0x48, 0x8D, 0x41, 0x01]); // lea rax, [rcx+1]
                                             // store temp_small_list_count
        asm.emit(&[0x49, 0x89, 0x87]);
        asm.emit_u32(TEMP_SMALL_LIST_COUNT_OFFSET as u32);

        // rdx *= 32 (size of JitList / 4 elems)
        asm.emit(&[0x48, 0x6B, 0xD2, 0x20]); // imul rdx, rdx, 32

        // rdi = &temp_small_list_data
        asm.emit(&[0x49, 0x8D, 0xBF]);
        asm.emit_u32(TEMP_SMALL_LIST_DATA_OFFSET as u32);
        // rdi += rdx
        asm.emit(&[0x48, 0x01, 0xD7]);

        // r8 = &temp_small_lists
        asm.emit(&[0x4D, 0x8D, 0x87]);
        asm.emit_u32(TEMP_SMALL_LISTS_OFFSET as u32);
        // r8 += rdx
        asm.emit(&[0x49, 0x01, 0xD0]);

        // r9 = data_ptr
        asm.emit(&[0x49, 0x89, 0xF9]); // mov r9, rdi

        for (i, src) in sources.iter().take(len).enumerate() {
            match src {
                TempValueSource::Local(idx) => {
                    let disp = (*idx as i32) * 8;
                    asm.emit(&[0x49, 0x8B, 0x85]);
                    asm.emit_u32(disp as u32);
                }
                TempValueSource::ConstNum(n) => {
                    asm.emit(&[0x48, 0xB8]);
                    asm.emit_u64(n.to_bits());
                }
                TempValueSource::Unknown => {
                    return false;
                }
            }
            let disp = (i as i32) * 8;
            asm.emit(&[0x48, 0x89, 0x87]);
            asm.emit_u32(disp as u32);
        }

        // list.version = 0
        asm.emit(&[0x48, 0x31, 0xC0]); // xor rax, rax
        asm.emit(&[0x49, 0x89, 0x80]); // mov [r8 + disp], rax
        asm.emit_u32(LIST_VERSION_OFFSET as u32);
        // list.len = len
        asm.emit(&[0x48, 0xC7, 0xC0]);
        asm.emit_u32(len as u32);
        asm.emit(&[0x49, 0x89, 0x80]);
        asm.emit_u32(LIST_LEN_OFFSET as u32);
        // list.cap = len
        asm.emit(&[0x49, 0x89, 0x80]);
        asm.emit_u32(LIST_CAP_OFFSET as u32);
        // list.data = data_ptr (r9)
        asm.emit(&[0x4D, 0x89, 0x88]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);

        // rax = list_ptr (r8)
        asm.emit(&[0x4C, 0x89, 0xC0]); // mov rax, r8
                                       // rdx = PAYLOAD_MASK; rax &= rdx
        asm.emit(&[0x48, 0xBA]);
        asm.emit_u64(vb::PAYLOAD_MASK);
        asm.emit(&[0x48, 0x21, 0xD0]); // and rax, rdx
                                       // rdx = TAG_LIST_BITS; rax |= rdx
        asm.emit(&[0x48, 0xBA]);
        asm.emit_u64(TAG_LIST_BITS);
        asm.emit(&[0x48, 0x09, 0xD0]); // or rax, rdx

        // rbx = rbx - len
        if len <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xEB, len as u8]);
        } else {
            asm.emit(&[0x48, 0x81, 0xEB]);
            asm.emit_u32(len as u32);
        }
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
        if asm.profile {
            asm.emit_inc_qword_at_r15(PROFILE_TEMP_LIST_ELIDED_OFFSET);
        }

        let done_jmp = asm.emit_jmp_placeholder();
        let slow_offset = asm.pos();
        emit_make_list_temp_call(asm, len);
        let done_offset = asm.pos();
        asm.patch_rel32(slow_jcc, slow_offset);
        asm.patch_rel32(done_jmp, done_offset);
        true
    }

    fn emit_make_list_temp_call(asm: &mut Asm, len: usize) {
        // rax = rbx
        asm.emit(&[0x48, 0x89, 0xD8]); // mov rax, rbx
        if len <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xE8, len as u8]); // sub rax, imm8
        } else {
            asm.emit(&[0x48, 0x2D]); // sub rax, imm32
            asm.emit_u32(len as u32);
        }
        // lea rdi, [r14 + rax*8]
        asm.emit(&[0x49, 0x8D, 0x3C, 0xC6]);
        // mov rsi, len
        asm.emit(&[0x48, 0xC7, 0xC6]);
        asm.emit_u32(len as u32);
        // mov rdx, r15
        asm.emit(&[0x4C, 0x89, 0xFA]);
        // call jit_make_list_temp
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_make_list_temp as *const () as usize as u64);
        asm.emit_call_rax();
        // rbx = rbx - len
        if len <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xEB, len as u8]);
        } else {
            asm.emit(&[0x48, 0x81, 0xEB]);
            asm.emit_u32(len as u32);
        }
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_call_reset_temps(asm: &mut Asm) {
        // mov rdi, r15 (runtime)
        asm.emit(&[0x4C, 0x89, 0xFF]);
        // call jit_reset_temps
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_reset_temps as *const () as usize as u64);
        asm.emit_call_rax();
    }

    fn emit_call_index(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (idx bits)
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (list bits)
        asm.emit(&[0x4C, 0x89, 0xFA]); // mov rdx, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_index as *const () as usize as u64);
        asm.emit_call_rax();
        emit_movsd_stack_from_xmm(asm, 0);
        emit_inc_sp(asm);
    }

    fn emit_call_index_list_num(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (idx bits)
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (list bits)
        asm.emit(&[0x4C, 0x89, 0xFA]); // mov rdx, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_index_list_num as *const () as usize as u64);
        asm.emit_call_rax();
        emit_movsd_stack_from_xmm(asm, 0);
        emit_inc_sp(asm);
    }

    fn emit_mask_payload_rax(asm: &mut Asm) {
        // shl rax, 16; shr rax, 16  (clear tag/QNaN bits)
        asm.emit(&[0x48, 0xC1, 0xE0, 0x10]);
        asm.emit(&[0x48, 0xC1, 0xE8, 0x10]);
    }

    fn emit_index_list_num_unchecked(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 0);
        // cvttsd2si rcx, xmm0
        asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // list bits
        emit_mask_payload_rax(asm);
        // mov rdx, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x90]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov rax, [rdx + rcx*8]
        asm.emit(&[0x48, 0x8B, 0x04, 0xCA]);
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_call_setindex(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xD2]); // mov rdx, rax (val bits)
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (idx bits)
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (list bits)
        asm.emit(&[0x4C, 0x89, 0xF9]); // mov rcx, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_setindex as *const () as usize as u64);
        asm.emit_call_rax();
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_call_setindex_list_num(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xD2]); // mov rdx, rax (val bits)
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (idx bits)
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (list bits)
        asm.emit(&[0x4C, 0x89, 0xF9]); // mov rcx, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_setindex_list_num as *const () as usize as u64);
        asm.emit_call_rax();
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_pop_stack_num_to_rcx(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 0);
        emit_cvttsd2si_rcx_from_xmm(asm, 0);
    }

    fn emit_call_syscall(asm: &mut Asm, argc: usize) {
        debug_assert!(supports_native_syscall(argc));
        let syscall_args = argc.saturating_sub(1);

        for arg_pos in (1..=syscall_args).rev() {
            emit_pop_stack_num_to_rcx(asm);
            match arg_pos {
                1 => asm.emit(&[0x48, 0x89, 0xCF]), // mov rdi, rcx
                2 => asm.emit(&[0x48, 0x89, 0xCE]), // mov rsi, rcx
                3 => asm.emit(&[0x48, 0x89, 0xCA]), // mov rdx, rcx
                4 => asm.emit(&[0x49, 0x89, 0xCA]), // mov r10, rcx
                5 => asm.emit(&[0x49, 0x89, 0xC8]), // mov r8, rcx
                6 => asm.emit(&[0x49, 0x89, 0xC9]), // mov r9, rcx
                _ => unreachable!("syscall supports at most 6 args"),
            }
        }

        emit_pop_stack_num_to_rcx(asm); // syscall number
        asm.emit(&[0x48, 0x89, 0xC8]); // mov rax, rcx
        asm.emit(&[0x0F, 0x05]); // syscall

        // Preserve signed return in numeric form for the VM stack.
        asm.emit(&[0x48, 0x89, 0xC1]); // mov rcx, rax
        emit_cvtsi2sd_xmm_from_rcx(asm, 0);
        emit_movsd_stack_from_xmm(asm, 0);
        emit_inc_sp(asm);
    }

    fn emit_guard_list_bounds(asm: &mut Asm, list_idx: usize, idx_idx: usize) -> Vec<usize> {
        let idx_disp = (idx_idx as i32) * 8;
        // movsd xmm0, [r13 + idx_disp]
        asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
        asm.emit_u32(idx_disp as u32);
        // cvttsd2si rcx, xmm0
        asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        // cmp rcx, 0
        asm.emit(&[0x48, 0x83, 0xF9, 0x00]);
        // jl -> deopt
        let mut patches = Vec::with_capacity(2);
        patches.push(asm.emit_jcc_placeholder(0x8C)); // JL
        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        emit_mask_payload_rax(asm);
        // mov rdx, [rax + LIST_LEN_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x90]);
        asm.emit_u32(LIST_LEN_OFFSET as u32);
        // cmp rcx, rdx
        asm.emit(&[0x48, 0x39, 0xD1]);
        // jge -> deopt
        patches.push(asm.emit_jcc_placeholder(0x8D)); // JGE
        patches
    }

    fn emit_guard_index_cmp_const(
        asm: &mut Asm,
        idx_idx: usize,
        limit: f64,
        inclusive: bool,
        promoted: &PromotedLocals,
    ) -> Vec<usize> {
        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        if limit.fract() == 0.0 && limit >= i32::MIN as f64 && limit <= i32::MAX as f64 {
            // cmp rcx, imm32
            asm.emit(&[0x48, 0x81, 0xF9]);
            asm.emit_u32((limit as i32) as u32);
        } else {
            // mov rax, limit_i64
            asm.emit(&[0x48, 0xB8]);
            asm.emit_u64(limit as i64 as u64);
            // cmp rcx, rax
            asm.emit(&[0x48, 0x39, 0xC1]);
        }
        if inclusive {
            vec![asm.emit_jcc_placeholder(0x8F)] // JG
        } else {
            vec![asm.emit_jcc_placeholder(0x8D)] // JGE
        }
    }

    fn emit_guard_index_range_const(
        asm: &mut Asm,
        idx_idx: usize,
        limit: f64,
        inclusive: bool,
        promoted: &PromotedLocals,
    ) -> Vec<usize> {
        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }

        if limit.fract() == 0.0 && limit >= 0.0 && limit <= u32::MAX as f64 {
            // cmp rcx, imm32
            asm.emit(&[0x48, 0x81, 0xF9]);
            asm.emit_u32(limit as u32);
        } else {
            // mov rax, limit_u64
            asm.emit(&[0x48, 0xB8]);
            asm.emit_u64(limit as u64);
            // cmp rcx, rax
            asm.emit(&[0x48, 0x39, 0xC1]);
        }

        if inclusive {
            vec![asm.emit_jcc_placeholder(0x87)] // JA: deopt if rcx (as unsigned) > limit
        } else {
            vec![asm.emit_jcc_placeholder(0x83)] // JAE: deopt if rcx (as unsigned) >= limit
        }
    }

    fn emit_guard_index_nonneg(
        asm: &mut Asm,
        idx_idx: usize,
        promoted: &PromotedLocals,
    ) -> Vec<usize> {
        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        // cmp rcx, 0
        asm.emit(&[0x48, 0x83, 0xF9, 0x00]);
        let patches = vec![asm.emit_jcc_placeholder(0x8C)]; // JL
        patches
    }

    fn emit_guard_list_noalias_same_len(asm: &mut Asm, list_a: usize, list_b: usize) -> Vec<usize> {
        let mut patches = Vec::with_capacity(2);
        let disp_a = (list_a as i32) * 8;
        let disp_b = (list_b as i32) * 8;
        // mov rax, [r13 + disp_a]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(disp_a as u32);
        emit_mask_payload_rax(asm);
        // mov rdx, [rax + LIST_LEN_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x90]);
        asm.emit_u32(LIST_LEN_OFFSET as u32);
        // mov r8, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);

        // mov rax, [r13 + disp_b]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(disp_b as u32);
        emit_mask_payload_rax(asm);
        // mov rcx, [rax + LIST_LEN_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x88]);
        asm.emit_u32(LIST_LEN_OFFSET as u32);
        // cmp rdx, rcx
        asm.emit(&[0x48, 0x39, 0xCA]);
        patches.push(asm.emit_jcc_placeholder(0x85)); // JNE
                                                      // mov r9, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x88]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // cmp r8, r9
        asm.emit(&[0x4D, 0x39, 0xC8]);
        patches.push(asm.emit_jcc_placeholder(0x84)); // JE (alias) -> deopt
        patches
    }

    fn emit_setindex_list_num_unchecked(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm);
        emit_movsd_xmm_from_stack(asm, 0); // idx
                                           // cvttsd2si rcx, xmm0
        asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // list bits
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (save list bits)
        emit_mask_payload_rax(asm);
        // mov r8, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov [r8 + rcx*8], rdx
        asm.emit(&[0x49, 0x89, 0x14, 0xC8]);
        // bump version
        asm.emit(&[0x4C, 0x8B, 0x88]); // mov r9, [rax + LIST_VERSION_OFFSET]
        asm.emit_u32(LIST_VERSION_OFFSET as u32);
        asm.emit(&[0x49, 0x83, 0xC1, 0x01]); // add r9, 1
        asm.emit(&[0x4C, 0x89, 0x88]); // mov [rax + LIST_VERSION_OFFSET], r9
        asm.emit_u32(LIST_VERSION_OFFSET as u32);
        // push list bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_setindex_list_num_local_nover(
        asm: &mut Asm,
        list_idx: usize,
        idx_idx: usize,
        promoted: &PromotedLocals,
    ) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop idx bits
        emit_dec_sp(asm); // drop list bits

        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (save list bits)
        emit_mask_payload_rax(asm);

        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        // mov r8, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov [r8 + rcx*8], rdx
        asm.emit(&[0x49, 0x89, 0x14, 0xC8]);

        // push list bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_setindex_list_num_local_ptr(
        asm: &mut Asm,
        list_idx: usize,
        idx_idx: usize,
        _data_ptr: u64,
        promoted: &PromotedLocals,
    ) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop idx bits
        emit_dec_sp(asm); // drop list bits

        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (save list bits)
        emit_mask_payload_rax(asm);

        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        // mov r8, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov [r8 + rcx*8], rdx
        asm.emit(&[0x49, 0x89, 0x14, 0xC8]);

        // bump version
        asm.emit(&[0x4C, 0x8B, 0x88]); // mov r9, [rax + LIST_VERSION_OFFSET]
        asm.emit_u32(LIST_VERSION_OFFSET as u32);
        asm.emit(&[0x49, 0x83, 0xC1, 0x01]); // add r9, 1
        asm.emit(&[0x4C, 0x89, 0x88]); // mov [rax + LIST_VERSION_OFFSET], r9
        asm.emit_u32(LIST_VERSION_OFFSET as u32);

        // push list bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_setindex_list_num_local_ptr_nover(
        asm: &mut Asm,
        list_idx: usize,
        idx_idx: usize,
        _data_ptr: u64,
        promoted: &PromotedLocals,
    ) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop idx bits
        emit_dec_sp(asm); // drop list bits

        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (save list bits)
        emit_mask_payload_rax(asm);

        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        // mov r8, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov [r8 + rcx*8], rdx
        asm.emit(&[0x49, 0x89, 0x14, 0xC8]);

        // push list bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_setindex_list_num_local_ptr_nover_off(
        asm: &mut Asm,
        list_idx: usize,
        idx_idx: usize,
        _data_ptr: u64,
        offset: i32,
        promoted: &PromotedLocals,
    ) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        emit_dec_sp(asm); // drop idx bits
        emit_dec_sp(asm); // drop list bits

        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (save list bits)
        emit_mask_payload_rax(asm);

        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        if offset != 0 {
            if (-128..=127).contains(&offset) {
                asm.emit(&[0x48, 0x83, 0xC1, offset as u8]); // add rcx, imm8
            } else {
                asm.emit(&[0x48, 0x81, 0xC1]); // add rcx, imm32
                asm.emit_u32(offset as u32);
            }
        }
        // mov r8, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov [r8 + rcx*8], rdx
        asm.emit(&[0x49, 0x89, 0x14, 0xC8]);

        // push list bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_setindex_list_num_local_ptr_nover_fast(
        asm: &mut Asm,
        list_idx: usize,
        idx_idx: usize,
        _data_ptr: u64,
        promoted: &PromotedLocals,
    ) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax

        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (save list bits)
        emit_mask_payload_rax(asm);

        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        // mov r8, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov [r8 + rcx*8], rdx
        asm.emit(&[0x49, 0x89, 0x14, 0xC8]);

        // push list bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_setindex_list_num_local_ptr_nover_off_fast(
        asm: &mut Asm,
        list_idx: usize,
        idx_idx: usize,
        _data_ptr: u64,
        offset: i32,
        promoted: &PromotedLocals,
    ) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // val bits
        asm.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax

        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        asm.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax (save list bits)
        emit_mask_payload_rax(asm);

        if let Some(reg) = promoted.xmm_for(idx_idx) {
            emit_cvttsd2si_rcx_from_xmm(asm, reg);
        } else {
            let idx_disp = (idx_idx as i32) * 8;
            // movsd xmm0, [r13 + idx_disp]
            asm.emit(&[0xF2, 0x41, 0x0F, 0x10, 0x85]);
            asm.emit_u32(idx_disp as u32);
            // cvttsd2si rcx, xmm0
            asm.emit(&[0xF2, 0x48, 0x0F, 0x2C, 0xC8]);
        }
        if offset != 0 {
            if (-128..=127).contains(&offset) {
                asm.emit(&[0x48, 0x83, 0xC1, offset as u8]); // add rcx, imm8
            } else {
                asm.emit(&[0x48, 0x81, 0xC1]); // add rcx, imm32
                asm.emit_u32(offset as u32);
            }
        }
        // mov r8, [rax + LIST_DATA_OFFSET]
        asm.emit(&[0x4C, 0x8B, 0x80]);
        asm.emit_u32(LIST_DATA_OFFSET as u32);
        // mov [r8 + rcx*8], rdx
        asm.emit(&[0x49, 0x89, 0x14, 0xC8]);

        // push list bits back
        asm.emit(&[0x48, 0x89, 0xF0]); // mov rax, rsi
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);
    }

    fn emit_bump_list_version_local(asm: &mut Asm, list_idx: usize) {
        let list_disp = (list_idx as i32) * 8;
        // mov rax, [r13 + list_disp]
        asm.emit(&[0x49, 0x8B, 0x85]);
        asm.emit_u32(list_disp as u32);
        emit_mask_payload_rax(asm);
        // bump version
        asm.emit(&[0x4C, 0x8B, 0x88]); // mov r9, [rax + LIST_VERSION_OFFSET]
        asm.emit_u32(LIST_VERSION_OFFSET as u32);
        asm.emit(&[0x49, 0x83, 0xC1, 0x01]); // add r9, 1
        asm.emit(&[0x4C, 0x89, 0x88]); // mov [rax + LIST_VERSION_OFFSET], r9
        asm.emit_u32(LIST_VERSION_OFFSET as u32);
    }

    fn emit_call_len(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (list bits)
        asm.emit(&[0x4C, 0x89, 0xFE]); // mov rsi, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_len as *const () as usize as u64);
        asm.emit_call_rax();
        emit_movsd_stack_from_xmm(asm, 0);
        emit_inc_sp(asm);
    }

    fn emit_call_len_list(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm);
        asm.emit(&[0x48, 0x89, 0xC7]); // mov rdi, rax (list bits)
        asm.emit(&[0x4C, 0x89, 0xFE]); // mov rsi, r15 (runtime)
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_len_list as *const () as usize as u64);
        asm.emit_call_rax();
        emit_movsd_stack_from_xmm(asm, 0);
        emit_inc_sp(asm);
    }

    fn emit_len_list_unchecked(asm: &mut Asm) {
        emit_dec_sp(asm);
        emit_load_rax_from_stack(asm); // list bits
        emit_mask_payload_rax(asm);
        // mov rax, [rax + LIST_LEN_OFFSET]
        asm.emit(&[0x48, 0x8B, 0x80]);
        asm.emit_u32(LIST_LEN_OFFSET as u32);
        // cvtsi2sd xmm0, rax
        asm.emit(&[0xF2, 0x48, 0x0F, 0x2A, 0xC0]);
        emit_movsd_stack_from_xmm(asm, 0);
        emit_inc_sp(asm);
    }

    fn emit_inc_sp(asm: &mut Asm) {
        asm.emit(&[0x48, 0xFF, 0xC3]); // inc rbx
    }

    fn emit_dec_sp(asm: &mut Asm) {
        asm.emit(&[0x48, 0xFF, 0xCB]); // dec rbx
    }

    fn emit_store_rax_to_stack(asm: &mut Asm) {
        asm.emit(&[0x49, 0x89, 0x04, 0xDE]);
    }

    fn emit_load_rax_from_stack(asm: &mut Asm) {
        asm.emit(&[0x49, 0x8B, 0x04, 0xDE]);
    }

    fn emit_movsd_xmm_from_stack(asm: &mut Asm, reg: u8) {
        let modrm = 0x04 | ((reg & 0x7) << 3);
        let rex = 0x40 | 0x01 | if reg >= 8 { 0x04 } else { 0x00 }; // base r14 + reg ext
        asm.emit(&[0xF2, rex, 0x0F, 0x10, modrm, 0xDE]);
    }

    fn emit_movsd_stack_from_xmm(asm: &mut Asm, reg: u8) {
        let modrm = 0x04 | ((reg & 0x7) << 3);
        let rex = 0x40 | 0x01 | if reg >= 8 { 0x04 } else { 0x00 }; // base r14 + reg ext
        asm.emit(&[0xF2, rex, 0x0F, 0x11, modrm, 0xDE]);
    }

    fn emit_call_user(asm: &mut Asm, name: &str, argc: usize, deopt_ip: usize) -> usize {
        // rax = rbx - argc
        asm.emit(&[0x48, 0x89, 0xD8]); // mov rax, rbx
        if argc <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xE8, argc as u8]);
        } else {
            asm.emit(&[0x48, 0x2D]);
            asm.emit_u32(argc as u32);
        }
        // lea rdx, [r14 + rax*8]
        asm.emit(&[0x49, 0x8D, 0x14, 0xC6]);
        // mov rdi, name_ptr
        let data_off = asm.emit_cstr(name);
        let at = asm.emit_mov_imm64_placeholder(&[0x48, 0xBF]);
        asm.data_patches.push((at, data_off));
        // mov rsi, argc
        asm.emit(&[0x48, 0xC7, 0xC6]);
        asm.emit_u32(argc as u32);
        // mov rcx, r15 (runtime)
        asm.emit(&[0x4C, 0x89, 0xF9]);
        // mov r8, deopt_ip
        asm.emit(&[0x49, 0xB8]);
        asm.emit_u64(deopt_ip as u64);
        // call jit_call_user
        asm.emit(&[0x48, 0xB8]);
        asm.emit_u64(jit_call_user as *const () as usize as u64);
        asm.emit_call_rax();

        // cmp dword ptr [r15 + exit_flag], 0
        asm.emit(&[0x41, 0x83, 0x7F, EXIT_FLAG_OFFSET as u8, 0x00]);
        let jne_at = asm.emit_jcc_placeholder(0x85); // JNE

        // rbx = rbx - argc
        if argc <= 0x7F {
            asm.emit(&[0x48, 0x83, 0xEB, argc as u8]);
        } else {
            asm.emit(&[0x48, 0x81, 0xEB]);
            asm.emit_u32(argc as u32);
        }
        emit_store_rax_to_stack(asm);
        emit_inc_sp(asm);

        jne_at
    }
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
pub use x64::{
    compile as run_jit, compile_trace, compile_trace_typed, is_supported, max_stack_depth,
    BranchKind, JitExecutable, JitRuntime, JitTraceProfile, PatchSite,
};

#[cfg(any(not(target_arch = "x86_64"), windows))]
pub struct JitExecutable;

#[cfg(any(not(target_arch = "x86_64"), windows))]
#[derive(Clone, Copy, Debug, Default)]
pub struct JitTraceProfile {
    pub calls: u64,
    pub trace_iters: u64,
    pub branch_taken: u64,
    pub branch_not_taken: u64,
    pub deopts: u64,
    pub temp_list_elided: u64,
    pub temp_map_elided: u64,
    pub temp_list_materialized: u64,
    pub temp_map_materialized: u64,
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchKind {
    Generic,
    Guard,
    Exit,
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
#[derive(Clone, Copy, Debug)]
pub struct PatchSite {
    pub offset: u32,
    pub kind: BranchKind,
    pub counter_idx: u32,
    pub inverted: bool,
    pub jump_size: u8,
    pub patchable: bool,
    pub invert_taken_jmp_rel32: u32,
    pub invert_not_taken_jmp_rel32: u32,
    pub target_a: u32,
    pub target_b: u32,
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
pub struct JitRuntime {
    pub error: i32,
    pub exit_flag: i32,
    pub deopt_ip: usize,
    pub deopt_sp: usize,
    pub deopt_site: usize,
    pub call_user: Option<JitCallUserFn>,
    pub call_ctx: *mut std::ffi::c_void,
    pub profile_enabled: u8,
    pub run_avx_dot_elements: u64,
    pub run_interp_index_elements: u64,
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
pub fn run_jit(_code: &[Instr], _locals: usize) -> Result<JitExecutable, String> {
    Err("JIT only supported on x86_64".into())
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
pub fn compile_trace(
    _code: &[Instr],
    _start: usize,
    _end: usize,
    _exit_target: usize,
) -> Result<JitExecutable, String> {
    Err("JIT only supported on x86_64".into())
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
pub fn compile_trace_typed(
    _ops: &[TraceOp],
    _temp_list_sources: &[TempListSource],
    _tail_resume_ip: usize,
    _profile_enabled: bool,
    _promoted_locals: &[usize],
    _merge_locals: &[(usize, usize)],
) -> Result<JitExecutable, String> {
    Err("JIT only supported on x86_64".into())
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
pub fn is_supported(_code: &[Instr]) -> bool {
    false
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
pub fn max_stack_depth(_code: &[Instr]) -> usize {
    0
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
impl JitExecutable {
    pub fn run(&self, _locals: &mut [f64], _stack: &mut [f64], _rt: &mut JitRuntime) -> f64 {
        0.0
    }

    pub fn code_len(&self) -> usize {
        0
    }

    pub fn hot_code_len(&self) -> usize {
        0
    }

    pub fn static_call_count(&self) -> u64 {
        0
    }

    pub fn static_branch_count(&self) -> u64 {
        0
    }

    pub fn profile_enabled(&self) -> bool {
        false
    }

    pub fn patch_sites(&self) -> &[PatchSite] {
        &[]
    }

    pub fn patch_flip_site_opcode(&mut self, _site_idx: usize) -> Result<bool, String> {
        Ok(false)
    }
}

#[cfg(any(not(target_arch = "x86_64"), windows))]
impl JitRuntime {
    pub fn new() -> Self {
        Self {
            error: 0,
            exit_flag: 0,
            deopt_ip: 0,
            deopt_sp: 0,
            deopt_site: 0,
            call_user: None,
            call_ctx: std::ptr::null_mut(),
            profile_enabled: 0,
            run_avx_dot_elements: 0,
            run_interp_index_elements: 0,
        }
    }

    pub fn set_profile_enabled(&mut self, enabled: bool) {
        self.profile_enabled = if enabled { 1 } else { 0 };
    }

    pub fn profile_enabled(&self) -> bool {
        self.profile_enabled != 0
    }

    pub fn reset_profile_counters(&mut self) {}

    pub fn set_profile_site_count(&mut self, _count: usize) {}

    pub fn profile_snapshot(&self) -> JitTraceProfile {
        JitTraceProfile::default()
    }

    pub fn profile_site_snapshot(&self, _site_idx: usize) -> Option<(u64, u64)> {
        None
    }

    pub fn reset_path_counters(&mut self) {
        self.run_avx_dot_elements = 0;
        self.run_interp_index_elements = 0;
    }

    pub fn path_counters(&self) -> (u64, u64) {
        (self.run_avx_dot_elements, self.run_interp_index_elements)
    }

    pub fn bump_interp_index_elements(&mut self, count: u64) {
        self.run_interp_index_elements = self.run_interp_index_elements.saturating_add(count);
    }

    pub fn cleanup(&mut self) {}

    pub fn prepare_temp_lists(&mut self, _total_elems: usize, _total_lists: usize) {}

    pub fn prepare_temp_maps(&mut self, _total_maps: usize) {}

    pub fn make_list(&mut self, _data: &[f64]) -> u64 {
        0
    }

    pub fn index(&mut self, _list_bits: u64, _idx_bits: u64) -> f64 {
        0.0
    }

    pub fn setindex(&mut self, _list_bits: u64, _idx_bits: u64, _val_bits: u64) -> u64 {
        0
    }

    pub fn bump_list_version(&mut self, _list_bits: u64) {}

    pub fn len(&mut self, _list_bits: u64) -> f64 {
        0.0
    }

    pub fn make_text(&mut self, _s: &str) -> u64 {
        0
    }

    pub fn make_map(&mut self, _keys: &[String], _values: &[u64]) -> u64 {
        0
    }

    pub fn make_map_temp(&mut self, _keys: &[String], _values: &[u64]) -> u64 {
        0
    }

    pub fn map_get_str(&mut self, _map_bits: u64, _key: &str) -> u64 {
        0
    }

    pub fn map_get(&mut self, _map_bits: u64, _key_bits: u64) -> u64 {
        0
    }

    pub fn map_set(&mut self, _map_bits: u64, _key_bits: u64, _val_bits: u64) -> u64 {
        0
    }

    pub fn map_get_str_slot(&self, _map_bits: u64, _key: &str) -> Option<usize> {
        None
    }

    pub fn map_get_str_slot_ptr(&self, _map_bits: u64, _key: &str) -> Option<u64> {
        None
    }

    pub fn map_get_slot_unchecked(&mut self, _map_bits: u64, _slot_idx: usize) -> u64 {
        0
    }

    pub fn materialize_temps_in_frame(
        &mut self,
        _locals: &mut [f64],
        _stack: &mut [f64],
        _sp: usize,
    ) {
    }

    pub fn to_text_bits(&mut self, _bits: u64) -> u64 {
        0
    }

    pub fn concat_text_bits(&mut self, _a_bits: u64, _b_bits: u64) -> u64 {
        0
    }

    pub fn list_uniform_tag(&self, _list_bits: u64) -> Option<Option<u64>> {
        None
    }

    pub fn map_uniform_value_tag(&self, _map_bits: u64) -> Option<Option<u64>> {
        None
    }

    pub fn list_meta(&self, _list_bits: u64) -> Option<(u64, usize, usize, u64, u64)> {
        None
    }

    pub fn map_meta(&self, _map_bits: u64) -> Option<(u64, usize, u64, u64, usize)> {
        None
    }

    pub fn text_meta(&self, _bits: u64) -> Option<(u64, usize, u64)> {
        None
    }

    pub fn format_bits(&self, _bits: u64) -> String {
        String::new()
    }

    pub fn value_from_bits(&self, _bits: u64) -> crate::runtime::value::Value {
        crate::runtime::value::Value::Null
    }
}

pub fn is_supported_program(prog: &Program) -> bool {
    prog.functions.is_empty() && is_supported(&prog.main)
}
