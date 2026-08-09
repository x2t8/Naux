//! Sovereign deterministic cost attribution for the rejected ADR-0055
//! policy-1.5 candidate.
//!
//! This evidence multiplies exact canonical target-plan execution counts by
//! exact encoder-owned byte spans. It is a structural cost inventory, not a
//! hardware-cycle measurement, performance claim, or encoder-selection token.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_baseline::{
    x64_gate_b_baseline_target_hash, X64_GATE_B_BASELINE_TARGET_BYTES,
};
use super::x64_gate_b_measurement::X64_GATE_B_ELEMENT_VISITS;
use super::x64_gate_b_profile::{
    x64_gate_b_weighted_profile_hash, VerifiedX64GateBWeightedProfile, X64GateBWeightedProfile,
    X64GateBWeightedProfileError,
};
use super::x64_target::{
    x64_target_policy15_accepted_candidate_capsule_hash, X64TargetProfileTemplateClass,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_GATE_B_POLICY15_COST_INVENTORY_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_COST_INVENTORY_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

const INVENTORY_DOMAIN: &[u8] = b"NAUX:gate-b:policy-1.5:sovereign-cost-inventory:v1\0";
const FROZEN_GATE_B_PROFILE_ROOT: SemanticHash = SemanticHash([
    0xea, 0x09, 0x58, 0xfd, 0x43, 0x46, 0xc0, 0xa2, 0xa2, 0x09, 0xb8, 0x31, 0x63, 0x37, 0x48, 0x70,
    0x97, 0x26, 0xe1, 0xba, 0x23, 0xee, 0x27, 0x12, 0x56, 0x5f, 0x6d, 0x2b, 0xe6, 0x27, 0x22, 0xa5,
]);
const FROZEN_BASELINE_TARGET_SEMANTIC_HASH: SemanticHash = SemanticHash([
    0xa6, 0x42, 0xbc, 0xc0, 0x2f, 0x2e, 0xa3, 0x56, 0x6b, 0x0d, 0x5f, 0x27, 0x57, 0x80, 0xe5, 0xcb,
    0xbe, 0xfe, 0x00, 0x7b, 0x46, 0xa0, 0xea, 0xa5, 0x57, 0x8f, 0x3f, 0x68, 0x0f, 0x83, 0x8e, 0x95,
]);
const FROZEN_BASELINE_TARGET_PLAN_HASH: SemanticHash = SemanticHash([
    0x86, 0xbb, 0x51, 0x38, 0x3c, 0x27, 0x51, 0x7f, 0xa9, 0x8e, 0xc8, 0xd5, 0x8f, 0x3d, 0x2d, 0x77,
    0x97, 0x0b, 0x61, 0xa4, 0x68, 0xef, 0x31, 0xd6, 0x6d, 0xef, 0xa3, 0x35, 0x21, 0x90, 0xc6, 0xbd,
]);
const FROZEN_BASELINE_TARGET_CODE_HASH: SemanticHash = SemanticHash([
    0xef, 0x32, 0x05, 0x1c, 0x5c, 0x7a, 0xf8, 0x13, 0x65, 0xee, 0xe8, 0x26, 0x64, 0x63, 0x6f, 0x0a,
    0x82, 0xbe, 0xf5, 0xb1, 0xde, 0x3a, 0x8e, 0x3d, 0xcc, 0x07, 0xc2, 0xc2, 0x07, 0xd7, 0xce, 0x54,
]);
const FROZEN_PROSPECTIVE_REALIZATION_HASH: SemanticHash = SemanticHash([
    0x17, 0x2b, 0x50, 0x8e, 0x96, 0x48, 0x50, 0x11, 0x62, 0xe2, 0x82, 0x74, 0xaf, 0xa3, 0xbc, 0xec,
    0x06, 0x32, 0xf9, 0xcb, 0x32, 0x12, 0xe3, 0x8f, 0x2b, 0x87, 0xb2, 0x1a, 0xd7, 0x51, 0x61, 0x98,
]);
const FROZEN_PROSPECTIVE_CODE_HASH: SemanticHash = SemanticHash([
    0x0e, 0x39, 0x2c, 0xaf, 0x51, 0xdb, 0xc6, 0x5f, 0x9e, 0x36, 0xe0, 0x8c, 0x67, 0x81, 0x18, 0xe7,
    0x8b, 0x8f, 0x6a, 0xed, 0x90, 0xbf, 0x1d, 0xf0, 0xed, 0xbf, 0x4b, 0x5c, 0x6a, 0x5f, 0x51, 0x73,
]);
const FROZEN_CANDIDATE_PLAN_HASH: SemanticHash = SemanticHash([
    0xf2, 0x14, 0x5a, 0xc0, 0x6a, 0x2c, 0x0c, 0xb7, 0x89, 0xac, 0xed, 0x9a, 0x87, 0x51, 0xf6, 0xc6,
    0xcb, 0xe8, 0xdd, 0xc1, 0x45, 0x75, 0xa4, 0xcc, 0xbf, 0xa5, 0xb4, 0x7f, 0x3f, 0xd9, 0xc5, 0xbd,
]);
const FROZEN_CANDIDATE_CODE_HASH: SemanticHash = SemanticHash([
    0xea, 0x16, 0x46, 0xe5, 0x17, 0x56, 0x2e, 0x42, 0xb2, 0x46, 0x94, 0x20, 0xd6, 0xe4, 0xb4, 0xe1,
    0x6d, 0x86, 0xdc, 0xc9, 0x45, 0x8a, 0xb0, 0x33, 0x63, 0xac, 0xac, 0x60, 0xaa, 0x02, 0xb9, 0x91,
]);
const FROZEN_CANDIDATE_SEMANTIC_HASH: SemanticHash = SemanticHash([
    0x4a, 0x29, 0x0f, 0xde, 0x1e, 0xaf, 0x4c, 0x0d, 0xf9, 0x83, 0x83, 0x81, 0x8a, 0xf4, 0xa1, 0x8b,
    0x53, 0x1a, 0xe6, 0xd8, 0x6f, 0x5d, 0x85, 0x99, 0x26, 0xe6, 0x3f, 0x46, 0x20, 0xfd, 0xe9, 0x9c,
]);

const EXPECTED_BASELINE_STATIC_BYTES: u64 = 3_097;
const EXPECTED_BASELINE_WEIGHTED_BYTES: u128 = 2_927_032_491;
const EXPECTED_CANDIDATE_STATIC_BYTES: u64 = 3_214;
const EXPECTED_CANDIDATE_WEIGHTED_BYTES: u128 = 2_574_710_635;
const EXPECTED_CANDIDATE_ATOMS: u64 = 199;
const FROZEN_INVENTORY_HASH: SemanticHash = SemanticHash([
    0x00, 0x4b, 0x3a, 0xa5, 0x14, 0xec, 0x55, 0x8c, 0x99, 0xed, 0x19, 0x52, 0x61, 0x82, 0xa6, 0x35,
    0x65, 0x61, 0x02, 0x6b, 0x4d, 0xb2, 0xbc, 0xae, 0x6e, 0x7c, 0xb1, 0x43, 0x9c, 0x59, 0xb3, 0x38,
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64GateBCostClassTotal {
    pub class: X64TargetProfileTemplateClass,
    pub sites_or_atoms: u32,
    pub static_bytes: u64,
    pub executions: u64,
    pub weighted_bytes: u128,
}

const FROZEN_BASELINE_CLASSES: [X64GateBCostClassTotal; 11] = [
    class_total(X64TargetProfileTemplateClass::EntryPrologue, 1, 99, 1, 99),
    class_total(
        X64TargetProfileTemplateClass::OrdinaryInstruction,
        3,
        139,
        8_388_608,
        348_127_232,
    ),
    class_total(
        X64TargetProfileTemplateClass::RegisterInstruction,
        11,
        220,
        9_123_820,
        227_359_264,
    ),
    class_total(
        X64TargetProfileTemplateClass::TailTransfer,
        30,
        1_939,
        29_360_258,
        1_799_362_381,
    ),
    class_total(X64TargetProfileTemplateClass::ReturnTransfer, 3, 114, 1, 38),
    class_total(
        X64TargetProfileTemplateClass::BranchCondition,
        9,
        54,
        12_583_041,
        75_498_246,
    ),
    class_total(
        X64TargetProfileTemplateClass::BranchElseJump,
        9,
        45,
        9_772_360,
        48_861_800,
    ),
    class_total(
        X64TargetProfileTemplateClass::FusedCompareInstruction,
        9,
        306,
        12_583_041,
        427_823_394,
    ),
    class_total(X64TargetProfileTemplateClass::ReturnEpilogue, 1, 37, 1, 37),
    class_total(X64TargetProfileTemplateClass::BoundsEpilogue, 1, 42, 0, 0),
    class_total(X64TargetProfileTemplateClass::Tombstone, 102, 102, 0, 0),
];

const FROZEN_CANDIDATE_CLASSES: [X64GateBCostClassTotal; 11] = [
    class_total(X64TargetProfileTemplateClass::EntryPrologue, 1, 99, 1, 99),
    class_total(
        X64TargetProfileTemplateClass::OrdinaryInstruction,
        2,
        112,
        4_194_304,
        234_881_024,
    ),
    class_total(
        X64TargetProfileTemplateClass::RegisterInstruction,
        13,
        268,
        13_318_124,
        328_022_560,
    ),
    class_total(
        X64TargetProfileTemplateClass::TailTransfer,
        29,
        1_805,
        25_165_954,
        1_459_623_437,
    ),
    class_total(X64TargetProfileTemplateClass::ReturnTransfer, 3, 114, 1, 38),
    class_total(
        X64TargetProfileTemplateClass::BranchCondition,
        14,
        84,
        12_583_041,
        75_498_246,
    ),
    class_total(
        X64TargetProfileTemplateClass::BranchElseJump,
        14,
        70,
        9_772_360,
        48_861_800,
    ),
    class_total(
        X64TargetProfileTemplateClass::FusedCompareInstruction,
        14,
        476,
        12_583_041,
        427_823_394,
    ),
    class_total(X64TargetProfileTemplateClass::ReturnEpilogue, 1, 37, 1, 37),
    class_total(X64TargetProfileTemplateClass::BoundsEpilogue, 1, 42, 0, 0),
    class_total(X64TargetProfileTemplateClass::Tombstone, 107, 107, 0, 0),
];

const FROZEN_CANDIDATE_RANK: [X64TargetProfileTemplateClass; 11] = [
    X64TargetProfileTemplateClass::TailTransfer,
    X64TargetProfileTemplateClass::FusedCompareInstruction,
    X64TargetProfileTemplateClass::RegisterInstruction,
    X64TargetProfileTemplateClass::OrdinaryInstruction,
    X64TargetProfileTemplateClass::BranchCondition,
    X64TargetProfileTemplateClass::BranchElseJump,
    X64TargetProfileTemplateClass::EntryPrologue,
    X64TargetProfileTemplateClass::ReturnTransfer,
    X64TargetProfileTemplateClass::ReturnEpilogue,
    X64TargetProfileTemplateClass::BoundsEpilogue,
    X64TargetProfileTemplateClass::Tombstone,
];

const fn class_total(
    class: X64TargetProfileTemplateClass,
    sites_or_atoms: u32,
    static_bytes: u64,
    executions: u64,
    weighted_bytes: u128,
) -> X64GateBCostClassTotal {
    X64GateBCostClassTotal {
        class,
        sites_or_atoms,
        static_bytes,
        executions,
        weighted_bytes,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64GateBSuccessorOptimizationClass {
    /// Eliminate repeated frame-home materialization and argument shuffling
    /// across canonical tail transfers while preserving the target-plan ABI.
    TailStateTransferElimination,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15CostInventory {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    weighted_profile_root: SemanticHash,
    baseline_target_semantic_hash: SemanticHash,
    baseline_target_plan_hash: SemanticHash,
    baseline_target_code_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    prospective_realization_hash: SemanticHash,
    prospective_candidate_code_hash: SemanticHash,
    candidate_target_plan_hash: SemanticHash,
    candidate_target_code_hash: SemanticHash,
    candidate_target_semantic_hash: SemanticHash,
    hand_baseline_target_hash: SemanticHash,
    element_visits: u64,
    baseline_static_bytes: u64,
    candidate_static_bytes: u64,
    hand_static_bytes: u64,
    baseline_weighted_bytes: u128,
    candidate_weighted_bytes: u128,
    candidate_atoms: u64,
    tail_transfers: u64,
    tail_argument_values: u64,
    tail_argument_words: u64,
    branches: u64,
    checked_array_gets: u64,
    baseline_classes: Vec<X64GateBCostClassTotal>,
    candidate_classes: Vec<X64GateBCostClassTotal>,
    ranked_candidate_classes: Vec<X64TargetProfileTemplateClass>,
    structural_leader: X64TargetProfileTemplateClass,
    proof_only_successor: X64GateBSuccessorOptimizationClass,
    inventory_hash: SemanticHash,
}

impl X64GateBPolicy15CostInventory {
    pub const fn weighted_profile_root(&self) -> SemanticHash {
        self.weighted_profile_root
    }

    pub const fn candidate_capsule_hash(&self) -> SemanticHash {
        self.candidate_capsule_hash
    }

    pub const fn baseline_static_bytes(&self) -> u64 {
        self.baseline_static_bytes
    }

    pub const fn candidate_static_bytes(&self) -> u64 {
        self.candidate_static_bytes
    }

    pub const fn hand_static_bytes(&self) -> u64 {
        self.hand_static_bytes
    }

    pub const fn baseline_weighted_bytes(&self) -> u128 {
        self.baseline_weighted_bytes
    }

    pub const fn candidate_weighted_bytes(&self) -> u128 {
        self.candidate_weighted_bytes
    }

    pub const fn tail_transfers(&self) -> u64 {
        self.tail_transfers
    }

    pub const fn tail_argument_words(&self) -> u64 {
        self.tail_argument_words
    }

    pub fn baseline_classes(&self) -> &[X64GateBCostClassTotal] {
        &self.baseline_classes
    }

    pub fn candidate_classes(&self) -> &[X64GateBCostClassTotal] {
        &self.candidate_classes
    }

    pub fn ranked_candidate_classes(&self) -> &[X64TargetProfileTemplateClass] {
        &self.ranked_candidate_classes
    }

    pub const fn structural_leader(&self) -> X64TargetProfileTemplateClass {
        self.structural_leader
    }

    pub const fn proof_only_successor(&self) -> X64GateBSuccessorOptimizationClass {
        self.proof_only_successor
    }

    pub const fn inventory_hash(&self) -> SemanticHash {
        self.inventory_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64GateBPolicy15CostInventory<'inventory> {
    inventory: &'inventory X64GateBPolicy15CostInventory,
}

impl<'inventory> VerifiedX64GateBPolicy15CostInventory<'inventory> {
    pub const fn inventory(self) -> &'inventory X64GateBPolicy15CostInventory {
        self.inventory
    }
}

#[derive(Debug)]
pub enum X64GateBPolicy15CostInventoryError {
    Profile(X64GateBWeightedProfileError),
    InvalidField { field: &'static str },
    ArithmeticOverflow { field: &'static str },
    InventoryHashMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64GateBPolicy15CostInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(error) => write!(formatter, "cost inventory profile failed: {error}"),
            Self::InvalidField { field } => {
                write!(formatter, "cost inventory has invalid {field}")
            }
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "cost inventory overflowed {field}")
            }
            Self::InventoryHashMismatch => {
                formatter.write_str("cost inventory seal does not replay")
            }
            Self::ReplayMismatch => {
                formatter.write_str("cost inventory differs from exact weighted-profile replay")
            }
        }
    }
}

impl std::error::Error for X64GateBPolicy15CostInventoryError {}

impl From<X64GateBWeightedProfileError> for X64GateBPolicy15CostInventoryError {
    fn from(value: X64GateBWeightedProfileError) -> Self {
        Self::Profile(value)
    }
}

pub fn emit_x64_gate_b_policy15_cost_inventory(
    verified_profile: VerifiedX64GateBWeightedProfile<'_>,
) -> Result<X64GateBPolicy15CostInventory, X64GateBPolicy15CostInventoryError> {
    build_inventory(verified_profile.profile())
}

pub fn verify_x64_gate_b_policy15_cost_inventory<'inventory>(
    inventory: &'inventory X64GateBPolicy15CostInventory,
) -> Result<VerifiedX64GateBPolicy15CostInventory<'inventory>, X64GateBPolicy15CostInventoryError> {
    validate_inventory(inventory)?;
    if inventory_hash(inventory)? != inventory.inventory_hash {
        return Err(X64GateBPolicy15CostInventoryError::InventoryHashMismatch);
    }
    if inventory.inventory_hash != FROZEN_INVENTORY_HASH {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "accepted inventory root",
        });
    }
    Ok(VerifiedX64GateBPolicy15CostInventory { inventory })
}

pub fn verify_x64_gate_b_policy15_cost_inventory_against_profile<'inventory>(
    inventory: &'inventory X64GateBPolicy15CostInventory,
    verified_profile: VerifiedX64GateBWeightedProfile<'_>,
) -> Result<VerifiedX64GateBPolicy15CostInventory<'inventory>, X64GateBPolicy15CostInventoryError> {
    let verified = verify_x64_gate_b_policy15_cost_inventory(inventory)?;
    let replayed = build_inventory(verified_profile.profile())?;
    if replayed != *inventory {
        return Err(X64GateBPolicy15CostInventoryError::ReplayMismatch);
    }
    Ok(verified)
}

/// Rebuild the compact accepted ledger without replaying the 2.526-billion
/// canonical target steps. The frozen root was admitted only after the full
/// release replay; this constructor grants evidence inspection, never target
/// or encoder authority.
pub fn frozen_x64_gate_b_policy15_cost_inventory(
) -> Result<X64GateBPolicy15CostInventory, X64GateBPolicy15CostInventoryError> {
    let mut inventory = X64GateBPolicy15CostInventory {
        schema_version: X64_GATE_B_POLICY15_COST_INVENTORY_SCHEMA_VERSION,
        policy_version: X64_GATE_B_POLICY15_COST_INVENTORY_POLICY_VERSION,
        weighted_profile_root: FROZEN_GATE_B_PROFILE_ROOT,
        baseline_target_semantic_hash: FROZEN_BASELINE_TARGET_SEMANTIC_HASH,
        baseline_target_plan_hash: FROZEN_BASELINE_TARGET_PLAN_HASH,
        baseline_target_code_hash: FROZEN_BASELINE_TARGET_CODE_HASH,
        candidate_capsule_hash: x64_target_policy15_accepted_candidate_capsule_hash(),
        prospective_realization_hash: FROZEN_PROSPECTIVE_REALIZATION_HASH,
        prospective_candidate_code_hash: FROZEN_PROSPECTIVE_CODE_HASH,
        candidate_target_plan_hash: FROZEN_CANDIDATE_PLAN_HASH,
        candidate_target_code_hash: FROZEN_CANDIDATE_CODE_HASH,
        candidate_target_semantic_hash: FROZEN_CANDIDATE_SEMANTIC_HASH,
        hand_baseline_target_hash: x64_gate_b_baseline_target_hash(),
        element_visits: X64_GATE_B_ELEMENT_VISITS,
        baseline_static_bytes: EXPECTED_BASELINE_STATIC_BYTES,
        candidate_static_bytes: EXPECTED_CANDIDATE_STATIC_BYTES,
        hand_static_bytes: u64::from(X64_GATE_B_BASELINE_TARGET_BYTES),
        baseline_weighted_bytes: EXPECTED_BASELINE_WEIGHTED_BYTES,
        candidate_weighted_bytes: EXPECTED_CANDIDATE_WEIGHTED_BYTES,
        candidate_atoms: EXPECTED_CANDIDATE_ATOMS,
        tail_transfers: 118_263_305,
        tail_argument_values: 1_182_632_968,
        tail_argument_words: 1_309_284_945,
        branches: 12_583_041,
        checked_array_gets: X64_GATE_B_ELEMENT_VISITS,
        baseline_classes: FROZEN_BASELINE_CLASSES.to_vec(),
        candidate_classes: FROZEN_CANDIDATE_CLASSES.to_vec(),
        ranked_candidate_classes: FROZEN_CANDIDATE_RANK.to_vec(),
        structural_leader: X64TargetProfileTemplateClass::TailTransfer,
        proof_only_successor: X64GateBSuccessorOptimizationClass::TailStateTransferElimination,
        inventory_hash: SemanticHash::ZERO,
    };
    validate_inventory(&inventory)?;
    inventory.inventory_hash = inventory_hash(&inventory)?;
    if inventory.inventory_hash != FROZEN_INVENTORY_HASH {
        return Err(X64GateBPolicy15CostInventoryError::InventoryHashMismatch);
    }
    Ok(inventory)
}

fn build_inventory(
    weighted: &X64GateBWeightedProfile,
) -> Result<X64GateBPolicy15CostInventory, X64GateBPolicy15CostInventoryError> {
    let weighted_profile_root = x64_gate_b_weighted_profile_hash(weighted)?;
    if weighted_profile_root != FROZEN_GATE_B_PROFILE_ROOT
        || weighted.profile_hash() != FROZEN_GATE_B_PROFILE_ROOT
    {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "weighted profile root",
        });
    }
    let profile = weighted.profile();
    let prospective = &profile.prospective_shared_join_realization;
    if !prospective.complete
        || prospective.realization_hash != FROZEN_PROSPECTIVE_REALIZATION_HASH
        || prospective.candidate_code_hash != FROZEN_PROSPECTIVE_CODE_HASH
        || prospective.baseline_code_bytes != EXPECTED_BASELINE_STATIC_BYTES
        || prospective.candidate_code_bytes != EXPECTED_CANDIDATE_STATIC_BYTES
        || prospective.candidate_atom_count != EXPECTED_CANDIDATE_ATOMS
    {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "prospective realization identity",
        });
    }

    let mut baseline_classes = profile
        .class_totals
        .iter()
        .map(|total| X64GateBCostClassTotal {
            class: total.class,
            sites_or_atoms: total.sites,
            static_bytes: total.static_bytes,
            executions: total.executions,
            weighted_bytes: total.weighted_bytes,
        })
        .collect::<Vec<_>>();
    baseline_classes.sort_by_key(|total| total.class);

    let mut candidate_map =
        BTreeMap::<X64TargetProfileTemplateClass, X64GateBCostClassTotal>::new();
    for atom in &prospective.atoms {
        if atom.weighted_bytes
            != u128::from(atom.static_bytes)
                .checked_mul(u128::from(atom.executions))
                .ok_or(X64GateBPolicy15CostInventoryError::ArithmeticOverflow {
                    field: "candidate atom weighted bytes",
                })?
        {
            return Err(X64GateBPolicy15CostInventoryError::InvalidField {
                field: "candidate atom weighted bytes",
            });
        }
        let total = candidate_map
            .entry(atom.class)
            .or_insert(X64GateBCostClassTotal {
                class: atom.class,
                sites_or_atoms: 0,
                static_bytes: 0,
                executions: 0,
                weighted_bytes: 0,
            });
        total.sites_or_atoms = total.sites_or_atoms.checked_add(1).ok_or(
            X64GateBPolicy15CostInventoryError::ArithmeticOverflow {
                field: "candidate atom count",
            },
        )?;
        total.static_bytes = total
            .static_bytes
            .checked_add(u64::from(atom.static_bytes))
            .ok_or(X64GateBPolicy15CostInventoryError::ArithmeticOverflow {
                field: "candidate class static bytes",
            })?;
        total.executions = total.executions.checked_add(atom.executions).ok_or(
            X64GateBPolicy15CostInventoryError::ArithmeticOverflow {
                field: "candidate class executions",
            },
        )?;
        total.weighted_bytes = total
            .weighted_bytes
            .checked_add(atom.weighted_bytes)
            .ok_or(X64GateBPolicy15CostInventoryError::ArithmeticOverflow {
                field: "candidate class weighted bytes",
            })?;
    }
    let candidate_classes = candidate_map.into_values().collect::<Vec<_>>();
    let mut ranked_candidate_classes = candidate_classes.clone();
    ranked_candidate_classes.sort_by(|left, right| {
        right
            .weighted_bytes
            .cmp(&left.weighted_bytes)
            .then_with(|| left.class.cmp(&right.class))
    });
    let structural_leader = ranked_candidate_classes
        .first()
        .map(|total| total.class)
        .ok_or(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "candidate class totals",
        })?;
    let ranked_candidate_classes = ranked_candidate_classes
        .into_iter()
        .map(|total| total.class)
        .collect::<Vec<_>>();

    let mut inventory = X64GateBPolicy15CostInventory {
        schema_version: X64_GATE_B_POLICY15_COST_INVENTORY_SCHEMA_VERSION,
        policy_version: X64_GATE_B_POLICY15_COST_INVENTORY_POLICY_VERSION,
        weighted_profile_root,
        baseline_target_semantic_hash: weighted.target_semantic_hash(),
        baseline_target_plan_hash: weighted.target_plan_hash(),
        baseline_target_code_hash: weighted.target_code_hash(),
        candidate_capsule_hash: x64_target_policy15_accepted_candidate_capsule_hash(),
        prospective_realization_hash: prospective.realization_hash,
        prospective_candidate_code_hash: prospective.candidate_code_hash,
        candidate_target_plan_hash: FROZEN_CANDIDATE_PLAN_HASH,
        candidate_target_code_hash: FROZEN_CANDIDATE_CODE_HASH,
        candidate_target_semantic_hash: FROZEN_CANDIDATE_SEMANTIC_HASH,
        hand_baseline_target_hash: x64_gate_b_baseline_target_hash(),
        element_visits: X64_GATE_B_ELEMENT_VISITS,
        baseline_static_bytes: profile.static_code_bytes,
        candidate_static_bytes: prospective.candidate_code_bytes,
        hand_static_bytes: u64::from(X64_GATE_B_BASELINE_TARGET_BYTES),
        baseline_weighted_bytes: profile.weighted_template_bytes,
        candidate_weighted_bytes: prospective.candidate_weighted_template_bytes,
        candidate_atoms: prospective.candidate_atom_count,
        tail_transfers: profile.control_counts.tail_transfers,
        tail_argument_values: profile.control_counts.tail_argument_values,
        tail_argument_words: profile.control_counts.tail_argument_words,
        branches: profile.control_counts.branches,
        checked_array_gets: profile.instruction_counts.checked_array_gets,
        baseline_classes,
        candidate_classes,
        ranked_candidate_classes,
        structural_leader,
        proof_only_successor: X64GateBSuccessorOptimizationClass::TailStateTransferElimination,
        inventory_hash: SemanticHash::ZERO,
    };
    validate_inventory(&inventory)?;
    inventory.inventory_hash = inventory_hash(&inventory)?;
    Ok(inventory)
}

fn validate_inventory(
    inventory: &X64GateBPolicy15CostInventory,
) -> Result<(), X64GateBPolicy15CostInventoryError> {
    if inventory.schema_version != X64_GATE_B_POLICY15_COST_INVENTORY_SCHEMA_VERSION
        || inventory.policy_version != X64_GATE_B_POLICY15_COST_INVENTORY_POLICY_VERSION
        || inventory.weighted_profile_root != FROZEN_GATE_B_PROFILE_ROOT
        || inventory.baseline_target_semantic_hash != FROZEN_BASELINE_TARGET_SEMANTIC_HASH
        || inventory.baseline_target_plan_hash != FROZEN_BASELINE_TARGET_PLAN_HASH
        || inventory.baseline_target_code_hash != FROZEN_BASELINE_TARGET_CODE_HASH
        || inventory.candidate_capsule_hash != x64_target_policy15_accepted_candidate_capsule_hash()
        || inventory.prospective_realization_hash != FROZEN_PROSPECTIVE_REALIZATION_HASH
        || inventory.prospective_candidate_code_hash != FROZEN_PROSPECTIVE_CODE_HASH
        || inventory.candidate_target_plan_hash != FROZEN_CANDIDATE_PLAN_HASH
        || inventory.candidate_target_code_hash != FROZEN_CANDIDATE_CODE_HASH
        || inventory.candidate_target_semantic_hash != FROZEN_CANDIDATE_SEMANTIC_HASH
        || inventory.hand_baseline_target_hash != x64_gate_b_baseline_target_hash()
    {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "frozen identity",
        });
    }
    if inventory.element_visits != X64_GATE_B_ELEMENT_VISITS
        || inventory.baseline_static_bytes != EXPECTED_BASELINE_STATIC_BYTES
        || inventory.candidate_static_bytes != EXPECTED_CANDIDATE_STATIC_BYTES
        || inventory.hand_static_bytes != u64::from(X64_GATE_B_BASELINE_TARGET_BYTES)
        || inventory.baseline_weighted_bytes != EXPECTED_BASELINE_WEIGHTED_BYTES
        || inventory.candidate_weighted_bytes != EXPECTED_CANDIDATE_WEIGHTED_BYTES
        || inventory.candidate_atoms != EXPECTED_CANDIDATE_ATOMS
        || inventory.checked_array_gets != X64_GATE_B_ELEMENT_VISITS
        || inventory.tail_transfers != 118_263_305
        || inventory.tail_argument_values != 1_182_632_968
        || inventory.tail_argument_words != 1_309_284_945
        || inventory.branches != 12_583_041
    {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "frozen cost totals",
        });
    }
    validate_class_totals(
        &inventory.baseline_classes,
        inventory.baseline_static_bytes,
        inventory.baseline_weighted_bytes,
        "baseline class totals",
    )?;
    if inventory.baseline_classes != FROZEN_BASELINE_CLASSES
        || inventory.candidate_classes != FROZEN_CANDIDATE_CLASSES
        || inventory.ranked_candidate_classes != FROZEN_CANDIDATE_RANK
    {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "frozen class ledger",
        });
    }
    validate_class_totals(
        &inventory.candidate_classes,
        inventory.candidate_static_bytes,
        inventory.candidate_weighted_bytes,
        "candidate class totals",
    )?;
    let candidate_atom_sum = inventory
        .candidate_classes
        .iter()
        .try_fold(0_u64, |sum, total| {
            sum.checked_add(u64::from(total.sites_or_atoms)).ok_or(
                X64GateBPolicy15CostInventoryError::ArithmeticOverflow {
                    field: "candidate atom total",
                },
            )
        })?;
    if candidate_atom_sum != inventory.candidate_atoms {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "candidate atom total",
        });
    }
    let mut expected_rank = inventory.candidate_classes.clone();
    expected_rank.sort_by(|left, right| {
        right
            .weighted_bytes
            .cmp(&left.weighted_bytes)
            .then_with(|| left.class.cmp(&right.class))
    });
    let expected_rank = expected_rank
        .into_iter()
        .map(|total| total.class)
        .collect::<Vec<_>>();
    if expected_rank != inventory.ranked_candidate_classes
        || expected_rank.first().copied() != Some(inventory.structural_leader)
        || inventory.structural_leader != X64TargetProfileTemplateClass::TailTransfer
        || inventory.proof_only_successor
            != X64GateBSuccessorOptimizationClass::TailStateTransferElimination
    {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField {
            field: "canonical structural ranking",
        });
    }
    Ok(())
}

fn validate_class_totals(
    totals: &[X64GateBCostClassTotal],
    expected_static: u64,
    expected_weighted: u128,
    field: &'static str,
) -> Result<(), X64GateBPolicy15CostInventoryError> {
    if totals.is_empty() {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField { field });
    }
    let mut seen = BTreeSet::new();
    let mut previous = None;
    let mut static_sum = 0_u64;
    let mut weighted_sum = 0_u128;
    for total in totals {
        if total.sites_or_atoms == 0
            || total.static_bytes == 0
            || (total.executions == 0) != (total.weighted_bytes == 0)
            || previous.is_some_and(|class| class >= total.class)
            || !seen.insert(total.class)
        {
            return Err(X64GateBPolicy15CostInventoryError::InvalidField { field });
        }
        previous = Some(total.class);
        static_sum = static_sum
            .checked_add(total.static_bytes)
            .ok_or(X64GateBPolicy15CostInventoryError::ArithmeticOverflow { field })?;
        weighted_sum = weighted_sum
            .checked_add(total.weighted_bytes)
            .ok_or(X64GateBPolicy15CostInventoryError::ArithmeticOverflow { field })?;
    }
    if static_sum != expected_static || weighted_sum != expected_weighted {
        return Err(X64GateBPolicy15CostInventoryError::InvalidField { field });
    }
    Ok(())
}

fn inventory_hash(
    inventory: &X64GateBPolicy15CostInventory,
) -> Result<SemanticHash, X64GateBPolicy15CostInventoryError> {
    let mut bytes = Vec::with_capacity(
        INVENTORY_DOMAIN.len()
            + 512
            + (inventory.baseline_classes.len() + inventory.candidate_classes.len()) * 37
            + inventory.ranked_candidate_classes.len(),
    );
    bytes.extend_from_slice(INVENTORY_DOMAIN);
    put_version(&mut bytes, inventory.schema_version);
    put_version(&mut bytes, inventory.policy_version);
    for hash in [
        inventory.weighted_profile_root,
        inventory.baseline_target_semantic_hash,
        inventory.baseline_target_plan_hash,
        inventory.baseline_target_code_hash,
        inventory.candidate_capsule_hash,
        inventory.prospective_realization_hash,
        inventory.prospective_candidate_code_hash,
        inventory.candidate_target_plan_hash,
        inventory.candidate_target_code_hash,
        inventory.candidate_target_semantic_hash,
        inventory.hand_baseline_target_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    for value in [
        inventory.element_visits,
        inventory.baseline_static_bytes,
        inventory.candidate_static_bytes,
        inventory.hand_static_bytes,
        inventory.candidate_atoms,
        inventory.tail_transfers,
        inventory.tail_argument_values,
        inventory.tail_argument_words,
        inventory.branches,
        inventory.checked_array_gets,
    ] {
        put_u64(&mut bytes, value);
    }
    put_u128(&mut bytes, inventory.baseline_weighted_bytes);
    put_u128(&mut bytes, inventory.candidate_weighted_bytes);
    put_totals(&mut bytes, &inventory.baseline_classes)?;
    put_totals(&mut bytes, &inventory.candidate_classes)?;
    put_u32(
        &mut bytes,
        u32::try_from(inventory.ranked_candidate_classes.len()).map_err(|_| {
            X64GateBPolicy15CostInventoryError::ArithmeticOverflow {
                field: "ranked class count",
            }
        })?,
    );
    for class in &inventory.ranked_candidate_classes {
        bytes.push(class_tag(*class));
    }
    bytes.push(class_tag(inventory.structural_leader));
    bytes.push(successor_tag(inventory.proof_only_successor));
    Ok(SemanticHash(sha256(&bytes)))
}

fn put_totals(
    bytes: &mut Vec<u8>,
    totals: &[X64GateBCostClassTotal],
) -> Result<(), X64GateBPolicy15CostInventoryError> {
    put_u32(
        bytes,
        u32::try_from(totals.len()).map_err(|_| {
            X64GateBPolicy15CostInventoryError::ArithmeticOverflow {
                field: "class total count",
            }
        })?,
    );
    for total in totals {
        bytes.push(class_tag(total.class));
        put_u32(bytes, total.sites_or_atoms);
        put_u64(bytes, total.static_bytes);
        put_u64(bytes, total.executions);
        put_u128(bytes, total.weighted_bytes);
    }
    Ok(())
}

fn class_tag(class: X64TargetProfileTemplateClass) -> u8 {
    match class {
        X64TargetProfileTemplateClass::EntryPrologue => 0,
        X64TargetProfileTemplateClass::OrdinaryInstruction => 1,
        X64TargetProfileTemplateClass::RegisterInstruction => 2,
        X64TargetProfileTemplateClass::TailTransfer => 3,
        X64TargetProfileTemplateClass::ReturnTransfer => 4,
        X64TargetProfileTemplateClass::BranchCondition => 5,
        X64TargetProfileTemplateClass::BranchElseJump => 6,
        X64TargetProfileTemplateClass::FusedCompareInstruction => 7,
        X64TargetProfileTemplateClass::ReturnEpilogue => 8,
        X64TargetProfileTemplateClass::BoundsEpilogue => 9,
        X64TargetProfileTemplateClass::Tombstone => 10,
    }
}

fn successor_tag(successor: X64GateBSuccessorOptimizationClass) -> u8 {
    match successor {
        X64GateBSuccessorOptimizationClass::TailStateTransferElimination => 0,
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u128(bytes: &mut Vec<u8>, value: u128) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::super::x64_gate_b_profile::emit_x64_gate_b_weighted_profile;
    use super::*;

    #[test]
    fn frozen_ledger_is_exact_and_adversarial_mutations_fail_after_resealing() {
        let inventory = frozen_x64_gate_b_policy15_cost_inventory().expect("frozen inventory");
        let verified =
            verify_x64_gate_b_policy15_cost_inventory(&inventory).expect("verified inventory");
        assert_eq!(verified.inventory().inventory_hash(), FROZEN_INVENTORY_HASH);
        assert_eq!(
            verified.inventory().ranked_candidate_classes(),
            FROZEN_CANDIDATE_RANK
        );

        let mut unsealed = inventory.clone();
        unsealed.inventory_hash = SemanticHash::ZERO;
        assert!(matches!(
            verify_x64_gate_b_policy15_cost_inventory(&unsealed),
            Err(X64GateBPolicy15CostInventoryError::InventoryHashMismatch)
        ));

        let mut class_tampered = inventory.clone();
        class_tampered.candidate_classes[3].weighted_bytes += 1;
        class_tampered.inventory_hash = inventory_hash(&class_tampered).expect("local reseal");
        assert!(matches!(
            verify_x64_gate_b_policy15_cost_inventory(&class_tampered),
            Err(X64GateBPolicy15CostInventoryError::InvalidField { .. })
        ));

        let mut identity_tampered = inventory.clone();
        identity_tampered.baseline_target_semantic_hash.0[0] ^= 1;
        identity_tampered.inventory_hash =
            inventory_hash(&identity_tampered).expect("local reseal");
        assert!(matches!(
            verify_x64_gate_b_policy15_cost_inventory(&identity_tampered),
            Err(X64GateBPolicy15CostInventoryError::InvalidField { .. })
        ));

        let mut rank_tampered = inventory;
        rank_tampered.ranked_candidate_classes.swap(0, 1);
        rank_tampered.inventory_hash = inventory_hash(&rank_tampered).expect("local reseal");
        assert!(matches!(
            verify_x64_gate_b_policy15_cost_inventory(&rank_tampered),
            Err(X64GateBPolicy15CostInventoryError::InvalidField { .. })
        ));
    }

    #[test]
    #[ignore = "regenerates the complete 2.526-billion-step Gate B profile; run explicitly in release mode"]
    fn regenerate_and_print_exact_cost_inventory() {
        let profile = emit_x64_gate_b_weighted_profile().expect("weighted profile");
        let inventory = build_inventory(&profile).expect("cost inventory");
        verify_x64_gate_b_policy15_cost_inventory(&inventory).expect("compact verification");
        println!("inventory_hash={}", inventory.inventory_hash.to_hex());
        println!("baseline={:?}", inventory.baseline_classes);
        println!("candidate={:?}", inventory.candidate_classes);
        println!("ranked={:?}", inventory.ranked_candidate_classes);
        println!(
            "tail_transfers={} tail_values={} tail_words={} branches={} array_gets={}",
            inventory.tail_transfers,
            inventory.tail_argument_values,
            inventory.tail_argument_words,
            inventory.branches,
            inventory.checked_array_gets,
        );
    }
}
