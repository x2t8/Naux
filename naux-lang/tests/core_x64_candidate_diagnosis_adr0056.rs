#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    frozen_x64_gate_b_policy15_cost_inventory, verify_x64_gate_b_policy15_cost_inventory,
    X64GateBSuccessorOptimizationClass, X64TargetProfileTemplateClass,
    X64_GATE_B_POLICY15_COST_INVENTORY_POLICY_VERSION,
    X64_GATE_B_POLICY15_COST_INVENTORY_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_DIAGNOSTIC_POLICY_VERSION, X64_GATE_B_POLICY15_DIAGNOSTIC_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_FIXED_SYMMETRY_DENOMINATOR, X64_GATE_B_POLICY15_FIXED_SYMMETRY_NUMERATOR,
    X64_GATE_B_POLICY15_INCREMENTAL_SHARE_DENOMINATOR,
    X64_GATE_B_POLICY15_INCREMENTAL_SHARE_NUMERATOR,
    X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_DENOMINATOR,
    X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_NUMERATOR,
    X64_GATE_B_POLICY15_SUCCESSOR_DECISION_POLICY_VERSION,
    X64_GATE_B_POLICY15_SUCCESSOR_DECISION_SCHEMA_VERSION, X64_TARGET_ENCODER_POLICY_VERSION,
};

#[test]
fn adr0056_freezes_sovereign_diagnosis_without_encoder_authority() {
    assert_eq!(X64_GATE_B_POLICY15_COST_INVENTORY_SCHEMA_VERSION, (1, 0, 0));
    assert_eq!(X64_GATE_B_POLICY15_COST_INVENTORY_POLICY_VERSION, (1, 0, 0));
    assert_eq!(X64_GATE_B_POLICY15_DIAGNOSTIC_SCHEMA_VERSION, (1, 0, 0));
    assert_eq!(X64_GATE_B_POLICY15_DIAGNOSTIC_POLICY_VERSION, (1, 0, 0));
    assert_eq!(
        X64_GATE_B_POLICY15_SUCCESSOR_DECISION_SCHEMA_VERSION,
        (1, 0, 0)
    );
    assert_eq!(
        X64_GATE_B_POLICY15_SUCCESSOR_DECISION_POLICY_VERSION,
        (1, 0, 0)
    );
    assert_eq!(
        (
            X64_GATE_B_POLICY15_FIXED_SYMMETRY_NUMERATOR,
            X64_GATE_B_POLICY15_FIXED_SYMMETRY_DENOMINATOR,
        ),
        (5, 4)
    );
    assert_eq!(
        (
            X64_GATE_B_POLICY15_INCREMENTAL_SHARE_NUMERATOR,
            X64_GATE_B_POLICY15_INCREMENTAL_SHARE_DENOMINATOR,
        ),
        (3, 4)
    );
    assert_eq!(
        (
            X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_NUMERATOR,
            X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_DENOMINATOR,
        ),
        (2, 1)
    );

    let inventory = frozen_x64_gate_b_policy15_cost_inventory().expect("frozen inventory");
    let verified = verify_x64_gate_b_policy15_cost_inventory(&inventory)
        .expect("compact inventory verification");
    assert_eq!(
        verified.inventory().inventory_hash().to_hex(),
        "004b3aa514ec558c99ed19526182a6356561026b4db2bcae6e7cb1439c59b338"
    );
    assert_eq!(verified.inventory().baseline_static_bytes(), 3_097);
    assert_eq!(verified.inventory().candidate_static_bytes(), 3_214);
    assert_eq!(verified.inventory().hand_static_bytes(), 158);
    assert_eq!(
        verified.inventory().baseline_weighted_bytes(),
        2_927_032_491
    );
    assert_eq!(
        verified.inventory().candidate_weighted_bytes(),
        2_574_710_635
    );
    assert_eq!(verified.inventory().tail_transfers(), 118_263_305);
    assert_eq!(verified.inventory().tail_argument_words(), 1_309_284_945);
    assert_eq!(
        verified.inventory().structural_leader(),
        X64TargetProfileTemplateClass::TailTransfer
    );
    assert_eq!(
        verified.inventory().proof_only_successor(),
        X64GateBSuccessorOptimizationClass::TailStateTransferElimination
    );

    // ADR-0056 selects only the next proof obligation. Global encoding stays
    // on the last accepted executable policy.
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
}
