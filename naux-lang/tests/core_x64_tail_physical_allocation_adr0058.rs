#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    emit_x64_tail_physical_allocation, emit_x64_tail_state_plan, lower_core_ssa_r1_s5,
    lower_machine_ir_r1_s6, lower_x64_target_r1_s7a, verify_x64_tail_physical_allocation,
    CoreArtifact, CoreProfile, EffectRow, Function, FunctionId, Operand, Program, SchemaVersion,
    Term, Type, X64TailPhysicalRegionDisposition, X64_TAIL_PHYSICAL_GPR_LANES,
    X64_TAIL_PHYSICAL_POLICY_VERSION, X64_TAIL_PHYSICAL_SCHEMA_VERSION,
    X64_TAIL_PHYSICAL_XMM_LANES, X64_TARGET_ENCODER_POLICY_VERSION,
};

fn direct_tail_source() -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions: vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::TailCall {
                    function: FunctionId(1),
                    arguments: vec![],
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Return(Operand::I64(7)),
            },
        ],
    })
    .expect("direct-tail fixture must seal")
}

#[test]
fn adr0058_public_boundary_allocates_without_emitting_or_selecting_code() {
    let source = direct_tail_source();
    let ssa = lower_core_ssa_r1_s5(&source).expect("fixture must lower to SSA");
    let machine = lower_machine_ir_r1_s6(&ssa, &source).expect("fixture must lower to Machine IR");
    let target =
        lower_x64_target_r1_s7a(&machine, &ssa, &source).expect("fixture must lower to x86-64");
    let original_code = target.program.code.clone();
    let original_code_hash = target.program.code_hash;

    let logical = emit_x64_tail_state_plan(&target).expect("logical plan must emit");
    let allocation = emit_x64_tail_physical_allocation(&target, &logical)
        .expect("physical allocation must emit");
    let verified = verify_x64_tail_physical_allocation(&allocation, &logical, &target)
        .expect("physical allocation must independently replay");

    assert_eq!(X64_TAIL_PHYSICAL_SCHEMA_VERSION, (1, 0, 0));
    assert_eq!(X64_TAIL_PHYSICAL_POLICY_VERSION, (1, 1, 0));
    assert_eq!(X64_TAIL_PHYSICAL_GPR_LANES, 5);
    assert_eq!(X64_TAIL_PHYSICAL_XMM_LANES, 5);
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    assert_eq!(
        verified.allocation().source_target_semantic_hash(),
        target.semantic_hash
    );
    assert_eq!(
        verified.allocation().source_logical_plan_hash(),
        logical.plan_hash()
    );
    assert!(verified
        .allocation()
        .regions()
        .iter()
        .all(|region| region.disposition == X64TailPhysicalRegionDisposition::Allocated));

    // Proof metadata cannot mutate or replace the accepted policy-1.4 image.
    assert_eq!(target.program.code, original_code);
    assert_eq!(target.program.code_hash, original_code_hash);
}
