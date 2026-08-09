#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    emit_x64_tail_state_plan, lower_core_ssa_r1_s5, lower_machine_ir_r1_s6,
    lower_x64_target_r1_s7a, verify_x64_tail_state_plan, CoreArtifact, CoreProfile, EffectRow,
    Function, FunctionId, Operand, Program, SchemaVersion, Term, Type, X64TailFrontierKind,
    X64_TAIL_STATE_PLAN_POLICY_VERSION, X64_TAIL_STATE_PLAN_SCHEMA_VERSION,
    X64_TARGET_ENCODER_POLICY_VERSION,
};

fn direct_call_source() -> CoreArtifact {
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
    .expect("direct-call fixture must seal")
}

#[test]
fn adr0057_public_boundary_is_proof_only_and_source_bound() {
    let source = direct_call_source();
    let ssa = lower_core_ssa_r1_s5(&source).expect("fixture must lower to SSA");
    let machine = lower_machine_ir_r1_s6(&ssa, &source).expect("fixture must lower to Machine IR");
    let target =
        lower_x64_target_r1_s7a(&machine, &ssa, &source).expect("fixture must lower to x86-64");
    let original_code = target.program.code.clone();
    let original_code_hash = target.program.code_hash;

    let plan = emit_x64_tail_state_plan(&target).expect("proof-only tail-state plan must emit");
    let verified =
        verify_x64_tail_state_plan(&plan, &target).expect("tail-state plan must replay exactly");

    assert_eq!(X64_TAIL_STATE_PLAN_SCHEMA_VERSION, (1, 0, 0));
    assert_eq!(X64_TAIL_STATE_PLAN_POLICY_VERSION, (1, 2, 0));
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    assert_eq!(verified.plan().source_semantic_hash(), target.semantic_hash);
    assert!(verified
        .plan()
        .frontiers()
        .iter()
        .any(|frontier| frontier.kind == X64TailFrontierKind::EntryAbi));
    assert!(verified
        .plan()
        .frontiers()
        .iter()
        .any(|frontier| frontier.kind == X64TailFrontierKind::Return));

    // Planning cannot mutate, replace, or authorize the accepted code image.
    assert_eq!(target.program.code, original_code);
    assert_eq!(target.program.code_hash, original_code_hash);
}
