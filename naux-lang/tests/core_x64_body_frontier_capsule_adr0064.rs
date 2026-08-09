#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    emit_x64_tail_body_frontier_capsule, emit_x64_tail_body_frontier_realization,
    emit_x64_tail_candidate_capsule, emit_x64_tail_physical_allocation,
    emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan, emit_x64_tail_template_realization,
    lower_core_ssa_r1_s5, lower_machine_ir_r1_s6, lower_x64_target_r1_s7a,
    verify_x64_tail_body_frontier_capsule, CoreArtifact, CoreProfile, EffectRow, Function,
    FunctionId, Program, SchemaVersion, Term, Type, X64_TAIL_BODY_CAPSULE_POLICY_VERSION,
    X64_TAIL_BODY_CAPSULE_SCHEMA_VERSION, X64_TAIL_BODY_DECODER_POLICY_VERSION,
    X64_TARGET_ENCODER_POLICY_VERSION,
};

fn finite_cycle_source() -> CoreArtifact {
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
                body: Term::TailCall {
                    function: FunctionId(2),
                    arguments: vec![],
                },
            },
            Function {
                id: FunctionId(2),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::TailCall {
                    function: FunctionId(1),
                    arguments: vec![],
                },
            },
        ],
    })
    .expect("finite compiler fixture must seal")
}

#[test]
fn adr0064_public_boundary_owns_bytes_without_whole_image_authority() {
    let source = finite_cycle_source();
    let ssa = lower_core_ssa_r1_s5(&source).expect("fixture must lower to SSA");
    let machine = lower_machine_ir_r1_s6(&ssa, &source).expect("fixture must lower to Machine IR");
    let target =
        lower_x64_target_r1_s7a(&machine, &ssa, &source).expect("fixture must lower to x86-64");
    let original_code = target.program.code.clone();
    let original_code_hash = target.program.code_hash;
    let logical = emit_x64_tail_state_plan(&target).expect("logical plan must emit");
    let physical =
        emit_x64_tail_physical_allocation(&target, &logical).expect("allocation must emit");
    let templates = emit_x64_tail_template_realization(&target, &logical, &physical)
        .expect("tail templates must emit");
    let transition_capsule =
        emit_x64_tail_candidate_capsule(&target, &logical, &physical, &templates)
            .expect("transition capsule must emit");
    let binding = emit_x64_tail_site_binding_proof(
        &target,
        &logical,
        &physical,
        &templates,
        &transition_capsule,
    )
    .expect("site binding must emit");
    let realization = emit_x64_tail_body_frontier_realization(
        &target,
        &logical,
        &physical,
        &templates,
        &transition_capsule,
        &binding,
    )
    .expect("body/frontier realization must emit");
    let capsule = emit_x64_tail_body_frontier_capsule(
        &target,
        &logical,
        &physical,
        &templates,
        &transition_capsule,
        &binding,
        &realization,
    )
    .expect("body/frontier capsule must emit");
    let verified = verify_x64_tail_body_frontier_capsule(
        &capsule,
        &realization,
        &binding,
        &transition_capsule,
        &templates,
        &physical,
        &logical,
        &target,
    )
    .expect("body/frontier capsule must independently replay");

    assert_eq!(X64_TAIL_BODY_CAPSULE_SCHEMA_VERSION, (1, 1, 0));
    assert_eq!(X64_TAIL_BODY_CAPSULE_POLICY_VERSION, (1, 2, 0));
    assert_eq!(X64_TAIL_BODY_DECODER_POLICY_VERSION, (1, 2, 0));
    assert_eq!(
        verified.capsule().source_target_semantic_hash(),
        target.semantic_hash
    );
    assert_eq!(
        verified.capsule().source_body_frontier_realization_hash(),
        realization.realization_hash()
    );
    assert_eq!(
        verified.capsule().source_transition_capsule_hash(),
        transition_capsule.capsule_hash()
    );
    assert_eq!(
        verified.decoded().external_references.len(),
        capsule.external_references().len()
    );
    assert_eq!(
        capsule.totals().code_bytes,
        u32::try_from(capsule.code().len()).expect("public fixture code length must fit")
    );
    assert_eq!(target.program.code, original_code);
    assert_eq!(target.program.code_hash, original_code_hash);
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
}
