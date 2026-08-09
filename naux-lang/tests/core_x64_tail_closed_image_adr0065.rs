#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    emit_x64_tail_body_frontier_capsule, emit_x64_tail_body_frontier_realization,
    emit_x64_tail_candidate_capsule, emit_x64_tail_closed_image, emit_x64_tail_physical_allocation,
    emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan, emit_x64_tail_template_realization,
    lower_core_ssa_r1_s5, lower_machine_ir_r1_s6, lower_x64_target_r1_s7a,
    verify_x64_tail_closed_image, CoreArtifact, CoreProfile, EffectRow, Function, FunctionId,
    Program, SchemaVersion, Term, Type, X64_TAIL_CLOSED_IMAGE_DECODER_POLICY_VERSION,
    X64_TAIL_CLOSED_IMAGE_POLICY_VERSION, X64_TAIL_CLOSED_IMAGE_SCHEMA_VERSION,
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
fn adr0065_public_boundary_closes_internal_image_without_execution_authority() {
    let source = finite_cycle_source();
    let ssa = lower_core_ssa_r1_s5(&source).expect("fixture must lower to SSA");
    let machine = lower_machine_ir_r1_s6(&ssa, &source).expect("fixture must lower to Machine IR");
    let target =
        lower_x64_target_r1_s7a(&machine, &ssa, &source).expect("fixture must lower to x86-64");
    let original_code = target.program.code.clone();
    let original_hash = target.program.code_hash;
    let logical = emit_x64_tail_state_plan(&target).expect("logical plan must emit");
    let physical =
        emit_x64_tail_physical_allocation(&target, &logical).expect("allocation must emit");
    let templates = emit_x64_tail_template_realization(&target, &logical, &physical)
        .expect("templates must emit");
    let transition = emit_x64_tail_candidate_capsule(&target, &logical, &physical, &templates)
        .expect("transition capsule must emit");
    let binding =
        emit_x64_tail_site_binding_proof(&target, &logical, &physical, &templates, &transition)
            .expect("binding must emit");
    let realization = emit_x64_tail_body_frontier_realization(
        &target,
        &logical,
        &physical,
        &templates,
        &transition,
        &binding,
    )
    .expect("body realization must emit");
    let body = emit_x64_tail_body_frontier_capsule(
        &target,
        &logical,
        &physical,
        &templates,
        &transition,
        &binding,
        &realization,
    )
    .expect("body capsule must emit");
    let image = emit_x64_tail_closed_image(
        &target,
        &logical,
        &physical,
        &templates,
        &transition,
        &binding,
        &realization,
        &body,
    )
    .expect("closed image must compose");
    let verified = verify_x64_tail_closed_image(
        &image,
        &body,
        &realization,
        &binding,
        &transition,
        &templates,
        &physical,
        &logical,
        &target,
    )
    .expect("closed image must independently replay");

    assert_eq!(X64_TAIL_CLOSED_IMAGE_SCHEMA_VERSION, (1, 0, 0));
    assert_eq!(X64_TAIL_CLOSED_IMAGE_POLICY_VERSION, (1, 1, 0));
    assert_eq!(X64_TAIL_CLOSED_IMAGE_DECODER_POLICY_VERSION, (1, 1, 0));
    assert_eq!(
        verified.image().source_target_semantic_hash(),
        target.semantic_hash
    );
    assert_eq!(
        verified.image().code().len(),
        verified.image().totals().code_bytes as usize
    );
    assert_eq!(verified.image().totals().terminal_bytes, 3);
    assert_eq!(
        verified.decoded().relocations.len(),
        image.relocation_receipts().len()
    );
    assert_eq!(target.program.code, original_code);
    assert_eq!(target.program.code_hash, original_hash);
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
}
