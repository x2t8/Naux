#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    emit_x64_tail_candidate_capsule, emit_x64_tail_physical_allocation,
    emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan, emit_x64_tail_template_realization,
    lower_core_ssa_r1_s5, lower_machine_ir_r1_s6, lower_x64_target_r1_s7a,
    verify_x64_tail_site_binding_proof, CoreArtifact, CoreProfile, EffectRow, Function, FunctionId,
    Program, SchemaVersion, Term, Type, X64_TAIL_SITE_BINDING_POLICY_VERSION,
    X64_TAIL_SITE_BINDING_SCHEMA_VERSION, X64_TARGET_ENCODER_POLICY_VERSION,
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
    .expect("finite compiler fixture must seal without evaluation")
}

#[test]
fn adr0061_public_boundary_binds_sites_and_frontiers_without_bytes() {
    let source = finite_cycle_source();
    let ssa = lower_core_ssa_r1_s5(&source).expect("fixture must lower to SSA");
    let machine = lower_machine_ir_r1_s6(&ssa, &source).expect("fixture must lower to Machine IR");
    let target =
        lower_x64_target_r1_s7a(&machine, &ssa, &source).expect("fixture must lower to x86-64");
    let original_code = target.program.code.clone();
    let original_code_hash = target.program.code_hash;
    let logical = emit_x64_tail_state_plan(&target).expect("logical plan must emit");
    let physical = emit_x64_tail_physical_allocation(&target, &logical)
        .expect("physical allocation must emit");
    let realization = emit_x64_tail_template_realization(&target, &logical, &physical)
        .expect("template realization must emit");
    let capsule = emit_x64_tail_candidate_capsule(&target, &logical, &physical, &realization)
        .expect("candidate capsule must emit");
    let proof =
        emit_x64_tail_site_binding_proof(&target, &logical, &physical, &realization, &capsule)
            .expect("site binding proof must emit");
    let verified = verify_x64_tail_site_binding_proof(
        &proof,
        &capsule,
        &realization,
        &physical,
        &logical,
        &target,
    )
    .expect("site binding proof must replay");

    assert_eq!(X64_TAIL_SITE_BINDING_SCHEMA_VERSION, (1, 1, 0));
    assert_eq!(X64_TAIL_SITE_BINDING_POLICY_VERSION, (1, 2, 0));
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    assert_eq!(
        verified.proof().source_target_semantic_hash(),
        target.semantic_hash
    );
    assert_eq!(
        verified.proof().source_candidate_capsule_hash(),
        capsule.capsule_hash()
    );
    for row in verified.proof().frontiers() {
        let flush_registers = row
            .flush
            .iter()
            .map(|word| word.register)
            .collect::<std::collections::BTreeSet<_>>();
        let hydrate_registers = row
            .hydrate
            .iter()
            .map(|word| word.register)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(flush_registers.len(), row.flush.len());
        assert_eq!(hydrate_registers.len(), row.hydrate.len());
    }
    assert_eq!(target.program.code, original_code);
    assert_eq!(target.program.code_hash, original_code_hash);
}
