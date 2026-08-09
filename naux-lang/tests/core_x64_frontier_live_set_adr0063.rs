#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    emit_x64_tail_candidate_capsule, emit_x64_tail_physical_allocation,
    emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan, emit_x64_tail_template_realization,
    lower_core_ssa_r1_s5, lower_machine_ir_r1_s6, lower_x64_target_r1_s7a,
    verify_x64_tail_site_binding_proof, CoreArtifact, CoreProfile, EffectRow, Function, FunctionId,
    Program, SchemaVersion, Term, Type, X64TailPhysicalLocation,
    X64_TAIL_SITE_BINDING_SCHEMA_VERSION, X64_TARGET_ENCODER_POLICY_VERSION,
};
use std::collections::BTreeSet;

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
fn adr0063_public_frontiers_are_live_narrowed_and_register_injective() {
    let source = finite_cycle_source();
    let ssa = lower_core_ssa_r1_s5(&source).expect("source must lower to SSA");
    let machine = lower_machine_ir_r1_s6(&ssa, &source).expect("SSA must lower to Machine IR");
    let target = lower_x64_target_r1_s7a(&machine, &ssa, &source).expect("Machine IR must lower");
    let original_code = target.program.code.clone();
    let original_code_hash = target.program.code_hash;
    let logical = emit_x64_tail_state_plan(&target).expect("logical plan must emit");
    let physical =
        emit_x64_tail_physical_allocation(&target, &logical).expect("allocation must emit");
    let tail_templates = emit_x64_tail_template_realization(&target, &logical, &physical)
        .expect("tail templates must emit");
    let capsule = emit_x64_tail_candidate_capsule(&target, &logical, &physical, &tail_templates)
        .expect("capsule must emit");
    let proof =
        emit_x64_tail_site_binding_proof(&target, &logical, &physical, &tail_templates, &capsule)
            .expect("schema-1.1 frontier proof must emit");
    let verified = verify_x64_tail_site_binding_proof(
        &proof,
        &capsule,
        &tail_templates,
        &physical,
        &logical,
        &target,
    )
    .expect("schema-1.1 frontier proof must replay");

    assert_eq!(X64_TAIL_SITE_BINDING_SCHEMA_VERSION, (1, 1, 0));
    assert!(!verified.proof().frontiers().is_empty());

    for row in verified.proof().frontiers() {
        let source_physical = row
            .source_live
            .iter()
            .map(|binding| binding.physical)
            .collect::<BTreeSet<_>>();
        let target_physical = row
            .target_live
            .iter()
            .map(|binding| binding.physical)
            .collect::<BTreeSet<_>>();
        assert_eq!(source_physical.len(), row.source_live.len());
        assert_eq!(target_physical.len(), row.target_live.len());

        let expected_flush = row
            .source_live
            .iter()
            .filter_map(|binding| match binding.physical {
                X64TailPhysicalLocation::Register { register, .. } => {
                    Some((binding.logical, register))
                }
                X64TailPhysicalLocation::Frame(_) => None,
            })
            .collect::<Vec<_>>();
        let actual_flush = row
            .flush
            .iter()
            .map(|word| (word.logical, word.register))
            .collect::<Vec<_>>();
        if row.source_region.is_some()
            && !matches!(
                row.action,
                naux::core::X64TailFrontierAction::PersistentTransition
                    | naux::core::X64TailFrontierAction::Preserve
            )
        {
            assert_eq!(actual_flush, expected_flush);
        }

        let flush_registers = row
            .flush
            .iter()
            .map(|word| word.register)
            .collect::<BTreeSet<_>>();
        let hydrate_registers = row
            .hydrate
            .iter()
            .map(|word| word.register)
            .collect::<BTreeSet<_>>();
        assert_eq!(flush_registers.len(), row.flush.len());
        assert_eq!(hydrate_registers.len(), row.hydrate.len());
    }

    assert_eq!(target.program.code, original_code);
    assert_eq!(target.program.code_hash, original_code_hash);
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
}
