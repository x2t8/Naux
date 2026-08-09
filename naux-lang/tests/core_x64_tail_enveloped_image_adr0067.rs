#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    emit_x64_tail_abi_envelope_capsule, emit_x64_tail_body_frontier_capsule,
    emit_x64_tail_body_frontier_realization, emit_x64_tail_candidate_capsule,
    emit_x64_tail_closed_image, emit_x64_tail_enveloped_image, emit_x64_tail_physical_allocation,
    emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan, emit_x64_tail_template_realization,
    lower_core_ssa_r1_s5, lower_machine_ir_r1_s6, lower_x64_target_r1_s7a,
    verify_x64_tail_abi_envelope_capsule, verify_x64_tail_closed_image,
    verify_x64_tail_enveloped_image, CoreArtifact, CoreProfile, EffectRow, Function, FunctionId,
    LocalId, Operand, Parameter, Program, SchemaVersion, Term, Type, X64TailAbiEnvelopeCapsule,
    X64TailClosedImage, X64TailClosedTerminalKind, X64TailEnvelopedImage, X64TargetArtifact,
    X64_TAIL_ENVELOPED_IMAGE_DECODER_POLICY_VERSION, X64_TAIL_ENVELOPED_IMAGE_POLICY_VERSION,
    X64_TAIL_ENVELOPED_IMAGE_SCHEMA_VERSION, X64_TARGET_ENCODER_POLICY_VERSION,
};

fn lane_source(lanes: u32) -> CoreArtifact {
    let parameters = (0..lanes)
        .map(|local| Parameter {
            local: LocalId(local),
            ty: Type::I64,
        })
        .collect::<Vec<_>>();
    let result = if lanes == 0 {
        Operand::I64(0)
    } else {
        Operand::Local(LocalId(lanes - 1))
    };
    CoreArtifact::seal(Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions: vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters,
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(result),
        }],
    })
    .expect("ADR-0067 public fixture must seal")
}

fn compile_enveloped(
    source: &CoreArtifact,
) -> (
    X64TargetArtifact,
    X64TailClosedImage,
    X64TailAbiEnvelopeCapsule,
    X64TailEnvelopedImage,
) {
    let ssa = lower_core_ssa_r1_s5(source).expect("fixture must lower to SSA");
    let machine = lower_machine_ir_r1_s6(&ssa, source).expect("fixture must lower to Machine IR");
    let target =
        lower_x64_target_r1_s7a(&machine, &ssa, source).expect("fixture must lower to x86-64");
    let logical = emit_x64_tail_state_plan(&target).expect("logical tail state must emit");
    let physical =
        emit_x64_tail_physical_allocation(&target, &logical).expect("allocation must emit");
    let templates = emit_x64_tail_template_realization(&target, &logical, &physical)
        .expect("templates must emit");
    let transition = emit_x64_tail_candidate_capsule(&target, &logical, &physical, &templates)
        .expect("transition capsule must emit");
    let binding =
        emit_x64_tail_site_binding_proof(&target, &logical, &physical, &templates, &transition)
            .expect("binding proof must emit");
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
    let closed = emit_x64_tail_closed_image(
        &target,
        &logical,
        &physical,
        &templates,
        &transition,
        &binding,
        &realization,
        &body,
    )
    .expect("closed image must emit");
    let verified_closed = verify_x64_tail_closed_image(
        &closed,
        &body,
        &realization,
        &binding,
        &transition,
        &templates,
        &physical,
        &logical,
        &target,
    )
    .expect("closed image must verify");
    let abi = emit_x64_tail_abi_envelope_capsule(&target, &verified_closed)
        .expect("ABI capsule must emit");
    let verified_abi = verify_x64_tail_abi_envelope_capsule(&abi, &target, &verified_closed)
        .expect("ABI capsule must verify");
    let enveloped = emit_x64_tail_enveloped_image(&target, &verified_closed, &verified_abi)
        .expect("enveloped image must emit");
    verify_x64_tail_enveloped_image(&enveloped, &target, &verified_closed, &verified_abi)
        .expect("enveloped image must independently verify");
    (target, closed, abi, enveloped)
}

#[test]
fn adr0067_public_boundary_replaces_terminals_without_execution_authority() {
    for lanes in 0..=5 {
        let (target, closed, abi, image) = compile_enveloped(&lane_source(lanes));
        assert_eq!(image.source_target_semantic_hash(), target.semantic_hash);
        assert_eq!(image.source_closed_image_hash(), closed.image_hash());
        assert_eq!(image.source_abi_capsule_hash(), abi.capsule_hash());
        assert_eq!(image.entry_successor(), closed.entry_successor());
        assert_eq!(image.source_spans().len(), 4);
        assert_eq!(image.abi_programs().len(), 3);
        assert_eq!(image.totals().abi_instructions, abi.totals().instructions);
        assert_eq!(
            image.code().len(),
            closed.code().len() - 3 + abi.code().len() - 1
        );
        let entry_terminal = closed
            .terminal_receipts()
            .iter()
            .find(|terminal| terminal.kind == X64TailClosedTerminalKind::EntryAdapter)
            .expect("entry terminal must exist");
        assert_eq!(image.entry_point(), entry_terminal.offset);
        assert_eq!(image.abi_programs()[0].start, image.entry_point());
        for relocation in image.relocation_receipts() {
            let patch = relocation.patch_offset as usize;
            let bytes = &image.code()[patch..patch + 4];
            let displacement = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            assert_eq!(displacement, relocation.displacement);
            assert_eq!(
                i64::from(relocation.patch_offset + 4) + i64::from(displacement),
                i64::from(relocation.target_offset)
            );
        }
        let mut owners = vec![0u8; image.code().len()];
        for source in image.source_spans() {
            for owner in &mut owners[source.image_start as usize..source.image_end as usize] {
                *owner += 1;
            }
        }
        assert!(owners.iter().all(|owner| *owner == 1));
    }

    assert_eq!(X64_TAIL_ENVELOPED_IMAGE_SCHEMA_VERSION, (1, 0, 0));
    assert_eq!(X64_TAIL_ENVELOPED_IMAGE_POLICY_VERSION, (1, 0, 0));
    assert_eq!(X64_TAIL_ENVELOPED_IMAGE_DECODER_POLICY_VERSION, (1, 0, 0));
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
}
