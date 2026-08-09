#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    emit_x64_tail_abi_envelope_capsule, emit_x64_tail_body_frontier_capsule,
    emit_x64_tail_body_frontier_realization, emit_x64_tail_candidate_capsule,
    emit_x64_tail_closed_image, emit_x64_tail_physical_allocation,
    emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan, emit_x64_tail_template_realization,
    lower_core_ssa_r1_s5, lower_machine_ir_r1_s6, lower_x64_target_r1_s7a,
    verify_x64_tail_abi_envelope_capsule, verify_x64_tail_closed_image, CoreArtifact, CoreProfile,
    EffectRow, Function, FunctionId, LocalId, Mutability, Operand, Parameter, Program, RegionId,
    SchemaVersion, Term, Type, X64TailAbiEnvelopeCapsule, X64TailAbiEnvelopeEffect,
    X64TailClosedImage, X64TargetArtifact, X64_TAIL_ABI_ENVELOPE_DECODER_POLICY_VERSION,
    X64_TAIL_ABI_ENVELOPE_POLICY_VERSION, X64_TAIL_ABI_ENVELOPE_SCHEMA_VERSION,
    X64_TARGET_ENCODER_POLICY_VERSION,
};

fn seal(function: Function) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions: vec![function],
    })
    .expect("ADR-0066 public fixture must seal")
}

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
    seal(Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters,
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(result),
    })
}

fn unit_source() -> CoreArtifact {
    seal(Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Unit,
        }],
        effects: EffectRow::pure(),
        result: Type::Unit,
        body: Term::Return(Operand::Local(LocalId(0))),
    })
}

fn array_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn array_source() -> CoreArtifact {
    seal(Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array_type(),
        }],
        effects: EffectRow::pure(),
        result: array_type(),
        body: Term::Return(Operand::Local(LocalId(0))),
    })
}

fn mixed_five_lane_source() -> CoreArtifact {
    seal(Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: Type::Unit,
            },
            Parameter {
                local: LocalId(1),
                ty: Type::Bool,
            },
            Parameter {
                local: LocalId(2),
                ty: Type::I64,
            },
            Parameter {
                local: LocalId(3),
                ty: Type::F64,
            },
            Parameter {
                local: LocalId(4),
                ty: array_type(),
            },
        ],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Return(Operand::Local(LocalId(3))),
    })
}

fn compile_envelope(
    source: &CoreArtifact,
) -> (
    X64TargetArtifact,
    X64TailClosedImage,
    X64TailAbiEnvelopeCapsule,
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
    .expect("closed image must emit");
    let verified_image = verify_x64_tail_closed_image(
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
    .expect("closed image must verify");
    let capsule = emit_x64_tail_abi_envelope_capsule(&target, &verified_image)
        .expect("ABI capsule must emit");
    verify_x64_tail_abi_envelope_capsule(&capsule, &target, &verified_image)
        .expect("ABI capsule must independently verify");
    (target, image, capsule)
}

#[test]
fn adr0066_public_boundary_covers_the_frozen_abi_lane_and_type_surface() {
    for lanes in 0..=5 {
        let source = lane_source(lanes);
        let (target, image, capsule) = compile_envelope(&source);
        assert_eq!(capsule.totals().input_lanes, lanes);
        assert_eq!(capsule.source_target_semantic_hash(), target.semantic_hash);
        assert_eq!(capsule.source_closed_image_hash(), image.image_hash());
        assert_eq!(capsule.entry_successor(), image.entry_successor());
        assert_eq!(capsule.totals().programs, 3);
        assert_eq!(capsule.totals().relocations, 1);
        assert_eq!(capsule.totals().anchors, 1);
    }

    let (_, _, unit) = compile_envelope(&unit_source());
    assert_eq!(unit.totals().input_lanes, 0);
    assert!(unit.instructions().iter().any(|instruction| matches!(
        instruction.effect,
        X64TailAbiEnvelopeEffect::ZeroUnitHome { parameter: 0, .. }
    )));

    let (_, _, array) = compile_envelope(&array_source());
    assert_eq!(array.totals().input_lanes, 2);
    assert_eq!(
        array
            .instructions()
            .iter()
            .filter(|instruction| matches!(
                instruction.effect,
                X64TailAbiEnvelopeEffect::StoreInputLane { .. }
            ))
            .count(),
        2
    );

    let (_, _, mixed) = compile_envelope(&mixed_five_lane_source());
    assert_eq!(mixed.totals().input_lanes, 5);
    assert!(mixed.instructions().iter().any(|instruction| matches!(
        instruction.effect,
        X64TailAbiEnvelopeEffect::SaveOutputPointer {
            register: naux::core::X64AbiRegister::R9,
            ..
        }
    )));
    assert!(mixed.instructions().iter().any(|instruction| matches!(
        instruction.effect,
        X64TailAbiEnvelopeEffect::StoreInputLane {
            ty: naux::core::MachineType::Bool,
            ..
        }
    )));
    assert!(mixed.instructions().iter().any(|instruction| matches!(
        instruction.effect,
        X64TailAbiEnvelopeEffect::StoreInputLane {
            ty: naux::core::MachineType::F64,
            ..
        }
    )));
    assert!(mixed.instructions().iter().any(|instruction| matches!(
        instruction.effect,
        X64TailAbiEnvelopeEffect::StoreInputLane {
            ty: naux::core::MachineType::F64Array,
            ..
        }
    )));

    assert_eq!(X64_TAIL_ABI_ENVELOPE_SCHEMA_VERSION, (1, 0, 0));
    assert_eq!(X64_TAIL_ABI_ENVELOPE_POLICY_VERSION, (1, 0, 0));
    assert_eq!(X64_TAIL_ABI_ENVELOPE_DECODER_POLICY_VERSION, (1, 0, 0));
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
}
