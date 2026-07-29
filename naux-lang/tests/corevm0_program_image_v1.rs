use naux::core::{
    branch_mix_kernel_program, corevm0_core_image, corevm0_program_image,
    corevm0_program_image_type, specialization_value_hash, verify_corevm0_program,
    verify_corevm0_program_image, CoreVmInstruction as I, CoreVmProgram,
    CoreVmProgramImageVerificationError, SpecializationValue, Type, COREVM0_MAX_ARGUMENTS,
    COREVM0_MAX_INSTRUCTIONS, COREVM0_MAX_LOCALS, COREVM0_PROGRAM_IMAGE_VERSION,
    COREVM0_SCHEMA_VERSION,
};

#[test]
fn full_program_image_binds_manifest_capacity_and_canonical_padding() {
    let program = branch_mix_kernel_program();
    let verified = verify_corevm0_program(&program).expect("branch_mix must verify");
    let first = corevm0_program_image(verified).expect("full image must encode");
    let second = corevm0_program_image(verified).expect("full image must reproduce");

    assert_eq!(first, second);
    assert_eq!(first.ty(), &corevm0_program_image_type());
    assert_eq!(first.program_hash(), second.program_hash());
    assert_eq!(first.image_hash(), second.image_hash());
    assert_eq!(
        specialization_value_hash(first.value()).expect("image must hash"),
        first.image_hash()
    );

    let Type::Tuple(image_types) = first.ty() else {
        panic!("ProgramImage v1 type must be a Tuple");
    };
    let SpecializationValue::Tuple(image) = first.value() else {
        panic!("ProgramImage v1 value must be a Tuple");
    };
    assert_eq!(image_types.len(), 10);
    assert_eq!(image.len(), 10);
    assert_eq!(
        &image[..3],
        &[
            SpecializationValue::I64(i64::from(COREVM0_PROGRAM_IMAGE_VERSION.0)),
            SpecializationValue::I64(i64::from(COREVM0_PROGRAM_IMAGE_VERSION.1)),
            SpecializationValue::I64(i64::from(COREVM0_PROGRAM_IMAGE_VERSION.2)),
        ]
    );
    assert_eq!(
        image[3],
        SpecializationValue::I64(program.arguments.len() as i64)
    );
    assert_eq!(
        image[5],
        SpecializationValue::I64(program.locals.len() as i64)
    );
    assert_eq!(
        image[7],
        SpecializationValue::I64(i64::from(program.max_stack))
    );
    assert_eq!(
        image[8],
        SpecializationValue::I64(program.instructions.len() as i64)
    );

    let SpecializationValue::Tuple(argument_slots) = &image[4] else {
        panic!("argument manifest must be a fixed Tuple");
    };
    assert_eq!(argument_slots.len(), COREVM0_MAX_ARGUMENTS);
    assert_sum_constructor(&argument_slots[0], 4);
    assert_sum_constructor(&argument_slots[1], 2);
    for slot in &argument_slots[2..] {
        assert_sum_constructor(slot, 0);
    }

    let SpecializationValue::Tuple(local_slots) = &image[6] else {
        panic!("local manifest must be a fixed Tuple");
    };
    assert_eq!(local_slots.len(), COREVM0_MAX_LOCALS);
    for (index, constructor) in [2, 3, 2, 2, 2].into_iter().enumerate() {
        assert_sum_constructor(&local_slots[index], constructor);
    }
    for slot in &local_slots[5..] {
        assert_sum_constructor(slot, 0);
    }

    let SpecializationValue::Tuple(instruction_slots) = &image[9] else {
        panic!("instruction bank must be a fixed Tuple");
    };
    assert_eq!(instruction_slots.len(), COREVM0_MAX_INSTRUCTIONS);
    for slot in &instruction_slots[..program.instructions.len()] {
        assert_sum_constructor(slot, 1);
    }
    for slot in &instruction_slots[program.instructions.len()..] {
        assert_sum_constructor(slot, 0);
    }

    assert_eq!(
        first.image_hash().to_hex(),
        "732cc709778d757988b34b1efcf5c376b1b1443e6cebec3bb61375d1f8fa1142"
    );
}

#[test]
fn full_image_changes_with_program_while_legacy_vector_remains_unchanged() {
    let baseline = branch_mix_kernel_program();
    let legacy = corevm0_core_image(&baseline).expect("legacy seed image must remain available");
    assert_eq!(
        specialization_value_hash(&legacy.value)
            .expect("legacy image must hash")
            .to_hex(),
        "9ced2bbdcc19b5225f7e15a5d30525ffd8424794e8ccc5b40c2402a3f11856c9"
    );

    let mut changed = baseline.clone();
    changed.instructions[22] = I::ConstI64(18);
    let baseline_verified = verify_corevm0_program(&baseline).expect("baseline must verify");
    let changed_verified = verify_corevm0_program(&changed).expect("mutation must still verify");
    let baseline_image =
        corevm0_program_image(baseline_verified).expect("baseline image must encode");
    let changed_image = corevm0_program_image(changed_verified).expect("changed image must encode");

    assert_ne!(baseline_image.program_hash(), changed_image.program_hash());
    assert_ne!(baseline_image.image_hash(), changed_image.image_hash());
    assert_ne!(baseline_image.value(), changed_image.value());
}

#[test]
fn invalid_bytecode_cannot_create_a_full_program_image() {
    let mut invalid = branch_mix_kernel_program();
    invalid.instructions[10] = I::Jump(999);
    assert!(verify_corevm0_program(&invalid).is_err());
}

#[test]
fn raw_candidate_is_reverified_and_compared_exactly() {
    let program = branch_mix_kernel_program();
    let verified = verify_corevm0_program(&program).expect("program must verify");
    let image = corevm0_program_image(verified).expect("image must encode");
    let admitted = verify_corevm0_program_image(&program, image.value())
        .expect("exact canonical image must be admitted");
    assert_eq!(admitted.image_hash(), image.image_hash());

    let mut forged = image.value().clone();
    let SpecializationValue::Tuple(fields) = &mut forged else {
        unreachable!("canonical image is a Tuple");
    };
    fields[8] = SpecializationValue::I64(61);
    assert_eq!(
        verify_corevm0_program_image(&program, &forged),
        Err(CoreVmProgramImageVerificationError::ImageMismatch)
    );

    let mut invalid = program;
    invalid.instructions[10] = I::Jump(999);
    assert!(matches!(
        verify_corevm0_program_image(&invalid, image.value()),
        Err(CoreVmProgramImageVerificationError::InvalidProgram(_))
    ));
}

#[test]
fn every_full_image_section_is_inside_the_exact_admission_comparison() {
    let program = branch_mix_kernel_program();
    let verified = verify_corevm0_program(&program).expect("program must verify");
    let image = corevm0_program_image(verified).expect("image must encode");
    let mut mutations = Vec::new();

    for index in [0_usize, 1, 2, 3, 5, 7, 8] {
        let mut candidate = image.value().clone();
        let SpecializationValue::Tuple(fields) = &mut candidate else {
            unreachable!("canonical image is a Tuple");
        };
        let SpecializationValue::I64(value) = &mut fields[index] else {
            unreachable!("selected manifest field is I64");
        };
        *value = value.wrapping_add(1);
        mutations.push(candidate);
    }

    let mut argument_type = image.value().clone();
    let SpecializationValue::Tuple(fields) = &mut argument_type else {
        unreachable!();
    };
    let SpecializationValue::Tuple(arguments) = &mut fields[4] else {
        unreachable!();
    };
    let SpecializationValue::Sum { constructor, .. } = &mut arguments[0] else {
        unreachable!();
    };
    *constructor = 3;
    mutations.push(argument_type);

    let mut local_type = image.value().clone();
    let SpecializationValue::Tuple(fields) = &mut local_type else {
        unreachable!();
    };
    let SpecializationValue::Tuple(locals) = &mut fields[6] else {
        unreachable!();
    };
    let SpecializationValue::Sum { constructor, .. } = &mut locals[0] else {
        unreachable!();
    };
    *constructor = 3;
    mutations.push(local_type);

    let mut instruction = image.value().clone();
    let SpecializationValue::Tuple(fields) = &mut instruction else {
        unreachable!();
    };
    let SpecializationValue::Tuple(instructions) = &mut fields[9] else {
        unreachable!();
    };
    let SpecializationValue::Sum { constructor, .. } = &mut instructions[0] else {
        unreachable!();
    };
    *constructor = 0;
    mutations.push(instruction);

    for candidate in mutations {
        assert_eq!(
            verify_corevm0_program_image(&program, &candidate),
            Err(CoreVmProgramImageVerificationError::ImageMismatch)
        );
    }
}

#[test]
fn image_admission_uses_core_numeric_canonicalization() {
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![],
        locals: vec![],
        max_stack: 1,
        instructions: vec![
            I::ConstF64(f64::from_bits(0x7ff8_0000_0000_0001)),
            I::ReturnF64,
        ],
    };
    let verified = verify_corevm0_program(&program).expect("NaN program must verify");
    let image = corevm0_program_image(verified).expect("NaN image must encode");
    let reproduced = corevm0_program_image(verified).expect("NaN image must reproduce");
    assert_eq!(image, reproduced);
    verify_corevm0_program_image(&program, image.value())
        .expect("canonical NaN image must admit itself");

    let mut equivalent_nan = image.value().clone();
    set_first_const_f64(&mut equivalent_nan, f64::from_bits(0xfff0_0000_0000_0042));
    verify_corevm0_program_image(&program, &equivalent_nan)
        .expect("NaN payload is not observable in Core-N0");

    let zero_program = CoreVmProgram {
        instructions: vec![I::ConstF64(0.0), I::ReturnF64],
        ..program
    };
    let verified = verify_corevm0_program(&zero_program).expect("zero program must verify");
    let zero_image = corevm0_program_image(verified).expect("zero image must encode");
    let mut negative_zero = zero_image.value().clone();
    set_first_const_f64(&mut negative_zero, -0.0);
    assert_eq!(
        verify_corevm0_program_image(&zero_program, &negative_zero),
        Err(CoreVmProgramImageVerificationError::ImageMismatch),
        "signed zero remains observable"
    );
}

fn assert_sum_constructor(value: &SpecializationValue, expected: u32) {
    let SpecializationValue::Sum { constructor, .. } = value else {
        panic!("expected Sum slot, found {value:?}");
    };
    assert_eq!(*constructor, expected);
}

fn set_first_const_f64(image: &mut SpecializationValue, value: f64) {
    let SpecializationValue::Tuple(fields) = image else {
        unreachable!();
    };
    let SpecializationValue::Tuple(instruction_slots) = &mut fields[9] else {
        unreachable!();
    };
    let SpecializationValue::Sum {
        constructor: 1,
        fields: present,
        ..
    } = &mut instruction_slots[0]
    else {
        unreachable!();
    };
    let SpecializationValue::Sum {
        constructor: 1,
        fields: immediate,
        ..
    } = &mut present[0]
    else {
        unreachable!();
    };
    immediate[0] = SpecializationValue::F64(value);
}
