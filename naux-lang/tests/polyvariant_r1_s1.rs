use naux::core::{
    certify_binding_time_b0d, evaluate, specialize_polyvariant_r1,
    validate_binding_time_b0_request, validate_specialization_r0a_request, verify, BindingTime,
    BindingTimeBudget, BindingTimeCertificate, BindingTimeRequest, CoreArtifact, CoreProfile,
    CoreValue, Effect, EffectRow, ErrorKind, EvaluationBudget, EvaluationOutcome, Function,
    FunctionId, LocalId, Mutability, NumericMode, Operand, Parameter, PolyvariantR1Budget,
    PolyvariantR1Error, PolyvariantR1Pattern, PolyvariantR1Specialization, Primitive, Program,
    RValue, SpecializationBudget, SpecializationRequest, SpecializationSlot, SumType, Term, Type,
};

fn seal(functions: Vec<Function>) -> CoreArtifact {
    seal_with_entry(FunctionId(0), functions)
}

fn seal_with_entry(entry: FunctionId, functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: naux::core::SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry,
        functions,
    })
    .expect("the R1-S1 fixture must encode")
}

fn primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
}

fn dynamic_if_artifact() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: Type::Bool,
            },
            Parameter {
                local: LocalId(1),
                ty: Type::I64,
            },
        ],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::If {
            condition: Operand::Local(LocalId(0)),
            then_term: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Add(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(1)), Operand::I64(7)],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            }),
            else_term: Box::new(Term::Let {
                binder: LocalId(3),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Sub(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(1)), Operand::I64(11)],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
            }),
        },
    }])
}

fn mixed_direct_call_artifact() -> CoreArtifact {
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::I64,
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(3),
                    ty: Type::I64,
                },
                Parameter {
                    local: LocalId(4),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(5),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Add(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(3)), Operand::Local(LocalId(4))],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(5)))),
            },
        },
    ])
}

fn same_key_tail_loop_artifact() -> CoreArtifact {
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::I64,
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::TailCall {
                function: FunctionId(1),
                arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(2),
                    ty: Type::I64,
                },
                Parameter {
                    local: LocalId(3),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(4),
                ty: Type::Bool,
                value: primitive(
                    Primitive::I64CmpLt,
                    vec![Operand::Local(LocalId(3)), Operand::I64(1)],
                ),
                next: Box::new(Term::If {
                    condition: Operand::Local(LocalId(4)),
                    then_term: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                    else_term: Box::new(Term::Let {
                        binder: LocalId(5),
                        ty: Type::I64,
                        value: primitive(
                            Primitive::I64Sub(NumericMode::Wrapping),
                            vec![Operand::Local(LocalId(3)), Operand::I64(1)],
                        ),
                        next: Box::new(Term::TailCall {
                            function: FunctionId(1),
                            arguments: vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(5))],
                        }),
                    }),
                }),
            },
        },
    ])
}

fn mutual_tail_recursion_artifact() -> CoreArtifact {
    let mutually_recursive = |id, callee| Function {
        id: FunctionId(id),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::I64,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::Bool,
            value: primitive(
                Primitive::I64CmpLt,
                vec![Operand::Local(LocalId(0)), Operand::I64(1)],
            ),
            next: Box::new(Term::If {
                condition: Operand::Local(LocalId(1)),
                then_term: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                else_term: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: primitive(
                        Primitive::I64Sub(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                    ),
                    next: Box::new(Term::TailCall {
                        function: FunctionId(callee),
                        arguments: vec![Operand::Local(LocalId(2))],
                    }),
                }),
            }),
        },
    };
    seal(vec![mutually_recursive(0, 1), mutually_recursive(1, 0)])
}

fn nonzero_entry_artifact() -> CoreArtifact {
    seal_with_entry(
        FunctionId(7),
        vec![
            Function {
                id: FunctionId(3),
                region_parameters: vec![],
                parameters: vec![Parameter {
                    local: LocalId(30),
                    ty: Type::I64,
                }],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Let {
                    binder: LocalId(31),
                    ty: Type::I64,
                    value: primitive(
                        Primitive::I64Add(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(30)), Operand::I64(5)],
                    ),
                    next: Box::new(Term::Return(Operand::Local(LocalId(31)))),
                },
            },
            Function {
                id: FunctionId(7),
                region_parameters: vec![],
                parameters: vec![Parameter {
                    local: LocalId(70),
                    ty: Type::I64,
                }],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Let {
                    binder: LocalId(71),
                    ty: Type::I64,
                    value: RValue::Call {
                        function: FunctionId(3),
                        arguments: vec![Operand::Local(LocalId(70))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(71)))),
                },
            },
        ],
    )
}

fn static_countdown_artifact() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::I64,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::Bool,
            value: primitive(
                Primitive::I64CmpLt,
                vec![Operand::Local(LocalId(0)), Operand::I64(1)],
            ),
            next: Box::new(Term::If {
                condition: Operand::Local(LocalId(1)),
                then_term: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                else_term: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: primitive(
                        Primitive::I64Sub(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                    ),
                    next: Box::new(Term::TailCall {
                        function: FunctionId(0),
                        arguments: vec![Operand::Local(LocalId(2))],
                    }),
                }),
            }),
        },
    }])
}

fn unbounded_static_counter_artifact() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::I64,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: primitive(
                Primitive::I64Add(NumericMode::Wrapping),
                vec![Operand::Local(LocalId(0)), Operand::I64(1)],
            ),
            next: Box::new(Term::TailCall {
                function: FunctionId(0),
                arguments: vec![Operand::Local(LocalId(1))],
            }),
        },
    }])
}

fn nested_dynamic_if_artifact() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: Type::Bool,
            },
            Parameter {
                local: LocalId(1),
                ty: Type::Bool,
            },
        ],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::If {
            condition: Operand::Local(LocalId(0)),
            then_term: Box::new(Term::If {
                condition: Operand::Local(LocalId(1)),
                then_term: Box::new(Term::Return(Operand::I64(1))),
                else_term: Box::new(Term::Return(Operand::I64(2))),
            }),
            else_term: Box::new(Term::Return(Operand::I64(3))),
        },
    }])
}

fn f64_version_key_artifact() -> CoreArtifact {
    let call = |binder, bits, next| Term::Let {
        binder: LocalId(binder),
        ty: Type::F64,
        value: RValue::Call {
            function: FunctionId(1),
            arguments: vec![Operand::F64(f64::from_bits(bits))],
        },
        next: Box::new(next),
    };
    let body = call(
        0,
        0x7ff8_0000_0000_0001,
        call(
            1,
            0x7ff8_0000_0000_00ff,
            call(
                2,
                0_u64,
                call(3, 1_u64 << 63, Term::Return(Operand::Local(LocalId(3)))),
            ),
        ),
    );
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::F64,
            body,
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(4),
                ty: Type::F64,
            }],
            effects: EffectRow::pure(),
            result: Type::F64,
            body: Term::Return(Operand::Local(LocalId(4))),
        },
    ])
}

fn i64_version_key_order_artifact() -> CoreArtifact {
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(0),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::I64(-1)],
                },
                next: Box::new(Term::Let {
                    binder: LocalId(1),
                    ty: Type::I64,
                    value: RValue::Call {
                        function: FunctionId(1),
                        arguments: vec![Operand::I64(1)],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(2),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::Local(LocalId(2))),
        },
    ])
}

fn dynamic_f64_artifact() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: Type::F64,
            },
            Parameter {
                local: LocalId(1),
                ty: Type::F64,
            },
        ],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Let {
            binder: LocalId(2),
            ty: Type::F64,
            value: primitive(
                Primitive::F64Add,
                vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
        },
    }])
}

fn two_recursive_components_artifact() -> CoreArtifact {
    let recursive = |id, result| Function {
        id: FunctionId(id),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Bool,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::If {
            condition: Operand::Local(LocalId(0)),
            then_term: Box::new(Term::Return(Operand::I64(result))),
            else_term: Box::new(Term::TailCall {
                function: FunctionId(id),
                arguments: vec![Operand::Local(LocalId(0))],
            }),
        },
    };
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::Bool,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(1),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(0))],
                },
                next: Box::new(Term::TailCall {
                    function: FunctionId(2),
                    arguments: vec![Operand::Local(LocalId(0))],
                }),
            },
        },
        recursive(1, 1),
        recursive(2, 2),
    ])
}

fn sum_artifact() -> CoreArtifact {
    let sum = SumType {
        name: "R1S1.UnsupportedSum".to_owned(),
        constructors: vec![
            naux::core::ConstructorType {
                name: "None".to_owned(),
                fields: vec![],
            },
            naux::core::ConstructorType {
                name: "Some".to_owned(),
                fields: vec![Type::I64],
            },
        ],
    };
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Sum(sum),
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::I64(0)),
    }])
}

fn array_artifact() -> CoreArtifact {
    let region = naux::core::RegionId(0);
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![region],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Array {
                region,
                mutability: Mutability::Read,
                element: Box::new(Type::F64),
            },
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::I64(0)),
    }])
}

fn tuple_artifact() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Tuple(vec![Type::I64, Type::I64]),
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: RValue::Project {
                tuple: Operand::Local(LocalId(0)),
                index: 0,
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }])
}

fn effectful_artifact() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::I64,
        }],
        effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
        result: Type::I64,
        body: Term::Return(Operand::Local(LocalId(0))),
    }])
}

fn run(artifact: &CoreArtifact, inputs: Vec<CoreValue>) -> EvaluationOutcome {
    evaluate(artifact, inputs, EvaluationBudget::new(100_000, 300))
        .expect("the verified scalar fixture must evaluate")
        .outcome
}

fn requests(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
) -> (
    BindingTimeRequest,
    BindingTimeCertificate,
    SpecializationRequest,
) {
    requests_with_budget(
        artifact,
        manifest,
        slots,
        SpecializationBudget::new(100_000, 100_000, 100_000, 100_000, 100_000_000),
    )
}

fn requests_with_budget(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
    specialization_budget: SpecializationBudget,
) -> (
    BindingTimeRequest,
    BindingTimeCertificate,
    SpecializationRequest,
) {
    let binding_time_request = BindingTimeRequest::p1v0(
        artifact,
        manifest,
        BindingTimeBudget::new(100_000, 100_000, 1_000),
    )
    .expect("the R1-S1 fixture B0 request must encode");
    let validated_binding_time = validate_binding_time_b0_request(artifact, &binding_time_request)
        .expect("the R1-S1 fixture B0 request must validate");
    let certificate = certify_binding_time_b0d(&validated_binding_time)
        .expect("the R1-S1 fixture B0 certificate must emit");
    let specialization_request = SpecializationRequest::p1v0(
        artifact,
        &binding_time_request,
        &certificate,
        slots,
        specialization_budget,
    )
    .expect("the R1-S1 fixture R0 request must encode");
    validate_specialization_r0a_request(
        artifact,
        &binding_time_request,
        &certificate,
        &specialization_request,
    )
    .expect("the R1-S1 fixture R0 request must validate");
    (binding_time_request, certificate, specialization_request)
}

fn specialize(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
    budget: PolyvariantR1Budget,
) -> Result<PolyvariantR1Specialization, PolyvariantR1Error> {
    let (binding_time_request, certificate, specialization_request) =
        requests(artifact, manifest, slots);
    let validated = validate_specialization_r0a_request(
        artifact,
        &binding_time_request,
        &certificate,
        &specialization_request,
    )
    .expect("the R1-S1 upstream request must remain valid");
    specialize_polyvariant_r1(&validated, budget)
}

fn specialize_with_output_budget(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
    r1_budget: PolyvariantR1Budget,
    output_budget: SpecializationBudget,
) -> Result<PolyvariantR1Specialization, PolyvariantR1Error> {
    let (binding_time_request, certificate, specialization_request) =
        requests_with_budget(artifact, manifest, slots, output_budget);
    let validated = validate_specialization_r0a_request(
        artifact,
        &binding_time_request,
        &certificate,
        &specialization_request,
    )
    .expect("the R1-S1 upstream request must remain valid");
    specialize_polyvariant_r1(&validated, r1_budget)
}

fn generous_r1_budget() -> PolyvariantR1Budget {
    PolyvariantR1Budget::new(100_000, 10_000, 10_000, 100_000)
}

fn contains_if(term: &Term) -> bool {
    match term {
        Term::If { .. } => true,
        Term::Let { next, .. } | Term::Region { body: next, .. } => contains_if(next),
        Term::Case { arms, .. } => arms.iter().any(|arm| contains_if(&arm.body)),
        Term::Handle { clauses, body, .. } => {
            clauses.iter().any(|clause| contains_if(&clause.body)) || contains_if(body)
        }
        Term::TailCall { .. } | Term::Return(_) => false,
    }
}

#[test]
fn r1_s1_source_fixtures_cover_both_dynamic_paths_calls_and_the_tail_loop() {
    let dynamic_if = dynamic_if_artifact();
    assert_eq!(
        run(&dynamic_if, vec![CoreValue::Bool(true), CoreValue::I64(5)]),
        EvaluationOutcome::Return(CoreValue::I64(12))
    );
    assert_eq!(
        run(&dynamic_if, vec![CoreValue::Bool(false), CoreValue::I64(5)]),
        EvaluationOutcome::Return(CoreValue::I64(-6))
    );

    assert_eq!(
        run(
            &mixed_direct_call_artifact(),
            vec![CoreValue::I64(9), CoreValue::I64(4)]
        ),
        EvaluationOutcome::Return(CoreValue::I64(13))
    );

    let tail_loop = same_key_tail_loop_artifact();
    for input in [0, 4] {
        assert_eq!(
            run(&tail_loop, vec![CoreValue::I64(17), CoreValue::I64(input)]),
            EvaluationOutcome::Return(CoreValue::I64(0))
        );
    }

    // These are valid Core-N0 artifacts; the R1-S1 boundary, not the canonical
    // verifier, is responsible for refusing their tuple/effect capabilities.
    let _ = tuple_artifact();
    let _ = effectful_artifact();

    let _ = requests(
        &dynamic_if,
        vec![BindingTime::Dynamic, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(Type::I64),
        ],
    );
}

#[test]
fn dynamic_if_residualizes_both_branches_and_matches_the_source() {
    let source = dynamic_if_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_r1_budget(),
    )
    .expect("dynamic If must specialize");
    verify(projected.artifact()).expect("R1-S1 residual must pass ordinary Core verification");
    let entry = projected
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == projected.artifact().program.entry)
        .expect("residual entry exists");
    assert!(contains_if(&entry.body));
    assert_eq!(projected.report().usage().branch_splits, 1);
    assert_eq!(entry.parameters.len(), 2);

    for (condition, input) in [(true, 5), (false, 5), (true, i64::MAX)] {
        let original = run(
            &source,
            vec![CoreValue::Bool(condition), CoreValue::I64(input)],
        );
        let residual = run(
            projected.artifact(),
            vec![CoreValue::Bool(condition), CoreValue::I64(input)],
        );
        assert_eq!(residual, original);
    }
}

#[test]
fn mixed_direct_call_omits_the_known_argument_and_keeps_the_dynamic_result() {
    let source = mixed_direct_call_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(naux::core::SpecializationValue::I64(9)),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_r1_budget(),
    )
    .expect("mixed direct call must specialize");
    assert_eq!(projected.artifact().program.functions.len(), 2);
    let entry = projected
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == projected.artifact().program.entry)
        .expect("residual entry exists");
    assert_eq!(entry.parameters.len(), 1);
    let callee_descriptor = projected
        .report()
        .variants()
        .iter()
        .find(|variant| variant.source_function() == FunctionId(1))
        .expect("mixed callee version exists");
    assert_eq!(
        callee_descriptor.patterns(),
        &[
            PolyvariantR1Pattern::KnownI64(9),
            PolyvariantR1Pattern::Dynamic(Type::I64),
        ]
    );
    let residual_callee = projected
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == callee_descriptor.residual_function())
        .expect("residual callee exists");
    assert_eq!(residual_callee.parameters.len(), 1);

    for dynamic in [-7, 0, 4, i64::MAX] {
        assert_eq!(
            run(projected.artifact(), vec![CoreValue::I64(dynamic)]),
            run(&source, vec![CoreValue::I64(9), CoreValue::I64(dynamic)])
        );
    }
}

#[test]
fn same_key_tail_recursion_closes_the_knot_and_is_deterministic() {
    let source = same_key_tail_loop_artifact();
    let project = || {
        specialize(
            &source,
            vec![BindingTime::Static, BindingTime::Dynamic],
            vec![
                SpecializationSlot::Static(naux::core::SpecializationValue::I64(17)),
                SpecializationSlot::Dynamic(Type::I64),
            ],
            generous_r1_budget(),
        )
        .expect("same-key recursive variant must close")
    };
    let first = project();
    let second = project();
    assert_eq!(first.report(), second.report());
    assert_eq!(
        first.artifact().semantic_hash,
        second.artifact().semantic_hash
    );
    assert_eq!(first.report().usage().variants, 2);
    assert_eq!(first.report().usage().branch_splits, 1);

    for remaining in [0, 1, 4, 12] {
        assert_eq!(
            run(first.artifact(), vec![CoreValue::I64(remaining)]),
            run(&source, vec![CoreValue::I64(17), CoreValue::I64(remaining)])
        );
    }
}

#[test]
fn one_mutually_recursive_scc_specializes_and_matches_the_source() {
    let source = mutual_tail_recursion_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_r1_budget(),
    )
    .expect("one mutually recursive SCC must be admitted");
    verify(projected.artifact()).expect("mutual-recursion residual must verify");

    assert_eq!(projected.report().usage().variants, 2);
    assert_eq!(projected.report().usage().branch_splits, 2);
    assert_eq!(projected.report().usage().dynamic_parameters, 2);
    assert_eq!(projected.report().variants().len(), 2);
    for (source_id, residual_id) in [(0, 0), (1, 1)] {
        let descriptor = &projected.report().variants()[residual_id as usize];
        assert_eq!(descriptor.source_function(), FunctionId(source_id));
        assert_eq!(descriptor.residual_function(), FunctionId(residual_id));
        assert_eq!(
            descriptor.patterns(),
            &[PolyvariantR1Pattern::Dynamic(Type::I64)]
        );
    }

    for input in [i64::MIN, -1, 0, 1, 2, 7, 31] {
        assert_eq!(
            run(projected.artifact(), vec![CoreValue::I64(input)]),
            run(&source, vec![CoreValue::I64(input)])
        );
    }
}

#[test]
fn nonzero_source_entry_is_canonically_remapped_and_matches_the_source() {
    let source = nonzero_entry_artifact();
    assert_eq!(source.program.entry, FunctionId(7));
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_r1_budget(),
    )
    .expect("a nonzero source entry must specialize");
    verify(projected.artifact()).expect("nonzero-entry residual must verify");

    assert_eq!(projected.artifact().program.entry, FunctionId(1));
    assert_eq!(projected.report().variants().len(), 2);
    let helper = &projected.report().variants()[0];
    assert_eq!(helper.source_function(), FunctionId(3));
    assert_eq!(helper.residual_function(), FunctionId(0));
    let entry = &projected.report().variants()[1];
    assert_eq!(entry.source_function(), FunctionId(7));
    assert_eq!(entry.residual_function(), FunctionId(1));

    let residual_entry = projected
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == projected.artifact().program.entry)
        .expect("remapped residual entry exists");
    let Term::Let {
        value: RValue::Call { function, .. },
        ..
    } = &residual_entry.body
    else {
        panic!("remapped residual entry must retain the direct helper call");
    };
    assert_eq!(*function, FunctionId(0));

    for input in [i64::MIN, -5, -1, 0, 1, i64::MAX] {
        assert_eq!(
            run(projected.artifact(), vec![CoreValue::I64(input)]),
            run(&source, vec![CoreValue::I64(input)])
        );
    }
}

#[test]
fn all_known_entry_folds_dynamic_control_out_of_the_residual() {
    let source = dynamic_if_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Static, BindingTime::Static],
        vec![
            SpecializationSlot::Static(naux::core::SpecializationValue::Bool(true)),
            SpecializationSlot::Static(naux::core::SpecializationValue::I64(5)),
        ],
        generous_r1_budget(),
    )
    .expect("all-known scalar entry must specialize");
    let entry = &projected.artifact().program.functions[0];
    assert!(entry.parameters.is_empty());
    assert!(!contains_if(&entry.body));
    assert_eq!(
        run(projected.artifact(), vec![]),
        EvaluationOutcome::Return(CoreValue::I64(12))
    );
}

#[test]
fn exact_r1_budgets_pass_and_every_one_below_limit_fails_closed() {
    let source = same_key_tail_loop_artifact();
    let manifest = vec![BindingTime::Static, BindingTime::Dynamic];
    let slots = vec![
        SpecializationSlot::Static(naux::core::SpecializationValue::I64(17)),
        SpecializationSlot::Dynamic(Type::I64),
    ];
    let baseline = specialize(
        &source,
        manifest.clone(),
        slots.clone(),
        generous_r1_budget(),
    )
    .expect("baseline specialization must pass");
    let usage = baseline.report().usage();
    let exact = PolyvariantR1Budget::new(
        usage.steps,
        usage.variants,
        usage.branch_splits,
        usage.dynamic_parameters,
    );
    let exact_result = specialize(&source, manifest.clone(), slots.clone(), exact)
        .expect("exact R1-S1 budgets must pass");
    assert_eq!(exact_result.report().usage(), usage);

    let candidates = [
        PolyvariantR1Budget::new(
            usage.steps - 1,
            usage.variants,
            usage.branch_splits,
            usage.dynamic_parameters,
        ),
        PolyvariantR1Budget::new(
            usage.steps,
            usage.variants - 1,
            usage.branch_splits,
            usage.dynamic_parameters,
        ),
        PolyvariantR1Budget::new(
            usage.steps,
            usage.variants,
            usage.branch_splits - 1,
            usage.dynamic_parameters,
        ),
        PolyvariantR1Budget::new(
            usage.steps,
            usage.variants,
            usage.branch_splits,
            usage.dynamic_parameters - 1,
        ),
    ];
    for candidate in candidates {
        assert!(
            specialize(&source, manifest.clone(), slots.clone(), candidate).is_err(),
            "one-below budget {candidate:?} must fail closed"
        );
    }
}

#[test]
fn zero_and_hard_cap_r1_budgets_are_rejected_before_specialization() {
    let source = dynamic_if_artifact();
    let manifest = vec![BindingTime::Dynamic, BindingTime::Dynamic];
    let slots = vec![
        SpecializationSlot::Dynamic(Type::Bool),
        SpecializationSlot::Dynamic(Type::I64),
    ];
    for budget in [
        PolyvariantR1Budget::new(0, 1, 1, 1),
        PolyvariantR1Budget::new(1, 0, 1, 1),
        PolyvariantR1Budget::new(1, 1, 0, 1),
        PolyvariantR1Budget::new(1, 1, 1, 0),
    ] {
        assert!(matches!(
            specialize(&source, manifest.clone(), slots.clone(), budget),
            Err(PolyvariantR1Error::ZeroBudget { .. })
        ));
    }
    for budget in [
        PolyvariantR1Budget::new(naux::core::R1_S1_MAX_STEPS_HARD_CAP + 1, 1, 1, 1),
        PolyvariantR1Budget::new(1, naux::core::R1_S1_MAX_VARIANTS_HARD_CAP + 1, 1, 1),
        PolyvariantR1Budget::new(1, 1, naux::core::R1_S1_MAX_BRANCH_SPLITS_HARD_CAP + 1, 1),
        PolyvariantR1Budget::new(
            1,
            1,
            1,
            naux::core::R1_S1_MAX_DYNAMIC_PARAMETERS_HARD_CAP + 1,
        ),
    ] {
        assert!(matches!(
            specialize(&source, manifest.clone(), slots.clone(), budget),
            Err(PolyvariantR1Error::BudgetHardCapExceeded { .. })
        ));
    }
}

#[test]
fn malformed_scalar_slot_types_are_rejected_by_the_upstream_envelope() {
    let source = dynamic_if_artifact();
    let binding_time_request = BindingTimeRequest::p1v0(
        &source,
        vec![BindingTime::Dynamic, BindingTime::Dynamic],
        BindingTimeBudget::new(100_000, 100_000, 1_000),
    )
    .expect("B0 request must encode");
    let validated_binding_time = validate_binding_time_b0_request(&source, &binding_time_request)
        .expect("B0 request must validate");
    let certificate = certify_binding_time_b0d(&validated_binding_time).expect("B0-D must certify");
    let malformed = SpecializationRequest::p1v0(
        &source,
        &binding_time_request,
        &certificate,
        vec![
            SpecializationSlot::Dynamic(Type::I64),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        SpecializationBudget::new(100_000, 100_000, 100_000, 100_000, 100_000_000),
    )
    .expect("malformed request still has a canonical envelope");
    assert!(
        validate_specialization_r0a_request(
            &source,
            &binding_time_request,
            &certificate,
            &malformed,
        )
        .is_err(),
        "R0-A must reject the Bool/I64 mismatch before R1 is callable"
    );
}

#[test]
fn residual_node_and_byte_caps_are_exact_and_fail_closed() {
    let source = dynamic_if_artifact();
    let manifest = vec![BindingTime::Dynamic, BindingTime::Dynamic];
    let slots = vec![
        SpecializationSlot::Dynamic(Type::Bool),
        SpecializationSlot::Dynamic(Type::I64),
    ];
    let baseline = specialize(
        &source,
        manifest.clone(),
        slots.clone(),
        generous_r1_budget(),
    )
    .expect("baseline residual must specialize");
    let nodes = baseline.report().residual_nodes();
    let bytes = baseline.report().residual_bytes();
    let output_budget = |max_nodes, max_bytes| {
        SpecializationBudget::new(100_000, 100_000, 100_000, max_nodes, max_bytes)
    };
    specialize_with_output_budget(
        &source,
        manifest.clone(),
        slots.clone(),
        generous_r1_budget(),
        output_budget(nodes, bytes),
    )
    .expect("exact residual caps must pass");
    assert!(matches!(
        specialize_with_output_budget(
            &source,
            manifest.clone(),
            slots.clone(),
            generous_r1_budget(),
            output_budget(nodes - 1, bytes)
        ),
        Err(PolyvariantR1Error::Residual(
            naux::core::ResidualGenerationError::ResidualNodeBudgetExceeded { .. }
        ))
    ));
    assert!(matches!(
        specialize_with_output_budget(
            &source,
            manifest,
            slots,
            generous_r1_budget(),
            output_budget(nodes, bytes - 1)
        ),
        Err(PolyvariantR1Error::Residual(
            naux::core::ResidualGenerationError::ResidualByteBudgetExceeded { .. }
        ))
    ));
}

#[test]
fn tuple_sum_array_and_effectful_sources_are_rejected_at_the_r1_boundary() {
    for aggregate in [tuple_artifact(), sum_artifact(), array_artifact()] {
        let ty = aggregate.program.functions[0].parameters[0].ty.clone();
        let error = specialize(
            &aggregate,
            vec![BindingTime::Dynamic],
            vec![SpecializationSlot::Dynamic(ty)],
            generous_r1_budget(),
        )
        .expect_err("aggregate source must be outside R1-S1");
        assert!(matches!(
            error,
            PolyvariantR1Error::UnsupportedType { .. }
                | PolyvariantR1Error::UnsupportedRegionParameters { .. }
                | PolyvariantR1Error::InvalidEntrySlot { .. }
        ));
    }

    let effectful = effectful_artifact();
    let effect_error = specialize(
        &effectful,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_r1_budget(),
    )
    .expect_err("effectful source must be outside R1-S1");
    assert!(matches!(
        effect_error,
        PolyvariantR1Error::UnsupportedEffects { .. }
    ));
}

#[test]
fn finite_static_recursion_builds_exact_versions_and_unbounded_keys_hit_the_cap() {
    let finite = static_countdown_artifact();
    let projected = specialize(
        &finite,
        vec![BindingTime::Static],
        vec![SpecializationSlot::Static(
            naux::core::SpecializationValue::I64(3),
        )],
        generous_r1_budget(),
    )
    .expect("finite static countdown must specialize");
    assert_eq!(projected.report().usage().variants, 4);
    assert_eq!(projected.report().usage().branch_splits, 0);
    let patterns = projected
        .report()
        .variants()
        .iter()
        .map(|variant| (variant.residual_function(), variant.patterns().to_vec()))
        .collect::<Vec<_>>();
    assert_eq!(
        patterns,
        vec![
            (FunctionId(0), vec![PolyvariantR1Pattern::KnownI64(0)]),
            (FunctionId(1), vec![PolyvariantR1Pattern::KnownI64(1)]),
            (FunctionId(2), vec![PolyvariantR1Pattern::KnownI64(2)]),
            (FunctionId(3), vec![PolyvariantR1Pattern::KnownI64(3)]),
        ]
    );
    assert_eq!(projected.artifact().program.entry, FunctionId(3));
    assert_eq!(
        run(projected.artifact(), vec![]),
        EvaluationOutcome::Return(CoreValue::I64(0))
    );

    let unbounded = unbounded_static_counter_artifact();
    let error = specialize(
        &unbounded,
        vec![BindingTime::Static],
        vec![SpecializationSlot::Static(
            naux::core::SpecializationValue::I64(0),
        )],
        PolyvariantR1Budget::new(100_000, 4, 10, 10),
    )
    .expect_err("changing static key sequence must not widen or fall back");
    assert!(matches!(
        error,
        PolyvariantR1Error::VariantBudgetExceeded { limit: 4 }
    ));
}

#[test]
fn nested_dynamic_control_consumes_an_exact_branch_budget() {
    let source = nested_dynamic_if_artifact();
    let manifest = vec![BindingTime::Dynamic, BindingTime::Dynamic];
    let slots = vec![
        SpecializationSlot::Dynamic(Type::Bool),
        SpecializationSlot::Dynamic(Type::Bool),
    ];
    let projected = specialize(
        &source,
        manifest.clone(),
        slots.clone(),
        generous_r1_budget(),
    )
    .expect("nested dynamic branches must specialize");
    assert_eq!(projected.report().usage().branch_splits, 2);
    for (left, right, expected) in [
        (true, true, 1),
        (true, false, 2),
        (false, true, 3),
        (false, false, 3),
    ] {
        assert_eq!(
            run(
                projected.artifact(),
                vec![CoreValue::Bool(left), CoreValue::Bool(right)]
            ),
            EvaluationOutcome::Return(CoreValue::I64(expected))
        );
    }
    assert!(matches!(
        specialize(
            &source,
            manifest,
            slots,
            PolyvariantR1Budget::new(100, 10, 1, 10)
        ),
        Err(PolyvariantR1Error::BranchBudgetExceeded { limit: 1 })
    ));
}

#[test]
fn version_keys_canonicalize_nan_but_preserve_signed_zero() {
    let source = f64_version_key_artifact();
    let projected = specialize(&source, vec![], vec![], generous_r1_budget())
        .expect("F64 version-key corpus must specialize");
    let callee_patterns = projected
        .report()
        .variants()
        .iter()
        .filter(|variant| variant.source_function() == FunctionId(1))
        .map(|variant| variant.patterns().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(callee_patterns.len(), 3);
    assert!(callee_patterns.contains(&vec![PolyvariantR1Pattern::KnownF64(0x7ff8_0000_0000_0000)]));
    assert!(callee_patterns.contains(&vec![PolyvariantR1Pattern::KnownF64(0)]));
    assert!(callee_patterns.contains(&vec![PolyvariantR1Pattern::KnownF64(1_u64 << 63)]));
    assert_eq!(
        run(projected.artifact(), vec![]),
        EvaluationOutcome::Return(CoreValue::F64(-0.0))
    );
}

#[test]
fn canonical_key_bytes_not_rust_signed_order_assign_function_ids() {
    let source = i64_version_key_order_artifact();
    let projected = specialize(&source, vec![], vec![], generous_r1_budget())
        .expect("I64 key-order corpus must specialize");
    let callees = projected
        .report()
        .variants()
        .iter()
        .filter(|variant| variant.source_function() == FunctionId(1))
        .collect::<Vec<_>>();
    assert_eq!(callees.len(), 2);
    assert_eq!(callees[0].patterns(), &[PolyvariantR1Pattern::KnownI64(1)]);
    assert_eq!(callees[0].residual_function(), FunctionId(1));
    assert_eq!(callees[1].patterns(), &[PolyvariantR1Pattern::KnownI64(-1)]);
    assert_eq!(callees[1].residual_function(), FunctionId(2));
    assert_eq!(
        run(projected.artifact(), vec![]),
        run(&source, vec![]),
        "temporary-to-canonical FunctionId remapping must preserve call targets"
    );
}

#[test]
fn dynamic_f64_residual_matches_nan_infinity_and_signed_zero_edges() {
    let source = dynamic_f64_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Dynamic(Type::F64),
            SpecializationSlot::Dynamic(Type::F64),
        ],
        generous_r1_budget(),
    )
    .expect("dynamic F64 program must specialize");
    for (left, right) in [
        (0.0, -0.0),
        (-0.0, -0.0),
        (f64::NAN, 1.0),
        (f64::INFINITY, f64::NEG_INFINITY),
        (f64::MAX, f64::MAX),
    ] {
        let original = run(&source, vec![CoreValue::F64(left), CoreValue::F64(right)]);
        let residual = run(
            projected.artifact(),
            vec![CoreValue::F64(left), CoreValue::F64(right)],
        );
        match (original, residual) {
            (
                EvaluationOutcome::Return(CoreValue::F64(expected)),
                EvaluationOutcome::Return(CoreValue::F64(actual)),
            ) if expected.is_nan() => assert!(actual.is_nan()),
            (
                EvaluationOutcome::Return(CoreValue::F64(expected)),
                EvaluationOutcome::Return(CoreValue::F64(actual)),
            ) => assert_eq!(actual.to_bits(), expected.to_bits()),
            (expected, actual) => assert_eq!(actual, expected),
        }
    }
}

#[test]
fn more_than_one_reachable_recursive_component_is_rejected() {
    let source = two_recursive_components_artifact();
    let error = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::Bool)],
        generous_r1_budget(),
    )
    .expect_err("R1-S1 admits at most one recursive SCC");
    assert!(matches!(
        error,
        PolyvariantR1Error::MultipleRecursiveComponents { count: 2 }
    ));
}

#[test]
fn r1_policy_and_residual_identity_are_locked_and_budget_bound() {
    let source = same_key_tail_loop_artifact();
    let manifest = vec![BindingTime::Static, BindingTime::Dynamic];
    let slots = vec![
        SpecializationSlot::Static(naux::core::SpecializationValue::I64(17)),
        SpecializationSlot::Dynamic(Type::I64),
    ];
    let first = specialize(
        &source,
        manifest.clone(),
        slots.clone(),
        generous_r1_budget(),
    )
    .expect("identity vector must specialize");
    let changed_budget = specialize(
        &source,
        manifest,
        slots,
        PolyvariantR1Budget::new(99_999, 10_000, 10_000, 100_000),
    )
    .expect("changed valid budget must still specialize");
    assert_eq!(
        first.report().policy_hash(),
        changed_budget.report().policy_hash()
    );
    assert_ne!(
        first.report().request_hash(),
        changed_budget.report().request_hash()
    );
    assert_eq!(
        first.report().residual_hash(),
        first.artifact().semantic_hash
    );
    assert_eq!(
        first.report().residual_nodes(),
        first.residual().residual_nodes
    );
    assert_eq!(
        first.report().residual_bytes(),
        first.residual().residual_bytes
    );
    assert_eq!(
        first.report().policy_hash().to_hex(),
        "21658612344c5d3502c3b74769131bb90c9f1f1e6c1599503afd142e536c19d1"
    );
    assert_eq!(
        first.report().request_hash().to_hex(),
        "0f245e34a481d407afc124b0c540aba06596697a624dcc2794abaec8b6aa2423"
    );
    assert_eq!(
        first.report().residual_hash().to_hex(),
        "a82ed85ffd70e3bfc8438156a04535e732d60d8166fd53e2ebe2a96f1650f615"
    );
    assert_eq!(first.report().usage().steps, 8);
    assert_eq!(first.report().usage().variants, 2);
    assert_eq!(first.report().usage().branch_splits, 1);
    assert_eq!(first.report().usage().dynamic_parameters, 2);
    assert_eq!(first.report().residual_nodes(), 16);
    assert_eq!(first.report().residual_bytes(), 188);
}
