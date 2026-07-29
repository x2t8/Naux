use naux::core::{
    certify_binding_time_b0d, evaluate, specialize_polyvariant_r1_s2,
    validate_binding_time_b0_request, validate_specialization_r0a_request, verify, BindingTime,
    BindingTimeBudget, BindingTimeCertificate, BindingTimeRequest, CaseArm, ConstructorType,
    CoreArtifact, CoreProfile, CoreValue, Effect, EffectRow, ErrorKind, EvaluationBudget,
    EvaluationOutcome, Function, FunctionId, LocalId, Mutability, NumericMode, Operand, Parameter,
    PolyvariantR1S2Budget, PolyvariantR1S2Error, PolyvariantR1S2Pattern,
    PolyvariantR1S2Specialization, Primitive, Program, RValue, RegionId, ResidualGenerationError,
    SpecializationBudget, SpecializationRequest, SpecializationSlot, SumType, Term, Type,
    R1_S2_MAX_CONTROL_SPLITS_HARD_CAP, R1_S2_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
    R1_S2_MAX_HELPER_DEPTH, R1_S2_MAX_HELPER_UNFOLDS_HARD_CAP,
    R1_S2_MAX_PARTIAL_VALUE_NODES_HARD_CAP, R1_S2_MAX_RESIDUAL_BYTES_HARD_CAP,
    R1_S2_MAX_RESIDUAL_NODES_HARD_CAP, R1_S2_MAX_VARIANTS_HARD_CAP, R1_S2_MAX_WORK_UNITS_HARD_CAP,
};

fn seal(functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: naux::core::SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    })
    .expect("the R1-S2 fixture must encode")
}

fn primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
}

fn option_i64(name: &str) -> SumType {
    SumType {
        name: name.to_owned(),
        constructors: vec![
            ConstructorType {
                name: "None".to_owned(),
                fields: vec![],
            },
            ConstructorType {
                name: "Some".to_owned(),
                fields: vec![Type::I64],
            },
        ],
    }
}

fn run(artifact: &CoreArtifact, arguments: Vec<CoreValue>) -> EvaluationOutcome {
    evaluate(artifact, arguments, EvaluationBudget::new(100_000, 300))
        .expect("the verified R1-S2 fixture must evaluate")
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
    let binding_time_request = BindingTimeRequest::p1v0(
        artifact,
        manifest,
        BindingTimeBudget::new(1_000_000, 1_000_000, 10_000),
    )
    .expect("the R1-S2 fixture B0 request must encode");
    let validated_binding_time = validate_binding_time_b0_request(artifact, &binding_time_request)
        .expect("the R1-S2 fixture B0 request must validate");
    let certificate = certify_binding_time_b0d(&validated_binding_time)
        .expect("the R1-S2 fixture B0 certificate must emit");
    let specialization_request = SpecializationRequest::p1v0(
        artifact,
        &binding_time_request,
        &certificate,
        slots,
        SpecializationBudget::new(1_000_000, 1_000_000, 10_000_000, 1_000_000, 1_000_000_000),
    )
    .expect("the R1-S2 fixture upstream request must encode");
    validate_specialization_r0a_request(
        artifact,
        &binding_time_request,
        &certificate,
        &specialization_request,
    )
    .expect("the R1-S2 fixture upstream request must validate");
    (binding_time_request, certificate, specialization_request)
}

fn specialize(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
    budget: PolyvariantR1S2Budget,
) -> Result<PolyvariantR1S2Specialization, PolyvariantR1S2Error> {
    let (binding_time_request, certificate, specialization_request) =
        requests(artifact, manifest, slots);
    let validated = validate_specialization_r0a_request(
        artifact,
        &binding_time_request,
        &certificate,
        &specialization_request,
    )
    .expect("the R1-S2 upstream request must remain valid");
    specialize_polyvariant_r1_s2(&validated, budget)
}

fn generous_budget() -> PolyvariantR1S2Budget {
    PolyvariantR1S2Budget::new(
        1_000_000,
        1_000_000,
        100_000,
        100_000,
        100_000,
        100_000,
        1_000_000,
        1_000_000_000,
    )
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Shapes {
    tuples: u64,
    projects: u64,
    constructs: u64,
    calls: u64,
    cases: u64,
    ifs: u64,
    tail_calls: u64,
}

fn shapes(artifact: &CoreArtifact) -> Shapes {
    let mut counts = Shapes::default();
    for function in &artifact.program.functions {
        count_term_shapes(&function.body, &mut counts);
    }
    counts
}

fn count_term_shapes(term: &Term, counts: &mut Shapes) {
    match term {
        Term::Let { value, next, .. } => {
            match value {
                RValue::Tuple(_) => counts.tuples += 1,
                RValue::Project { .. } => counts.projects += 1,
                RValue::Construct { .. } => counts.constructs += 1,
                RValue::Call { .. } => counts.calls += 1,
                RValue::Use(_)
                | RValue::Primitive { .. }
                | RValue::RefAlloc { .. }
                | RValue::RefLoad { .. }
                | RValue::RefStore { .. }
                | RValue::PackClosure { .. }
                | RValue::CallClosure { .. }
                | RValue::Perform { .. } => {}
            }
            count_term_shapes(next, counts);
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            counts.ifs += 1;
            count_term_shapes(then_term, counts);
            count_term_shapes(else_term, counts);
        }
        Term::Case { arms, .. } => {
            counts.cases += 1;
            for arm in arms {
                count_term_shapes(&arm.body, counts);
            }
        }
        Term::TailCall { .. } => counts.tail_calls += 1,
        Term::Region { body, .. } => count_term_shapes(body, counts),
        Term::Handle { clauses, body, .. } => {
            for clause in clauses {
                count_term_shapes(&clause.body, counts);
            }
            count_term_shapes(body, counts);
        }
        Term::Return(_) => {}
    }
}

fn tuple_projection_artifact() -> CoreArtifact {
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
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
            ty: pair,
            value: RValue::Tuple(vec![Operand::I64(7), Operand::Local(LocalId(0))]),
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: RValue::Project {
                    tuple: Operand::Local(LocalId(1)),
                    index: 0,
                },
                next: Box::new(Term::Let {
                    binder: LocalId(3),
                    ty: Type::I64,
                    value: RValue::Project {
                        tuple: Operand::Local(LocalId(1)),
                        index: 1,
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(4),
                        ty: Type::I64,
                        value: primitive(
                            Primitive::I64Add(NumericMode::Wrapping),
                            vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(3))],
                        ),
                        next: Box::new(Term::Return(Operand::Local(LocalId(4)))),
                    }),
                }),
            }),
        },
    }])
}

fn partial_tuple_return_artifact() -> CoreArtifact {
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::I64,
        }],
        effects: EffectRow::pure(),
        result: pair.clone(),
        body: Term::Let {
            binder: LocalId(1),
            ty: pair,
            value: RValue::Tuple(vec![Operand::I64(7), Operand::Local(LocalId(0))]),
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }])
}

fn opaque_tuple_projection_artifact() -> CoreArtifact {
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: pair,
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
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: RValue::Project {
                    tuple: Operand::Local(LocalId(0)),
                    index: 1,
                },
                next: Box::new(Term::Let {
                    binder: LocalId(3),
                    ty: Type::I64,
                    value: primitive(
                        Primitive::I64Sub(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(1))],
                    ),
                    next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                }),
            }),
        },
    }])
}

fn known_sum_case_artifact() -> CoreArtifact {
    let option = option_i64("R1S2.KnownOption");
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
            ty: Type::Sum(option.clone()),
            value: RValue::Construct {
                sum: option,
                constructor: 1,
                fields: vec![Operand::Local(LocalId(0))],
            },
            next: Box::new(Term::Case {
                scrutinee: Operand::Local(LocalId(1)),
                arms: vec![
                    CaseArm {
                        constructor: 0,
                        bindings: vec![],
                        body: Term::Return(Operand::I64(-9)),
                    },
                    CaseArm {
                        constructor: 1,
                        bindings: vec![LocalId(2)],
                        body: Term::Let {
                            binder: LocalId(3),
                            ty: Type::I64,
                            value: primitive(
                                Primitive::I64Add(NumericMode::Wrapping),
                                vec![Operand::Local(LocalId(2)), Operand::I64(1)],
                            ),
                            next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                        },
                    },
                ],
            }),
        },
    }])
}

fn unknown_sum_case_artifact() -> (CoreArtifact, SumType) {
    let option = option_i64("R1S2.UnknownOption");
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Sum(option.clone()),
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Case {
            scrutinee: Operand::Local(LocalId(0)),
            arms: vec![
                CaseArm {
                    constructor: 0,
                    bindings: vec![],
                    body: Term::Return(Operand::I64(11)),
                },
                CaseArm {
                    constructor: 1,
                    bindings: vec![LocalId(1)],
                    body: Term::Let {
                        binder: LocalId(2),
                        ty: Type::I64,
                        value: primitive(
                            Primitive::I64Add(NumericMode::Wrapping),
                            vec![Operand::Local(LocalId(1)), Operand::I64(3)],
                        ),
                        next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                    },
                },
            ],
        },
    }]);
    (artifact, option)
}

fn known_helper_artifact() -> CoreArtifact {
    seal(vec![
        Function {
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
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(0))],
                },
                next: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: primitive(
                        Primitive::I64Add(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                    ),
                    next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(10),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::I64(7)),
        },
    ])
}

fn partial_helper_artifact() -> CoreArtifact {
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    let maybe_pair = SumType {
        name: "R1S2.MaybePair".to_owned(),
        constructors: vec![
            ConstructorType {
                name: "Empty".to_owned(),
                fields: vec![],
            },
            ConstructorType {
                name: "Pair".to_owned(),
                fields: vec![pair.clone()],
            },
        ],
    };
    seal(vec![
        Function {
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
                ty: Type::Sum(maybe_pair.clone()),
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(0))],
                },
                next: Box::new(Term::Case {
                    scrutinee: Operand::Local(LocalId(1)),
                    arms: vec![
                        CaseArm {
                            constructor: 0,
                            bindings: vec![],
                            body: Term::Return(Operand::I64(-1)),
                        },
                        CaseArm {
                            constructor: 1,
                            bindings: vec![LocalId(2)],
                            body: Term::Let {
                                binder: LocalId(3),
                                ty: Type::I64,
                                value: RValue::Project {
                                    tuple: Operand::Local(LocalId(2)),
                                    index: 0,
                                },
                                next: Box::new(Term::Let {
                                    binder: LocalId(4),
                                    ty: Type::I64,
                                    value: RValue::Project {
                                        tuple: Operand::Local(LocalId(2)),
                                        index: 1,
                                    },
                                    next: Box::new(Term::Let {
                                        binder: LocalId(5),
                                        ty: Type::I64,
                                        value: primitive(
                                            Primitive::I64Add(NumericMode::Wrapping),
                                            vec![
                                                Operand::Local(LocalId(3)),
                                                Operand::Local(LocalId(4)),
                                            ],
                                        ),
                                        next: Box::new(Term::Return(Operand::Local(LocalId(5)))),
                                    }),
                                }),
                            },
                        },
                    ],
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(10),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::Sum(maybe_pair.clone()),
            body: Term::Let {
                binder: LocalId(11),
                ty: pair,
                value: RValue::Tuple(vec![Operand::I64(9), Operand::Local(LocalId(10))]),
                next: Box::new(Term::Let {
                    binder: LocalId(12),
                    ty: Type::Sum(maybe_pair.clone()),
                    value: RValue::Construct {
                        sum: maybe_pair,
                        constructor: 1,
                        fields: vec![Operand::Local(LocalId(11))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(12)))),
                }),
            },
        },
    ])
}

fn dynamic_control_helper_artifact() -> (CoreArtifact, SumType) {
    let option = option_i64("R1S2.DynamicHelperOption");
    let artifact = seal(vec![
        Function {
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
                Parameter {
                    local: LocalId(2),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(3),
                ty: Type::Sum(option.clone()),
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![
                        Operand::Local(LocalId(0)),
                        Operand::Local(LocalId(1)),
                        Operand::Local(LocalId(2)),
                    ],
                },
                next: Box::new(Term::Case {
                    scrutinee: Operand::Local(LocalId(3)),
                    arms: vec![
                        CaseArm {
                            constructor: 0,
                            bindings: vec![],
                            body: Term::Return(Operand::I64(-1)),
                        },
                        CaseArm {
                            constructor: 1,
                            bindings: vec![LocalId(4)],
                            body: Term::Return(Operand::Local(LocalId(4))),
                        },
                    ],
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(10),
                    ty: Type::Bool,
                },
                Parameter {
                    local: LocalId(11),
                    ty: Type::I64,
                },
                Parameter {
                    local: LocalId(12),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::Sum(option.clone()),
            body: Term::If {
                condition: Operand::Local(LocalId(10)),
                then_term: Box::new(Term::Let {
                    binder: LocalId(13),
                    ty: Type::Sum(option.clone()),
                    value: RValue::Construct {
                        sum: option.clone(),
                        constructor: 1,
                        fields: vec![Operand::Local(LocalId(11))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(13)))),
                }),
                else_term: Box::new(Term::Let {
                    binder: LocalId(14),
                    ty: Type::Sum(option.clone()),
                    value: RValue::Construct {
                        sum: option.clone(),
                        constructor: 1,
                        fields: vec![Operand::Local(LocalId(12))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(14)))),
                }),
            },
        },
    ]);
    (artifact, option)
}

fn alias_artifact() -> CoreArtifact {
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    seal(vec![
        Function {
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
                Parameter {
                    local: LocalId(2),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(3),
                ty: pair.clone(),
                value: RValue::Tuple(vec![Operand::Local(LocalId(1)), Operand::Local(LocalId(1))]),
                next: Box::new(Term::Let {
                    binder: LocalId(4),
                    ty: pair.clone(),
                    value: RValue::Tuple(vec![
                        Operand::Local(LocalId(1)),
                        Operand::Local(LocalId(2)),
                    ]),
                    next: Box::new(Term::If {
                        condition: Operand::Local(LocalId(0)),
                        then_term: Box::new(Term::TailCall {
                            function: FunctionId(1),
                            arguments: vec![Operand::Local(LocalId(3))],
                        }),
                        else_term: Box::new(Term::TailCall {
                            function: FunctionId(1),
                            arguments: vec![Operand::Local(LocalId(4))],
                        }),
                    }),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(10),
                ty: pair,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(11),
                ty: Type::I64,
                value: RValue::Project {
                    tuple: Operand::Local(LocalId(10)),
                    index: 0,
                },
                next: Box::new(Term::Let {
                    binder: LocalId(12),
                    ty: Type::I64,
                    value: RValue::Project {
                        tuple: Operand::Local(LocalId(10)),
                        index: 1,
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(13),
                        ty: Type::I64,
                        value: primitive(
                            Primitive::I64Sub(NumericMode::Wrapping),
                            vec![Operand::Local(LocalId(12)), Operand::Local(LocalId(11))],
                        ),
                        next: Box::new(Term::Return(Operand::Local(LocalId(13)))),
                    }),
                }),
            },
        },
    ])
}

fn recursive_aggregate_artifact() -> (CoreArtifact, SumType) {
    let option = option_i64("R1S2.RecursiveOption");
    let artifact = seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::Bool,
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::Sum(option.clone()),
                },
            ],
            effects: EffectRow::pure(),
            result: Type::Sum(option.clone()),
            body: Term::Let {
                binder: LocalId(2),
                ty: Type::Sum(option.clone()),
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
                    local: LocalId(10),
                    ty: Type::Bool,
                },
                Parameter {
                    local: LocalId(11),
                    ty: Type::Sum(option.clone()),
                },
            ],
            effects: EffectRow::pure(),
            result: Type::Sum(option.clone()),
            body: Term::If {
                condition: Operand::Local(LocalId(10)),
                then_term: Box::new(Term::Return(Operand::Local(LocalId(11)))),
                else_term: Box::new(Term::TailCall {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(10)), Operand::Local(LocalId(11))],
                }),
            },
        },
    ]);
    (artifact, option)
}

fn nested_f64_key_artifact() -> CoreArtifact {
    let pair = Type::Tuple(vec![Type::F64, Type::Bool]);
    let call = |binder, tuple, next| Term::Let {
        binder: LocalId(binder),
        ty: Type::F64,
        value: RValue::Call {
            function: FunctionId(1),
            arguments: vec![Operand::Local(LocalId(tuple))],
        },
        next: Box::new(next),
    };
    let mut body = Term::Return(Operand::Local(LocalId(8)));
    for (tuple_local, call_local, bits) in [
        (4, 8, 1_u64 << 63),
        (3, 7, 0_u64),
        (2, 6, 0x7ff8_0000_0000_00ff),
        (1, 5, 0x7ff8_0000_0000_0001),
    ]
    .into_iter()
    .rev()
    {
        body = Term::Let {
            binder: LocalId(tuple_local),
            ty: pair.clone(),
            value: RValue::Tuple(vec![
                Operand::F64(f64::from_bits(bits)),
                Operand::Local(LocalId(0)),
            ]),
            next: Box::new(call(call_local, tuple_local, body)),
        };
    }

    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::Bool,
            }],
            effects: EffectRow::pure(),
            result: Type::F64,
            body,
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(10),
                ty: pair,
            }],
            effects: EffectRow::pure(),
            result: Type::F64,
            body: Term::Let {
                binder: LocalId(11),
                ty: Type::F64,
                value: RValue::Project {
                    tuple: Operand::Local(LocalId(10)),
                    index: 0,
                },
                next: Box::new(Term::Let {
                    binder: LocalId(12),
                    ty: Type::Bool,
                    value: RValue::Project {
                        tuple: Operand::Local(LocalId(10)),
                        index: 1,
                    },
                    next: Box::new(Term::If {
                        condition: Operand::Local(LocalId(12)),
                        then_term: Box::new(Term::Return(Operand::Local(LocalId(11)))),
                        else_term: Box::new(Term::Return(Operand::Local(LocalId(11)))),
                    }),
                }),
            },
        },
    ])
}

fn budget_artifact() -> (CoreArtifact, SumType) {
    let option = option_i64("R1S2.BudgetOption");
    let artifact = seal(vec![
        Function {
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
                Parameter {
                    local: LocalId(2),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(3),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(1))],
                },
                next: Box::new(Term::Let {
                    binder: LocalId(4),
                    ty: Type::Sum(option.clone()),
                    value: RValue::Call {
                        function: FunctionId(2),
                        arguments: vec![Operand::Local(LocalId(1))],
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(5),
                        ty: Type::Sum(option.clone()),
                        value: RValue::Call {
                            function: FunctionId(3),
                            arguments: vec![
                                Operand::Local(LocalId(0)),
                                Operand::Local(LocalId(1)),
                                Operand::Local(LocalId(2)),
                            ],
                        },
                        next: Box::new(Term::Case {
                            scrutinee: Operand::Local(LocalId(5)),
                            arms: vec![
                                CaseArm {
                                    constructor: 0,
                                    bindings: vec![],
                                    body: Term::Return(Operand::Local(LocalId(3))),
                                },
                                CaseArm {
                                    constructor: 1,
                                    bindings: vec![LocalId(6)],
                                    body: Term::Return(Operand::Local(LocalId(6))),
                                },
                            ],
                        }),
                    }),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(10),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::I64(7)),
        },
        Function {
            id: FunctionId(2),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(20),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::Sum(option.clone()),
            body: Term::Let {
                binder: LocalId(21),
                ty: Type::Sum(option.clone()),
                value: RValue::Construct {
                    sum: option.clone(),
                    constructor: 1,
                    fields: vec![Operand::Local(LocalId(20))],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(21)))),
            },
        },
        Function {
            id: FunctionId(3),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(30),
                    ty: Type::Bool,
                },
                Parameter {
                    local: LocalId(31),
                    ty: Type::I64,
                },
                Parameter {
                    local: LocalId(32),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::Sum(option.clone()),
            body: Term::If {
                condition: Operand::Local(LocalId(30)),
                then_term: Box::new(Term::Let {
                    binder: LocalId(33),
                    ty: Type::Sum(option.clone()),
                    value: RValue::Construct {
                        sum: option.clone(),
                        constructor: 1,
                        fields: vec![Operand::Local(LocalId(31))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(33)))),
                }),
                else_term: Box::new(Term::Let {
                    binder: LocalId(34),
                    ty: Type::Sum(option.clone()),
                    value: RValue::Construct {
                        sum: option.clone(),
                        constructor: 1,
                        fields: vec![Operand::Local(LocalId(32))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(34)))),
                }),
            },
        },
    ]);
    (artifact, option)
}

fn repeated_opaque_projection_artifact() -> CoreArtifact {
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: pair,
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
                next: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: RValue::Project {
                        tuple: Operand::Local(LocalId(0)),
                        index: 0,
                    },
                    next: Box::new(Term::TailCall {
                        function: FunctionId(1),
                        arguments: vec![Operand::Local(LocalId(1)), Operand::Local(LocalId(2))],
                    }),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(10),
                    ty: Type::I64,
                },
                Parameter {
                    local: LocalId(11),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(12),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Sub(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(11)), Operand::Local(LocalId(10))],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(12)))),
            },
        },
    ])
}

fn helper_chain_artifact(helper_count: usize) -> CoreArtifact {
    assert!(helper_count > 0);
    let mut functions = Vec::with_capacity(helper_count + 1);
    functions.push(Function {
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
            value: RValue::Call {
                function: FunctionId(1),
                arguments: vec![Operand::Local(LocalId(0))],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    });
    for index in 1..=helper_count {
        let id = u32::try_from(index).expect("the bounded helper chain fits FunctionId");
        let body = if index == helper_count {
            Term::Return(Operand::Local(LocalId(0)))
        } else {
            Term::Let {
                binder: LocalId(1),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(id + 1),
                    arguments: vec![Operand::Local(LocalId(0))],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
            }
        };
        functions.push(Function {
            id: FunctionId(id),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body,
        });
    }
    seal(functions)
}

fn aggregate_array_artifact() -> CoreArtifact {
    let region = RegionId(0);
    let array = Type::Array {
        region,
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    };
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![region],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Tuple(vec![array]),
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::I64(0)),
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

fn exhausted_parameter_local_artifact() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(u32::MAX),
            ty: Type::I64,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::Local(LocalId(u32::MAX))),
    }])
}

fn exhausted_materializer_local_artifact() -> CoreArtifact {
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: pair.clone(),
        body: Term::Let {
            binder: LocalId(u32::MAX),
            ty: pair,
            value: RValue::Tuple(vec![Operand::I64(1), Operand::I64(2)]),
            next: Box::new(Term::Return(Operand::Local(LocalId(u32::MAX)))),
        },
    }])
}

#[test]
fn structural_tuple_projection_erases_shape_and_matches_wrapping_edges() {
    let source = tuple_projection_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_budget(),
    )
    .expect("the structural Tuple projection fixture must specialize");
    verify(projected.artifact()).expect("the structural Tuple residual must verify");
    let counts = shapes(projected.artifact());
    assert_eq!(counts.tuples, 0);
    assert_eq!(counts.projects, 0);
    for x in [i64::MIN, -1, 0, 1, i64::MAX] {
        assert_eq!(
            run(&source, vec![CoreValue::I64(x)]),
            run(projected.artifact(), vec![CoreValue::I64(x)])
        );
    }
}

#[test]
fn partial_tuple_return_materializes_once_in_field_order() {
    let source = partial_tuple_return_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_budget(),
    )
    .expect("the partial Tuple result must specialize");
    verify(projected.artifact()).expect("the partial Tuple residual must verify");
    let counts = shapes(projected.artifact());
    assert_eq!(counts.tuples, 1);
    assert_eq!(counts.projects, 0);
    for x in [-7, 0, 19] {
        assert_eq!(
            run(&source, vec![CoreValue::I64(x)]),
            run(projected.artifact(), vec![CoreValue::I64(x)])
        );
        assert_eq!(
            run(projected.artifact(), vec![CoreValue::I64(x)]),
            EvaluationOutcome::Return(CoreValue::Tuple(
                vec![CoreValue::I64(7), CoreValue::I64(x),]
            ))
        );
    }
}

#[test]
fn opaque_tuple_stays_one_parameter_and_projects_at_runtime() {
    let source = opaque_tuple_projection_artifact();
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(pair.clone())],
        generous_budget(),
    )
    .expect("the opaque Tuple fixture must specialize");
    verify(projected.artifact()).expect("the opaque Tuple residual must verify");
    let entry = projected
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == projected.artifact().program.entry)
        .expect("the residual entry must exist");
    assert_eq!(entry.parameters.len(), 1);
    assert_eq!(entry.parameters[0].ty, pair);
    assert_eq!(shapes(projected.artifact()).projects, 2);
    assert_eq!(
        projected.report().variants()[0].patterns(),
        &[PolyvariantR1S2Pattern::Hole {
            ty: Type::Tuple(vec![Type::I64, Type::I64]),
            alias: 0,
        }]
    );
    for (left, right) in [(-3, 8), (0, 0), (i64::MAX, i64::MIN)] {
        let argument = CoreValue::Tuple(vec![CoreValue::I64(left), CoreValue::I64(right)]);
        assert_eq!(
            run(&source, vec![argument.clone()]),
            run(projected.artifact(), vec![argument])
        );
    }
}

#[test]
fn known_sum_selects_one_arm_without_inspecting_the_dynamic_payload() {
    let source = known_sum_case_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_budget(),
    )
    .expect("the KnownSum fixture must specialize");
    verify(projected.artifact()).expect("the KnownSum residual must verify");
    let counts = shapes(projected.artifact());
    assert_eq!(counts.constructs, 0);
    assert_eq!(counts.cases, 0);
    for x in [i64::MIN, -1, 0, i64::MAX] {
        assert_eq!(
            run(&source, vec![CoreValue::I64(x)]),
            run(projected.artifact(), vec![CoreValue::I64(x)])
        );
    }
}

#[test]
fn unknown_sum_keeps_every_canonical_arm_and_payload_binding() {
    let (source, option) = unknown_sum_case_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::Sum(option.clone()))],
        generous_budget(),
    )
    .expect("the UnknownSum fixture must specialize");
    verify(projected.artifact()).expect("the UnknownSum residual must verify");
    assert_eq!(shapes(projected.artifact()).cases, 1);
    assert_eq!(projected.report().usage().control_splits, 1);
    let values = [
        CoreValue::Sum {
            ty: option.clone(),
            constructor: 0,
            fields: vec![],
        },
        CoreValue::Sum {
            ty: option.clone(),
            constructor: 1,
            fields: vec![CoreValue::I64(-3)],
        },
        CoreValue::Sum {
            ty: option.clone(),
            constructor: 1,
            fields: vec![CoreValue::I64(i64::MAX)],
        },
    ];
    for value in values {
        assert_eq!(
            run(&source, vec![value.clone()]),
            run(projected.artifact(), vec![value])
        );
    }
}

#[test]
fn zero_residual_helpers_propagate_known_and_nested_partial_results() {
    let known = known_helper_artifact();
    let known_result = specialize(
        &known,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_budget(),
    )
    .expect("the known helper result must propagate");
    verify(known_result.artifact()).expect("the known helper residual must verify");
    assert_eq!(known_result.artifact().program.functions.len(), 1);
    assert_eq!(shapes(known_result.artifact()).calls, 0);
    assert_eq!(known_result.report().usage().helper_unfolds, 1);

    let partial = partial_helper_artifact();
    let partial_result = specialize(
        &partial,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_budget(),
    )
    .expect("the nested partial helper result must propagate");
    verify(partial_result.artifact()).expect("the partial helper residual must verify");
    assert_eq!(partial_result.artifact().program.functions.len(), 1);
    let counts = shapes(partial_result.artifact());
    assert_eq!(counts.calls, 0);
    assert_eq!(counts.cases, 0);
    assert_eq!(counts.constructs, 0);
    assert_eq!(counts.tuples, 0);
    assert_eq!(counts.projects, 0);
    assert_eq!(partial_result.report().usage().helper_unfolds, 1);

    for x in [i64::MIN, -1, 0, 9, i64::MAX] {
        assert_eq!(
            run(&known, vec![CoreValue::I64(x)]),
            run(known_result.artifact(), vec![CoreValue::I64(x)])
        );
        assert_eq!(
            run(&partial, vec![CoreValue::I64(x)]),
            run(partial_result.artifact(), vec![CoreValue::I64(x)])
        );
    }
}

#[test]
fn dynamic_control_helper_is_not_unfolded_or_given_an_invented_payload() {
    let (source, _) = dynamic_control_helper_artifact();
    let projected = specialize(
        &source,
        vec![
            BindingTime::Dynamic,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(Type::I64),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_budget(),
    )
    .expect("the dynamic-control helper must residualize conservatively");
    verify(projected.artifact()).expect("the refused helper residual must verify");
    let counts = shapes(projected.artifact());
    assert_eq!(counts.calls, 1);
    assert_eq!(counts.cases, 1);
    assert_eq!(counts.ifs, 1);
    assert_eq!(projected.report().usage().helper_unfolds, 0);
    for (condition, left, right) in [(true, 4, 99), (false, 4, 99), (true, -7, -3)] {
        assert_eq!(
            run(
                &source,
                vec![
                    CoreValue::Bool(condition),
                    CoreValue::I64(left),
                    CoreValue::I64(right),
                ],
            ),
            run(
                projected.artifact(),
                vec![
                    CoreValue::Bool(condition),
                    CoreValue::I64(left),
                    CoreValue::I64(right),
                ],
            )
        );
    }
}

#[test]
fn structural_version_keys_preserve_aliases_and_flatten_signatures() {
    let source = alias_artifact();
    let first = specialize(
        &source,
        vec![
            BindingTime::Dynamic,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(Type::I64),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_budget(),
    )
    .expect("the alias-sensitive fixture must specialize");
    let second = specialize(
        &source,
        vec![
            BindingTime::Dynamic,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(Type::I64),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_budget(),
    )
    .expect("repeated alias specialization must pass");
    assert_eq!(first, second, "R1-S2 output must be deterministic");
    verify(first.artifact()).expect("the alias-sensitive residual must verify");

    let repeated = PolyvariantR1S2Pattern::Tuple(vec![
        PolyvariantR1S2Pattern::Hole {
            ty: Type::I64,
            alias: 0,
        },
        PolyvariantR1S2Pattern::Hole {
            ty: Type::I64,
            alias: 0,
        },
    ]);
    let distinct = PolyvariantR1S2Pattern::Tuple(vec![
        PolyvariantR1S2Pattern::Hole {
            ty: Type::I64,
            alias: 0,
        },
        PolyvariantR1S2Pattern::Hole {
            ty: Type::I64,
            alias: 1,
        },
    ]);
    let helper_variants = first
        .report()
        .variants()
        .iter()
        .filter(|variant| variant.source_function() == FunctionId(1))
        .collect::<Vec<_>>();
    assert_eq!(helper_variants.len(), 2);
    assert!(helper_variants
        .iter()
        .any(|variant| variant.patterns() == [repeated.clone()]));
    assert!(helper_variants
        .iter()
        .any(|variant| variant.patterns() == [distinct.clone()]));
    for variant in helper_variants {
        let function = first
            .artifact()
            .program
            .functions
            .iter()
            .find(|function| function.id == variant.residual_function())
            .expect("the described helper version must exist");
        let expected = if variant.patterns() == [repeated.clone()] {
            1
        } else {
            assert_eq!(variant.patterns(), std::slice::from_ref(&distinct));
            2
        };
        assert_eq!(function.parameters.len(), expected);
    }
    let counts = shapes(first.artifact());
    assert_eq!(counts.tuples, 0);
    assert_eq!(counts.projects, 0);
    for (condition, x, y) in [(true, 5, 17), (false, 5, 17), (false, -4, 9)] {
        assert_eq!(
            run(
                &source,
                vec![
                    CoreValue::Bool(condition),
                    CoreValue::I64(x),
                    CoreValue::I64(y),
                ],
            ),
            run(
                first.artifact(),
                vec![
                    CoreValue::Bool(condition),
                    CoreValue::I64(x),
                    CoreValue::I64(y),
                ],
            )
        );
    }
}

#[test]
fn repeated_opaque_projection_reuses_one_alias_and_the_first_operand() {
    let source = repeated_opaque_projection_artifact();
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(pair)],
        generous_budget(),
    )
    .expect("repeated opaque projection must specialize");
    verify(projected.artifact()).expect("the repeated-projection residual must verify");
    let helper = projected
        .report()
        .variants()
        .iter()
        .find(|variant| variant.source_function() == FunctionId(1))
        .expect("the residual helper version must exist");
    assert_eq!(
        helper.patterns(),
        &[
            PolyvariantR1S2Pattern::Hole {
                ty: Type::I64,
                alias: 0,
            },
            PolyvariantR1S2Pattern::Hole {
                ty: Type::I64,
                alias: 0,
            },
        ]
    );
    let helper_function = projected
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == helper.residual_function())
        .expect("the described helper function must exist");
    assert_eq!(helper_function.parameters.len(), 1);
    for (left, right) in [(-9, 4), (0, 17), (i64::MAX, i64::MIN)] {
        let input = CoreValue::Tuple(vec![CoreValue::I64(left), CoreValue::I64(right)]);
        assert_eq!(
            run(&source, vec![input.clone()]),
            run(projected.artifact(), vec![input])
        );
        assert_eq!(
            run(
                projected.artifact(),
                vec![CoreValue::Tuple(vec![
                    CoreValue::I64(left),
                    CoreValue::I64(right),
                ])],
            ),
            EvaluationOutcome::Return(CoreValue::I64(0))
        );
    }
}

#[test]
fn helper_depth_boundary_unfolds_exactly_and_refuses_one_deeper_chain() {
    let at_limit = helper_chain_artifact(R1_S2_MAX_HELPER_DEPTH);
    let exact = specialize(
        &at_limit,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_budget(),
    )
    .expect("the exact helper-depth boundary must unfold");
    verify(exact.artifact()).expect("the exact-depth residual must verify");
    assert_eq!(exact.artifact().program.functions.len(), 1);
    assert_eq!(shapes(exact.artifact()).calls, 0);

    let beyond = helper_chain_artifact(R1_S2_MAX_HELPER_DEPTH + 1);
    let refused = specialize(
        &beyond,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        generous_budget(),
    )
    .expect("the one-deeper helper chain must residualize, not diverge");
    verify(refused.artifact()).expect("the refused-depth residual must verify");
    assert_eq!(refused.artifact().program.functions.len(), 2);
    assert_eq!(shapes(refused.artifact()).calls, 1);
    for x in [-7, 0, 19] {
        assert_eq!(
            run(exact.artifact(), vec![CoreValue::I64(x)]),
            EvaluationOutcome::Return(CoreValue::I64(x))
        );
        assert_eq!(
            run(refused.artifact(), vec![CoreValue::I64(x)]),
            EvaluationOutcome::Return(CoreValue::I64(x))
        );
    }
}

#[test]
fn recursive_aggregate_call_closes_pending_without_helper_unfolding() {
    let (source, option) = recursive_aggregate_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(Type::Sum(option.clone())),
        ],
        generous_budget(),
    )
    .expect("the aggregate recursive knot must specialize");
    verify(projected.artifact()).expect("the aggregate recursive residual must verify");
    assert_eq!(projected.report().usage().variants, 2);
    assert_eq!(projected.report().usage().helper_unfolds, 0);
    let counts = shapes(projected.artifact());
    assert_eq!(counts.calls, 1);
    assert_eq!(counts.tail_calls, 1);
    assert_eq!(counts.ifs, 1);
    for value in [
        CoreValue::Sum {
            ty: option.clone(),
            constructor: 0,
            fields: vec![],
        },
        CoreValue::Sum {
            ty: option.clone(),
            constructor: 1,
            fields: vec![CoreValue::I64(41)],
        },
    ] {
        assert_eq!(
            run(&source, vec![CoreValue::Bool(true), value.clone()]),
            run(projected.artifact(), vec![CoreValue::Bool(true), value])
        );
    }
}

#[test]
fn nested_f64_patterns_canonicalize_nan_and_preserve_signed_zero() {
    let source = nested_f64_key_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::Bool)],
        generous_budget(),
    )
    .expect("the nested F64 key fixture must specialize");
    verify(projected.artifact()).expect("the nested F64 residual must verify");
    let helper_patterns = projected
        .report()
        .variants()
        .iter()
        .filter(|variant| variant.source_function() == FunctionId(1))
        .map(|variant| variant.patterns().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(helper_patterns.len(), 3);
    for bits in [0x7ff8_0000_0000_0000, 0, 1_u64 << 63] {
        assert!(
            helper_patterns.contains(&vec![PolyvariantR1S2Pattern::Tuple(vec![
                PolyvariantR1S2Pattern::KnownF64(bits),
                PolyvariantR1S2Pattern::Hole {
                    ty: Type::Bool,
                    alias: 0,
                },
            ])])
        );
    }
    for condition in [false, true] {
        let source_outcome = run(&source, vec![CoreValue::Bool(condition)]);
        let residual_outcome = run(projected.artifact(), vec![CoreValue::Bool(condition)]);
        let (
            EvaluationOutcome::Return(CoreValue::F64(source_value)),
            EvaluationOutcome::Return(CoreValue::F64(residual_value)),
        ) = (source_outcome, residual_outcome)
        else {
            panic!("the nested F64 fixture must return F64");
        };
        assert_eq!(source_value.to_bits(), residual_value.to_bits());
        assert_eq!(residual_value.to_bits(), 1_u64 << 63);
    }
}

#[test]
fn every_exact_s2_budget_passes_and_every_one_below_fails_closed() {
    let (source, _) = budget_artifact();
    let manifest = || {
        vec![
            BindingTime::Dynamic,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ]
    };
    let slots = || {
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(Type::I64),
            SpecializationSlot::Dynamic(Type::I64),
        ]
    };
    let project = |budget| specialize(&source, manifest(), slots(), budget);
    let baseline = project(generous_budget()).expect("the budget fixture must specialize");
    let usage = baseline.report().usage();
    let nodes = baseline.report().residual_nodes();
    let bytes = baseline.report().residual_bytes();
    assert_eq!(
        baseline.report().policy_hash().to_hex(),
        "034ef346e4b036b8860e196fdb065c3b99ae024809d497a97ebccc66eb5c55f1"
    );
    assert_eq!(
        baseline.report().request_hash().to_hex(),
        "9a1707f75a3bb4d1f2d0bfea38b62999248b2e549c24f9f90886bda773c0f1f9"
    );
    assert_eq!(
        baseline.report().residual_hash().to_hex(),
        "d617aa9405c91b494a71b9fe533b05ec0c364774e1b766b14b9295e57c27353e"
    );
    assert_eq!(usage.work_units, 254);
    assert_eq!(usage.partial_value_nodes, 15);
    assert_eq!(usage.variants, 2);
    assert_eq!(usage.control_splits, 2);
    assert_eq!(usage.dynamic_parameters, 6);
    assert_eq!(usage.helper_unfolds, 2);
    assert_eq!(nodes, 23);
    assert_eq!(bytes, 549);
    assert!(
        [
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        ]
        .into_iter()
        .all(|value| value > 1),
        "the boundary fixture must make every one-below limit nonzero: {usage:?}, nodes={nodes}, bytes={bytes}"
    );

    let exact = PolyvariantR1S2Budget::new(
        usage.work_units,
        usage.partial_value_nodes,
        usage.variants,
        usage.control_splits,
        usage.dynamic_parameters,
        usage.helper_unfolds,
        nodes,
        bytes,
    );
    let exact_result = project(exact).expect("every exact R1-S2 limit must pass");
    assert_eq!(exact_result.report().usage(), usage);
    assert_eq!(exact_result.report().residual_nodes(), nodes);
    assert_eq!(exact_result.report().residual_bytes(), bytes);

    let candidate = |work, partial, variants, control, dynamic, helpers, max_nodes, max_bytes| {
        PolyvariantR1S2Budget::new(
            work, partial, variants, control, dynamic, helpers, max_nodes, max_bytes,
        )
    };
    assert!(matches!(
        project(candidate(
            usage.work_units - 1,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        )),
        Err(PolyvariantR1S2Error::WorkBudgetExceeded { limit }) if limit == usage.work_units - 1
    ));
    assert!(matches!(
        project(candidate(
            usage.work_units,
            usage.partial_value_nodes - 1,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        )),
        Err(PolyvariantR1S2Error::PartialValueBudgetExceeded { limit })
            if limit == usage.partial_value_nodes - 1
    ));
    assert!(matches!(
        project(candidate(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants - 1,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        )),
        Err(PolyvariantR1S2Error::VariantBudgetExceeded { limit })
            if limit == usage.variants - 1
    ));
    assert!(matches!(
        project(candidate(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits - 1,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        )),
        Err(PolyvariantR1S2Error::ControlBudgetExceeded { limit })
            if limit == usage.control_splits - 1
    ));
    assert!(matches!(
        project(candidate(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters - 1,
            usage.helper_unfolds,
            nodes,
            bytes,
        )),
        Err(PolyvariantR1S2Error::DynamicParameterBudgetExceeded { limit })
            if limit == usage.dynamic_parameters - 1
    ));
    assert!(matches!(
        project(candidate(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds - 1,
            nodes,
            bytes,
        )),
        Err(PolyvariantR1S2Error::HelperBudgetExceeded { limit })
            if limit == usage.helper_unfolds - 1
    ));
    assert!(matches!(
        project(candidate(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes - 1,
            bytes,
        )),
        Err(PolyvariantR1S2Error::Residual(
            ResidualGenerationError::ResidualNodeBudgetExceeded { limit, .. }
        )) if limit == nodes - 1
    ));
    assert!(matches!(
        project(candidate(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes - 1,
        )),
        Err(PolyvariantR1S2Error::Residual(
            ResidualGenerationError::ResidualByteBudgetExceeded { limit, .. }
        )) if limit == bytes - 1
    ));

    let changed_budget = PolyvariantR1S2Budget::new(
        generous_budget().max_work_units - 1,
        generous_budget().max_partial_value_nodes,
        generous_budget().max_variants,
        generous_budget().max_control_splits,
        generous_budget().max_dynamic_parameters,
        generous_budget().max_helper_unfolds,
        generous_budget().max_residual_nodes,
        generous_budget().max_residual_bytes,
    );
    let changed = project(changed_budget).expect("a still-sufficient budget must specialize");
    assert_eq!(
        baseline.report().policy_hash(),
        changed.report().policy_hash()
    );
    assert_ne!(
        baseline.report().request_hash(),
        changed.report().request_hash()
    );
    assert_eq!(
        baseline.report().residual_hash(),
        changed.report().residual_hash()
    );
    assert_eq!(baseline.report().usage(), changed.report().usage());
}

#[test]
fn zero_and_hard_cap_overflow_are_rejected_for_all_eight_budget_fields() {
    let source = tuple_projection_artifact();
    let manifest = || vec![BindingTime::Dynamic];
    let slots = || vec![SpecializationSlot::Dynamic(Type::I64)];
    let project = |budget| specialize(&source, manifest(), slots(), budget);
    for budget in [
        PolyvariantR1S2Budget::new(0, 1, 1, 1, 1, 1, 1, 1),
        PolyvariantR1S2Budget::new(1, 0, 1, 1, 1, 1, 1, 1),
        PolyvariantR1S2Budget::new(1, 1, 0, 1, 1, 1, 1, 1),
        PolyvariantR1S2Budget::new(1, 1, 1, 0, 1, 1, 1, 1),
        PolyvariantR1S2Budget::new(1, 1, 1, 1, 0, 1, 1, 1),
        PolyvariantR1S2Budget::new(1, 1, 1, 1, 1, 0, 1, 1),
        PolyvariantR1S2Budget::new(1, 1, 1, 1, 1, 1, 0, 1),
        PolyvariantR1S2Budget::new(1, 1, 1, 1, 1, 1, 1, 0),
    ] {
        assert!(matches!(
            project(budget),
            Err(PolyvariantR1S2Error::ZeroBudget { .. })
        ));
    }
    for budget in [
        PolyvariantR1S2Budget::new(R1_S2_MAX_WORK_UNITS_HARD_CAP + 1, 1, 1, 1, 1, 1, 1, 1),
        PolyvariantR1S2Budget::new(
            1,
            R1_S2_MAX_PARTIAL_VALUE_NODES_HARD_CAP + 1,
            1,
            1,
            1,
            1,
            1,
            1,
        ),
        PolyvariantR1S2Budget::new(1, 1, R1_S2_MAX_VARIANTS_HARD_CAP + 1, 1, 1, 1, 1, 1),
        PolyvariantR1S2Budget::new(1, 1, 1, R1_S2_MAX_CONTROL_SPLITS_HARD_CAP + 1, 1, 1, 1, 1),
        PolyvariantR1S2Budget::new(
            1,
            1,
            1,
            1,
            R1_S2_MAX_DYNAMIC_PARAMETERS_HARD_CAP + 1,
            1,
            1,
            1,
        ),
        PolyvariantR1S2Budget::new(1, 1, 1, 1, 1, R1_S2_MAX_HELPER_UNFOLDS_HARD_CAP + 1, 1, 1),
        PolyvariantR1S2Budget::new(1, 1, 1, 1, 1, 1, R1_S2_MAX_RESIDUAL_NODES_HARD_CAP + 1, 1),
        PolyvariantR1S2Budget::new(1, 1, 1, 1, 1, 1, 1, R1_S2_MAX_RESIDUAL_BYTES_HARD_CAP + 1),
    ] {
        assert!(matches!(
            project(budget),
            Err(PolyvariantR1S2Error::BudgetHardCapExceeded { .. })
        ));
    }
}

#[test]
fn unsupported_aggregate_effects_and_two_recursive_components_fail_closed() {
    let aggregate = aggregate_array_artifact();
    let aggregate_ty = aggregate.program.functions[0].parameters[0].ty.clone();
    let aggregate_error = specialize(
        &aggregate,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(aggregate_ty)],
        generous_budget(),
    )
    .expect_err("an aggregate containing Array must remain outside R1-S2");
    assert!(matches!(
        aggregate_error,
        PolyvariantR1S2Error::UnsupportedRegionParameters { .. }
            | PolyvariantR1S2Error::UnsupportedType { .. }
    ));

    let effectful = effectful_artifact();
    assert!(matches!(
        specialize(
            &effectful,
            vec![BindingTime::Dynamic],
            vec![SpecializationSlot::Dynamic(Type::I64)],
            generous_budget(),
        ),
        Err(PolyvariantR1S2Error::UnsupportedEffects { .. })
    ));

    let recursive = two_recursive_components_artifact();
    assert!(matches!(
        specialize(
            &recursive,
            vec![BindingTime::Dynamic],
            vec![SpecializationSlot::Dynamic(Type::Bool)],
            generous_budget(),
        ),
        Err(PolyvariantR1S2Error::MultipleRecursiveComponents { count: 2 })
    ));
}

#[test]
fn residual_parameters_and_materializers_fail_closed_at_local_id_exhaustion() {
    let parameter = exhausted_parameter_local_artifact();
    assert!(matches!(
        specialize(
            &parameter,
            vec![BindingTime::Dynamic],
            vec![SpecializationSlot::Dynamic(Type::I64)],
            generous_budget(),
        ),
        Err(PolyvariantR1S2Error::LocalIdExhausted)
    ));

    let materializer = exhausted_materializer_local_artifact();
    assert!(matches!(
        specialize(&materializer, vec![], vec![], generous_budget()),
        Err(PolyvariantR1S2Error::LocalIdExhausted)
    ));
}
