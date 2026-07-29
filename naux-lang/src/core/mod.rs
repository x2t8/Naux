//! Core-N0 semantic nucleus.
//!
//! This module intentionally depends only on Rust's standard library while
//! Rust remains the bridge implementation. It does not reuse the surface AST,
//! dynamic runtime `Value`, VM IR, JIT, or `egg`.

mod core_ssa;
mod corevm0;
mod corevm0_definitional;
mod corevm0_gate_a;
mod corevm0_r1_s3;
mod corevm0_r1_s4;
mod encoding;
mod interpret;
mod machine_ir;
mod polyvariant_r1;
mod polyvariant_r1_s2;
mod polyvariant_r1_s3;
mod polyvariant_r1_s4;
mod residual;
mod residual_evidence;
mod residual_r0c2;
mod schema;
mod specialization;
mod staging;
mod staging_verify;
mod static_evaluate;
mod static_evaluate_r0b2;
mod verify;
mod x64_native;
mod x64_target;

pub use core_ssa::{
    core_ssa_semantic_bytes, core_ssa_semantic_hash, evaluate_core_ssa,
    evaluate_core_ssa_translation, evaluate_source_bound_core_ssa, lower_core_ssa_r1_s5,
    verify_core_ssa, verify_core_ssa_source, CoreSsaArtifact, CoreSsaEncodeError,
    CoreSsaExecutionError, CoreSsaLowerError, CoreSsaProgram, CoreSsaSchemaVersion,
    CoreSsaSourceError, CoreSsaTranslationExecutionError, CoreSsaVerificationCode,
    CoreSsaVerificationError, CoreSsaVerificationErrors, SourceBoundCoreSsaArtifact, SsaBlock,
    SsaBlockId, SsaFunction, SsaInstruction, SsaInstructionKind, SsaOperand, SsaParameter,
    SsaTerminator, SsaValueId, VerifiedCoreSsaArtifact, CORE_SSA_LOWERING_POLICY_VERSION,
    CORE_SSA_MAX_BLOCKS, CORE_SSA_MAX_CFG_DEPTH, CORE_SSA_MAX_DIAGNOSTICS, CORE_SSA_MAX_EDGES,
    CORE_SSA_MAX_ENVIRONMENT_COPY_WORK, CORE_SSA_MAX_FUNCTIONS, CORE_SSA_MAX_INSTRUCTIONS,
    CORE_SSA_MAX_LIVE_VALUE_SLOTS, CORE_SSA_MAX_SEMANTIC_BYTES, CORE_SSA_MAX_VALUES,
    CORE_SSA_SCHEMA_NAME, CORE_SSA_SCHEMA_VERSION,
};
pub use corevm0::{
    branch_mix_kernel_program, corevm0_core_image, corevm0_instruction_slot_sum_type,
    corevm0_instruction_sum_type, corevm0_program_bytes, corevm0_program_hash,
    corevm0_program_image, corevm0_program_image_type, corevm0_type_slot_sum_type,
    evaluate_corevm0, verify_corevm0_program, verify_corevm0_program_image, CoreVmCoreImage,
    CoreVmCoreImageError, CoreVmEvaluation, CoreVmExecutionError, CoreVmInstruction, CoreVmOutcome,
    CoreVmProgram, CoreVmProgramImage, CoreVmProgramImageVerificationError, CoreVmType,
    CoreVmTypedError, CoreVmValue, CoreVmVerificationCode, CoreVmVerificationError,
    CoreVmVerificationErrors, VerifiedCoreVmProgram, COREVM0_INSTRUCTION_SLOT_SUM_NAME,
    COREVM0_INSTRUCTION_SUM_NAME, COREVM0_MAX_ARGUMENTS, COREVM0_MAX_INSTRUCTIONS,
    COREVM0_MAX_LOCALS, COREVM0_MAX_STACK, COREVM0_PROGRAM_IMAGE_VERSION, COREVM0_SCHEMA_VERSION,
    COREVM0_TYPE_SLOT_SUM_NAME,
};
pub use corevm0_definitional::{
    build_definitional_corevm0, evaluate_definitional_corevm0, DefinitionalCoreVmArtifact,
    DefinitionalCoreVmBuildError, DefinitionalCoreVmEvaluation, DefinitionalCoreVmExecutionError,
    COREVM0_BANK_UPDATE_SUM_NAME, COREVM0_DEFINITIONAL_CONSTRUCTION_VERSION,
    COREVM0_RUNTIME_VALUE_SUM_NAME, COREVM0_VALUE_LOOKUP_SUM_NAME,
};
pub use corevm0_gate_a::{
    corevm0_gate_a_case_input_hash, corevm0_gate_a_evidence_hash, corevm0_gate_a_execution_budget,
    corevm0_gate_a_manifest, corevm0_gate_a_manifest_hash, corevm0_gate_a_numeric_contract_hash,
    corevm0_gate_a_record_hash, corevm0_gate_a_results_hash, corevm0_gate_a_telemetry_hash,
    emit_corevm0_gate_a_r1_s5, verify_corevm0_gate_a_r1_s5, CoreVmGateAAssurance, CoreVmGateACase,
    CoreVmGateACaseClass, CoreVmGateACorpusManifest, CoreVmGateAEffect, CoreVmGateAError,
    CoreVmGateAEvidence, CoreVmGateAExecutionBudget, CoreVmGateAF64, CoreVmGateAInput,
    CoreVmGateAObservation, CoreVmGateAOutcome, CoreVmGateAReplayError, CoreVmGateAThreeWayRecord,
    CoreVmGateAUsage, CoreVmGateAWorkload, VerifiedCoreVmGateA, COREVM0_GATE_A_BOUNDS_CASES,
    COREVM0_GATE_A_CALL_DEPTH_LIMIT, COREVM0_GATE_A_CORPUS_VERSION, COREVM0_GATE_A_EDGE_CASES,
    COREVM0_GATE_A_EXHAUSTIVE_CASES, COREVM0_GATE_A_GENERATED_CASES, COREVM0_GATE_A_GENERATOR_SEED,
    COREVM0_GATE_A_GENERATOR_VERSION, COREVM0_GATE_A_MAX_ARRAY_ELEMENTS_PER_CASE,
    COREVM0_GATE_A_MAX_CASES, COREVM0_GATE_A_MAX_EFFECTS_PER_ENGINE,
    COREVM0_GATE_A_MAX_TOTAL_ARRAY_ELEMENTS, COREVM0_GATE_A_MAX_TOTAL_CORE_STEPS,
    COREVM0_GATE_A_MAX_TOTAL_RESIDUAL_STEPS, COREVM0_GATE_A_MAX_TOTAL_SEED_STEPS,
    COREVM0_GATE_A_NUMERIC_CONTRACT_VERSION, COREVM0_GATE_A_REPLAY_VERSION,
    COREVM0_GATE_A_RESIDUAL_STEP_LIMIT, COREVM0_GATE_A_SCHEMA_VERSION,
    COREVM0_GATE_A_SEED_STEP_LIMIT, COREVM0_GATE_A_TOTAL_CASES,
};
pub use corevm0_r1_s3::{
    specialize_corevm0_r1_s3, CoreVmR1S3Error, CoreVmR1S3Report, CoreVmR1S3Specialization,
    COREVM0_R1_S3_BINDING_VERSION,
};
pub use corevm0_r1_s4::{
    corevm0_r1_s4_evidence_hash, emit_corevm0_r1_s4_evidence, specialize_corevm0_r1_s4,
    verify_corevm0_r1_s4_evidence, CoreVmR1S4ErasureError, CoreVmR1S4ErasureReport,
    CoreVmR1S4Error, CoreVmR1S4Evidence, CoreVmR1S4ReplayError, CoreVmR1S4Report,
    CoreVmR1S4Specialization, COREVM0_R1_S4_BINDING_VERSION, COREVM0_R1_S4_ERASURE_VERSION,
    COREVM0_R1_S4_EVIDENCE_VERSION, COREVM0_R1_S4_REPLAY_VERSION,
};
pub use encoding::{
    binding_time_certificate_bytes, binding_time_certificate_hash, binding_time_node_bytes,
    binding_time_node_hash, binding_time_policy_bytes, binding_time_policy_hash,
    binding_time_request_bytes, binding_time_request_hash, interpreter_semantics_bytes,
    interpreter_semantics_hash, semantic_bytes, semantic_hash, specialization_policy_bytes,
    specialization_policy_hash, specialization_request_bytes, specialization_request_hash,
    specialization_value_bytes, specialization_value_hash, EncodeError,
};
pub use interpret::{
    evaluate, CoreClosure, CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome,
    ExecutionError, LogicalReference, OperationRequest,
};
pub use machine_ir::{
    evaluate_machine_ir, evaluate_machine_ir_translation, evaluate_source_bound_machine_ir,
    lower_machine_ir_r1_s6, machine_ir_semantic_bytes, machine_ir_semantic_hash, verify_machine_ir,
    verify_machine_ir_source, MachineBlock, MachineBlockId, MachineEffect, MachineF64BinaryOp,
    MachineFunction, MachineFunctionId, MachineI64BinaryOp, MachineI64CompareOp,
    MachineInstruction, MachineInstructionKind, MachineIntegerMode, MachineIrArtifact,
    MachineIrEncodeError, MachineIrExecutionError, MachineIrLimits, MachineIrLowerError,
    MachineIrProgram, MachineIrSchemaVersion, MachineIrSourceError,
    MachineIrTranslationExecutionError, MachineIrVerificationCode, MachineIrVerificationError,
    MachineIrVerificationErrors, MachineOperand, MachineParameter, MachineTerminator, MachineType,
    SourceBoundMachineIrArtifact, VerifiedMachineIrArtifact, VirtualRegister,
    MACHINE_IR_LOWERING_POLICY_VERSION, MACHINE_IR_MAX_BLOCKS, MACHINE_IR_MAX_CALL_DEPTH,
    MACHINE_IR_MAX_CFG_DEPTH, MACHINE_IR_MAX_DIAGNOSTICS, MACHINE_IR_MAX_EDGES,
    MACHINE_IR_MAX_EXECUTION_STEPS, MACHINE_IR_MAX_FUNCTIONS, MACHINE_IR_MAX_INSTRUCTIONS,
    MACHINE_IR_MAX_LIVE_REGISTER_SLOTS, MACHINE_IR_MAX_LOWERING_WORK, MACHINE_IR_MAX_OPERANDS,
    MACHINE_IR_MAX_REGISTERS, MACHINE_IR_MAX_SEMANTIC_BYTES, MACHINE_IR_SCHEMA_NAME,
    MACHINE_IR_SCHEMA_VERSION,
};
pub use polyvariant_r1::{
    polyvariant_r1_policy_hash, specialize_polyvariant_r1, PolyvariantR1Budget, PolyvariantR1Error,
    PolyvariantR1Pattern, PolyvariantR1Report, PolyvariantR1Specialization, PolyvariantR1Usage,
    PolyvariantR1Variant, POLYVARIANT_R1_S1_VERSION, R1_S1_MAX_BRANCH_SPLITS_HARD_CAP,
    R1_S1_MAX_DYNAMIC_PARAMETERS_HARD_CAP, R1_S1_MAX_STEPS_HARD_CAP, R1_S1_MAX_VARIANTS_HARD_CAP,
};
pub use polyvariant_r1_s2::{
    polyvariant_r1_s2_policy_hash, specialize_polyvariant_r1_s2, PolyvariantR1S2Budget,
    PolyvariantR1S2Error, PolyvariantR1S2Pattern, PolyvariantR1S2Report,
    PolyvariantR1S2Specialization, PolyvariantR1S2Usage, PolyvariantR1S2Variant,
    POLYVARIANT_R1_S2_VERSION, R1_S2_MAX_CONTROL_SPLITS_HARD_CAP,
    R1_S2_MAX_DYNAMIC_PARAMETERS_HARD_CAP, R1_S2_MAX_HELPER_DEPTH,
    R1_S2_MAX_HELPER_UNFOLDS_HARD_CAP, R1_S2_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
    R1_S2_MAX_RESIDUAL_BYTES_HARD_CAP, R1_S2_MAX_RESIDUAL_NODES_HARD_CAP,
    R1_S2_MAX_VARIANTS_HARD_CAP, R1_S2_MAX_WORK_UNITS_HARD_CAP,
};
pub use polyvariant_r1_s3::{
    polyvariant_r1_s3_policy_hash, specialize_polyvariant_r1_s3, PolyvariantR1S3Budget,
    PolyvariantR1S3Error, PolyvariantR1S3Pattern, PolyvariantR1S3Report,
    PolyvariantR1S3Specialization, PolyvariantR1S3Usage, PolyvariantR1S3Variant,
    POLYVARIANT_R1_S3_VERSION, R1_S3_MAX_CONTROL_SPLITS_HARD_CAP,
    R1_S3_MAX_DYNAMIC_PARAMETERS_HARD_CAP, R1_S3_MAX_HELPER_DEPTH,
    R1_S3_MAX_HELPER_UNFOLDS_HARD_CAP, R1_S3_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
    R1_S3_MAX_RESIDUAL_BYTES_HARD_CAP, R1_S3_MAX_RESIDUAL_NODES_HARD_CAP,
    R1_S3_MAX_VARIANTS_HARD_CAP, R1_S3_MAX_WORK_UNITS_HARD_CAP,
};
pub use polyvariant_r1_s4::{
    polyvariant_r1_s4_policy_hash, specialize_polyvariant_r1_s4,
    specialize_polyvariant_r1_s4_with_control, PolyvariantR1S4Budget, PolyvariantR1S4Control,
    PolyvariantR1S4Error, PolyvariantR1S4Pattern, PolyvariantR1S4Report,
    PolyvariantR1S4Specialization, PolyvariantR1S4Usage, PolyvariantR1S4Variant,
    POLYVARIANT_R1_S4_VERSION, R1_S4_MAX_CONTROL_SPLITS_HARD_CAP,
    R1_S4_MAX_DYNAMIC_PARAMETERS_HARD_CAP, R1_S4_MAX_HELPER_DEPTH,
    R1_S4_MAX_HELPER_UNFOLDS_HARD_CAP, R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
    R1_S4_MAX_RESIDUAL_BYTES_HARD_CAP, R1_S4_MAX_RESIDUAL_NODES_HARD_CAP,
    R1_S4_MAX_VARIANTS_HARD_CAP, R1_S4_MAX_WORK_UNITS_HARD_CAP,
};
pub use residual::{generate_residual_r0c, ResidualCore, ResidualGenerationError};
pub use residual_evidence::{
    emit_residual_evidence_r0d, mixed_static_evaluation_bytes, mixed_static_evaluation_hash,
    residual_evidence_bytes, residual_evidence_hash, verify_residual_evidence_r0d,
    ResidualEvidence, ResidualEvidenceBuildError, ResidualEvidenceCode, ResidualEvidenceError,
    ResidualEvidenceErrors, VerifiedResidualEvidence, R0D_EVIDENCE_SCHEMA_VERSION,
    R0D_REPLAY_POLICY_VERSION,
};
pub use residual_r0c2::generate_residual_r0c2;
pub use schema::{
    CaseArm, ConstructorType, CoreArtifact, CoreProfile, Effect, EffectRow, ErrorKind, Function,
    FunctionId, HandlerClause, LocalId, Mutability, NumericMode, Operand, OperationId,
    OperationSignature, Parameter, Primitive, Program, RValue, RegionId, SchemaVersion,
    SemanticHash, SumType, Term, Type, CORE_SCHEMA_NAME, CORE_SCHEMA_VERSION,
};
pub use specialization::{
    validate_specialization_r0a_request, SpecializationBudget, SpecializationRequest,
    SpecializationRequestCode, SpecializationRequestError, SpecializationRequestErrors,
    SpecializationSlot, SpecializationValue, ValidatedSpecializationRequest,
    R0_MAX_RESIDUAL_BYTES_HARD_CAP, R0_MAX_RESIDUAL_NODES_HARD_CAP,
    R0_MAX_SPECIALIZATION_STEPS_HARD_CAP, R0_MAX_STATIC_ARRAY_ELEMENTS_HARD_CAP,
    R0_MAX_STATIC_VALUE_NODES_HARD_CAP, R0_POLICY_VERSION, R0_REQUEST_SCHEMA_VERSION,
};
pub use staging::{
    analyze_binding_time_b0b, analyze_binding_time_b0c, certify_binding_time_b0d,
    validate_binding_time_b0_request, BindingTime, BindingTimeAnalysis, BindingTimeAnalysisCode,
    BindingTimeAnalysisError, BindingTimeBudget, BindingTimeBudgetUsage, BindingTimeCertificate,
    BindingTimeCertificateBuildError, BindingTimeFunctionSummary, BindingTimeJudgment,
    BindingTimeNodeId, BindingTimeNodeKind, BindingTimePathField, BindingTimePathSegment,
    BindingTimeRequest, BindingTimeRequestCode, BindingTimeRequestError, BindingTimeRequestErrors,
    StaticEvaluationEligibility, ValidatedBindingTimeRequest, B0_CERTIFICATE_SCHEMA_VERSION,
    B0_MAX_CALL_EDGES_HARD_CAP, B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP, B0_MAX_NODES_HARD_CAP,
    B0_POLICY_VERSION, B0_REQUEST_SCHEMA_VERSION,
};
pub use staging_verify::{
    verify_binding_time_b0_certificate, BindingTimeCertificateCode, BindingTimeCertificateError,
    BindingTimeCertificateErrors, VerifiedBindingTimeCertificate,
};
pub use static_evaluate::{
    evaluate_static_r0b1, StaticEvaluation, StaticEvaluationError, StaticEvaluationOutcome,
    StaticResidual, StaticResidualReason,
};
pub use static_evaluate_r0b2::{
    evaluate_static_r0b2, MixedStaticEvaluation, MixedStaticOutcome, SkippedStaticNode, StaticFact,
    R0B2_MAX_FRAMES,
};
pub use verify::{
    verify, VerificationCode, VerificationError, VerificationErrors, VerifiedArtifact,
};
pub use x64_native::{
    execute_x64_native_case_r1_s7b, execute_x64_native_r1_s7b,
    seal_x64_native_correspondence_evidence, seal_x64_native_correspondence_record,
    seal_x64_native_execution_record, verify_x64_native_correspondence_evidence,
    verify_x64_native_correspondence_record, verify_x64_native_execution_record,
    x64_native_canonical_abi_hash, x64_native_correspondence_record_hash,
    x64_native_correspondence_results_hash, x64_native_execution_record_hash,
    X64NativeCaseExecution, X64NativeCorrespondenceEffect, X64NativeCorrespondenceEvidence,
    X64NativeCorrespondenceF64, X64NativeCorrespondenceObservation, X64NativeCorrespondenceOutcome,
    X64NativeCorrespondenceRecord, X64NativeEvidenceError, X64NativeExecution,
    X64NativeExecutionRecord, X64NativeHashStage, X64NativeLimits, X64NativeMappingState,
    X64NativeRunnerError, X64_NATIVE_ENTRY_DISPATCH_POLICY_VERSION,
    X64_NATIVE_ENTRY_POLICY_VERSION, X64_NATIVE_EVIDENCE_SCHEMA_VERSION,
    X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS, X64_NATIVE_MAPPING_STATE_EVENTS,
    X64_NATIVE_MAX_BORROWED_F64_ARRAYS, X64_NATIVE_MAX_CODE_MAPPINGS,
    X64_NATIVE_MAX_CORRESPONDENCE_RECORDS, X64_NATIVE_MAX_DIAGNOSTICS,
    X64_NATIVE_MAX_EFFECTS_PER_ENGINE, X64_NATIVE_MAX_ENTRY_LANES, X64_NATIVE_MAX_MAPPING_BYTES,
    X64_NATIVE_MAX_RECORD_BYTES, X64_NATIVE_OUTPUT_WORDS, X64_NATIVE_RUNNER_POLICY_VERSION,
    X64_NATIVE_RUNNER_SCHEMA_VERSION, X64_NATIVE_SYSCALL_POLICY_VERSION,
};
pub use x64_target::{
    evaluate_source_bound_x64_target_plan, evaluate_x64_target_plan,
    evaluate_x64_target_translation, lower_x64_target_r1_s7a,
    seal_x64_target_correspondence_evidence, seal_x64_target_correspondence_record,
    verify_x64_target_correspondence_evidence, verify_x64_target_correspondence_record,
    verify_x64_target_r1_s7a, verify_x64_target_source, x64_target_code_hash,
    x64_target_correspondence_record_hash, x64_target_correspondence_results_hash,
    x64_target_plan_bytes, x64_target_plan_hash, x64_target_semantic_bytes,
    x64_target_semantic_hash, SourceBoundX64TargetArtifact, VerifiedX64TargetArtifact,
    X64AbiRegister, X64Block, X64BlockId, X64EntryAbi, X64EntryLane, X64Fixup, X64FrameLayout,
    X64Function, X64FunctionId, X64Home, X64HomeSlot, X64I64Opcode, X64Immediate, X64Instruction,
    X64InstructionKind, X64Label, X64LabelId, X64LabelOwner, X64Operand, X64Parameter,
    X64SetCondition, X64SourceOrigin, X64SourcePosition, X64Sse2F64Opcode, X64TargetAbi,
    X64TargetArchitecture, X64TargetArtifact, X64TargetCallingConvention, X64TargetCodeModel,
    X64TargetCorrespondenceEffect, X64TargetCorrespondenceError, X64TargetCorrespondenceEvidence,
    X64TargetCorrespondenceF64, X64TargetCorrespondenceObservation, X64TargetCorrespondenceOutcome,
    X64TargetCorrespondenceRecord, X64TargetEncodeError, X64TargetEndian, X64TargetFeatureProfile,
    X64TargetLimits, X64TargetLowerError, X64TargetOperatingSystem, X64TargetPlanEvaluatorError,
    X64TargetPlanExecutionError, X64TargetProgram, X64TargetSchemaVersion, X64TargetSourceError,
    X64TargetTranslationExecutionError, X64TargetVerificationCode, X64TargetVerificationError,
    X64TargetVerificationErrors, X64Terminator, X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION,
    X64_TARGET_ENCODER_POLICY_VERSION, X64_TARGET_LOWERING_POLICY_VERSION,
    X64_TARGET_MAX_CFG_DEPTH, X64_TARGET_MAX_CODE_BYTES,
    X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE, X64_TARGET_MAX_CORRESPONDENCE_RECORDS,
    X64_TARGET_MAX_DIAGNOSTICS, X64_TARGET_MAX_ENTRY_INPUT_LANES, X64_TARGET_MAX_FIXUPS,
    X64_TARGET_MAX_FRAME_BYTES, X64_TARGET_MAX_LABELS, X64_TARGET_MAX_LOWERING_WORK,
    X64_TARGET_MAX_OPS, X64_TARGET_MAX_OUTGOING_BYTES, X64_TARGET_MAX_PLAN_EVAL_WORK,
    X64_TARGET_MAX_SEMANTIC_BYTES, X64_TARGET_MAX_SOURCE_BLOCKS, X64_TARGET_MAX_SOURCE_FUNCTIONS,
    X64_TARGET_MAX_SOURCE_INSTRUCTIONS, X64_TARGET_SCHEMA_NAME, X64_TARGET_SCHEMA_VERSION,
};

impl CoreArtifact {
    /// Seal a Core program with the deterministic semantic hash used by the
    /// fail-closed verifier.
    pub fn seal(program: Program) -> Result<Self, EncodeError> {
        let semantic_hash = semantic_hash(&program)?;
        Ok(Self {
            program,
            semantic_hash,
        })
    }
}
