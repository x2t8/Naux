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
mod translation_correspondence;
mod verify;
mod x64_gate_b_baseline;
mod x64_gate_b_baseline_admission;
mod x64_gate_b_candidate;
mod x64_gate_b_candidate_admission;
mod x64_gate_b_candidate_diagnosis;
mod x64_gate_b_candidate_diagnostic_measurement;
mod x64_gate_b_candidate_ipc;
mod x64_gate_b_candidate_measurement;
mod x64_gate_b_candidate_process;
mod x64_gate_b_candidate_standalone_artifact;
mod x64_gate_b_candidate_standalone_authority;
mod x64_gate_b_candidate_standalone_process;
mod x64_gate_b_measurement;
mod x64_gate_b_profile;
mod x64_native;
mod x64_native_ipc;
mod x64_native_lighthouse;
mod x64_native_process;
mod x64_standalone_artifact;
mod x64_standalone_authority;
mod x64_standalone_elf;
mod x64_standalone_process;
mod x64_standalone_protocol;
mod x64_standalone_startup;
mod x64_standalone_startup_raw;
mod x64_tail_abi_envelope;
mod x64_tail_abi_envelope_decode;
mod x64_tail_body_frontier_capsule;
mod x64_tail_body_frontier_decode;
mod x64_tail_body_frontier_realization;
mod x64_tail_candidate_capsule;
mod x64_tail_candidate_decode;
mod x64_tail_closed_image;
mod x64_tail_closed_image_decode;
mod x64_tail_enveloped_correspondence;
mod x64_tail_enveloped_image;
mod x64_tail_enveloped_image_decode;
mod x64_tail_enveloped_ipc;
mod x64_tail_enveloped_native;
mod x64_tail_enveloped_process;
mod x64_tail_enveloped_worker;
mod x64_tail_site_binding;
mod x64_tail_state_allocation;
mod x64_tail_state_plan;
mod x64_tail_template_realization;
mod x64_tail_worker_artifact;
mod x64_tail_worker_elf;
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
pub use translation_correspondence::{
    emit_r1_s5_core_ssa_correspondence, emit_r1_s6_machine_ir_correspondence,
    r1_s5_core_ssa_correspondence_record_hash, r1_s5_core_ssa_correspondence_results_hash,
    r1_s6_machine_ir_correspondence_record_hash, r1_s6_machine_ir_correspondence_results_hash,
    verify_r1_s5_core_ssa_correspondence, verify_r1_s6_machine_ir_correspondence,
    R1S5CoreSsaCorrespondenceEvidence, R1S5CoreSsaCorrespondenceRecord,
    R1S6MachineIrCorrespondenceEvidence, R1S6MachineIrCorrespondenceRecord,
    TranslationCorrespondenceEffect, TranslationCorrespondenceError, TranslationCorrespondenceF64,
    TranslationCorrespondenceLimits, TranslationCorrespondenceObservation,
    TranslationCorrespondenceOutcome, TranslationCorrespondenceStage,
    VerifiedR1S5CoreSsaCorrespondence, VerifiedR1S6MachineIrCorrespondence,
    R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION, R1_S5_CORE_SSA_CORRESPONDENCE_RECORD_DOMAIN,
    R1_S5_CORE_SSA_CORRESPONDENCE_RESULTS_DOMAIN, R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION,
    R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION, R1_S6_MACHINE_IR_CORRESPONDENCE_RECORD_DOMAIN,
    R1_S6_MACHINE_IR_CORRESPONDENCE_RESULTS_DOMAIN, R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION,
    TRANSLATION_CORRESPONDENCE_BOUNDS_CASES, TRANSLATION_CORRESPONDENCE_BRANCH_CASES,
    TRANSLATION_CORRESPONDENCE_CALL_DEPTH_LIMIT,
    TRANSLATION_CORRESPONDENCE_MAX_EFFECTS_PER_OBSERVATION,
    TRANSLATION_CORRESPONDENCE_MAX_TOTAL_STEPS_PER_ENGINE,
    TRANSLATION_CORRESPONDENCE_STEP_LIMIT_PER_CASE, TRANSLATION_CORRESPONDENCE_TOTAL_CASES,
};
pub use verify::{
    verify, VerificationCode, VerificationError, VerificationErrors, VerifiedArtifact,
};
pub use x64_gate_b_baseline::{
    build_x64_gate_b_baseline_artifact, verify_x64_gate_b_baseline_artifact,
    x64_gate_b_baseline_target_hash, VerifiedX64GateBBaselineArtifact, X64GateBBaselineArtifact,
    X64GateBBaselineError, X64_GATE_B_BASELINE_IMAGE_BYTES, X64_GATE_B_BASELINE_POLICY_VERSION,
    X64_GATE_B_BASELINE_SCHEMA_VERSION, X64_GATE_B_BASELINE_STARTUP_BYTES,
    X64_GATE_B_BASELINE_TARGET_BYTES, X64_GATE_B_BASELINE_TARGET_OFFSET,
};
pub use x64_gate_b_baseline_admission::{
    emit_x64_gate_b_baseline_admission, verify_x64_gate_b_baseline_admission,
    VerifiedX64GateBBaselineAdmission, X64GateBBaselineAdmissionError,
    X64GateBBaselineAdmissionEvidence, X64GateBBaselineAdmissionRecord,
    X64_GATE_B_BASELINE_ADMISSION_CASES, X64_GATE_B_BASELINE_ADMISSION_POLICY_VERSION,
    X64_GATE_B_BASELINE_ADMISSION_SCHEMA_VERSION,
};
pub use x64_gate_b_candidate::{
    emit_x64_gate_b_policy15_candidate_capsule, verify_x64_gate_b_policy15_candidate_capsule,
    X64GateBPolicy15CandidateError,
};
pub use x64_gate_b_candidate_admission::{
    emit_x64_gate_b_policy15_candidate_correctness,
    emit_x64_gate_b_policy15_candidate_process_record,
    verify_x64_gate_b_policy15_candidate_correctness,
    x64_gate_b_policy15_candidate_accepted_correctness_results_hash,
    x64_gate_b_policy15_candidate_correctness_record_hash,
    x64_gate_b_policy15_candidate_correctness_results_hash,
    VerifiedX64GateBPolicy15CandidateCorrectness, X64GateBPolicy15CandidateCorrectnessError,
    X64GateBPolicy15CandidateCorrectnessEvidence, X64GateBPolicy15CandidateCorrectnessRecord,
    X64GateBPolicy15CandidateSelection, X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_CASES,
    X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION,
    X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_CANDIDATE_EXECUTION_CASES, X64_GATE_B_POLICY15_CANDIDATE_FALLBACK_CASES,
};
pub use x64_gate_b_candidate_diagnosis::{
    emit_x64_gate_b_policy15_cost_inventory, frozen_x64_gate_b_policy15_cost_inventory,
    verify_x64_gate_b_policy15_cost_inventory,
    verify_x64_gate_b_policy15_cost_inventory_against_profile,
    VerifiedX64GateBPolicy15CostInventory, X64GateBCostClassTotal, X64GateBPolicy15CostInventory,
    X64GateBPolicy15CostInventoryError, X64GateBSuccessorOptimizationClass,
    X64_GATE_B_POLICY15_COST_INVENTORY_POLICY_VERSION,
    X64_GATE_B_POLICY15_COST_INVENTORY_SCHEMA_VERSION,
};
pub use x64_gate_b_candidate_diagnostic_measurement::{
    emit_x64_gate_b_policy15_diagnostic_observation, select_x64_gate_b_policy15_successor,
    verify_x64_gate_b_policy15_diagnostic_observation,
    verify_x64_gate_b_policy15_successor_decision, VerifiedX64GateBPolicy15Diagnostic,
    VerifiedX64GateBPolicy15SuccessorDecision, X64GateBDiagnosticMember, X64GateBDiagnosticSample,
    X64GateBPolicy15DiagnosticError, X64GateBPolicy15DiagnosticObservation,
    X64GateBPolicy15SuccessorDecision, X64_GATE_B_POLICY15_DIAGNOSTIC_POLICY_VERSION,
    X64_GATE_B_POLICY15_DIAGNOSTIC_SCHEMA_VERSION, X64_GATE_B_POLICY15_FIXED_SYMMETRY_DENOMINATOR,
    X64_GATE_B_POLICY15_FIXED_SYMMETRY_NUMERATOR,
    X64_GATE_B_POLICY15_INCREMENTAL_SHARE_DENOMINATOR,
    X64_GATE_B_POLICY15_INCREMENTAL_SHARE_NUMERATOR,
    X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_DENOMINATOR,
    X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_NUMERATOR,
    X64_GATE_B_POLICY15_SUCCESSOR_DECISION_POLICY_VERSION,
    X64_GATE_B_POLICY15_SUCCESSOR_DECISION_SCHEMA_VERSION,
};
pub use x64_gate_b_candidate_ipc::{
    X64GateBPolicy15CandidateIpcError, X64GateBPolicy15CandidateIpcRecord,
    X64_GATE_B_POLICY15_CANDIDATE_IPC_MAX_FRAME_BYTES,
    X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION,
};
pub use x64_gate_b_candidate_measurement::{
    admit_x64_gate_b_policy15_measurement_claim, emit_x64_gate_b_policy15_measurement_observation,
    verify_x64_gate_b_policy15_measurement_observation, AdmittedX64GateBPolicy15Claim,
    VerifiedX64GateBPolicy15Measurement, X64GateBPolicy15ClaimRejection,
    X64GateBPolicy15MeasurementError, X64GateBPolicy15MeasurementObservation,
    X64_GATE_B_POLICY15_MEASUREMENT_POLICY_VERSION, X64_GATE_B_POLICY15_MEASUREMENT_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_STATISTICS_POLICY_VERSION, X64_GATE_B_POLICY15_THRESHOLD_POLICY_VERSION,
};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use x64_gate_b_candidate_process::probe_x64_gate_b_policy15_candidate_worker_debug;
pub use x64_gate_b_candidate_process::{
    emit_x64_gate_b_policy15_candidate_process_evidence,
    emit_x64_gate_b_policy15_candidate_worker_frame,
    execute_x64_gate_b_policy15_candidate_worker_case,
    verify_x64_gate_b_policy15_candidate_process_evidence,
    x64_gate_b_policy15_candidate_accepted_process_results_hash,
    x64_gate_b_policy15_candidate_process_results_hash, VerifiedX64GateBPolicy15CandidateProcess,
    X64GateBPolicy15CandidateProcessError, X64GateBPolicy15CandidateProcessEvidence,
    X64GateBPolicy15CandidateProcessReceipt, X64_GATE_B_POLICY15_CANDIDATE_PROCESS_SCHEMA_VERSION,
};
pub use x64_gate_b_candidate_standalone_artifact::{
    build_x64_gate_b_policy15_standalone_artifact, verify_x64_gate_b_policy15_standalone_artifact,
    x64_gate_b_policy15_accepted_standalone_artifact_hash,
    VerifiedX64GateBPolicy15StandaloneArtifact, X64GateBPolicy15StandaloneArtifact,
    X64GateBPolicy15StandaloneArtifactError,
    X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_VERIFIER_POLICY_VERSION,
    X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_WRITER_POLICY_VERSION,
};
pub use x64_gate_b_candidate_standalone_authority::{
    authorize_x64_gate_b_policy15_standalone, X64GateBPolicy15StandaloneAuthority,
    X64GateBPolicy15StandaloneAuthorityError,
    X64_GATE_B_POLICY15_STANDALONE_AUTHORITY_POLICY_VERSION,
    X64_GATE_B_POLICY15_STANDALONE_AUTHORITY_SCHEMA_VERSION,
};
pub use x64_gate_b_candidate_standalone_process::{
    emit_x64_gate_b_policy15_standalone_process_evidence,
    verify_x64_gate_b_policy15_standalone_process_evidence,
    x64_gate_b_policy15_accepted_standalone_results_hash,
    x64_gate_b_policy15_standalone_record_hash, x64_gate_b_policy15_standalone_results_hash,
    VerifiedX64GateBPolicy15StandaloneProcess, X64GateBPolicy15StandaloneExecutionRecord,
    X64GateBPolicy15StandaloneProcessError, X64GateBPolicy15StandaloneProcessEvidence,
    X64_GATE_B_POLICY15_STANDALONE_PROCESS_CASES,
    X64_GATE_B_POLICY15_STANDALONE_PROCESS_POLICY_VERSION,
    X64_GATE_B_POLICY15_STANDALONE_PROCESS_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_STANDALONE_RESULTS_POLICY_VERSION,
};
pub use x64_gate_b_measurement::{
    admit_x64_gate_b_measurement_claim, emit_x64_gate_b_measurement_observation,
    verify_x64_gate_b_measurement_observation, AdmittedX64GateBClaim, VerifiedX64GateBMeasurement,
    X64GateBClaimRejection, X64GateBEngine, X64GateBMeasurementError,
    X64GateBMeasurementObservation, X64GateBPairSample, X64GateBSampleStatistics,
    X64_GATE_B_ARRAY_ELEMENTS, X64_GATE_B_ELEMENT_VISITS, X64_GATE_B_MAX_CV_PERCENT,
    X64_GATE_B_MAX_SLOWDOWN_DENOMINATOR, X64_GATE_B_MAX_SLOWDOWN_NUMERATOR,
    X64_GATE_B_MEASURED_PAIRS, X64_GATE_B_MEASUREMENT_POLICY_VERSION,
    X64_GATE_B_MEASUREMENT_SCHEMA_VERSION, X64_GATE_B_PROCESS_TIMEOUT_MILLIS,
    X64_GATE_B_REPETITIONS, X64_GATE_B_WARMUP_PAIRS, X64_GATE_B_WORKLOAD_GENERATOR_SEED,
    X64_GATE_B_WORKLOAD_GENERATOR_VERSION,
};
pub use x64_gate_b_profile::{
    emit_x64_gate_b_weighted_profile, verify_x64_gate_b_weighted_profile,
    x64_gate_b_weighted_profile_hash, VerifiedX64GateBWeightedProfile, X64GateBWeightedProfile,
    X64GateBWeightedProfileError, X64_GATE_B_WEIGHTED_PROFILE_POLICY_VERSION,
    X64_GATE_B_WEIGHTED_PROFILE_SCHEMA_VERSION,
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
pub use x64_native_ipc::{
    decode_x64_native_ipc_record, encode_x64_native_ipc_record, seal_x64_native_ipc_record,
    verify_x64_native_ipc_record, x64_native_ipc_record_bytes, x64_native_ipc_record_hash,
    X64NativeIpcError, X64NativeIpcRecord, X64_NATIVE_IPC_RECORD_DOMAIN,
    X64_NATIVE_IPC_SCHEMA_VERSION, X64_NATIVE_PROCESS_POLICY_VERSION,
};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use x64_native_process::probe_x64_native_worker_debug_r1_s7bc;
pub use x64_native_process::{
    emit_x64_native_process_evidence_r1_s7bc, emit_x64_native_worker_frame_r1_s7bc,
    execute_x64_native_worker_case_r1_s7bc, verify_x64_native_process_evidence_r1_s7bc,
    x64_native_process_results_hash, VerifiedX64NativeProcessEvidence, X64NativeProcessError,
    X64NativeProcessEvidence, X64NativeProcessReceipt, X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES,
    X64_NATIVE_PROCESS_SCHEMA_VERSION, X64_NATIVE_PROCESS_TIMEOUT_MILLIS,
};
pub use x64_standalone_artifact::{
    build_x64_standalone_artifact_r1_s8, verify_x64_standalone_artifact_r1_s8,
    VerifiedX64StandaloneArtifact, X64StandaloneArtifact, X64StandaloneArtifactError,
    X64StandaloneArtifactLayout, X64StandaloneArtifactLimits, X64StandaloneArtifactUsage,
    X64_STANDALONE_ARTIFACT_SCHEMA_VERSION, X64_STANDALONE_ARTIFACT_VERIFIER_POLICY_VERSION,
    X64_STANDALONE_ARTIFACT_WRITER_POLICY_VERSION, X64_STANDALONE_ELF_LAYOUT_POLICY_VERSION,
    X64_STANDALONE_ELF_VERIFIER_POLICY_VERSION, X64_STANDALONE_ELF_WRITER_POLICY_VERSION,
};
pub use x64_standalone_authority::{
    authorize_x64_standalone_seed_r1_s8, X64StandaloneAuthorityError,
    X64StandaloneAuthorityHashField, X64StandaloneSeedAuthority,
};
pub use x64_standalone_process::{
    emit_x64_standalone_process_evidence_r1_s8c, verify_x64_standalone_process_evidence_r1_s8c,
    x64_standalone_execution_record_hash, x64_standalone_execution_results_hash,
    VerifiedX64StandaloneProcessEvidence, X64StandaloneExecutionEffect, X64StandaloneExecutionF64,
    X64StandaloneExecutionObservation, X64StandaloneExecutionOutcome, X64StandaloneExecutionRecord,
    X64StandaloneProcessError, X64StandaloneProcessEvidence, X64StandaloneTeardownFailure,
    X64_STANDALONE_EXECUTION_POLICY_VERSION, X64_STANDALONE_EXECUTION_RECORD_DOMAIN,
    X64_STANDALONE_EXECUTION_RESULTS_DOMAIN, X64_STANDALONE_EXECUTION_RESULTS_POLICY_VERSION,
    X64_STANDALONE_EXECUTION_SCHEMA_VERSION, X64_STANDALONE_PROCESS_EXECUTABLE_MODE,
    X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_BYTES, X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_RECORDS,
    X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
};
pub use x64_standalone_protocol::{
    decode_x64_standalone_input, decode_x64_standalone_input_for_profile,
    decode_x64_standalone_output, decode_x64_standalone_output_for_profile,
    encode_x64_standalone_input, encode_x64_standalone_output, X64StandaloneInput,
    X64StandaloneOutcome, X64StandaloneOutput, X64StandaloneProfile, X64StandaloneProtocolError,
    X64_STANDALONE_CANONICAL_NAN_BITS, X64_STANDALONE_INPUT_MAGIC,
    X64_STANDALONE_MAX_ARRAY_ELEMENTS, X64_STANDALONE_MAX_INPUT_BYTES,
    X64_STANDALONE_MAX_PAYLOAD_BYTES, X64_STANDALONE_OUTPUT_BYTES, X64_STANDALONE_OUTPUT_MAGIC,
    X64_STANDALONE_PROTOCOL_VERSION,
};
pub use x64_standalone_startup::{
    verify_x64_standalone_startup_plan_local_r1_s8, x64_standalone_io_contract_bytes,
    x64_standalone_io_contract_hash, x64_standalone_startup_code_hash,
    x64_standalone_startup_plan_bytes, x64_standalone_startup_plan_hash,
    LocallyVerifiedX64StandaloneStartupPlan, X64StandaloneStartupCondition,
    X64StandaloneStartupError, X64StandaloneStartupFixup, X64StandaloneStartupFixupKind,
    X64StandaloneStartupIoContract, X64StandaloneStartupLabel, X64StandaloneStartupLimits,
    X64StandaloneStartupOp, X64StandaloneStartupPlan, X64StandaloneStartupStackLayout,
    X64StandaloneStartupUsage, X64_STANDALONE_ELF_BASE, X64_STANDALONE_EXIT_INPUT,
    X64_STANDALONE_EXIT_INVARIANT, X64_STANDALONE_EXIT_IO, X64_STANDALONE_EXIT_MEMORY,
    X64_STANDALONE_EXIT_SUCCESS, X64_STANDALONE_IO_POLICY_VERSION,
    X64_STANDALONE_IO_SCHEMA_VERSION, X64_STANDALONE_MAX_ELF_IMAGE_BYTES,
    X64_STANDALONE_STARTUP_ENCODER_POLICY_VERSION, X64_STANDALONE_STARTUP_ENTRY_VADDR,
    X64_STANDALONE_STARTUP_LOWERING_POLICY_VERSION, X64_STANDALONE_STARTUP_MAX_CODE_BYTES,
    X64_STANDALONE_STARTUP_MAX_FIXUPS, X64_STANDALONE_STARTUP_MAX_LABELS,
    X64_STANDALONE_STARTUP_MAX_OPS, X64_STANDALONE_STARTUP_MAX_STACK_BYTES,
    X64_STANDALONE_STARTUP_OFFSET, X64_STANDALONE_STARTUP_PLANNER_POLICY_VERSION,
    X64_STANDALONE_STARTUP_SCHEMA_VERSION, X64_STANDALONE_STARTUP_TARGET_CALL_FIXUPS,
    X64_STANDALONE_TARGET_ALIGNMENT,
};
pub use x64_tail_abi_envelope::{
    emit_x64_tail_abi_envelope_capsule, verify_x64_tail_abi_envelope_capsule,
    x64_tail_abi_envelope_capsule_hash, x64_tail_abi_envelope_code_hash,
    VerifiedX64TailAbiEnvelopeCapsule, X64TailAbiEnvelopeAnchorReceipt, X64TailAbiEnvelopeCapsule,
    X64TailAbiEnvelopeEffect, X64TailAbiEnvelopeError, X64TailAbiEnvelopeInstructionReceipt,
    X64TailAbiEnvelopeProgramKind, X64TailAbiEnvelopeProgramReceipt,
    X64TailAbiEnvelopeRelocationReceipt, X64TailAbiEnvelopeTotals,
    X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES, X64_TAIL_ABI_ENVELOPE_MAX_EVIDENCE_BYTES,
    X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS, X64_TAIL_ABI_ENVELOPE_MAX_WORK,
    X64_TAIL_ABI_ENVELOPE_POLICY_VERSION, X64_TAIL_ABI_ENVELOPE_SCHEMA_VERSION,
};
pub use x64_tail_abi_envelope_decode::{
    decode_x64_tail_abi_envelope_capsule, X64TailAbiEnvelopeDecodeError, X64TailDecodedAbiEnvelope,
    X64_TAIL_ABI_ENVELOPE_DECODER_POLICY_VERSION,
};
pub use x64_tail_body_frontier_capsule::{
    emit_x64_tail_body_frontier_capsule, verify_x64_tail_body_frontier_capsule,
    x64_tail_body_frontier_capsule_hash, x64_tail_body_frontier_code_hash,
    VerifiedX64TailBodyFrontierCapsule, X64TailBodyCapsuleAnchorReceipt,
    X64TailBodyCapsuleExternalReference, X64TailBodyCapsuleFixupReceipt,
    X64TailBodyCapsuleProgramKind, X64TailBodyCapsuleProgramReceipt, X64TailBodyFrontierCapsule,
    X64TailBodyFrontierCapsuleError, X64TailBodyFrontierCapsuleTotals,
    X64_TAIL_BODY_CAPSULE_MAX_ANCHORS, X64_TAIL_BODY_CAPSULE_MAX_ATOMS,
    X64_TAIL_BODY_CAPSULE_MAX_CODE_BYTES, X64_TAIL_BODY_CAPSULE_MAX_ENCODER_WORK,
    X64_TAIL_BODY_CAPSULE_MAX_EVIDENCE_BYTES, X64_TAIL_BODY_CAPSULE_MAX_FIXUPS,
    X64_TAIL_BODY_CAPSULE_MAX_FRONTIER_PROGRAMS, X64_TAIL_BODY_CAPSULE_MAX_REFERENCES,
    X64_TAIL_BODY_CAPSULE_MAX_SITE_PROGRAMS, X64_TAIL_BODY_CAPSULE_POLICY_VERSION,
    X64_TAIL_BODY_CAPSULE_SCHEMA_VERSION,
};
pub use x64_tail_body_frontier_decode::{
    decode_x64_tail_body_frontier_bytes, X64TailBodyDecodeError, X64TailBodyDecodedAnchor,
    X64TailBodyDecodedAtom, X64TailBodyDecodedCapsule, X64TailBodyDecodedExternalReference,
    X64TailBodyDecodedFixup, X64TailBodyDecodedProgram, X64TailBodyDecodedProgramKind,
    X64_TAIL_BODY_DECODER_MAX_ANCHORS, X64_TAIL_BODY_DECODER_MAX_ATOMS,
    X64_TAIL_BODY_DECODER_MAX_CODE_BYTES, X64_TAIL_BODY_DECODER_MAX_FIXUPS,
    X64_TAIL_BODY_DECODER_MAX_PROGRAMS, X64_TAIL_BODY_DECODER_MAX_REFERENCES,
    X64_TAIL_BODY_DECODER_MAX_WORK, X64_TAIL_BODY_DECODER_POLICY_VERSION,
};
pub use x64_tail_body_frontier_realization::{
    emit_x64_tail_body_frontier_realization, verify_x64_tail_body_frontier_realization,
    x64_tail_body_frontier_realization_hash, VerifiedX64TailBodyFrontierRealization,
    X64TailBodyAtom, X64TailBodyAtomInstruction, X64TailBodyControlTarget, X64TailBodyFixup,
    X64TailBodyFrontierError, X64TailBodyFrontierRealization, X64TailBodyFrontierTotals,
    X64TailBodyScratch, X64TailBodySiteProgram, X64TailFrontierPlacement, X64TailFrontierProgram,
    X64TailFrontierProgramDisposition, X64_TAIL_BODY_FRONTIER_MAX_ATOMS,
    X64_TAIL_BODY_FRONTIER_MAX_ATOMS_PER_FRONTIER, X64_TAIL_BODY_FRONTIER_MAX_ATOMS_PER_SITE,
    X64_TAIL_BODY_FRONTIER_MAX_EVIDENCE_BYTES, X64_TAIL_BODY_FRONTIER_MAX_FIXUPS,
    X64_TAIL_BODY_FRONTIER_MAX_FRONTIER_PROGRAMS, X64_TAIL_BODY_FRONTIER_MAX_REPLAY_WORK,
    X64_TAIL_BODY_FRONTIER_MAX_SITE_PROGRAMS, X64_TAIL_BODY_FRONTIER_POLICY_VERSION,
    X64_TAIL_BODY_FRONTIER_SCHEMA_VERSION,
};
pub use x64_tail_candidate_capsule::{
    emit_x64_tail_candidate_capsule, verify_x64_tail_candidate_capsule,
    x64_tail_candidate_capsule_hash, x64_tail_candidate_code_hash, VerifiedX64TailCandidateCapsule,
    X64TailCandidateAnchorReceipt, X64TailCandidateCapsule, X64TailCandidateCapsuleError,
    X64TailCandidateCapsuleTotals, X64TailCandidateFixupReceipt, X64TailCandidateTransitionReceipt,
    X64_TAIL_CANDIDATE_CAPSULE_MAX_ANCHORS, X64_TAIL_CANDIDATE_CAPSULE_MAX_ATOMS,
    X64_TAIL_CANDIDATE_CAPSULE_MAX_CODE_BYTES, X64_TAIL_CANDIDATE_CAPSULE_MAX_ENCODER_WORK,
    X64_TAIL_CANDIDATE_CAPSULE_MAX_FIXUPS, X64_TAIL_CANDIDATE_CAPSULE_MAX_TRANSITIONS,
    X64_TAIL_CANDIDATE_CAPSULE_POLICY_VERSION, X64_TAIL_CANDIDATE_CAPSULE_SCHEMA_VERSION,
};
pub use x64_tail_candidate_decode::{
    decode_x64_tail_candidate_bytes, X64TailCandidateDecodeError, X64TailDecodedAnchor,
    X64TailDecodedAtom, X64TailDecodedCapsule, X64TailDecodedFixup, X64TailDecodedInstruction,
    X64TailDecodedTransition, X64_TAIL_CANDIDATE_DECODER_POLICY_VERSION,
    X64_TAIL_CANDIDATE_MAX_ANCHORS, X64_TAIL_CANDIDATE_MAX_CODE_BYTES,
    X64_TAIL_CANDIDATE_MAX_DECODED_ATOMS, X64_TAIL_CANDIDATE_MAX_DECODE_WORK,
};
pub use x64_tail_closed_image::{
    emit_x64_tail_closed_image, verify_x64_tail_closed_image, x64_tail_closed_image_code_hash,
    x64_tail_closed_image_hash, VerifiedX64TailClosedImage, X64TailClosedCfgDestination,
    X64TailClosedCfgEdge, X64TailClosedCfgEdgeKind, X64TailClosedFrontierReceipt,
    X64TailClosedImage, X64TailClosedImageError, X64TailClosedImageTotals,
    X64TailClosedLabelReceipt, X64TailClosedProgramKind, X64TailClosedProgramReceipt,
    X64TailClosedRelocationReceipt, X64TailClosedSourceKind, X64TailClosedSourceReceipt,
    X64TailClosedTerminalKind, X64TailClosedTerminalReceipt, X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES,
    X64_TAIL_CLOSED_IMAGE_MAX_EVIDENCE_BYTES, X64_TAIL_CLOSED_IMAGE_MAX_LABELS,
    X64_TAIL_CLOSED_IMAGE_MAX_PROGRAMS, X64_TAIL_CLOSED_IMAGE_MAX_RELOCATIONS,
    X64_TAIL_CLOSED_IMAGE_MAX_SOURCE_RANGES, X64_TAIL_CLOSED_IMAGE_MAX_WORK,
    X64_TAIL_CLOSED_IMAGE_POLICY_VERSION, X64_TAIL_CLOSED_IMAGE_SCHEMA_VERSION,
};
pub use x64_tail_closed_image_decode::{
    decode_x64_tail_closed_image, X64TailClosedImageDecodeError, X64TailDecodedClosedImage,
    X64_TAIL_CLOSED_IMAGE_DECODER_POLICY_VERSION,
};
pub use x64_tail_enveloped_correspondence::{
    emit_x64_tail_enveloped_correspondence, verify_x64_tail_enveloped_correspondence,
    verify_x64_tail_enveloped_observations, x64_tail_enveloped_correspondence_evidence_hash,
    x64_tail_enveloped_correspondence_record_hash, x64_tail_enveloped_correspondence_results_hash,
    VerifiedX64TailEnvelopedCorrespondence, VerifiedX64TailEnvelopedObservations,
    X64TailEnvelopedCorrespondenceError, X64TailEnvelopedCorrespondenceEvidence,
    X64TailEnvelopedCorrespondenceRecord, X64_TAIL_ENVELOPED_CORRESPONDENCE_ACCEPTED_ROOT,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_EFFECTS_PER_RECORD,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_RECORDS,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_POLICY_VERSION,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_SCHEMA_VERSION,
};
pub use x64_tail_enveloped_image::{
    emit_x64_tail_enveloped_image, verify_x64_tail_enveloped_image,
    x64_tail_enveloped_image_code_hash, x64_tail_enveloped_image_hash,
    VerifiedX64TailEnvelopedImage, X64TailEnvelopedImage, X64TailEnvelopedImageError,
    X64TailEnvelopedImageTotals, X64TailEnvelopedRelocationOrigin,
    X64TailEnvelopedRelocationReceipt, X64TailEnvelopedSourceKind, X64TailEnvelopedSourceReceipt,
    X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES, X64_TAIL_ENVELOPED_IMAGE_MAX_EVIDENCE_BYTES,
    X64_TAIL_ENVELOPED_IMAGE_MAX_RELOCATIONS, X64_TAIL_ENVELOPED_IMAGE_MAX_WORK,
    X64_TAIL_ENVELOPED_IMAGE_POLICY_VERSION, X64_TAIL_ENVELOPED_IMAGE_SCHEMA_VERSION,
};
pub use x64_tail_enveloped_image_decode::{
    decode_x64_tail_enveloped_image, X64TailDecodedEnvelopedImage,
    X64TailEnvelopedImageDecodeError, X64_TAIL_ENVELOPED_IMAGE_DECODER_POLICY_VERSION,
};
pub use x64_tail_enveloped_ipc::{
    decode_x64_tail_enveloped_ipc, encode_x64_tail_enveloped_ipc,
    x64_tail_enveloped_ipc_frame_hash, X64TailEnvelopedIpcError,
    X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES, X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION,
};
pub use x64_tail_enveloped_native::{
    execute_x64_tail_enveloped_native, X64TailEnvelopedNativeExecution,
    X64TailEnvelopedNativeHashStage, X64TailEnvelopedNativeLimits,
    X64TailEnvelopedNativeMappingState, X64TailEnvelopedNativeRunnerError,
    X64_TAIL_ENVELOPED_NATIVE_ENTRY_POLICY_VERSION, X64_TAIL_ENVELOPED_NATIVE_MAPPING_STATE_EVENTS,
    X64_TAIL_ENVELOPED_NATIVE_MAX_BORROWED_F64_ARRAYS, X64_TAIL_ENVELOPED_NATIVE_MAX_ENTRY_LANES,
    X64_TAIL_ENVELOPED_NATIVE_MAX_MAPPING_BYTES, X64_TAIL_ENVELOPED_NATIVE_OUTPUT_WORDS,
    X64_TAIL_ENVELOPED_NATIVE_POLICY_VERSION, X64_TAIL_ENVELOPED_NATIVE_SCHEMA_VERSION,
    X64_TAIL_ENVELOPED_NATIVE_SYSCALL_POLICY_VERSION,
};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use x64_tail_enveloped_process::probe_x64_tail_enveloped_worker;
pub use x64_tail_enveloped_process::{
    emit_x64_tail_enveloped_process_evidence, verify_x64_tail_enveloped_process_evidence,
    VerifiedX64TailEnvelopedProcess, X64TailEnvelopedProcessError, X64TailEnvelopedProcessEvidence,
    X64TailEnvelopedProcessReceipt, X64_TAIL_ENVELOPED_PROCESS_CHILDREN,
    X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT, X64_TAIL_ENVELOPED_PROCESS_MAX_STDERR_BYTES,
    X64_TAIL_ENVELOPED_PROCESS_POLICY_VERSION, X64_TAIL_ENVELOPED_PROCESS_SCHEMA_VERSION,
    X64_TAIL_ENVELOPED_PROCESS_TIMEOUT_MILLIS,
};
#[doc(hidden)]
pub use x64_tail_enveloped_worker::{
    emit_x64_tail_enveloped_worker_frame_adr0069, X64TailEnvelopedWorkerError,
};
pub use x64_tail_site_binding::{
    emit_x64_tail_site_binding_proof, verify_x64_tail_site_binding_proof,
    x64_tail_site_binding_proof_hash, VerifiedX64TailSiteBindingProof, X64TailAdapterWord,
    X64TailBoundDefinition, X64TailBoundRead, X64TailFrontierAction, X64TailFrontierBindingKind,
    X64TailFrontierBindingRow, X64TailSiteAliasConflict, X64TailSiteBinding,
    X64TailSiteBindingError, X64TailSiteBindingProof, X64TailSiteBindingTotals,
    X64TailSiteRegionReceipt, X64TailSiteRegionStatus, X64_TAIL_SITE_BINDING_MAX_ANALYSIS_WORK,
    X64_TAIL_SITE_BINDING_MAX_BOUND_WORDS, X64_TAIL_SITE_BINDING_MAX_CFG_EDGES,
    X64_TAIL_SITE_BINDING_MAX_EVIDENCE_BYTES, X64_TAIL_SITE_BINDING_MAX_FIXED_POINT_ROUNDS,
    X64_TAIL_SITE_BINDING_MAX_FRONTIER_ROWS, X64_TAIL_SITE_BINDING_MAX_REGIONS,
    X64_TAIL_SITE_BINDING_MAX_SITES, X64_TAIL_SITE_BINDING_MAX_WORDS_PER_REGION,
    X64_TAIL_SITE_BINDING_POLICY_VERSION, X64_TAIL_SITE_BINDING_SCHEMA_VERSION,
};
pub use x64_tail_state_allocation::{
    emit_x64_tail_physical_allocation, verify_x64_tail_physical_allocation,
    x64_tail_physical_allocation_hash, VerifiedX64TailPhysicalAllocation,
    X64TailPhysicalAllocation, X64TailPhysicalAllocationError, X64TailPhysicalAssignment,
    X64TailPhysicalLocation, X64TailPhysicalRefusalReason, X64TailPhysicalRegion,
    X64TailPhysicalRegionDisposition, X64TailPhysicalRegister, X64TailPhysicalScheduledSource,
    X64TailPhysicalSource, X64TailPhysicalStep, X64TailPhysicalTotals, X64TailPhysicalTransition,
    X64TailRegisterBank, X64TailScratchRegister, X64TailValueAllocation,
    X64_TAIL_PHYSICAL_GPR_LANES, X64_TAIL_PHYSICAL_MAX_ALLOCATION_WORK,
    X64_TAIL_PHYSICAL_MAX_BYTES_PER_OPERATION, X64_TAIL_PHYSICAL_MAX_INTERFERENCE_PAIRS,
    X64_TAIL_PHYSICAL_MAX_LOCATIONS_PER_REGION, X64_TAIL_PHYSICAL_MAX_TRANSITION_STEPS,
    X64_TAIL_PHYSICAL_POLICY_VERSION, X64_TAIL_PHYSICAL_SCHEMA_VERSION,
    X64_TAIL_PHYSICAL_XMM_LANES,
};
pub use x64_tail_state_plan::{
    emit_x64_tail_state_plan, verify_x64_tail_state_plan, x64_tail_state_plan_hash,
    VerifiedX64TailStatePlan, X64TailCopyStep, X64TailEdgeDisposition, X64TailEdgePlan,
    X64TailFrontier, X64TailFrontierKind, X64TailImmediateWord, X64TailRefusalReason,
    X64TailScheduledSource, X64TailStatePlan, X64TailStatePlanError, X64TailStateRegion,
    X64TailStateTotals, X64TailWordAssignment, X64TailWordLocation, X64TailWordSource,
    X64TailWordType, X64_TAIL_STATE_MAX_BYTES_PER_OPERATION, X64_TAIL_STATE_MAX_EDGES,
    X64_TAIL_STATE_MAX_FRONTIERS, X64_TAIL_STATE_MAX_REGIONS, X64_TAIL_STATE_MAX_REGION_EDGES,
    X64_TAIL_STATE_MAX_SCHEDULE_STEPS, X64_TAIL_STATE_MAX_WORDS_PER_EDGE,
    X64_TAIL_STATE_PLAN_POLICY_VERSION, X64_TAIL_STATE_PLAN_SCHEMA_VERSION,
};
pub use x64_tail_template_realization::{
    emit_x64_tail_template_realization, verify_x64_tail_template_realization,
    x64_tail_template_realization_hash, VerifiedX64TailTemplateRealization,
    X64TailPreservationSite, X64TailProgramTemplateKind, X64TailTemplateAtom, X64TailTemplateFixup,
    X64TailTemplateGpr, X64TailTemplateInstruction, X64TailTemplateRealization,
    X64TailTemplateRealizationError, X64TailTemplateRegister, X64TailTemplateSitePosition,
    X64TailTemplateTotals, X64TailTemplateTransition, X64TailTemplateXmm,
    X64_TAIL_TEMPLATE_MAX_ATOMS, X64_TAIL_TEMPLATE_MAX_FIXUPS, X64_TAIL_TEMPLATE_MAX_LAYOUT_BYTES,
    X64_TAIL_TEMPLATE_MAX_REPLAY_WORK, X64_TAIL_TEMPLATE_MAX_SITES,
    X64_TAIL_TEMPLATE_MAX_TRANSITIONS, X64_TAIL_TEMPLATE_POLICY_VERSION,
    X64_TAIL_TEMPLATE_SCHEMA_VERSION,
};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use x64_tail_worker_artifact::probe_x64_tail_worker_launch_evidence_mutations;
pub use x64_tail_worker_artifact::{
    admit_x64_tail_worker_artifact, emit_x64_tail_worker_launch_evidence,
    verify_x64_tail_worker_artifact, verify_x64_tail_worker_launch_evidence,
    x64_tail_worker_artifact_policy_hash, x64_tail_worker_expectation_from_reviewed_bytes,
    VerifiedX64TailWorkerArtifact, VerifiedX64TailWorkerLaunch, X64TailWorkerArtifact,
    X64TailWorkerArtifactError, X64TailWorkerArtifactExpectation, X64TailWorkerLaunchEvidence,
    X64TailWorkerLaunchReceipt, X64_TAIL_WORKER_ARTIFACT_EXECVEAT_FLAGS,
    X64_TAIL_WORKER_ARTIFACT_LAUNCH_MODE, X64_TAIL_WORKER_ARTIFACT_MAX_BYTES,
    X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT, X64_TAIL_WORKER_ARTIFACT_POLICY_VERSION,
    X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS, X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION,
};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use x64_tail_worker_elf::probe_x64_tail_worker_elf_evidence_mutations;
pub use x64_tail_worker_elf::{
    decode_x64_tail_worker_elf, emit_x64_tail_worker_elf_evidence,
    verify_x64_tail_worker_elf_evidence, x64_tail_worker_elf_evidence_hash,
    x64_tail_worker_elf_policy_hash, VerifiedX64TailWorkerElf, X64TailWorkerElfDependency,
    X64TailWorkerElfDynamicEntry, X64TailWorkerElfError, X64TailWorkerElfEvidence,
    X64TailWorkerElfHeader, X64TailWorkerElfSegment, X64TailWorkerElfTotals,
    X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES, X64_TAIL_WORKER_ELF_MAX_DYNAMIC_ENTRIES,
    X64_TAIL_WORKER_ELF_MAX_LOAD_SEGMENTS, X64_TAIL_WORKER_ELF_MAX_NAME_BYTES,
    X64_TAIL_WORKER_ELF_MAX_PROGRAM_HEADERS, X64_TAIL_WORKER_ELF_MAX_SECTION_HEADERS,
    X64_TAIL_WORKER_ELF_MAX_STRING_TABLE_BYTES, X64_TAIL_WORKER_ELF_POLICY_VERSION,
    X64_TAIL_WORKER_ELF_SCHEMA_VERSION,
};
pub use x64_target::{
    evaluate_source_bound_x64_target_plan, evaluate_x64_target_plan,
    evaluate_x64_target_translation, lower_x64_target_r1_s7a, profile_source_bound_x64_target_plan,
    profile_x64_target_plan, seal_x64_target_correspondence_evidence,
    seal_x64_target_correspondence_record, verify_x64_target_correspondence_evidence,
    verify_x64_target_correspondence_record, verify_x64_target_r1_s7a, verify_x64_target_source,
    x64_target_code_hash, x64_target_correspondence_record_hash,
    x64_target_correspondence_results_hash, x64_target_plan_bytes, x64_target_plan_hash,
    x64_target_policy15_accepted_candidate_capsule_hash,
    x64_target_policy15_candidate_capsule_hash,
    x64_target_prospective_shared_join_realization_hash, x64_target_semantic_bytes,
    x64_target_semantic_hash, SourceBoundX64TargetArtifact, VerifiedX64TargetArtifact,
    VerifiedX64TargetPolicy15CandidateCapsule, X64AbiRegister, X64Block, X64BlockId, X64EntryAbi,
    X64EntryLane, X64Fixup, X64FrameLayout, X64Function, X64FunctionId, X64Home, X64HomeSlot,
    X64I64Opcode, X64Immediate, X64Instruction, X64InstructionKind, X64Label, X64LabelId,
    X64LabelOwner, X64Operand, X64Parameter, X64SetCondition, X64SourceOrigin, X64SourcePosition,
    X64Sse2F64Opcode, X64TargetAbi, X64TargetArchitecture, X64TargetArtifact,
    X64TargetCallingConvention, X64TargetCodeModel, X64TargetCorrespondenceEffect,
    X64TargetCorrespondenceError, X64TargetCorrespondenceEvidence, X64TargetCorrespondenceF64,
    X64TargetCorrespondenceObservation, X64TargetCorrespondenceOutcome,
    X64TargetCorrespondenceRecord, X64TargetEncodeError, X64TargetEndian,
    X64TargetExecutionProfile, X64TargetFeatureProfile, X64TargetLimits, X64TargetLowerError,
    X64TargetOperatingSystem, X64TargetPlanEvaluatorError, X64TargetPlanExecutionError,
    X64TargetPolicy15CandidateCapsule, X64TargetPolicy15CandidateError, X64TargetProfileBlockCount,
    X64TargetProfileClassTotal, X64TargetProfileControlCounts, X64TargetProfileEdgeCount,
    X64TargetProfileError, X64TargetProfileEvent, X64TargetProfileInstructionCounts,
    X64TargetProfileSite, X64TargetProfileTemplateClass, X64TargetProfiledEvaluation,
    X64TargetProgram, X64TargetProspectiveExecutionAuthority, X64TargetProspectiveFixupReceipt,
    X64TargetProspectiveLabelDisposition, X64TargetProspectiveLabelReceipt,
    X64TargetProspectiveRealizationAtom, X64TargetProspectiveSharedJoinPartition,
    X64TargetProspectiveSharedJoinRealization, X64TargetSchemaVersion,
    X64TargetSharedJoinBranchArmCounts, X64TargetSharedJoinComposition,
    X64TargetSharedJoinCompositionIngress, X64TargetSharedJoinCompositionStep,
    X64TargetSharedJoinIngress, X64TargetSharedJoinKind, X64TargetSharedJoinOpportunity,
    X64TargetSharedJoinRouteEvent, X64TargetSourceError, X64TargetTranslationExecutionError,
    X64TargetVerificationCode, X64TargetVerificationError, X64TargetVerificationErrors,
    X64Terminator, X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION, X64_TARGET_ENCODER_POLICY_VERSION,
    X64_TARGET_LOWERING_POLICY_VERSION, X64_TARGET_MAX_CFG_DEPTH, X64_TARGET_MAX_CODE_BYTES,
    X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE, X64_TARGET_MAX_CORRESPONDENCE_RECORDS,
    X64_TARGET_MAX_DIAGNOSTICS, X64_TARGET_MAX_ENTRY_INPUT_LANES, X64_TARGET_MAX_FIXUPS,
    X64_TARGET_MAX_FRAME_BYTES, X64_TARGET_MAX_LABELS, X64_TARGET_MAX_LOWERING_WORK,
    X64_TARGET_MAX_OPS, X64_TARGET_MAX_OUTGOING_BYTES, X64_TARGET_MAX_PLAN_EVAL_WORK,
    X64_TARGET_MAX_PROFILE_EVAL_WORK, X64_TARGET_MAX_SEMANTIC_BYTES, X64_TARGET_MAX_SOURCE_BLOCKS,
    X64_TARGET_MAX_SOURCE_FUNCTIONS, X64_TARGET_MAX_SOURCE_INSTRUCTIONS,
    X64_TARGET_POLICY15_CANDIDATE_POLICY_VERSION, X64_TARGET_POLICY15_CANDIDATE_SCHEMA_VERSION,
    X64_TARGET_POLICY15_ENCODER_POLICY_VERSION, X64_TARGET_PROFILE_POLICY_VERSION,
    X64_TARGET_PROFILE_SCHEMA_VERSION, X64_TARGET_SCHEMA_NAME, X64_TARGET_SCHEMA_VERSION,
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
