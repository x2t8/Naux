//! Sealed deterministic weighted profile for the frozen Gate B workload.
//!
//! This is optimizer-selection evidence, not a timing claim. The profile
//! weights exact encoder-owned template byte spans by canonical plan-evaluator
//! event counts while leaving the standalone benchmark uninstrumented.

use super::corevm0_gate_a::{CoreVmGateAWorkload, COREVM0_GATE_A_CALL_DEPTH_LIMIT};
use super::encoding::sha256;
use super::interpret::{CoreValue, EvaluationBudget, EvaluationOutcome};
use super::schema::SemanticHash;
use super::x64_gate_b_measurement::{
    frozen_workload, X64GateBMeasurementError, X64_GATE_B_ARRAY_ELEMENTS,
    X64_GATE_B_ELEMENT_VISITS, X64_GATE_B_REPETITIONS, X64_GATE_B_WORKLOAD_GENERATOR_SEED,
    X64_GATE_B_WORKLOAD_GENERATOR_VERSION,
};
use super::x64_native_lighthouse::{X64NativeLighthouseError, X64NativeLighthousePackage};
use super::x64_target::{
    profile_source_bound_x64_target_plan, x64_target_prospective_shared_join_realization_hash,
    X64TargetExecutionProfile, X64TargetProfileError, X64TargetProfileEvent,
    X64TargetProfileTemplateClass, X64TargetProspectiveExecutionAuthority,
    X64TargetProspectiveLabelDisposition, X64TargetProspectiveMachineSemanticProof,
    X64TargetProspectiveSharedJoinPartition, X64TargetProspectiveSharedJoinRealization,
    X64TargetSharedJoinKind, X64TargetSharedJoinRouteEvent, X64_TARGET_ENCODER_POLICY_VERSION,
    X64_TARGET_MAX_PROFILE_EVAL_WORK, X64_TARGET_PROFILE_POLICY_VERSION,
    X64_TARGET_PROFILE_SCHEMA_VERSION,
};
use std::fmt;

pub const X64_GATE_B_WEIGHTED_PROFILE_SCHEMA_VERSION: (u16, u16, u16) = (1, 6, 0);
pub const X64_GATE_B_WEIGHTED_PROFILE_POLICY_VERSION: (u16, u16, u16) = (1, 5, 0);

const WEIGHTED_PROFILE_DOMAIN: &[u8] = b"NAUX:gate-b:weighted-profile:v2\0";
const MAX_WEIGHTED_PROFILE_HASH_PREIMAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROSPECTIVE_GATE_PROFILE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBWeightedProfile {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    generator_version: (u16, u16, u16),
    generator_seed: u64,
    array_elements: u32,
    repetitions: i64,
    element_visits: u64,
    input_values_hash: SemanticHash,
    input_frame_hash: SemanticHash,
    expected_result_bits: u64,
    target_semantic_hash: SemanticHash,
    target_plan_hash: SemanticHash,
    target_code_hash: SemanticHash,
    profile: X64TargetExecutionProfile,
    profile_hash: SemanticHash,
}

impl X64GateBWeightedProfile {
    pub const fn input_values_hash(&self) -> SemanticHash {
        self.input_values_hash
    }

    pub const fn input_frame_hash(&self) -> SemanticHash {
        self.input_frame_hash
    }

    pub const fn expected_result_bits(&self) -> u64 {
        self.expected_result_bits
    }

    pub const fn target_semantic_hash(&self) -> SemanticHash {
        self.target_semantic_hash
    }

    pub const fn target_plan_hash(&self) -> SemanticHash {
        self.target_plan_hash
    }

    pub const fn target_code_hash(&self) -> SemanticHash {
        self.target_code_hash
    }

    pub const fn profile(&self) -> &X64TargetExecutionProfile {
        &self.profile
    }

    pub const fn profile_hash(&self) -> SemanticHash {
        self.profile_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64GateBWeightedProfile<'profile> {
    profile: &'profile X64GateBWeightedProfile,
}

impl<'profile> VerifiedX64GateBWeightedProfile<'profile> {
    pub const fn profile(self) -> &'profile X64GateBWeightedProfile {
        self.profile
    }
}

#[derive(Debug)]
pub enum X64GateBWeightedProfileError {
    Workload(String),
    Lighthouse(String),
    Target(X64TargetProfileError),
    UnexpectedOutcome,
    UnexpectedEffect,
    InvalidEnvelope { field: &'static str },
    ProfileHashMismatch,
    ReplayMismatch,
    EncodingOverflow { field: &'static str },
}

impl fmt::Display for X64GateBWeightedProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workload(error) => {
                write!(
                    formatter,
                    "Gate B weighted-profile workload failed: {error}"
                )
            }
            Self::Lighthouse(error) => {
                write!(
                    formatter,
                    "Gate B weighted-profile lighthouse failed: {error}"
                )
            }
            Self::Target(error) => write!(formatter, "{error}"),
            Self::UnexpectedOutcome => formatter
                .write_str("Gate B weighted profile produced a non-canonical BranchMix outcome"),
            Self::UnexpectedEffect => formatter
                .write_str("Gate B weighted profile produced an unexpected observable effect"),
            Self::InvalidEnvelope { field } => {
                write!(
                    formatter,
                    "Gate B weighted-profile envelope has invalid {field}"
                )
            }
            Self::ProfileHashMismatch => {
                formatter.write_str("Gate B weighted-profile hash does not replay")
            }
            Self::ReplayMismatch => formatter
                .write_str("Gate B weighted profile differs from complete independent replay"),
            Self::EncodingOverflow { field } => {
                write!(
                    formatter,
                    "Gate B weighted-profile encoding overflowed {field}"
                )
            }
        }
    }
}

impl std::error::Error for X64GateBWeightedProfileError {}

impl From<X64GateBMeasurementError> for X64GateBWeightedProfileError {
    fn from(value: X64GateBMeasurementError) -> Self {
        Self::Workload(value.to_string())
    }
}

impl From<X64NativeLighthouseError> for X64GateBWeightedProfileError {
    fn from(value: X64NativeLighthouseError) -> Self {
        Self::Lighthouse(value.to_string())
    }
}

impl From<X64TargetProfileError> for X64GateBWeightedProfileError {
    fn from(value: X64TargetProfileError) -> Self {
        Self::Target(value)
    }
}

pub fn emit_x64_gate_b_weighted_profile(
) -> Result<X64GateBWeightedProfile, X64GateBWeightedProfileError> {
    let mut profile = regenerate_profile()?;
    profile.profile_hash = x64_gate_b_weighted_profile_hash(&profile)?;
    Ok(profile)
}

pub fn verify_x64_gate_b_weighted_profile(
    profile: &X64GateBWeightedProfile,
) -> Result<VerifiedX64GateBWeightedProfile<'_>, X64GateBWeightedProfileError> {
    validate_envelope(profile)?;
    if x64_gate_b_weighted_profile_hash(profile)? != profile.profile_hash {
        return Err(X64GateBWeightedProfileError::ProfileHashMismatch);
    }
    let replayed = emit_x64_gate_b_weighted_profile()?;
    compare_regenerated_profile(profile, &replayed)?;
    Ok(VerifiedX64GateBWeightedProfile { profile })
}

fn compare_regenerated_profile(
    profile: &X64GateBWeightedProfile,
    replayed: &X64GateBWeightedProfile,
) -> Result<(), X64GateBWeightedProfileError> {
    if replayed != profile {
        return Err(X64GateBWeightedProfileError::ReplayMismatch);
    }
    Ok(())
}

pub fn x64_gate_b_weighted_profile_hash(
    profile: &X64GateBWeightedProfile,
) -> Result<SemanticHash, X64GateBWeightedProfileError> {
    let capacity = weighted_profile_hash_preimage_len(profile)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        X64GateBWeightedProfileError::EncodingOverflow {
            field: "weighted-profile hash allocation",
        }
    })?;
    bytes.extend_from_slice(WEIGHTED_PROFILE_DOMAIN);
    put_version(&mut bytes, profile.schema_version);
    put_version(&mut bytes, profile.policy_version);
    put_version(&mut bytes, profile.generator_version);
    put_u64(&mut bytes, profile.generator_seed);
    put_u32(&mut bytes, profile.array_elements);
    put_i64(&mut bytes, profile.repetitions);
    put_u64(&mut bytes, profile.element_visits);
    put_hash(&mut bytes, profile.input_values_hash);
    put_hash(&mut bytes, profile.input_frame_hash);
    put_u64(&mut bytes, profile.expected_result_bits);
    put_hash(&mut bytes, profile.target_semantic_hash);
    put_hash(&mut bytes, profile.target_plan_hash);
    put_hash(&mut bytes, profile.target_code_hash);
    encode_target_profile(&mut bytes, &profile.profile)?;
    if bytes.len() != capacity {
        return Err(X64GateBWeightedProfileError::EncodingOverflow {
            field: "weighted-profile canonical size",
        });
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn weighted_profile_hash_preimage_len(
    profile: &X64GateBWeightedProfile,
) -> Result<usize, X64GateBWeightedProfileError> {
    let mut length = WEIGHTED_PROFILE_DOMAIN.len();
    add_weighted_profile_bytes(&mut length, 214)?;
    add_weighted_profile_bytes(&mut length, target_profile_encoded_len(&profile.profile)?)?;
    Ok(length)
}

fn target_profile_encoded_len(
    profile: &X64TargetExecutionProfile,
) -> Result<usize, X64GateBWeightedProfileError> {
    checked_profile_count(profile.block_counts.len(), "block count")?;
    checked_profile_count(profile.edge_counts.len(), "edge count")?;
    checked_profile_count(
        profile.shared_join_opportunities.len(),
        "shared-join opportunity count",
    )?;
    checked_profile_count(
        profile.shared_join_composition.steps.len(),
        "shared-join composition step count",
    )?;
    checked_profile_count(profile.sites.len(), "site count")?;
    checked_profile_count(profile.class_totals.len(), "class total count")?;

    let mut length = 283_usize;
    add_weighted_profile_bytes(&mut length, 4)?;
    add_weighted_profile_product(&mut length, profile.block_counts.len(), 12, "block bytes")?;
    add_weighted_profile_bytes(&mut length, 4)?;
    add_weighted_profile_product(&mut length, profile.edge_counts.len(), 16, "edge bytes")?;

    add_weighted_profile_bytes(&mut length, 4)?;
    for opportunity in &profile.shared_join_opportunities {
        checked_profile_count(opportunity.ingresses.len(), "shared-join ingress count")?;
        add_weighted_profile_bytes(&mut length, 33)?;
        add_weighted_profile_product(
            &mut length,
            opportunity.ingresses.len(),
            36,
            "shared-join ingress bytes",
        )?;
    }

    add_weighted_profile_bytes(&mut length, 5)?;
    for step in &profile.shared_join_composition.steps {
        checked_profile_count(
            step.ancestors.len(),
            "shared-join composition ancestor count",
        )?;
        checked_profile_count(
            step.ingresses.len(),
            "shared-join composition ingress count",
        )?;
        add_weighted_profile_bytes(&mut length, 37)?;
        add_weighted_profile_product(
            &mut length,
            step.ancestors.len(),
            4,
            "shared-join composition ancestor bytes",
        )?;
        for ingress in &step.ingresses {
            checked_profile_count(
                ingress.route.len(),
                "shared-join composition ingress route count",
            )?;
            add_weighted_profile_bytes(
                &mut length,
                if ingress.branch_arm_counts.is_some() {
                    57
                } else {
                    41
                },
            )?;
            add_weighted_profile_product(
                &mut length,
                ingress.route.len(),
                9,
                "shared-join composition route bytes",
            )?;
        }
    }
    add_weighted_profile_bytes(&mut length, 28)?;

    add_weighted_profile_bytes(
        &mut length,
        prospective_shared_join_realization_encoded_len(
            &profile.prospective_shared_join_realization,
        )?,
    )?;

    add_weighted_profile_bytes(&mut length, 4)?;
    for site in &profile.sites {
        add_weighted_profile_bytes(
            &mut length,
            37_usize
                .checked_add(profile_event_encoded_len(site.event))
                .ok_or(X64GateBWeightedProfileError::EncodingOverflow {
                    field: "site bytes",
                })?,
        )?;
    }
    add_weighted_profile_bytes(&mut length, 4)?;
    add_weighted_profile_product(
        &mut length,
        profile.class_totals.len(),
        37,
        "class total bytes",
    )?;
    add_weighted_profile_bytes(&mut length, 24)?;
    Ok(length)
}

fn checked_profile_count(
    length: usize,
    field: &'static str,
) -> Result<(), X64GateBWeightedProfileError> {
    u32::try_from(length)
        .map(|_| ())
        .map_err(|_| X64GateBWeightedProfileError::EncodingOverflow { field })
}

fn add_weighted_profile_product(
    length: &mut usize,
    count: usize,
    item_bytes: usize,
    field: &'static str,
) -> Result<(), X64GateBWeightedProfileError> {
    let amount = count
        .checked_mul(item_bytes)
        .ok_or(X64GateBWeightedProfileError::EncodingOverflow { field })?;
    add_weighted_profile_bytes(length, amount)
}

fn add_weighted_profile_bytes(
    length: &mut usize,
    amount: usize,
) -> Result<(), X64GateBWeightedProfileError> {
    *length = length
        .checked_add(amount)
        .ok_or(X64GateBWeightedProfileError::EncodingOverflow {
            field: "weighted-profile hash preimage bytes",
        })?;
    if *length > MAX_WEIGHTED_PROFILE_HASH_PREIMAGE_BYTES {
        return Err(X64GateBWeightedProfileError::EncodingOverflow {
            field: "weighted-profile hash preimage ceiling",
        });
    }
    Ok(())
}

fn regenerate_profile() -> Result<X64GateBWeightedProfile, X64GateBWeightedProfileError> {
    let workload = frozen_workload()?;
    let expected_result_bits = workload
        .expected_output
        .returned_f64_bits()
        .ok_or(X64GateBWeightedProfileError::UnexpectedOutcome)?;
    let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bound = package.source_bound()?;
    let arguments = vec![
        CoreValue::array_f64(
            workload
                .values
                .iter()
                .copied()
                .map(f64::from_bits)
                .collect::<Vec<_>>(),
        ),
        CoreValue::I64(X64_GATE_B_REPETITIONS),
    ];
    let profiled = profile_source_bound_x64_target_plan(
        bound,
        arguments,
        EvaluationBudget::new(
            X64_TARGET_MAX_PROFILE_EVAL_WORK,
            COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        ),
    )?;
    let EvaluationOutcome::Return(CoreValue::F64(value)) = profiled.evaluation.outcome else {
        return Err(X64GateBWeightedProfileError::UnexpectedOutcome);
    };
    let result_bits = if value.is_nan() {
        super::x64_standalone_protocol::X64_STANDALONE_CANONICAL_NAN_BITS
    } else {
        value.to_bits()
    };
    if result_bits != expected_result_bits {
        return Err(X64GateBWeightedProfileError::UnexpectedOutcome);
    }
    if !profiled.evaluation.effect_trace.is_empty() {
        return Err(X64GateBWeightedProfileError::UnexpectedEffect);
    }

    let profile = profiled.profile;
    Ok(X64GateBWeightedProfile {
        schema_version: X64_GATE_B_WEIGHTED_PROFILE_SCHEMA_VERSION,
        policy_version: X64_GATE_B_WEIGHTED_PROFILE_POLICY_VERSION,
        generator_version: X64_GATE_B_WORKLOAD_GENERATOR_VERSION,
        generator_seed: X64_GATE_B_WORKLOAD_GENERATOR_SEED,
        array_elements: X64_GATE_B_ARRAY_ELEMENTS,
        repetitions: X64_GATE_B_REPETITIONS,
        element_visits: X64_GATE_B_ELEMENT_VISITS,
        input_values_hash: workload.input_values_hash,
        input_frame_hash: workload.input_frame_hash,
        expected_result_bits,
        target_semantic_hash: profile.target_semantic_hash,
        target_plan_hash: profile.target_plan_hash,
        target_code_hash: profile.target_code_hash,
        profile,
        profile_hash: SemanticHash::ZERO,
    })
}

fn validate_envelope(
    profile: &X64GateBWeightedProfile,
) -> Result<(), X64GateBWeightedProfileError> {
    if profile.schema_version != X64_GATE_B_WEIGHTED_PROFILE_SCHEMA_VERSION
        || profile.policy_version != X64_GATE_B_WEIGHTED_PROFILE_POLICY_VERSION
        || profile.generator_version != X64_GATE_B_WORKLOAD_GENERATOR_VERSION
        || profile.generator_seed != X64_GATE_B_WORKLOAD_GENERATOR_SEED
        || profile.array_elements != X64_GATE_B_ARRAY_ELEMENTS
        || profile.repetitions != X64_GATE_B_REPETITIONS
        || profile.element_visits != X64_GATE_B_ELEMENT_VISITS
    {
        return Err(X64GateBWeightedProfileError::InvalidEnvelope {
            field: "workload policy",
        });
    }
    if profile.profile.schema_version != X64_TARGET_PROFILE_SCHEMA_VERSION
        || profile.profile.policy_version != X64_TARGET_PROFILE_POLICY_VERSION
        || profile.profile.encoder_policy_version != X64_TARGET_ENCODER_POLICY_VERSION
        || !profile.profile.optimized_realization
        || !profile.profile.shared_join_composition.complete
        || !profile.profile.prospective_shared_join_realization.complete
    {
        return Err(X64GateBWeightedProfileError::InvalidEnvelope {
            field: "target profile policy",
        });
    }
    if profile.target_semantic_hash != profile.profile.target_semantic_hash
        || profile.target_plan_hash != profile.profile.target_plan_hash
        || profile.target_code_hash != profile.profile.target_code_hash
    {
        return Err(X64GateBWeightedProfileError::InvalidEnvelope {
            field: "target identity",
        });
    }
    let prospective = &profile.profile.prospective_shared_join_realization;
    let expected_semantic_rows = profile
        .profile
        .shared_join_composition
        .steps
        .iter()
        .filter(|step| step.kind == X64TargetSharedJoinKind::RegisterInstruction)
        .try_fold(0_u32, |total, step| {
            let rows = u32::try_from(step.ingresses.len()).map_err(|_| {
                X64GateBWeightedProfileError::InvalidEnvelope {
                    field: "prospective machine semantics",
                }
            })?;
            total
                .checked_add(rows)
                .ok_or(X64GateBWeightedProfileError::InvalidEnvelope {
                    field: "prospective machine semantics",
                })
        })?;
    let semantic: &X64TargetProspectiveMachineSemanticProof = &prospective.machine_semantic_proof;
    if prospective.baseline_code_hash != profile.target_code_hash
        || prospective.baseline_code_bytes != profile.profile.static_code_bytes
        || prospective.body_replicas != profile.profile.shared_join_composition.body_replicas
        || !semantic.complete
        || semantic.register_rows != expected_semantic_rows
        || semantic.register_rows == 0
        || semantic.decoded_bytes == 0
        || semantic.decoded_instructions == 0
        || semantic.symbolic_nodes == 0
        || semantic.reference_route_events == 0
        || x64_target_prospective_shared_join_realization_hash(prospective)
            .map_err(X64GateBWeightedProfileError::Target)?
            != prospective.realization_hash
    {
        return Err(X64GateBWeightedProfileError::InvalidEnvelope {
            field: "prospective realization",
        });
    }
    if profile.profile.control_counts.bounds_exits != 0 {
        return Err(X64GateBWeightedProfileError::InvalidEnvelope {
            field: "Bounds count",
        });
    }
    Ok(())
}

fn encode_target_profile(
    bytes: &mut Vec<u8>,
    profile: &X64TargetExecutionProfile,
) -> Result<(), X64GateBWeightedProfileError> {
    put_version(bytes, profile.schema_version);
    put_version(bytes, profile.policy_version);
    put_hash(bytes, profile.target_semantic_hash);
    put_hash(bytes, profile.target_plan_hash);
    put_hash(bytes, profile.target_code_hash);
    put_version(bytes, profile.encoder_policy_version);
    put_bool(bytes, profile.optimized_realization);
    put_u64(bytes, profile.evaluation_steps);
    put_u64(bytes, profile.observer_updates);

    let instructions = profile.instruction_counts;
    for count in [
        instructions.moves,
        instructions.i64_adds,
        instructions.i64_subtracts,
        instructions.i64_multiplies,
        instructions.f64_adds,
        instructions.f64_subtracts,
        instructions.i64_less_than,
        instructions.i64_greater_or_equal,
        instructions.array_lengths,
        instructions.checked_array_gets,
    ] {
        put_u64(bytes, count);
    }
    let control = profile.control_counts;
    for count in [
        control.entries,
        control.returns,
        control.branches,
        control.branch_then,
        control.branch_else,
        control.tail_transfers,
        control.tail_argument_values,
        control.tail_argument_words,
        control.bounds_exits,
    ] {
        put_u64(bytes, count);
    }

    put_len(bytes, profile.block_counts.len(), "block count")?;
    for block in &profile.block_counts {
        put_u32(bytes, block.label.0);
        put_u64(bytes, block.entries);
    }
    put_len(bytes, profile.edge_counts.len(), "edge count")?;
    for edge in &profile.edge_counts {
        put_u32(bytes, edge.source.0);
        put_u32(bytes, edge.target.0);
        put_u64(bytes, edge.traversals);
    }
    put_len(
        bytes,
        profile.shared_join_opportunities.len(),
        "shared-join opportunity count",
    )?;
    for opportunity in &profile.shared_join_opportunities {
        put_u32(bytes, opportunity.target.0);
        put_u8(bytes, shared_join_kind_tag(opportunity.kind));
        put_u64(bytes, opportunity.executions);
        put_len(
            bytes,
            opportunity.ingresses.len(),
            "shared-join ingress count",
        )?;
        for ingress in &opportunity.ingresses {
            put_u32(bytes, ingress.root.0);
            put_u32(bytes, ingress.trigger.0);
            put_u64(bytes, ingress.executions);
            put_u32(bytes, ingress.frame_accesses_per_execution);
            put_u128(bytes, ingress.weighted_frame_accesses);
        }
        put_u128(bytes, opportunity.weighted_ingress_frame_accesses);
    }
    let composition = &profile.shared_join_composition;
    put_bool(bytes, composition.complete);
    put_len(
        bytes,
        composition.steps.len(),
        "shared-join composition step count",
    )?;
    for step in &composition.steps {
        put_u32(bytes, step.target.0);
        put_u8(bytes, shared_join_kind_tag(step.kind));
        put_len(
            bytes,
            step.ancestors.len(),
            "shared-join composition ancestor count",
        )?;
        for ancestor in &step.ancestors {
            put_u32(bytes, ancestor.0);
        }
        put_u64(bytes, step.executions);
        put_len(
            bytes,
            step.ingresses.len(),
            "shared-join composition ingress count",
        )?;
        for ingress in &step.ingresses {
            put_u32(bytes, ingress.root.0);
            put_u32(bytes, ingress.authority_trigger.0);
            put_len(
                bytes,
                ingress.route.len(),
                "shared-join composition ingress route count",
            )?;
            for event in &ingress.route {
                encode_shared_join_route_event(bytes, *event);
            }
            put_u64(bytes, ingress.executions);
            put_u32(bytes, ingress.frame_accesses_per_execution);
            put_u128(bytes, ingress.weighted_frame_accesses);
            match ingress.branch_arm_counts {
                None => put_u8(bytes, 0),
                Some(counts) => {
                    put_u8(bytes, 1);
                    put_u64(bytes, counts.then_executions);
                    put_u64(bytes, counts.else_executions);
                }
            }
        }
        put_u128(bytes, step.weighted_ingress_frame_accesses);
    }
    put_u32(bytes, composition.body_replicas);
    put_u64(bytes, composition.body_executions);
    put_u128(bytes, composition.weighted_ingress_frame_accesses);
    encode_prospective_shared_join_realization(
        bytes,
        &profile.prospective_shared_join_realization,
    )?;
    put_len(bytes, profile.sites.len(), "site count")?;
    for site in &profile.sites {
        encode_event(bytes, site.event);
        put_u8(bytes, template_tag(site.class));
        put_u32(bytes, site.start);
        put_u32(bytes, site.end);
        put_u32(bytes, site.static_bytes);
        put_u64(bytes, site.executions);
        put_u128(bytes, site.weighted_bytes);
    }
    put_len(bytes, profile.class_totals.len(), "class total count")?;
    for total in &profile.class_totals {
        put_u8(bytes, template_tag(total.class));
        put_u32(bytes, total.sites);
        put_u64(bytes, total.static_bytes);
        put_u64(bytes, total.executions);
        put_u128(bytes, total.weighted_bytes);
    }
    put_u64(bytes, profile.static_code_bytes);
    put_u128(bytes, profile.weighted_template_bytes);
    Ok(())
}

fn encode_shared_join_route_event(bytes: &mut Vec<u8>, event: X64TargetSharedJoinRouteEvent) {
    match event {
        X64TargetSharedJoinRouteEvent::Instruction { label, index } => {
            put_u8(bytes, 0);
            put_u32(bytes, label.0);
            put_u32(bytes, index);
        }
        X64TargetSharedJoinRouteEvent::Tail { source, target } => {
            put_u8(bytes, 1);
            put_u32(bytes, source.0);
            put_u32(bytes, target.0);
        }
    }
}

fn encode_prospective_shared_join_realization(
    bytes: &mut Vec<u8>,
    realization: &X64TargetProspectiveSharedJoinRealization,
) -> Result<(), X64GateBWeightedProfileError> {
    let encoded_len = prospective_shared_join_realization_encoded_len(realization)?;
    bytes.try_reserve_exact(encoded_len).map_err(|_| {
        X64GateBWeightedProfileError::EncodingOverflow {
            field: "prospective realization allocation",
        }
    })?;
    let encoded_start = bytes.len();
    put_bool(bytes, realization.complete);
    put_u64(bytes, realization.baseline_code_bytes);
    put_hash(bytes, realization.baseline_code_hash);
    put_u64(bytes, realization.candidate_code_bytes);
    put_hash(bytes, realization.candidate_code_hash);
    for value in [
        realization.code_bytes_added,
        realization.code_bytes_removed,
        realization.baseline_atom_count,
        realization.candidate_atom_count,
        realization.atom_count_added,
        realization.atom_count_removed,
        realization.label_count,
        realization.baseline_fixup_count,
        realization.candidate_fixup_count,
        realization.fixup_count_added,
        realization.fixup_count_removed,
    ] {
        put_u64(bytes, value);
    }
    put_u32(bytes, realization.body_replicas);
    put_u32(bytes, realization.shared_join_authority_atoms);
    put_u128(bytes, realization.candidate_weighted_template_bytes);
    put_bool(bytes, realization.machine_semantic_proof.complete);
    put_u32(bytes, realization.machine_semantic_proof.register_rows);
    put_u64(bytes, realization.machine_semantic_proof.decoded_bytes);
    put_u32(
        bytes,
        realization.machine_semantic_proof.decoded_instructions,
    );
    put_u32(bytes, realization.machine_semantic_proof.symbolic_nodes);
    put_u32(
        bytes,
        realization.machine_semantic_proof.reference_route_events,
    );
    put_len(bytes, realization.atoms.len(), "prospective atom count")?;
    for atom in &realization.atoms {
        put_u32(bytes, atom.physical_owner.0);
        encode_event(bytes, atom.semantic_event);
        encode_prospective_authority(bytes, atom.execution_authority);
        put_u8(bytes, template_tag(atom.class));
        put_u32(bytes, atom.start);
        put_u32(bytes, atom.end);
        put_u32(bytes, atom.static_bytes);
        put_u64(bytes, atom.executions);
        put_u128(bytes, atom.weighted_bytes);
    }
    put_len(
        bytes,
        realization.labels.len(),
        "prospective label receipt count",
    )?;
    for label in &realization.labels {
        put_u32(bytes, label.label.0);
        encode_label_owner(bytes, label.owner);
        put_u32(bytes, label.code_offset);
        put_u32(bytes, label.owning_atom);
        put_u8(bytes, prospective_disposition_tag(label.disposition));
    }
    put_len(
        bytes,
        realization.fixups.len(),
        "prospective fixup receipt count",
    )?;
    for fixup in &realization.fixups {
        put_u32(bytes, fixup.fixup_index);
        put_u32(bytes, fixup.owning_atom);
        put_u32(bytes, fixup.patch_offset);
        put_u32(bytes, fixup.target.0);
        put_i32(bytes, fixup.addend);
    }
    put_hash(bytes, realization.realization_hash);
    let actual_len = bytes.len().checked_sub(encoded_start).ok_or(
        X64GateBWeightedProfileError::EncodingOverflow {
            field: "prospective realization encoded length",
        },
    )?;
    if actual_len != encoded_len {
        return Err(X64GateBWeightedProfileError::EncodingOverflow {
            field: "prospective realization canonical size",
        });
    }
    Ok(())
}

fn prospective_shared_join_realization_encoded_len(
    realization: &X64TargetProspectiveSharedJoinRealization,
) -> Result<usize, X64GateBWeightedProfileError> {
    for (length, field) in [
        (realization.atoms.len(), "prospective atom count"),
        (realization.labels.len(), "prospective label receipt count"),
        (realization.fixups.len(), "prospective fixup receipt count"),
    ] {
        u32::try_from(length)
            .map_err(|_| X64GateBWeightedProfileError::EncodingOverflow { field })?;
    }

    let mut length = 0_usize;
    for amount in [1_usize, 8, 32, 8, 32, 11 * 8, 4, 4, 16, 25, 4] {
        add_prospective_gate_profile_bytes(&mut length, amount)?;
    }
    for atom in &realization.atoms {
        let atom_bytes = 41_usize
            .checked_add(profile_event_encoded_len(atom.semantic_event))
            .and_then(|amount| {
                amount.checked_add(prospective_authority_encoded_len(atom.execution_authority))
            })
            .ok_or(X64GateBWeightedProfileError::EncodingOverflow {
                field: "prospective atom bytes",
            })?;
        add_prospective_gate_profile_bytes(&mut length, atom_bytes)?;
    }
    add_prospective_gate_profile_bytes(&mut length, 4)?;
    for label in &realization.labels {
        let label_bytes = 13_usize
            .checked_add(label_owner_encoded_len(label.owner))
            .ok_or(X64GateBWeightedProfileError::EncodingOverflow {
                field: "prospective label bytes",
            })?;
        add_prospective_gate_profile_bytes(&mut length, label_bytes)?;
    }
    add_prospective_gate_profile_bytes(&mut length, 4)?;
    let fixup_bytes = realization.fixups.len().checked_mul(20).ok_or(
        X64GateBWeightedProfileError::EncodingOverflow {
            field: "prospective fixup bytes",
        },
    )?;
    add_prospective_gate_profile_bytes(&mut length, fixup_bytes)?;
    add_prospective_gate_profile_bytes(&mut length, 32)?;
    Ok(length)
}

fn add_prospective_gate_profile_bytes(
    length: &mut usize,
    amount: usize,
) -> Result<(), X64GateBWeightedProfileError> {
    *length = length
        .checked_add(amount)
        .ok_or(X64GateBWeightedProfileError::EncodingOverflow {
            field: "prospective realization bytes",
        })?;
    if *length > MAX_PROSPECTIVE_GATE_PROFILE_BYTES {
        return Err(X64GateBWeightedProfileError::EncodingOverflow {
            field: "prospective realization byte ceiling",
        });
    }
    Ok(())
}

const fn profile_event_encoded_len(event: X64TargetProfileEvent) -> usize {
    match event {
        X64TargetProfileEvent::Instruction { .. } => 9,
        X64TargetProfileEvent::Tail { .. }
        | X64TargetProfileEvent::Return { .. }
        | X64TargetProfileEvent::Branch { .. }
        | X64TargetProfileEvent::BranchElse { .. } => 5,
        X64TargetProfileEvent::Entry
        | X64TargetProfileEvent::ReturnEpilogue
        | X64TargetProfileEvent::BoundsEpilogue
        | X64TargetProfileEvent::Static => 1,
    }
}

const fn prospective_authority_encoded_len(
    authority: X64TargetProspectiveExecutionAuthority,
) -> usize {
    match authority {
        X64TargetProspectiveExecutionAuthority::Semantic { event } => {
            1 + profile_event_encoded_len(event)
        }
        X64TargetProspectiveExecutionAuthority::SharedJoin { .. } => 14,
        X64TargetProspectiveExecutionAuthority::Static => 1,
    }
}

const fn label_owner_encoded_len(owner: super::x64_target::X64LabelOwner) -> usize {
    match owner {
        super::x64_target::X64LabelOwner::Block { .. } => 9,
        super::x64_target::X64LabelOwner::EntryAdapter
        | super::x64_target::X64LabelOwner::ReturnEpilogue
        | super::x64_target::X64LabelOwner::BoundsEpilogue => 1,
    }
}

fn encode_prospective_authority(
    bytes: &mut Vec<u8>,
    authority: X64TargetProspectiveExecutionAuthority,
) {
    match authority {
        X64TargetProspectiveExecutionAuthority::Semantic { event } => {
            put_u8(bytes, 0);
            encode_event(bytes, event);
        }
        X64TargetProspectiveExecutionAuthority::SharedJoin {
            target,
            root,
            authority_trigger,
            partition,
        } => {
            put_u8(bytes, 1);
            put_u32(bytes, target.0);
            put_u32(bytes, root.0);
            put_u32(bytes, authority_trigger.0);
            put_u8(
                bytes,
                match partition {
                    X64TargetProspectiveSharedJoinPartition::All => 0,
                    X64TargetProspectiveSharedJoinPartition::Else => 1,
                },
            );
        }
        X64TargetProspectiveExecutionAuthority::Static => put_u8(bytes, 2),
    }
}

fn encode_label_owner(bytes: &mut Vec<u8>, owner: super::x64_target::X64LabelOwner) {
    match owner {
        super::x64_target::X64LabelOwner::EntryAdapter => put_u8(bytes, 0),
        super::x64_target::X64LabelOwner::Block { function, block } => {
            put_u8(bytes, 1);
            put_u32(bytes, function.0);
            put_u32(bytes, block.0);
        }
        super::x64_target::X64LabelOwner::ReturnEpilogue => put_u8(bytes, 2),
        super::x64_target::X64LabelOwner::BoundsEpilogue => put_u8(bytes, 3),
    }
}

const fn prospective_disposition_tag(disposition: X64TargetProspectiveLabelDisposition) -> u8 {
    match disposition {
        X64TargetProspectiveLabelDisposition::Live => 0,
        X64TargetProspectiveLabelDisposition::UnreachableTombstone => 1,
        X64TargetProspectiveLabelDisposition::Policy14ConsumedTombstone => 2,
        X64TargetProspectiveLabelDisposition::SharedJoinConsumedTombstone => 3,
    }
}

const fn shared_join_kind_tag(kind: X64TargetSharedJoinKind) -> u8 {
    match kind {
        X64TargetSharedJoinKind::RegisterInstruction => 0,
        X64TargetSharedJoinKind::FusedCompare => 1,
    }
}

fn encode_event(bytes: &mut Vec<u8>, event: X64TargetProfileEvent) {
    match event {
        X64TargetProfileEvent::Entry => put_u8(bytes, 0),
        X64TargetProfileEvent::Instruction { label, index } => {
            put_u8(bytes, 1);
            put_u32(bytes, label.0);
            put_u32(bytes, index);
        }
        X64TargetProfileEvent::Tail { label } => {
            put_u8(bytes, 2);
            put_u32(bytes, label.0);
        }
        X64TargetProfileEvent::Return { label } => {
            put_u8(bytes, 3);
            put_u32(bytes, label.0);
        }
        X64TargetProfileEvent::Branch { label } => {
            put_u8(bytes, 4);
            put_u32(bytes, label.0);
        }
        X64TargetProfileEvent::BranchElse { label } => {
            put_u8(bytes, 5);
            put_u32(bytes, label.0);
        }
        X64TargetProfileEvent::ReturnEpilogue => put_u8(bytes, 6),
        X64TargetProfileEvent::BoundsEpilogue => put_u8(bytes, 7),
        X64TargetProfileEvent::Static => put_u8(bytes, 8),
    }
}

const fn template_tag(class: X64TargetProfileTemplateClass) -> u8 {
    match class {
        X64TargetProfileTemplateClass::EntryPrologue => 0,
        X64TargetProfileTemplateClass::OrdinaryInstruction => 1,
        X64TargetProfileTemplateClass::RegisterInstruction => 2,
        X64TargetProfileTemplateClass::TailTransfer => 3,
        X64TargetProfileTemplateClass::ReturnTransfer => 4,
        X64TargetProfileTemplateClass::BranchCondition => 5,
        X64TargetProfileTemplateClass::BranchElseJump => 6,
        X64TargetProfileTemplateClass::FusedCompareInstruction => 7,
        X64TargetProfileTemplateClass::ReturnEpilogue => 8,
        X64TargetProfileTemplateClass::BoundsEpilogue => 9,
        X64TargetProfileTemplateClass::Tombstone => 10,
    }
}

fn put_len(
    bytes: &mut Vec<u8>,
    length: usize,
    field: &'static str,
) -> Result<(), X64GateBWeightedProfileError> {
    let length = u32::try_from(length)
        .map_err(|_| X64GateBWeightedProfileError::EncodingOverflow { field })?;
    put_u32(bytes, length);
    Ok(())
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

fn put_bool(bytes: &mut Vec<u8>, value: bool) {
    put_u8(bytes, u8::from(value));
}

fn put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_i32(bytes: &mut Vec<u8>, value: i32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u128(bytes: &mut Vec<u8>, value: u128) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::super::x64_target::X64LabelId;
    use super::*;

    #[test]
    fn weighted_profile_hash_preflight_matches_nonempty_canonical_encoding() {
        let case = super::super::x64_native_lighthouse::x64_native_lighthouse_case(0)
            .expect("canonical lighthouse case");
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix package");
        let arguments = package
            .case_arguments(&case)
            .expect("canonical case arguments");
        let profiled = profile_source_bound_x64_target_plan(
            package.source_bound().expect("source-bound target"),
            arguments,
            EvaluationBudget::new(
                X64_TARGET_MAX_PROFILE_EVAL_WORK,
                COREVM0_GATE_A_CALL_DEPTH_LIMIT,
            ),
        )
        .expect("nonempty target profile");

        let expected_target_len = target_profile_encoded_len(&profiled.profile).unwrap();
        let mut target_bytes = Vec::new();
        encode_target_profile(&mut target_bytes, &profiled.profile).unwrap();
        assert_eq!(target_bytes.len(), expected_target_len);

        let wrapper = X64GateBWeightedProfile {
            schema_version: X64_GATE_B_WEIGHTED_PROFILE_SCHEMA_VERSION,
            policy_version: X64_GATE_B_WEIGHTED_PROFILE_POLICY_VERSION,
            generator_version: X64_GATE_B_WORKLOAD_GENERATOR_VERSION,
            generator_seed: X64_GATE_B_WORKLOAD_GENERATOR_SEED,
            array_elements: X64_GATE_B_ARRAY_ELEMENTS,
            repetitions: X64_GATE_B_REPETITIONS,
            element_visits: X64_GATE_B_ELEMENT_VISITS,
            input_values_hash: SemanticHash::ZERO,
            input_frame_hash: SemanticHash::ZERO,
            expected_result_bits: 0,
            target_semantic_hash: profiled.profile.target_semantic_hash,
            target_plan_hash: profiled.profile.target_plan_hash,
            target_code_hash: profiled.profile.target_code_hash,
            profile: profiled.profile,
            profile_hash: SemanticHash::ZERO,
        };
        let expected_wrapper_len = weighted_profile_hash_preimage_len(&wrapper).unwrap();
        assert_eq!(
            expected_wrapper_len,
            WEIGHTED_PROFILE_DOMAIN.len() + 214 + expected_target_len
        );
        x64_gate_b_weighted_profile_hash(&wrapper)
            .expect("canonical wrapper sizing must match emitted bytes");
    }

    #[test]
    #[ignore = "full 2.526-billion-work Gate B replay; run explicitly in release mode"]
    fn frozen_weighted_profile_is_sealed_and_replays() {
        let profile = emit_x64_gate_b_weighted_profile().expect("weighted profile must emit");
        let prospective = &profile.profile().prospective_shared_join_realization;
        assert_eq!(
            (
                prospective.baseline_code_bytes,
                prospective.candidate_code_bytes,
                prospective.candidate_code_hash.to_hex(),
                prospective.code_bytes_added,
                prospective.code_bytes_removed,
                prospective.baseline_atom_count,
                prospective.candidate_atom_count,
                prospective.label_count,
                prospective.candidate_fixup_count,
                prospective.body_replicas,
                prospective.shared_join_authority_atoms,
                prospective.candidate_weighted_template_bytes,
            ),
            (
                3_097,
                3_214,
                "0e392caf51dbc65f9e36e08c678118e78b8f6aed90bf1df0edbf4b5c6a5f5173".to_owned(),
                117,
                0,
                179,
                199,
                142,
                51,
                11,
                31,
                2_574_710_635,
            )
        );
        assert_eq!(
            prospective.realization_hash.to_hex(),
            "172b508e9648501162e28274afa3bcec0632f9cb3212e38f2b87b21ad7516198"
        );
        assert_eq!(
            (
                prospective.machine_semantic_proof.complete,
                prospective.machine_semantic_proof.register_rows,
                prospective.machine_semantic_proof.decoded_bytes,
                prospective.machine_semantic_proof.decoded_instructions,
                prospective.machine_semantic_proof.symbolic_nodes,
                prospective.machine_semantic_proof.reference_route_events,
            ),
            (true, 2, 310, 42, 15, 25)
        );
        let target_49 = prospective
            .atoms
            .iter()
            .filter_map(|atom| {
                let X64TargetProspectiveExecutionAuthority::SharedJoin {
                    target,
                    root,
                    authority_trigger,
                    partition,
                } = atom.execution_authority
                else {
                    return None;
                };
                (target == X64LabelId(49)).then_some((
                    root,
                    authority_trigger,
                    partition,
                    atom.class,
                    atom.executions,
                    atom.weighted_bytes,
                ))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            target_49,
            vec![
                (
                    X64LabelId(30),
                    X64LabelId(39),
                    X64TargetProspectiveSharedJoinPartition::All,
                    X64TargetProfileTemplateClass::FusedCompareInstruction,
                    0,
                    0,
                ),
                (
                    X64LabelId(30),
                    X64LabelId(39),
                    X64TargetProspectiveSharedJoinPartition::All,
                    X64TargetProfileTemplateClass::BranchCondition,
                    0,
                    0,
                ),
                (
                    X64LabelId(30),
                    X64LabelId(39),
                    X64TargetProspectiveSharedJoinPartition::Else,
                    X64TargetProfileTemplateClass::BranchElseJump,
                    0,
                    0,
                ),
                (
                    X64LabelId(31),
                    X64LabelId(40),
                    X64TargetProspectiveSharedJoinPartition::All,
                    X64TargetProfileTemplateClass::FusedCompareInstruction,
                    1,
                    34,
                ),
                (
                    X64LabelId(31),
                    X64LabelId(40),
                    X64TargetProspectiveSharedJoinPartition::All,
                    X64TargetProfileTemplateClass::BranchCondition,
                    1,
                    6,
                ),
                (
                    X64LabelId(31),
                    X64LabelId(40),
                    X64TargetProspectiveSharedJoinPartition::Else,
                    X64TargetProfileTemplateClass::BranchElseJump,
                    1,
                    5,
                ),
            ]
        );
        println!(
            "prospective realization hash={}",
            prospective.realization_hash.to_hex()
        );
        assert_eq!(profile.profile().control_counts.bounds_exits, 0);
        assert_eq!(
            profile.profile().instruction_counts.checked_array_gets,
            X64_GATE_B_ELEMENT_VISITS
        );
        assert_eq!(
            (
                profile.profile_hash().to_hex(),
                profile.profile().evaluation_steps,
                profile.profile().observer_updates,
                profile.profile().block_counts.len(),
                profile.profile().edge_counts.len(),
                profile.profile().static_code_bytes,
                profile.profile().weighted_template_bytes,
            ),
            (
                "ea0958fd4346c0a2a209b831633748709726e1ba23ee2712565f6d2be62722a5".to_owned(),
                2_526_207_757,
                160_941_817,
                104,
                107,
                3_097,
                2_927_032_491,
            )
        );
        assert_eq!(
            profile.profile().control_counts,
            super::super::x64_target::X64TargetProfileControlCounts {
                entries: 1,
                returns: 1,
                branches: 12_583_041,
                branch_then: 2_810_681,
                branch_else: 9_772_360,
                tail_transfers: 118_263_305,
                tail_argument_values: 1_182_632_968,
                tail_argument_words: 1_309_284_945,
                bounds_exits: 0,
            }
        );
        assert_eq!(
            profile
                .profile()
                .shared_join_opportunities
                .iter()
                .map(|opportunity| (
                    opportunity.target.0,
                    opportunity.kind,
                    opportunity.executions,
                    opportunity.weighted_ingress_frame_accesses,
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    48,
                    X64TargetSharedJoinKind::FusedCompare,
                    4_194_367,
                    25_166_076,
                ),
                (49, X64TargetSharedJoinKind::FusedCompare, 1, 4),
                (
                    92,
                    X64TargetSharedJoinKind::FusedCompare,
                    4_194_303,
                    12_582_909,
                ),
                (93, X64TargetSharedJoinKind::FusedCompare, 1, 3),
                (
                    121,
                    X64TargetSharedJoinKind::RegisterInstruction,
                    4_194_304,
                    58_720_256,
                ),
            ]
        );
        assert!(profile.profile().shared_join_composition.complete);
        assert_eq!(
            (
                profile.profile().shared_join_composition.body_replicas,
                profile.profile().shared_join_composition.body_executions,
                profile
                    .profile()
                    .shared_join_composition
                    .steps
                    .iter()
                    .map(|step| step.target.0)
                    .collect::<Vec<_>>(),
                profile
                    .profile()
                    .shared_join_composition
                    .weighted_ingress_frame_accesses,
            ),
            (11, 12_582_976, vec![49, 92, 93, 121, 48], 125_829_376,)
        );
        assert_eq!(
            profile
                .profile()
                .shared_join_composition
                .steps
                .iter()
                .map(|step| (
                    step.target.0,
                    step.ancestors
                        .iter()
                        .map(|label| label.0)
                        .collect::<Vec<_>>(),
                    step.executions,
                    step.weighted_ingress_frame_accesses,
                    step.ingresses
                        .iter()
                        .map(|ingress| (
                            ingress.root.0,
                            ingress.authority_trigger.0,
                            ingress.executions,
                            ingress.frame_accesses_per_execution,
                            ingress.weighted_frame_accesses,
                            ingress
                                .branch_arm_counts
                                .map(|counts| (counts.then_executions, counts.else_executions,)),
                        ))
                        .collect::<Vec<_>>(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    49,
                    vec![],
                    1,
                    4,
                    vec![
                        (30, 39, 0, 4, 0, Some((0, 0))),
                        (31, 40, 1, 4, 4, Some((0, 1))),
                    ],
                ),
                (
                    92,
                    vec![],
                    4_194_303,
                    12_582_909,
                    vec![
                        (78, 82, 735_084, 3, 2_205_252, Some((735_084, 0))),
                        (
                            86,
                            86,
                            3_459_219,
                            3,
                            10_377_657,
                            Some((1_340_447, 2_118_772)),
                        ),
                    ],
                ),
                (
                    93,
                    vec![],
                    1,
                    3,
                    vec![
                        (79, 83, 0, 3, 0, Some((0, 0))),
                        (87, 87, 1, 3, 3, Some((1, 0))),
                    ],
                ),
                (
                    121,
                    vec![],
                    4_194_304,
                    58_720_256,
                    vec![
                        (106, 107, 2_075_532, 14, 29_057_448, None),
                        (116, 117, 2_118_772, 14, 29_662_808, None),
                    ],
                ),
                (
                    48,
                    vec![121],
                    4_194_367,
                    54_526_204,
                    vec![
                        (29, 38, 63, 4, 252, Some((0, 63))),
                        (106, 107, 2_075_532, 13, 26_981_916, Some((32, 2_075_500)),),
                        (116, 117, 2_118_772, 13, 27_544_036, Some((32, 2_118_740)),),
                    ],
                ),
            ]
        );
        let target_48_routes = profile
            .profile()
            .shared_join_composition
            .steps
            .iter()
            .find(|step| step.target.0 == 48)
            .unwrap()
            .ingresses
            .iter()
            .map(|ingress| {
                (
                    ingress.authority_trigger.0,
                    ingress
                        .route
                        .iter()
                        .map(|event| match event {
                            X64TargetSharedJoinRouteEvent::Instruction { label, index } => {
                                (0, label.0, *index)
                            }
                            X64TargetSharedJoinRouteEvent::Tail { source, target } => {
                                (1, source.0, target.0)
                            }
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            target_48_routes,
            vec![
                (
                    38,
                    vec![
                        (1, 38, 41),
                        (1, 41, 44),
                        (1, 44, 46),
                        (1, 46, 48),
                        (0, 48, 0),
                        (1, 48, 50),
                    ],
                ),
                (
                    107,
                    vec![
                        (1, 107, 108),
                        (1, 108, 109),
                        (1, 109, 119),
                        (1, 119, 120),
                        (1, 120, 121),
                        (0, 121, 0),
                        (1, 121, 122),
                        (1, 122, 123),
                        (1, 123, 44),
                        (1, 44, 46),
                        (1, 46, 48),
                        (0, 48, 0),
                        (1, 48, 50),
                    ],
                ),
                (
                    117,
                    vec![
                        (1, 117, 118),
                        (1, 118, 119),
                        (1, 119, 120),
                        (1, 120, 121),
                        (0, 121, 0),
                        (1, 121, 122),
                        (1, 122, 123),
                        (1, 123, 44),
                        (1, 44, 46),
                        (1, 46, 48),
                        (0, 48, 0),
                        (1, 48, 50),
                    ],
                ),
            ]
        );
        let mut ranked = profile.profile().class_totals.clone();
        ranked.sort_by(|left, right| {
            right
                .weighted_bytes
                .cmp(&left.weighted_bytes)
                .then_with(|| left.class.cmp(&right.class))
        });
        println!(
            "Gate B weighted profile: hash={} steps={} updates={} blocks={} edges={} static_bytes={} weighted_bytes={} instructions={:?} control={:?} shared_joins={:?} shared_join_composition={:?} ranked={ranked:?}",
            profile.profile_hash().to_hex(),
            profile.profile().evaluation_steps,
            profile.profile().observer_updates,
            profile.profile().block_counts.len(),
            profile.profile().edge_counts.len(),
            profile.profile().static_code_bytes,
            profile.profile().weighted_template_bytes,
            profile.profile().instruction_counts,
            profile.profile().control_counts,
            profile.profile().shared_join_opportunities,
            profile.profile().shared_join_composition,
        );
        verify_x64_gate_b_weighted_profile(&profile)
            .expect("weighted profile must replay independently");

        let mut invalid = profile.clone();
        invalid.element_visits ^= 1;
        assert!(matches!(
            verify_x64_gate_b_weighted_profile(&invalid),
            Err(X64GateBWeightedProfileError::InvalidEnvelope {
                field: "workload policy"
            })
        ));

        let mut unsealed = profile.clone();
        unsealed.profile_hash = SemanticHash::ZERO;
        assert!(matches!(
            verify_x64_gate_b_weighted_profile(&unsealed),
            Err(X64GateBWeightedProfileError::ProfileHashMismatch)
        ));

        let mut composition_tampered = unsealed;
        composition_tampered.profile_hash =
            x64_gate_b_weighted_profile_hash(&composition_tampered).unwrap();
        composition_tampered
            .profile
            .shared_join_composition
            .body_replicas ^= 1;
        assert!(matches!(
            verify_x64_gate_b_weighted_profile(&composition_tampered),
            Err(X64GateBWeightedProfileError::InvalidEnvelope {
                field: "prospective realization"
            })
        ));

        let mut route_tampered = profile.clone();
        let route_event = route_tampered
            .profile
            .shared_join_composition
            .steps
            .iter_mut()
            .find(|step| step.target.0 == 48)
            .unwrap()
            .ingresses
            .iter_mut()
            .find(|ingress| ingress.authority_trigger.0 == 38)
            .unwrap()
            .route
            .first_mut()
            .unwrap();
        let X64TargetSharedJoinRouteEvent::Tail { target, .. } = route_event else {
            panic!("authority route must start with a tail");
        };
        *target = super::super::x64_target::X64LabelId(121);
        route_tampered.profile_hash = x64_gate_b_weighted_profile_hash(&route_tampered).unwrap();
        validate_envelope(&route_tampered).unwrap();
        assert_eq!(
            x64_gate_b_weighted_profile_hash(&route_tampered).unwrap(),
            route_tampered.profile_hash
        );
        assert!(matches!(
            compare_regenerated_profile(&route_tampered, &profile),
            Err(X64GateBWeightedProfileError::ReplayMismatch)
        ));

        let mut branch_cell_tampered = profile.clone();
        let target_48 = branch_cell_tampered
            .profile
            .shared_join_composition
            .steps
            .iter_mut()
            .find(|step| step.target.0 == 48)
            .unwrap();
        let (left, right) = target_48.ingresses.split_at_mut(2);
        let left_counts = left[1].branch_arm_counts.as_mut().unwrap();
        let right_counts = right[0].branch_arm_counts.as_mut().unwrap();
        left_counts.then_executions += 1;
        left_counts.else_executions -= 1;
        right_counts.then_executions -= 1;
        right_counts.else_executions += 1;
        branch_cell_tampered.profile_hash =
            x64_gate_b_weighted_profile_hash(&branch_cell_tampered).unwrap();
        validate_envelope(&branch_cell_tampered).unwrap();
        assert_eq!(
            x64_gate_b_weighted_profile_hash(&branch_cell_tampered).unwrap(),
            branch_cell_tampered.profile_hash
        );
        assert!(matches!(
            compare_regenerated_profile(&branch_cell_tampered, &profile),
            Err(X64GateBWeightedProfileError::ReplayMismatch)
        ));

        let mut unobserved_arm_tampered = profile.clone();
        let target_49 = unobserved_arm_tampered
            .profile
            .shared_join_composition
            .steps
            .iter_mut()
            .find(|step| step.target.0 == 49)
            .unwrap();
        let observed_ingress = target_49
            .ingresses
            .iter_mut()
            .find(|ingress| ingress.executions == 1)
            .unwrap();
        let counts = observed_ingress.branch_arm_counts.as_mut().unwrap();
        assert_eq!((counts.then_executions, counts.else_executions), (0, 1));
        counts.then_executions = 1;
        counts.else_executions = 0;
        unobserved_arm_tampered.profile_hash =
            x64_gate_b_weighted_profile_hash(&unobserved_arm_tampered).unwrap();
        validate_envelope(&unobserved_arm_tampered).unwrap();
        assert_eq!(
            x64_gate_b_weighted_profile_hash(&unobserved_arm_tampered).unwrap(),
            unobserved_arm_tampered.profile_hash
        );
        assert!(matches!(
            compare_regenerated_profile(&unobserved_arm_tampered, &profile),
            Err(X64GateBWeightedProfileError::ReplayMismatch)
        ));

        let mut prospective_tampered = profile.clone();
        {
            let prospective = &mut prospective_tampered
                .profile
                .prospective_shared_join_realization;
            let atom = prospective
                .atoms
                .iter_mut()
                .find(|atom| {
                    matches!(
                        atom.execution_authority,
                        X64TargetProspectiveExecutionAuthority::SharedJoin {
                            target,
                            root,
                            partition: X64TargetProspectiveSharedJoinPartition::All,
                            ..
                        } if target.0 == 49 && root.0 == 30
                    )
                })
                .expect("frozen target 49/root 30 prospective atom");
            let X64TargetProspectiveExecutionAuthority::SharedJoin { root, .. } =
                &mut atom.execution_authority
            else {
                unreachable!("selected prospective atom must have shared authority");
            };
            *root = super::super::x64_target::X64LabelId(31);
            prospective.realization_hash =
                x64_target_prospective_shared_join_realization_hash(prospective).unwrap();
        }
        prospective_tampered.profile_hash =
            x64_gate_b_weighted_profile_hash(&prospective_tampered).unwrap();
        validate_envelope(&prospective_tampered).unwrap();
        assert!(matches!(
            compare_regenerated_profile(&prospective_tampered, &profile),
            Err(X64GateBWeightedProfileError::ReplayMismatch)
        ));

        let mut semantic_tampered = profile.clone();
        {
            let prospective = &mut semantic_tampered
                .profile
                .prospective_shared_join_realization;
            prospective.machine_semantic_proof.decoded_instructions += 1;
            prospective.realization_hash =
                x64_target_prospective_shared_join_realization_hash(prospective).unwrap();
        }
        semantic_tampered.profile_hash =
            x64_gate_b_weighted_profile_hash(&semantic_tampered).unwrap();
        validate_envelope(&semantic_tampered).unwrap();
        assert!(matches!(
            compare_regenerated_profile(&semantic_tampered, &profile),
            Err(X64GateBWeightedProfileError::ReplayMismatch)
        ));

        let mut incomplete_semantic = profile.clone();
        incomplete_semantic
            .profile
            .prospective_shared_join_realization
            .machine_semantic_proof
            .complete = false;
        assert!(matches!(
            validate_envelope(&incomplete_semantic),
            Err(X64GateBWeightedProfileError::InvalidEnvelope {
                field: "prospective realization"
            })
        ));
    }
}
