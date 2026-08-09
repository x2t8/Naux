//! Canonical R1-S7b lighthouse package regeneration.
//!
//! This module owns the deterministic bridge from either frozen Gate A
//! workload to its Residual Core, Core SSA, Machine IR, and R1-S7a target
//! artifacts.  It is shared by the S7b-c worker and its parent so each
//! process independently rebuilds and source-replays the exact artifact it
//! uses.  No caller-provided pointer, target byte string, or copied identity
//! participates in package construction.

use super::core_ssa::{lower_core_ssa_r1_s5, CoreSsaArtifact};
use super::corevm0::{branch_mix_kernel_program, CoreVmProgram};
use super::corevm0_definitional::build_definitional_corevm0;
use super::corevm0_gate_a::{
    bounds_ordered_array_get_program, corevm0_gate_a_manifest, emit_corevm0_gate_a_r1_s5,
    CoreVmGateACase, CoreVmGateAError, CoreVmGateAEvidence, CoreVmGateAWorkload,
    COREVM0_GATE_A_CALL_DEPTH_LIMIT, COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
    COREVM0_GATE_A_TOTAL_CASES,
};
use super::corevm0_r1_s4::{
    emit_corevm0_r1_s4_evidence, specialize_corevm0_r1_s4, CoreVmR1S4Evidence,
    CoreVmR1S4Specialization,
};
use super::interpret::{CoreValue, Evaluation, EvaluationBudget};
use super::machine_ir::{
    evaluate_machine_ir_translation, lower_machine_ir_r1_s6, MachineIrArtifact,
};
use super::polyvariant_r1_s4::PolyvariantR1S4Budget;
use super::schema::{CoreArtifact, Mutability, RegionId, Type};
use super::specialization::{
    validate_specialization_r0a_request, SpecializationBudget, SpecializationRequest,
    SpecializationSlot,
};
use super::staging::{
    certify_binding_time_b0d, validate_binding_time_b0_request, BindingTime, BindingTimeBudget,
    BindingTimeRequest,
};
use super::translation_correspondence::{
    emit_r1_s5_core_ssa_correspondence, emit_r1_s6_machine_ir_correspondence,
    verify_r1_s5_core_ssa_correspondence, verify_r1_s6_machine_ir_correspondence,
    R1S5CoreSsaCorrespondenceEvidence, R1S6MachineIrCorrespondenceEvidence,
};
use super::x64_target::{
    evaluate_source_bound_x64_target_plan, lower_x64_target_r1_s7a,
    seal_x64_target_correspondence_evidence, seal_x64_target_correspondence_record,
    verify_x64_target_correspondence_evidence, verify_x64_target_source,
    SourceBoundX64TargetArtifact, X64TargetArtifact, X64TargetCorrespondenceEvidence,
};
use std::fmt;

/// Failure to regenerate or use one exact S7b lighthouse package.
///
/// Pipeline errors retain their exact stage and workload.  The underlying
/// diagnostic is deliberately non-semantic; callers must not hash it into
/// process evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum X64NativeLighthouseError {
    Manifest(CoreVmGateAError),
    ManifestShape {
        expected: u32,
        declared: u32,
        actual: usize,
    },
    CaseOrdinal {
        ordinal: u32,
        total: u32,
    },
    WorkloadMismatch {
        ordinal: u32,
        expected: CoreVmGateAWorkload,
        actual: CoreVmGateAWorkload,
    },
    NonCanonicalCase {
        ordinal: u32,
    },
    Pipeline {
        workload: CoreVmGateAWorkload,
        stage: &'static str,
        message: String,
    },
}

impl fmt::Display for X64NativeLighthouseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => {
                write!(
                    formatter,
                    "cannot regenerate the fixed Gate A manifest: {error}"
                )
            }
            Self::ManifestShape {
                expected,
                declared,
                actual,
            } => write!(
                formatter,
                "Gate A manifest must contain exactly {expected} cases; \
                 it declares {declared} and contains {actual}"
            ),
            Self::CaseOrdinal { ordinal, total } => write!(
                formatter,
                "R1-S7b lighthouse case ordinal {ordinal} is outside 0..{total}"
            ),
            Self::WorkloadMismatch {
                ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S7b case {ordinal} belongs to {actual:?}, \
                 but this package is {expected:?}"
            ),
            Self::NonCanonicalCase { ordinal } => write!(
                formatter,
                "R1-S7b case {ordinal} differs from the fixed Gate A manifest"
            ),
            Self::Pipeline {
                workload,
                stage,
                message,
            } => write!(
                formatter,
                "R1-S7b {workload:?} lighthouse {stage} failed: {message}"
            ),
        }
    }
}

impl std::error::Error for X64NativeLighthouseError {}

/// Owned source chain for one of the two exact Gate A workloads.
///
/// The source-bound target view is intentionally not stored: it borrows all
/// four artifacts.  `source_bound` independently replays the chain and
/// returns the opaque view only for the lifetime of this owned package.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct X64NativeLighthousePackage {
    workload: CoreVmGateAWorkload,
    s4: CoreVmR1S4Specialization,
    s4_evidence: CoreVmR1S4Evidence,
    ssa: CoreSsaArtifact,
    machine_ir: MachineIrArtifact,
    target: X64TargetArtifact,
}

impl X64NativeLighthousePackage {
    /// Regenerate the exact frozen workload through R1-S4, R1-S5, R1-S6,
    /// and R1-S7a, then source-replay the final target before publishing the
    /// package.
    pub(super) fn build(workload: CoreVmGateAWorkload) -> Result<Self, X64NativeLighthouseError> {
        let (program, dynamic_types) = match workload {
            CoreVmGateAWorkload::BranchMix => (
                branch_mix_kernel_program(),
                vec![array_f64_type(), Type::I64],
            ),
            CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                (bounds_ordered_array_get_program(), vec![array_f64_type()])
            }
        };
        let s4 = specialize_program(workload, &program, dynamic_types)?;
        let s4_evidence = emit_corevm0_r1_s4_evidence(&s4);
        let residual = s4.artifact();
        let ssa = lower_core_ssa_r1_s5(residual)
            .map_err(|error| pipeline(workload, "R1-S5 lowering", error))?;
        let machine_ir = lower_machine_ir_r1_s6(&ssa, residual)
            .map_err(|error| pipeline(workload, "R1-S6 lowering", error))?;
        let target = lower_x64_target_r1_s7a(&machine_ir, &ssa, residual)
            .map_err(|error| pipeline(workload, "R1-S7a lowering", error))?;

        verify_x64_target_source(&target, &machine_ir, &ssa, residual)
            .map_err(|error| pipeline(workload, "R1-S7a source replay", error))?;

        Ok(Self {
            workload,
            s4,
            s4_evidence,
            ssa,
            machine_ir,
            target,
        })
    }

    /// Independently reconstruct the opaque target authority from this
    /// package's complete owned source chain.
    pub(super) fn source_bound(
        &self,
    ) -> Result<SourceBoundX64TargetArtifact<'_, '_, '_, '_>, X64NativeLighthouseError> {
        verify_x64_target_source(
            &self.target,
            &self.machine_ir,
            &self.ssa,
            self.s4.artifact(),
        )
        .map_err(|error| pipeline(self.workload, "R1-S7a source replay", error))
    }

    pub(super) fn s4_evidence(&self) -> &CoreVmR1S4Evidence {
        &self.s4_evidence
    }

    pub(super) fn residual(&self) -> &CoreArtifact {
        self.s4.artifact()
    }

    pub(super) fn ssa(&self) -> &CoreSsaArtifact {
        &self.ssa
    }

    pub(super) fn machine_ir(&self) -> &MachineIrArtifact {
        &self.machine_ir
    }

    pub(super) fn target(&self) -> &X64TargetArtifact {
        &self.target
    }

    /// Regenerate the complete sealed R1-S5 Gate A identity from the frozen
    /// branch workload. The selected package is reused when it already owns
    /// that exact specialization; a Bounds authority independently rebuilds
    /// the branch package rather than accepting detached evidence.
    pub(super) fn regenerate_gate_a_evidence(
        &self,
    ) -> Result<CoreVmGateAEvidence, X64NativeLighthouseError> {
        let program = branch_mix_kernel_program();
        if self.workload == CoreVmGateAWorkload::BranchMix {
            return emit_corevm0_gate_a_r1_s5(&program, &self.s4, &self.s4_evidence)
                .map_err(|error| pipeline(self.workload, "R1-S5 Gate A evidence", error));
        }

        let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
        emit_corevm0_gate_a_r1_s5(&program, &branch.s4, &branch.s4_evidence)
            .map_err(|error| pipeline(self.workload, "R1-S5 Gate A evidence", error))
    }

    /// Independently regenerate and reverify both predecessor translation
    /// correspondence lines over the exact ordered 51-case Gate A corpus.
    ///
    /// The second workload is always rebuilt from its source program. No
    /// detached artifact identity or caller-provided evidence participates
    /// in either aggregate result.
    pub(super) fn regenerate_translation_correspondences(
        &self,
    ) -> Result<
        (
            R1S5CoreSsaCorrespondenceEvidence,
            R1S6MachineIrCorrespondenceEvidence,
        ),
        X64NativeLighthouseError,
    > {
        let other_workload = match self.workload {
            CoreVmGateAWorkload::BranchMix => CoreVmGateAWorkload::BoundsOrderedArrayGet,
            CoreVmGateAWorkload::BoundsOrderedArrayGet => CoreVmGateAWorkload::BranchMix,
        };
        let other = X64NativeLighthousePackage::build(other_workload)?;
        let (branch, bounds) = match self.workload {
            CoreVmGateAWorkload::BranchMix => (self, &other),
            CoreVmGateAWorkload::BoundsOrderedArrayGet => (&other, self),
        };

        let core_ssa = emit_r1_s5_core_ssa_correspondence(
            branch.residual(),
            branch.ssa(),
            bounds.residual(),
            bounds.ssa(),
        )
        .map_err(|error| pipeline(self.workload, "R1-S5 correspondence emission", error))?;
        verify_r1_s5_core_ssa_correspondence(
            branch.residual(),
            branch.ssa(),
            bounds.residual(),
            bounds.ssa(),
            &core_ssa,
        )
        .map_err(|error| pipeline(self.workload, "R1-S5 correspondence replay", error))?;

        let machine_ir = emit_r1_s6_machine_ir_correspondence(
            branch.residual(),
            branch.ssa(),
            branch.machine_ir(),
            bounds.residual(),
            bounds.ssa(),
            bounds.machine_ir(),
        )
        .map_err(|error| pipeline(self.workload, "R1-S6 correspondence emission", error))?;
        verify_r1_s6_machine_ir_correspondence(
            branch.residual(),
            branch.ssa(),
            branch.machine_ir(),
            bounds.residual(),
            bounds.ssa(),
            bounds.machine_ir(),
            &machine_ir,
        )
        .map_err(|error| pipeline(self.workload, "R1-S6 correspondence replay", error))?;

        Ok((core_ssa, machine_ir))
    }

    /// Independently regenerate the sealed ordered R1-S7a Machine-IR versus
    /// target-plan correspondence identity over the exact Gate A corpus.
    pub(super) fn regenerate_target_correspondence(
        &self,
    ) -> Result<X64TargetCorrespondenceEvidence, X64NativeLighthouseError> {
        let other_workload = match self.workload {
            CoreVmGateAWorkload::BranchMix => CoreVmGateAWorkload::BoundsOrderedArrayGet,
            CoreVmGateAWorkload::BoundsOrderedArrayGet => CoreVmGateAWorkload::BranchMix,
        };
        let other = X64NativeLighthousePackage::build(other_workload)?;
        let manifest = canonical_manifest()?;
        let mut records = Vec::with_capacity(manifest.cases.len());

        for case in &manifest.cases {
            let package = if case.workload == self.workload {
                self
            } else {
                &other
            };
            let arguments = package.case_arguments(case)?;
            let machine_ir = package.evaluate_machine_ir_case(case)?;
            let target = package.source_bound()?;
            let target_plan = evaluate_source_bound_x64_target_plan(
                target,
                arguments,
                EvaluationBudget::new(
                    COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
                    COREVM0_GATE_A_CALL_DEPTH_LIMIT,
                ),
            )
            .map_err(|error| pipeline(package.workload, "R1-S7a plan evaluation", error))?;
            records.push(
                seal_x64_target_correspondence_record(
                    case.ordinal,
                    case.input_hash,
                    package.machine_ir(),
                    package.target(),
                    &machine_ir,
                    &target_plan,
                )
                .map_err(|error| {
                    pipeline(package.workload, "R1-S7a correspondence record", error)
                })?,
            );
        }

        let evidence = seal_x64_target_correspondence_evidence(records)
            .map_err(|error| pipeline(self.workload, "R1-S7a correspondence result", error))?;
        verify_x64_target_correspondence_evidence(&evidence)
            .map_err(|error| pipeline(self.workload, "R1-S7a correspondence replay", error))?;
        Ok(evidence)
    }

    /// Derive typed host arguments only from an exactly admitted manifest
    /// case.  No raw data/length descriptor crosses this boundary.
    pub(super) fn case_arguments(
        &self,
        case: &CoreVmGateACase,
    ) -> Result<Vec<CoreValue>, X64NativeLighthouseError> {
        admit_case(case, self.workload)?;
        let values = case
            .input
            .array_f64_bits
            .iter()
            .copied()
            .map(f64::from_bits)
            .collect::<Vec<_>>();
        let mut arguments = vec![CoreValue::array_f64(values)];
        if self.workload == CoreVmGateAWorkload::BranchMix {
            arguments.push(CoreValue::I64(case.input.repetitions));
        }
        Ok(arguments)
    }

    /// Independently execute this package's source-bound Machine IR under
    /// the exact Gate A residual budget.
    pub(super) fn evaluate_machine_ir_case(
        &self,
        case: &CoreVmGateACase,
    ) -> Result<Evaluation, X64NativeLighthouseError> {
        let arguments = self.case_arguments(case)?;
        evaluate_machine_ir_translation(
            &self.machine_ir,
            &self.ssa,
            self.s4.artifact(),
            arguments,
            EvaluationBudget::new(
                COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
                COREVM0_GATE_A_CALL_DEPTH_LIMIT,
            ),
        )
        .map_err(|error| pipeline(self.workload, "Machine IR evaluation", error))
    }
}

/// Regenerate and return one exact canonical case by ordinal.
pub(super) fn x64_native_lighthouse_case(
    ordinal: u32,
) -> Result<CoreVmGateACase, X64NativeLighthouseError> {
    let manifest = canonical_manifest()?;
    let index = usize::try_from(ordinal).map_err(|_| X64NativeLighthouseError::CaseOrdinal {
        ordinal,
        total: COREVM0_GATE_A_TOTAL_CASES,
    })?;
    manifest
        .cases
        .get(index)
        .filter(|case| case.ordinal == ordinal)
        .cloned()
        .ok_or(X64NativeLighthouseError::CaseOrdinal {
            ordinal,
            total: COREVM0_GATE_A_TOTAL_CASES,
        })
}

fn canonical_manifest(
) -> Result<super::corevm0_gate_a::CoreVmGateACorpusManifest, X64NativeLighthouseError> {
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeLighthouseError::Manifest)?;
    let expected_length = usize::try_from(COREVM0_GATE_A_TOTAL_CASES).map_err(|_| {
        X64NativeLighthouseError::ManifestShape {
            expected: COREVM0_GATE_A_TOTAL_CASES,
            declared: manifest.total_cases,
            actual: manifest.cases.len(),
        }
    })?;
    if manifest.total_cases != COREVM0_GATE_A_TOTAL_CASES || manifest.cases.len() != expected_length
    {
        return Err(X64NativeLighthouseError::ManifestShape {
            expected: COREVM0_GATE_A_TOTAL_CASES,
            declared: manifest.total_cases,
            actual: manifest.cases.len(),
        });
    }
    Ok(manifest)
}

fn admit_case(
    case: &CoreVmGateACase,
    expected_workload: CoreVmGateAWorkload,
) -> Result<(), X64NativeLighthouseError> {
    if case.workload != expected_workload {
        return Err(X64NativeLighthouseError::WorkloadMismatch {
            ordinal: case.ordinal,
            expected: expected_workload,
            actual: case.workload,
        });
    }
    let canonical = x64_native_lighthouse_case(case.ordinal)?;
    if canonical != *case {
        return Err(X64NativeLighthouseError::NonCanonicalCase {
            ordinal: case.ordinal,
        });
    }
    Ok(())
}

fn specialize_program(
    workload: CoreVmGateAWorkload,
    program: &CoreVmProgram,
    dynamic_types: Vec<Type>,
) -> Result<CoreVmR1S4Specialization, X64NativeLighthouseError> {
    let bound = build_definitional_corevm0(program)
        .map_err(|error| pipeline(workload, "CoreVM0 definitional build", error))?;

    let mut manifest = vec![BindingTime::Static];
    manifest.extend(std::iter::repeat_n(
        BindingTime::Dynamic,
        dynamic_types.len(),
    ));
    let binding = BindingTimeRequest::p1v0(
        bound.artifact(),
        manifest,
        BindingTimeBudget::new(1_000_000, 1_000_000, 10_000),
    )
    .map_err(|error| pipeline(workload, "B0 request construction", error))?;
    let validated_binding = validate_binding_time_b0_request(bound.artifact(), &binding)
        .map_err(|error| pipeline(workload, "B0 request validation", error))?;
    let certificate = certify_binding_time_b0d(&validated_binding)
        .map_err(|error| pipeline(workload, "B0 certificate", error))?;

    let mut slots = vec![SpecializationSlot::Static(bound.program_image().clone())];
    slots.extend(dynamic_types.into_iter().map(SpecializationSlot::Dynamic));
    let request = SpecializationRequest::p1v0(
        bound.artifact(),
        &binding,
        &certificate,
        slots,
        SpecializationBudget::new(1_000_000, 1_000_000, 100_000_000, 1_000_000, 1_000_000_000),
    )
    .map_err(|error| pipeline(workload, "R0 request construction", error))?;
    let validated =
        validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
            .map_err(|error| pipeline(workload, "R0 request validation", error))?;
    let specialization = specialize_corevm0_r1_s4(&bound, &validated, fixed_s4_budget())
        .map_err(|error| pipeline(workload, "R1-S4 specialization", error))?;
    Ok(specialization)
}

fn array_f64_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn fixed_s4_budget() -> PolyvariantR1S4Budget {
    PolyvariantR1S4Budget::new(
        100_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000_000,
    )
}

fn pipeline(
    workload: CoreVmGateAWorkload,
    stage: &'static str,
    error: impl fmt::Display,
) -> X64NativeLighthouseError {
    X64NativeLighthouseError::Pipeline {
        workload,
        stage,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::x64_target::{X64InstructionKind, X64Operand, X64Terminator};
    use super::*;

    #[test]
    fn both_frozen_workloads_rebuild_and_source_replay() {
        for ordinal in [0, 46] {
            let case = x64_native_lighthouse_case(ordinal)
                .expect("frozen case must regenerate by ordinal");
            let package = X64NativeLighthousePackage::build(case.workload)
                .expect("frozen lighthouse package must rebuild");
            let source_bound = package
                .source_bound()
                .expect("rebuilt target must replay from its exact source chain");
            assert_eq!(
                source_bound.source_core().semantic_hash,
                package.s4.artifact().semantic_hash
            );
            assert_eq!(
                source_bound.source_ssa().semantic_hash,
                package.ssa.semantic_hash
            );
            assert_eq!(
                source_bound.source_machine_ir().semantic_hash,
                package.machine_ir.semantic_hash
            );
            assert_eq!(source_bound.semantic_hash(), package.target.semantic_hash);

            let arguments = package
                .case_arguments(&case)
                .expect("canonical case must derive typed arguments");
            let expected_arguments = match case.workload {
                CoreVmGateAWorkload::BranchMix => 2,
                CoreVmGateAWorkload::BoundsOrderedArrayGet => 1,
            };
            assert_eq!(arguments.len(), expected_arguments);
            package
                .evaluate_machine_ir_case(&case)
                .expect("source-bound Machine IR must evaluate within the Gate A budget");
        }
    }

    #[test]
    fn case_admission_rejects_wrong_workload_mutation_and_out_of_range_ordinal() {
        let branch =
            x64_native_lighthouse_case(0).expect("first branch case must regenerate exactly");
        let bounds_package =
            X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)
                .expect("Bounds package must rebuild");
        assert!(matches!(
            bounds_package.case_arguments(&branch),
            Err(X64NativeLighthouseError::WorkloadMismatch {
                ordinal: 0,
                expected: CoreVmGateAWorkload::BoundsOrderedArrayGet,
                actual: CoreVmGateAWorkload::BranchMix,
            })
        ));

        let branch_package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch package must rebuild");
        let mut mutated = branch;
        mutated.input.repetitions ^= 1;
        assert!(matches!(
            branch_package.case_arguments(&mutated),
            Err(X64NativeLighthouseError::NonCanonicalCase { ordinal: 0 })
        ));
        assert!(matches!(
            x64_native_lighthouse_case(COREVM0_GATE_A_TOTAL_CASES),
            Err(X64NativeLighthouseError::CaseOrdinal {
                ordinal: COREVM0_GATE_A_TOTAL_CASES,
                total: COREVM0_GATE_A_TOTAL_CASES,
            })
        ));
    }

    #[test]
    fn predecessor_evidence_regeneration_keeps_locked_aggregate_identities() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch lighthouse package must rebuild");
        assert_eq!(
            package.s4_evidence().evidence_hash.to_hex(),
            "8d648c021a3c806d76790e49ae8655ee59f2e97427800827db91577c90d64896"
        );

        let gate_a = package
            .regenerate_gate_a_evidence()
            .expect("complete Gate A evidence must regenerate");
        assert_eq!(
            gate_a.results_hash.to_hex(),
            "bc755f8a99b6cbffaa7fee7d1e7cbc81de7787249a2dc5ba83458798a2366249"
        );
        assert_eq!(
            gate_a.telemetry_hash.to_hex(),
            "f5d709e2713fac7f2268ad6da4855010dc7978a61529adfd74cf7b34b9ef1a29"
        );
        assert_eq!(
            gate_a.evidence_hash.to_hex(),
            "5c2d81b3cd20ef72e41437b1426156642404a1c736faf7cace70ffe1e82c5f01"
        );

        let (core_ssa, machine_ir) = package
            .regenerate_translation_correspondences()
            .expect("complete R1-S5/R1-S6 correspondence must regenerate and replay");
        let expected_records = usize::try_from(COREVM0_GATE_A_TOTAL_CASES)
            .expect("fixed correspondence count must fit usize");
        assert_eq!(core_ssa.records.len(), expected_records);
        assert_eq!(machine_ir.records.len(), expected_records);
        assert_eq!(core_ssa.manifest_hash, gate_a.corpus.manifest_hash);
        assert_eq!(machine_ir.manifest_hash, gate_a.corpus.manifest_hash);
        assert_eq!(
            core_ssa.results_hash.to_hex(),
            "18db0347094dfad000e7a6401cd1d989edd57f44bd0b31a9544d80f3803ba58b"
        );
        assert_eq!(
            machine_ir.results_hash.to_hex(),
            "3cc7cbd876531ea6f88c56f50c851eb168ac76afe2d9a05ae6835687bf411205"
        );

        let target = package
            .regenerate_target_correspondence()
            .expect("complete R1-S7a correspondence must regenerate");
        assert_eq!(target.records.len(), expected_records);
        assert_eq!(
            target.results_hash.to_hex(),
            "fe9cbcaf67798b502e8405eecb0228b7453d39427e97e4d404c7cd1356c8c49d"
        );
    }

    #[test]
    fn branch_target_tail_transfer_shape_is_visible() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch lighthouse package must rebuild");
        let program = &package.target().program;
        let mut transfers = 0_u32;
        let mut arguments = 0_u32;
        let mut identity_arguments = 0_u32;
        let mut noop_tail_blocks = 0_u32;
        let mut fused_compare_branches = 0_u32;
        for function in &program.functions {
            for block in &function.blocks {
                let X64Terminator::TailJumpRel32 {
                    function: callee,
                    target_label,
                    arguments: tail_arguments,
                    ..
                } = &block.terminator
                else {
                    continue;
                };
                transfers += 1;
                let parameters = &program.functions[callee.0 as usize].parameters;
                arguments += tail_arguments.len() as u32;
                identity_arguments += tail_arguments
                    .iter()
                    .zip(parameters)
                    .filter(|(argument, parameter)| {
                        matches!(argument, X64Operand::Home(home) if *home == parameter.home)
                    })
                    .count() as u32;
                if block.instructions.is_empty()
                    && tail_arguments.len() == parameters.len()
                    && tail_arguments
                        .iter()
                        .zip(parameters)
                        .all(|(argument, parameter)| {
                            matches!(argument, X64Operand::Home(home) if *home == parameter.home)
                        })
                {
                    noop_tail_blocks += 1;
                }

                let [instruction] = block.instructions.as_slice() else {
                    continue;
                };
                if !matches!(instruction.kind, X64InstructionKind::I64Setcc { .. }) {
                    continue;
                }
                let callee_entry = &program.functions[callee.0 as usize].blocks
                    [program.functions[callee.0 as usize].entry_block.0 as usize];
                let X64Terminator::BranchRel32 {
                    condition: X64Operand::Home(condition_home),
                    ..
                } = &callee_entry.terminator
                else {
                    continue;
                };
                let condition_indices = parameters
                    .iter()
                    .enumerate()
                    .filter_map(|(index, parameter)| {
                        (parameter.home == *condition_home).then_some(index)
                    })
                    .collect::<Vec<_>>();
                if callee_entry.label == *target_label
                    && callee_entry.instructions.is_empty()
                    && condition_indices.len() == 1
                    && tail_arguments.iter().zip(parameters).enumerate().all(
                        |(index, (argument, parameter))| {
                            if index == condition_indices[0] {
                                matches!(
                                    argument,
                                    X64Operand::Home(home) if *home == instruction.result
                                )
                            } else {
                                matches!(
                                    argument,
                                    X64Operand::Home(home) if *home == parameter.home
                                )
                            }
                        },
                    )
                {
                    fused_compare_branches += 1;
                }
            }
        }
        println!(
            "branch target shape: functions={} blocks={} instructions={} tails={} tail_args={} \
             identity_args={} noop_tail_blocks={} fused_compare_branches={} frame={} code={}",
            program.functions.len(),
            program
                .functions
                .iter()
                .map(|function| function.blocks.len())
                .sum::<usize>(),
            program
                .functions
                .iter()
                .flat_map(|function| &function.blocks)
                .map(|block| block.instructions.len())
                .sum::<usize>(),
            transfers,
            arguments,
            identity_arguments,
            noop_tail_blocks,
            fused_compare_branches,
            program.frame.frame_bytes,
            program.code.len(),
        );
        assert_eq!(
            (
                program.functions.len(),
                program
                    .functions
                    .iter()
                    .map(|function| function.blocks.len())
                    .sum::<usize>(),
                program
                    .functions
                    .iter()
                    .flat_map(|function| &function.blocks)
                    .map(|block| block.instructions.len())
                    .sum::<usize>(),
                transfers,
                arguments,
                identity_arguments,
                noop_tail_blocks,
                fused_compare_branches,
                program.frame.frame_bytes,
                program.code.len(),
            ),
            (121, 139, 23, 127, 1_151, 969, 28, 9, 240, 3_097),
        );
    }
}
