//! # Region Inference for Naux (Tofte-Talpin style)
//!
//! Experimental region analysis for deterministic memory lifetime tracking.
//!
//! Direct heap-producing bindings are assigned to a **region**. Regions are
//! created at scope boundaries and ordered by parent lifetime. The compiler
//! reports an escape/bulk-free plan for the supported allocation subset.
//!
//! This module does not yet replace the `Rc` runtime or insert
//! creation/destruction instructions. Its output is proof-oriented evidence
//! for future lowering work, not a zero-GC runtime claim.

pub mod analyze;
#[cfg(feature = "experimental-regions")]
pub mod lower;
pub mod types;

pub use analyze::{
    infer_regions, RegionAllocation, RegionAllocationKind, RegionCapture, RegionReport,
};
#[cfg(feature = "experimental-regions")]
pub use lower::{
    lower_region_report, verify_region_lowering_plan, RegionFallbackReason, RegionFreePoint,
    RegionLoweringAllocation, RegionLoweringError, RegionLoweringPlan, RegionOrdinal,
    RegionStorageClass,
};
pub use types::{Region, RegionEnv, RegionId, RegionVar};
