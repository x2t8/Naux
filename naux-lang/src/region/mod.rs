//! # Region Inference for Naux (Tofte-Talpin style)
//!
//! Region analysis experiments for deterministic memory lifetime tracking.
//!
//! Every heap allocation is assigned to a **region**. Regions are created
//! at scope boundaries and deallocated in LIFO order. The compiler infers
//! which region each value belongs to, and inserts region
//! creation/destruction automatically.
//!
//! Benefits:
//! - Zero garbage collector overhead
//! - Zero manual free / reference counting
//! - Deterministic memory deallocation
//! - Stack-like region deallocation (fast bulk free)

pub mod analyze;
pub mod types;

pub use analyze::{infer_regions, RegionReport};
pub use types::{Region, RegionEnv, RegionId, RegionVar};
