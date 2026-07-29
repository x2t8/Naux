//! Checked bridges from evolving Surface syntax into canonical Core-N0.
//!
//! Elaboration is intentionally outside `crate::core`: it may inspect the
//! Surface AST, while the Core schema, verifier, encoder, and interpreter must
//! remain independent of Surface and bridge runtime representations.

mod surface_t2;

pub use surface_t2::{
    bind_surface_inputs, bind_surface_t2a_inputs, elaborate_surface_t2a, elaborate_surface_t2b,
    normalize_core_scalar, normalize_surface_scalar, BoundSurfaceInputs, ElaborationBudget,
    ElaborationCode, ElaborationError, ElaborationReport, InputBindingError, NormalizedScalar,
    ScalarObservationError, SurfaceElaborationProfile, SurfaceFunctionSignature, SurfaceInput,
    SurfaceScalarType, SurfaceScalarValue, T2A_MAX_CORE_NODES, T2A_MAX_INPUTS,
    T2A_MAX_SOURCE_STEPS, T2B_MAX_FUNCTIONS, T2B_MAX_PARAMETERS,
};
