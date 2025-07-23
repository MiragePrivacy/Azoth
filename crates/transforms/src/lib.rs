pub mod function_dispatcher;
pub mod jump_address_transformer;
pub mod obfuscator;
pub mod opaque_predicate;
pub mod pass;
pub mod shuffle;

use azoth_core::cfg_ir::CfgIrBundle;
use azoth_utils::errors::TransformError;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

/// Trait for bytecode obfuscation transforms.
pub trait Transform: Send + Sync {
    /// Returns the transform's name for logging and identification.
    fn name(&self) -> &'static str;
    /// Applies the transform to the CFG IR, returning whether changes were made.
    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError>;
}

/// Configuration for transform passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassConfig {
    /// Minimum quality threshold for accepting transforms
    pub accept_threshold: f64,
    /// Apply transforms aggressively without quality gates
    pub aggressive: bool,
    /// Maximum allowable bytecode size increase (as ratio)
    pub max_size_delta: f32,
    /// Maximum ratio of blocks to apply opaque predicates to
    pub max_opaque_ratio: f32,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            accept_threshold: 0.0,
            aggressive: true,
            max_size_delta: 0.1,   // 10% size increase limit
            max_opaque_ratio: 0.2, // Apply to 20% of blocks max
        }
    }
}
