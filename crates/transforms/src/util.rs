use async_trait::async_trait;
use bytecloak_core::cfg_ir::CfgIrBundle;
use bytecloak_utils::errors::TransformError;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

/// Trait for bytecode obfuscation transforms.
#[async_trait]
pub trait Transform: Send + Sync {
    /// Returns the transform's name for logging and identification.
    fn name(&self) -> &'static str;
    /// Applies the transform to the CFG IR, returning whether changes were made.
    async fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError>;
}

/// Configuration for transform passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassConfig {
    pub accept_threshold: f64,
    pub aggressive: bool,
    pub max_size_delta: f32,
    pub max_noise_ratio: f32,
    pub max_opaque_ratio: f32,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            accept_threshold: 0.0,
            aggressive: false,
            max_size_delta: 0.05,
            max_noise_ratio: 0.20,
            max_opaque_ratio: 0.10,
        }
    }
}
