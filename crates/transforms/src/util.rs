use async_trait::async_trait;
use bytecloak_core::cfg_ir::CfgIrBundle;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for transform operations.
#[derive(Debug, Error)]
pub enum TransformError {
    #[error("bytecode size exceeds maximum allowed delta")]
    SizeLimitExceeded,
    #[error("stack depth exceeds maximum limit of 1024")]
    StackOverflow,
    #[error("invalid jump target: {0}")]
    InvalidJumpTarget(usize),
    #[error("instruction encoding failed: {0}")]
    EncodingError(String),
    #[error("core operation failed")]
    CoreError(#[from] bytecloak_core::cfg_ir::CfgIrError),
    #[error("metrics computation failed")]
    MetricsError(#[from] bytecloak_analysis::metrics::MetricsError),
}

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
