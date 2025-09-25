//! Azoth Formal Verification Engine
//!
//! This crate provides mathematical guarantees that obfuscated contracts are
//! functionally equivalent to their original versions through:
//!
//! 1. **Formal Verification**: Mathematical proofs using SMT solvers
//! 2. **Practical Testing**: Empirical validation using EVM simulation

pub mod certificate;
pub mod config;
pub mod formal;
pub mod orchestrator;
pub mod practical;

pub use certificate::{VerificationCertificate, VerificationProof};
pub use config::{VerificationConfig, VerificationLevel};
pub use formal::proofs::{FormalProof, ProofStatement};
pub use formal::{FormalVerifier, SecurityProperty};
pub use orchestrator::VerificationEngine;
pub use practical::{EquivalenceResults, PracticalTester};
use revm::context::DBErrorMarker;

/// Main error type for verification operations
#[derive(thiserror::Error, Debug)]
pub enum VerificationError {
    #[error("SMT solver error: {0}")]
    SmtSolver(String),

    #[error("EVM execution error: {0}")]
    EvmExecution(String),

    #[error("Verification timeout after {seconds} seconds")]
    Timeout { seconds: u64 },

    #[error("Bytecode analysis failed: {0}")]
    BytecodeAnalysis(String),

    #[error("Property verification failed: {property}")]
    PropertyFailed { property: String },

    #[error("Equivalence test failed: {test_type}")]
    EquivalenceFailed { test_type: String },

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl DBErrorMarker for VerificationError {}

/// Result type for verification operations
pub type VerificationResult<T> = Result<T, VerificationError>;

/// Information about a transform that was applied during obfuscation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransformInfo {
    pub name: String,
    pub parameters: serde_json::Value,
    pub order: usize,
}

/// Summary of verification results for quick inspection
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationSummary {
    pub overall_passed: bool,
    pub formal_verification_passed: bool,
    pub practical_testing_passed: bool,
    pub verification_time_ms: u64,
    pub certificate_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_verification_workflow() {
        // This will be our integration test
        // For now, just ensure the module structure compiles
        let config = VerificationConfig::development();
        assert_eq!(config.verification_level, VerificationLevel::Quick);
    }
}
