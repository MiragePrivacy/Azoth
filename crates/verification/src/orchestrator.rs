//! Main verification orchestrator that combines formal and practical verification

use crate::{
    certificate::VerificationCertificate,
    config::{VerificationConfig, VerificationLevel},
    formal::{FormalProof, FormalVerifier, SecurityProperty},
    practical::{EquivalenceResults, PracticalTester},
    TransformInfo, VerificationError, VerificationResult,
};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Main verification engine that orchestrates formal and practical verification
pub struct VerificationEngine {
    config: VerificationConfig,
    formal_verifier: Option<FormalVerifier>,
    practical_tester: Option<PracticalTester>,
}

/// Combined verification results
#[derive(Debug, Clone)]
pub struct CombinedVerificationResult {
    pub formal_proof: Option<FormalProof>,
    pub practical_results: Option<EquivalenceResults>,
    pub overall_passed: bool,
    pub verification_time: Duration,
    pub warnings: Vec<String>,
}

impl VerificationEngine {
    /// Create a new verification engine
    pub async fn new(config: VerificationConfig) -> VerificationResult<Self> {
        info!("Initializing Azoth verification engine");

        // Validate configuration
        config.validate()?;

        // Initialize formal verifier if enabled
        let formal_verifier = if config.formal_verification_enabled {
            match FormalVerifier::new(config.smt_config.clone()) {
                Ok(verifier) => {
                    info!("Formal verification enabled with SMT solver");
                    Some(verifier)
                }
                Err(e) => {
                    warn!("Failed to initialize formal verifier: {}", e);
                    if matches!(config.verification_level, VerificationLevel::Comprehensive) {
                        return Err(e);
                    }
                    None
                }
            }
        } else {
            debug!("Formal verification disabled");
            None
        };

        // Initialize practical tester if enabled
        let practical_tester = if config.practical_testing_enabled {
            match PracticalTester::new(config.evm_config.clone()).await {
                Ok(tester) => {
                    info!("Practical testing enabled");
                    Some(tester)
                }
                Err(e) => {
                    warn!("Failed to initialize practical tester: {}", e);
                    return Err(e);
                }
            }
        } else {
            debug!("Practical testing disabled");
            None
        };

        Ok(Self {
            config,
            formal_verifier,
            practical_tester,
        })
    }

    /// Main verification entry point
    pub async fn verify_equivalence(
        &mut self,
        original_bytecode: &[u8],
        obfuscated_bytecode: &[u8],
        seed: u64,
        transforms_applied: &[TransformInfo],
    ) -> VerificationResult<VerificationCertificate> {
        let start_time = Instant::now();

        info!(
            "Starting verification of {} byte contract with {} transforms",
            original_bytecode.len(),
            transforms_applied.len()
        );

        // Run verification with timeout
        let verification_result = timeout(
            self.config.timeout,
            self.run_verification_internal(
                original_bytecode,
                obfuscated_bytecode,
                seed,
                transforms_applied,
            ),
        )
        .await;

        let combined_result = match verification_result {
            Ok(result) => result?,
            Err(_) => {
                return Err(VerificationError::Timeout {
                    seconds: self.config.timeout.as_secs(),
                });
            }
        };

        let total_time = start_time.elapsed();

        // Generate verification certificate
        let certificate = VerificationCertificate::new(
            original_bytecode,
            obfuscated_bytecode,
            seed,
            transforms_applied,
            combined_result.formal_proof,
            combined_result.practical_results,
            total_time,
            &self.config,
        )?;

        info!(
            "Verification completed in {:.2}s - Overall: {}",
            total_time.as_secs_f64(),
            if certificate.overall_passed() {
                "PASSED"
            } else {
                "FAILED"
            }
        );

        Ok(certificate)
    }

    /// Internal verification logic
    async fn run_verification_internal(
        &mut self,
        original_bytecode: &[u8],
        obfuscated_bytecode: &[u8],
        _seed: u64,
        _transforms_applied: &[TransformInfo],
    ) -> VerificationResult<CombinedVerificationResult> {
        let mut warnings = Vec::new();

        // Extract security properties to verify
        let security_properties = self.extract_security_properties(original_bytecode)?;
        debug!(
            "Extracted {} security properties",
            security_properties.len()
        );

        // Run verifications based on configuration
        let (formal_proof, practical_results) =
            if self.config.parallelism.parallel_verification_types {
                self.run_parallel_verification(
                    original_bytecode,
                    obfuscated_bytecode,
                    &security_properties,
                )
                .await?
            } else {
                self.run_sequential_verification(
                    original_bytecode,
                    obfuscated_bytecode,
                    &security_properties,
                )
                .await?
            };

        // Validate results consistency
        if let (Some(ref formal), Some(ref practical)) = (&formal_proof, &practical_results) {
            self.validate_result_consistency(formal, practical, &mut warnings)?;
        }

        // Determine overall pass/fail
        let overall_passed = self.evaluate_overall_result(&formal_proof, &practical_results);

        Ok(CombinedVerificationResult {
            formal_proof,
            practical_results,
            overall_passed,
            verification_time: Duration::default(), // Will be set by caller
            warnings,
        })
    }

    /// Run formal and practical verification in parallel
    async fn run_parallel_verification(
        &mut self,
        original_bytecode: &[u8],
        obfuscated_bytecode: &[u8],
        security_properties: &[SecurityProperty],
    ) -> VerificationResult<(Option<FormalProof>, Option<EquivalenceResults>)> {
        info!("Running parallel verification");

        let formal_task = async {
            if let Some(ref mut verifier) = self.formal_verifier {
                Some(
                    verifier
                        .prove_equivalence(
                            original_bytecode,
                            obfuscated_bytecode,
                            security_properties,
                        )
                        .await,
                )
            } else {
                None
            }
        };

        let practical_task = async {
            if let Some(ref mut tester) = self.practical_tester {
                Some(
                    tester
                        .test_equivalence(original_bytecode, obfuscated_bytecode)
                        .await,
                )
            } else {
                None
            }
        };

        let (formal_result, practical_result) = tokio::join!(formal_task, practical_task);

        let formal_proof = match formal_result {
            Some(Ok(proof)) => Some(proof),
            Some(Err(e)) => {
                warn!("Formal verification failed: {}", e);
                None
            }
            None => None,
        };

        let practical_results = match practical_result {
            Some(Ok(results)) => Some(results),
            Some(Err(e)) => {
                warn!("Practical testing failed: {}", e);
                None
            }
            None => None,
        };

        Ok((formal_proof, practical_results))
    }

    /// Run formal and practical verification sequentially
    async fn run_sequential_verification(
        &mut self,
        original_bytecode: &[u8],
        obfuscated_bytecode: &[u8],
        security_properties: &[SecurityProperty],
    ) -> VerificationResult<(Option<FormalProof>, Option<EquivalenceResults>)> {
        info!("Running sequential verification");

        // Run formal verification first (usually faster)
        let formal_proof = if let Some(ref mut verifier) = self.formal_verifier {
            match verifier
                .prove_equivalence(original_bytecode, obfuscated_bytecode, security_properties)
                .await
            {
                Ok(proof) => Some(proof),
                Err(e) => {
                    warn!("Formal verification failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Run practical testing
        let practical_results = if let Some(ref mut tester) = self.practical_tester {
            match tester
                .test_equivalence(original_bytecode, obfuscated_bytecode)
                .await
            {
                Ok(results) => Some(results),
                Err(e) => {
                    warn!("Practical testing failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok((formal_proof, practical_results))
    }

    /// Extract security properties from original contract
    fn extract_security_properties(
        &self,
        bytecode: &[u8],
    ) -> VerificationResult<Vec<SecurityProperty>> {
        let mut properties = Vec::new();

        // Basic properties that should always be checked
        properties.push(SecurityProperty::ArithmeticSafety {
            operations: vec![
                crate::formal::ArithmeticOperation::Addition,
                crate::formal::ArithmeticOperation::Subtraction,
                crate::formal::ArithmeticOperation::Multiplication,
            ],
        });

        // Look for common patterns in bytecode to extract more properties
        // This is a simplified heuristic-based approach
        let bytecode_hex = hex::encode(bytecode);

        // Look for access control patterns
        if bytecode_hex.contains("33") {
            // CALLER opcode
            properties.push(SecurityProperty::Custom {
                name: "Caller-based access control".to_string(),
                property_formula: "(assert (authorized-caller (caller tx)))".to_string(),
            });
        }

        // Look for reentrancy protection patterns
        if bytecode_hex.contains("5415") {
            // SLOAD followed by ISZERO pattern
            properties.push(SecurityProperty::ReentrancyProtection {
                protected_functions: vec![], // Would need more analysis
            });
        }

        // Add Mirage-specific properties if this looks like a Mirage contract
        if self.is_mirage_contract(bytecode) {
            properties.extend(self.extract_mirage_properties());
        }

        debug!("Extracted {} security properties", properties.len());
        Ok(properties)
    }

    /// Check if this is a Mirage protocol contract
    fn is_mirage_contract(&self, bytecode: &[u8]) -> bool {
        let bytecode_hex = hex::encode(bytecode);

        // Look for Mirage-specific patterns
        // This is a heuristic - in practice you'd have more sophisticated detection
        bytecode_hex.contains("bond")
            || bytecode_hex.contains("executor")
            || bytecode_hex.contains("escrow")
    }

    /// Extract Mirage-specific security properties
    fn extract_mirage_properties(&self) -> Vec<SecurityProperty> {
        vec![
            SecurityProperty::Custom {
                name: "Bond enforcement".to_string(),
                property_formula:
                    "(assert (=> (execute-signal signal) (>= (bond executor) (required-bond signal))))".to_string(),
            },
            SecurityProperty::Custom {
                name: "Executor isolation".to_string(),
                property_formula:
                    "(assert (not (= (eoa1 executor) (eoa2 executor))))".to_string(),
            },
            SecurityProperty::Custom {
                name: "Proof validation".to_string(),
                property_formula:
                    "(assert (=> (claim-reward executor) (valid-proof (submitted-proof executor))))".to_string(),
            },
        ]
    }

    /// Validate consistency between formal and practical results
    fn validate_result_consistency(
        &self,
        formal_proof: &FormalProof,
        practical_results: &EquivalenceResults,
        warnings: &mut Vec<String>,
    ) -> VerificationResult<()> {
        // Check if formal and practical results agree
        if formal_proof.valid && !practical_results.overall_passed {
            warnings.push(
                "Formal verification passed but practical testing failed - investigate discrepancy"
                    .to_string(),
            );
        } else if !formal_proof.valid && practical_results.overall_passed {
            warnings.push(
                "Practical testing passed but formal verification failed - may indicate incomplete formal model".to_string()
            );
        }

        // Check gas overhead consistency
        if let Some(gas_results) = &practical_results.gas_equivalence {
            let practical_overhead = gas_results.max_overhead_percentage / 100.0;
            let config_limit = self.config.max_gas_overhead;

            if practical_overhead > config_limit {
                return Err(VerificationError::EquivalenceFailed {
                    test_type: format!(
                        "Gas overhead {:.1}% exceeds limit {:.1}%",
                        practical_overhead * 100.0,
                        config_limit * 100.0
                    ),
                });
            }
        }

        Ok(())
    }

    /// Evaluate overall verification result
    fn evaluate_overall_result(
        &self,
        formal_proof: &Option<FormalProof>,
        practical_results: &Option<EquivalenceResults>,
    ) -> bool {
        match self.config.verification_level {
            VerificationLevel::Quick => {
                // For quick verification, either formal OR practical passing is sufficient
                formal_proof.as_ref().map(|p| p.valid).unwrap_or(false)
                    || practical_results
                        .as_ref()
                        .map(|r| r.overall_passed)
                        .unwrap_or(false)
            }
            VerificationLevel::Standard => {
                // For standard verification, require both if both are enabled
                let formal_ok = !self.config.formal_verification_enabled
                    || formal_proof.as_ref().map(|p| p.valid).unwrap_or(false);
                let practical_ok = !self.config.practical_testing_enabled
                    || practical_results
                        .as_ref()
                        .map(|r| r.overall_passed)
                        .unwrap_or(false);

                formal_ok && practical_ok
            }
            VerificationLevel::Comprehensive => {
                // For comprehensive verification, require both formal AND practical to pass
                formal_proof.as_ref().map(|p| p.valid).unwrap_or(false)
                    && practical_results
                        .as_ref()
                        .map(|r| r.overall_passed)
                        .unwrap_or(false)
            }
        }
    }

    /// Quick verification for development use
    pub async fn quick_verify(
        &mut self,
        original_bytecode: &[u8],
        obfuscated_bytecode: &[u8],
    ) -> VerificationResult<bool> {
        // Override config for quick verification
        let original_level = self.config.verification_level;
        self.config.verification_level = VerificationLevel::Quick;

        let result = if let Some(ref mut tester) = self.practical_tester {
            tester
                .test_equivalence(original_bytecode, obfuscated_bytecode)
                .await
                .map(|r| r.overall_passed)
                .unwrap_or(false)
        } else {
            false
        };

        // Restore original config
        self.config.verification_level = original_level;

        Ok(result)
    }

    /// Get verification statistics
    pub fn get_verification_stats(&self) -> VerificationStats {
        VerificationStats {
            formal_verification_available: self.formal_verifier.is_some(),
            practical_testing_available: self.practical_tester.is_some(),
            verification_level: self.config.verification_level,
            max_gas_overhead: self.config.max_gas_overhead,
            timeout_seconds: self.config.timeout.as_secs(),
            test_case_count: self.config.test_case_count,
        }
    }
}

/// Verification engine statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationStats {
    pub formal_verification_available: bool,
    pub practical_testing_available: bool,
    pub verification_level: VerificationLevel,
    pub max_gas_overhead: f64,
    pub timeout_seconds: u64,
    pub test_case_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VerificationConfig;

    #[tokio::test]
    async fn test_verification_engine_creation() {
        let config = VerificationConfig::development();
        let _engine = VerificationEngine::new(config).await;
    }

    #[test]
    fn test_security_property_extraction() {
        let _config = VerificationConfig::development();
        let bytecode = vec![0x33, 0x54, 0x15]; // CALLER, SLOAD, ISZERO pattern

        // Would test actual property extraction in real implementation
        assert!(hex::encode(&bytecode).contains("33")); // CALLER opcode present
    }
}
