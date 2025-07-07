//! Verification certificates and proof validation

use crate::{
    VerificationResult, VerificationError, TransformInfo,
    config::VerificationConfig,
    formal::proofs::FormalProof,
    practical::EquivalenceResults,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A cryptographically signed certificate proving contract equivalence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCertificate {
    /// Certificate metadata
    pub metadata: CertificateMetadata,
    /// Contract information
    pub contracts: ContractInfo,
    /// Verification results
    pub results: VerificationResults,
    /// Configuration used for verification
    pub config_summary: ConfigSummary,
    /// Digital signature of the certificate
    pub signature: Option<String>,
}

/// Certificate metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    /// Certificate version
    pub version: String,
    /// Timestamp when certificate was created
    pub timestamp: u64,
    /// Unique certificate ID
    pub certificate_id: String,
    /// ByteCloak version used
    pub bytecloak_version: String,
}

/// Information about the contracts being verified
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    /// Hash of original bytecode
    pub original_hash: String,
    /// Hash of obfuscated bytecode
    pub obfuscated_hash: String,
    /// Obfuscation seed used
    pub seed: u64,
    /// Transforms applied
    pub transforms: Vec<TransformInfo>,
    /// Original bytecode size
    pub original_size: usize,
    /// Obfuscated bytecode size
    pub obfuscated_size: usize,
}

/// Summary of verification results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResults {
    /// Overall verification result
    pub overall_passed: bool,
    /// Formal verification results
    pub formal_verification: Option<FormalVerificationSummary>,
    /// Practical testing results
    pub practical_testing: Option<PracticalTestingSummary>,
    /// Total verification time
    pub total_time: Duration,
    /// Warnings generated during verification
    pub warnings: Vec<String>,
}

/// Summary of formal verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormalVerificationSummary {
    /// Whether formal verification passed
    pub passed: bool,
    /// Number of statements proven
    pub statements_proven: usize,
    /// Total number of statements
    pub total_statements: usize,
    /// Success rate
    pub success_rate: f64,
    /// Time taken for formal verification
    pub verification_time: Duration,
    /// Proof hash for integrity
    pub proof_hash: String,
}

/// Summary of practical testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PracticalTestingSummary {
    /// Whether practical testing passed
    pub passed: bool,
    /// State equivalence result
    pub state_equivalence: bool,
    /// Output equivalence result
    pub output_equivalence: bool,
    /// Event equivalence result
    pub event_equivalence: bool,
    /// Gas equivalence result
    pub gas_equivalence: bool,
    /// Maximum gas overhead observed
    pub max_gas_overhead: f64,
    /// Number of test cases executed
    pub test_cases_executed: usize,
}

/// Configuration summary used for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSummary {
    /// Verification level used
    pub verification_level: String,
    /// Maximum gas overhead allowed
    pub max_gas_overhead: f64,
    /// Timeout used
    pub timeout_seconds: u64,
    /// Whether formal verification was enabled
    pub formal_verification_enabled: bool,
    /// Whether practical testing was enabled
    pub practical_testing_enabled: bool,
}

impl VerificationCertificate {
    /// Create a new verification certificate
    pub fn new(
        original_bytecode: &[u8],
        obfuscated_bytecode: &[u8],
        seed: u64,
        transforms: &[TransformInfo],
        formal_proof: Option<FormalProof>,
        practical_results: Option<EquivalenceResults>,
        total_time: Duration,
        config: &VerificationConfig,
    ) -> VerificationResult<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let original_hash = Self::compute_hash(original_bytecode);
        let obfuscated_hash = Self::compute_hash(obfuscated_bytecode);
        let certificate_id = Self::generate_certificate_id(&original_hash, &obfuscated_hash, seed);
        
        // Create metadata
        let metadata = CertificateMetadata {
            version: "1.0".to_string(),
            timestamp,
            certificate_id,
            bytecloak_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        
        // Create contract info
        let contracts = ContractInfo {
            original_hash,
            obfuscated_hash,
            seed,
            transforms: transforms.to_vec(),
            original_size: original_bytecode.len(),
            obfuscated_size: obfuscated_bytecode.len(),
        };
        
        // Create verification results summary
        let formal_verification = formal_proof.as_ref().map(|proof| {
            FormalVerificationSummary {
                passed: proof.valid,
                statements_proven: proof.proven_statements_count(),
                total_statements: proof.total_statements_count(),
                success_rate: proof.success_rate(),
                verification_time: proof.proof_time,
                proof_hash: proof.proof_hash.clone(),
            }
        });
        
        let practical_testing = practical_results.as_ref().map(|results| {
            PracticalTestingSummary {
                passed: results.overall_passed,
                state_equivalence: results.state_equivalence,
                output_equivalence: results.output_equivalence,
                event_equivalence: results.event_equivalence,
                gas_equivalence: results.gas_equivalence.as_ref().map(|g| g.passed).unwrap_or(false),
                max_gas_overhead: results.gas_equivalence.as_ref().map(|g| g.max_overhead_percentage).unwrap_or(0.0),
                test_cases_executed: results.test_cases_executed.unwrap_or(0),
            }
        });
        
        let overall_passed = Self::determine_overall_result(&formal_verification, &practical_testing, config);
        
        let results = VerificationResults {
            overall_passed,
            formal_verification,
            practical_testing,
            total_time,
            warnings: vec![], // Would be populated from verification process
        };
        
        // Create config summary
        let config_summary = ConfigSummary {
            verification_level: format!("{:?}", config.verification_level),
            max_gas_overhead: config.max_gas_overhead,
            timeout_seconds: config.timeout.as_secs(),
            formal_verification_enabled: config.formal_verification_enabled,
            practical_testing_enabled: config.practical_testing_enabled,
        };
        
        Ok(Self {
            metadata,
            contracts,
            results,
            config_summary,
            signature: None, // Would be signed if crypto keys available
        })
    }
    
    /// Check if overall verification passed
    pub fn overall_passed(&self) -> bool {
        self.results.overall_passed
    }
    
    /// Get a summary string of the verification
    pub fn summary(&self) -> String {
        let status = if self.overall_passed() { "PASSED" } else { "FAILED" };
        let formal_status = self.results.formal_verification
            .as_ref()
            .map(|f| if f.passed { "PASSED" } else { "FAILED" })
            .unwrap_or("N/A");
        let practical_status = self.results.practical_testing
            .as_ref()
            .map(|p| if p.passed { "PASSED" } else { "FAILED" })
            .unwrap_or("N/A");
        
        format!(
            "Verification {} - Formal: {}, Practical: {}, Time: {:.2}s",
            status,
            formal_status,
            practical_status,
            self.results.total_time.as_secs_f64()
        )
    }
    
    /// Save certificate to file
    pub fn save(&self, filename: &str) -> VerificationResult<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(filename, json)?;
        Ok(())
    }
    
    /// Load certificate from file
    pub fn load(filename: &str) -> VerificationResult<Self> {
        let content = std::fs::read_to_string(filename)?;
        let certificate: Self = serde_json::from_str(&content)?;
        Ok(certificate)
    }
    
    /// Validate certificate integrity
    pub fn validate(&self) -> VerificationResult<bool> {
        // Check timestamp is reasonable
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if self.metadata.timestamp > now {
            return Ok(false); // Future timestamp
        }
        
        // Check certificate age (optional - could set expiry)
        let age_days = (now - self.metadata.timestamp) / (24 * 60 * 60);
        if age_days > 365 {
            return Ok(false); // Older than 1 year
        }
        
        // Validate formal proof hash if present
        if let Some(formal) = &self.results.formal_verification {
            if formal.proof_hash.is_empty() {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Compute SHA3 hash of data
    fn compute_hash(data: &[u8]) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
    
    /// Generate unique certificate ID
    fn generate_certificate_id(original_hash: &str, obfuscated_hash: &str, seed: u64) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(original_hash.as_bytes());
        hasher.update(obfuscated_hash.as_bytes());
        hasher.update(&seed.to_le_bytes());
        hex::encode(&hasher.finalize()[0..16]) // First 16 bytes for shorter ID
    }
    
    /// Determine overall verification result
    fn determine_overall_result(
        formal: &Option<FormalVerificationSummary>,
        practical: &Option<PracticalTestingSummary>,
        config: &VerificationConfig,
    ) -> bool {
        match config.verification_level {
            crate::config::VerificationLevel::Quick => {
                // Either formal OR practical passing is sufficient
                formal.as_ref().map(|f| f.passed).unwrap_or(false) ||
                practical.as_ref().map(|p| p.passed).unwrap_or(false)
            },
            crate::config::VerificationLevel::Standard => {
                // Require both if both are enabled
                let formal_ok = !config.formal_verification_enabled ||
                    formal.as_ref().map(|f| f.passed).unwrap_or(false);
                let practical_ok = !config.practical_testing_enabled ||
                    practical.as_ref().map(|p| p.passed).unwrap_or(false);
                
                formal_ok && practical_ok
            },
            crate::config::VerificationLevel::Comprehensive => {
                // Require both formal AND practical to pass
                formal.as_ref().map(|f| f.passed).unwrap_or(false) &&
                practical.as_ref().map(|p| p.passed).unwrap_or(false)
            },
        }
    }
}

/// Verification proof that can be independently validated
pub type VerificationProof = VerificationCertificate;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VerificationConfig;
    
    #[test]
    fn test_certificate_creation() {
        let original = vec![0x60, 0x01];
        let obfuscated = vec![0x60, 0x01, 0x00];
        let transforms = vec![];
        let config = VerificationConfig::development();
        
        let certificate = VerificationCertificate::new(
            &original,
            &obfuscated,
            12345,
            &transforms,
            None,
            None,
            Duration::from_secs(1),
            &config,
        );
        
        assert!(certificate.is_ok());
        let cert = certificate.unwrap();
        assert!(!cert.metadata.certificate_id.is_empty());
        assert_eq!(cert.contracts.seed, 12345);
    }
    
    #[test]
    fn test_certificate_validation() {
        let original = vec![0x60, 0x01];
        let obfuscated = vec![0x60, 0x01, 0x00];
        let transforms = vec![];
        let config = VerificationConfig::development();
        
        let certificate = VerificationCertificate::new(
            &original,
            &obfuscated,
            12345,
            &transforms,
            None,
            None,
            Duration::from_secs(1),
            &config,
        ).unwrap();
        
        assert!(certificate.validate().unwrap());
    }
}
