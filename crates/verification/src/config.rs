//! Verification configuration and settings

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Verification configuration that controls how thorough the verification process is
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Level of verification to perform
    pub verification_level: VerificationLevel,
    
    /// Maximum acceptable gas overhead as a fraction (e.g., 0.15 = 15%)
    pub max_gas_overhead: f64,
    
    /// Timeout for the entire verification process
    pub timeout: Duration,
    
    /// Number of test cases to generate for practical testing
    pub test_case_count: usize,
    
    /// Whether to enable formal verification (requires SMT solver)
    pub formal_verification_enabled: bool,
    
    /// Whether to enable practical testing (requires EVM simulation)
    pub practical_testing_enabled: bool,
    
    /// Parallel execution settings
    pub parallelism: ParallelismConfig,
    
    /// SMT solver configuration
    pub smt_config: SmtConfig,
    
    /// EVM testing configuration
    pub evm_config: EvmConfig,
}

/// Different levels of verification thoroughness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// Quick verification for development (minimal testing)
    Quick,
    /// Standard verification for CI/CD (balanced)
    Standard,
    /// Comprehensive verification for production (exhaustive)
    Comprehensive,
}

/// Parallel execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelismConfig {
    /// Maximum number of concurrent verification tasks
    pub max_concurrent_tasks: usize,
    /// Whether to run formal and practical verification in parallel
    pub parallel_verification_types: bool,
}

/// SMT solver configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtConfig {
    /// Timeout for individual SMT queries
    pub query_timeout: Duration,
    /// Maximum memory usage for SMT solver (in MB)
    pub max_memory_mb: usize,
    /// Z3 specific parameters
    pub z3_params: Vec<(String, String)>,
}

/// EVM testing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmConfig {
    /// Gas limit for test transactions
    pub gas_limit: u64,
    /// Number of test accounts to create
    pub test_account_count: usize,
    /// Whether to use Anvil for more realistic testing
    pub use_anvil: bool,
    /// Random seed for deterministic test generation
    pub test_seed: u64,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self::standard()
    }
}

impl VerificationConfig {
    /// Quick verification configuration for development
    pub fn development() -> Self {
        Self {
            verification_level: VerificationLevel::Quick,
            max_gas_overhead: 0.20, // 20% overhead acceptable in dev
            timeout: Duration::from_secs(60),
            test_case_count: 10,
            formal_verification_enabled: false, // Skip formal in dev for speed
            practical_testing_enabled: true,
            parallelism: ParallelismConfig {
                max_concurrent_tasks: 2,
                parallel_verification_types: false,
            },
            smt_config: SmtConfig::default(),
            evm_config: EvmConfig {
                gas_limit: 10_000_000,
                test_account_count: 3,
                use_anvil: false, // Use REVM only for speed
                test_seed: 42,
            },
        }
    }
    
    /// Standard verification configuration for CI/CD
    pub fn standard() -> Self {
        Self {
            verification_level: VerificationLevel::Standard,
            max_gas_overhead: 0.15, // 15% overhead acceptable
            timeout: Duration::from_secs(300), // 5 minutes
            test_case_count: 100,
            formal_verification_enabled: true,
            practical_testing_enabled: true,
            parallelism: ParallelismConfig {
                max_concurrent_tasks: 4,
                parallel_verification_types: true,
            },
            smt_config: SmtConfig::default(),
            evm_config: EvmConfig {
                gas_limit: 30_000_000,
                test_account_count: 5,
                use_anvil: false, // REVM is faster for CI
                test_seed: 12345,
            },
        }
    }
    
    /// Comprehensive verification configuration for production
    pub fn production() -> Self {
        Self {
            verification_level: VerificationLevel::Comprehensive,
            max_gas_overhead: 0.15, // Strict 15% limit for production
            timeout: Duration::from_secs(1800), // 30 minutes
            test_case_count: 1000,
            formal_verification_enabled: true,
            practical_testing_enabled: true,
            parallelism: ParallelismConfig {
                max_concurrent_tasks: 8,
                parallel_verification_types: true,
            },
            smt_config: SmtConfig {
                query_timeout: Duration::from_secs(300),
                max_memory_mb: 8192, // 8GB for complex proofs
                z3_params: vec![
                    ("timeout".to_string(), "300000".to_string()),
                    ("memory_max_size".to_string(), "8192".to_string()),
                ],
            },
            evm_config: EvmConfig {
                gas_limit: 50_000_000,
                test_account_count: 10,
                use_anvil: true, // Use Anvil for most realistic testing
                test_seed: 98765,
            },
        }
    }
    
    /// Custom configuration for Mirage Protocol
    pub fn mirage_protocol() -> Self {
        Self {
            verification_level: VerificationLevel::Comprehensive,
            max_gas_overhead: 0.15, // Critical for Mirage gas efficiency
            timeout: Duration::from_secs(600), // 10 minutes
            test_case_count: 500,
            formal_verification_enabled: true, // Essential for privacy protocol
            practical_testing_enabled: true,
            parallelism: ParallelismConfig {
                max_concurrent_tasks: 6,
                parallel_verification_types: true,
            },
            smt_config: SmtConfig {
                query_timeout: Duration::from_secs(180),
                max_memory_mb: 4096,
                z3_params: vec![
                    ("timeout".to_string(), "180000".to_string()),
                    ("sat.random_seed".to_string(), "42".to_string()),
                ],
            },
            evm_config: EvmConfig {
                gas_limit: 30_000_000,
                test_account_count: 8,
                use_anvil: true,
                test_seed: 31337, // Ethereum development tradition
            },
        }
    }
    
    /// Validate configuration parameters
    pub fn validate(&self) -> Result<(), crate::VerificationError> {
        if self.max_gas_overhead < 0.0 || self.max_gas_overhead > 1.0 {
            return Err(crate::VerificationError::Configuration(
                "max_gas_overhead must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if self.test_case_count == 0 {
            return Err(crate::VerificationError::Configuration(
                "test_case_count must be greater than 0".to_string()
            ));
        }
        
        if !self.formal_verification_enabled && !self.practical_testing_enabled {
            return Err(crate::VerificationError::Configuration(
                "At least one verification method must be enabled".to_string()
            ));
        }
        
        if self.parallelism.max_concurrent_tasks == 0 {
            return Err(crate::VerificationError::Configuration(
                "max_concurrent_tasks must be greater than 0".to_string()
            ));
        }
        
        Ok(())
    }
}

impl Default for SmtConfig {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(60),
            max_memory_mb: 2048, // 2GB default
            z3_params: vec![
                ("timeout".to_string(), "60000".to_string()),
                ("model".to_string(), "true".to_string()),
                ("proof".to_string(), "true".to_string()),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_validation() {
        let mut config = VerificationConfig::development();
        assert!(config.validate().is_ok());
        
        // Test invalid gas overhead
        config.max_gas_overhead = -0.1;
        assert!(config.validate().is_err());
        
        config.max_gas_overhead = 1.5;
        assert!(config.validate().is_err());
        
        // Test zero test cases
        config.max_gas_overhead = 0.15;
        config.test_case_count = 0;
        assert!(config.validate().is_err());
        
        // Test no verification methods enabled
        config.test_case_count = 10;
        config.formal_verification_enabled = false;
        config.practical_testing_enabled = false;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_preset_configs() {
        assert!(VerificationConfig::development().validate().is_ok());
        assert!(VerificationConfig::standard().validate().is_ok());
        assert!(VerificationConfig::production().validate().is_ok());
        assert!(VerificationConfig::mirage_protocol().validate().is_ok());
    }
    
    #[test]
    fn test_verification_levels() {
        let dev = VerificationConfig::development();
        let std = VerificationConfig::standard();
        let prod = VerificationConfig::production();
        
        assert_eq!(dev.verification_level, VerificationLevel::Quick);
        assert_eq!(std.verification_level, VerificationLevel::Standard);
        assert_eq!(prod.verification_level, VerificationLevel::Comprehensive);
        
        // Production should have the most test cases
        assert!(prod.test_case_count > std.test_case_count);
        assert!(std.test_case_count > dev.test_case_count);
    }
}
