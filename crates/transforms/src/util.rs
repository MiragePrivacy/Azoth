use async_trait::async_trait;
use bytecloak_core::cfg_ir::CfgIrBundle;
use bytecloak_core::Opcode;
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
            aggressive: false,
            max_size_delta: 0.1,   // 10% size increase limit
            max_opaque_ratio: 0.2, // Apply to 20% of blocks max
        }
    }
}

/// Parses a PUSH opcode string and returns the corresponding Opcode enum and immediate size.
///
/// This helper function centralizes the parsing of PUSH opcodes (PUSH1-PUSH32) and eliminates
/// repetitive matching patterns throughout the transforms codebase.
///
/// # Arguments
/// * `opcode_str` - The opcode string (e.g., "PUSH1", "PUSH32")
///
/// # Returns
/// * `Some((Opcode, usize))` - The parsed opcode and its immediate size (1-32 bytes)
/// * `None` - If the input is not a valid PUSH opcode
///
/// # Examples
/// ```
/// use bytecloak_transform::util::parse_push_opcode;
///
/// assert_eq!(parse_push_opcode("PUSH1").unwrap().1, 1);
/// assert_eq!(parse_push_opcode("PUSH32").unwrap().1, 32);
/// assert!(parse_push_opcode("PUSH0").is_none());
/// assert!(parse_push_opcode("PUSH33").is_none());
/// assert!(parse_push_opcode("ADD").is_none());
/// ```
pub fn parse_push_opcode(opcode_str: &str) -> Option<(Opcode, usize)> {
    if let Some(push_num_str) = opcode_str.strip_prefix("PUSH") {
        if let Ok(push_num) = push_num_str.parse::<u8>() {
            if push_num >= 1 && push_num <= 32 {
                let opcode_byte = 0x60 + (push_num - 1);
                return Some(Opcode::parse(opcode_byte));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_push_opcode() {
        // Valid PUSH opcodes
        assert_eq!(parse_push_opcode("PUSH1").unwrap().1, 1);
        assert_eq!(parse_push_opcode("PUSH2").unwrap().1, 2);
        assert_eq!(parse_push_opcode("PUSH16").unwrap().1, 16);
        assert_eq!(parse_push_opcode("PUSH32").unwrap().1, 32);

        // Invalid PUSH opcodes
        assert!(parse_push_opcode("PUSH0").is_none());
        assert!(parse_push_opcode("PUSH33").is_none());
        assert!(parse_push_opcode("PUSH").is_none());
        assert!(parse_push_opcode("PUSHx").is_none());

        // Non-PUSH opcodes
        assert!(parse_push_opcode("ADD").is_none());
        assert!(parse_push_opcode("JUMP").is_none());
        assert!(parse_push_opcode("STOP").is_none());
        assert!(parse_push_opcode("").is_none());
    }
}
