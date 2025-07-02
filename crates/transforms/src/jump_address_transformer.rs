use crate::util::{PassConfig, Transform};
use async_trait::async_trait;
use bytecloak_core::cfg_ir::{Block, CfgIrBundle};
use bytecloak_core::decoder::Instruction;
use bytecloak_core::Opcode;
use bytecloak_utils::errors::TransformError;
use petgraph::graph::NodeIndex;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng};
use tracing::debug;

/// Jump Address Transformer obfuscates JUMP/JUMPI targets by splitting addresses
/// into arithmetic operations that compute the original target at runtime.
///
/// Instead of: PUSH1 0x42 JUMPI
/// Produces:   PUSH1 0x20 PUSH1 0x22 ADD JUMPI
/// Where 0x20 + 0x22 = 0x42
pub struct JumpAddressTransformer {
    config: PassConfig,
}

impl JumpAddressTransformer {
    pub fn new(config: PassConfig) -> Self {
        Self { config }
    }

    /// Finds PUSH + JUMP/JUMPI patterns and transforms them
    fn find_jump_patterns(&self, instructions: &[Instruction]) -> Vec<usize> {
        let mut patterns = Vec::new();

        for i in 0..instructions.len().saturating_sub(1) {
            if let (Some(push_instr), Some(jump_instr)) =
                (instructions.get(i), instructions.get(i + 1))
            {
                // Look for PUSH followed by JUMP or JUMPI
                if push_instr.opcode.starts_with("PUSH")
                    && (jump_instr.opcode == "JUMP" || jump_instr.opcode == "JUMPI")
                {
                    patterns.push(i);
                }
            }
        }

        patterns
    }

    /// Splits a jump target into two values that add up to the original
    fn split_jump_target(&self, target: u64, rng: &mut StdRng) -> (u64, u64) {
        // Generate a random value less than the target
        let split_point = if target > 1 {
            rng.random_range(1..target)
        } else {
            0
        };

        let part1 = split_point;
        let part2 = target - split_point;

        (part1, part2)
    }

    /// Determines the appropriate PUSH opcode size for a value
    fn get_push_opcode_for_value(&self, value: u64) -> String {
        let bytes_needed = if value == 0 {
            1
        } else {
            (64 - value.leading_zeros()).div_ceil(8) as usize
        };

        format!("PUSH{}", bytes_needed.max(1))
    }

    /// Formats a value as hex string with appropriate padding
    fn format_hex_value(&self, value: u64, bytes: usize) -> String {
        format!("{:0width$x}", value, width = bytes * 2)
    }
}

#[async_trait]
impl Transform for JumpAddressTransformer {
    fn name(&self) -> &'static str {
        "JumpAddressTransformer"
    }

    async fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError> {
        let mut changed = false;
        let mut transformations = Vec::new();

        // Process each block to find and transform jump patterns
        for node_idx in ir.cfg.node_indices().collect::<Vec<_>>() {
            if let Block::Body { instructions, .. } = &ir.cfg[node_idx] {
                let patterns = self.find_jump_patterns(instructions);

                if !patterns.is_empty() {
                    transformations.push((node_idx, patterns));
                }
            }
        }

        // Use config to limit the number of transformations
        let max_transforms = if transformations.is_empty() {
            0
        } else {
            let total_patterns: usize = transformations
                .iter()
                .map(|(_, patterns)| patterns.len())
                .sum();

            // Use max_size_delta as a ratio to control how many jumps to transform
            let transform_ratio = self.config.max_size_delta.clamp(0.0, 1.0);
            let max_count = ((total_patterns as f32) * transform_ratio).ceil() as usize;
            max_count.max(1) // Transform at least one if any exist
        };

        // Shuffle and limit transformations based on config
        if !transformations.is_empty() {
            // Flatten all patterns with their block indices
            let mut all_patterns: Vec<(NodeIndex, usize)> = Vec::new(); // (node_idx, pattern_idx)
            for (node_idx, patterns) in &transformations {
                for &pattern_idx in patterns {
                    all_patterns.push((*node_idx, pattern_idx));
                }
            }

            // Shuffle and limit
            all_patterns.shuffle(rng);
            all_patterns.truncate(max_transforms);

            // Rebuild transformations list with limited patterns
            let mut limited_transformations: Vec<(NodeIndex, Vec<usize>)> = Vec::new();
            for (node_idx, pattern_idx) in all_patterns {
                // Find or create entry for this node
                if let Some((_, patterns)) = limited_transformations
                    .iter_mut()
                    .find(|(idx, _)| *idx == node_idx)
                {
                    patterns.push(pattern_idx);
                } else {
                    limited_transformations.push((node_idx, vec![pattern_idx]));
                }
            }

            transformations = limited_transformations;
        }

        // Apply transformations (iterate in reverse to maintain indices)
        for (node_idx, patterns) in &transformations {
            if let Block::Body {
                instructions,
                max_stack,
                ..
            } = &mut ir.cfg[*node_idx]
            {
                // Process patterns in reverse order to maintain indices
                for &pattern_idx in patterns.iter().rev() {
                    if let Some(push_instr) = instructions.get(pattern_idx) {
                        if let Some(target_hex) = &push_instr.imm {
                            // Parse the jump target
                            if let Ok(target) = u64::from_str_radix(target_hex, 16) {
                                let (part1, part2) = self.split_jump_target(target, rng);

                                // Determine opcode sizes
                                let part1_opcode = self.get_push_opcode_for_value(part1);
                                let part2_opcode = self.get_push_opcode_for_value(part2);

                                // Calculate byte sizes for formatting
                                let part1_bytes = part1_opcode
                                    .strip_prefix("PUSH")
                                    .and_then(|s| s.parse::<usize>().ok())
                                    .unwrap_or(1);
                                let part2_bytes = part2_opcode
                                    .strip_prefix("PUSH")
                                    .and_then(|s| s.parse::<usize>().ok())
                                    .unwrap_or(1);

                                // Create new instruction sequence
                                let new_instructions = vec![
                                    Instruction {
                                        pc: push_instr.pc,
                                        opcode: part1_opcode,
                                        imm: Some(self.format_hex_value(part1, part1_bytes)),
                                    },
                                    Instruction {
                                        pc: push_instr.pc + part1_bytes + 1,
                                        opcode: part2_opcode,
                                        imm: Some(self.format_hex_value(part2, part2_bytes)),
                                    },
                                    Instruction {
                                        pc: push_instr.pc + part1_bytes + part2_bytes + 2,
                                        opcode: Opcode::ADD.to_string(),
                                        imm: None,
                                    },
                                ];

                                // Replace the original PUSH instruction with the sequence
                                instructions.remove(pattern_idx);
                                for (offset, new_instr) in new_instructions.into_iter().enumerate()
                                {
                                    instructions.insert(pattern_idx + offset, new_instr);
                                }

                                // Update max_stack if needed (we temporarily use one extra stack slot)
                                *max_stack = (*max_stack).max(2);
                                changed = true;

                                debug!(
                                    "Transformed jump target 0x{:x} into 0x{:x} + 0x{:x}",
                                    target, part1, part2
                                );
                            }
                        }
                    }
                }
            }
        }

        if changed {
            debug!(
                "Applied jump address transformation to {} patterns",
                transformations
                    .iter()
                    .map(|(_, patterns)| patterns.len())
                    .sum::<usize>()
            );
        }

        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecloak_core::{cfg_ir, decoder, detection, strip};
    use rand::SeedableRng;
    use tokio;

    #[tokio::test]
    async fn test_jump_address_transformer() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();

        // Simple bytecode with a conditional jump
        let bytecode = "0x60085760015b00"; // PUSH1 0x08, JUMPI, PUSH1 0x01, JUMPDEST, STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let mut cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report).unwrap();

        // Count instructions before transformation
        let mut instruction_count_before = 0;
        for node_idx in cfg_ir.cfg.node_indices() {
            if let bytecloak_core::cfg_ir::Block::Body { instructions, .. } = &cfg_ir.cfg[node_idx]
            {
                instruction_count_before += instructions.len();
            }
        }

        let mut rng = StdRng::seed_from_u64(42);

        // Use a config that allows the transformation
        let config = PassConfig {
            max_size_delta: 1.0, // Allow all jumps to be transformed
            ..Default::default()
        };
        let transform = JumpAddressTransformer::new(config);

        let changed = transform.apply(&mut cfg_ir, &mut rng).await.unwrap();
        assert!(changed, "JumpAddressTransformer should modify bytecode");

        // Count instructions after transformation
        let mut instruction_count_after = 0;
        for node_idx in cfg_ir.cfg.node_indices() {
            if let bytecloak_core::cfg_ir::Block::Body { instructions, .. } = &cfg_ir.cfg[node_idx]
            {
                instruction_count_after += instructions.len();
            }
        }

        // Should have more instructions after transformation
        assert!(
            instruction_count_after > instruction_count_before,
            "Instruction count should increase: before={}, after={}",
            instruction_count_before,
            instruction_count_after
        );

        // Verify we added exactly 2 more instructions (1 PUSH was replaced with 2 PUSH + 1 ADD = net +2)
        assert_eq!(
            instruction_count_after,
            instruction_count_before + 2,
            "Should add exactly 2 instructions"
        );
    }

    #[test]
    fn test_split_jump_target() {
        let mut rng = StdRng::seed_from_u64(42);
        let config = PassConfig::default();
        let transformer = JumpAddressTransformer::new(config);

        let target = 0x100;
        let (part1, part2) = transformer.split_jump_target(target, &mut rng);

        assert_eq!(
            part1 + part2,
            target,
            "Split parts should sum to original target"
        );
        assert!(part1 < target, "First part should be less than target");
        assert!(part1 > 0, "First part should be greater than 0");
    }

    #[test]
    fn test_push_opcode_sizing() {
        let config = PassConfig::default();
        let transformer = JumpAddressTransformer::new(config);

        assert_eq!(transformer.get_push_opcode_for_value(0x42), "PUSH1");
        assert_eq!(transformer.get_push_opcode_for_value(0x1234), "PUSH2");
        assert_eq!(transformer.get_push_opcode_for_value(0x123456), "PUSH3");
    }
}
