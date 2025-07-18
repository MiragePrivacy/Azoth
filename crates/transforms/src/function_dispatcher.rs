use crate::{PassConfig, Transform};
use async_trait::async_trait;
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{detect_function_dispatcher, FunctionSelector};
use azoth_core::Opcode;
use azoth_utils::errors::TransformError;
use rand::{rngs::StdRng, Rng};
use std::collections::HashSet;
use tracing::debug;

/// Function Dispatcher obfuscates the standard Solidity function dispatcher pattern
/// to prevent fingerprinting and detection of azoth-generated contracts.
///
/// **IMPORTANT:** This transform must run **before** any jump-address transforms
/// to ensure PC integrity is maintained across the transformation pipeline.
///
/// The standard dispatcher pattern:
/// 1. PUSH1 0x00 CALLDATALOAD PUSH1 0xE0 SHR  // Extract function selector
/// 2. DUP1 PUSH4 <selector1> EQ PUSH2 <addr1> JUMPI  // Check each function
/// 3. DUP1 PUSH4 <selector2> EQ PUSH2 <addr2> JUMPI
/// 4. ... (repeat for each function)
/// 5. REVERT  // Default case
///
/// This transform randomizes:
/// - Order of function checks
/// - Introduces dummy comparisons
/// - Uses different comparison patterns
/// - Adds arithmetic obfuscation to selectors
/// - Inserts dead code branches
pub struct FunctionDispatcher {
    config: PassConfig,
}

#[derive(Debug, Clone)]
enum DispatcherPattern {
    Standard,   // DUP1 PUSH4 selector EQ PUSH2 addr JUMPI
    Arithmetic, // Transform selector with ADD/SUB/XOR
    Inverted,   // Use inequality checks with branching
    Cascaded,   // Multiple comparison layers
}

impl FunctionDispatcher {
    pub fn new(config: PassConfig) -> Self {
        Self { config }
    }

    /// Creates a safe instruction with proper opcode validation
    fn create_instruction(
        &self,
        opcode: Opcode,
        imm: Option<String>,
    ) -> Result<Instruction, TransformError> {
        Ok(Instruction {
            pc: 0, // Will be set during PC reindexing
            opcode: opcode.to_string(),
            imm,
        })
    }

    /// Creates a PUSH instruction with proper size validation
    fn create_push_instruction(
        &self,
        value: u64,
        target_bytes: Option<usize>,
    ) -> Result<Instruction, TransformError> {
        let bytes_needed = if value == 0 {
            1
        } else {
            (64 - value.leading_zeros()).div_ceil(8) as usize
        };

        let push_size = target_bytes.unwrap_or(bytes_needed).clamp(1, 32);
        let opcode = Opcode::PUSH(push_size as u8);
        let hex_value = format!("{:0width$x}", value, width = push_size * 2);

        self.create_instruction(opcode, Some(hex_value))
    }

    /// Detects the standard Solidity function dispatcher pattern using the detection module
    fn detect_dispatcher(
        &self,
        instructions: &[Instruction],
    ) -> Option<(usize, usize, Vec<FunctionSelector>)> {
        if let Some(dispatcher_info) = detect_function_dispatcher(instructions) {
            Some((
                dispatcher_info.start_offset,
                dispatcher_info.end_offset,
                dispatcher_info.selectors,
            ))
        } else {
            None
        }
    }

    /// Generates a dummy function selector that doesn't conflict with real ones
    /// Uses reservoir sampling to avoid infinite loops on large selector sets
    fn generate_dummy_selector(
        &self,
        real_selectors: &[FunctionSelector],
        rng: &mut StdRng,
    ) -> u32 {
        const MAX_TRIES: usize = 1000;
        let real_selector_set: HashSet<u32> = real_selectors.iter().map(|s| s.selector).collect();

        for _ in 0..MAX_TRIES {
            let dummy = rng.random::<u32>();
            if !real_selector_set.contains(&dummy) {
                return dummy;
            }
        }

        // Fallback: use a deterministic approach if we can't find a random one
        let mut candidate = rng.random::<u32>();
        while real_selector_set.contains(&candidate) {
            candidate = candidate.wrapping_add(1);
        }
        candidate
    }

    /// Calculates the maximum stack depth needed for a pattern
    fn calculate_stack_depth(&self, pattern: &DispatcherPattern) -> usize {
        match pattern {
            DispatcherPattern::Standard => 2, // DUP1 pushes selector, max 2 words
            DispatcherPattern::Arithmetic => 3, // XOR operations need 3 words
            DispatcherPattern::Inverted => 3, // ISZERO and branching needs 3 words
            DispatcherPattern::Cascaded => 4, // AND operations with multiple values need 4 words
        }
    }

    /// Creates an obfuscated dispatcher using various patterns
    fn create_obfuscated_dispatcher(
        &self,
        mut selectors: Vec<FunctionSelector>,
        rng: &mut StdRng,
    ) -> Result<(Vec<Instruction>, usize), TransformError> {
        let mut instructions = Vec::new();
        let mut max_stack_needed = 1;

        // 1. Calldata extraction (randomize the approach)
        let extraction_variant = if self.config.aggressive {
            rng.random_range(0..3)
        } else {
            0 // Use standard pattern when not aggressive
        };
        match extraction_variant {
            0 => {
                // Standard: PUSH1 0x00 CALLDATALOAD PUSH1 0xE0 SHR
                instructions.extend(vec![
                    self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
                    self.create_instruction(Opcode::CALLDATALOAD, None)?,
                    self.create_instruction(Opcode::PUSH(1), Some("e0".to_string()))?,
                    self.create_instruction(Opcode::SHR, None)?,
                ]);
                max_stack_needed = max_stack_needed.max(2);
            }
            1 => {
                // Alternative: PUSH1 0x00 CALLDATALOAD PUSH29 0x0100...00 SHR
                instructions.extend(vec![
                    self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
                    self.create_instruction(Opcode::CALLDATALOAD, None)?,
                    self.create_instruction(
                        Opcode::PUSH(29),
                        Some(
                            "0100000000000000000000000000000000000000000000000000000000"
                                .to_string(),
                        ),
                    )?,
                    self.create_instruction(Opcode::SHR, None)?,
                ]);
                max_stack_needed = max_stack_needed.max(2);
            }
            _ => {
                // Arithmetic variant: CALLDATALOAD PUSH29 mask SHR
                instructions.extend(vec![
                    self.create_instruction(Opcode::CALLDATALOAD, None)?,
                    self.create_instruction(
                        Opcode::PUSH(29),
                        Some(
                            "0100000000000000000000000000000000000000000000000000000000"
                                .to_string(),
                        ),
                    )?,
                    self.create_instruction(Opcode::SHR, None)?,
                ]);
                max_stack_needed = max_stack_needed.max(2);
            }
        }

        // 2. Add dummy comparisons and randomize order
        let num_dummies = rng.random_range(1..=3);
        for _ in 0..num_dummies {
            let dummy_selector = self.generate_dummy_selector(&selectors, rng);
            selectors.push(FunctionSelector {
                selector: dummy_selector,
                target_address: 0, // Will jump to revert
                instruction_index: 0,
            });
        }

        // 3. Shuffle the order of checks
        use rand::seq::SliceRandom;
        selectors.shuffle(rng);

        // 4. Generate checks with different patterns
        for selector in &selectors {
            let pattern = match rng.random_range(0..4) {
                0 => DispatcherPattern::Standard,
                1 => DispatcherPattern::Arithmetic,
                2 => DispatcherPattern::Inverted,
                _ => DispatcherPattern::Cascaded,
            };

            let pattern_stack_depth = self.calculate_stack_depth(&pattern);
            max_stack_needed = max_stack_needed.max(pattern_stack_depth);

            let check_instructions = self.generate_selector_check(selector, &pattern, rng)?;
            instructions.extend(check_instructions);
        }

        // 5. Add final revert
        instructions.extend(vec![
            self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
            self.create_instruction(Opcode::DUP(1), None)?,
            self.create_instruction(Opcode::REVERT, None)?,
        ]);

        Ok((instructions, max_stack_needed))
    }

    /// Generates a selector check using the specified pattern
    fn generate_selector_check(
        &self,
        selector: &FunctionSelector,
        pattern: &DispatcherPattern,
        rng: &mut StdRng,
    ) -> Result<Vec<Instruction>, TransformError> {
        match pattern {
            DispatcherPattern::Standard => Ok(vec![
                self.create_instruction(Opcode::DUP(1), None)?,
                self.create_push_instruction(selector.selector as u64, Some(4))?,
                self.create_instruction(Opcode::EQ, None)?,
                self.create_push_instruction(selector.target_address, Some(2))?,
                self.create_instruction(Opcode::JUMPI, None)?,
            ]),
            DispatcherPattern::Arithmetic => {
                // Transform selector with arithmetic: (selector XOR key) XOR key == selector
                let key = rng.random::<u32>();
                let transformed = selector.selector ^ key;
                Ok(vec![
                    self.create_instruction(Opcode::DUP(1), None)?,
                    self.create_push_instruction(key as u64, Some(4))?,
                    self.create_instruction(Opcode::XOR, None)?,
                    self.create_push_instruction(transformed as u64, Some(4))?,
                    self.create_instruction(Opcode::EQ, None)?,
                    self.create_push_instruction(selector.target_address, Some(2))?,
                    self.create_instruction(Opcode::JUMPI, None)?,
                ])
            }
            DispatcherPattern::Inverted => {
                // Use NE and jump to next check instead of function
                Ok(vec![
                    self.create_instruction(Opcode::DUP(1), None)?,
                    self.create_push_instruction(selector.selector as u64, Some(4))?,
                    self.create_instruction(Opcode::EQ, None)?,
                    self.create_instruction(Opcode::ISZERO, None)?,
                    self.create_instruction(Opcode::PUSH(1), Some("20".to_string()))?, // Skip ahead (placeholder - will be fixed in PC reindexing)
                    self.create_instruction(Opcode::JUMPI, None)?,
                    self.create_push_instruction(selector.target_address, Some(2))?,
                    self.create_instruction(Opcode::JUMP, None)?,
                ])
            }
            DispatcherPattern::Cascaded => {
                // Multiple comparison layers
                let high_mask = selector.selector & 0xFFFF0000;
                let mask_value = 0xFFFF0000u32;
                Ok(vec![
                    self.create_instruction(Opcode::DUP(1), None)?,
                    self.create_push_instruction(high_mask as u64, Some(4))?,
                    self.create_instruction(Opcode::SWAP(1), None)?,
                    self.create_push_instruction(mask_value as u64, Some(4))?,
                    self.create_instruction(Opcode::AND, None)?,
                    self.create_instruction(Opcode::EQ, None)?,
                    self.create_instruction(Opcode::DUP(2), None)?,
                    self.create_push_instruction(selector.selector as u64, Some(4))?,
                    self.create_instruction(Opcode::EQ, None)?,
                    self.create_instruction(Opcode::AND, None)?,
                    self.create_push_instruction(selector.target_address, Some(2))?,
                    self.create_instruction(Opcode::JUMPI, None)?,
                ])
            }
        }
    }

    /// Estimates the byte size of instructions for size delta calculation
    fn estimate_bytecode_size(&self, instructions: &[Instruction]) -> usize {
        instructions
            .iter()
            .map(|instr| {
                if instr.opcode.starts_with("PUSH") {
                    if let Some(Ok(push_size)) = instr
                        .opcode
                        .strip_prefix("PUSH")
                        .map(|s| s.parse::<usize>())
                    {
                        1 + push_size
                    } else {
                        1
                    }
                } else {
                    1
                }
            })
            .sum()
    }
}

#[async_trait]
impl Transform for FunctionDispatcher {
    fn name(&self) -> &'static str {
        "FunctionDispatcher"
    }

    async fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError> {
        // First, collect all instructions from all blocks in execution order
        let mut all_instructions = Vec::new();
        let mut block_boundaries = Vec::new();

        for node_idx in ir.cfg.node_indices() {
            if let Block::Body {
                instructions,
                start_pc,
                ..
            } = &ir.cfg[node_idx]
            {
                block_boundaries.push((node_idx, all_instructions.len(), *start_pc));
                all_instructions.extend(instructions.clone());
            }
        }

        // Now detect dispatcher across all instructions
        if let Some((start, end, selectors)) = self.detect_dispatcher(&all_instructions) {
            debug!(
                "Found function dispatcher with {} selectors spanning instructions {} to {}",
                selectors.len(),
                start,
                end
            );

            // Find which blocks contain the dispatcher
            let mut affected_blocks = Vec::new();
            for (node_idx, block_start, start_pc) in block_boundaries {
                let block_instructions = if let Block::Body { instructions, .. } = &ir.cfg[node_idx]
                {
                    instructions.len()
                } else {
                    continue;
                };

                let block_end = block_start + block_instructions;

                // Check if this block overlaps with the dispatcher region
                if block_start < end && block_end > start {
                    affected_blocks.push((node_idx, block_start, start_pc));
                }
            }

            if !affected_blocks.is_empty() {
                let (first_block_idx, first_block_start, _) = affected_blocks[0];

                if let Block::Body {
                    instructions,
                    start_pc,
                    max_stack,
                } = &mut ir.cfg[first_block_idx]
                {
                    // Calculate relative positions within this block
                    let block_start_pos = start.saturating_sub(first_block_start);
                    let block_end_pos =
                        (end.saturating_sub(first_block_start)).min(instructions.len());

                    if block_start_pos < instructions.len() && block_end_pos > block_start_pos {
                        let original_size = self
                            .estimate_bytecode_size(&instructions[block_start_pos..block_end_pos]);
                        let (new_instructions, needed_stack) =
                            self.create_obfuscated_dispatcher(selectors, rng)?;
                        let new_size = self.estimate_bytecode_size(&new_instructions);
                        let size_delta = new_size as isize - original_size as isize;

                        // Replace the dispatcher section in this block
                        instructions.drain(block_start_pos..block_end_pos);

                        // Insert new instructions
                        for (i, new_instr) in new_instructions.clone().into_iter().enumerate() {
                            instructions.insert(block_start_pos + i, new_instr);
                        }

                        // Update max_stack
                        *max_stack = (*max_stack).max(needed_stack);

                        debug!(
                            "Replaced dispatcher in block {}: {} -> {} instructions, size delta: {:+} bytes",
                            first_block_idx.index(),
                            block_end_pos - block_start_pos,
                            new_instructions.len(),
                            size_delta
                        );

                        // Update CFG structure
                        let region_start = *start_pc + (block_start_pos * 2); // Rough PC estimate
                        ir.update_jump_targets(size_delta, region_start, None)
                            .map_err(TransformError::CoreError)?;

                        ir.reindex_pcs().map_err(TransformError::CoreError)?;

                        ir.rebuild_edges_for_block(first_block_idx)
                            .map_err(TransformError::CoreError)?;

                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obfuscator::obfuscate_bytecode;
    use crate::obfuscator::ObfuscationConfig;
    use azoth_core::{cfg_ir, decoder, detection, strip};
    use rand::SeedableRng;
    use tokio;

    /// Pretty-print dispatcher sections for debugging
    #[cfg(test)]
    fn print_dispatcher_section(instructions: &[Instruction], start: usize, end: usize) -> String {
        let mut result = String::new();
        for (i, instr) in instructions[start..end].iter().enumerate() {
            result.push_str(&format!(
                "{:3}: {} {}\n",
                start + i,
                instr.opcode,
                instr.imm.as_deref().unwrap_or("")
            ));
        }
        result
    }

    #[test]
    fn test_opcode_type_safety() {
        let config = PassConfig::default();
        let transform = FunctionDispatcher::new(config);

        // Test that we can create instructions safely using Opcode enum
        let push_instr = transform
            .create_instruction(Opcode::PUSH(1), Some("42".to_string()))
            .unwrap();
        assert_eq!(push_instr.opcode, "PUSH1");
        assert_eq!(push_instr.imm, Some("42".to_string()));

        let jump_instr = transform.create_instruction(Opcode::JUMP, None).unwrap();
        assert_eq!(jump_instr.opcode, "JUMP");
        assert_eq!(jump_instr.imm, None);

        // Test PUSH instruction creation with auto-sizing
        let push4_instr = transform
            .create_push_instruction(0x12345678, Some(4))
            .unwrap();
        assert_eq!(push4_instr.opcode, "PUSH4");
        assert_eq!(push4_instr.imm, Some("12345678".to_string()));

        // Test auto-sizing
        let auto_push_instr = transform.create_push_instruction(0x42, None).unwrap();
        assert_eq!(auto_push_instr.opcode, "PUSH1");
        assert_eq!(auto_push_instr.imm, Some("42".to_string()));
    }

    #[tokio::test]
    async fn test_dispatcher_detection() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();

        let config = PassConfig::default();
        let transform = FunctionDispatcher::new(config);

        let mut instructions = vec![
            // Calldata extraction
            transform
                .create_instruction(Opcode::PUSH(1), Some("00".to_string()))
                .unwrap(),
            transform
                .create_instruction(Opcode::CALLDATALOAD, None)
                .unwrap(),
            transform
                .create_instruction(Opcode::PUSH(1), Some("e0".to_string()))
                .unwrap(),
            transform.create_instruction(Opcode::SHR, None).unwrap(),
            // Function selector check 1
            transform.create_instruction(Opcode::DUP(1), None).unwrap(),
            transform
                .create_instruction(Opcode::PUSH(4), Some("c2985578".to_string()))
                .unwrap(),
            transform.create_instruction(Opcode::EQ, None).unwrap(),
            transform
                .create_instruction(Opcode::PUSH(2), Some("0080".to_string()))
                .unwrap(),
            transform.create_instruction(Opcode::JUMPI, None).unwrap(),
            // Function selector check 2
            transform.create_instruction(Opcode::DUP(1), None).unwrap(),
            transform
                .create_instruction(Opcode::PUSH(4), Some("12345678".to_string()))
                .unwrap(),
            transform.create_instruction(Opcode::EQ, None).unwrap(),
            transform
                .create_instruction(Opcode::PUSH(2), Some("0100".to_string()))
                .unwrap(),
            transform.create_instruction(Opcode::JUMPI, None).unwrap(),
            // Revert
            transform
                .create_instruction(Opcode::PUSH(1), Some("00".to_string()))
                .unwrap(),
            transform.create_instruction(Opcode::DUP(1), None).unwrap(),
            transform.create_instruction(Opcode::REVERT, None).unwrap(),
        ];

        // Set sequential PCs
        for (i, instr) in instructions.iter_mut().enumerate() {
            instr.pc = i * 2; // Simplified PC assignment
        }

        let detection_result = transform.detect_dispatcher(&instructions);
        assert!(detection_result.is_some());

        let (start, _end, selectors) = detection_result.unwrap();
        assert_eq!(start, 0);

        println!("Found {} selectors: {:?}", selectors.len(), selectors);
        assert_eq!(selectors.len(), 2);

        assert_eq!(selectors[0].selector, 0xc2985578);
        assert_eq!(selectors[1].selector, 0x12345678);

        println!("Original dispatcher:");
        println!(
            "{}",
            print_dispatcher_section(&instructions, start, instructions.len())
        );
    }

    #[test]
    fn test_dummy_selector_generation_safety() {
        let config = PassConfig::default();
        let transform = FunctionDispatcher::new(config);
        let mut rng = StdRng::seed_from_u64(42);

        let real_selectors = vec![
            FunctionSelector {
                selector: 0x12345678,
                target_address: 0x100,
                instruction_index: 0,
            },
            FunctionSelector {
                selector: 0x87654321,
                target_address: 0x200,
                instruction_index: 10,
            },
        ];

        // Should always succeed even with many existing selectors
        for _ in 0..100 {
            let dummy = transform.generate_dummy_selector(&real_selectors, &mut rng);
            assert_ne!(dummy, 0x12345678);
            assert_ne!(dummy, 0x87654321);
        }
    }

    #[test]
    fn test_stack_depth_calculation() {
        let config = PassConfig::default();
        let transform = FunctionDispatcher::new(config);

        assert_eq!(
            transform.calculate_stack_depth(&DispatcherPattern::Standard),
            2
        );
        assert_eq!(
            transform.calculate_stack_depth(&DispatcherPattern::Arithmetic),
            3
        );
        assert_eq!(
            transform.calculate_stack_depth(&DispatcherPattern::Inverted),
            3
        );
        assert_eq!(
            transform.calculate_stack_depth(&DispatcherPattern::Cascaded),
            4
        );
    }

    #[tokio::test]
    async fn test_pc_integrity_integration() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();

        // Create a simple bytecode with a dispatcher-like pattern
        let bytecode = "0x6000356020527f63c29855780817ffffffffffffffffffffffffffffffff5b";
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let mut cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report).unwrap();

        // Get original PC count
        let _original_total_size = cfg_ir
            .cfg
            .node_indices()
            .filter_map(|idx| {
                if let Block::Body { instructions, .. } = &cfg_ir.cfg[idx] {
                    Some(instructions.len())
                } else {
                    None
                }
            })
            .sum::<usize>();

        let config = PassConfig::default();
        let transform = FunctionDispatcher::new(config);
        let mut rng = StdRng::seed_from_u64(42);

        // Apply the transform
        let changed = transform.apply(&mut cfg_ir, &mut rng).await.unwrap();

        if changed {
            // Verify PC integrity after transformation
            let mut current_pc = 0;
            let mut all_pcs_sequential = true;

            // Check that PCs are sequential across all blocks
            for node_idx in cfg_ir.cfg.node_indices() {
                if let Block::Body {
                    instructions,
                    start_pc,
                    ..
                } = &cfg_ir.cfg[node_idx]
                {
                    if *start_pc != current_pc {
                        all_pcs_sequential = false;
                        break;
                    }

                    for instr in instructions {
                        if instr.pc != current_pc {
                            all_pcs_sequential = false;
                            break;
                        }
                        current_pc += if instr.opcode.starts_with("PUSH") {
                            if let Some(Ok(push_size)) = instr
                                .opcode
                                .strip_prefix("PUSH")
                                .and_then(|s| Some(s.parse::<usize>()))
                            {
                                1 + push_size
                            } else {
                                1
                            }
                        } else {
                            1
                        };
                    }

                    if !all_pcs_sequential {
                        break;
                    }
                }
            }

            assert!(
                all_pcs_sequential,
                "PCs should be sequential after reindexing"
            );

            // Verify pc_to_block mapping is consistent
            for (pc, &node_idx) in &cfg_ir.pc_to_block {
                if let Block::Body { start_pc, .. } = &cfg_ir.cfg[node_idx] {
                    assert_eq!(*pc, *start_pc, "pc_to_block mapping should be consistent");
                }
            }

            debug!("PC integrity verified after dispatcher transformation");
        }
    }

    #[tokio::test]
    async fn test_obfuscate_with_function_dispatcher() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init()
            .ok(); // Ignore if already initialized

        // Bytecode with function dispatcher pattern
        let bytecode = "0x60003580632e64cec114601757806360fe47b1146019575b005b00";
        let config = ObfuscationConfig::default();

        tracing::debug!("Testing bytecode: {}", bytecode);

        // Let's first decode and analyze the bytecode manually
        let (instructions, _, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        tracing::debug!("Decoded {} instructions", instructions.len());

        for (i, instr) in instructions.iter().enumerate() {
            tracing::debug!("  [{}] PC:{} {} {:?}", i, instr.pc, instr.opcode, instr.imm);
        }

        // Test dispatcher detection directly
        let dispatcher_detected = detection::has_dispatcher(&instructions);
        tracing::debug!("Dispatcher detected: {}", dispatcher_detected);

        if let Some(dispatcher_info) = detection::detect_function_dispatcher(&instructions) {
            tracing::debug!("Dispatcher info: {:?}", dispatcher_info);
        } else {
            tracing::debug!("No dispatcher info found");
        }

        let result = obfuscate_bytecode(bytecode, config).await.unwrap();

        tracing::debug!("Obfuscation result:");
        tracing::debug!("  Original: {}", bytecode);
        tracing::debug!("  Obfuscated: {}", result.obfuscated_bytecode);
        tracing::debug!(
            "  Transforms applied: {:?}",
            result.metadata.transforms_applied
        );
        tracing::debug!("  Instructions added: {}", result.instructions_added);
        tracing::debug!("  Blocks created: {}", result.blocks_created);

        // Should detect dispatcher and apply FunctionDispatcher transform
        assert!(
            result
                .metadata
                .transforms_applied
                .contains(&"FunctionDispatcher".to_string()),
            "FunctionDispatcher transform was not applied. Applied transforms: {:?}",
            result.metadata.transforms_applied
        );
        assert!(
            result.obfuscated_bytecode != bytecode,
            "Bytecode was not modified"
        );
        assert!(
            result.instructions_added > 0 || result.blocks_created > 0,
            "No instructions added or blocks created"
        );
    }
}
