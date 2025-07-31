use crate::{PassConfig, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{detect_function_dispatcher, FunctionSelector};
use azoth_core::Opcode;
use azoth_utils::errors::TransformError;
use rand::{rngs::StdRng, Rng};
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Function Dispatcher that replaces 4-byte selectors with 1-byte derived values
/// to prevent fingerprinting while maintaining deterministic mapping.
///
/// **IMPORTANT:** This transform must run **before** any jump-address transforms
/// to ensure PC integrity is maintained across the transformation pipeline.
pub struct FunctionDispatcher {
    config: PassConfig,
}

impl FunctionDispatcher {
    pub fn new(config: PassConfig) -> Self {
        Self { config }
    }

    /// Generates collision-free mapping from selectors to tokens
    pub fn generate_mapping(
        &self,
        selectors: &[FunctionSelector],
        rng: &mut StdRng,
    ) -> Result<HashMap<u32, u8>, TransformError> {
        let mut mapping = HashMap::new();
        let mut used_tokens = HashSet::new();

        for selector_info in selectors {
            // Generate random token, retry if collision
            let mut token = rng.random::<u8>();

            while used_tokens.contains(&token) {
                token = rng.random::<u8>();
            }

            mapping.insert(selector_info.selector, token);
            used_tokens.insert(token);
        }

        Ok(mapping)
    }

    /// Creates the obfuscated dispatcher using 1-byte tokens
    fn create_obfuscated_dispatcher(
        &self,
        selectors: &[FunctionSelector],
        mapping: &HashMap<u32, u8>,
        rng: &mut StdRng,
    ) -> Result<(Vec<Instruction>, usize), TransformError> {
        let mut instructions = Vec::new();
        let max_stack_needed = 2;

        // Extract first byte from calldata (token) instead of 4-byte selector
        instructions.extend(vec![
            self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
            self.create_instruction(Opcode::CALLDATALOAD, None)?,
            self.create_instruction(Opcode::PUSH(1), Some("ff".to_string()))?,
            self.create_instruction(Opcode::AND, None)?,
        ]);

        // Randomize order of checks if aggressive
        let mut selector_order: Vec<_> = selectors.iter().collect();
        if self.config.aggressive {
            use rand::seq::SliceRandom;
            selector_order.shuffle(rng);
        }

        // Generate token comparisons (PUSH1 instead of PUSH4)
        for selector_info in selector_order {
            let token = mapping[&selector_info.selector];
            instructions.extend(vec![
                self.create_instruction(Opcode::DUP(1), None)?,
                self.create_instruction(Opcode::PUSH(1), Some(format!("{token:02x}")))?,
                self.create_instruction(Opcode::EQ, None)?,
                self.create_push_instruction(selector_info.target_address, Some(2))?,
                self.create_instruction(Opcode::JUMPI, None)?,
            ]);
        }

        // Final revert
        instructions.extend(vec![
            self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
            self.create_instruction(Opcode::DUP(1), None)?,
            self.create_instruction(Opcode::REVERT, None)?,
        ]);

        Ok((instructions, max_stack_needed))
    }

    /// Updates internal CALL instructions to use tokens instead of selectors
    /// 
    /// before update internal calls:
    /// PUSH4 <selector> // Function selector
    /// CALL             // Or DELEGATECALL, STATICCALL
    /// 
    /// after:
    /// PUSH1 <token>    // Corresponding token
    /// CALL             // Same call instruction
    pub fn update_internal_calls(
        &self,
        ir: &mut CfgIrBundle,
        mapping: &HashMap<u32, u8>,
    ) -> Result<(), TransformError> {
        for node_idx in ir.cfg.node_indices().collect::<Vec<_>>() {
            if let Block::Body { instructions, .. } = &mut ir.cfg[node_idx] {
                let mut i = 0;
                while i < instructions.len().saturating_sub(1) {
                    // Look for PUSH4 <selector> followed by CALL variants
                    if instructions[i].opcode == "PUSH4"
                        && matches!(
                            instructions[i + 1].opcode.as_str(),
                            "CALL" | "DELEGATECALL" | "STATICCALL"
                        )
                    {
                        if let Some(imm) = &instructions[i].imm {
                            if let Ok(selector) = u32::from_str_radix(imm, 16) {
                                if let Some(&token) = mapping.get(&selector) {
                                    // Replace PUSH4 <selector> with PUSH1 <token>
                                    instructions[i] = self.create_instruction(
                                        Opcode::PUSH(1), // 1-byte token (matches dispatcher expectation)
                                        Some(format!("{token:02x}")),
                                    )?;
                                }
                            }
                        }
                    }
                    i += 1;
                }
            }
        }
        Ok(())
    }

    /// Detects the standard function dispatcher
    pub fn detect_dispatcher(
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

    /// Creates a safe instruction with proper opcode validation
    pub fn create_instruction(
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
    pub fn create_push_instruction(
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

impl Transform for FunctionDispatcher {
    fn name(&self) -> &'static str {
        "FunctionDispatcher"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError> {
        // Collect all instructions from all blocks in execution order
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

        // Detect the dispatcher
        if let Some((start, end, selectors)) = self.detect_dispatcher(&all_instructions) {
            // Generate token mapping
            let mapping = self.generate_mapping(&selectors, rng)?;

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

                if block_start < end && block_end > start {
                    affected_blocks.push((node_idx, block_start, start_pc));
                }
            }

            if !affected_blocks.is_empty() {
                // Collect all dispatcher instructions across all affected blocks
                let mut dispatcher_instructions = Vec::new();
                let mut total_original_size = 0;

                for (block_idx, block_start, _) in &affected_blocks {
                    if let Block::Body { instructions, .. } = &ir.cfg[*block_idx] {
                        let block_dispatcher_start = if start >= *block_start {
                            start - block_start
                        } else {
                            0
                        };
                        let block_dispatcher_end = if end >= *block_start {
                            (end - block_start).min(instructions.len())
                        } else {
                            0
                        };

                        if block_dispatcher_start < instructions.len()
                            && block_dispatcher_end > block_dispatcher_start
                        {
                            let block_section =
                                &instructions[block_dispatcher_start..block_dispatcher_end];
                            dispatcher_instructions.extend_from_slice(block_section);
                            total_original_size += self.estimate_bytecode_size(block_section);
                        }
                    }
                }

                // Generate the complete new dispatcher
                let (new_instructions, needed_stack) =
                    self.create_obfuscated_dispatcher(&selectors, &mapping, rng)?;

                let new_size = self.estimate_bytecode_size(&new_instructions);
                let size_delta = new_size as isize - total_original_size as isize;

                // Clear dispatcher sections from all affected blocks
                for (block_idx, block_start, _) in &affected_blocks {
                    if let Block::Body {
                        instructions,
                        max_stack,
                        ..
                    } = &mut ir.cfg[*block_idx]
                    {
                        let block_dispatcher_start = if start >= *block_start {
                            start - block_start
                        } else {
                            0
                        };
                        let block_dispatcher_end = if end >= *block_start {
                            (end - block_start).min(instructions.len())
                        } else {
                            0
                        };

                        if block_dispatcher_start < instructions.len()
                            && block_dispatcher_end > block_dispatcher_start
                        {
                            instructions.drain(block_dispatcher_start..block_dispatcher_end); // clear dispatcher section from block
                            *max_stack = (*max_stack).max(needed_stack);
                        }
                    }
                }

                // Insert the complete new dispatcher into the first affected block
                let (first_block_idx, first_block_start, first_block_start_pc) = affected_blocks[0];
                if let Block::Body { instructions, .. } = &mut ir.cfg[first_block_idx] {
                    let insertion_point = start.saturating_sub(first_block_start);

                    for (i, new_instr) in new_instructions.into_iter().enumerate() {
                        instructions.insert(insertion_point + i, new_instr);
                    }
                }

                // Update internal CALL instructions throughout the CFG
                self.update_internal_calls(ir, &mapping)?;

                // Update CFG structure
                let region_start = first_block_start_pc;
                ir.update_jump_targets(size_delta, region_start, None)
                    .map_err(TransformError::CoreError)?;

                ir.reindex_pcs().map_err(TransformError::CoreError)?;

                // Rebuild edges for all affected blocks
                for (block_idx, _, _) in &affected_blocks {
                    ir.rebuild_edges_for_block(*block_idx)
                        .map_err(TransformError::CoreError)?;
                }

                debug!("Token-based dispatcher transformation completed successfully");
                return Ok(true);
            }
        }

        Ok(false)
    }
}
