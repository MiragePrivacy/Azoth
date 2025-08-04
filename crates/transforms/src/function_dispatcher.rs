use crate::{PassConfig, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{detect_function_dispatcher, FunctionSelector};
use azoth_core::Opcode;
use azoth_utils::errors::TransformError;
use rand::{rngs::StdRng, Rng};
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Function Dispatcher that replaces 4-byte selectors with variable-size tokens
/// and completely disguises the dispatcher pattern to prevent detection.
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

    /// Derives a cryptographically secure token from selector using keyed hash
    ///
    /// ```assembly
    /// selector: 0xa9059cbb
    /// secret: [random 32 bytes]
    /// keccak256(secret || 0xa9059cbb) = 0x8f3a2b1c9d...(`||` -> concatenate)
    /// token (2 bytes): [0x8f, 0x3a]
    /// ```
    fn derive_token(&self, selector: u32, secret: &[u8], token_size: usize) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(secret);
        hasher.update(selector.to_be_bytes());
        let hash = hasher.finalize();
        hash[..token_size.min(32)].to_vec()
    }

    /// Generates collision-free mapping from selectors to variable-size tokens
    ///
    /// before:
    /// ```assembly
    /// 0xa9059cbb → transfer(address,uint256)
    /// 0x7ff36ab5 → balanceOf(address)
    /// ```
    ///
    /// after:
    /// ```assembly
    /// 0xa9059cbb → [0x8f, 0x3a]    (2-byte token)
    /// 0x7ff36ab5 → [0x42]          (1-byte token)
    /// ```
    pub fn generate_mapping(
        &self,
        selectors: &[FunctionSelector],
        rng: &mut StdRng,
    ) -> Result<HashMap<u32, Vec<u8>>, TransformError> {
        let mut mapping = HashMap::new();
        let mut used_tokens = HashSet::new();

        // Generate random secret for this contract
        let secret: Vec<u8> = (0..32).map(|_| rng.random::<u8>()).collect();

        for selector_info in selectors {
            // Generate token with variable size (1-8 bytes)
            let token_size = rng.random_range(1..=8);
            let mut token = self.derive_token(selector_info.selector, &secret, token_size);

            // Handle collisions by tweaking secret slightly (more efficient)
            let mut attempt = 0;
            while used_tokens.contains(&token) && attempt < 100 {
                let mut new_secret = secret.clone();
                new_secret[0] = new_secret[0].wrapping_add(attempt as u8 + 1);
                token = self.derive_token(selector_info.selector, &new_secret, token_size);
                attempt += 1;
            }

            if attempt >= 100 {
                return Err(TransformError::Generic(
                    "Could not generate unique token after 100 attempts".to_string(),
                ));
            }

            mapping.insert(selector_info.selector, token.clone());
            used_tokens.insert(token.clone());

            debug!(
                "Generated {}-byte token mapping: 0x{:08x} → {:02x?}",
                token_size, selector_info.selector, token
            );
        }

        Ok(mapping)
    }

    /// Creates variable-size token extraction with universal dispatcher disguise
    ///
    /// Completely hides any dispatcher pattern by disguising calldata loading.
    /// Instead of obvious signatures, uses randomized mathematical operations:
    /// - Arithmetic disguises (SUB, XOR, ADD combinations)
    /// - Memory-based disguises (MSTORE/MLOAD patterns)
    /// - Complex multi-step calculations
    ///
    /// All disguises mathematically resolve to offset 0x00 for CALLDATALOAD.
    fn create_token_extraction(
        &self,
        max_token_size: usize,
        rng: &mut StdRng,
    ) -> Result<Vec<Instruction>, TransformError> {
        let mut instructions = Vec::new();

        // Phase 1: Disguised calldata offset calculation (always results in 0x00)
        let disguise_method = rng.random_range(0..6);

        match disguise_method {
            0 => {
                // SUB disguise: val - val = 0
                let val = rng.random_range(1..=255);
                instructions.extend(vec![
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val:02x}")))?,
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val:02x}")))?,
                    self.create_instruction(Opcode::SUB, None)?,
                ]);
                debug!("Using SUB disguise with value 0x{:02x}", val);
            }
            1 => {
                // XOR disguise: val ^ val = 0
                let val = rng.random_range(1..=255);
                instructions.extend(vec![
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val:02x}")))?,
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val:02x}")))?,
                    self.create_instruction(Opcode::XOR, None)?,
                ]);
                debug!("Using XOR disguise with value 0x{:02x}", val);
            }
            2 => {
                // Memory disguise: store 0, then load it
                let mem_offset = rng.random_range(0x20..=0x80); // Random memory slot
                instructions.extend(vec![
                    self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{mem_offset:02x}")))?,
                    self.create_instruction(Opcode::MSTORE, None)?,
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{mem_offset:02x}")))?,
                    self.create_instruction(Opcode::MLOAD, None)?,
                ]);
                debug!("Using memory disguise with offset 0x{:02x}", mem_offset);
            }
            4 => {
                // Modulo disguise: val % (val + 1) where val < val + 1 = val, then val - val = 0
                let val = rng.random_range(1..=200);
                let divisor = val + 1;
                instructions.extend(vec![
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val:02x}")))?,
                    self.create_instruction(Opcode::DUP(1), None)?, // duplicate val
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{divisor:02x}")))?,
                    self.create_instruction(Opcode::MOD, None)?, // val % (val + 1) = val
                    self.create_instruction(Opcode::SUB, None)?, // val - val = 0
                ]);
                debug!(
                    "Using modulo disguise with value 0x{:02x} % 0x{:02x}",
                    val, divisor
                );
            }
            _ => {
                // Multi-layer disguise: ((a * b) / b) - a = 0
                let val1 = rng.random_range(2..=50); // Avoid 0 and 1 for multiplication/division
                let val2 = rng.random_range(2..=50);
                instructions.extend(vec![
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val1:02x}")))?,
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val2:02x}")))?,
                    self.create_instruction(Opcode::MUL, None)?, // a * b
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val2:02x}")))?,
                    self.create_instruction(Opcode::DIV, None)?, // (a * b) / b = a
                    self.create_instruction(Opcode::PUSH(1), Some(format!("{val1:02x}")))?,
                    self.create_instruction(Opcode::SUB, None)?, // a - a = 0
                ]);
                debug!(
                    "Using multi-layer disguise with values 0x{:02x}, 0x{:02x}",
                    val1, val2
                );
            }
        }

        // Phase 2: Load calldata from calculated offset (always 0x00)
        instructions.push(self.create_instruction(Opcode::CALLDATALOAD, None)?);

        // Phase 3: Token extraction using variable-size mask
        //
        // The choice for `ffff`(or any other size it takes) isn't arbitrary, it's hexadecimal where f represents
        // the binary value `1111`
        // Input:  1010110101001101...  (calldata)
        // Mask:   111111111111111111111111  (ffffff)
        // AND:    1010110101001101...  (preserves first 24 bits)
        let mask = match max_token_size {
            1 => "ff",               // 1 byte:  0xFF
            2 => "ffff",             // 2 bytes: 0xFFFF
            3 => "ffffff",           // 3 bytes: 0xFFFFFF
            4 => "ffffffff",         // 4 bytes: 0xFFFFFFFF
            5 => "ffffffffff",       // 5 bytes: 0xFFFFFFFFFF
            6 => "ffffffffffff",     // 6 bytes: 0xFFFFFFFFFFFF
            7 => "ffffffffffffff",   // 7 bytes: 0xFFFFFFFFFFFFFF
            8 => "ffffffffffffffff", // 8 bytes: 0xFFFFFFFFFFFFFFFF
            _ => "ffffffffffffffff", // Default to 8 bytes max
        };

        let push_size = max_token_size.clamp(1, 8);

        // Phase 4: Apply mask to extract token
        instructions.extend(vec![
            self.create_instruction(Opcode::PUSH(push_size as u8), Some(mask.to_string()))?,
            self.create_instruction(Opcode::AND, None)?,
        ]);

        // Phase 5: Optional noise operations (Bernoulli trial)
        // we flip a biased coin that lands true with probability 0.3 (30 %) and false otherwise
        if rng.random_bool(0.3) {
            match rng.random_range(0..3) {
                0 => {
                    // DUP + POP = no-op
                    instructions.extend(vec![
                        self.create_instruction(Opcode::DUP(1), None)?,
                        self.create_instruction(Opcode::POP, None)?,
                    ]);
                    debug!("Added DUP+POP noise operations");
                }
                1 => {
                    // Add 0 = no-op
                    instructions.extend(vec![
                        self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
                        self.create_instruction(Opcode::ADD, None)?,
                    ]);
                    debug!("Added ADD 0 noise operations");
                }
                _ => {
                    // OR with 0 = no-op
                    instructions.extend(vec![
                        self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
                        self.create_instruction(Opcode::OR, None)?,
                    ]);
                    debug!("Added OR 0 noise operations");
                }
            }
        }

        debug!(
            "Created disguised token extraction with {} instructions",
            instructions.len()
        );
        Ok(instructions)
    }

    /// Creates the obfuscated dispatcher using variable-size tokens and disguised pattern
    fn create_obfuscated_dispatcher(
        &self,
        selectors: &[FunctionSelector],
        mapping: &HashMap<u32, Vec<u8>>,
        rng: &mut StdRng,
    ) -> Result<(Vec<Instruction>, usize), TransformError> {
        let mut instructions = Vec::new();
        let max_stack_needed = 3;

        // Phase 1: Disguised token extraction (completely hides dispatcher signature)
        let max_token_size = mapping.values().map(|token| token.len()).max().unwrap_or(1);
        instructions.extend(self.create_token_extraction(max_token_size, rng)?);

        // Phase 2: Token-based selector comparisons (shuffled order for additional obfuscation)
        let mut selector_order: Vec<_> = selectors.iter().collect();
        if self.config.aggressive {
            use rand::seq::SliceRandom;
            selector_order.shuffle(rng);
            debug!("Shuffled selector comparison order");
        }

        for selector_info in selector_order {
            if let Some(token) = mapping.get(&selector_info.selector) {
                instructions
                    .extend(self.create_token_comparison(token, selector_info.target_address)?);
            }
        }

        // Phase 3: Default case protection (prevents execution of random code)
        instructions.extend(vec![
            self.create_instruction(Opcode::PUSH(1), Some("00".to_string()))?,
            self.create_instruction(Opcode::DUP(1), None)?,
            self.create_instruction(Opcode::REVERT, None)?,
        ]);

        debug!(
            "Created complete obfuscated dispatcher with {} instructions",
            instructions.len()
        );
        Ok((instructions, max_stack_needed))
    }

    /// Creates token comparison sequence for variable-size tokens
    ///
    /// before:
    /// ```assembly
    /// DUP1                 // duplicate selector on stack
    /// PUSH4 0xa9059cbb     // push 4-byte selector to compare
    /// EQ                   // compare: stack_top == 0xa9059cbb
    /// PUSH2 0x001a         // target address if match
    /// JUMPI                // jump to function if equal
    /// ```
    ///
    /// after:
    /// ```assembly
    /// DUP1                 // duplicate token on stack
    /// PUSH2 0x8f3a         // push 2-byte derived token
    /// EQ                   // compare: stack_top == 0x8f3a
    /// PUSH2 0x001a         // same target address  
    /// JUMPI                // jump to function if equal
    /// ```
    fn create_token_comparison(
        &self,
        token: &[u8],
        target_address: u64,
    ) -> Result<Vec<Instruction>, TransformError> {
        let mut comparison = vec![self.create_instruction(Opcode::DUP(1), None)?];

        // Push token with appropriate size
        let push_size = token.len().clamp(1, 32);
        let token_hex = hex::encode(token);
        comparison.push(self.create_instruction(Opcode::PUSH(push_size as u8), Some(token_hex))?);

        comparison.extend(vec![
            self.create_instruction(Opcode::EQ, None)?,
            self.create_push_instruction(target_address, Some(2))?,
            self.create_instruction(Opcode::JUMPI, None)?,
        ]);

        Ok(comparison)
    }

    /// Updates internal CALL instructions to use tokens instead of selectors
    ///
    /// before update internal calls:
    /// ```assembly
    /// PUSH4 <selector> // Function selector
    /// CALL             // Or DELEGATECALL, STATICCALL
    /// ```
    /// after:
    /// ```assembly
    /// PUSH1/2/3 <token> // Variable-size corresponding token
    /// CALL              // Same call instruction
    /// ```
    pub fn update_internal_calls(
        &self,
        ir: &mut CfgIrBundle,
        mapping: &HashMap<u32, Vec<u8>>,
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
                                if let Some(token) = mapping.get(&selector) {
                                    // Replace PUSH4 <selector> with PUSH(n) <token>
                                    let token_size = token.len().clamp(1, 32);
                                    let token_hex = hex::encode(token);
                                    instructions[i] = self.create_instruction(
                                        Opcode::PUSH(token_size as u8),
                                        Some(token_hex),
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

    /// Detects any standard function dispatcher pattern
    pub fn detect_dispatcher(
        &self,
        instructions: &[Instruction],
    ) -> Option<(usize, usize, Vec<FunctionSelector>)> {
        if let Some(dispatcher_info) = detect_function_dispatcher(instructions) {
            debug!(
                "Detected dispatcher: {} selectors, pattern: {:?}",
                dispatcher_info.selectors.len(),
                dispatcher_info.extraction_pattern
            );
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

        debug!(
            "Analyzing {} instructions across {} blocks",
            all_instructions.len(),
            block_boundaries.len()
        );

        // Detect any dispatcher pattern (works for all types: Standard, Alternative, Newer, etc.)
        if let Some((start, end, selectors)) = self.detect_dispatcher(&all_instructions) {
            debug!(
                "Found dispatcher at offset {}..{} with {} selectors",
                start,
                end,
                selectors.len()
            );

            // Generate cryptographically secure token mapping
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
                debug!("Dispatcher spans {} blocks", affected_blocks.len());

                // Calculate original dispatcher size
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
                            total_original_size += self.estimate_bytecode_size(block_section);
                        }
                    }
                }

                // Generate the complete disguised dispatcher
                let (new_instructions, needed_stack) =
                    self.create_obfuscated_dispatcher(&selectors, &mapping, rng)?;

                let new_size = self.estimate_bytecode_size(&new_instructions);
                let size_delta = new_size as isize - total_original_size as isize;

                debug!(
                    "Dispatcher transformation: {} → {} bytes (Δ{:+})",
                    total_original_size, new_size, size_delta
                );

                // Clear original dispatcher sections from all affected blocks
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
                            instructions.drain(block_dispatcher_start..block_dispatcher_end);
                            *max_stack = (*max_stack).max(needed_stack);
                        }
                    }
                }

                // Insert the disguised dispatcher into the first affected block
                let (first_block_idx, first_block_start, first_block_start_pc) = affected_blocks[0];
                if let Block::Body { instructions, .. } = &mut ir.cfg[first_block_idx] {
                    let insertion_point = start.saturating_sub(first_block_start);

                    for (i, new_instr) in new_instructions.into_iter().enumerate() {
                        instructions.insert(insertion_point + i, new_instr);
                    }
                }

                // Update any internal CALL instructions to use tokens
                self.update_internal_calls(ir, &mapping)?;

                // Update CFG structure and addresses
                let region_start = first_block_start_pc;
                ir.update_jump_targets(size_delta, region_start, None)
                    .map_err(TransformError::CoreError)?;

                ir.reindex_pcs().map_err(TransformError::CoreError)?;

                // Rebuild edges for all affected blocks
                for (block_idx, _, _) in &affected_blocks {
                    ir.rebuild_edges_for_block(*block_idx)
                        .map_err(TransformError::CoreError)?;
                }

                // Store the mapping in the CFG bundle for potential future use
                ir.selector_mapping = Some(mapping);

                return Ok(true);
            }
        } else {
            debug!("No dispatcher pattern detected - skipping transformation");
        }

        Ok(false)
    }
}
