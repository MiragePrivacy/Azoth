use crate::Opcode;
use crate::decoder::Instruction;

/// Represents a detected function dispatcher with its selectors and metadata.
#[derive(Debug, Clone)]
pub struct DispatcherInfo {
    /// Start offset of the dispatcher in the instruction sequence
    pub start_offset: usize,
    /// End offset of the dispatcher in the instruction sequence  
    pub end_offset: usize,
    /// List of detected function selectors
    pub selectors: Vec<FunctionSelector>,
    /// Type of calldata extraction pattern used
    pub extraction_pattern: ExtractionPattern,
}

/// Represents a function selector found in the dispatcher.
#[derive(Debug, Clone)]
pub struct FunctionSelector {
    /// 4-byte function selector (first 4 bytes of keccak256(function_signature))
    pub selector: u32,
    /// Target address to jump to when this selector matches
    pub target_address: u64,
    /// Index in the instruction sequence where this selector check begins
    pub instruction_index: usize,
}

/// Types of calldata extraction patterns used by Solidity compilers.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractionPattern {
    /// Standard: PUSH1 0x00 CALLDATALOAD PUSH1 0xE0 SHR
    Standard,
    /// Alternative: PUSH1 0x00 CALLDATALOAD PUSH29 ... SHR
    Alternative,
    /// Newer: CALLDATALOAD PUSH29 ... SHR (newer Solidity)
    Newer,
    /// Fallback: CALLDATASIZE ISZERO (fallback-only contracts)
    Fallback,
    /// Direct: PUSH1 0x00 CALLDATALOAD (no shift, direct comparison)
    Direct,
}

/// Detects Solidity function dispatcher patterns in the given instructions.
///
/// This function identifies the standard dispatcher pattern used by Solidity:
/// 1. Extract function selector from calldata
/// 2. Compare against known function selectors
/// 3. Jump to appropriate function or revert
///
/// # Arguments
/// * `instructions` - Decoded EVM instructions to analyze
///
/// # Returns
/// `Some(DispatcherInfo)` if a dispatcher is detected, `None` otherwise
///
/// # Examples
/// ```rust,ignore
/// let instructions = decode_contract_bytecode();
/// if let Some(dispatcher) = detect_function_dispatcher(&instructions) {
///     println!("Found dispatcher with {} selectors", dispatcher.selectors.len());
/// }
/// ```
pub fn detect_function_dispatcher(instructions: &[Instruction]) -> Option<DispatcherInfo> {
    // 1) Try the structured, AST-like detector first
    // Scan more aggressively to find dispatcher patterns
    let max_attempts = instructions.len().min(200); // Increased from 50

    for start_idx in (0..max_attempts).step_by(10) {
        if let Some(dispatcher) = try_detect_dispatcher_at(&instructions[start_idx..], start_idx) {
            return Some(dispatcher);
        }
    }

    // 2) If structured detection fails, try byte-pattern fallback
    if let Some(selectors) = try_byte_pattern_fallback(instructions) {
        // Find the first extraction pattern to set a reasonable start offset
        let start_offset = find_extraction_pattern_offset(instructions).unwrap_or(0);
        let end_offset = start_offset + 50; // Estimate end offset

        return Some(DispatcherInfo {
            start_offset,
            end_offset,
            selectors: selectors
                .into_iter()
                .enumerate()
                .map(|(i, sel)| FunctionSelector {
                    selector: sel,
                    target_address: 0,
                    instruction_index: i,
                })
                .collect(),
            extraction_pattern: ExtractionPattern::Standard,
        });
    }

    None
}

/// Find the offset of the first extraction pattern
fn find_extraction_pattern_offset(instructions: &[Instruction]) -> Option<usize> {
    for (i, window) in instructions.windows(4).enumerate() {
        if window[0].opcode == "PUSH1"
            && window[0].imm.as_deref() == Some("00")
            && window[1].opcode == "CALLDATALOAD"
            && window[2].opcode == "PUSH1"
            && window[2].imm.as_deref() == Some("e0")
            && window[3].opcode == "SHR"
        {
            return Some(i);
        }
    }

    // Also check for CALLDATALOAD PUSH1 e0 SHR pattern
    for (i, window) in instructions.windows(3).enumerate() {
        if window[0].opcode == "CALLDATALOAD"
            && window[1].opcode == "PUSH1"
            && window[1].imm.as_deref() == Some("e0")
            && window[2].opcode == "SHR"
        {
            return Some(i);
        }
    }
    None
}

/// Try to extract selectors using byte patterns from instructions
fn try_byte_pattern_fallback(instructions: &[Instruction]) -> Option<Vec<u32>> {
    let mut selectors = Vec::new();

    // First, find the dispatcher extraction pattern (look more broadly)
    let mut extraction_found = false;
    for i in 0..instructions.len().saturating_sub(5) {
        if (instructions[i].opcode == "PUSH1"
            && instructions[i].imm.as_deref() == Some("00")
            && instructions[i + 1].opcode == "CALLDATALOAD"
            && instructions[i + 2].opcode == "PUSH1"
            && instructions[i + 2].imm.as_deref() == Some("e0")
            && instructions[i + 3].opcode == "SHR")
            || (instructions[i].opcode == "CALLDATALOAD"
                && instructions[i + 1].opcode == "PUSH1"
                && instructions[i + 1].imm.as_deref() == Some("e0")
                && instructions[i + 2].opcode == "SHR")
        {
            tracing::debug!("Found extraction pattern at instruction {}", i);
            extraction_found = true;
            break;
        }
    }

    if !extraction_found {
        tracing::debug!("No extraction pattern found in byte fallback");
        return None;
    }

    // Now look for all PUSH4 instructions that could be selectors
    for (i, instr) in instructions.iter().enumerate() {
        if instr.opcode == "PUSH4"
            && let Some(selector_hex) = &instr.imm
            && let Ok(selector) = u32::from_str_radix(selector_hex, 16)
        {
            // Enhanced validation: look for EQ or GT instruction after PUSH4
            if i + 1 < instructions.len()
                && (instructions[i + 1].opcode == "EQ" || instructions[i + 1].opcode == "GT")
            {
                tracing::debug!(
                    "Found selector candidate 0x{:08x} at instruction {} (followed by {})",
                    selector,
                    i,
                    instructions[i + 1].opcode
                );
                selectors.push(selector);
            }
        }
    }

    tracing::debug!("Byte pattern fallback found {} selectors", selectors.len());

    if selectors.is_empty() {
        None
    } else {
        Some(selectors)
    }
}

/// Attempts to detect a dispatcher pattern starting at a specific position
fn try_detect_dispatcher_at(instrs: &[Instruction], base_offset: usize) -> Option<DispatcherInfo> {
    // Look for the core selector extraction pattern
    let mut extraction_start = None;
    let mut extraction_pattern = None;

    // Scan more instructions to find extraction pattern
    for i in 0..instrs.len().saturating_sub(3) {
        if let Some(pattern) = is_calldata_extraction_pattern(&instrs[i..]) {
            extraction_start = Some(i);
            extraction_pattern = Some(pattern.clone());
            tracing::debug!(
                "Found extraction pattern {:?} at base_offset {} + {}",
                pattern,
                base_offset,
                i
            );
            break;
        }
    }

    let start_idx = extraction_start?;
    let pattern = extraction_pattern?;

    // Skip past the extraction pattern
    let pattern_len = get_extraction_pattern_length(&instrs[start_idx..], &pattern)?;
    let mut current_idx = start_idx + pattern_len;

    let mut selectors = Vec::new();

    tracing::debug!("Starting selector search from instruction {}", current_idx);

    // Look for selector comparison blocks - scan the entire remaining slice
    while current_idx < instrs.len().saturating_sub(3) {
        if let Some(selector_info) = parse_selector_check(&instrs[current_idx..]) {
            selectors.push(FunctionSelector {
                selector: selector_info.0,
                target_address: selector_info.1,
                instruction_index: base_offset + current_idx,
            });

            tracing::debug!(
                "Found selector 0x{:08x} at instruction {}",
                selector_info.0,
                current_idx
            );

            // Move past this selector block
            current_idx += selector_info.2; // block length
        } else {
            // Look for PUSH4 instructions that might be selectors
            if current_idx < instrs.len()
                && instrs[current_idx].opcode == "PUSH4"
                && let Some(selector_hex) = &instrs[current_idx].imm
                && let Ok(selector) = u32::from_str_radix(selector_hex, 16)
            {
                // Check if this looks like a selector (followed by EQ or GT)
                if current_idx + 1 < instrs.len()
                    && (instrs[current_idx + 1].opcode == "EQ"
                        || instrs[current_idx + 1].opcode == "GT")
                {
                    selectors.push(FunctionSelector {
                        selector,
                        target_address: 0, // Unknown
                        instruction_index: base_offset + current_idx,
                    });
                    tracing::debug!(
                        "Found loose selector 0x{:08x} at instruction {} (followed by {})",
                        selector,
                        current_idx,
                        instrs[current_idx + 1].opcode
                    );
                    current_idx += 2; // Skip PUSH4 + EQ/GT
                    continue;
                }
            }

            current_idx += 1;
        }

        // Safety check to avoid infinite loops
        if current_idx >= instrs.len() {
            break;
        }
    }

    tracing::debug!("Structured detection found {} selectors", selectors.len());

    if !selectors.is_empty() {
        Some(DispatcherInfo {
            start_offset: base_offset + start_idx,
            end_offset: base_offset + current_idx,
            selectors,
            extraction_pattern: pattern,
        })
    } else {
        None
    }
}

/// Checks if the instruction sequence matches a known calldata extraction pattern.
///
/// Identifies the various patterns used by different Solidity compiler versions
/// to extract the 4-byte function selector from calldata.
///
/// # Arguments
/// * `instrs` - Instruction sequence to check (should start at potential pattern)
///
/// # Returns
/// `Some(ExtractionPattern)` if a pattern is detected, `None` otherwise
pub fn is_calldata_extraction_pattern(instrs: &[Instruction]) -> Option<ExtractionPattern> {
    if instrs.len() < 2 {
        return None;
    }

    // Pattern 1: [PUSH1 0x00 | PUSH0] CALLDATALOAD PUSH1 0xE0 SHR
    if instrs.len() >= 4
        && ((instrs[0].opcode == Opcode::PUSH(1).to_string()
            && instrs[0].imm.as_deref() == Some("00"))
            || instrs[0].opcode == Opcode::PUSH(0).to_string())
        && instrs[1].opcode == Opcode::CALLDATALOAD.to_string()
        && instrs[2].opcode == Opcode::PUSH(1).to_string()
        && instrs[2].imm.as_deref() == Some("e0")
        && instrs[3].opcode == Opcode::SHR.to_string()
    {
        return Some(ExtractionPattern::Standard);
    }

    // Pattern 2: [PUSH1 0x00 | PUSH0] CALLDATALOAD PUSH29 ... SHR
    if instrs.len() >= 4
        && ((instrs[0].opcode == Opcode::PUSH(1).to_string()
            && instrs[0].imm.as_deref() == Some("00"))
            || instrs[0].opcode == Opcode::PUSH(0).to_string())
        && instrs[1].opcode == Opcode::CALLDATALOAD.to_string()
        && instrs[2].opcode == Opcode::PUSH(29).to_string()
        && instrs[3].opcode == Opcode::SHR.to_string()
    {
        return Some(ExtractionPattern::Alternative);
    }

    // Pattern 3: CALLDATALOAD PUSH1 0xE0 SHR (newer Solidity - corrected)
    if instrs.len() >= 3
        && instrs[0].opcode == Opcode::CALLDATALOAD.to_string()
        && instrs[1].opcode == Opcode::PUSH(1).to_string()
        && instrs[1].imm.as_deref() == Some("e0")
        && instrs[2].opcode == Opcode::SHR.to_string()
    {
        return Some(ExtractionPattern::Newer);
    }

    // Pattern 4: CALLDATALOAD PUSH29 ... SHR (original newer pattern)
    if instrs.len() >= 3
        && instrs[0].opcode == Opcode::CALLDATALOAD.to_string()
        && instrs[1].opcode == Opcode::PUSH(29).to_string()
        && instrs[2].opcode == Opcode::SHR.to_string()
    {
        return Some(ExtractionPattern::Newer);
    }

    // Pattern 5: CALLDATASIZE ISZERO (fallback-only contracts)
    if instrs.len() >= 2
        && instrs[0].opcode == Opcode::CALLDATASIZE.to_string()
        && instrs[1].opcode == Opcode::ISZERO.to_string()
    {
        return Some(ExtractionPattern::Fallback);
    }

    // Pattern 6: Direct comparison without shift - PUSH1 0x00 CALLDATALOAD
    if instrs.len() >= 2
        && ((instrs[0].opcode == Opcode::PUSH(1).to_string()
            && instrs[0].imm.as_deref() == Some("00"))
            || instrs[0].opcode == Opcode::PUSH(0).to_string())
        && instrs[1].opcode == Opcode::CALLDATALOAD.to_string()
    {
        tracing::debug!("Matched Direct extraction pattern (no shift)");
        return Some(ExtractionPattern::Direct);
    }

    // Fallback: scan for CALLDATALOAD + SHR within first 6 instructions
    for i in 0..instrs.len().min(6).saturating_sub(1) {
        if instrs[i].opcode == Opcode::CALLDATALOAD.to_string() {
            for instr in instrs.iter().skip(i + 1).take(3) {
                if instr.opcode == Opcode::SHR.to_string() {
                    return Some(ExtractionPattern::Standard); // Default to standard for fallback
                }
            }
        }
    }

    None
}

/// Gets the instruction length of an extraction pattern.
///
/// # Arguments
/// * `instrs` - Instructions starting with the extraction pattern
/// * `pattern` - The detected extraction pattern type
///
/// # Returns
/// Some(n) if pattern matches; None otherwise
fn get_extraction_pattern_length(
    instrs: &[Instruction],
    pattern: &ExtractionPattern,
) -> Option<usize> {
    match pattern {
        ExtractionPattern::Standard => {
            if instrs.len() >= 4
                && instrs[0].opcode == Opcode::PUSH(1).to_string()
                && instrs[0].imm.as_deref() == Some("00")
                && instrs[1].opcode == Opcode::CALLDATALOAD.to_string()
                && instrs[2].opcode == Opcode::PUSH(1).to_string()
                && instrs[2].imm.as_deref() == Some("e0")
                && instrs[3].opcode == Opcode::SHR.to_string()
            {
                Some(4)
            } else {
                None
            }
        }
        ExtractionPattern::Alternative => {
            if instrs.len() >= 4
                && instrs[0].opcode == Opcode::PUSH(1).to_string()
                && instrs[0].imm.as_deref() == Some("00")
                && instrs[1].opcode == Opcode::CALLDATALOAD.to_string()
                && instrs[2].opcode == Opcode::PUSH(29).to_string()
                && instrs[3].opcode == Opcode::SHR.to_string()
            {
                Some(4)
            } else {
                None
            }
        }
        ExtractionPattern::Newer => {
            // Check for CALLDATALOAD PUSH1 0xE0 SHR first
            if instrs.len() >= 3
                && instrs[0].opcode == Opcode::CALLDATALOAD.to_string()
                && instrs[1].opcode == Opcode::PUSH(1).to_string()
                && instrs[1].imm.as_deref() == Some("e0")
                && instrs[2].opcode == Opcode::SHR.to_string()
            {
                Some(3)
            } else {
                None
            }
        }
        ExtractionPattern::Fallback => {
            if instrs.len() >= 2
                && instrs[0].opcode == Opcode::CALLDATASIZE.to_string()
                && instrs[1].opcode == Opcode::ISZERO.to_string()
            {
                Some(2)
            } else {
                None
            }
        }
        ExtractionPattern::Direct => {
            if instrs.len() >= 2
                && ((instrs[0].opcode == Opcode::PUSH(1).to_string()
                    && instrs[0].imm.as_deref() == Some("00"))
                    || instrs[0].opcode == Opcode::PUSH(0).to_string())
                && instrs[1].opcode == Opcode::CALLDATALOAD.to_string()
            {
                Some(2)
            } else {
                None
            }
        }
    }
}

/// Parses a function selector comparison pattern.
///
/// Identifies patterns like: DUP1 [optional PUSH0|PUSH1 0x00] PUSH4 <selector> (EQ|GT) PUSH{1,2} <addr> JUMPI
///
/// # Arguments
/// * `instrs` - Instructions starting at potential selector check
///
/// # Returns
/// `Some((selector, target_address, block_length))` if pattern matches, `None` otherwise
fn parse_selector_check(instrs: &[Instruction]) -> Option<(u32, u64, usize)> {
    if instrs.len() < 4 {
        return None;
    }

    let mut i = 0;

    // Optional DUP1 at the start (for subsequent comparisons)
    if instrs.get(i)?.opcode == Opcode::DUP(1).to_string() {
        i += 1;
    }

    // Must have PUSH4 with selector
    if i >= instrs.len() || instrs.get(i)?.opcode != Opcode::PUSH(4).to_string() {
        return None;
    }
    let selector = u32::from_str_radix(instrs[i].imm.as_ref()?, 16).ok()?;
    i += 1;

    // Must have EQ or GT
    if i >= instrs.len()
        || (instrs.get(i)?.opcode != Opcode::EQ.to_string()
            && instrs.get(i)?.opcode != Opcode::GT.to_string())
    {
        return None;
    }
    i += 1;

    // Try to find PUSH and JUMPI (allowing some flexibility)
    let mut address = 0u64;
    let mut found_jumpi = false;

    // Look ahead more instructions for PUSH{1-4} and JUMPI
    for j in 0..10 {
        // Increased from 5
        if i + j >= instrs.len() {
            break;
        }

        let instr = &instrs[i + j];

        // Look for PUSH instruction
        if instr.opcode.starts_with("PUSH")
            && (instr.opcode == "PUSH1"
                || instr.opcode == "PUSH2"
                || instr.opcode == "PUSH3"
                || instr.opcode == "PUSH4")
            && let Some(imm) = &instr.imm
            && let Ok(addr) = u64::from_str_radix(imm, 16)
        {
            address = addr;
        }

        // Look for JUMPI
        if instr.opcode == "JUMPI" {
            found_jumpi = true;
            i += j + 1;
            break;
        }
    }

    if found_jumpi {
        Some((selector, address, i)) // Return selector, address, and total block length
    } else {
        None
    }
}

/// Returns true iff a canonical dispatcher was found.
pub fn has_dispatcher(instructions: &[Instruction]) -> bool {
    detect_function_dispatcher(instructions).is_some()
}
