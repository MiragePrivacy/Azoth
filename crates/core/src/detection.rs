use crate::Opcode;
/// Module for detecting and classifying bytecode regions (Init, Runtime, ConstructorArgs,
/// Auxdata, Padding) as part of BOSC Step 1 preprocessing.
///
/// This module implements the structural analysis of EVM bytecode to extract runtime bytecode,
/// remove deployment and auxdata bytecode, and provide exact byte-ranges for subsequent stages
/// (e.g., stripping and recovery). It uses raw bytes, decoded instructions, and metadata from
/// `decoder.rs` to identify logical regions based on opcode patterns and byte-level
/// signatures.
///
/// # Usage
/// ```rust,ignore
/// let (instructions, _, _) = decoder::decode_bytecode("0x60016002", false).await.unwrap();
/// let sections =
///     locate_sections(&hex::decode("60016002").unwrap(), &instructions).unwrap();
/// assert!(!sections.is_empty());
/// ```
use crate::decoder::Instruction;
use crate::is_terminal_opcode;
use azoth_utils::errors::DetectError;
use serde::{Deserialize, Serialize};

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

/// Represents the type of a bytecode section.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionKind {
    /// Deployment code executed once during contract creation.
    Init,
    /// Executable code stored and executed on-chain.
    Runtime,
    /// Constructor arguments appended to deployment payload.
    ConstructorArgs,
    /// CBOR metadata (e.g., Solidity fingerprint) appended after runtime.
    Auxdata,
    /// Padding bytes after terminal instructions but before Auxdata.
    Padding,
}

impl SectionKind {
    /// Returns true if the section should be removed (i.e., not Runtime).
    pub fn is_removed(self) -> bool {
        !matches!(self, SectionKind::Runtime)
    }
}

/// Represents a detected section with its kind, starting offset, and length.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub kind: SectionKind,
    pub offset: usize, // Start position in raw bytes
    pub len: usize,    // Byte-length of the section
}

impl Section {
    /// Returns the end offset of the section (offset + len).
    pub fn end(self) -> usize {
        self.offset + self.len
    }
}

/// Locates all non-overlapping, offset-ordered sections in the bytecode.
pub fn locate_sections(
    bytes: &[u8],
    instructions: &[Instruction],
) -> Result<Vec<Section>, DetectError> {
    let mut sections = Vec::new();
    let total_len = bytes.len();

    tracing::debug!(
        "Processing bytecode: {} bytes, {} instructions",
        total_len,
        instructions.len()
    );

    // Pass A: Detect Auxdata (CBOR) from the end
    let auxdata = detect_auxdata(bytes);
    let aux_offset = auxdata.map(|(offset, _)| offset).unwrap_or(total_len);
    tracing::debug!("Auxdata offset: {}", aux_offset);

    // Special case: If auxdata starts at offset 0, the entire bytecode is auxdata
    if aux_offset == 0 {
        if let Some((offset, len)) = auxdata {
            tracing::debug!("Entire bytecode is auxdata: offset={}, len={}", offset, len);
            sections.push(Section {
                kind: SectionKind::Auxdata,
                offset,
                len,
            });
            return Ok(sections);
        }
    }

    // Pass B: Detect Padding before Auxdata
    let padding = detect_padding(instructions, aux_offset);

    // Pass C: Detect Init -> Runtime split using dispatcher pattern
    let (mut init_end, mut runtime_start, mut runtime_len) =
        detect_init_runtime_split(instructions).unwrap_or((0, 0, aux_offset));

    tracing::debug!(
        "Initial detection: init_end={}, runtime_start={}, runtime_len={}",
        init_end,
        runtime_start,
        runtime_len
    );

    // Handles cases where deployment pattern detection fails
    // but we clearly have deployment bytecode (substantial size suggests it)
    if init_end == 0 && runtime_start == 0 && aux_offset > 100 {
        // Try fallback detection methods
        if let Some((detected_init_end, detected_runtime_start)) =
            detect_deployment_fallback(instructions, aux_offset)
        {
            init_end = detected_init_end;
            runtime_start = detected_runtime_start;
            runtime_len = aux_offset.saturating_sub(runtime_start);
            tracing::debug!(
                "Fallback detection succeeded: init_end={}, runtime_start={}, runtime_len={}",
                init_end,
                runtime_start,
                runtime_len
            );
        }
    }

    // Additional guard: if we found runtime_start but not init_end
    if init_end == 0 && runtime_start > 0 {
        init_end = runtime_start;
        tracing::debug!(
            "Fixed init_end from 0 to {} based on runtime_start",
            init_end
        );
    }

    // Clamp runtime_len to avoid exceeding aux_offset
    if runtime_start + runtime_len > aux_offset {
        runtime_len = aux_offset.saturating_sub(runtime_start);
        tracing::debug!("Clamped runtime_len to {}", runtime_len);
    }

    // Pass D: Detect ConstructorArgs if applicable
    let constructor_args = detect_constructor_args(init_end, runtime_start, aux_offset);
    let has_constructor_args = constructor_args.is_some();
    if let Some((args_offset, args_len)) = constructor_args {
        tracing::debug!(
            "ConstructorArgs detected: offset={}, len={}",
            args_offset,
            args_len
        );
        sections.push(Section {
            kind: SectionKind::ConstructorArgs,
            offset: args_offset,
            len: args_len,
        });
    }

    // Only push Padding if ConstructorArgs is not present
    if !has_constructor_args {
        if let Some((pad_offset, pad_len)) = padding {
            tracing::debug!("Padding detected: offset={}, len={}", pad_offset, pad_len);
            sections.push(Section {
                kind: SectionKind::Padding,
                offset: pad_offset,
                len: pad_len,
            });
        }
    }

    // Pass E: Create sections based on detected boundaries
    if init_end == 0 && runtime_start == 0 {
        // True runtime-only contract
        tracing::debug!("Runtime-only bytecode detected");
        sections.push(Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: aux_offset,
        });
    } else {
        // Deployment bytecode (original or obfuscated)
        if init_end > 0 {
            tracing::debug!("Creating Init section: offset=0, len={}", init_end);
            sections.push(Section {
                kind: SectionKind::Init,
                offset: 0,
                len: init_end,
            });
        }
        if runtime_len > 0 && runtime_start < aux_offset {
            tracing::debug!(
                "Creating Runtime section: offset={}, len={}",
                runtime_start,
                runtime_len
            );
            sections.push(Section {
                kind: SectionKind::Runtime,
                offset: runtime_start,
                len: runtime_len,
            });
        }
    }

    // Add Auxdata section if detected
    if let Some((offset, len)) = auxdata {
        tracing::debug!("Adding auxdata section: offset={}, len={}", offset, len);
        sections.push(Section {
            kind: SectionKind::Auxdata,
            offset,
            len,
        });
    }

    // Adjust runtime section to account for padding overlap
    let sections_clone = sections.clone();
    if let Some(rt) = sections.iter_mut().find(|s| s.kind == SectionKind::Runtime) {
        for sec in &sections_clone {
            if sec.kind == SectionKind::Padding
                && sec.offset >= rt.offset
                && sec.offset < rt.offset + rt.len
            {
                let new_len = sec.offset - rt.offset;
                tracing::debug!(
                    "Adjusting runtime section length from {} to {} due to padding",
                    rt.len,
                    new_len
                );
                rt.len = new_len;
            }
        }
    }

    // Ensure sections are non-overlapping and cover the entire range
    sections.sort_by_key(|s| s.offset);
    tracing::debug!("Final sections before validation: {:?}", sections);

    validate_sections(&sections, total_len)?;

    tracing::debug!("Sections validation passed: {:?}", sections);
    Ok(sections)
}

/// Fallback deployment detection for when the strict pattern fails
fn detect_deployment_fallback(
    instructions: &[Instruction],
    aux_offset: usize,
) -> Option<(usize, usize)> {
    // Method 1: Look for CODECOPY + RETURN pattern
    if let Some((init_end, runtime_start)) = detect_codecopy_return_simple(instructions) {
        if runtime_start < aux_offset {
            return Some((init_end, runtime_start));
        }
    }

    // Method 2: Look for function dispatcher pattern (indicates runtime start)
    if let Some(dispatcher_info) = detect_function_dispatcher(instructions) {
        // If we found a dispatcher, assume everything before it is Init
        let runtime_start = dispatcher_info.start_offset;
        if runtime_start > 0 && runtime_start < aux_offset {
            tracing::debug!(
                "Using function dispatcher at offset {} as runtime start",
                runtime_start
            );
            return Some((runtime_start, runtime_start));
        }
    }

    // Method 3: Heuristic based on instruction patterns
    // Look for the transition from deployment-style to runtime-style code
    for instruction in instructions.iter() {
        // Common runtime start patterns
        if instruction.opcode == "CALLDATASIZE"
            || (instruction.opcode == "PUSH1" && instruction.imm.as_deref() == Some("00"))
        {
            // This might be the start of runtime code
            let potential_runtime_start = instruction.pc;
            if potential_runtime_start > 100 && potential_runtime_start < aux_offset {
                tracing::debug!(
                    "Heuristic runtime start detected at PC {}",
                    potential_runtime_start
                );
                return Some((potential_runtime_start, potential_runtime_start));
            }
        }
    }

    None
}

/// Simple CODECOPY + RETURN detection
fn detect_codecopy_return_simple(instructions: &[Instruction]) -> Option<(usize, usize)> {
    // Find first CODECOPY
    let codecopy_idx = instructions.iter().position(|i| i.opcode == "CODECOPY")?;

    // Find RETURN after CODECOPY (within reasonable distance)
    let return_idx = instructions[codecopy_idx..]
        .iter()
        .take(20)
        .position(|i| i.opcode == "RETURN")
        .map(|pos| codecopy_idx + pos)?;

    let init_end = instructions[return_idx].pc + 1;

    // Try to find runtime start from PUSH instructions before CODECOPY
    let mut runtime_start = init_end; // fallback

    for i in (0..codecopy_idx).rev().take(10) {
        if instructions[i].opcode.starts_with("PUSH") {
            if let Some(imm) = &instructions[i].imm {
                if let Ok(value) = usize::from_str_radix(imm, 16) {
                    if value > init_end && value < 100000 {
                        runtime_start = value;
                        break;
                    }
                }
            }
        }
    }

    tracing::debug!(
        "CODECOPY+RETURN detection: init_end={}, runtime_start={}",
        init_end,
        runtime_start
    );
    Some((init_end, runtime_start))
}

/// Validates sections for overlaps, gaps, and bounds
pub fn validate_sections(sections: &[Section], total_len: usize) -> Result<(), DetectError> {
    let mut current_offset = 0;
    for section in sections.iter() {
        tracing::debug!(
            "Validating section: kind={:?}, offset={}, len={}, end={}",
            section.kind,
            section.offset,
            section.len,
            section.end()
        );

        if section.offset < current_offset {
            return Err(DetectError::Overlap(section.offset));
        }
        if section.offset > current_offset {
            return Err(DetectError::Gap(current_offset));
        }
        if section.end() > total_len {
            return Err(DetectError::OutOfBounds(section.end()));
        }
        current_offset = section.end();
    }

    if current_offset != total_len {
        return Err(DetectError::Gap(current_offset));
    }

    Ok(())
}

/// Detects Auxdata (CBOR) section from the end of the bytecode.
///
/// # Arguments
/// * `bytes` - Raw bytecode bytes.
///
/// # Returns
/// Optional tuple of (offset, length) if Auxdata is found, None otherwise.
/// Detects Auxdata (CBOR) section from the end of the bytecode, using a canonical length check
/// and a fallback scan for invalid lengths.
fn detect_auxdata(bytes: &[u8]) -> Option<(usize, usize)> {
    const MARKER: &[u8] = &[0xa1, 0x65, 0x62, 0x7a, 0x7a, 0x72]; // a165627a7a72
    let len = bytes.len();
    if len < MARKER.len() + 2 {
        tracing::debug!("Bytecode too short for auxdata: len={}", len);
        return None;
    }

    // Canonical path: trust len_raw when it is plausible
    let len_raw = u16::from_be_bytes([bytes[len - 2], bytes[len - 1]]) as usize;
    if len_raw > 0 && len_raw + 2 <= len && bytes[len - len_raw - 2..len - 2].starts_with(MARKER) {
        let off = len - len_raw - 2;
        tracing::debug!(
            "Auxdata detected (canonical): offset={}, len={}",
            off,
            len_raw + 2
        );
        return Some((off, len_raw + 2));
    }

    // Fallback: scan last ≤64 bytes for the marker
    let tail_start = len.saturating_sub(64 + MARKER.len());
    for off in (tail_start..=len - MARKER.len()).rev() {
        if bytes[off..off + MARKER.len()] == *MARKER {
            let aux_len = len - off;
            tracing::debug!(
                "Auxdata detected (fallback): offset={}, len={}",
                off,
                aux_len
            );
            return Some((off, aux_len)); // Marker to EOF
        }
    }

    tracing::debug!("No auxdata marker found");
    None
}

/// Detects Padding section before Auxdata.
///
/// # Arguments
/// * `instructions` - Decoded instructions.
/// * `aux_offset` - Offset of Auxdata or total length if none.
///
/// # Returns
/// Optional tuple of (offset, length) if Padding is found, None otherwise.
fn detect_padding(instructions: &[Instruction], aux_offset: usize) -> Option<(usize, usize)> {
    let last_terminal = instructions
        .iter()
        .rev()
        .skip_while(|instr| instr.opcode == "STOP")
        .find(|instr| is_terminal_opcode(&instr.opcode));

    last_terminal.and_then(|instr| {
        let pad_offset = instr.pc + 1;
        if pad_offset < aux_offset {
            Some((pad_offset, aux_offset - pad_offset))
        } else {
            None
        }
    })
}

/// Detects the Init to Runtime split using the dispatcher pattern.
///
/// # Arguments
/// * `instructions` - Decoded instructions.
///
/// # Returns
/// Optional tuple of (init_end, runtime_start, runtime_len) if pattern is found, None otherwise.
fn detect_init_runtime_split(instructions: &[Instruction]) -> Option<(usize, usize, usize)> {
    // Try the strict pattern first (for backwards compatibility)
    if let Some(result) = detect_strict_deployment_pattern(instructions) {
        return Some(result);
    }

    // Fallback: Look for any CODECOPY + RETURN pattern
    if let Some(result) = detect_codecopy_return_pattern(instructions) {
        return Some(result);
    }

    None
}

/// Detects the strict deployment pattern (original heuristic)
fn detect_strict_deployment_pattern(instructions: &[Instruction]) -> Option<(usize, usize, usize)> {
    for i in 0..instructions.len().saturating_sub(6) {
        if instructions[i].opcode.starts_with("PUSH")
            && instructions[i + 1].opcode.starts_with("PUSH")
            && matches!(instructions[i + 2].opcode.as_str(), "PUSH0" | "PUSH1")
            && instructions[i + 2].imm.as_deref() == Some("00")
            && instructions[i + 3].opcode == "CODECOPY"
            && instructions[i + 4].opcode.starts_with("PUSH")
            && instructions[i + 5].opcode == "RETURN"
        {
            let runtime_len = instructions[i]
                .imm
                .as_ref()
                .and_then(|s| usize::from_str_radix(s, 16).ok())?;
            let runtime_ofs = instructions[i + 1]
                .imm
                .as_ref()
                .and_then(|s| usize::from_str_radix(s, 16).ok())?;
            let init_end = instructions[i + 5].pc + 1;

            tracing::debug!(
                "Found strict deployment pattern at {}: init_end={}, runtime_start={}, runtime_len={}",
                i,
                init_end,
                runtime_ofs,
                runtime_len
            );

            return Some((init_end, runtime_ofs, runtime_len));
        }
    }
    None
}

/// Fallback: Look for CODECOPY + RETURN pattern with more flexibility
fn detect_codecopy_return_pattern(instructions: &[Instruction]) -> Option<(usize, usize, usize)> {
    // Find CODECOPY instruction
    let codecopy_idx = instructions
        .iter()
        .position(|instr| instr.opcode == "CODECOPY")?;

    // Look for RETURN after CODECOPY (within reasonable distance)
    let return_idx = instructions[codecopy_idx + 1..]
        .iter()
        .take(10) // Look within next 10 instructions
        .position(|instr| instr.opcode == "RETURN")
        .map(|pos| codecopy_idx + 1 + pos)?;

    // Try to extract runtime parameters from PUSH instructions before CODECOPY
    let mut runtime_len = None;
    let mut runtime_start = None;

    // Look backwards from CODECOPY for PUSH instructions
    for i in (0..codecopy_idx).rev().take(10) {
        if instructions[i].opcode.starts_with("PUSH") {
            if let Some(imm) = &instructions[i].imm {
                if let Ok(value) = usize::from_str_radix(imm, 16) {
                    if runtime_len.is_none() && value > 0 && value < 100000 {
                        // First reasonable value could be runtime length
                        runtime_len = Some(value);
                    } else if runtime_start.is_none() && value > 0 && value < 100000 {
                        // Second reasonable value could be runtime start
                        runtime_start = Some(value);
                    }

                    if runtime_len.is_some() && runtime_start.is_some() {
                        break;
                    }
                }
            }
        }
    }

    // If we found CODECOPY + RETURN but can't extract parameters,
    // make reasonable assumptions
    let runtime_len = runtime_len.unwrap_or_else(|| {
        // Estimate runtime length from instruction count after return
        instructions.len().saturating_sub(return_idx + 1) * 2 // rough estimate
    });

    let runtime_start = runtime_start.unwrap_or_else(|| {
        // Assume runtime starts right after the RETURN instruction
        instructions[return_idx].pc + 1
    });

    let init_end = instructions[return_idx].pc + 1;

    tracing::debug!(
        "Found fallback deployment pattern: CODECOPY at {}, RETURN at {}, init_end={}, runtime_start={}, runtime_len={}",
        codecopy_idx,
        return_idx,
        init_end,
        runtime_start,
        runtime_len
    );

    Some((init_end, runtime_start, runtime_len))
}

/// Detects ConstructorArgs section between Init end and Runtime start.
///
/// # Arguments
/// * `init_end` - End offset of Init section.
/// * `runtime_start` - Start offset of Runtime section.
/// * `aux_offset` - Offset of Auxdata or total length if none.
///
/// # Returns
/// Optional tuple of (offset, length) if ConstructorArgs are found, None otherwise.
fn detect_constructor_args(
    init_end: usize,
    runtime_start: usize,
    aux_offset: usize,
) -> Option<(usize, usize)> {
    if runtime_start > 0 && init_end < runtime_start && runtime_start < aux_offset {
        Some((init_end, runtime_start - init_end))
    } else {
        None
    }
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
    // Look for the calldata extraction pattern first
    let mut start_idx = None;
    let mut extraction_pattern = None;

    for i in 0..instructions.len().saturating_sub(6) {
        if let Some(pattern) = is_calldata_extraction_pattern(&instructions[i..]) {
            start_idx = Some(i);
            extraction_pattern = Some(pattern);
            break;
        }
    }

    let start = start_idx?;
    let pattern = extraction_pattern?;
    let mut selectors = Vec::new();
    let mut current_idx = start + get_extraction_pattern_length(&instructions[start..], &pattern)?;

    // Look for function selector comparisons
    while current_idx < instructions.len().saturating_sub(6) {
        if let Some(selector) = parse_selector_check(&instructions[current_idx..]) {
            selectors.push(FunctionSelector {
                selector: selector.0,
                target_address: selector.1,
                instruction_index: current_idx,
            });
            current_idx += 5; // Standard pattern is 5 instructions: DUP1, PUSH4, EQ, PUSH2, JUMPI
        } else {
            break;
        }
    }

    if !selectors.is_empty() {
        Some(DispatcherInfo {
            start_offset: start,
            end_offset: current_idx,
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

    // Pattern 3: CALLDATALOAD PUSH29 ... SHR (newer Solidity)
    if instrs.len() >= 3
        && instrs[0].opcode == Opcode::CALLDATALOAD.to_string()
        && instrs[1].opcode == Opcode::PUSH(29).to_string()
        && instrs[2].opcode == Opcode::SHR.to_string()
    {
        return Some(ExtractionPattern::Newer);
    }

    // Pattern 4: CALLDATASIZE ISZERO (fallback-only contracts)
    if instrs.len() >= 2
        && instrs[0].opcode == Opcode::CALLDATASIZE.to_string()
        && instrs[1].opcode == Opcode::ISZERO.to_string()
    {
        return Some(ExtractionPattern::Fallback);
    }

    // Pattern 5: Direct comparison without shift - PUSH1 0x00 CALLDATALOAD
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
            if instrs.len() >= 3
                && instrs[0].opcode == Opcode::CALLDATALOAD.to_string()
                && instrs[1].opcode == Opcode::PUSH(29).to_string()
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
/// Identifies the standard pattern: DUP1 [optional PUSH0|PUSH1 0x00] PUSH4 <selector> EQ PUSH{1,2} <addr> JUMPI
///
/// # Arguments
/// * `instrs` - Instructions starting at potential selector check
///
/// # Returns
/// `Some((selector, target_address))` if pattern matches, `None` otherwise
fn parse_selector_check(instrs: &[Instruction]) -> Option<(u32, u64)> {
    if instrs.len() < 5 {
        return None;
    }

    let mut i = 0;

    // Must start with DUP1
    if instrs.get(i)?.opcode != Opcode::DUP(1).to_string() {
        return None;
    }
    i += 1;

    // Must have PUSH4 with selector
    if instrs.get(i)?.opcode != Opcode::PUSH(4).to_string() {
        return None;
    }
    let selector = u32::from_str_radix(instrs[i].imm.as_ref()?, 16).ok()?;
    i += 1;

    // Must have EQ
    if instrs.get(i)?.opcode != Opcode::EQ.to_string() {
        return None;
    }
    i += 1;

    // Must have PUSH1 or PUSH2 with address
    if !instrs.get(i)?.opcode.starts_with("PUSH1") && !instrs.get(i)?.opcode.starts_with("PUSH2") {
        return None;
    }
    let address = u64::from_str_radix(instrs[i].imm.as_ref()?, 16).ok()?;
    i += 1;

    // Must have JUMPI
    if instrs.get(i)?.opcode != Opcode::JUMPI.to_string() {
        return None;
    }

    Some((selector, address))
}

/// Returns true iff a canonical dispatcher was found.
pub fn has_dispatcher(instructions: &[Instruction]) -> bool {
    detect_function_dispatcher(instructions).is_some()
}
