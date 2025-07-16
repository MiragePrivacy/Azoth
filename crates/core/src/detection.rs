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
/// let (instructions, info, _) = decoder::decode_bytecode("0x60016002", false).await.unwrap();
/// let sections =
///     locate_sections(&hex::decode("60016002").unwrap(), &instructions, &info).unwrap();
/// assert!(!sections.is_empty());
/// ```
use crate::decoder::{DecodeInfo, Instruction};
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
///
/// # Arguments
/// * `bytes` - Raw bytecode bytes.
/// * `instructions` - Decoded instructions from `decoder.rs`.
/// * `info` - Metadata about the bytecode from `decoder.rs`.
///
/// # Returns
/// A `Result` containing a vector of `Section` structs, ordered by offset, covering the entire
/// bytecode. If no dispatcher pattern is found, returns a single `Runtime` section (minus Auxdata).
/// Returns an error if sections overlap or leave gaps.
///
/// # Examples
/// ```rust,ignore
/// let bytes = hex::decode("60016002").unwrap();
/// let instructions = vec![/* parsed instructions */];
/// let info = DecodeInfo { byte_length: 2, keccak_hash: [0; 32], source: SourceType::HexString };
/// let sections = locate_sections(&bytes, &instructions, &info).unwrap();
/// assert_eq!(sections.len(), 1); // Single Runtime section if no pattern
/// ```
pub fn locate_sections(
    bytes: &[u8],
    instructions: &[Instruction],
    _info: &DecodeInfo,
) -> Result<Vec<Section>, DetectError> {
    let mut sections = Vec::new();
    let total_len = bytes.len();

    // Pass A: Detect Auxdata (CBOR) from the end
    let auxdata = detect_auxdata(bytes);
    let aux_offset = auxdata.map(|(offset, _)| offset).unwrap_or(total_len);
    tracing::debug!("Auxdata offset: {}", aux_offset);

    // Pass B: Detect Padding before Auxdata
    let padding = detect_padding(instructions, aux_offset);
    let _has_padding = padding.is_some();

    // Pass C: Detect Init -> Runtime split using dispatcher pattern
    let (init_end, runtime_start, runtime_len) =
        detect_init_runtime_split(instructions).unwrap_or((0, 0, aux_offset));
    tracing::debug!(
        "Init end: {}, Runtime start: {}, Runtime len: {}",
        init_end,
        runtime_start,
        runtime_len
    );

    // Clamp runtime_len to avoid exceeding aux_offset
    let mut runtime_len = runtime_len;
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

    // Pass E: Fallback to Runtime if no dispatcher pattern
    if init_end == 0 && runtime_start == 0 && aux_offset != 0 {
        // Fix: Skip Runtime if aux_offset=0
        let runtime_len = aux_offset;
        tracing::debug!("No dispatcher, full Runtime: len={}", runtime_len);
        sections.push(Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: runtime_len,
        });
    } else {
        if init_end > 0 {
            tracing::debug!("Init section: offset=0, len={}", init_end);
            sections.push(Section {
                kind: SectionKind::Init,
                offset: 0,
                len: init_end,
            });
        }
        if runtime_len > 0 {
            tracing::debug!(
                "Runtime section: offset={}, len={}",
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
        tracing::debug!("Auxdata section: offset={}, len={}", offset, len);
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
                // Shrink runtime so it ends where padding begins
                rt.len = sec.offset - rt.offset;
            }
        }
    }

    // Ensure sections are non-overlapping and cover the entire range
    sections.sort_by_key(|s| s.offset);
    tracing::debug!("Sorted sections: {:?}", sections);

    let mut current_offset = 0;
    for section in sections.iter() {
        tracing::debug!(
            "Checking section: kind={:?}, offset={}, len={}",
            section.kind,
            section.offset,
            section.len
        );
        if section.offset < current_offset {
            tracing::debug!("Overlap detected at offset {}", section.offset);
            return Err(DetectError::Overlap(section.offset));
        }
        if section.offset > current_offset {
            tracing::debug!("Gap detected at offset {}", current_offset);
            return Err(DetectError::Gap(current_offset));
        }
        current_offset = section.offset + section.len;
    }

    if current_offset != total_len {
        tracing::debug!(
            "Gap at end: current_offset={}, total_len={}",
            current_offset,
            total_len
        );
        return Err(DetectError::Gap(current_offset));
    }

    tracing::debug!("Sections validated: {:?}", sections);
    Ok(sections)
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
            return Some((init_end, runtime_ofs, runtime_len));
        }
    }
    None
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

    // Pattern 1: PUSH1 0x00 CALLDATALOAD PUSH1 0xE0 SHR
    if instrs.len() >= 4
        && instrs[0].opcode == Opcode::PUSH(1).to_string()
        && instrs[0].imm.as_deref() == Some("00")
        && instrs[1].opcode == Opcode::CALLDATALOAD.to_string()
        && instrs[2].opcode == Opcode::PUSH(1).to_string()
        && instrs[2].imm.as_deref() == Some("e0")
        && instrs[3].opcode == Opcode::SHR.to_string()
    {
        return Some(ExtractionPattern::Standard);
    }

    // Pattern 2: PUSH1 0x00 CALLDATALOAD PUSH29 ... SHR
    if instrs.len() >= 4
        && instrs[0].opcode == Opcode::PUSH(1).to_string()
        && instrs[0].imm.as_deref() == Some("00")
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
    }
}

/// Parses a function selector comparison pattern.
///
/// Identifies the standard pattern: DUP1 PUSH4 <selector> EQ PUSH2 <addr> JUMPI
///
/// # Arguments
/// * `instrs` - Instructions starting at potential selector check
///
/// # Returns
/// `Some((selector, target_address))` if pattern matches, `None` otherwise
fn parse_selector_check(instrs: &[Instruction]) -> Option<(u32, u64)> {
    if instrs.len() < 6 {
        return None;
    }

    // Standard pattern: DUP1 PUSH4 <selector> EQ PUSH2 <addr> JUMPI
    if instrs[0].opcode == Opcode::DUP(1).to_string()
        && instrs[1].opcode == Opcode::PUSH(4).to_string()
        && instrs[2].opcode == Opcode::EQ.to_string()
        && instrs[3].opcode.starts_with("PUSH")
        && instrs[4].opcode == Opcode::JUMPI.to_string()
    {
        let selector = u32::from_str_radix(instrs[1].imm.as_ref()?, 16).ok()?;
        let address = u64::from_str_radix(instrs[3].imm.as_ref()?, 16).ok()?;
        return Some((selector, address));
    }

    None
}

// todo(g4titanx): turn the unit-test into a property test instead of checking hard-coded offsets.
// the idea is that we let `locate_sections` do its job and then we verify intrinsic invariants that
// must always hold, regardless of any particular byte indices. that way the test automatically
// adapts to any fixture we feed it, and we never need to update constants when the fixture changes
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decoder, decoder::SourceType};
    use hex;

    #[tokio::test]
    async fn test_locate_sections_with_auxdata() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0xa165627a7a720000"; // Simplified Auxdata example
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        tracing::debug!("Bytecode: {:?}", bytes);
        tracing::debug!("Instructions: {:?}", instructions);
        tracing::debug!("DecodeInfo: {:?}", info);

        let result = locate_sections(&bytes, &instructions, &info);
        match result {
            Ok(sections) => {
                tracing::debug!("Detected sections: {:?}", sections);
                for (i, section) in sections.iter().enumerate() {
                    tracing::debug!(
                        "Section {}: kind={:?}, offset={}, len={}",
                        i,
                        section.kind,
                        section.offset,
                        section.len
                    );
                }
                assert_eq!(sections.len(), 1, "Expected exactly one section");
                assert_eq!(
                    sections[0].kind,
                    SectionKind::Auxdata,
                    "Expected Auxdata section"
                );
            }
            Err(e) => {
                tracing::debug!("Error in locate_sections: {:?}", e);
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_overlap_error() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let _bytes = vec![0; 10];
        let _instructions: Vec<Instruction> = vec![]; // Explicit type annotation
        let _info = DecodeInfo {
            byte_length: 10,
            keccak_hash: [0; 32],
            source: SourceType::HexString,
        };
        // Simulate overlap
        let mut simulated_sections = vec![
            Section {
                kind: SectionKind::Init,
                offset: 0,
                len: 5,
            },
            Section {
                kind: SectionKind::Runtime,
                offset: 3,
                len: 5,
            }, // Overlaps at 3
        ];
        tracing::debug!("Simulated sections: {:?}", simulated_sections);

        // Directly test overlap validation
        simulated_sections.sort_by_key(|s| s.offset);
        let result = validate_sections(&mut simulated_sections);
        tracing::debug!("Result from validate_sections: {:?}", result);
        assert!(
            matches!(result, Err(DetectError::Overlap(3))),
            "Expected Overlap error at offset 3"
        );
    }

    #[tokio::test]
    async fn test_full_deploy_payload() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = concat!(
            "0x",
            "600a",             // PUSH1 0x0a (runtime len)
            "600e",             // PUSH1 0x0e (runtime offset)
            "6000",             // PUSH1 0x00
            "39",               // CODECOPY
            "600a",             // PUSH1 0x0a (runtime len)
            "f3",               // RETURN
            "deadbeef",         // ConstructorArgs (4 bytes)
            "600101",           // Runtime: PUSH1 0x01, STOP
            "a165627a7a723058"  // Auxdata (simplified CBOR: "bzzr0X")
        );

        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        tracing::debug!("Full deploy bytecode: {:?}", bytes);
        tracing::debug!("Instructions: {:?}", instructions);
        tracing::debug!("DecodeInfo: {:?}", info);

        let sections = locate_sections(&bytes, &instructions, &info).unwrap();
        tracing::debug!("Detected sections: {:?}", sections);
        for (i, section) in sections.iter().enumerate() {
            tracing::debug!(
                "Section {}: kind={:?}, offset={}, len={}",
                i,
                section.kind,
                section.offset,
                section.len
            );
        }

        assert_eq!(sections.len(), 4, "Expected 4 sections");
        assert_eq!(
            sections[0],
            Section {
                kind: SectionKind::Init,
                offset: 0,
                len: 10
            },
            "Init section mismatch"
        );
        assert_eq!(
            sections[1],
            Section {
                kind: SectionKind::ConstructorArgs,
                offset: 10,
                len: 4
            },
            "ConstructorArgs section mismatch"
        );
        assert_eq!(
            sections[2],
            Section {
                kind: SectionKind::Runtime,
                offset: 14,
                len: 3
            },
            "Runtime section mismatch"
        );
        assert_eq!(
            sections[3],
            Section {
                kind: SectionKind::Auxdata,
                offset: 17,
                len: 8
            },
            "Auxdata section mismatch"
        );

        let total_len = sections.iter().map(|s| s.len).sum::<usize>();
        assert_eq!(
            total_len,
            bytes.len(),
            "Sections do not cover full bytecode"
        );
    }

    #[tokio::test]
    async fn runtime_with_trailing_zeros_is_split_properly() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let hex = "60016000f3".to_owned() + &"00".repeat(32);
        let (instructions, info, _) = decoder::decode_bytecode(&format!("0x{}", hex), false)
            .await
            .unwrap();
        let bytes = hex::decode(hex).unwrap();
        let sections = locate_sections(&bytes, &instructions, &info).unwrap();
        let rt = sections
            .iter()
            .find(|s| s.kind == SectionKind::Runtime)
            .unwrap();
        assert_eq!(rt.len, 5); // 5-byte program
        assert!(sections.iter().any(|s| s.kind == SectionKind::Padding));
    }

    /// Validates sections for overlaps and gaps.
    fn validate_sections(sections: &mut [Section]) -> Result<(), DetectError> {
        sections.sort_by_key(|s| s.offset);
        let mut current_offset = 0;
        for section in sections.iter() {
            if section.offset < current_offset {
                return Err(DetectError::Overlap(section.offset));
            }
            if section.offset > current_offset {
                return Err(DetectError::Gap(current_offset));
            }
            current_offset = section.offset + section.len;
        }
        Ok(())
    }
}
