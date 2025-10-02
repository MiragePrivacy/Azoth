//! azoth's single entry-point for turning byte-sequences into Heimdall instruction streams.

use crate::Opcode;
use azoth_utils::errors::DecodeError;
use heimdall::{DisassemblerArgsBuilder, disassemble};
use hex::FromHex;
use std::str::FromStr;
use std::{fmt, fs, path::Path};
use tiny_keccak::{Hasher, Keccak};

/// Represents a single disassembled instruction.
#[derive(Clone, Debug, PartialEq)]
pub struct Instruction {
    /// the instruction's program counter (in bytes)
    pub pc: usize,
    /// Opcode name - the mnemonic (e.g. "PUSH1", "ADD")
    pub opcode: String,
    /// any immediate data (hex string without 0x), if present
    pub imm: Option<String>,
}

/// Metadata about the decoded bytecode blob.
#[derive(Debug)]
pub struct DecodeInfo {
    /// number of bytes
    pub byte_length: usize,
    /// a 32-byte Keccak-256 hash of the raw bytes
    pub keccak_hash: [u8; 32],
    /// input from the variants of SourceType
    pub source: SourceType,
}

/// Source type of the bytecode input.
#[derive(Debug, PartialEq, Eq)]
pub enum SourceType {
    HexString,
    File,
    // OnChain remains for future RPC-based fetching
}

/// Normalizes hex strings by removing whitespace, 0x prefix, and ensuring even length
pub fn normalize_hex_string(input: &str) -> Result<String, DecodeError> {
    let clean = input
        .trim()
        .replace(['\n', '\r', ' ', '\t'], "")
        .strip_prefix("0x")
        .unwrap_or(input.trim().replace(['\n', '\r', ' ', '\t'], "").as_str())
        .to_string();

    // Validate hex characters
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DecodeError::HexDecode(
            hex::FromHexError::InvalidHexCharacter {
                c: clean
                    .chars()
                    .find(|c| !c.is_ascii_hexdigit())
                    .unwrap_or('?'),
                index: 0,
            },
        ));
    }

    // Ensure even length by padding with leading zero if necessary
    Ok(if clean.len() % 2 == 1 {
        format!("0{}", clean)
    } else {
        clean
    })
}

/// Normalizes input into a byte vector from hex string or file.
pub fn input_to_bytes(input: &str, is_file: bool) -> Result<Vec<u8>, DecodeError> {
    if is_file {
        let path = Path::new(input);
        let file_content = fs::read_to_string(path).map_err(|e| DecodeError::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let normalized = normalize_hex_string(&file_content)?;
        Vec::from_hex(&normalized).map_err(DecodeError::HexDecode)
    } else {
        let normalized = normalize_hex_string(input)?;
        Vec::from_hex(&normalized).map_err(DecodeError::HexDecode)
    }
}

/// Decodes raw EVM bytecode from bytes into an instruction stream with metadata and raw assembly.
///
/// This is the core decoding function that operates directly on byte slices, making it more
/// generic and suitable for use throughout the core crate without file I/O dependencies.
///
/// # Arguments
/// * `bytes` - The raw EVM bytecode bytes to decode.
/// * `source` - The source type indicating how the bytes were obtained.
///
/// # Returns
/// A tuple of (InstructionStream, DecodeInfo, raw assembly string), or an error if decoding fails.
pub async fn decode_bytecode_from_bytes(
    bytes: &[u8],
    source: SourceType,
) -> Result<(Vec<Instruction>, DecodeInfo, String), DecodeError> {
    // 1. Compute metadata
    let byte_length = bytes.len();
    let mut keccak = Keccak::v256();
    keccak.update(bytes);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    // 2. Configure and run heimdall disassembly
    let target_arg = format!("0x{}", hex::encode(bytes));

    let args = DisassemblerArgsBuilder::new()
        .target(target_arg)
        .output("print".into())
        .decimal_counter(false) // Hexadecimal PCs
        .build()
        .map_err(|e| DecodeError::Heimdall(e.to_string()))?;

    let asm = disassemble(args)
        .await
        .map_err(|e| DecodeError::Heimdall(e.to_string()))?;

    // 3. Parse assembly into structured instructions
    let instructions = parse_assembly(&asm)?;

    Ok((
        instructions,
        DecodeInfo {
            byte_length,
            keccak_hash: hash,
            source,
        },
        asm,
    ))
}

/// Decodes raw EVM bytecode into an instruction stream with metadata and raw assembly.
///
/// This is a convenience wrapper around `decode_bytecode_from_bytes` that handles
/// input normalization from hex strings or file paths.
///
/// # Arguments
/// * `input` - A hex string or file path representing the EVM bytecode.
/// * `is_file` - Flag indicating if the input is a file path (false for hex string).
///
/// # Returns
/// A tuple of (InstructionStream, DecodeInfo, raw assembly string, raw bytes), or an error if decoding fails.
pub async fn decode_bytecode(
    input: &str,
    is_file: bool,
) -> Result<(Vec<Instruction>, DecodeInfo, String, Vec<u8>), DecodeError> {
    // 1. Normalize input to bytes (handles hex normalization internally)
    let bytes = input_to_bytes(input, is_file)?;

    // 2. Determine source type
    let source = if is_file {
        SourceType::File
    } else {
        SourceType::HexString
    };

    // 3. Delegate to the core decoding function
    let (instructions, decode_info, asm) = decode_bytecode_from_bytes(&bytes, source).await?;

    Ok((instructions, decode_info, asm, bytes))
}

/// Parses the assembly string into a vector of Instructions.
///
/// Handles lines like "0x0003 PUSH1 0x60 # comment" and skips labels (e.g., "label_0000:") or blank
/// lines.
pub fn parse_assembly(asm: &str) -> Result<Vec<Instruction>, DecodeError> {
    // Fail on empty assembly
    if asm.trim().is_empty() {
        return Err(DecodeError::Parse {
            line: 0,
            msg: "empty assembly".into(),
            raw: asm.to_string(),
        });
    }

    let mut instructions = Vec::new();
    for (line_no, raw) in asm.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with("label_") {
            continue; // Skip blank lines and label lines
        }

        let mut parts = line.split_whitespace();
        let pc_hex = parts.next().ok_or_else(|| DecodeError::Parse {
            line: line_no,
            msg: "missing PC".to_string(),
            raw: raw.to_string(),
        })?;
        let opcode = parts.next().ok_or_else(|| DecodeError::Parse {
            line: line_no,
            msg: "missing opcode".to_string(),
            raw: raw.to_string(),
        })?;
        let imm = parts
            .next()
            .map(|s| s.trim_start_matches("0x").to_ascii_lowercase());

        let pc = usize::from_str_radix(pc_hex.trim_start_matches("0x"), 16).map_err(|_| {
            DecodeError::Parse {
                line: line_no,
                msg: "invalid PC".to_string(),
                raw: raw.to_string(),
            }
        })?;

        if opcode.is_empty() || opcode.chars().all(|c| !c.is_alphanumeric()) {
            return Err(DecodeError::Parse {
                line: line_no,
                msg: "invalid opcode".to_string(),
                raw: raw.to_string(),
            });
        }

        instructions.push(Instruction {
            pc,
            opcode: opcode.to_string(),
            imm,
        });
    }
    Ok(instructions)
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // pc: six-digit hex, opcode left-padded to 8 chars, then optional imm
        if let Some(imm) = &self.imm {
            write!(f, "{:06x}  {:<8} {}", self.pc, self.opcode, imm)
        } else {
            write!(f, "{:06x}  {}", self.pc, self.opcode)
        }
    }
}

impl Instruction {
    /// Returns the number of bytes this instruction occupies in bytecode.
    ///
    /// This version includes validation and handles edge cases.
    #[inline]
    pub fn byte_size(&self) -> usize {
        match Opcode::from_str(&self.opcode) {
            // Handle PUSH0 specifically (introduced in Shanghai fork)
            Ok(Opcode::PUSH0) => 1, // PUSH0 has no immediate data

            // Handle PUSH1-PUSH32
            Ok(Opcode::PUSH(n)) => 1 + n as usize, // opcode byte + immediate bytes

            // All other EVM instructions (valid or unknown) are single-byte
            _ => 1,
        }
    }
}
