//! bytecloak’s single entry-point for turning byte-sequences into Heimdall instruction streams.
use heimdall::{DisassemblerArgsBuilder, disassemble};
use hex::FromHex;
use std::{fmt, fs, path::Path};
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

/// Represents a single disassembled instruction.
#[derive(Clone, Debug, PartialEq)]
pub struct Instruction {
    /// the instruction’s program counter (in bytes)
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
    OnChain, // placeholder for future on-chain fetch
}

/// Custom error type for decoding operations.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("hex decode failed: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("could not read file '{path}': {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("heimdall disassembly failed: {0}")]
    Heimdall(String),

    #[error("assembly parse error at line {line}: {msg} ⇒ `{raw}`")]
    Parse {
        line: usize,
        msg: String,
        raw: String,
    },
}

/// Normalizes input into a byte vector from hex string or file.
fn input_to_bytes(input: &str, is_file: bool) -> Result<Vec<u8>, DecodeError> {
    if is_file {
        let path = Path::new(input);
        fs::read(path).map_err(|e| DecodeError::FileRead {
            path: path.display().to_string(),
            source: e,
        })
    } else {
        let clean = input.strip_prefix("0x").unwrap_or(input);
        Vec::from_hex(clean).map_err(DecodeError::HexDecode)
    }
}

/// Decodes raw EVM bytecode into an instruction stream with metadata and raw assembly.
///
/// # Arguments
/// * `input` - A hex string or file path representing the EVM bytecode.
/// * `is_file` - Flag indicating if the input is a file path (false for hex string).
///
/// # Returns
/// A tuple of (InstructionStream, DecodeInfo, raw assembly string), or an error if decoding fails.
pub async fn decode_bytecode(
    input: &str,
    is_file: bool,
) -> Result<(Vec<Instruction>, DecodeInfo, String), DecodeError> {
    // 1. Normalize input to bytes
    let bytes = input_to_bytes(input, is_file)?;

    // 2. Compute metadata
    let byte_length = bytes.len();
    let mut keccak = Keccak::v256();
    keccak.update(&bytes);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    let source = if is_file {
        SourceType::File
    } else {
        SourceType::HexString
    };

    // 3. Configure and run heimdall disassembly
    let target_arg = format!("0x{}", hex::encode(&bytes));

    let args = DisassemblerArgsBuilder::new()
        .target(target_arg)
        .output("print".into())
        .decimal_counter(false) // Hexadecimal PCs
        .build()
        .map_err(|e| DecodeError::Heimdall(e.to_string()))?;

    let asm = disassemble(args)
        .await
        .map_err(|e| DecodeError::Heimdall(e.to_string()))?;

    // 4. Parse assembly into structured instructions
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

/// Parses the assembly string into a vector of Instructions.
///
/// Handles lines like "0x0003 PUSH1 0x60 # comment" and skips labels (e.g., "label_0000:") or blank
/// lines.
fn parse_assembly(asm: &str) -> Result<Vec<Instruction>, DecodeError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tokio;

    // Fixture: PUSH1 0x01, PUSH1 0x02, ADD, STOP
    const BYTECODE: &str = "0x6001600201600057";

    #[tokio::test]
    async fn test_hex_roundtrip() {
        let (ins, info, asm) = decode_bytecode(BYTECODE, false).await.unwrap();
        tracing::debug!("\nRaw assembly:\n{}", asm);
        tracing::debug!("Parsed instructions:");
        for instr in &ins {
            tracing::debug!("{}", instr);
        }
        assert_eq!(ins.len(), 5);

        let expected_bytes = BYTECODE.trim_start_matches("0x").len() / 2;
        assert_eq!(info.byte_length, expected_bytes);

        assert_eq!(info.source, SourceType::HexString);
        assert!(!info.keccak_hash.is_empty());
    }

    #[tokio::test]
    async fn test_file_input() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&hex::decode(BYTECODE.trim_start_matches("0x")).unwrap())
            .unwrap();
        let path = tmp.path().to_str().unwrap();

        let (ins_file, info_file, asm) = decode_bytecode(path, true).await.unwrap();
        tracing::debug!("\nRaw assembly from heimdall (file):\n{}", asm);
        tracing::debug!("Parsed instructions (file):");
        for instr in &ins_file {
            tracing::debug!("{}", instr);
        }
        let (ins_hex, info_hex, _) = decode_bytecode(BYTECODE, false).await.unwrap();

        assert_eq!(ins_file, ins_hex);
        assert_eq!(info_file.byte_length, info_hex.byte_length);
        assert_eq!(info_file.source, SourceType::File);
    }

    #[tokio::test]
    async fn test_bad_hex_fails() {
        let result = decode_bytecode("0xZZ42", false).await;
        assert!(matches!(result, Err(DecodeError::HexDecode(_))));
    }

    #[tokio::test]
    async fn test_invalid_assembly_fails() {
        let args = DisassemblerArgsBuilder::new()
            .target("0x".to_string()) // Empty bytecode
            .output("print".into())
            .build()
            .unwrap();
        let asm = disassemble(args)
            .await
            .map_err(|e| DecodeError::Heimdall(e.to_string()));
        match asm {
            Ok(asm) => {
                tracing::debug!("\nRaw assembly from invalid input:\n{}", asm);
                let result = parse_assembly(&asm);
                assert!(matches!(result, Err(DecodeError::Parse { .. })));
            }
            Err(e) => assert!(matches!(e, DecodeError::Heimdall(_))),
        }
    }
}
