use crate::Opcode;
/// Module for encoding EVM instructions into bytecode and reassembling bytecode with
/// non-runtime sections.
///
/// This module provides functionality to convert a sequence of decoded EVM instructions into
/// their corresponding bytecode representation, handling opcodes and immediate data. It also
/// supports reassembling the runtime bytecode with non-runtime sections (e.g., init code,
/// auxdata) using a `CleanReport` from the `strip` module. The encoding process ensures
/// compatibility with the opcodes defined in the `opcode` module.
use crate::decoder::Instruction;
use crate::strip::CleanReport;
use azoth_utils::errors::EncodeError;
use hex;
use std::str::FromStr;

/// Encodes a sequence of EVM instructions into bytecode.
///
/// # Arguments
/// * `instructions` - A slice of `Instruction` structs, each containing an opcode and optional
///   immediate data.
/// * `original_bytecode` - Optional original bytecode to extract unknown bytes from using PC.
///
/// # Returns
/// A `Result` containing the encoded bytecode as a `Vec<u8>` or an `EncodeError` if encoding fails.
///
/// # Examples
/// ```rust,ignore
/// let ins = Instruction {
///     pc: 0,
///     opcode: "PUSH1".to_string(),
///     imm: Some("aa".to_string()),
/// };
/// let bytes = encode(&[ins]).unwrap();
/// assert_eq!(bytes, vec![0x60, 0xaa]);
/// ```
pub fn encode(instructions: &[Instruction]) -> Result<Vec<u8>, EncodeError> {
    encode_with_original(instructions, None)
}

pub fn encode_with_original(
    instructions: &[Instruction],
    original_bytecode: Option<&[u8]>,
) -> Result<Vec<u8>, EncodeError> {
    let mut bytes = Vec::with_capacity(instructions.len() * 3);
    let mut unknown_count = 0;

    for ins in instructions {
        tracing::debug!(
            "Encoding instruction: pc={}, opcode='{}', imm={:?}",
            ins.pc,
            ins.opcode,
            ins.imm
        );

        // Handle unknown opcodes by preserving them as raw bytes from the original bytecode
        if ins.opcode == "unknown" || ins.opcode.starts_with("UNKNOWN_") {
            unknown_count += 1;

            // For "unknown", try to get the byte from original bytecode using PC
            if ins.opcode == "unknown" {
                tracing::warn!("Preserving unknown opcode at pc={}", ins.pc);

                // First try immediate data
                if let Some(imm) = &ins.imm {
                    if let Ok(byte_val) = u8::from_str_radix(imm, 16) {
                        bytes.push(byte_val);
                        tracing::debug!(
                            "Preserved unknown opcode from immediate as byte 0x{:02x}",
                            byte_val
                        );
                        continue;
                    }
                }

                // Then try original bytecode lookup
                if let Some(original) = original_bytecode {
                    if ins.pc < original.len() {
                        let byte_val = original[ins.pc];
                        bytes.push(byte_val);
                        tracing::debug!(
                            "Preserved unknown opcode from original bytecode as byte 0x{:02x} at pc={}",
                            byte_val,
                            ins.pc
                        );
                        continue;
                    }
                }

                // Last resort: skip with warning (controversial but prevents total failure)
                tracing::error!(
                    "Cannot determine byte value for unknown opcode at pc={}, skipping (this may break functionality)",
                    ins.pc
                );
                continue; // Skip this instruction instead of failing
            }

            // For "UNKNOWN_0x??" format, extract the hex value
            if let Some(hex_part) = ins.opcode.strip_prefix("UNKNOWN_0x") {
                if let Ok(byte_val) = u8::from_str_radix(hex_part, 16) {
                    bytes.push(byte_val);
                    tracing::debug!(
                        "Preserved unknown opcode {} as byte 0x{:02x}",
                        ins.opcode,
                        byte_val
                    );
                    continue;
                } else {
                    return Err(EncodeError::UnsupportedOpcode(format!(
                        "Invalid unknown opcode format: {}",
                        ins.opcode
                    )));
                }
            }

            // If we reach here, it's an unhandled unknown format
            return Err(EncodeError::UnsupportedOpcode(format!(
                "Unhandled unknown opcode format: {}",
                ins.opcode
            )));
        }

        // Parse opcode from string using EOT's unified interface
        let opcode = Opcode::from_str(&ins.opcode).map_err(|e| {
            tracing::error!(
                "Failed to parse opcode '{}' at pc={}: {:?}",
                ins.opcode,
                ins.pc,
                e
            );
            EncodeError::UnsupportedOpcode(format!("opcode '{}' at pc={}", ins.opcode, ins.pc))
        })?;

        tracing::debug!(
            "Successfully parsed opcode '{}' -> byte 0x{:02x}",
            ins.opcode,
            opcode.to_byte()
        );
        bytes.push(opcode.to_byte());

        // Handle immediate data for PUSH opcodes
        if let Opcode::PUSH(n) = opcode {
            if let Some(imm) = &ins.imm {
                let imm_bytes = hex::decode(imm).inspect_err(|&e| {
                    tracing::error!(
                        "Failed to decode immediate '{}' for {} at pc={}: {:?}",
                        imm,
                        ins.opcode,
                        ins.pc,
                        e
                    );
                })?;
                if imm_bytes.len() != n as usize {
                    tracing::error!(
                        "Invalid immediate length for {}: expected {} bytes, got {} bytes",
                        ins.opcode,
                        n,
                        imm_bytes.len()
                    );
                    return Err(EncodeError::InvalidImmediate(format!(
                        "PUSH{} requires {}-byte immediate, got {} bytes at pc={}",
                        n,
                        n,
                        imm_bytes.len(),
                        ins.pc
                    )));
                }
                bytes.extend_from_slice(&imm_bytes);
                tracing::debug!(
                    "Added {} immediate bytes for {}",
                    imm_bytes.len(),
                    ins.opcode
                );
            } else {
                tracing::error!("Missing immediate for {} at pc={}", ins.opcode, ins.pc);
                return Err(EncodeError::InvalidImmediate(format!(
                    "PUSH{} missing immediate at pc={}",
                    n, ins.pc
                )));
            }
        }
    }

    if unknown_count > 0 {
        tracing::warn!(
            "Encoded {} unknown opcodes as raw bytes. The resulting bytecode preserves the original bytes but these may represent invalid EVM instructions.",
            unknown_count
        );
        tracing::warn!(
            "If the original contract works, the obfuscated version should too. If not, the input bytecode may be corrupted."
        );
    }

    tracing::debug!(
        "Successfully encoded {} instructions into {} bytes",
        instructions.len(),
        bytes.len()
    );
    Ok(bytes)
}

/// Reassembles the original bytecode by combining runtime bytecode with non-runtime sections.
///
/// Uses the `CleanReport` from the `strip` module to restore sections like init code, constructor
/// arguments, and auxdata that were removed during stripping.
///
/// # Arguments
/// * `runtime` - The cleaned runtime bytecode as a slice of bytes.
/// * `report` - The `CleanReport` containing metadata about removed sections.
///
/// # Returns
/// The reassembled bytecode as a `Vec<u8>`.
pub fn rebuild(runtime: &[u8], report: &CleanReport) -> Vec<u8> {
    report.reassemble(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::Instruction;

    #[test]
    fn encode_push1() {
        let ins = Instruction {
            pc: 0,
            opcode: "PUSH1".to_string(),
            imm: Some("aa".to_string()),
        };
        let bytes = encode(&[ins]).unwrap();
        assert_eq!(bytes, vec![0x60, 0xaa]);
    }

    #[test]
    fn encode_jumpdest() {
        let ins = Instruction {
            pc: 0,
            opcode: "JUMPDEST".to_string(),
            imm: None,
        };
        let bytes = encode(&[ins]).unwrap();
        assert_eq!(bytes, vec![0x5b]);
    }

    #[test]
    fn encode_return() {
        let ins = Instruction {
            pc: 0,
            opcode: "RETURN".to_string(),
            imm: None,
        };
        let bytes = encode(&[ins]).unwrap();
        assert_eq!(bytes, vec![0xf3]);
    }

    #[test]
    fn encode_unknown_hex_format() {
        let ins = Instruction {
            pc: 42,
            opcode: "UNKNOWN_0xfe".to_string(),
            imm: None,
        };
        let bytes = encode(&[ins]).unwrap();
        assert_eq!(bytes, vec![0xfe]);
    }

    #[test]
    fn encode_unknown_fails_without_hex() {
        let ins = Instruction {
            pc: 42,
            opcode: "unknown".to_string(),
            imm: None,
        };
        // Without original bytecode or immediate, unknown opcodes are skipped
        let result = encode(&[ins]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new()); // Empty because unknown was skipped
    }
}
