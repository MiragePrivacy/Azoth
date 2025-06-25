/// Module for encoding EVM instructions into bytecode and reassembling bytecode with
/// non-runtime sections.
///
/// This module provides functionality to convert a sequence of decoded EVM instructions into
/// their corresponding bytecode representation, handling opcodes and immediate data. It also
/// supports reassembling the runtime bytecode with non-runtime sections (e.g., init code,
/// auxdata) using a `CleanReport` from the `strip` module. The encoding process ensures
/// compatibility with the opcodes defined in the `opcode` module.
use crate::decoder::Instruction;
use crate::opcode::Opcode;
use crate::strip::CleanReport;
use bytecloak_utils::errors::EncodeError;
use hex;

/// Encodes a sequence of EVM instructions into bytecode.
///
/// # Arguments
/// * `instructions` - A slice of `Instruction` structs, each containing an opcode and optional
///   immediate data.
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
    let mut bytes = Vec::with_capacity(instructions.len() * 3);
    for ins in instructions {
        let opcode = match ins.opcode.as_str() {
            "PUSH1" => Opcode::PUSH(1),
            "PUSH2" => Opcode::PUSH(2),
            "PUSH32" => Opcode::PUSH(32),
            "JUMPDEST" => Opcode::JUMPDEST,
            "JUMP" => Opcode::JUMP,
            "JUMPI" => Opcode::JUMPI,
            "STOP" => Opcode::STOP,
            "ADD" => Opcode::ADD,
            "POP" => Opcode::POP,
            "EQ" => Opcode::EQ,
            "DUP1" => Opcode::DUP(1),
            "DUP2" => Opcode::DUP(2),
            "AND" => Opcode::AND,
            "OR" => Opcode::OR,
            "MUL" => Opcode::MUL,
            "MSTORE" => Opcode::MSTORE,
            "ADDRESS" => Opcode::ADDRESS,
            "SSTORE" => Opcode::SSTORE,
            "SUB" => Opcode::SUB,
            "DIV" => Opcode::DIV,
            "LT" => Opcode::LT,
            "GT" => Opcode::GT,
            "ISZERO" => Opcode::ISZERO,
            "XOR" => Opcode::XOR,
            "BALANCE" => Opcode::BALANCE,
            "MLOAD" => Opcode::MLOAD,
            "MSTORE8" => Opcode::MSTORE8,
            "SLOAD" => Opcode::SLOAD,
            "RETURN" => Opcode::RETURN,
            "REVERT" => Opcode::REVERT,
            "INVALID" => Opcode::INVALID,
            "SELFDESTRUCT" => Opcode::SELFDESTRUCT,
            "SWAP1" => Opcode::SWAP(1),
            "SWAP2" => Opcode::SWAP(2),
            _ => return Err(EncodeError::UnsupportedOpcode(ins.opcode.clone())),
        };

        bytes.push(opcode.to_byte());

        // Handle immediate data for PUSH opcodes
        if let Opcode::PUSH(n) = opcode {
            if let Some(imm) = &ins.imm {
                let imm_bytes = hex::decode(imm)?;
                if imm_bytes.len() != n as usize {
                    return Err(EncodeError::InvalidImmediate(format!(
                        "PUSH{} requires {}-byte immediate",
                        n, n
                    )));
                }
                bytes.extend_from_slice(&imm_bytes);
            } else {
                return Err(EncodeError::InvalidImmediate(format!(
                    "PUSH{} missing immediate",
                    n
                )));
            }
        }
    }
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
}
