use crate::decoder::Instruction;
use crate::opcode::Opcode;
use crate::strip::CleanReport;
use hex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("invalid immediate: {0}")]
    InvalidImmediate(String),
    #[error("unsupported opcode: {0}")]
    UnsupportedOpcode(String),
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

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
                    return Err(EncodeError::InvalidImmediate(
                        format!("PUSH{} requires {}-byte immediate", n, n),
                    ));
                }
                bytes.extend_from_slice(&imm_bytes);
            } else {
                return Err(EncodeError::InvalidImmediate(
                    format!("PUSH{} missing immediate", n),
                ));
            }
        }
    }
    Ok(bytes)
}

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
