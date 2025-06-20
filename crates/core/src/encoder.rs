use crate::decoder::Instruction;
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
        match ins.opcode.as_str() {
            "PUSH1" => {
                bytes.push(0x60);
                if let Some(imm) = &ins.imm {
                    let imm_bytes = hex::decode(imm)?;
                    if imm_bytes.len() != 1 {
                        return Err(EncodeError::InvalidImmediate(
                            "PUSH1 requires 1-byte immediate".to_string(),
                        ));
                    }
                    bytes.extend_from_slice(&imm_bytes);
                } else {
                    return Err(EncodeError::InvalidImmediate(
                        "PUSH1 missing immediate".to_string(),
                    ));
                }
            }
            "PUSH2" => {
                bytes.push(0x61);
                if let Some(imm) = &ins.imm {
                    let imm_bytes = hex::decode(imm)?;
                    if imm_bytes.len() != 2 {
                        return Err(EncodeError::InvalidImmediate(
                            "PUSH2 requires 2-byte immediate".to_string(),
                        ));
                    }
                    bytes.extend_from_slice(&imm_bytes);
                } else {
                    return Err(EncodeError::InvalidImmediate(
                        "PUSH2 missing immediate".to_string(),
                    ));
                }
            }
            "PUSH32" => {
                bytes.push(0x7f);
                if let Some(imm) = &ins.imm {
                    let imm_bytes = hex::decode(imm)?;
                    if imm_bytes.len() != 32 {
                        return Err(EncodeError::InvalidImmediate(
                            "PUSH32 requires 32-byte immediate".to_string(),
                        ));
                    }
                    bytes.extend_from_slice(&imm_bytes);
                } else {
                    return Err(EncodeError::InvalidImmediate(
                        "PUSH32 missing immediate".to_string(),
                    ));
                }
            }
            "JUMPDEST" => bytes.push(0x5b),
            "JUMP" => bytes.push(0x56),
            "JUMPI" => bytes.push(0x57),
            "STOP" => bytes.push(0x00),
            "ADD" => bytes.push(0x01),
            "POP" => bytes.push(0x50),
            "EQ" => bytes.push(0x14),
            "DUP1" => bytes.push(0x80),
            "DUP2" => bytes.push(0x81),
            "AND" => bytes.push(0x16),
            "OR" => bytes.push(0x17),
            "MUL" => bytes.push(0x02),
            "MSTORE" => bytes.push(0x52),
            "ADDRESS" => bytes.push(0x30),
            "SSTORE" => bytes.push(0x55),
            _ => return Err(EncodeError::UnsupportedOpcode(ins.opcode.clone())),
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
}
