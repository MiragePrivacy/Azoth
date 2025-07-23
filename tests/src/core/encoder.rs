use azoth_core::decoder::Instruction;
use azoth_core::encoder::encode;

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
