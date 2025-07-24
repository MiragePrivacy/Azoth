use azoth_core::decoder::{
    decode_bytecode, decode_bytecode_from_bytes, parse_assembly, SourceType,
};
use azoth_utils::errors::DecodeError;
use heimdall::{disassemble, DisassemblerArgsBuilder};
use std::io::Write;

#[allow(dead_code)]
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
async fn test_decode_from_bytes() {
    let bytes = hex::decode(BYTECODE.trim_start_matches("0x")).unwrap();
    let (ins, info, asm) = decode_bytecode_from_bytes(&bytes, SourceType::HexString)
        .await
        .unwrap();

    tracing::debug!("\nRaw assembly from bytes:\n{}", asm);
    tracing::debug!("Parsed instructions from bytes:");
    for instr in &ins {
        tracing::debug!("{}", instr);
    }
    assert_eq!(ins.len(), 5);

    assert_eq!(info.byte_length, bytes.len());
    assert_eq!(info.source, SourceType::HexString);
    assert!(!info.keccak_hash.is_empty());

    // Test with different source type
    let (ins2, info2, _) = decode_bytecode_from_bytes(&bytes, SourceType::File)
        .await
        .unwrap();
    assert_eq!(ins2, ins); // Instructions should be identical
    assert_eq!(info2.byte_length, info.byte_length);
    assert_eq!(info2.keccak_hash, info.keccak_hash);
    assert_eq!(info2.source, SourceType::File); // Source should be different
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
