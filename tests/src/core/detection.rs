use azoth_core::{
    decoder::{decode_bytecode, DecodeInfo, Instruction, SourceType},
    detection::{locate_sections, validate_sections, Section, SectionKind},
};
use azoth_utils::errors::DetectError;

#[tokio::test]
async fn test_locate_sections_with_auxdata() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let bytecode = "0xa165627a7a720000"; // Simplified Auxdata example
    let (instructions, info, _) = decode_bytecode(bytecode, false).await.unwrap();
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
    let bytes = vec![0; 10];
    let total_len = bytes.len();
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
    let result = validate_sections(&mut simulated_sections, total_len);
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

    let (instructions, info, _) = decode_bytecode(bytecode, false).await.unwrap();
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
    let (instructions, info, _) = decode_bytecode(&format!("0x{}", hex), false).await.unwrap();
    let bytes = hex::decode(hex).unwrap();
    let sections = locate_sections(&bytes, &instructions, &info).unwrap();
    let rt = sections
        .iter()
        .find(|s| s.kind == SectionKind::Runtime)
        .unwrap();
    assert_eq!(rt.len, 5); // 5-byte program
    assert!(sections.iter().any(|s| s.kind == SectionKind::Padding));
}
