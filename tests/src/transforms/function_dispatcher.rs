use azoth_core::cfg_ir::Block;
use azoth_core::decoder::Instruction;
use azoth_core::detection::FunctionSelector;
use azoth_core::{decoder, detection, process_bytecode_to_cfg_only, Opcode};
use azoth_transform::function_dispatcher::FunctionDispatcher;
use azoth_transform::obfuscator::obfuscate_bytecode;
use azoth_transform::obfuscator::ObfuscationConfig;
use azoth_transform::{PassConfig, Transform};
use azoth_utils::seed::Seed;

/// Pretty-print dispatcher sections for debugging
#[cfg(test)]
fn print_dispatcher_section(instructions: &[Instruction], start: usize, end: usize) -> String {
    let mut result = String::new();
    for (i, instr) in instructions[start..end].iter().enumerate() {
        result.push_str(&format!(
            "{:3}: {} {}\n",
            start + i,
            instr.opcode,
            instr.imm.as_deref().unwrap_or("")
        ));
    }
    result
}

#[test]
fn test_opcode_type_safety() {
    let config = PassConfig::default();
    let transform = FunctionDispatcher::new(config);

    // Test that we can create instructions safely using Opcode enum
    let push_instr = transform
        .create_instruction(Opcode::PUSH(1), Some("42".to_string()))
        .unwrap();
    assert_eq!(push_instr.opcode, "PUSH1");
    assert_eq!(push_instr.imm, Some("42".to_string()));

    let jump_instr = transform.create_instruction(Opcode::JUMP, None).unwrap();
    assert_eq!(jump_instr.opcode, "JUMP");
    assert_eq!(jump_instr.imm, None);

    // Test PUSH instruction creation with auto-sizing
    let push4_instr = transform
        .create_push_instruction(0x12345678, Some(4))
        .unwrap();
    assert_eq!(push4_instr.opcode, "PUSH4");
    assert_eq!(push4_instr.imm, Some("12345678".to_string()));

    // Test auto-sizing
    let auto_push_instr = transform.create_push_instruction(0x42, None).unwrap();
    assert_eq!(auto_push_instr.opcode, "PUSH1");
    assert_eq!(auto_push_instr.imm, Some("42".to_string()));
}

#[test]
fn test_token_generation() {
    let config = PassConfig::default();
    let transform = FunctionDispatcher::new(config);
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();

    let selectors = vec![
        FunctionSelector {
            selector: 0xa9059cbb, // transfer(address,uint256)
            target_address: 0x1234,
            instruction_index: 0,
        },
        FunctionSelector {
            selector: 0x095ea7b3, // approve(address,uint256)
            target_address: 0x5678,
            instruction_index: 10,
        },
    ];

    let mapping = transform.generate_mapping(&selectors, &mut rng).unwrap();

    // Should have mapping for both selectors
    assert_eq!(mapping.len(), 2);
    assert!(mapping.contains_key(&0xa9059cbb));
    assert!(mapping.contains_key(&0x095ea7b3));

    // Tokens should be different (no collisions)
    let token1 = mapping[&0xa9059cbb];
    let token2 = mapping[&0x095ea7b3];
    assert_ne!(token1, token2, "Tokens should be unique");

    println!("Generated mapping:");
    println!("  0xa9059cbb -> 0x{:02x}", token1);
    println!("  0x095ea7b3 -> 0x{:02x}", token2);
}

#[tokio::test]
async fn test_dispatcher_detection() {
    let config = PassConfig::default();
    let transform = FunctionDispatcher::new(config);

    let mut instructions = vec![
        // Calldata extraction
        transform
            .create_instruction(Opcode::PUSH(1), Some("00".to_string()))
            .unwrap(),
        transform
            .create_instruction(Opcode::CALLDATALOAD, None)
            .unwrap(),
        transform
            .create_instruction(Opcode::PUSH(1), Some("e0".to_string()))
            .unwrap(),
        transform.create_instruction(Opcode::SHR, None).unwrap(),
        // Function selector check 1
        transform.create_instruction(Opcode::DUP(1), None).unwrap(),
        transform
            .create_instruction(Opcode::PUSH(4), Some("c2985578".to_string()))
            .unwrap(),
        transform.create_instruction(Opcode::EQ, None).unwrap(),
        transform
            .create_instruction(Opcode::PUSH(2), Some("0080".to_string()))
            .unwrap(),
        transform.create_instruction(Opcode::JUMPI, None).unwrap(),
        // Function selector check 2
        transform.create_instruction(Opcode::DUP(1), None).unwrap(),
        transform
            .create_instruction(Opcode::PUSH(4), Some("12345678".to_string()))
            .unwrap(),
        transform.create_instruction(Opcode::EQ, None).unwrap(),
        transform
            .create_instruction(Opcode::PUSH(2), Some("0100".to_string()))
            .unwrap(),
        transform.create_instruction(Opcode::JUMPI, None).unwrap(),
        // Revert
        transform
            .create_instruction(Opcode::PUSH(1), Some("00".to_string()))
            .unwrap(),
        transform.create_instruction(Opcode::DUP(1), None).unwrap(),
        transform.create_instruction(Opcode::REVERT, None).unwrap(),
    ];

    // Set sequential PCs
    for (i, instr) in instructions.iter_mut().enumerate() {
        instr.pc = i * 2; // Simplified PC assignment
    }

    let detection_result = transform.detect_dispatcher(&instructions);
    assert!(detection_result.is_some());

    let (start, _end, selectors) = detection_result.unwrap();
    assert_eq!(start, 0);

    println!("Found {} selectors: {:?}", selectors.len(), selectors);
    assert_eq!(selectors.len(), 2);

    assert_eq!(selectors[0].selector, 0xc2985578);
    assert_eq!(selectors[1].selector, 0x12345678);

    println!("Original dispatcher:");
    println!(
        "{}",
        print_dispatcher_section(&instructions, start, instructions.len())
    );
}

#[tokio::test]
async fn test_token_dispatcher_transformation() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok();

    // Use the example bytecode with exposed selectors
    let bytecode =
        "0x60003560e01c80637ff36ab514601a578063a9059cbb14602157600080fd5b600080fd5b600080fd";

    println!("Input bytecode: {}", bytecode);

    // Decode and analyze original structure
    let (instructions, _, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();

    println!("\nOriginal dispatcher structure:");
    for (i, instr) in instructions.iter().enumerate() {
        if instr.opcode.starts_with("PUSH4") {
            println!(
                "  [{}] {} {} ← EXPOSED SELECTOR",
                i,
                instr.opcode,
                instr.imm.as_deref().unwrap_or("")
            );
        } else {
            println!(
                "  [{}] {} {}",
                i,
                instr.opcode,
                instr.imm.as_deref().unwrap_or("")
            );
        }
    }

    // Detect selectors
    if let Some(dispatcher_info) = detection::detect_function_dispatcher(&instructions) {
        println!("\nDetected selectors:");
        for selector in &dispatcher_info.selectors {
            println!(
                "  0x{:08x} -> jump target 0x{:x}",
                selector.selector, selector.target_address
            );
        }
    }

    // Apply token-based obfuscation
    let config = ObfuscationConfig::default();
    let result = obfuscate_bytecode(bytecode, config).await.unwrap();

    println!("\nTransformation result:");
    println!("  Original: {} bytes", result.original_size);
    println!("  Obfuscated: {} bytes", result.obfuscated_size);
    println!("  Size change: {:+.1}%", result.size_increase_percentage);
    println!("  Transforms: {:?}", result.metadata.transforms_applied);

    // Verify transformation was applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher should be applied"
    );

    assert_ne!(
        result.obfuscated_bytecode, bytecode,
        "Bytecode should be modified"
    );

    // Decode obfuscated bytecode to verify tokens replaced selectors
    let (obfuscated_instructions, _, _) =
        decoder::decode_bytecode(&result.obfuscated_bytecode, false)
            .await
            .unwrap();

    println!("\nObfuscated dispatcher structure:");
    for (i, instr) in obfuscated_instructions.iter().enumerate() {
        if instr.opcode == "PUSH1"
            && instr
                .imm
                .as_ref()
                .map_or(false, |imm| imm != "00" && imm != "ff")
        {
            println!(
                "  [{}] {} {} ← HIDDEN TOKEN",
                i,
                instr.opcode,
                instr.imm.as_deref().unwrap_or("")
            );
        } else {
            println!(
                "  [{}] {} {}",
                i,
                instr.opcode,
                instr.imm.as_deref().unwrap_or("")
            );
        }
    }

    // Verify no PUSH4 selectors remain
    let push4_count = obfuscated_instructions
        .iter()
        .filter(|instr| instr.opcode == "PUSH4")
        .count();

    assert_eq!(
        push4_count, 0,
        "No PUSH4 instructions should remain in obfuscated dispatcher"
    );

    println!("\n✓ Selectors successfully replaced with tokens");
    println!("✓ No PUSH4 instructions remain in dispatcher");
    println!("✓ Function fingerprinting prevented");
}

#[tokio::test]
async fn test_internal_call_updates() {
    let config = PassConfig::default();
    let transform = FunctionDispatcher::new(config);
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();

    // Create CFG with PUSH4 + CALL pattern
    let bytecode = "0x63a9059cbbf163095ea7b3f1"; // PUSH4 selector1 CALL PUSH4 selector2 CALL
    let mut cfg_ir = process_bytecode_to_cfg_only(bytecode, false).await.unwrap();

    // Create selector mapping
    let selectors = vec![
        FunctionSelector {
            selector: 0xa9059cbb,
            target_address: 0x1234,
            instruction_index: 0,
        },
        FunctionSelector {
            selector: 0x095ea7b3,
            target_address: 0x5678,
            instruction_index: 3,
        },
    ];

    let mapping = transform.generate_mapping(&selectors, &mut rng).unwrap();

    // Apply internal call updates
    transform
        .update_internal_calls(&mut cfg_ir, &mapping)
        .unwrap();

    // Verify PUSH4 instructions were replaced with PUSH1
    for node_idx in cfg_ir.cfg.node_indices() {
        if let Block::Body { instructions, .. } = &cfg_ir.cfg[node_idx] {
            for instr in instructions {
                // Should not find any PUSH4 instructions
                assert_ne!(
                    instr.opcode, "PUSH4",
                    "PUSH4 instructions should be replaced"
                );
            }
        }
    }

    println!("✓ Internal CALL instructions successfully updated to use tokens");
}

#[tokio::test]
async fn test_pc_integrity_integration() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok();

    let bytecode =
        "0x60003560e01c80637ff36ab514601a578063a9059cbb14602157600080fd5b600080fd5b600080fd";
    let mut cfg_ir = process_bytecode_to_cfg_only(bytecode, false).await.unwrap();

    let config = PassConfig::default();
    let transform = FunctionDispatcher::new(config);
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();

    // Apply the transform
    let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();

    if changed {
        // Verify PC integrity after transformation
        let mut current_pc = 0;
        let mut all_pcs_sequential = true;

        // Check that PCs are sequential across all blocks
        for node_idx in cfg_ir.cfg.node_indices() {
            if let Block::Body {
                instructions,
                start_pc,
                ..
            } = &cfg_ir.cfg[node_idx]
            {
                if *start_pc != current_pc {
                    all_pcs_sequential = false;
                    break;
                }

                for instr in instructions {
                    if instr.pc != current_pc {
                        all_pcs_sequential = false;
                        break;
                    }
                    current_pc += if instr.opcode.starts_with("PUSH") {
                        if let Some(Ok(push_size)) = instr
                            .opcode
                            .strip_prefix("PUSH")
                            .and_then(|s| Some(s.parse::<usize>()))
                        {
                            1 + push_size
                        } else {
                            1
                        }
                    } else {
                        1
                    };
                }

                if !all_pcs_sequential {
                    break;
                }
            }
        }

        assert!(
            all_pcs_sequential,
            "PCs should be sequential after reindexing"
        );

        // Verify pc_to_block mapping is consistent
        for (pc, &node_idx) in &cfg_ir.pc_to_block {
            if let Block::Body { start_pc, .. } = &cfg_ir.cfg[node_idx] {
                assert_eq!(*pc, *start_pc, "pc_to_block mapping should be consistent");
            }
        }

        tracing::debug!("PC integrity verified after token dispatcher transformation");
    }
}

#[tokio::test]
async fn test_obfuscate_with_token_dispatcher() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok();

    // Use the example bytecode with exposed selectors
    let bytecode =
        "0x60003560e01c80637ff36ab514601a578063a9059cbb14602157600080fd5b600080fd5b600080fd";
    let config = ObfuscationConfig::default();

    tracing::debug!("Testing token-based dispatcher with bytecode: {}", bytecode);

    // Analyze original bytecode
    let (instructions, _, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    tracing::debug!("Original bytecode has {} instructions", instructions.len());

    // Count original PUSH4 instructions (exposed selectors)
    let original_push4_count = instructions
        .iter()
        .filter(|instr| instr.opcode == "PUSH4")
        .count();

    tracing::debug!("Original PUSH4 count: {}", original_push4_count);

    // Test dispatcher detection
    let dispatcher_detected = detection::has_dispatcher(&instructions);
    tracing::debug!("Dispatcher detected: {}", dispatcher_detected);

    if let Some(dispatcher_info) = detection::detect_function_dispatcher(&instructions) {
        tracing::debug!(
            "Found {} selectors in dispatcher",
            dispatcher_info.selectors.len()
        );
        for selector in &dispatcher_info.selectors {
            tracing::debug!("  Selector: 0x{:08x}", selector.selector);
        }
    }

    // Apply obfuscation
    let result = obfuscate_bytecode(bytecode, config).await.unwrap();

    tracing::debug!("Obfuscation completed:");
    tracing::debug!("  Original: {}", bytecode);
    tracing::debug!("  Obfuscated: {}", result.obfuscated_bytecode);
    tracing::debug!("  Size change: {:+.1}%", result.size_increase_percentage);

    // Should apply FunctionDispatcher transform
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher transform should be applied"
    );

    // Bytecode should be different
    assert_ne!(
        result.obfuscated_bytecode, bytecode,
        "Obfuscated bytecode should differ from original"
    );

    // Verify transformation: decode obfuscated bytecode
    let (obfuscated_instructions, _, _) =
        decoder::decode_bytecode(&result.obfuscated_bytecode, false)
            .await
            .unwrap();

    // Count PUSH4 in obfuscated version (should be 0 in dispatcher)
    let obfuscated_push4_count = obfuscated_instructions
        .iter()
        .filter(|instr| instr.opcode == "PUSH4")
        .count();

    tracing::debug!("Obfuscated PUSH4 count: {}", obfuscated_push4_count);

    // In dispatcher region, PUSH4 should be replaced with PUSH1
    assert!(
        obfuscated_push4_count < original_push4_count,
        "PUSH4 count should be reduced (selectors replaced with tokens)"
    );

    tracing::debug!("✓ Function selectors hidden from bytecode analysis");
}
