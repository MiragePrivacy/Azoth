use azoth_core::cfg_ir::Block;
use azoth_core::decoder::Instruction;
use azoth_core::detection::FunctionSelector;
use azoth_core::{decoder, detection, process_bytecode_to_cfg_only, Opcode};
use azoth_transform::function_dispatcher::{DispatcherPattern, FunctionDispatcher};
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

#[tokio::test]
async fn test_dispatcher_detection() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

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

#[test]
fn test_dummy_selector_generation_safety() {
    let config = PassConfig::default();
    let transform = FunctionDispatcher::new(config);
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();

    let real_selectors = vec![
        FunctionSelector {
            selector: 0x12345678,
            target_address: 0x100,
            instruction_index: 0,
        },
        FunctionSelector {
            selector: 0x87654321,
            target_address: 0x200,
            instruction_index: 10,
        },
    ];

    // Should always succeed even with many existing selectors
    for _ in 0..100 {
        let dummy = transform.generate_dummy_selector(&real_selectors, &mut rng);
        assert_ne!(dummy, 0x12345678);
        assert_ne!(dummy, 0x87654321);
    }
}

#[test]
fn test_stack_depth_calculation() {
    let config = PassConfig::default();
    let transform = FunctionDispatcher::new(config);

    assert_eq!(
        transform.calculate_stack_depth(&DispatcherPattern::Standard),
        2
    );
    assert_eq!(
        transform.calculate_stack_depth(&DispatcherPattern::Arithmetic),
        3
    );
    assert_eq!(
        transform.calculate_stack_depth(&DispatcherPattern::Inverted),
        3
    );
    assert_eq!(
        transform.calculate_stack_depth(&DispatcherPattern::Cascaded),
        4
    );
}

#[tokio::test]
async fn test_pc_integrity_integration() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Create a simple bytecode with a dispatcher-like pattern
    let bytecode = "0x6000356020527f63c29855780817ffffffffffffffffffffffffffffffff5b";
    let mut cfg_ir = process_bytecode_to_cfg_only(bytecode, false).await.unwrap();

    // Get original PC count
    let _original_total_size = cfg_ir
        .cfg
        .node_indices()
        .filter_map(|idx| {
            if let Block::Body { instructions, .. } = &cfg_ir.cfg[idx] {
                Some(instructions.len())
            } else {
                None
            }
        })
        .sum::<usize>();

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

        tracing::debug!("PC integrity verified after dispatcher transformation");
    }
}

#[tokio::test]
async fn test_obfuscate_with_function_dispatcher() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok(); // Ignore if already initialized

    // Bytecode with function dispatcher pattern
    let bytecode = "0x60003580632e64cec114601757806360fe47b1146019575b005b00";
    let config = ObfuscationConfig::default();

    tracing::debug!("Testing bytecode: {}", bytecode);

    // Let's first decode and analyze the bytecode manually
    let (instructions, _, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    tracing::debug!("Decoded {} instructions", instructions.len());

    for (i, instr) in instructions.iter().enumerate() {
        tracing::debug!("  [{}] PC:{} {} {:?}", i, instr.pc, instr.opcode, instr.imm);
    }

    // Test dispatcher detection directly
    let dispatcher_detected = detection::has_dispatcher(&instructions);
    tracing::debug!("Dispatcher detected: {}", dispatcher_detected);

    if let Some(dispatcher_info) = detection::detect_function_dispatcher(&instructions) {
        tracing::debug!("Dispatcher info: {:?}", dispatcher_info);
    } else {
        tracing::debug!("No dispatcher info found");
    }

    let result = obfuscate_bytecode(bytecode, config).await.unwrap();

    tracing::debug!("Obfuscation result:");
    tracing::debug!("  Original: {}", bytecode);
    tracing::debug!("  Obfuscated: {}", result.obfuscated_bytecode);
    tracing::debug!(
        "  Transforms applied: {:?}",
        result.metadata.transforms_applied
    );
    tracing::debug!("  Instructions added: {}", result.instructions_added);
    tracing::debug!("  Blocks created: {}", result.blocks_created);

    // Should detect dispatcher and apply FunctionDispatcher transform
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher transform was not applied. Applied transforms: {:?}",
        result.metadata.transforms_applied
    );
    assert!(
        result.obfuscated_bytecode != bytecode,
        "Bytecode was not modified"
    );
    assert!(
        result.instructions_added > 0 || result.blocks_created > 0,
        "No instructions added or blocks created"
    );
}
