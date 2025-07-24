use azoth_transform::jump_address_transformer::JumpAddressTransformer;
use azoth_transform::{PassConfig, Transform};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[tokio::test]
async fn test_jump_address_transformer() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Simple bytecode with a conditional jump
    let bytecode = "0x60085760015b00"; // PUSH1 0x08, JUMPI, PUSH1 0x01, JUMPDEST, STOP
    let mut cfg_ir = azoth_core::process_bytecode_to_cfg_only(bytecode, false)
        .await
        .unwrap();

    // Count instructions before transformation
    let mut instruction_count_before = 0;
    for node_idx in cfg_ir.cfg.node_indices() {
        if let azoth_core::cfg_ir::Block::Body { instructions, .. } = &cfg_ir.cfg[node_idx] {
            instruction_count_before += instructions.len();
        }
    }

    let mut rng = StdRng::seed_from_u64(42);

    // Use a config that allows the transformation
    let config = PassConfig {
        max_size_delta: 1.0, // Allow all jumps to be transformed
        ..Default::default()
    };
    let transform = JumpAddressTransformer::new(config);

    let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();
    assert!(changed, "JumpAddressTransformer should modify bytecode");

    // Count instructions after transformation
    let mut instruction_count_after = 0;
    for node_idx in cfg_ir.cfg.node_indices() {
        if let azoth_core::cfg_ir::Block::Body { instructions, .. } = &cfg_ir.cfg[node_idx] {
            instruction_count_after += instructions.len();
        }
    }

    // Should have more instructions after transformation
    assert!(
        instruction_count_after > instruction_count_before,
        "Instruction count should increase: before={}, after={}",
        instruction_count_before,
        instruction_count_after
    );

    // Verify we added exactly 2 more instructions (1 PUSH was replaced with 2 PUSH + 1 ADD = net +2)
    assert_eq!(
        instruction_count_after,
        instruction_count_before + 2,
        "Should add exactly 2 instructions"
    );
}

#[test]
fn test_split_jump_target() {
    let mut rng = StdRng::seed_from_u64(42);
    let config = PassConfig::default();
    let transformer = JumpAddressTransformer::new(config);

    let target = 0x100;
    let (part1, part2) = transformer.split_jump_target(target, &mut rng);

    assert_eq!(
        part1 + part2,
        target,
        "Split parts should sum to original target"
    );
    assert!(part1 < target, "First part should be less than target");
    assert!(part1 > 0, "First part should be greater than 0");
}

#[test]
fn test_push_opcode_sizing() {
    let config = PassConfig::default();
    let transformer = JumpAddressTransformer::new(config);

    assert_eq!(transformer.get_push_opcode_for_value(0x42), "PUSH1");
    assert_eq!(transformer.get_push_opcode_for_value(0x1234), "PUSH2");
    assert_eq!(transformer.get_push_opcode_for_value(0x123456), "PUSH3");
}
