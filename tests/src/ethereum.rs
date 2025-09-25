//! End to end ethereum tests.
//!
//! Test variations of obfuscation options:
//!   - Function dispatch only (all options off)
//!   - Each transformation type enabled
//!   - Each combination of 2 transformations
//!   - All options enabled
//!
//! Each test case should assert that the contract is deployable on the anvil instance
//! TODO: use a wrapper around alloy transactions to call obfuscated selectors after deploying

use alloy::hex;
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use azoth_transform::jump_address_transformer::JumpAddressTransformer;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::opaque_predicate::OpaquePredicate;
use azoth_transform::shuffle::Shuffle;
use azoth_transform::{PassConfig, Transform};
use azoth_utils::seed::Seed;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use std::str::FromStr;

// Simple ERC20-like contract bytecode for testing
const ESCROW_CONTRACT_BYTECODE: &str =
    include_str!("../../examples/escrow-bytecode/artifacts/bytecode.hex");

/// Start local anvil instance for testing
async fn start_anvil(port: u16) -> Result<AnvilInstance> {
    let anvil = Anvil::new().port(port).spawn();
    Ok(anvil)
}

/// Deploy bytecode to anvil and verify it deploys successfully
async fn deploy_and_verify_contract(
    anvil: &AnvilInstance,
    bytecode_hex: &str,
    name: &str,
) -> Result<Address> {
    // Create provider with wallet
    let signer = PrivateKeySigner::from_str(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;

    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(anvil.endpoint_url().as_str())
        .await?;

    // Remove 0x prefix if present
    let clean_bytecode = bytecode_hex.trim_start_matches("0x");
    let bytecode_bytes = hex::decode(clean_bytecode)?;

    println!(
        "Deploying {} contract ({} bytes)",
        name,
        bytecode_bytes.len()
    );

    // Create deployment transaction
    let tx = TransactionRequest::default()
        .input(bytecode_bytes.into())
        .gas_limit(3_000_000); // High gas limit for obfuscated contracts

    // Send transaction and wait for receipt
    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;

    let contract_address = receipt
        .contract_address
        .ok_or(eyre!("No contract address in receipt"))?;

    println!("✓ {} deployed successfully at {}", name, contract_address);

    Ok(contract_address)
}

/// Create obfuscation config with specific transforms
fn create_config_with_transforms(
    transforms: Vec<Box<dyn Transform>>,
    seed: Seed,
) -> ObfuscationConfig {
    ObfuscationConfig {
        seed,
        transforms,
        pass_config: PassConfig::default(),
        preserve_unknown_opcodes: true,
    }
}

#[tokio::test]
async fn test_function_dispatch_only() {
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();

    println!("Testing function dispatch only (no other transforms)");

    // Start anvil instance
    let anvil = start_anvil(5000 + line!() as u16)
        .await
        .expect("Failed to start anvil");

    // Deploy original contract first
    let original_address = deploy_and_verify_contract(&anvil, ESCROW_CONTRACT_BYTECODE, "Original")
        .await
        .expect("Failed to deploy original contract");

    // Apply function dispatcher only (this is the baseline obfuscation)
    let config = create_config_with_transforms(vec![], seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .expect("Failed to obfuscate bytecode");

    // Verify obfuscation occurred
    assert_ne!(
        result.obfuscated_bytecode, ESCROW_CONTRACT_BYTECODE,
        "Bytecode should be modified by function dispatcher"
    );
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher should be applied automatically"
    );

    // Deploy obfuscated contract
    let obfuscated_address =
        deploy_and_verify_contract(&anvil, &result.obfuscated_bytecode, "FunctionDispatch-Only")
            .await
            .expect("Failed to deploy obfuscated contract");

    println!(
        "✓ Function dispatch test passed - Original: {}, Obfuscated: {}",
        original_address, obfuscated_address
    );
}

#[tokio::test]
async fn test_shuffle_transform() {
    let seed = Seed::from_hex("0x2345678901bcdef12345678901bcdef12345678901bcdef12345678901bcdef1")
        .unwrap();

    println!("Testing Shuffle transform");

    // Start anvil instance
    let anvil = start_anvil(5000 + line!() as u16)
        .await
        .expect("Failed to start anvil");

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(Shuffle)];

    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .expect("Failed to obfuscate with shuffle");

    // Verify transforms were applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"Shuffle".to_string()),
        "Shuffle transform should be applied"
    );
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher should be applied automatically"
    );

    // Deploy obfuscated contract
    let address = deploy_and_verify_contract(&anvil, &result.obfuscated_bytecode, "Shuffle")
        .await
        .expect("Failed to deploy shuffle-obfuscated contract");

    println!("✓ Shuffle test passed - Deployed at: {}", address);
}

#[tokio::test]
async fn test_jump_address_transform() {
    let seed = Seed::from_hex("0x3456789012cdef123456789012cdef123456789012cdef123456789012cdef12")
        .unwrap();

    println!("Testing JumpAddressTransformer");

    // Start anvil instance
    let anvil = start_anvil(5000 + line!() as u16)
        .await
        .expect("Failed to start anvil");

    let transforms: Vec<Box<dyn Transform>> =
        vec![Box::new(JumpAddressTransformer::new(PassConfig::default()))];

    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .expect("Failed to obfuscate with jump address transformer");

    // Verify transforms were applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"JumpAddressTransformer".to_string()),
        "JumpAddressTransformer should be applied"
    );

    // Deploy obfuscated contract

    let address = deploy_and_verify_contract(&anvil, &result.obfuscated_bytecode, "JumpAddress")
        .await
        .expect("Failed to deploy jump-address-obfuscated contract");

    println!("✓ JumpAddress test passed - Deployed at: {}", address);
}

#[tokio::test]
async fn test_opaque_predicate_transform() {
    let seed =
        Seed::from_hex("0x456789013def23456789013def23456789013def23456789013def23456789013d")
            .unwrap();

    println!("Testing OpaquePredicate");

    // Start anvil instance
    let anvil = start_anvil(5000 + line!() as u16)
        .await
        .expect("Failed to start anvil");

    let transforms: Vec<Box<dyn Transform>> =
        vec![Box::new(OpaquePredicate::new(PassConfig::default()))];

    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .expect("Failed to obfuscate with opaque predicate");

    // Verify transforms were applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"OpaquePredicate".to_string()),
        "OpaquePredicate should be applied"
    );

    // Deploy obfuscated contract

    let address =
        deploy_and_verify_contract(&anvil, &result.obfuscated_bytecode, "OpaquePredicate")
            .await
            .expect("Failed to deploy opaque-predicate-obfuscated contract");

    println!("✓ OpaquePredicate test passed - Deployed at: {}", address);
}

#[tokio::test]
async fn test_shuffle_and_jump_address() {
    let seed = Seed::from_hex("0x56789014ef3456789014ef3456789014ef3456789014ef3456789014ef345678")
        .unwrap();

    println!("Testing Shuffle + JumpAddressTransformer combination");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(Shuffle),
        Box::new(JumpAddressTransformer::new(PassConfig::default())),
    ];

    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .expect("Failed to obfuscate with shuffle + jump address");

    // Verify both transforms were applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"Shuffle".to_string()),
        "Shuffle transform should be applied"
    );
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"JumpAddressTransformer".to_string()),
        "JumpAddressTransformer should be applied"
    );

    // Start anvil instance
    let anvil = start_anvil(5000 + line!() as u16)
        .await
        .expect("Failed to start anvil");

    // Deploy obfuscated contract
    let address =
        deploy_and_verify_contract(&anvil, &result.obfuscated_bytecode, "Shuffle+JumpAddress")
            .await
            .expect("Failed to deploy combined obfuscated contract");

    println!("✓ Shuffle + JumpAddress test passed - Deployed at: {address}",);
}

#[tokio::test]
async fn test_shuffle_and_opaque_predicate() {
    let seed = Seed::from_hex("0x6789015f456789015f456789015f456789015f456789015f456789015f45678")
        .unwrap();

    println!("Testing Shuffle + OpaquePredicate combination");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(Shuffle),
        Box::new(OpaquePredicate::new(PassConfig::default())),
    ];

    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .expect("Failed to obfuscate with shuffle + opaque predicate");

    // Verify both transforms were applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"Shuffle".to_string()),
        "Shuffle transform should be applied"
    );
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"OpaquePredicate".to_string()),
        "OpaquePredicate should be applied"
    );

    // Start anvil instance
    let anvil = start_anvil(5000 + line!() as u16)
        .await
        .expect("Failed to start anvil");

    // Deploy obfuscated contract
    let address = deploy_and_verify_contract(
        &anvil,
        &result.obfuscated_bytecode,
        "Shuffle+OpaquePredicate",
    )
    .await
    .expect("Failed to deploy combined obfuscated contract");

    println!("✓ Shuffle + OpaquePredicate test passed - Deployed at: {address}");
}

#[tokio::test]
async fn test_jump_address_and_opaque_predicate() {
    let seed =
        Seed::from_hex("0x789016056789016056789016056789016056789016056789016056789016056789")
            .unwrap();

    println!("Testing JumpAddressTransformer + OpaquePredicate combination");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(JumpAddressTransformer::new(PassConfig::default())),
        Box::new(OpaquePredicate::new(PassConfig::default())),
    ];

    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .expect("Failed to obfuscate with jump address + opaque predicate");

    // Verify both transforms were applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"JumpAddressTransformer".to_string()),
        "JumpAddressTransformer should be applied"
    );
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"OpaquePredicate".to_string()),
        "OpaquePredicate should be applied"
    );

    // Start anvil instance
    let anvil = start_anvil(5000 + line!() as u16)
        .await
        .expect("Failed to start anvil");

    // Deploy obfuscated contract
    let address = deploy_and_verify_contract(
        &anvil,
        &result.obfuscated_bytecode,
        "JumpAddress+OpaquePredicate",
    )
    .await
    .expect("Failed to deploy combined obfuscated contract");

    println!("✓ JumpAddress + OpaquePredicate test passed - Deployed at: {address}");
}

#[tokio::test]
async fn test_all_transforms_enabled() {
    let seed =
        Seed::from_hex("0x89017167890171678901716789017167890171678901716789017167890171678")
            .unwrap();

    println!("Testing all transforms enabled");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(Shuffle),
        Box::new(JumpAddressTransformer::new(PassConfig::default())),
        Box::new(OpaquePredicate::new(PassConfig::default())),
    ];

    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .expect("Failed to obfuscate with all transforms");

    // Verify all transforms were applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher should be applied automatically"
    );
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"Shuffle".to_string()),
        "Shuffle transform should be applied"
    );
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"JumpAddressTransformer".to_string()),
        "JumpAddressTransformer should be applied"
    );
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"OpaquePredicate".to_string()),
        "OpaquePredicate should be applied"
    );

    // Verify significant obfuscation occurred
    let size_increase = result.size_increase_percentage;
    println!(
        "Size increase with all transforms: {:.1}% ({} -> {} bytes)",
        size_increase, result.original_size, result.obfuscated_size
    );

    // Deploy obfuscated contract
    // Start anvil instance
    let anvil = start_anvil(5000 + line!() as u16)
        .await
        .expect("Failed to start anvil");

    let address = deploy_and_verify_contract(&anvil, &result.obfuscated_bytecode, "AllTransforms")
        .await
        .expect("Failed to deploy fully obfuscated contract");

    println!("✓ All transforms test passed - Deployed at: {}", address);
    println!(
        "  Final size: {} bytes ({:+.1}% vs original)",
        result.obfuscated_size, size_increase
    );
}
