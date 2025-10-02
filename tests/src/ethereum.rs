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

use azoth_core::decoder;
use azoth_transform::jump_address_transformer::JumpAddressTransformer;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::opaque_predicate::OpaquePredicate;
use azoth_transform::shuffle::Shuffle;
use azoth_transform::{PassConfig, Transform};
use azoth_utils::seed::Seed;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use hex;
use revm::context::result::{ExecutionResult, Output};
use revm::context::TxEnv;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

const ESCROW_CONTRACT_BYTECODE: &str =
    include_str!("../../examples/escrow-bytecode/artifacts/bytecode.hex");

/// Deploy bytecode and verify it executes without reverting
fn deploy_and_verify_contract_revm(bytecode_hex: &str, name: &str) -> Result<Address> {
    // Normalize bytecode
    let normalized_hex = decoder::normalize_hex_string(bytecode_hex)
        .map_err(|e| eyre!("Failed to normalize bytecode for {}: {}", name, e))?;

    let bytecode_bytes = hex::decode(&normalized_hex)
        .map_err(|e| eyre!("Failed to decode bytecode for {}: {}", name, e))?;

    if bytecode_bytes.is_empty() {
        return Err(eyre!("Empty bytecode for {}", name));
    }

    println!(
        "Testing {} contract deployment ({} bytes)",
        name,
        bytecode_bytes.len()
    );

    let mut evm = Context::mainnet()
        .with_db(InMemoryDB::default())
        .build_mainnet();

    // Set up deployment transaction
    let deployer = Address::from([0x42u8; 20]);

    let tx_env = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: Bytes::from(bytecode_bytes),
        value: U256::ZERO,
        ..Default::default()
    };

    // Execute deployment
    let result = evm
        .transact(tx_env)
        .map_err(|e| eyre!("REVM execution failed for {}: {:?}", name, e))?;

    match result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Create(bytes, Some(address)) => {
                println!(
                    "✓ {} deployed successfully at {} (deployed {} bytes)",
                    name,
                    address,
                    bytes.len()
                );
                Ok(address)
            }
            Output::Create(_, None) => Err(eyre!(
                "Contract deployment failed - no address returned for {}",
                name
            )),
            _ => Err(eyre!(
                "Unexpected output type for contract deployment: {}",
                name
            )),
        },
        ExecutionResult::Revert { output, .. } => Err(eyre!(
            "Contract deployment reverted for {}: {:?}",
            name,
            output
        )),
        ExecutionResult::Halt { reason, .. } => Err(eyre!(
            "Contract deployment halted for {} with reason: {:?}",
            name,
            reason
        )),
    }
}

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
async fn test_function_dispatch_only() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing FunctionDispatcher only (no additional transforms)");

    let config = create_config_with_transforms(vec![], seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate with function dispatcher: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"FunctionDispatcher".to_string()));

    let address =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "FunctionDispatcher")?;
    println!(
        "✓ FunctionDispatcher test passed - Deployed at: {}",
        address
    );
    Ok(())
}

#[tokio::test]
async fn test_shuffle_transform() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing Shuffle transform");

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(Shuffle)];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate with shuffle: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"Shuffle".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"FunctionDispatcher".to_string()));

    let address = deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "Shuffle")?;
    println!("✓ Shuffle test passed - Deployed at: {}", address);
    Ok(())
}

#[tokio::test]
async fn test_jump_address_transform() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing JumpAddressTransformer");

    let transforms: Vec<Box<dyn Transform>> =
        vec![Box::new(JumpAddressTransformer::new(PassConfig::default()))];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate with jump address transformer: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"JumpAddressTransformer".to_string()));

    let address = deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "JumpAddress")?;
    println!("✓ JumpAddress test passed - Deployed at: {}", address);
    Ok(())
}

#[tokio::test]
async fn test_opaque_predicate_transform() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing OpaquePredicate");

    let transforms: Vec<Box<dyn Transform>> =
        vec![Box::new(OpaquePredicate::new(PassConfig::default()))];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate with opaque predicate: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"OpaquePredicate".to_string()));

    let address = deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "OpaquePredicate")?;
    println!("✓ OpaquePredicate test passed - Deployed at: {}", address);
    Ok(())
}

#[tokio::test]
async fn test_shuffle_and_jump_address() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing Shuffle + JumpAddressTransformer combination");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(Shuffle),
        Box::new(JumpAddressTransformer::new(PassConfig::default())),
    ];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate with shuffle + jump address: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"Shuffle".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"JumpAddressTransformer".to_string()));

    let address =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "Shuffle+JumpAddress")?;
    println!(
        "✓ Shuffle + JumpAddress test passed - Deployed at: {}",
        address
    );
    Ok(())
}

#[tokio::test]
async fn test_shuffle_and_opaque_predicate() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing Shuffle + OpaquePredicate combination");
    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(Shuffle),
        Box::new(OpaquePredicate::new(PassConfig::default())),
    ];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate with shuffle + opaque predicate: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"Shuffle".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"OpaquePredicate".to_string()));

    let address =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "Shuffle+OpaquePredicate")?;
    println!(
        "✓ Shuffle + OpaquePredicate test passed - Deployed at: {}",
        address
    );
    Ok(())
}

#[tokio::test]
async fn test_jump_address_and_opaque_predicate() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing JumpAddressTransformer + OpaquePredicate combination");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(JumpAddressTransformer::new(PassConfig::default())),
        Box::new(OpaquePredicate::new(PassConfig::default())),
    ];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| {
            eyre!(
                "Failed to obfuscate with jump address + opaque predicate: {}",
                e
            )
        })?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"JumpAddressTransformer".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"OpaquePredicate".to_string()));

    let address = deploy_and_verify_contract_revm(
        &result.obfuscated_bytecode,
        "JumpAddress+OpaquePredicate",
    )?;
    println!(
        "✓ JumpAddress + OpaquePredicate test passed - Deployed at: {}",
        address
    );
    Ok(())
}

#[tokio::test]
async fn test_all_transforms_enabled() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing all transforms enabled");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(Shuffle),
        Box::new(JumpAddressTransformer::new(PassConfig::default())),
        Box::new(OpaquePredicate::new(PassConfig::default())),
    ];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate with all transforms: {}", e))?;

    // Verify all transforms were applied
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"FunctionDispatcher".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"Shuffle".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"JumpAddressTransformer".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"OpaquePredicate".to_string()));

    let size_increase = result.size_increase_percentage;
    println!(
        "Size increase with all transforms: {:.1}% ({} -> {} bytes)",
        size_increase, result.original_size, result.obfuscated_size
    );

    let address = deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "AllTransforms")?;
    println!("✓ All transforms test passed - Deployed at: {}", address);
    println!(
        "  Final size: {} bytes ({:+.1}% vs original)",
        result.obfuscated_size, size_increase
    );
    Ok(())
}

#[tokio::test]
async fn test_gas_consumption_analysis() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing gas consumption analysis");

    // Test original contract gas consumption
    let mut evm_original = Context::mainnet()
        .with_db(InMemoryDB::default())
        .build_mainnet();

    let deployer = Address::from([0x42u8; 20]);

    let tx_env_original = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: Bytes::from(hex::decode(decoder::normalize_hex_string(
            ESCROW_CONTRACT_BYTECODE,
        )?)?),
        value: U256::ZERO,
        ..Default::default()
    };

    let original_result = evm_original.transact(tx_env_original)?;
    let original_gas = match &original_result.result {
        ExecutionResult::Success { gas_used, .. } => *gas_used,
        _ => return Err(eyre!("Original contract deployment failed")),
    };

    // Test obfuscated contract gas consumption
    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(Shuffle)];
    let config = create_config_with_transforms(transforms, seed);
    let obfuscation_result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate: {}", e))?;

    let mut evm_obfuscated = Context::mainnet()
        .with_db(InMemoryDB::default())
        .build_mainnet();

    let tx_env_obfuscated = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: Bytes::from(hex::decode(decoder::normalize_hex_string(
            &obfuscation_result.obfuscated_bytecode,
        )?)?),
        value: U256::ZERO,
        ..Default::default()
    };

    let obfuscated_result = evm_obfuscated.transact(tx_env_obfuscated)?;
    let obfuscated_gas = match &obfuscated_result.result {
        ExecutionResult::Success { gas_used, .. } => *gas_used,
        _ => return Err(eyre!("Obfuscated contract deployment failed")),
    };

    let gas_increase =
        ((obfuscated_gas as f64 - original_gas as f64) / original_gas as f64) * 100.0;

    println!("Gas Analysis:");
    println!("  Original deployment gas: {}", original_gas);
    println!("  Obfuscated deployment gas: {}", obfuscated_gas);
    println!(
        "  Gas increase: {:.1}% ({:+} gas)",
        gas_increase,
        obfuscated_gas as i64 - original_gas as i64
    );

    println!("✓ Gas consumption analysis completed");
    Ok(())
}
