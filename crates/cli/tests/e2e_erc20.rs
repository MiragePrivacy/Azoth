use ethers::{
    abi::Abi,
    prelude::*,
    signers::LocalWallet,
    types::{Address, U256, U64},
    utils::{hex, Anvil},
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tempfile::TempDir;

const ABI: &str = r#"[
    {"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
    {"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"stateMutability":"nonpayable","type":"function"},
    {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"stateMutability":"view","type":"function"}
]"#;

#[ignore]
#[tokio::test]
async fn e2e_erc20() -> anyhow::Result<()> {
    // 1. Temp workspace
    let tmp = TempDir::new()?;
    let plain_path = tmp.path().join("runtime.hex");
    let obf_path = tmp.path().join("runtime_obf.hex");

    // 2. Compile contract
    let status = Command::new("forge")
        .args(["build", "--silent"])
        .current_dir("examples/erc20")
        .status()?;
    if !status.success() {
        anyhow::bail!("forge build failed");
    }

    let json_path = Path::new("examples/erc20/out/DemoToken.sol/DemoToken.json");
    if !json_path.exists() {
        anyhow::bail!("Build artifact not found; did forge build succeed?");
    }

    let json_str = fs::read_to_string(json_path)?;
    let json: Value = serde_json::from_str(&json_str)?;
    let runtime = json
        .get("deployedBytecode")
        .and_then(|v| v.get("object"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("No deployedBytecode.object in artifact"))?;
    if runtime.is_empty() {
        anyhow::bail!("Runtime bytecode is empty");
    }
    let plain_hex = runtime.trim_start_matches("0x").to_string();
    fs::write(&plain_path, &plain_hex)?;

    // 3. Run Bytecloak CLI
    let status = Command::new("cargo")
        .args([
            "run",
            "-q",
            "-p",
            "bytecloak-cli",
            "--",
            "obfuscate",
            plain_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid path"))?,
            "--seed",
            "42",
            "-o",
            obf_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid path"))?,
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("Bytecloak CLI failed");
    }
    if !obf_path.exists() || fs::read(&obf_path)?.is_empty() {
        anyhow::bail!("Obfuscated bytecode not generated");
    }

    // 4. Load bytecodes
    let plain_bytes = hex::decode(&plain_hex)?;
    let obf_hex = fs::read_to_string(&obf_path)?;
    let obf_bytes = hex::decode(obf_hex.trim_start_matches("0x"))?;

    // 5. Deploy contracts
    let anvil = Anvil::new().spawn();
    let provider = Provider::<Http>::try_from(anvil.endpoint())?;
    let wallet: LocalWallet = anvil
        .keys()
        .first()
        .ok_or_else(|| anyhow::anyhow!("No keys in Anvil"))?
        .clone()
        .into();
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    let plain_result = deploy_and_test(&client, &plain_bytes, ABI).await?;
    let obf_result = deploy_and_test(&client, &obf_bytes, ABI).await?;

    // 6. Functional equivalence
    let abi: Abi = serde_json::from_str(ABI)?;
    let plain_contract = Contract::new(plain_result.0, abi.clone(), client.clone());
    let obf_contract = Contract::new(obf_result.0, abi.clone(), client.clone());

    let plain_total: U256 = plain_contract
        .method::<(), U256>("totalSupply", ())?
        .call()
        .await?;
    let obf_total: U256 = obf_contract
        .method::<(), U256>("totalSupply", ())?
        .call()
        .await?;
    assert_eq!(plain_total, obf_total, "totalSupply mismatch");
    assert_eq!(
        plain_total,
        U256::from(1_000_000_u64) * U256::from(10_u64.pow(18)),
        "totalSupply incorrect"
    );

    let to = Address::random();
    let value = U256::from(1000);
    let plain_method = plain_contract.method::<(Address, U256), bool>("transfer", (to, value))?;
    let plain_pending = plain_method.send().await?;
    let plain_success: bool = plain_pending
        .await?
        .map_or(false, |receipt| receipt.status == Some(U64::from(1)));
    let obf_method = obf_contract.method::<(Address, U256), bool>("transfer", (to, value))?;
    let obf_pending = obf_method.send().await?;
    let obf_success: bool = obf_pending
        .await?
        .map_or(false, |receipt| receipt.status == Some(U64::from(1)));
    assert!(plain_success && obf_success, "Transfer failed");

    let plain_balance: U256 = plain_contract
        .method::<Address, U256>("balanceOf", to)?
        .call()
        .await?;
    let obf_balance: U256 = obf_contract
        .method::<Address, U256>("balanceOf", to)?
        .call()
        .await?;
    assert_eq!(plain_balance, obf_balance, "balanceOf mismatch");
    assert_eq!(plain_balance, value, "balanceOf incorrect");

    // 7. Gas comparison
    let plain_gas_used = plain_result.1;
    let obf_gas_used = obf_result.1;
    let delta = (obf_gas_used.as_u64() as f64 / plain_gas_used.as_u64() as f64 - 1.0) * 100.0;
    println!(
        "Gas plain={} obf={} Δ={:.1}%",
        plain_gas_used, obf_gas_used, delta
    );
    assert!(delta <= 5.0, "Gas increase exceeds 5%: {:.1}%", delta);

    // 8. Clean-up handled by TempDir drop
    Ok(())
}

async fn deploy_and_test<M: Middleware>(
    client: &Arc<M>,
    bytecode: &[u8],
    abi_json: &str,
) -> anyhow::Result<(Address, U256)>
where
    M: Middleware + 'static,
{
    let abi: Abi = serde_json::from_str(abi_json)?;
    let factory = ContractFactory::new(abi.into(), Bytes::from(bytecode.to_vec()), client.clone());

    let deployer = factory.deploy(("Demo".to_string(), "DMO".to_string()))?;
    let (_contract, receipt) = deployer.send_with_receipt().await?;

    let address = receipt
        .contract_address
        .ok_or_else(|| anyhow::anyhow!("No contract address in receipt"))?;
    let gas_used = receipt
        .gas_used
        .ok_or_else(|| anyhow::anyhow!("No gas data in receipt"))?;

    Ok((address, gas_used))
}
