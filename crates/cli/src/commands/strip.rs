/// Module for the `strip` subcommand, which extracts the runtime bytecode from EVM bytecode.
///
/// This module processes input bytecode, removes non-runtime sections (e.g., init code,
/// auxdata), and outputs either the cleaned runtime bytecode as a hex string or a JSON report
/// detailing the stripping process.
use async_trait::async_trait;
use bytecloak_core::decoder::decode_bytecode;
use bytecloak_core::detection::locate_sections;
use bytecloak_core::strip::strip_bytecode;
use clap::Args;
use hex::FromHex;
use serde_json;
use std::error::Error;
use std::fs;

/// Arguments for the `strip` subcommand.
#[derive(Args)]
pub struct StripArgs {
    /// Output raw cleaned runtime hex instead of JSON report
    #[arg(long)]
    raw: bool,
}

/// Executes the `strip` subcommand to extract runtime bytecode.
///
/// # Arguments
/// * `input` - A hex string (0x...) or file path (@...) containing EVM bytecode.
///
/// # Returns
/// A `Result` indicating success or an error if processing fails.
#[async_trait]
impl super::Command for StripArgs {
    async fn execute(self, input: &str) -> Result<(), Box<dyn Error>> {
        let (bytes, is_file) = if let Some(path) = input.strip_prefix('@') {
            (fs::read(path)?, true)
        } else {
            let clean = input.strip_prefix("0x").unwrap_or(input);
            (Vec::from_hex(clean)?, false)
        };

        let (instructions, info, _) = decode_bytecode(input, is_file).await?;
        let sections = locate_sections(&bytes, &instructions, &info)?;
        let (clean_runtime, report) = strip_bytecode(&bytes, &sections)?;

        if self.raw {
            println!("0x{}", hex::encode(&clean_runtime));
        } else {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{}", json);
        }
        Ok(())
    }
}
