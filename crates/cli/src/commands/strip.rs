use async_trait::async_trait;
use bytecloak_core::decoder::decode_bytecode;
use bytecloak_core::detection::locate_sections;
use bytecloak_core::strip::strip_bytecode;
use clap::Args;
use hex::FromHex;
use serde_json;
use std::error::Error;
use std::fs;

#[derive(Args)]
pub struct StripArgs {
    /// Output raw cleaned runtime hex instead of JSON report
    #[arg(long)]
    raw: bool,
}

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
