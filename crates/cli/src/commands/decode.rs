use async_trait::async_trait;
use bytecloak_core::decoder::decode_bytecode;
use clap::Args;
use hex::FromHex;
use std::error::Error;
use std::fs;

#[derive(Args)]
pub struct DecodeArgs;

#[async_trait]
impl super::Command for DecodeArgs {
    async fn execute(self, input: &str) -> Result<(), Box<dyn Error>> {
        let (_bytes, is_file) = if let Some(path) = input.strip_prefix('@') {
            (fs::read(path)?, true)
        } else {
            let clean = input.strip_prefix("0x").unwrap_or(input);
            (Vec::from_hex(clean)?, false)
        };

        let (instructions, _, asm) = decode_bytecode(input, is_file).await?;
        println!("{}", asm);
        for instr in instructions {
            println!("{}", instr);
        }
        Ok(())
    }
}
