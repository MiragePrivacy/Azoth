/// Module for the `decode` subcommand, which decodes EVM bytecode to annotated assembly.
///
/// This module processes input bytecode and outputs both the raw assembly from the Heimdall
/// disassembler and a structured list of instructions with program counters and opcodes.
use async_trait::async_trait;
use bytecloak_core::decoder::decode_bytecode;
use clap::Args;
use hex::FromHex;
use std::error::Error;
use std::fs;

/// Arguments for the `decode` subcommand.
#[derive(Args)]
pub struct DecodeArgs;

/// Executes the `decode` subcommand to decode bytecode.
///
/// # Arguments
/// * `input` - A hex string (0x...) or file path (@...) containing EVM bytecode.
///
/// # Returns
/// A `Result` indicating success or an error if decoding fails.
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
