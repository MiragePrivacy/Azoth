/// Module for the `decode` subcommand, which decodes EVM bytecode to annotated assembly.
///
/// This module processes input bytecode and outputs both the raw assembly from the Heimdall
/// disassembler and a structured list of instructions with program counters and opcodes.
use async_trait::async_trait;
use azoth_core::decoder::decode_bytecode;
use clap::Args;
use std::error::Error;
use std::path::Path;

/// Arguments for the `decode` subcommand.
#[derive(Args)]
pub struct DecodeArgs {
    /// Input bytecode as a hex string (0x...) or file path containing EVM bytecode.
    pub input: String,
}

/// Executes the `decode` subcommand to decode bytecode.
#[async_trait]
impl super::Command for DecodeArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let is_file = !self.input.starts_with("0x") && Path::new(&self.input).is_file();
        let (instructions, _, asm, _) = decode_bytecode(&self.input, is_file).await?;
        println!("{asm}");
        for instr in instructions {
            println!("{instr}");
        }
        Ok(())
    }
}
