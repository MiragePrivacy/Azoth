use async_trait::async_trait;
use clap::Subcommand;
use std::error::Error;

pub mod cfg;
pub mod decode;
pub mod obfuscate;
pub mod strip;

/// CLI subcommands for Bytecloak.
#[derive(Subcommand)]
pub enum Cmd {
    /// Decode bytecode to annotated assembly
    Decode(decode::DecodeArgs),
    /// Strip init/auxdata, dump runtime hex
    Strip(strip::StripArgs),
    /// Write runtime CFG to stdout or a file
    Cfg(cfg::CfgArgs),
    /// Obfuscate bytecode with specified transforms
    Obfuscate(obfuscate::ObfuscateArgs),
}

/// Trait for executing CLI subcommands.
///
/// Implementors define the logic for processing input bytecode and producing output (e.g.,
/// assembly, stripped bytecode, CFG, or obfuscated bytecode).
#[async_trait]
pub trait Command {
    /// Executes the subcommand.
    ///
    /// # Returns
    /// A `Result` indicating success or an error if execution fails.
    async fn execute(self) -> Result<(), Box<dyn Error>>;
}

#[async_trait]
impl Command for Cmd {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        match self {
            Cmd::Decode(args) => args.execute().await,
            Cmd::Strip(args) => args.execute().await,
            Cmd::Cfg(args) => args.execute().await,
            Cmd::Obfuscate(args) => args.execute().await,
        }
    }
}
