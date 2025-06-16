use async_trait::async_trait;
use clap::Subcommand;
use std::error::Error;

pub mod cfg;
pub mod decode;
pub mod strip;

#[derive(Subcommand)]
pub enum Cmd {
    /// Decode bytecode to annotated assembly
    Decode(decode::DecodeArgs),

    /// Strip init/auxdata, dump runtime hex
    Strip(strip::StripArgs),

    /// Write runtime CFG to stdout or a file
    Cfg(cfg::CfgArgs),
}

#[async_trait]
pub trait Command {
    async fn execute(self, input: &str) -> Result<(), Box<dyn Error>>;
}

#[async_trait]
impl Command for Cmd {
    async fn execute(self, input: &str) -> Result<(), Box<dyn Error>> {
        match self {
            Cmd::Decode(args) => args.execute(input).await,
            Cmd::Strip(args) => args.execute(input).await,
            Cmd::Cfg(args) => args.execute(input).await,
        }
    }
}
