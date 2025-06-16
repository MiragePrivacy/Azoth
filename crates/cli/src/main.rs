use bytecloak_cli::commands::{Cmd, Command};
use clap::Parser;

#[derive(Parser)]
#[command(name = "bytecloak")]
#[command(about = "Bytecloak: EVM bytecode obfuscator")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    /// Input bytecode as a hex string (0x...) or file path prefixed with @
    input: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let cli = Cli::parse();
    cli.command.execute(&cli.input).await
}
