/// Entry point for the Bytecloak CLI, an EVM bytecode obfuscation tool.
///
/// This module parses command-line arguments and dispatches to subcommands for decoding,
/// stripping, CFG visualization, or obfuscating EVM bytecode. It initializes logging and
/// handles the main execution flow.
use bytecloak_cli::commands::{Cmd, Command};
use clap::Parser;

/// Command-line interface for Bytecloak.
///
/// Bytecloak is an EVM bytecode obfuscator that supports decoding bytecode to assembly,
/// stripping non-runtime sections, generating control flow graphs, and applying obfuscation
/// transforms (e.g., shuffle, stack-noise, opaque-predicates).
#[derive(Parser)]
#[command(name = "bytecloak")]
#[command(about = "Bytecloak: EVM bytecode obfuscator")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    /// Input bytecode as a hex string (0x...) or file path prefixed with @
    input: String,
}

/// Runs the Bytecloak CLI with the provided arguments.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let cli = Cli::parse();
    cli.command.execute(&cli.input).await
}
