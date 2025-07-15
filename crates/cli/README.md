# Azoth CLI

The `azoth-cli` crate provides the command-line interface for the Azoth EVM bytecode obfuscator. This crate offers a comprehensive set of tools for analyzing, transforming, and obfuscating Ethereum smart contract bytecode.

## Architecture

The CLI is structured around a command-based architecture with the following components:

1. **Command Processing** - Parse and validate command-line arguments
2. **Input Handling** - Support for hex strings, file paths, and piped input
3. **Output Formatting** - JSON, human-readable, and binary output formats
4. **Error Handling** - Comprehensive error reporting and recovery

## Installation

```bash
# Install from source
cd crates/cli
cargo install --path .

# Or build binary
cargo build --release --bin azoth
```

## Commands

### `azoth decode`
Decodes EVM bytecode into human-readable instruction format with comprehensive analysis.

```bash
azoth decode <INPUT>
azoth decode 0x608060405234801561001057600080fd5b50
azoth decode @path/to/bytecode.hex
azoth decode --json 0x608060405234801561001057600080fd5b50
```

Features:
- **Instruction Disassembly** - Convert bytecode to opcode sequences
- **Jump Target Analysis** - Identify and validate jump destinations
- **Stack Effect Calculation** - Compute stack depth changes
- **Gas Cost Estimation** - Estimate execution costs
- **Metadata Extraction** - Extract compiler and version information

Options:
- `--json` - Output in JSON format for programmatic use
- `--verbose` - Include detailed analysis information
- `--no-color` - Disable colored output
- `--output <file>` - Write results to file

### `azoth strip`
Isolates runtime bytecode from deployment artifacts, removing constructor code and metadata.

```bash
azoth strip <INPUT>
azoth strip 0x608060405234801561001057600080fd5b50
azoth strip --raw @contract.hex
azoth strip --json --output stripped.json 0x608060405234801561001057600080fd5b50
```

Features:
- **Runtime Isolation** - Extract only executable contract code
- **Section Detection** - Identify constructor, runtime, and auxiliary data
- **Metadata Removal** - Strip compiler metadata and debug information
- **Size Optimization** - Minimize bytecode size while preserving functionality

Options:
- `--raw` - Output raw bytecode without analysis
- `--json` - Structured output with section information
- `--keep-metadata` - Preserve auxiliary data sections
- `--output <file>` - Write stripped bytecode to file

### `azoth cfg`
Generates control flow graph visualization and analysis from bytecode.

```bash
azoth cfg <INPUT>
azoth cfg --output graph.dot 0x608060405234801561001057600080fd5b50
azoth cfg --format svg --output graph.svg @contract.hex
azoth cfg --json --analysis 0x608060405234801561001057600080fd5b50
```

Features:
- **CFG Generation** - Build control flow graph from bytecode
- **Basic Block Analysis** - Identify and analyze basic blocks
- **Dominance Analysis** - Compute dominance relationships
- **Loop Detection** - Identify loop structures and nesting
- **Visualization Export** - Generate DOT, SVG, and PNG formats

Options:
- `--output <file>` - Specify output file path
- `--format <format>` - Output format (dot, svg, png, json)
- `--analysis` - Include detailed structural analysis
- `--simplify` - Simplify graph for better visualization

### `azoth obfuscate`
Applies obfuscation transformations to bytecode while maintaining semantic equivalence.

```bash
azoth obfuscate <INPUT>
azoth obfuscate --seed 12345 0x608060405234801561001057600080fd5b50
azoth obfuscate --passes opaque,shuffle @contract.hex
azoth obfuscate --emit obfuscated.hex --json 0x608060405234801561001057600080fd5b50
```

Features:
- **Opaque Predicates** - Inject complex conditions with known outcomes
- **Instruction Shuffling** - Reorder blocks and instructions safely
- **Jump Transformation** - Obscure control flow patterns
- **Deterministic Output** - Reproducible results with seed values
- **Metrics Validation** - Automatic quality assessment

Options:
- `--seed <value>` - Set deterministic seed for reproducibility
- `--passes <list>` - Specify transformation passes (opaque,shuffle,jump)
- `--accept-threshold <value>` - Set minimum improvement threshold
- `--max-size-delta <percent>` - Limit bytecode size increase
- `--emit <file>` - Output obfuscated bytecode to file
- `--json` - Include detailed metrics in JSON format

### Universal Options

All commands support these universal options:

- `--help` - Display command-specific help information
- `--version` - Show version information
- `--verbose` - Enable detailed logging output
- `--quiet` - Suppress non-essential output
- `--no-color` - Disable colored terminal output

## Input Formats

The CLI supports multiple input formats:

1. **Hex String** - Direct bytecode as hex: `0x608060405234801561001057600080fd5b50`
2. **File Path** - File containing bytecode: `@path/to/bytecode.hex`
3. **Stdin** - Piped input: `echo "0x6080..." | azoth decode`

## Output Formats

### Human-Readable
Default format with syntax highlighting and structured presentation:

```
Instruction Analysis:
  0x00: PUSH1 0x80      [Stack: +1, Gas: 3]
  0x02: PUSH1 0x40      [Stack: +1, Gas: 3]
  0x04: MSTORE          [Stack: -2, Gas: 3]
  ...
```

### JSON Format
Structured data for programmatic processing:

```json
{
  "instructions": [
    {
      "pc": 0,
      "opcode": "PUSH1",
      "operand": "0x80",
      "stack_effect": 1,
      "gas_cost": 3
    }
  ],
  "analysis": {
    "total_instructions": 42,
    "total_gas": 156,
    "jump_targets": [10, 25, 40]
  }
}
```

### Binary Output
Raw bytecode output for deployment or further processing.

## Error Handling

The CLI provides comprehensive error reporting:

```bash
# Invalid bytecode
azoth decode 0xZZZZ
Error: Invalid hex character 'Z' at position 2

# File not found
azoth decode @missing.hex
Error: File not found: missing.hex

# Obfuscation failure
azoth obfuscate --accept-threshold 99.0 0x6080...
Error: No transformations met acceptance threshold of 99.0
```

## Integration Examples

### Shell Scripting
```bash
#!/bin/bash
# Process multiple contracts
for contract in contracts/*.hex; do
    echo "Processing $contract..."
    azoth obfuscate --emit "obfuscated/$(basename $contract)" "@$contract"
done
```

### Build Pipeline
```bash
# Deploy obfuscated contracts
solc Contract.sol --bin | azoth obfuscate --seed $DEPLOY_SEED --emit deployment.hex
```

### Analysis Workflow
```bash
# Full analysis pipeline
azoth decode @contract.hex --json > analysis.json
azoth cfg @contract.hex --format svg --output cfg.svg
azoth obfuscate @contract.hex --emit obfuscated.hex --json > metrics.json
```

## Configuration

The CLI can be configured through:

1. **Command-line arguments** - Override defaults per execution
2. **Environment variables** - Set global preferences
3. **Configuration files** - Persistent settings

Environment variables:
- `AZOTH_SEED` - Default seed value for deterministic operations
- `AZOTH_OUTPUT_FORMAT` - Default output format (json, human)
- `AZOTH_LOG_LEVEL` - Logging verbosity (error, warn, info, debug)

## Performance

The CLI is optimized for various use cases:

- **Single Files** - Fast processing with minimal memory usage
- **Batch Processing** - Efficient handling of multiple files
- **Large Contracts** - Streaming processing for contracts >1MB
- **Real-time Analysis** - Sub-second response for typical contracts

## Dependencies

- `azoth-core` - Core bytecode processing functionality
- `azoth-transform` - Obfuscation transformation passes
- `azoth-utils` - Common utility functions
- `clap` - Command-line argument parsing
- `serde_json` - JSON serialization support
- `tokio` - Async runtime for processing

The CLI provides a powerful and flexible interface for all Azoth functionality, supporting both interactive use and automated deployment pipelines.