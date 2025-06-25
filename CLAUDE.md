# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bytecloak is a research-grade toolchain for Ethereum smart-contract obfuscation. The project follows a three-stage pipeline:

1. **Pre-processing/Analysis**: Isolate runtime bytecode and measure structure
2. **Obfuscation Passes**: Apply reversible transforms to raise analyst effort
3. **Re-assembly & Validation**: Splice segments back and validate equivalence

## Architecture

This is a Rust workspace with four main crates:

- **`crates/core/`**: Core functionality including bytecode loader, detector, stripper, and IR/CFG generation
- **`crates/analysis/`**: Analysis utilities including dominators, metrics, and pattern mining
- **`crates/transforms/`**: Obfuscation passes (opaque predicates, shuffling, stack noise)
- **`crates/cli/`**: Command-line interface (`bytecloak` binary)

## Development Requirements

**Important**: This project requires Rust edition 2024, which needs nightly toolchain:
```bash
rustup toolchain install nightly
rustup default nightly
```

## Common Commands

### Build and Test
```bash
# Build the project (requires nightly Rust)
cargo build

# Run tests
cargo test

# Run specific test
cargo test test_name

# Run end-to-end tests
cargo test --test e2e_erc20

# Format code
cargo fmt

# Check for issues
cargo clippy
```

### CLI Usage
```bash
# Build CLI binary
cargo build --bin bytecloak

# Run CLI commands
cargo run --bin bytecloak -- decode <bytecode>
cargo run --bin bytecloak -- strip <bytecode>
cargo run --bin bytecloak -- cfg <bytecode>
cargo run --bin bytecloak -- obfuscate <bytecode>
```

### Input Formats
- Hex string: `0x608060405234801561001057600080fd5b50...`
- File path: `@path/to/bytecode.hex`

## Code Style

- Uses rustfmt with custom configuration (see `rustfmt.toml`)
- Max line width: 100 characters
- Edition 2024 features enabled
- Comprehensive documentation expected for public APIs

## Key Data Structures

- **CFG IR**: Control Flow Graph intermediate representation in `crates/core/src/cfg_ir.rs`
- **Opcodes**: EVM opcode definitions and utilities in `crates/core/src/opcode.rs`
- **Transform Passes**: Obfuscation transforms implementing a common pass interface

## Git Workflow

### Creating New Branches
```bash
# Create and switch to new branch from master
git checkout master
git pull origin master
git checkout -b feature/your-feature-name

# Push new branch to remote and set upstream
git push -u origin feature/your-feature-name
```

### Commit Guidelines
- Follow conventional commit format: `type(scope): description`
- Common types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
- When user says "commit", create a commit with appropriate conventional message and push to origin
- Examples:
  - `feat(core): add new opcode detection logic`
  - `fix(cli): handle invalid bytecode input gracefully`
  - `docs: update installation instructions`
  - `refactor(transforms): simplify shuffle algorithm`

## Testing

- Unit tests are located alongside source files
- End-to-end tests in `crates/cli/tests/`
- Test data includes ERC20 token examples in `examples/erc20/`