# Azoth

**Azoth** is an open-source EVM bytecode obfuscator designed to make Mirage's execution contracts _statistically indistinguishable_ from ordinary, unverified deployments on Ethereum. By providing on-chain privacy without the tell-tale fingerprints that mixers or shielded pools leave behind, Azoth raises the analytical cost of deobfuscating contracts while keeping gas overhead and deploy size within reasonable bounds.

## Etymology and Philosophy

The name "Azoth" derives from medieval alchemy, where it referred to the universal solvent—a hypothetical substance capable of dissolving any material and serving as the essential agent of transformation. Just as alchemical azoth was believed to transmute base metals into gold through deterministic processes, our Azoth transforms EVM bytecode through deterministic, seed-based obfuscation passes.

This naming reflects our core philosophy: **"dissect first, disguise later"**. Azoth analyzes a contract's control-flow, rewrites it with deterministic layered transforms, then re-assembles and emits a byte-for-byte reproducible binary. Like its alchemical namesake, the transformation is both profound and reproducible—given the same input and seed, Azoth will always produce identical output.

## Project Status

Azoth is currently in **active development** as a research-grade toolchain. The following components are implemented and functional:

### ✅ Core Infrastructure
- **Bytecode Analysis**: Complete EVM bytecode parsing and section detection
- **CFG Construction**: Control Flow Graph generation with SSA-form intermediate representation
- **Instruction Decoding**: Full EVM opcode support with semantic analysis
- **Bytecode Stripping**: Isolation of runtime code from constructor and auxiliary data

### ✅ Obfuscation Transforms
- **Opaque Predicates**: Injection of always-true/false conditions to confuse static analysis
- **Control Flow Shuffling**: Reordering of basic blocks while preserving semantics
- **Jump Address Transformation**: Modification of jump targets to obscure control flow
- **Stack Noise Injection**: Addition of semantically neutral stack operations

### ✅ Analysis and Metrics
- **Potency Measurement**: Structural and statistical complexity analysis
- **Resilience Scoring**: Resistance to automated decompilation
- **Cost Analysis**: Gas overhead and bytecode size impact tracking
- **Dominance Analysis**: Control flow dominance tree construction

### ✅ Tooling
- **CLI Interface**: Complete command-line tool with comprehensive options
- **Deterministic Compilation**: Reproducible builds from seed values
- **Pass Management**: Configurable transform pipeline with threshold-based acceptance

### 🚧 In Development
- **Formal Verification**: Mathematical proofs of semantic equivalence (verification crate)
- **Advanced Metrics**: Enhanced complexity and obfuscation quality measures
- **Additional Transforms**: Function dispatcher obfuscation, data flow obfuscation

## Architecture

Azoth unfolds in three distinct stages:

### 1. Pre-processing
Precisely isolates and analyzes different sections of EVM bytecode, producing a clean `runtime` blob and typed instruction stream. This stage includes:
- Bytecode section detection and isolation
- Instruction stream parsing and validation
- Control flow graph construction
- SSA-form intermediate representation generation

### 2. Obfuscation Core
The `runtime` is lifted into a `CFG + SSA` intermediate representation. Deterministic, pluggable passes then mutate the graph with different transforms:
- Each pass operates on the CFG/SSA representation
- Metrics are recomputed after each transformation
- Changes are rolled back if improvement doesn't exceed configurable thresholds
- Passes can be chained and configured independently

### 3. Bytecode Recovery
The encoder re-assembles the transformed runtime with the untouched constructor and auxiliary data, producing deployable bytecode whose Keccak hash matches deterministic recompilation `O(S, seed)`.

## Metrics and Quality Assurance

Azoth tracks three key metrics to ensure obfuscation quality:

- **Potency**: Structural and statistical complexity added (cyclomatic complexity, injected opaque instructions, etc.)
- **Resilience**: Resistance to automated decompilation and reverse engineering
- **Cost**: Overhead in gas consumption and bytecode size

Every transform must raise Potency and Resilience above clearly defined thresholds while keeping Cost below the defined threshold, otherwise it is rejected.

## Installation and Setup

### Prerequisites
Azoth requires Rust edition 2024, which needs the nightly toolchain:

```bash
rustup toolchain install nightly
rustup default nightly
```

### Building from Source
```bash
git clone https://github.com/MiragePrivacy/obfuscator.git
cd obfuscator
cargo build --release
```

### Installing the CLI
```bash
cargo install --path crates/cli
```

## Usage Guide

### Basic Commands

#### Decode Bytecode
Parse and display bytecode instructions:
```bash
azoth decode 0x608060405234801561001057600080fd5b50...
azoth decode @bytecode.hex
```

#### Strip Bytecode
Isolate runtime code from constructor and auxiliary data:
```bash
azoth strip 0x608060405234801561001057600080fd5b50...
azoth strip @bytecode.hex --raw
```

#### Generate Control Flow Graph
Create a visual representation of the control flow:
```bash
azoth cfg 0x608060405234801561001057600080fd5b50...
azoth cfg @bytecode.hex -o cfg_output.dot
```

#### Obfuscate Bytecode
Apply obfuscation transforms:
```bash
azoth obfuscate 0x608060405234801561001057600080fd5b50...
azoth obfuscate @bytecode.hex --seed 12345
```

### Advanced Usage

#### Configuring Obfuscation Passes
```bash
azoth obfuscate @bytecode.hex \
  --seed 12345 \
  --passes "opaque_predicate,shuffle,jump_transform" \
  --accept-threshold 0.15 \
  --max-size-delta 0.20 \
  --emit obfuscated_output.hex
```

#### Working with Different Input Formats
```bash
# Hex string (with or without 0x prefix)
azoth obfuscate 608060405234801561001057600080fd5b50...

# File input
azoth obfuscate @contract.hex

# Raw binary input
azoth obfuscate @contract.bin --raw
```

#### Deterministic Compilation
```bash
# Same seed always produces identical output
azoth obfuscate @contract.hex --seed 42
azoth obfuscate @contract.hex --seed 42  # Identical result

# Different seeds produce different obfuscation
azoth obfuscate @contract.hex --seed 123
azoth obfuscate @contract.hex --seed 456  # Different result
```

### Transform Configuration

#### Available Transforms
- `opaque_predicate`: Inject always-true/false conditions
- `shuffle`: Reorder basic blocks while preserving semantics
- `jump_transform`: Modify jump targets to obscure control flow
- `stack_noise`: Add semantically neutral stack operations

#### Threshold Configuration
- `--accept-threshold`: Minimum improvement required to accept a transform (default: 0.1)
- `--max-size-delta`: Maximum allowed bytecode size increase (default: 0.25)

### Output Options
```bash
# Save to file
azoth obfuscate @contract.hex --emit output.hex

# Display metrics
azoth obfuscate @contract.hex --verbose

# JSON output format
azoth obfuscate @contract.hex --format json
```

## Examples

### Basic ERC20 Obfuscation
```bash
# Download sample ERC20 bytecode
curl -o erc20.hex "https://api.etherscan.io/api?module=proxy&action=eth_getCode&address=0xA0b86a33E6441E1e623A71e86c5e5e8C2A92a0B7"

# Strip and analyze
azoth strip @erc20.hex
azoth cfg @erc20.hex -o erc20_cfg.dot

# Obfuscate with medium strength
azoth obfuscate @erc20.hex --seed 12345 --emit erc20_obfuscated.hex
```

### High-Strength Obfuscation
```bash
azoth obfuscate @contract.hex \
  --seed 67890 \
  --passes "opaque_predicate,shuffle,jump_transform,stack_noise" \
  --accept-threshold 0.20 \
  --max-size-delta 0.30 \
  --emit heavily_obfuscated.hex \
  --verbose
```

### Batch Processing
```bash
# Process multiple contracts
for contract in contracts/*.hex; do
  azoth obfuscate "@$contract" --seed 12345 --emit "obfuscated_$(basename $contract)"
done
```

## Development and Testing

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_opaque_predicate

# Run end-to-end tests
cargo test --test e2e_erc20
```

### Code Quality
```bash
# Format code
cargo fmt

# Check for issues
cargo clippy

# Run benchmarks
cargo bench
```

## Contributing

Azoth is an active research project. We welcome contributions in the form of:

- New obfuscation transforms
- Improved metrics and analysis
- Performance optimizations
- Documentation improvements
- Bug reports and fixes

Please see our [contributing guidelines](CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Research and Citations

If you use Azoth in your research, please cite:

```bibtex
@misc{azoth2024,
  title={Azoth: Deterministic EVM Bytecode Obfuscation for On-Chain Privacy},
  author={Mirage Privacy Team},
  year={2024},
  howpublished={\url{https://github.com/MiragePrivacy/obfuscator}}
}
```

## Acknowledgments

Azoth builds upon extensive research in program obfuscation, control flow analysis, and blockchain privacy. We thank the broader research community for their foundational work in these areas.