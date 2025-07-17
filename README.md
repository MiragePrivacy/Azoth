# Azoth

**Azoth** is an open-source EVM bytecode obfuscator designed to make Mirage's execution contracts ***statistically indistinguishable*** from ordinary, unverified deployments on Ethereum. By providing on-chain privacy without the tell-tale fingerprints that mixers or shielded pools leave behind, Azoth raises the analytical cost of deobfuscating contracts while keeping gas overhead and deploy size within reasonable bounds.

## Etymology and Philosophy

The name "[Azoth](https://www.wikiwand.com/en/articles/Azoth)" derives from medieval alchemy, where it referred to the universal solvent: a hypothetical substance capable of dissolving any material and serving as **the essential agent of transformation**. Just as alchemical azoth was believed to transmute base metals into gold through deterministic processes, our Azoth transforms EVM bytecode through deterministic, seed-based obfuscation passes.

This naming reflects our core philosophy: "dissect first, disguise later". Azoth analyzes a contract's control-flow, rewrites it with deterministic layered transforms, then re-assembles and emits a byte-for-byte reproducible binary. Like its alchemical namesake, the transformation is both profound and reproducible. Given the same input and seed, Azoth will always produce identical output.

## Current Status

Azoth is currently in active development and testing as we prepare for production deployment. The core infrastructure is complete and functional, including comprehensive EVM bytecode parsing, section detection, control flow graph generation with SSA-form intermediate representation, and full instruction decoding with semantic analysis. The bytecode stripping functionality successfully isolates runtime code from constructor and auxiliary data.

The obfuscation transform system is operational with several key passes implemented. Opaque predicates inject always-true or always-false conditions to confuse static analysis. Control flow shuffling reorders basic blocks while preserving semantics. Jump address transformation modifies jump targets to obscure control flow patterns. Stack noise injection adds semantically neutral stack operations that complicate reverse engineering without affecting execution.

Our analysis and metrics system tracks i) potency through structural and statistical complexity measurement, ii) resilience via resistance to automated decompilation scoring, and iii) cost through gas overhead and bytecode size impact analysis. The dominance analysis component constructs control flow dominance trees for advanced program analysis.

The CLI interface provides comprehensive tooling with deterministic compilation support, enabling reproducible builds from seed values. The pass management system offers configurable transform pipelines with threshold-based acceptance criteria.

Currently under active development are formal verification components that will provide mathematical proofs of semantic equivalence, enhanced complexity and obfuscation quality measures, and additional transforms including function dispatcher obfuscation and advanced data flow obfuscation techniques. These components are being rigorously tested before production release.

## Architecture

Azoth unfolds in three distinct stages that mirror the alchemical process of dissolution, transformation, and reconstitution.

**Pre-processing** precisely isolates and analyzes different sections of EVM bytecode, producing a clean runtime blob and typed instruction stream. This stage encompasses bytecode section detection and isolation, instruction stream parsing and validation, control flow graph construction, and SSA-form intermediate representation generation. The system must understand the contract's structure completely before any transformation can begin.

**Obfuscation Core** lifts the runtime into a CFG plus SSA intermediate representation. Deterministic, pluggable passes then mutate the graph with different transforms. Each pass operates on the CFG/SSA representation while metrics are recomputed after each transformation. Changes are rolled back if improvement doesn't exceed configurable thresholds. Passes can be chained and configured independently, allowing for fine-tuned obfuscation strategies.

**Bytecode Recovery** re-assembles the transformed runtime with the untouched constructor and auxiliary data, producing deployable bytecode whose Keccak hash matches deterministic recompilation. The function signature remains O(S, seed), ensuring reproducibility while maintaining the contract's original deployment characteristics.

## Metrics and Quality Assurance

Azoth tracks three key metrics to ensure obfuscation quality. **Potency** measures structural and statistical complexity added, including cyclomatic complexity increases and injected opaque instructions. **Resilience** evaluates resistance to automated decompilation and reverse engineering attempts. **Cost** monitors overhead in gas consumption and bytecode size expansion.

Every transform must raise Potency and Resilience above clearly defined thresholds while keeping Cost below the defined threshold, otherwise it is rejected. This ensures that obfuscation meaningfully improves privacy without creating impractical deployment costs.

## Formal Verification System
Azoth incorporates a formal verification system that provides mathematical guarantees of functional and semantic equivalence between original and obfuscated contracts. This addresses the critical challenge that traditional testing can only verify specific cases, while smart contracts must handle infinite input combinations.

## Usage Guide

Azoth provides a comprehensive CLI tool for local development, testing, and experimentation with bytecode obfuscation. This CLI interface allows developers to analyze, strip, visualize, and obfuscate EVM bytecode during the development process.

### CLI Tool Installation

The CLI tool is included for local testing and development purposes:

```bash
# Build the development CLI
cargo build --release

# The CLI binary will be available at target/release/azoth
# Or install it locally
cargo install --path crates/cli
```

### Basic CLI Usage

The CLI provides four main commands for bytecode analysis and obfuscation:

```bash
# Decode bytecode to annotated assembly
azoth decode "0x608060405234801561001057600080fd5b50..."

# Strip and analyze bytecode sections  
azoth strip bytecode.hex

# Generate control flow graph visualization
azoth cfg -o analysis.dot bytecode.hex

# Apply obfuscation transforms
azoth obfuscate --seed 12345 --passes "shuffle,jump_transform,opaque_pred" bytecode.hex
```

For detailed CLI documentation, command options, and usage examples, run:

```bash
azoth --help
azoth <command> --help
```

The CLI tool accepts various input formats (hex strings, .hex files, binary files) and provides comprehensive output options including JSON reports, Graphviz visualizations, and detailed metrics analysis.

## Production Readiness

Azoth is being prepared for production deployment with comprehensive testing of all obfuscation passes, formal verification of semantic equivalence, and extensive benchmarking of gas costs and deployment sizes. We are actively working toward a stable release that will provide enterprise-grade bytecode obfuscation capabilities.

## Contributing

Azoth welcomes contributions in new obfuscation transforms, improved metrics and analysis, performance optimizations, documentation improvements, and bug reports with fixes. See our contributing guidelines for detailed information.

### Testing & Development

| Command    | Description            |
| ---------- | ---------------------- |
| `cargo bb` | Build packages         |
| `cargo cc` | Clippy all packages    |
| `cargo tt` | Run all tests          |

We're using `cargo-nextest` for testing, the commands above are described in [.cargo/config.toml](.cargo/config.toml).


## Acknowledgments

Azoth builds upon extensive research in program obfuscation, control flow analysis, and blockchain privacy. We thank the broader research community for their foundational work in these areas.
