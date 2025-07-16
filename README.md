# Azoth

**Azoth** is an open-source EVM bytecode obfuscator designed to make Mirage's execution contracts ***statistically indistinguishable*** from ordinary, unverified deployments on Ethereum. By providing on-chain privacy without the tell-tale fingerprints that mixers or shielded pools leave behind, Azoth raises the analytical cost of deobfuscating contracts while keeping gas overhead and deploy size within reasonable bounds.

## Etymology and Philosophy

The name [_Azoth_](https://en.wikipedia.org/wiki/Azoth) derives from medieval alchemy, where it referred to the universal solvent: a hypothetical substance capable of dissolving any material and serving as **the essential agent of transformation**. Just as alchemical azoth was believed to transmute base metals into gold through deterministic processes, our Azoth transforms EVM bytecode through deterministic, seed-based obfuscation passes.

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

## Installation and Setup

Azoth requires Rust edition 2024, which needs the nightly toolchain. Install it with `rustup toolchain install nightly` followed by `rustup default nightly`. 

Build from source by cloning the repository, entering the directory, and running `cargo build --release`. Install the CLI with `cargo install --path crates/cli`.

## Usage Guide

### Basic Commands

**Decode Bytecode** parses and displays bytecode instructions. Use `azoth decode` followed by either a hex string like `0x608060405234801561001057600080fd5b50...` or a file reference like `@bytecode.hex`.

**Strip Bytecode** isolates runtime code from constructor and auxiliary data. The command `azoth strip` accepts the same input formats, with an optional `--raw` flag for binary input.

**Generate Control Flow Graph** creates a visual representation of the control flow. Use `azoth cfg` with your bytecode input, optionally specifying output with `-o cfg_output.dot`.

**Obfuscate Bytecode** applies the transformation passes. Basic usage is `azoth obfuscate` with your input, optionally specifying a seed with `--seed 12345` for deterministic results.

### Advanced Configuration

Configure specific obfuscation passes by listing them with the `--passes` flag. Available transforms include `opaque_predicate` for injecting always-true/false conditions, `shuffle` for reordering basic blocks while preserving semantics, `jump_transform` for modifying jump targets to obscure control flow, and `stack_noise` for adding semantically neutral stack operations.

Threshold configuration controls when transforms are accepted. The `--accept-threshold` flag sets the minimum improvement required (default 0.1), while `--max-size-delta` limits bytecode size increases (default 0.25).

Working with different input formats is straightforward. Hex strings work with or without the 0x prefix. File input uses the @ prefix like `@contract.hex`. Raw binary input adds the `--raw` flag.

Deterministic compilation ensures reproducibility. The same seed always produces identical output, while different seeds create different obfuscation patterns. This allows for controlled experimentation and consistent deployment strategies.

### Output Options

Save results to a file with `--emit output.hex`. Display detailed metrics with `--verbose`. JSON output format is available with `--format json`.

## Examples

### Basic ERC20 Obfuscation

```bash
curl -o erc20.hex "https://api.etherscan.io/api?module=proxy&action=eth_getCode&address=0xA0b86a33E6441E1e623A71e86c5e5e8C2A92a0B7"
azoth strip @erc20.hex
azoth cfg @erc20.hex -o erc20_cfg.dot
azoth obfuscate @erc20.hex --seed 12345 --emit erc20_obfuscated.hex
```

### High-Strength Obfuscation

```bash
azoth obfuscate @contract.hex --seed 67890 --passes "opaque_predicate,shuffle,jump_transform,stack_noise" --accept-threshold 0.20 --max-size-delta 0.30 --emit heavily_obfuscated.hex --verbose
```

### Batch Processing

```bash
for contract in contracts/*.hex; do
  azoth obfuscate "@$contract" --seed 12345 --emit "obfuscated_$(basename $contract)"
done
```

## Production Readiness

Azoth is being prepared for production deployment with comprehensive testing of all obfuscation passes, formal verification of semantic equivalence, and extensive benchmarking of gas costs and deployment sizes. We are actively working toward a stable release that will provide enterprise-grade bytecode obfuscation capabilities.

## Contributing

Azoth welcomes contributions in new obfuscation transforms, improved metrics and analysis, performance optimizations, documentation improvements, and bug reports with fixes. See our contributing guidelines for detailed information.

### Development and Testing

Run all tests with `cargo test`. Target specific tests with `cargo test test_opaque_predicate`. End-to-end tests are available with `cargo test --test e2e_erc20`.

Maintain code quality with `cargo fmt` for formatting and `cargo clippy` for issue detection. Performance benchmarks run with `cargo bench`.


## Acknowledgments

Azoth builds upon extensive research in program obfuscation, control flow analysis, and blockchain privacy. We thank the broader research community for their foundational work in these areas.
