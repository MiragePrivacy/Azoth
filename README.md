# Azoth

**Azoth** is an open-source EVM bytecode obfuscator designed to make Mirage's execution contracts ***statistically indistinguishable*** from ordinary, unverified deployments on Ethereum. By providing on-chain privacy without the tell-tale fingerprints that mixers or shielded pools leave behind, Azoth raises the analytical cost of deobfuscating contracts while keeping gas overhead and deploy size within reasonable bounds.

## Etymology and Philosophy

The name "[Azoth](https://www.wikiwand.com/en/articles/Azoth)" derives from medieval alchemy, where it referred to the universal solvent: a hypothetical substance capable of dissolving any material and serving as **the essential agent of transformation**. Just as alchemical azoth was believed to transmute base metals into gold through deterministic processes, our Azoth transforms EVM bytecode through deterministic, seed-based obfuscation passes.

This naming reflects our core philosophy: "dissect first, disguise later". Azoth analyzes a contract's control-flow, rewrites it with deterministic layered transforms, then re-assembles and emits a byte-for-byte reproducible binary. Like its alchemical namesake, the transformation is both profound and reproducible. Given the same input and seed, Azoth will always produce identical output.

## Current Status

Azoth is currently in active development and testing as we prepare for production deployment. The core infrastructure is operational, including comprehensive EVM bytecode parsing, section detection, control flow graph generation with SSA-form intermediate representation, and full instruction decoding with semantic analysis. The bytecode stripping functionality successfully isolates runtime code from constructor and auxiliary data.

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

## Getting Started

Azoth is available through a [command-line interface](crates/cli). This could be used for local development, testing, and experimentation with bytecode obfuscation. This CLI interface allows developers to analyze, strip, visualize, and obfuscate EVM bytecode during the development process.

## Production Readiness

Azoth is being prepared for production deployment with comprehensive testing of all obfuscation passes, formal verification of semantic equivalence, and extensive benchmarking of gas costs and deployment sizes. We are actively working toward a stable release that will provide enterprise-grade bytecode obfuscation capabilities.

## Contributing

Azoth welcomes contributions in new obfuscation transforms, improved metrics and analysis, performance optimizations, documentation improvements, and bug reports with fixes. See our [contributing guidelines](CONTRIBUTING.md) for detailed information.

### Testing & Development

| Command    | Description            |
| ---------- | ---------------------- |
| `cargo bb` | Build packages         |
| `cargo cc` | Clippy all packages    |
| `cargo tt` | Run all tests          |

We're using `cargo-nextest` for testing, the commands above are described in [.cargo/config.toml](.cargo/config.toml).


## Acknowledgments

Azoth builds upon extensive research in program obfuscation, control flow analysis, and blockchain privacy. We thank the broader research community for their foundational work in these areas.
