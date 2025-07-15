# Azoth Transforms

The `azoth-transform` crate implements the obfuscation transformations that enhance bytecode complexity and resistance to analysis. This crate provides a pluggable architecture for applying various obfuscation techniques while maintaining semantic equivalence.

## Architecture

The transforms crate implements a pass-based architecture where each transformation operates on the CFG/IR representation:

1. **Pass Interface** - Standardized transformation interface for modularity
2. **Transformation Passes** - Individual obfuscation techniques
3. **Metrics Integration** - Continuous evaluation during transformation
4. **Rollback Support** - Automatic rejection of ineffective passes

## Key Components

### Pass Interface (`pass.rs`)
Defines the standardized interface for all obfuscation transformations. The pass system enables modular composition of different obfuscation techniques with automatic metrics-based validation.

Key traits and structures:
- `TransformPass` - Core interface for all transformation passes
- `PassResult` - Transformation outcome with metrics
- `PassConfig` - Configuration parameters for each pass
- `PassManager` - Orchestrates pass execution and rollback

### Opaque Predicates (`opaque_predicate.rs`)
Implements opaque predicate injection to increase control flow complexity. Opaque predicates are expressions that always evaluate to true or false but appear non-trivial to static analysis.

Transformation features:
- **Invariant Injection** - Algebraic expressions with known outcomes
- **Stack Manipulation** - Complex stack operations that preserve semantics
- **Control Flow Splitting** - Branch injection with deterministic outcomes
- **Pattern Diversification** - Multiple predicate forms to avoid detection

Example transformations:
```rust
// Original: PUSH1 0x10
// Transformed: PUSH1 0x05 PUSH1 0x0B ADD
//              DUP1 PUSH1 0x10 EQ 
//              PUSH1 target JUMPI
//              REVERT
//              JUMPDEST
```

### Instruction Shuffling (`shuffle.rs`)
Implements basic block and instruction reordering to obscure program structure while maintaining semantic equivalence. Shuffling transforms linear code sequences into equivalent but structurally different forms.

Shuffling techniques:
- **Basic Block Reordering** - Randomized block sequence with corrected jumps
- **Instruction Interleaving** - Safe reordering within basic blocks
- **Stack Balancing** - Maintaining stack consistency across shuffles
- **Jump Target Updates** - Correcting addresses after reordering

### Jump Address Transformation (`jump_address_transformer.rs`)
Modifies jump targets and control flow patterns to obscure program structure. This pass makes static analysis more difficult by introducing indirect jumps and computed addresses.

Transformation approaches:
- **Indirect Jumps** - Convert direct jumps to computed addresses
- **Jump Table Obfuscation** - Encrypt jump target tables
- **Address Computation** - Complex calculations for jump targets
- **Control Flow Flattening** - Reduce nested structures to linear dispatch

### Utility Functions (`util.rs`)
Provides common functionality used across multiple transformation passes including instruction analysis, stack tracking, and semantic validation.

Utility features:
- **Instruction Classification** - Categorize instructions by behavior
- **Stack State Tracking** - Monitor stack depth and contents
- **Semantic Validation** - Ensure transformations preserve behavior
- **Random Number Generation** - Deterministic randomness for reproducibility

## Usage Example

```rust
use azoth_transform::{
    PassManager, OpaquePredicatePass, ShufflePass, JumpTransformPass
};
use azoth_core::{build_cfg_ir, decode_bytecode};

// Create pass manager with configuration
let mut pass_manager = PassManager::new(PassConfig {
    seed: 12345,
    max_passes: 10,
    threshold_config: ThresholdConfig::default(),
});

// Register transformation passes
pass_manager.register_pass(Box::new(OpaquePredicatePass::new()));
pass_manager.register_pass(Box::new(ShufflePass::new()));
pass_manager.register_pass(Box::new(JumpTransformPass::new()));

// Apply transformations to CFG
let (instructions, _, _) = decode_bytecode(&bytecode, false).await?;
let cfg_bundle = build_cfg_ir(&instructions, &sections, &bytecode, report)?;

// Execute transformation passes
let transformed_cfg = pass_manager.apply_passes(&cfg_bundle)?;

// Encode back to bytecode
let obfuscated_bytecode = encode_cfg(&transformed_cfg)?;
```

## Pass Configuration

Each transformation pass supports detailed configuration:

```rust
use azoth_transform::{OpaquePredicateConfig, ShuffleConfig};

let opaque_config = OpaquePredicateConfig {
    injection_probability: 0.3,
    max_complexity: 5,
    use_stack_predicates: true,
    diversify_patterns: true,
};

let shuffle_config = ShuffleConfig {
    block_shuffle_probability: 0.8,
    instruction_interleave: true,
    preserve_semantics: true,
    max_reorder_distance: 10,
};
```

## Metrics Integration

All transformation passes integrate with the analysis crate for continuous evaluation:

```rust
use azoth_analysis::{MetricsBundle, ThresholdConfig};

let threshold_config = ThresholdConfig {
    min_potency_improvement: 2.0,
    min_resilience_improvement: 1.5,
    max_cost_increase: 10.0,
};

// Passes automatically rollback if metrics don't improve
let result = pass_manager.apply_with_thresholds(&cfg_bundle, &threshold_config)?;
```

## Semantic Preservation

All transformations maintain semantic equivalence through:

1. **Stack Consistency** - Preserving stack state at block boundaries
2. **Control Flow Integrity** - Maintaining reachability and execution paths
3. **Data Flow Preservation** - Ensuring variable values remain consistent
4. **Gas Behavior** - Keeping gas consumption patterns similar

## Deterministic Obfuscation

Transformations are deterministic based on seed values:

```rust
use azoth_transform::DeterministicConfig;

let config = DeterministicConfig {
    seed: 0x1234567890abcdef,
    reproducible: true,
};

// Same input + same seed = identical output
let result1 = apply_obfuscation(&bytecode, &config)?;
let result2 = apply_obfuscation(&bytecode, &config)?;
assert_eq!(result1, result2);
```

## Testing

Comprehensive test coverage for all transformation passes:

```bash
cargo test --lib
cargo test test_opaque_predicate_injection
cargo test test_shuffle_preservation
cargo test test_jump_transformation
cargo test test_semantic_equivalence
```

## Dependencies

- `azoth-core` - Core bytecode processing and CFG/IR
- `azoth-analysis` - Metrics and threshold validation
- `azoth-utils` - Common utility functions
- `petgraph` - Graph algorithms for CFG manipulation
- `rand` - Deterministic random number generation

The transforms crate provides the essential obfuscation capabilities that make Azoth effective at protecting smart contract privacy while maintaining functional correctness and acceptable performance characteristics.