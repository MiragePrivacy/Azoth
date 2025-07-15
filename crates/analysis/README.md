# Azoth Analysis

The `azoth-analysis` crate provides comprehensive analysis tools for evaluating EVM bytecode complexity, structure, and transformation effectiveness. This crate implements the metrics system that guides obfuscation decisions and measures transformation success.

## Architecture

The analysis crate focuses on three key measurement dimensions:

1. **Potency** - Structural and statistical complexity metrics
2. **Resilience** - Resistance to automated decompilation and analysis
3. **Cost** - Gas consumption and bytecode size overhead

## Key Components

### Metrics System (`metrics.rs`)
Implements a comprehensive suite of metrics for evaluating bytecode complexity and transformation effectiveness. The metrics system provides quantitative measures that guide obfuscation pass selection and validation.

#### Potency Metrics
Measures the structural complexity and obfuscation depth achieved through transformations:

- **Cyclomatic Complexity** - Control flow graph complexity measurement
- **Basic Block Count** - Number of distinct execution paths
- **Jump Instruction Density** - Frequency of control flow modifications
- **Opaque Instruction Ratio** - Percentage of injected complexity instructions
- **Stack Depth Variance** - Variability in stack operations
- **Loop Complexity** - Nested loop and iteration analysis

#### Resilience Metrics
Evaluates resistance to automated analysis and decompilation:

- **Decompilation Resistance** - Difficulty score for static analysis tools
- **Pattern Obfuscation** - Concealment of recognizable code patterns
- **Control Flow Entropy** - Randomness in execution paths
- **Dead Code Ratio** - Percentage of unreachable code segments
- **Anti-Analysis Score** - Resistance to common analysis techniques

#### Cost Metrics
Tracks overhead introduced by obfuscation transformations:

- **Gas Overhead** - Additional execution cost percentage
- **Size Increase** - Bytecode size expansion ratio
- **Deployment Cost** - Additional deployment gas requirements
- **Runtime Performance** - Execution speed impact

### Analysis Functions

Key analysis functions available in the crate:

```rust
use azoth_analysis::{
    analyze_potency, analyze_resilience, analyze_cost,
    compute_cyclomatic_complexity, measure_entropy
};

// Comprehensive analysis of bytecode
let potency = analyze_potency(&cfg, &instructions)?;
let resilience = analyze_resilience(&cfg, &original_cfg)?;
let cost = analyze_cost(&original_bytecode, &transformed_bytecode)?;

// Specific complexity measurements
let complexity = compute_cyclomatic_complexity(&cfg)?;
let entropy = measure_entropy(&instruction_stream)?;
```

## Usage Example

```rust
use azoth_analysis::{MetricsBundle, analyze_transformation};
use azoth_core::{build_cfg_ir, decode_bytecode};

// Analyze original bytecode
let (instructions, _, _) = decode_bytecode(&original_bytecode, false).await?;
let cfg_bundle = build_cfg_ir(&instructions, &sections, &bytecode, report)?;

// Perform transformation (from transforms crate)
let transformed_cfg = apply_obfuscation_passes(&cfg_bundle)?;

// Analyze transformation effectiveness
let metrics = analyze_transformation(&cfg_bundle, &transformed_cfg)?;

// Evaluate against thresholds
if metrics.potency.score > POTENCY_THRESHOLD &&
   metrics.resilience.score > RESILIENCE_THRESHOLD &&
   metrics.cost.overhead < COST_THRESHOLD {
    println!("Transformation successful: {}", metrics.summary());
} else {
    println!("Transformation rejected: insufficient improvement");
}
```

## Metrics Data Structures

### MetricsBundle
Comprehensive container for all metric measurements:

```rust
pub struct MetricsBundle {
    pub potency: PotencyMetrics,
    pub resilience: ResilienceMetrics,
    pub cost: CostMetrics,
    pub timestamp: DateTime<Utc>,
}
```

### PotencyMetrics
Structural complexity measurements:

```rust
pub struct PotencyMetrics {
    pub cyclomatic_complexity: u32,
    pub basic_block_count: u32,
    pub jump_density: f64,
    pub opaque_ratio: f64,
    pub score: f64,
}
```

### ResilienceMetrics
Decompilation resistance measurements:

```rust
pub struct ResilienceMetrics {
    pub decompilation_resistance: f64,
    pub pattern_concealment: f64,
    pub control_flow_entropy: f64,
    pub anti_analysis_score: f64,
    pub score: f64,
}
```

### CostMetrics
Performance overhead measurements:

```rust
pub struct CostMetrics {
    pub gas_overhead_percent: f64,
    pub size_increase_percent: f64,
    pub deployment_cost_delta: u64,
    pub runtime_performance_impact: f64,
    pub overhead: f64,
}
```

## Threshold Configuration

The analysis system supports configurable thresholds for transformation acceptance:

```rust
use azoth_analysis::ThresholdConfig;

let config = ThresholdConfig {
    min_potency_score: 7.5,
    min_resilience_score: 8.0,
    max_cost_overhead: 15.0,
    max_size_increase: 25.0,
};

let is_acceptable = metrics.meets_thresholds(&config);
```

## Integration with Transforms

The analysis crate integrates closely with the transforms crate to provide continuous feedback during obfuscation:

1. **Pre-transformation** - Baseline metrics measurement
2. **Per-pass Analysis** - Incremental improvement tracking
3. **Post-transformation** - Final effectiveness validation
4. **Rollback Decisions** - Automatic rejection of ineffective passes

## Performance Considerations

Analysis operations are optimized for integration into the obfuscation pipeline:

- **Incremental Analysis** - Only recompute affected metrics
- **Cached Computations** - Avoid redundant calculations
- **Parallel Processing** - Concurrent metric computation where possible
- **Memory Efficient** - Minimal allocation during analysis

## Testing

Comprehensive test coverage for all metric calculations:

```bash
cargo test --lib
cargo test test_cyclomatic_complexity
cargo test test_entropy_calculation
cargo test test_threshold_validation
```

## Dependencies

- `azoth-core` - Core bytecode processing functionality
- `petgraph` - Graph algorithms for complexity analysis
- `serde` - Serialization for metrics export
- `tokio` - Async processing support

The analysis crate provides the quantitative foundation that ensures obfuscation transformations achieve meaningful improvements in privacy and security while maintaining acceptable performance characteristics.