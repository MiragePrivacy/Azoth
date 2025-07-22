# Azoth Transforms

The `azoth-transform` crate implements the obfuscation transformations that enhance bytecode complexity and resistance to analysis. This crate provides a pluggable architecture for applying various obfuscation techniques while maintaining semantic equivalence.

## Architecture

The transforms crate implements a pass-based architecture where each transformation operates on the CFG/IR representation:

1. **Pass Interface** - Standardized transformation interface for modularity
2. **Transformation Passes** - Individual obfuscation techniques
3. **Metrics Integration** - Continuous evaluation during transformation
4. **Rollback Support** - Automatic rejection of ineffective passes

## Current Transforms

### Shuffle (`shuffle.rs`)

Reorders basic blocks within the CFG while updating jump targets to maintain correctness. Simple block-level randomization that changes program layout without affecting execution.

Example

```
Original -> 0x60015b6002
Shuffled -> 0x5b60026001
```

###  Opaque Predicate (`opaque_predicate.rs`)

Injects always-true (or always-false) predicates built from cheap arithmetic or constant-equality (e.g., XOR + ISZERO or EQ on identical constants). Adds dummy control-flow that never influences observable behavior but explodes CFG shape.

Example

Original bytecode: 0x6001600260016003 (8 bytes, 4 instructions, 1 block)
```assembly
PUSH1 0x01
PUSH1 0x02  
PUSH1 0x01
PUSH1 0x03
```

After OpaquePredicate: (~80–100 bytes, ~12 instructions, 3 blocks; seed-dependent)
```assembly
// Original block (now with predicate appended)
PUSH1 0x01
PUSH1 0x02
PUSH1 0x01
PUSH1 0x03
PUSH32 C                // Random 32-byte constant
PUSH32 C                // Same constant
XOR                     // 0
ISZERO                  // -> 1 (true)
PUSH2 true_pc
JUMPI
JUMPDEST                // Join point (false path)
JUMP false_pc

// New true_label block
JUMPDEST                // True branch target (always taken)
// execution continues to original fallthrough

// New false_label block  
JUMPDEST                // False branch target (never reached)
PUSH1 0x00
JUMP <original_fallthrough>  // Dead code path
```

Changes: +80-100 bytes, splits 1 block into 3, adds always-true branching that never affects execution but complicates CFG analysis.

### Jump Address Transformer (`jump_address_transformer.rs`)

Splits jump targets into arithmetic operations. Replaces PUSH1 0x42 JUMP with PUSH1 0x20 PUSH1 0x22 ADD JUMP where the values sum to the original target.

Example

Original bytecode: 0x60085760015b00 (7 bytes, 5 instructions, 3 blocks)

```assembly
PUSH1 0x08    // Direct jump target
JUMPI         // Conditional jump to 0x08
PUSH1 0x01    // Fallthrough path  
JUMPDEST      // Jump destination at 0x08
STOP
```

After JumpAddressTransformer: 0x60046004015760015b00 (10 bytes, 7 instructions, 3 blocks)
```assembly
PUSH1 0x04    // First part of split target
PUSH1 0x04    // Second part (0x04 + 0x04 = 0x08)
ADD           // Compute original target at runtime
JUMPI         // Conditional jump to computed value
PUSH1 0x01    // Fallthrough path unchanged
JUMPDEST      // Same jump destination  
STOP
```

Changes: +3 bytes, +2 instructions; replaces direct 0x08 with 0x04 + 0x04 via ADD. Net +6 gas (2 extra PUSH1s + ADD – original single PUSH1).

### Function Dispatcher (function_dispatcher.rs)

Obfuscates Solidity function dispatcher patterns by randomizing selector check order, adding dummy comparisons, and using different comparison patterns.

Example

Original dispatcher:
```assembly
PUSH1 0x00
CALLDATALOAD
DUP1
PUSH4 0x2e64cec1    // Real selector A
EQ
PUSH1 0x17          // Jump to function A
JUMPI
DUP1  
PUSH4 0x60fe47b1    // Real selector B
EQ
PUSH1 0x19          // Jump to function B  
JUMPI
JUMPDEST            // Function A
STOP
JUMPDEST            // Function B
STOP
```

Obfuscated dispatcher:
```
PUSH1 0x00
CALLDATALOAD
PUSH1 0xE0
SHR                 // Explicit selector extraction
DUP1
PUSH4 0x2e64cec1    // Real selector A (kept)
EQ
ISZERO              // Inverted branch logic
PUSH1 0x62          // Jump past padding if NOT equal
JUMPI
PUSH1 0x59          // Dummy branch target
JUMP
DUP1
PUSH4 0x3fad005b    // Fake selector (was 0x60fe47b1)
EQ
STOP                // Dead code + 62 bytes of 0x00 padding
```

Changes:
- 27 bytes → 89 bytes, +248 (≈ 1.2 %) gas
- Inserted PUSH1 0xE0; SHR.
- Inverted the branch with ISZERO (and swapped jump targets).
- Added a “fake” branch (PUSH1 0x59; JUMP) that jumps into padding.
- Replaced the second selector 0x60fe47b1 with 0x3fad005b.
- Inserted 62 zero bytes (`0x00`, decoded as STOP) as padding while keeping the non‑zero‑byte count unchanged (24).

### Transform Interface

```rust
#[async_trait]
pub trait Transform: Send + Sync {
    fn name(&self) -> &'static str;
    async fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError>;
}
```

### Pass Execution
The pass.rs module provides a simple sequential pass runner:
```rust
use azoth_transform::{run, PassConfig};

let transforms: Vec<Box<dyn Transform>> = vec![
    Box::new(Shuffle),
    Box::new(OpaquePredicate::new(PassConfig::default())),
    Box::new(JumpAddressTransformer::new(PassConfig::default())),
];

run(&mut cfg_ir, &transforms, &PassConfig::default(), seed).await?;
```

### Configuration
Basic configuration through PassConfig:
```rust
pub struct PassConfig {
    pub accept_threshold: f64,      // Minimum quality threshold
    pub aggressive: bool,           // Skip quality gates
    pub max_size_delta: f32,        // Max size increase ratio
    pub max_opaque_ratio: f32,      // Max blocks to apply opaque predicates
}
```

The transforms operate on CfgIrBundle structures and use metrics from azoth-analysis to evaluate effectiveness.
