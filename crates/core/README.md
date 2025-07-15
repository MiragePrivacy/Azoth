# Azoth Core

The `azoth-core` crate provides the fundamental building blocks for EVM bytecode analysis and transformation. This crate handles the essential stages of bytecode processing: decoding, analysis, intermediate representation generation, and re-encoding.

## Architecture

The core crate implements a multi-stage pipeline for bytecode processing:

1. **Bytecode Decoding** - Converts raw bytecode into structured instruction sequences
2. **Section Detection** - Identifies constructor, runtime, and auxiliary data sections
3. **Stripping** - Isolates runtime code from deployment artifacts
4. **CFG/IR Generation** - Builds control flow graphs with intermediate representation
5. **Encoding** - Reconstructs bytecode from transformed representations

## Key Components

### Decoder (`decoder.rs`)
Transforms raw EVM bytecode into structured instruction sequences with comprehensive metadata analysis. The decoder handles opcode parsing, jump target resolution, and instruction stream validation.

Key functions:
- `decode_bytecode()` - Main entry point for bytecode decoding
- `decode_instruction()` - Individual instruction parsing
- `resolve_jumps()` - Jump target analysis and validation

### Detection (`detection.rs`)
Analyzes bytecode structure to identify different sections including constructor code, runtime code, and auxiliary data. This component provides the foundation for precise bytecode manipulation.

Key functions:
- `locate_sections()` - Identifies and categorizes bytecode sections
- `detect_patterns()` - Recognizes common contract patterns
- `validate_structure()` - Ensures bytecode structural integrity

### Stripping (`strip.rs`)
Isolates runtime bytecode from deployment artifacts, producing clean execution code suitable for analysis and transformation. The stripping process maintains precise mappings for later reassembly.

Key functions:
- `strip_bytecode()` - Main stripping operation
- `extract_runtime()` - Isolates runtime code
- `generate_mapping()` - Creates reassembly mappings

### CFG/IR Generation (`cfg_ir.rs`)
Constructs control flow graphs with intermediate representation from EVM bytecode. This component transforms linear instruction sequences into analyzable graph structures that enable sophisticated obfuscation passes.

Key functions:
- `build_cfg_ir()` - Constructs CFG with IR from instructions
- `create_basic_blocks()` - Identifies and creates basic blocks
- `build_edges()` - Establishes control flow relationships
- `generate_ssa()` - Produces SSA form for stack operations

### Encoding (`encoder.rs`)
Reconstructs bytecode from transformed CFG/IR representations, maintaining semantic equivalence while integrating obfuscation modifications. The encoder ensures deterministic, reproducible output.

Key functions:
- `encode_cfg()` - Converts CFG back to bytecode
- `reassemble_sections()` - Combines transformed runtime with original sections
- `validate_output()` - Ensures semantic equivalence

## Usage Example

```rust
use azoth_core::{decode_bytecode, locate_sections, strip_bytecode, build_cfg_ir};

// Decode bytecode into instructions
let (instructions, info, _) = decode_bytecode("0x608060405234801561001057600080fd5b50", false).await?;

// Locate bytecode sections
let sections = locate_sections(&bytecode, &instructions, &info)?;

// Strip to isolate runtime code
let (clean_runtime, report) = strip_bytecode(&bytecode, &sections)?;

// Build CFG with intermediate representation
let cfg_bundle = build_cfg_ir(&instructions, &sections, &bytecode, report)?;

// The CFG is now ready for analysis and transformation
println!("CFG contains {} basic blocks", cfg_bundle.cfg.node_count());
```

## Data Structures

### Instruction
Represents a single EVM instruction with metadata including opcode, operands, program counter, and jump targets.

### Section
Defines bytecode sections with boundaries, types, and characteristics for proper processing and reassembly.

### CFG (Control Flow Graph)
Graph representation of program control flow using petgraph, enabling sophisticated analysis and transformation operations.

### CleanReport
Maintains mapping information between original and stripped bytecode for precise reassembly after transformations.

## Dependencies

- `heimdall` - EVM disassembly and analysis
- `petgraph` - Graph data structures and algorithms
- `eot` - Ethereum opcode toolkit
- `tokio` - Async runtime for processing operations

## Testing

The core crate includes comprehensive test coverage for all major components:

```bash
cargo test --lib
cargo test test_decode_simple_contract
cargo test test_cfg_generation
cargo test test_strip_runtime
```

## Error Handling

The crate uses structured error types for comprehensive error reporting:
- `DecodeError` - Bytecode decoding failures
- `DetectionError` - Section detection issues
- `CfgIrError` - CFG/IR generation problems
- `EncodeError` - Bytecode reconstruction failures

All operations return `Result` types with detailed error information for debugging and recovery.