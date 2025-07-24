# Azoth Core

The `azoth-core` crate provides the fundamental building blocks for EVM bytecode analysis and transformation. This crate handles the essential stages of bytecode processing: decoding, analysis, intermediate representation generation, and re-encoding.

## Architecture

The core crate implements a multi-stage pipeline for bytecode processing:

1. **Bytecode Decoding** - Converts raw bytecode into structured instruction sequences
2. **Section Detection** - Identifies constructor, runtime, and auxiliary data sections
3. **Stripping** - Isolates runtime code from deployment artifacts
4. **CFG/IR Generation** - Builds control flow graphs with intermediate representation
5. **Encoding** - Reconstructs bytecode from transformed representations
