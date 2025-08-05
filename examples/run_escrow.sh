#!/bin/bash

set -e

echo "🚀 Running Mirage Obfuscation Workflow for Escrow"
echo "================================================"
echo ""

# Check if we're in the examples directory
if [[ ! -f "Cargo.toml" ]]; then
    echo "❌ Please run this script from the examples/ directory"
    echo "   Current directory: $(pwd)"
    exit 1
fi

# Initialize submodule if not present
if [ ! -d "escrow-bytecode" ]; then
    echo "📥 Initializing escrow submodule..."
    git submodule update --init --recursive
else
    echo "📥 Updating escrow submodule to latest..."
    git submodule update --remote --merge escrow-bytecode
fi

# Validate the bytecode file exists in submodule
if [ ! -f "escrow-bytecode/artifacts/bytecode.hex" ]; then
    echo "❌ Error: Bytecode file not found (escrow-bytecode/artifacts/bytecode.hex)"
    echo "   Ensure it's committed in the escrow repo and try again."
    exit 1
fi

# Build Rust project
echo ""
echo "🦀 Building Rust project..."
if ! cargo build; then
    echo "   ❌ Rust project compilation failed."
    exit 1
fi

# Run the obfuscation demo
echo ""
echo "🔨 Running obfuscation demo..."
cargo run --bin azoth-examples

echo ""
echo "🎉 Workflow complete!"
echo "📋 Verify the report: cat mirage_report.json"