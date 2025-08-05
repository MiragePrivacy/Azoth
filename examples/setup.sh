#!/bin/bash

set -e

echo "🚀 Setting up Mirage Obfuscation Workflow Demo"
echo "=============================================="
echo ""

# Check if we're in the right location
if [[ ! -f "../Cargo.toml" ]]; then
    echo "❌ Please run this script from: examples/"
    echo "   Current directory: $(pwd)"
    exit 1
fi

echo "📁 Creating directory structure..."
mkdir -p src contracts

echo "🔨 Setting up Foundry project..."
if command -v forge &> /dev/null; then
    # Create Foundry project in the current mirage-workflow directory
    if [ ! -d "foundry-contracts" ]; then
        echo "   Creating new Foundry project..."
        forge init foundry-contracts --no-git
    else
        echo "   Foundry project already exists"
    fi
    
    cd foundry-contracts
    
    # Install dependencies
    echo "   Installing OpenZeppelin contracts..."
    forge install OpenZeppelin/openzeppelin-contracts@v5.0.2 --no-git || true
    
    # Copy our contract to src/
    echo "   Copying Escrow.sol..."
    cp ../contracts/Escrow.sol src/ 2>/dev/null || true
    
    # Compile contracts
    echo "   Compiling contracts..."
    if ! forge build; then
        echo "   ❌ Compilation failed. Check Escrow.sol for errors."
        exit 1
    fi
    
    if [ -f "out/Escrow.sol/Escrow.json" ]; then
        echo "   ✅ Escrow compiled successfully!"
        # Show some info about the compiled contract
        BYTECODE_SIZE=$(jq -r '.bytecode.object' out/Escrow.sol/Escrow.json | wc -c)
        echo "   📏 Bytecode size: $((BYTECODE_SIZE/2)) bytes"
    else
        echo "   ❌ Compilation failed: Artifact not found (out/Escrow.sol/Escrow.json)"
        exit 1
    fi
    
    cd ..
else
    echo "   ⚠️ Forge not found. Install Foundry for real contract compilation:"
    echo "   curl -L https://foundry.paradigm.xyz | bash"
    echo "   foundryup"
    exit 1
fi

echo ""
echo "🦀 Building Rust project..."
if ! cargo build; then
    echo "   ❌ Rust project compilation failed."
    exit 1
fi

echo ""
echo "🎉 Setup complete!"
echo "📋 Next steps:"
echo "   Run the demo: cargo run --bin azoth-examples"
echo "   Verify the report: cat mirage_report.json"
