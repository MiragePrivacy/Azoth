#!/bin/bash

set -e

echo "🚀 Setting up Mirage Obfuscation Workflow Demo"
echo "=============================================="
echo ""

# Check if we're in the right location
if [[ ! -f "../../Cargo.toml" ]]; then
    echo "❌ Please run this script from: examples/mirage-workflow/"
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
    forge install OpenZeppelin/openzeppelin-contracts --no-git --no-commit || true
    
    # Copy our contract to src/
    echo "   Copying MirageEscrow.sol..."
    cp ../contracts/MirageEscrow.sol src/ 2>/dev/null || true
    
    # Compile contracts
    echo "   Compiling contracts..."
    forge build
    
    if [ -f "out/MirageEscrow.sol/MirageEscrow.json" ]; then
        echo "   ✅ MirageEscrow compiled successfully!"
        # Show some info about the compiled contract
        BYTECODE_SIZE=$(jq -r '.bytecode.object' out/MirageEscrow.sol/MirageEscrow.json | wc -c)
        echo "   📏 Bytecode size: $((BYTECODE_SIZE/2)) bytes"
    else
        echo "   ⚠️  Compilation may have failed, will use fallback contract"
    fi
    
    cd ..
else
    echo "   ⚠️  Forge not found. Install Foundry for real contract compilation:"
    echo "   curl -L https://foundry.paradigm.xyz | bash"
    echo "   foundryup"
    echo ""
    echo "   Will use fallback contract for demo"
fi

echo ""
echo "🦀 Building Rust project..."
cargo build

echo ""
echo "🎉 Setup complete! Ready to demonstrate Mirage workflow"
echo ""
echo "📋 What's been set up:"
echo "   ✅ Foundry project with MirageEscrow contract"
echo "   ✅ Compiled bytecode ready for obfuscation"  
echo "   ✅ Rust workflow implementation"
echo "   ✅ Gas analysis and integrity verification"
echo ""
echo "🚀 Run the demo:"
echo "   cargo run --bin mirage-workflow"
