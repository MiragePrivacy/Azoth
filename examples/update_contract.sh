#!/bin/bash

set -e

echo "🚀 Updating Escrow.sol from MiragePrivacy/escrow"
echo "============================================="
echo ""

# Check if we're in the examples directory
if [[ ! -f "Cargo.toml" || ! -d "contracts" ]]; then
    echo "❌ Please run this script from the examples/ directory"
    echo "   Current directory: $(pwd)"
    exit 1
fi

# Download Escrow.sol from MiragePrivacy/escrow (master branch)
echo "📥 Downloading Escrow.sol..."
curl -s -o contracts/Escrow.sol https://raw.githubusercontent.com/MiragePrivacy/escrow/master/src/Escrow.sol

# Validate the downloaded file
if grep -q "404: Not Found" contracts/Escrow.sol; then
    echo "❌ Error: Failed to download Escrow.sol (404: Not Found)"
    echo "   Check the repository URL or file path: https://github.com/MiragePrivacy/escrow/blob/master/src/Escrow.sol"
    exit 1
fi

# Run setup.sh to compile the contract
echo "🔨 Running setup.sh to compile contract..."
chmod +x setup.sh
./setup.sh
