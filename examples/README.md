# Azoth Examples
An example use of Azoth in Mirage Protocol

## Quick Start

1. Initial setup:
```bash
cd examples/
chmod +x update_contract.sh
./update_contract.sh
```

2. Run the example:
```bash
cargo run --bin azoth-examples
```

## Notes

- The Escrow.sol contract is sourced from `MiragePrivacy/escrow/src/Escrow.sol`.
- Ensure Foundry is installed to compile the contract (curl -L https://foundry.paradigm.xyz | bash and foundryup if needed).
- Output reports are saved to mirage_report.json for analysis.
