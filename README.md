# Azoth

**Azoth** is an open-source EVM‐bytecode obfuscator. Its purpose is to make Mirage's execution contracts _statistically indistinguishable_ from the ocean of ordinary, unverified deployments on Ethereum, giving users on-chain privacy **without** the tell-tale fingerprints that mixers or shielded pools leave behind. In the process of doing this, we also raise the analytical cost of deobfuscating a single contract while keeping gas overhead and deploy size in check. Now, with this in mind, we approach this with a philosophy that says: "dissect first, disguise later". Therefore, Azoth analyses a contract's control-flow, rewrites it with deterministic layered transforms, it then re-assembles and emit a byte‑for‑byte reproducible binary.

## Overview
Azoth unfolds itself in three different stages:

1. **Pre-processing**  
   In this stage we precisely isolate/analyze the different sections of the EVM bytecode, producing a clean `runtime` blob and a typed instruction stream.

2. **Obfuscation Core**  
   The `runtime` is lifted into a `CFG + SSA` intermediate representation. Deterministic, pluggable passes then mutate the graph with different transforms. After each pass we recompute metrics; if its score does not improve the overall metrics beyond a configurable threshold the changes are rolled back.
   
3. **Bytecode Recovery**  
   The encoder re-assembles the transformed runtime with the untouched constructor, aux-data, etc. producing deployable bytecode whose Keccak matches deterministic recompilation `(O(S, seed))`


### Metrics We Track

* **Potency** – how much structural and statistical complexity we add (cyclomatic complexity, injected opaque instructions, etc.).  
* **Resilience** – resistance to automated decompilation
* **Cost** – overhead in gas and byte size.

Every transform must raise Potency and Resilience above clearly defined thresholds _while keeping Cost below the defined threshold_, otherwise it is rejected.

### Quick Start

```bash
cd crates/cli
cargo install --path .
azoth decode <INPUT>
azoth strip <INPUT> [--raw]
azoth cfg <INPUT> [-o <OUTPUT>]
azoth obfuscate <INPUT> [--seed <SEED>] [--passes <PASSES>] [--accept-threshold <THRESHOLD>] [--max-size-delta <DELTA>] [--emit <PATH>]
```
