# bytecloak

**bytecloak** is a research‑grade toolchain for *Ethereum smart‑contract obfuscation*. Our guiding principle, is:

> *“Dissect first – disguise later.”*

The project therefore unfolds in **three simple stages**:

| Stage                             | Goal                                                                               | What we build                                                                                                       |
| --------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **1  Pre‑processing / Analysis** | Precisely isolate the on‑chain **runtime** bytecode and measure its structure.     | Byte‑accurate *cleaner* (auxdata & init stripper). Stack‑SSA IR + CFG builder. Potency/Cost metrics & JSON report |
| **2  Obfuscation Passes**        | Apply reversible transforms that raise analyst effort while bounding gas overhead. | Control‑flow flattening. Opaque predicates. Data/constant encoders. Layout shufflers                              |
| **3  Re‑assembly & Validation**  | Splice removed segments back, emit final artefact, run differential tests.         | Byte‑perfect re‑assembler. Dynamic equivalence harness (REVM). Gas/size delta report                              |

---

## Current milestone: **Stage 1**

```
crates/
 ├─ core/       # loader + detector + strip + IR/CFG
 ├─ analysis/   # dominators, metrics, pattern miners
 ├─ transforms/ # obfuscation passes
 ├─ cli/        # `bytecloak` binary
 └─ utils/      # tracing, error, hex helpers
```

Implemented so far:

* 🔍 **Detection** — splits Init, Args, Runtime, Auxdata (CBOR)
* ✂️ **Strip** — extracts the runtime blob, stores precise removal map, guarantees round‑trip.

Next up:
- [ ] **SSA IR** + CFG dominance.

- [ ] CLI commands: `bytecloak disasm|strip|cfg|metrics`.

- [ ] Docs: architecture.md