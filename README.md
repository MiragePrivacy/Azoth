## bytecloak

`bytecloak` is a research‑grade toolchain for *Ethereum smart‑contract obfuscation*. Our guiding principle, is:

> *“Dissect first – disguise later.”*

The project therefore unfolds in **three simple stages**:

| Stage                             | Goal                                                                               | What we build                                                                                                       |
| --------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Pre‑processing / Analysis | Precisely isolate the on‑chain **runtime** bytecode and measure its structure.     | Byte‑accurate cleaner (auxdata & init stripper). Stack‑SSA IR + CFG builder. Potency/Cost metrics & JSON report |
| Obfuscation Passes        | Apply reversible transforms that raise analyst effort while bounding gas overhead. | Control‑flow flattening. Opaque predicates. Data/constant encoders. Layout shufflers                              |
| Re‑assembly & Validation  | Splice removed segments back, emit final artefact, run differential tests.         | Byte‑perfect re‑assembler. Dynamic equivalence harness (REVM). Gas/size delta report                              |

### overview

```
crates/
 ├─ core/       # loader + detector + strip + IR/CFG
 ├─ analysis/   # dominators, metrics, pattern miners
 ├─ transforms/ # obfuscation passes
 ├─ cli/        # `bytecloak` binary
 └─ utils/      # tracing, error, hex helpers
```
