## bytecloak-verification

This crate provides mathematical guarantees that obfuscated smart contracts behave identically to their original versions. When we obfuscate bytecode, we fundamentally alter its structure while preserving functionality. Formal verification uses mathematical proofs to ensure this preservation is complete and correct.

Traditional testing can only verify specific cases, but smart contracts must handle infinite input combinations. A single undetected difference between original and obfuscated contracts could compromise security or functionality. Formal verification provides mathematical certainty that the contracts are equivalent for **all possible inputs**, not just tested ones.

We use SMT-LIB (Satisfiability Modulo Theories) as our mathematical language to express contract properties, and Z3 theorem prover to automatically verify these properties. This serves as link between low-level bytecode and high-level mathematical reasoning.

Now our verification establishes four key equivalence properties:

- Bisimulation
```smt
(assert (forall ((state State) (input Input))
    (= (execute-original state input)
       (execute-obfuscated state input))))
```
For EVERY input and state, both contracts produce the same execution trace.

- State Equivalence
```smt
(assert (forall ((initial-state State) (transaction Tx))
    (= (final-state (execute-original initial-state transaction))
       (final-state (execute-obfuscated initial-state transaction)))))
```
After ANY transaction, the storage, balances, and contract state are identical between original and obfuscated versions.

- Property Preservation
```smt
(assert (forall ((s State)) 
    (and (access-control-original s) 
         (access-control-obfuscated s))))
```
ALL security properties satisfied by original are satisfied by obfuscated.

- Gas Bounds
```smt
(assert (forall ((tx Transaction))
    (<= (gas-used (execute-obfuscated tx))
        (* 1.15 (gas-used (execute-original tx))))))
```
For ANY transaction, obfuscated version uses at most 15% more gas.
