# Scope

**Status:** validated (kickoff 2026-10-19, Karl 2026-10-29).

## Setting
- **A central bank digital currency (CBDC) with a privacy focus** (kickoff, 2026-10-19).
- **The baseline is Platypus** (Wüst et al., CCS 2022): "Platypus, but more efficient for a central bank with a TEE" (kickoff).
- **Blockchain and Sui are optional.** A ledger is used only where it adds value (kickoff).
- **A large spent set (nullifier set) is acceptable** in the central-bank setting (kickoff).
- **Reuse existing building blocks:** "Take things that exist and put them together. Don't create a product" (kickoff).

## Direction
- **The TEE protects privacy, not integrity** (kickoff). See [FOUNDATIONS.md](FOUNDATIONS.md).
- **The bank is trusted for integrity.** The thesis focuses on users' privacy (Karl, 2026-10-29).
- **A TEE inside the bank replaces the ZK proofs,** to make Platypus cheaper for users (Karl, 2026-10-29).
- **The TEE keeps no state,** or as little as possible (Karl, 2026-10-29).
- **The main design question:** how state survives across TEE instances when one fails, and how the system recovers (Karl, 2026-10-29; open question at kickoff: "how to keep track of state, keys").
- **The goal:** a simple, solid design (Karl, 2026-10-29).

## Deliverables requested
From Karl, 2026-10-29:
1. **The trust model:** privacy, integrity and availability, defined per party.
2. **The goals.**
3. **A specification that still works when the TEE fails,** with its recovery plan and trade-offs.
4. **A check of the specification against the trust model.**

## Process and evaluation
From Alberto at the kickoff:
- every design, implementation and evaluation decision is tracked;
- the evaluation is industry-grade and lists every tool used.

## Outside the core scope (kickoff)
- **AI:** a mix of privacy and AI at most; publishing in AI alone is too competitive (Lefteris).
- **Ideas raised but not chosen:** offline payments, travel-rule reconciliation, anonymised analytics in a TEE, and Zef with a TEE.
