# Foundation: the TEE protects privacy, never integrity

## Validated principle
"TEE not for integrity but for privacy" (kickoff, 2026-10-19, all advisors). Combined with "the bank is trusted for integrity" (Karl, 2026-10-29), this gives:

| If the TEE... | Privacy | Integrity (no forged, stolen or duplicated money) | Availability |
|---|---|---|---|
| works | Holds | Holds | Holds |
| crashes | Holds | Holds | Paused until a new instance runs |
| is broken (its memory read or its keys used) | May be lost for the data it processed | **Must still hold** | Not required |

**Integrity must never depend on the TEE.** The bank, which is trusted for integrity, must be able to reject every invalid payment using only what it can verify itself: its own signatures, its spent set, and checks that need no secret held by the enclave.

## Integrity properties that must survive a broken TEE
From Platypus, Section 5:
- **Unforgeability:** nobody spends a state they do not own, and nobody changes the amount of a payment.
- **Balance invariance:** every payment moves exactly its amount; no money is created or destroyed.
- **No double spending:** each state is spent once.
- **Fund-destruction resistance:** nobody can make another user's state unspendable.

## Privacy properties the TEE may protect
- **Transaction indistinguishability toward the bank** (Platypus Def. 5.2): the bank does not learn who pays whom, amounts or balances.

A broken TEE may lose this property for the payments it processed, but never the integrity properties above.

## Open design questions (not validated)
1. **Who verifies validity, if not the TEE?** The bank must check balance conservation and ownership without seeing values. Candidates:
   - zero-knowledge proofs, as in Platypus (the TEE then helps with privacy-related work only, for example as a delegated prover that holds witnesses but no authority);
   - user signatures with one-time keys, which stop theft of existing funds but not counterfeiting;
   - several TEEs from different vendors co-signing, which only raises the bar.

   The choice decides what "a TEE replaces the ZK proofs" can mean under this principle.
2. **Is the 2026-10-29 note "the TEE is trusted for correct execution, not for confidentiality" a transcription error?** It conflicts with the kickoff principle above, and needs confirming at the next meeting.
3. **Which privacy properties may a broken TEE lose?** For example the payments it processed, or also the future linkability of the users involved.
