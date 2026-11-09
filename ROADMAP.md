# Roadmap

## Next meeting: to validate
- [ ] Confirm the foundation and resolve open question 2 in [FOUNDATIONS.md](FOUNDATIONS.md).
- [ ] [Round 1](round-1/README.md): the design, its crash behaviour, and its check against the trust model.
- [ ] Round 1's remaining dependence on the TEE: ownership is enforced by the bank, balance conservation still rests on the enclave's signing key ([round 1, section 9](round-1/README.md#9-if-the-enclaves-memory-is-read)).
- [ ] Which direction closes that gap: per-result attestation, additive commitments with range proofs (with or without TEE batching), or zero-knowledge proofs with the TEE reducing cost.

## After validation: to add here
- [ ] Round 1 status updated to validated, with the meeting cited.
- [ ] The chosen direction for balance integrity, as round 1b or round 2.
- [ ] Glossary.
