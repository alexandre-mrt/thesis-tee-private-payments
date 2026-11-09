# Roadmap

## Next meeting: to validate
- [ ] The consequences of the foundation ([FOUNDATIONS.md](../FOUNDATIONS.md), "What follows from the rule"); the rule itself is validated (2026-10-19).
- [ ] Is the 2026-10-29 note "the TEE is trusted for correct execution, not for confidentiality" a transcription error? It conflicts with the kickoff principle.
- [ ] [Round 1](../round-1/README.md): the design, its crash behaviour, and its check against the trust model.
- [ ] Round 1's remaining dependence on the TEE: ownership is checked by the bank, balance still rests on the enclave's signing key.
- [ ] Which direction closes that gap: per-result attestation, additive commitments with range proofs (with or without TEE batching), or zero-knowledge proofs with the TEE reducing cost.

## After validation
- [ ] Round 1 status set to validated, with the meeting cited in [the validation log](validation-log.md).
- [ ] The chosen direction for balance integrity, as the next round.
- [ ] Glossary.
