# Roadmap

Items enter this repository only after an advisor validates them.

## Next meeting: to validate
- [ ] Confirm the foundation and resolve open question 2 in [FOUNDATIONS.md](FOUNDATIONS.md).
- [ ] Choose how integrity is verified without trusting the TEE ([FOUNDATIONS.md](FOUNDATIONS.md), open question 1).
- [ ] Trust model per party (privacy, integrity, availability) and the goals.
- [ ] Round 1 specification, including its behaviour when the TEE fails and its check against the trust model.

## After validation: to add here
- [ ] `round-1/`: the refined round 1 design document, rewritten to satisfy the foundation.
- [ ] `round-1/system-map`: the full system map (actors, logs, messages, properties, assumptions), redrawn from the validated design.
- [ ] Glossary.

## Known gap in the current draft (private workspace, not validated)
The current round 1 draft (thesis workspace D-031, D-032) trusts the enclave for integrity: the bank accepts any output signed by an attested enclave key. A broken enclave could therefore sign payments that create money. The draft does not yet satisfy the foundation and must be reworked before it enters this repository.
