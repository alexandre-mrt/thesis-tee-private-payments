# Validation log

What each advisor meeting validated.

| Date | Meeting | Validated |
|---|---|---|
| 2026-10-19 | Kickoff (Karl, Alberto, Lefteris) | CBDC setting with a privacy focus; TEE for privacy, not for integrity; blockchain optional; a large spent set is acceptable; build on Platypus; reuse existing building blocks; track design, implementation and evaluation; industry-grade evaluation |
| 2026-10-29 | Karl | The bank is trusted for integrity; replace the ZK proofs by a TEE inside the bank; the TEE as stateless as possible; define the trust model per party; recovery when the TEE fails; a simple, solid design |
| 2026-11-10 | Advisors | The enclave runs inside the bank: results go straight to the bank, which settles in the same step and answers the payee (no relay of results); attestation is kept; properties to be stated as ownership integrity and balance integrity in Platypus's terms; new properties to explore for the next round (auditability, a proof that no money was printed, forward secrecy, non-repudiation) |
