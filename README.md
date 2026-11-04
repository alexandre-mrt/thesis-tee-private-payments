# Thesis: TEEs for private payments

EPFL master thesis at Mysten Labs (advisors Karl Wüst, Alberto Sonnino, Lefteris Kokoris-Kogias).

**Rule of this repository:** it holds only what the advisors have validated. Every statement cites the meeting where it was validated. Working notes, proposals and drafts stay in the private workspace (`~/projects/thesis/Master Thesis`) and the prototype repository (`tee-pay`) until a meeting validates them.

| File | Content | Status |
|---|---|---|
| [SCOPE.md](SCOPE.md) | Thesis scope and direction | Validated (2026-10-19 kickoff, 2026-10-29 Karl) |
| [FOUNDATIONS.md](FOUNDATIONS.md) | Trust foundation: the TEE protects privacy, never integrity | Validated (2026-10-19 kickoff); its design consequences are listed as open questions |
| [ROADMAP.md](ROADMAP.md) | What enters this repository next, and what must be validated first | Working list |

## Validation log
| Date | Meeting | Validated |
|---|---|---|
| 2026-10-19 | Kickoff (Karl, Alberto, Lefteris) | CBDC setting with a privacy focus; TEE for privacy, not for integrity; blockchain optional; a large spent set is acceptable; build on Platypus; reuse existing building blocks; track design, implementation and evaluation; industry-grade evaluation |
| 2026-10-29 | Karl | The bank is trusted for integrity; replace the ZK proofs by a TEE inside the bank; the TEE as stateless as possible; define the trust model per party; recovery when the TEE fails; a simple, solid design |
