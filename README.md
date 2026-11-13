# Thesis: TEEs for private payments

EPFL master thesis at Mysten Labs (advisors Karl Wüst, Alberto Sonnino, Lefteris Kokoris-Kogias).

Can a trusted execution environment (TEE) run by a central bank replace the zero-knowledge proofs of a private payment system such as Platypus, so that a broken TEE costs privacy but never integrity?

## Read in this order
| | Content | Status |
|---|---|---|
| [Scope](SCOPE.md) | The setting, the direction, the deliverables | Validated (2026-10-19, 2026-10-29) |
| [Foundation](FOUNDATIONS.md) | The rule every design follows: the TEE protects privacy, never integrity | Rule validated (2026-10-19); consequences submitted |
| [Round 1](round-1/README.md) | Platypus with one TEE call in place of the proofs; serials as one-time public keys | Submitted (2026-11-09), revised (2026-11-10) |
| [Implementation](implementation/README.md) | Rust prototype of round 1: bank, enclave, wallet, tests, benchmarks | Submitted (2026-11-12); mock enclave, Nitro deployment pending |

Every design file (scope, foundation, rounds) states its status: **validated** cites the meeting, **submitted** awaits the next one. Meeting logistics (roadmap, validation log) are in [logistics/](logistics/).
