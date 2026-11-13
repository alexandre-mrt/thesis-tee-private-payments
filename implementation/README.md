# Round 1 prototype (tee-pay-v2)

Rust prototype of [round 1](../round-1/README.md) as revised at the advisor meeting of 2026-11-10: the enclave runs inside the bank's machine, serials are one-time Ed25519 public keys derived from a wallet seed, owners sign every payment, the bank checks those signatures itself (B1 to B4) and forwards the sealed openings to its own enclave (E1 to E4), which answers a signed result over the bank's fresh nonce (B3).

**Status:** submitted with round 1 (2026-11-12). Runs on loopback with a mock enclave; not yet deployed on AWS Nitro.

## Read in this order
| File | Content |
|---|---|
| [SPEC.md](SPEC.md) | The specification the code follows: flow, checks, properties P1 to P5, required tests |
| [docs/DESIGN.md](docs/DESIGN.md) | What the code does: processes and keys, primitives, wire messages, which check carries which property, what the bank sees, blast radius of an enclave read, limitations |
| [docs/payment-flow.pdf](docs/payment-flow.pdf) | One payment through the code: every wire message with its fields, the function behind each step, B1 to B4 and E1 to E4, keys, what is persisted where, which check carries P1 to P5, what the bank sees ([PNG](docs/payment-flow.png), [source](docs/payment-flow.tex)) |
| [docs/payment-flow-2.pdf](docs/payment-flow-2.pdf) | Around the payment: startup and enclave registration, enroll and refresh, issue and redeem, recovery from the seed, crash and retry cases ([PNG](docs/payment-flow-2.png), [source](docs/payment-flow-2.tex)) |
| [docs/BENCH.md](docs/BENCH.md) | Measured performance, machine, commands, before and after each optimisation |

## Layout
| Crate | Role |
|---|---|
| `tv-core` | primitives (HKDF keys, commitments, digests, signatures), wire messages, constants |
| `tv-enclave` | enclave: one channel key per attestation, checks E1 to E4, signed results |
| `tv-bank` | bank server: owner signatures, spent set, durable log with group commit, issuance ledger, enclave link |
| `tv-client` | wallet (`tv-cli`): enroll, request, pay, receive, finish, refresh, redeem, recover |
| `tv-tests` | integration tests for P1 to P5, attacks with a leaked enclave memory, crash cases |
| `tv-bench` | benchmarks behind `docs/BENCH.md` |
| `pt-tee`, `pt-host` | vendored attestation and enclave transport (Nitro NSM and a mock) |

## Commands
Needs rustup (the toolchain is pinned in `rust-toolchain.toml`).

```sh
make test        # build, all tests, a short bench run, clippy -D warnings, fmt check
make demo        # bank, mock enclave, two wallets: issue, pay, refresh, redeem, recover
make crash-demo  # enclave killed before answering, bank killed after its log append
make bench       # the measurements of docs/BENCH.md
```

## Measured (Apple M3 Pro, loopback, mock enclave)
From [docs/BENCH.md](docs/BENCH.md): one enclave check costs about 0.19 ms, which is the mandated cryptography (4 signature verifications, 2 openings, 1 signature); the bank settles about 6,000 payments per second with 44 concurrent pairs thanks to group commit of its log; a payment takes about 4.4 ms end to end at the median.

## Review history
The code went through a performance pass and 13 audit rounds (protocol and integrity, privacy toward the bank, crash and durability, code and spec conformance), each finding reproduced before being fixed with a regression test. The rounds found fewer and smaller defects over time, but did not reach three consecutive rounds without a serious finding: the last rounds still found one crash-recovery corner case each (torn or cut log tails, group-commit edge cases), all fixed. Two privacy gaps came from the literature review rather than the audits and are fixed: the payer now refuses a stale attestation, and the enclave no longer receives any network attribute of the client.

## Known limitations
Listed in full in [docs/DESIGN.md](docs/DESIGN.md#limitations): no Nitro deployment yet; no TLS between users and the bank (an on-path attacker can burn a channel key, availability only); the bank sees source addresses (network anonymity is out of scope, as in Platypus); balance integrity rests on the enclave's result over the bank's own channel, so it holds against a remote reader of enclave memory and not against a host-level one (see [FOUNDATIONS.md](../FOUNDATIONS.md)).
