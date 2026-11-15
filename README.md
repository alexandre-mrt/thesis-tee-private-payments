# Thesis: TEEs for private payments

EPFL master thesis at Mysten Labs (advisors Karl Wüst, Alberto Sonnino, Lefteris Kokoris-Kogias).

Can a trusted execution environment (TEE) run by a central bank replace the zero-knowledge proofs of a private payment system such as Platypus, so that a broken TEE costs privacy but never integrity?

## In short
- **Setting.** A central bank digital currency with a privacy focus, built on Platypus (Wüst et al., CCS 2022). The bank is trusted for integrity and honest-but-curious for privacy; users are untrusted.
- **The idea.** Platypus's two zero-knowledge proofs are replaced by one check in a TEE (the enclave) that runs inside the bank. The enclave opens the hidden states and checks the balances, so the bank never sees amounts, balances, or who pays whom.
- **The rule.** If the TEE breaks, only privacy may be lost: no money is created, stolen, spent twice or destroyed. No secret that can spend funds is ever sent to the TEE.
- **How round 1 meets it.** Serials are one-time public keys derived from each user's seed. Owners sign every payment, and the bank checks those signatures and its spent set itself, so ownership, no double spend and no fund destruction hold even if the enclave's memory is read.
- **The open gap.** Balance integrity still rests on the enclave's checks, accepted only from the bank's own enclave over its own channel. It holds against a remote reader of enclave memory, not against a host-level one; closing it needs a check the bank verifies itself ([round 1, section 11](round-1/PROTOCOL.md#11-possible-solutions-for-balance-integrity)).
- **Status.** Scope and rule validated; round 1 and its Rust prototype (mock enclave, AWS Nitro deployment pending) submitted for validation.

## Contents
| | Content | Status |
|---|---|---|
| [Scope](#scope) | The setting, the direction, the deliverables | Validated (2026-10-19, 2026-10-29) |
| [Foundation](#foundation-the-tee-protects-privacy-never-integrity) | The rule every design follows: the TEE protects privacy, never integrity | Rule validated (2026-10-19); consequences submitted |
| [Round 1](round-1/PROTOCOL.md) | Platypus with one TEE call in place of the proofs; serials as one-time public keys | Submitted (2026-11-09), revised (2026-11-10) |
| [Implementation](implementation/README.md) | Rust prototype of round 1: bank, enclave, wallet, tests, benchmarks | Submitted (2026-11-12); mock enclave, Nitro deployment pending |

Every design section and file states its status: **validated** cites the meeting, **submitted** awaits the next one. Meeting logistics (roadmap, validation log) are in [logistics/](logistics/).

## Scope

**Status:** validated (kickoff 2026-10-19, Karl 2026-10-29).

### Setting
- **A central bank digital currency (CBDC) with a privacy focus** (kickoff, 2026-10-19).
- **The baseline is Platypus** (Wüst et al., CCS 2022): "Platypus, but more efficient for a central bank with a TEE" (kickoff).
- **Blockchain and Sui are optional.** A ledger is used only where it adds value (kickoff).
- **A large spent set (nullifier set) is acceptable** in the central-bank setting (kickoff).
- **Reuse existing building blocks:** "Take things that exist and put them together. Don't create a product" (kickoff).

### Direction
- **The TEE protects privacy, not integrity** (kickoff). See [Foundation](#foundation-the-tee-protects-privacy-never-integrity).
- **The bank is trusted for integrity.** The thesis focuses on users' privacy (Karl, 2026-10-29).
- **A TEE inside the bank replaces the ZK proofs,** to make Platypus cheaper for users (Karl, 2026-10-29).
- **The TEE keeps no state,** or as little as possible (Karl, 2026-10-29).
- **The main design question:** how state survives across TEE instances when one fails, and how the system recovers (Karl, 2026-10-29; open question at kickoff: "how to keep track of state, keys").
- **The goal:** a simple, solid design (Karl, 2026-10-29).

### Deliverables requested
From Karl, 2026-10-29:
1. **The trust model:** privacy, integrity and availability, defined per party.
2. **The goals.**
3. **A specification that still works when the TEE fails,** with its recovery plan and trade-offs.
4. **A check of the specification against the trust model.**

### Process and evaluation
From Alberto at the kickoff:
- every design, implementation and evaluation decision is tracked;
- the evaluation is industry-grade and lists every tool used.

### Outside the core scope (kickoff)
- **AI:** a mix of privacy and AI at most; publishing in AI alone is too competitive (Lefteris).
- **Ideas raised but not chosen:** offline payments, travel-rule reconciliation, anonymised analytics in a TEE, and Zef with a TEE.

## Foundation: the TEE protects privacy, never integrity

**Status:** the rule is validated (kickoff, 2026-10-19). Its consequences below are submitted for validation (2026-11-09); the attacker classes and two consequences added on 2026-11-10 (prevent or detect; checks against the bank's own secrets) are submitted for validation.

> "TEE not for integrity but for privacy." (all advisors, kickoff 2026-10-19)
>
> "The bank is trusted for integrity." (Karl, 2026-10-29)

### The rule
If the TEE breaks, **only privacy may be lost**. No money may be created, stolen, spent twice or destroyed. The bank must be able to reject every invalid payment **with checks it performs itself**. Those checks may rely on mathematics or on the bank's own records, never on a secret held by the TEE.

**No secret that lets someone spend a user's funds or break integrity is ever sent to the TEE.** Users keep their secret seed and every signing key derived from it on their devices ([round 1, section 4](round-1/PROTOCOL.md#4-state-and-the-chain-of-ownership)). The TEE may receive the private data it needs to check a payment, such as balances and blinds, because a leak of that data costs privacy only. It never receives anything that can sign, spend or derive future keys.

### What "the TEE breaks" means
| The TEE... | Meaning | In scope |
|---|---|---|
| **works** | runs the attested code and keeps its memory secret | yes |
| **crashes** | stops and loses its memory; a fresh instance starts | yes |
| **is broken** (its memory is read) | runs the attested code correctly, but everything it holds or receives can be read: its inputs and its own keys | yes |
| **runs malicious code** | its code is replaced | no |

#### Who reads the memory
"The TEE is broken" covers attackers with different reach. Which one the thesis targets is open (submitted for validation, 2026-11-10).

| Attacker | Reads the enclave's memory and keys | Can also inject messages on the bank's machine | Examples |
|---|---|---|---|
| **Remote reader** | yes | no | a memory-disclosure bug in the enclave's code |
| **Host-level reader** | yes | yes, on the channel between the enclave and the bank's software | a hypervisor bug, a cloud-provider insider, malware on the machine hosting the enclave |
| **The bank itself** | not covered | not covered | out of scope: the bank is trusted for integrity |

The distinction matters because "its code still runs correctly" already assumes that the enclave computes honestly. What a break removes is the **secrecy** of what the enclave holds, including its signing key. A leaked signing key only matters where the bank accepts something signed by that key without having read it from its own enclave. Against a remote reader, the bank can therefore close that path by accepting only results it received from its own enclave, in answer to a fresh challenge it chose. Against a host-level reader, which can impersonate the enclave on that channel, no check that rests on the enclave can stand in for the bank's own.

### What must hold in each case
| Property | Plain meaning | Works | Crashes | Broken |
|---|---|---|---|---|
| **Ownership** | only the owner spends a state; a payment cannot be changed or redirected | must hold | must hold | **must hold** |
| **Balance** | every payment moves exactly its amount; no money is created | must hold | must hold | **must hold** |
| **No double spend** | each state is spent once | must hold | must hold | **must hold** |
| **No fund destruction** | nobody can make another user's state unspendable | must hold | must hold | **must hold** |
| **Privacy toward the bank** | the bank learns neither who pays whom, nor amounts, nor balances, nor which payments belong to the same user (for payments between users it does not collude with) | must hold | must hold | may be lost for the payments the TEE processed |
| **Availability** | payments go through | must hold | paused until a new instance runs | not required |

The integrity properties follow Platypus (Section 5): ownership is its transaction unforgeability (Claim 5.1), balance and no double spend are its balance invariance (Claim 5.2), and no fund destruction is Claim 5.4. The privacy property is its transaction indistinguishability (Claim 5.3, Definition 5.2) restricted to the bank as adversary; the paper's notion covers every party except the regulator.

### What follows from the rule
These consequences are derived, not yet validated.
- **The TEE alone cannot prove balances to the bank.** To check balances it cannot see, the bank must verify something about hidden values, and doing that without learning anything else is a zero-knowledge proof by definition. A TEE can only vouch with its signature or its attestation, so a design that relies on the TEE for balance moves integrity onto the TEE.
- **The bank either prevents or detects, nothing in between.** A bank-side check of hidden balances is either a proof the bank verifies before it settles, which prevents invalid payments, or a check after the fact (supply totals, audits), which only detects them once the money has moved. Only the first meets the rule; the second can bound a loss but not exclude it.
- **What the TEE emits must be checkable against the bank's own secrets.** A check that rests on a secret the TEE holds is lost when the TEE is broken. A check against something the bank chose and the TEE never saw (a fresh challenge, a key the bank keeps) survives. This is how ownership already works in round 1: the bank checks signatures under keys that never entered the TEE.
- **Every operation the TEE vouches for counts.** Enrollment and refresh carry the same risk as a payment: wherever the bank signs a new state on the TEE's word alone, a broken TEE can create money there too.
- **Ownership is cheap to keep on the bank's side.** Owners sign their own transactions with keys that never leave their devices, and the bank verifies those signatures.
- **The TEE's role is privacy and cost.** It can open states, hide who pays whom, or compute proofs on behalf of weak devices, provided the proof's witness holds no long-term spending key (Platypus's witness holds one). A break then leaks what it saw, and the bank's checks are unaffected.

### Round 1 in Platypus's terms
Platypus groups integrity under **transaction integrity** (Section 5): **transaction unforgeability** (Claim 5.1: only authorized parties spend their funds, and values and recipients cannot be changed; this includes spending an account state that never came out of a transaction the bank accepted) and **balance invariance** (Claim 5.2: no funds are spent twice and the supply never grows). Claim 5.4 adds that nobody can invalidate another client's state, Claim 5.5 that no transaction breaks a regulation, and Claim 5.3 gives privacy as transaction indistinguishability.

Round 1 as revised at the advisor meeting of 2026-11-10 (the enclave runs inside the bank, results never leave the bank's machine, submitted for validation) splits these into two kinds of integrity:
- **Ownership integrity:** nobody but the owner can spend, redirect or change a payment of a state. The bank checks it itself, with the owners' signatures under one-time keys that never reach the enclave.
- **Balance integrity:** no money is printed. No state appears that the bank never issued, no balance is forged, every payment moves exactly its amount, and nothing is spent twice. The double-spend part is the bank's spent set; the rest rests on the enclave's checks, accepted only from the bank's own enclave over its own channel.

| Property | Platypus | Checked by | Remote reader | Host-level reader |
|---|---|---|---|---|
| Only the owner spends; amount and payee fixed | unforgeability (5.1) | bank: owner signatures (B2) | holds | holds |
| No spend of a state the bank never issued (forged balance) | unforgeability (5.1), its "non-existing account" case | enclave (E1), accepted over the bank's channel | holds | **lost** |
| No money printed: each payment moves exactly its amount | balance invariance (5.2) | enclave (E2, E4), same channel | holds | **lost** |
| No double spend | balance invariance (5.2) | bank: spent set (B4) | holds | holds |
| Nobody invalidates another user's state | Claim 5.4 | bank: burning needs the owner's signature | holds | holds |
| Holding limit respected | Claim 5.5 (holding limit only; no receiving limit yet) | enclave (E4) | holds | **lost** |
| Privacy toward the bank | indistinguishability (5.3), bank only | enclave | lost for the requests read | lost for the requests read |

Ownership integrity never depends on the enclave. Balance integrity survives a remote reader because the bank accepts results only from its own enclave, in answer to its own nonce; it is lost to a host-level reader, which can impersonate the enclave on that channel. Closing that last gap needs a check the bank verifies itself ([round 1, section 11](round-1/PROTOCOL.md#11-possible-solutions-for-balance-integrity)).

### Where the designs stand
| Design | Ownership integrity | Balance integrity | Status |
|---|---|---|---|
| [Round 1](round-1/PROTOCOL.md) | checked by the bank | checked by the enclave inside the bank; holds against a remote reader, not a host-level one | submitted 2026-11-09, revised 2026-11-10 |
