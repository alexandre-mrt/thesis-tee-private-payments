# Foundation: the TEE protects privacy, never integrity

> "TEE not for integrity but for privacy." (all advisors, kickoff 2026-10-19)
>
> "The bank is trusted for integrity." (Karl, 2026-10-29)

## The rule
If the TEE breaks, **only privacy may be lost**. No money may be created, stolen, spent twice or destroyed. The bank must be able to reject every invalid payment **with checks it performs itself**. Those checks may rely on mathematics or on the bank's own records, never on a secret held by the TEE.

**No secret that lets someone spend a user's funds or break integrity is ever sent to the TEE.** Users keep their seed and signing keys on their devices. The TEE may receive the private data it needs to check a payment, such as balances and blinds, because a leak of that data costs privacy only.

**No secret belonging to a user is ever sent to the TEE.** A user's secrets are what gives authority over their money: the seed and every key derived from it. The TEE may receive private data it needs to check a payment, such as balances and blinds, because a leak of that data costs privacy only. It never receives anything that can sign, spend or derive future keys.

## What "the TEE breaks" means
| The TEE... | Meaning | In scope |
|---|---|---|
| **works** | runs the attested code and keeps its memory secret | yes |
| **crashes** | stops and loses its memory; a fresh instance starts | yes |
| **is broken** | runs the attested code correctly, but everything it holds or receives can be read: its inputs and its own keys | yes |
| **runs malicious code** | its code is replaced | no |

## What must hold in each case
| Property | Plain meaning | Works | Crashes | Broken |
|---|---|---|---|---|
| **Ownership** | only the owner spends a state; a payment cannot be changed or redirected | must hold | must hold | **must hold** |
| **Balance** | every payment moves exactly its amount; no money is created | must hold | must hold | **must hold** |
| **No double spend** | each state is spent once | must hold | must hold | **must hold** |
| **No fund destruction** | nobody can make another user's state unspendable | must hold | must hold | **must hold** |
| **Privacy toward the bank** | the bank learns neither who pays whom, nor amounts, nor balances | must hold | must hold | may be lost for the payments the TEE processed |
| **Availability** | payments go through | must hold | paused until a new instance runs | not required |

The four integrity properties are those of Platypus (Section 5). The privacy property is Platypus's transaction indistinguishability (Definition 5.2).

## What follows from the rule
These consequences are derived, not yet validated.
- **The TEE alone cannot prove balances to the bank.** To check balances it cannot see, the bank must verify something about hidden values, and doing that without learning anything else is a zero-knowledge proof by definition. A TEE can only vouch with its signature or its attestation, so a design that relies on the TEE for balance moves integrity onto the TEE.
- **Ownership is cheap to keep on the bank's side.** Owners sign their own transactions with keys that never leave their devices, and the bank verifies those signatures.
- **The TEE's role is privacy and cost.** It can open states, hide who pays whom, or compute proofs on behalf of weak devices. A break then leaks what it saw, and the bank's checks are unaffected.

## Where the designs stand
| Design | Ownership | Balance | Status |
|---|---|---|---|
| [Round 1](round-1/README.md) | checked by the bank | checked by the enclave, trusted through its signing key | submitted 2026-11-09 |

In round 1, a leaked enclave key lets an attacker inflate its own states, but not take anyone's money. Closing that gap is the next design step (round 1, section 11).
