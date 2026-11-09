# Round 1: Platypus with a TEE in place of the zero-knowledge proofs

**Status:** submitted for advisor validation (2026-11-09). Builds on [SCOPE.md](../SCOPE.md) and [FOUNDATIONS.md](../FOUNDATIONS.md).

| Design | Behaviour | Analysis |
|---|---|---|
| [1. Goal](#1-goal-stay-as-close-to-platypus-as-possible) | [5. A payment](#5-a-payment) | [9. If the enclave's memory is read](#9-if-the-enclaves-memory-is-read) |
| [2. In one paragraph](#2-the-system-in-one-paragraph) | [6. Who checks what](#6-who-checks-what) | [10. What the bank learns](#10-what-the-bank-learns) |
| [3. Setting and trust](#3-setting-and-trust) | [7. Other operations](#7-other-operations) | [11. Differences from Platypus](#11-differences-from-platypus) |
| [4. State and ownership](#4-state-and-the-chain-of-ownership) | [8. Crashes](#8-when-the-enclave-crashes) | [12. Possible solutions for balance](#12-possible-solutions-for-balance-integrity) |
| [Overview map](#overview-map) | [Appendix A: messages](#appendix-a-messages) | [Appendix B: notation](#appendix-b-notation) |

![Round 1 payment](maps/payment.png)

The [payment map](maps/payment.pdf) and the [overview map](maps/overview.pdf) are also available as PDF.

## 1. Goal: stay as close to Platypus as possible

Round 1 stays **as close to Platypus as possible**. The aim is to isolate a single change, replacing the two zero-knowledge proofs of a Platypus transaction with one call to a TEE run by the bank, so that its effect on cost, privacy and trust can be measured on its own.

Round 1 keeps the structure of Platypus's base transaction (Platypus, Section 3):
- a user-held state (balance, serial, blind) signed by the bank;
- one joint transaction between payer and payee, submitted by the payee;
- the bank's spent-serial check;
- the public transaction log;
- issuance from the bank's own account;
- abort by an empty update.

Regulation (Platypus, Section 4) is not part of this round.

> **On top of the replacement, round 1 makes one adjustment required by the foundation: no user secret that can spend funds is ever sent to the enclave.**
>
> **The version presented on 2026-11-03 gave the enclave the user's serial and blinding keys.** This version makes each serial a one-time public key and has the owner sign each transaction. The enclave only ever sees signed transactions, never a key that can sign.

**Result.**
- If the enclave's memory is read, the privacy of the payments it is processing is lost.
- Ownership, no double spend and no fund destruction still hold, because the bank checks them itself.
- Balance conservation does not hold: a leaked enclave key lets an attacker create money (section 9).
- The enclave keeps no payment state, so crashes are handled by retries (section 8).
- The open question is balance integrity (section 12).

## 2. The system in one paragraph

Each user holds a **state**: a balance, a one-time public key that serves as the serial, and a blind. The bank signs a commitment to it. To pay, the payer and the payee agree on one joint transaction, made of both spent serials and both new commitments, and each **signs it with the one-time key of the state they spend**. The payee sends the enclave the transaction, both signatures and both parties' openings, the payer's sealed so the payee cannot read it. The enclave checks that both states are genuine, that both owners signed and that the balances add up, then outputs a signed result. The payee sends the result to the bank. The bank checks the enclave's signature and **both owners' signatures**, burns the two serials, publishes the transaction in the public log, and signs both new states. While the enclave works, the bank never sees balances, amounts, or who pays whom.

## 3. Setting and trust

| Party | Integrity | Privacy | Failure |
|---|---|---|---|
| **Bank** | trusted: follows the protocol and signs only valid results | honest-but-curious: analyses everything it sees and may collude with users; privacy is claimed for payments in which neither party colludes, as in Platypus (Definition 5.2) | does not lose its records |
| **TEE** (run by the bank) | runs the attested code correctly | protects what it processes | may crash; a fresh instance starts with empty memory |
| **Users** | untrusted: may double spend, replay old states or forge states | the protected party | keep their device |
| **Network** | none | attacks on network anonymity are out of scope, as in Platypus (Section 2.2); users may use an anonymity network | none |

**Assumptions:**
- As in Platypus, the payer receives the payee's request over an authenticated channel. How that channel is set up is out of scope.
- The hand-off between payer and payee is confidential, for privacy only. An eavesdropper would learn the amount and the two serials, which locate the payment in the public log. It could not change or redirect the payment (section 5).
- For the analysis of section 9, the enclave's memory may also be read while its code keeps running correctly. Replacing its code is out of scope.

## 4. State and the chain of ownership

A state is `S = (b, pk, r)`:
- `b` is the balance;
- `pk` is a one-time public key, which also serves as the serial;
- `r` is the commitment's blind. Without it, the commitment would not hide `b` once `pk` is revealed at spend: balances are few enough to try them all against the published commitment, which would reveal the balance and link the payment to the one that created the state.

The bank signs a commitment `C = Com(b, pk, r)` without learning its content. The commitment hides `S`, and the bank's signature `σ` makes it valid money.

Each user keeps one secret seed, which **never leaves the device**. The `i`-th signing key and blind are derived from it, with separate labels. Spending the `i`-th state is signed with `sk_i` and creates a new state carrying `pk_{i+1}`.

```mermaid
flowchart LR
  seed["seed<br/>(never leaves the device)"] -. derives .-> k0["sk₀, pk₀, r₀"]
  seed -. derives .-> k1["sk₁, pk₁, r₁"]
  seed -. derives .-> k2["sk₂, pk₂, r₂"]
  C0["C₀ = Com(0, pk₀, r₀)<br/>enrolled, signed by the bank"] -- "payment signed with sk₀<br/>reveals serial pk₀" --> C1["C₁ = Com(b₁, pk₁, r₁)<br/>signed by the bank"]
  C1 -- "payment signed with sk₁<br/>reveals serial pk₁" --> C2["C₂ = Com(b₂, pk₂, r₂)<br/>signed by the bank"]
  k0 -.-> C0
  k1 -.-> C1
  k2 -.-> C2
```

**Why this proves ownership without proving identity.**
- The first state carries `pk_0`, chosen by the user at enrollment.
- Every later key `pk_{i+1}` sits inside a state that the bank signed only after verifying a signature by `sk_i`.
- By induction, only the holder of the seed can spend the chain.

To the bank, two keys from one chain are unrelated. The enclave sees one link per payment (the current key and the next one) and keeps nothing after the request.

**Recovery.** The seed regenerates every key and blind. The user downloads the public log, or a mirror of it, and walks the chain locally, so nobody learns which entries it looks for. The balance of each new state is found by trying values up to `B_max` against its commitment.

## 5. A payment

Alice pays `v` to Bob. As in Platypus, only the recipient talks to the system: Bob alone contacts the enclave and the bank.

```mermaid
sequenceDiagram
  autonumber
  participant A as Alice (payer)
  participant B as Bob (payee)
  participant E as Enclave
  participant K as Bank
  participant L as Public log
  B->>E: attest (fresh nonce)
  E-->>B: attestation (code measurement, fresh channel key)
  Note over B: prepares C_B' = Com(b_B + v, pk_B⁺, r_B⁺)
  B->>A: request (v, pk_B, C_B') + attestation
  Note over A: checks the attestation<br/>builds C_A' = Com(b_A − v, pk_A⁺, r_A⁺)<br/>signs m with sk_A<br/>seals her opening to the channel key
  A->>B: offer (pk_A, C_A', sig_A, sealed opening)
  Note over B: signs m with sk_B
  B->>E: v, transaction, sig_A, sig_B, both openings (Alice's still sealed)
  Note over E: E1 to E4 in order, one refusal for any failure<br/>erases the channel key
  E-->>B: result (pk_A, C_A', sig_A, pk_B, C_B', sig_B) + enclave signature
  B->>K: settle (result)
  Note over K: B1 to B4: retry, owner signatures, enclave signature<br/>burns both serials, signs both new states
  K->>L: publish
  K-->>B: settled (σ_A', σ_B')
  B->>A: receipt (σ_A'), or Alice reads the public log
```

1. **Request.** Bob attests the enclave with a fresh nonce and gets a channel key used for this payment only. He prepares his new state `C_B' = Com(b_B + v, pk_B⁺, r_B⁺)` and sends Alice the amount, his current serial `pk_B`, `C_B'` and the attestation. Alice never contacts the bank's machine.
2. **Offer.** Alice checks the attestation. She builds `C_A' = Com(b_A − v, pk_A⁺, r_A⁺)` and signs the transaction `m = H("pay", pk_A, C_A', pk_B, C_B')` with `sk_A`. She seals the opening of her current state, its bank signature, and her next key and blind to the channel key, so Bob cannot read them. She hands Bob the offer.
3. **Receive.** Bob signs the same `m` with `sk_B`. He sends the enclave the amount `v`, the transaction, both signatures, Alice's sealed opening and his own opening, encrypted to the channel key, so the bank's machine sees only ciphertext.
4. **Check.** The enclave runs the checks of section 6, returns one signed result, and erases the channel key.
5. **Settle.** Bob submits the result. The bank runs its checks, burns both serials together, appends the transaction to the public log, and signs both new states. Bob counts the payment as received only once it is settled.
6. **Finish.** Bob forwards Alice's new signature. If he does not, Alice finds it in the public log under her old serial.

**The amount never appears in `m`.** The bank must be able to recompute `m` without learning `v`. That is not a loss: `C_A'` commits to `b_A − v` and `C_B'` to `b_B + v`, so the two signed commitments fix the amount, and the enclave checks it by opening both.

## 6. Who checks what

**The enclave** opens both states and runs the checks in this order. Any failure returns the same refusal, so a wrong `v` fails at E2 before the balance is ever compared, and Bob learns nothing about Alice's balance by retrying.

| # | Check | Prevents | Rests on |
|---|---|---|---|
| E1 | both openings give commitments that contain the revealed serials `pk_A`, `pk_B` and carry a valid bank signature | spending a state the bank never issued | enclave key |
| E2 | the new commitments open to `b_A − v` and `b_B + v` with the new keys and blinds | new states that do not match the amount | enclave key |
| E3 | both owner signatures on `m` | someone else spending a state | bank (repeated in B2) |
| E4 | `0 < v ≤ b_A` and `b_B + v ≤ B_max` | overspending, overflow | enclave key |

**The bank** sees only serials, commitments and signatures:

| # | Check | Prevents | Rests on |
|---|---|---|---|
| B1 | a retry of a settled transaction (same `m`) gets the stored answer, before any other check | a lost or doubled payment after a crash | bank |
| B2 | it recomputes `m` and verifies Alice's signature under `pk_A` and Bob's under `pk_B` | theft, even if the enclave's memory is read | bank |
| B3 | the result is signed by a registered enclave | results not checked by the attested code | enclave key |
| B4 | the two serials differ and neither was spent; it burns both, signs both new commitments and publishes the transaction | double spending, and spending one state on both sides | bank |

## 7. Other operations

All of them go through the enclave and the bank like a payment, with the same checks restricted to one state.

| Operation | What happens | What the bank learns |
|---|---|---|
| **Enroll** | The user opens a first state `Com(0, pk_0, r_0)` to the enclave, which checks that the balance is 0. The bank signs it. | one new commitment |
| **Refresh** (abort) | Platypus's empty update. The owner signs `H("refresh", pk, C')` with `sk`. The enclave checks E1 and that `C'` holds the same balance; the bank checks the signature and burns `pk`. It cancels an offer that was never settled. A party whose serial was shown to the counterparty in a payment that did not complete refreshes too, so no exposed serial stays in use. | one spent serial, one new commitment |
| **Issue** | As in Platypus, the bank signs a state for its own account, whose content it knows, and logs the issued amount. It pays users from that state with ordinary payments. Its states are exempt from `B_max`. | its own side and the amount |
| **Redeem** (not in Platypus) | A payment to the bank's state. | its own side and the amount; whether it learns the user depends on how the request reaches it |
| **Read the public log** | Anyone can download it or mirror it. A user finds the bank's signature on a new state under the old serial. | nothing, when the whole log is downloaded |

## 8. When the enclave crashes

The enclave keeps no payment state between requests, so a crash loses nothing:
- **Before the enclave returns a result:** nothing happened. Bob attests a fresh instance and relays the new attestation; Alice, who must be online, reseals the same content to the new channel key. Her signature does not change, because `m` names no enclave.
- **After the result, before settlement:** Bob settles the result he already holds. The bank keeps the old instance's registered key valid long enough to accept it.
- **After the bank records it:** a retry of the same transaction gets the stored answer (B1). There is never a second debit.
- **Deterministic results:** every new key and blind comes from the users, so the same input always gives the same transaction.
- **Replaying an old state:** its serial is spent, so the bank refuses it.
- **Total outage:** the bank's records, the users' states and the public log are enough to restart. A new enclave is attested and registered.

## 9. If the enclave's memory is read

Suppose an attacker can read everything the enclave holds or receives: the openings of the states, the channel keys of the requests in progress, and the enclave's signing key. The code itself still runs correctly.

| Property | Holds? | Why |
|---|---|---|
| **Ownership:** nobody spends someone else's state | **yes** | Spending needs the owner's signature (B2). Signing keys never leave the devices; the enclave only sees signed transactions. |
| A payment cannot be redirected or changed | **yes** | The owners sign the exact new states (`m`). A replay finds the serial already spent (B4). |
| No double spend | **yes** | The bank's spent set (B4). |
| Nobody can burn another user's state | **yes** | Burning a serial needs its owner's signature. |
| **Balance:** no money created | **no** | The bank cannot see balances, so E1, E2 and E4 are checked only by the enclave. With its signing key, an attacker signs results for states that never existed, with any balance, and can then redeem them at the bank. It still cannot take anyone's existing state. |
| Privacy of the payments processed | **no** | For each payment it reads, the attacker learns the amount and both balances, and links it to the previous and the next payment of both participants. Each channel key serves one payment and is then erased, so payments completed before the read stay private. |

## 10. What the bank learns

While the enclave works, and with recovery done by downloading the whole log:

| Operation | Sees | Never sees |
|---|---|---|
| Payment | two spent serials (and which one paid), two new commitments, three signatures, the time | who pays or receives, the amount, any balance, the next serials |
| Refresh | one spent serial, one new commitment, the time | who, the balance |
| Enroll | one new commitment, the time | who, the first serial |

Each serial is a fresh key used once, so the bank cannot link two payments by the same user.

## 11. Differences from Platypus

| | Platypus | Round 1 |
|---|---|---|
| Validity of a transaction | two zero-knowledge proofs, one per party, bound by a transaction commitment | one enclave check of the whole transaction, and one signed result |
| Serial | a pseudorandom chain derived from a long-term key | a one-time public key derived from the seed |
| Ownership of a state | proven inside the zero-knowledge proof | the owner signs with the serial's one-time key, and the bank verifies it |
| Binding the two sides | the transaction commitment; the payer starts | both owners sign `m`; the payee starts with a request, so the payer learns the payee's serial before settlement |
| Payer's private data | hidden inside her proof | sealed to the attested enclave, so the payee cannot read it |
| Balance conservation | guaranteed by the proofs (mathematics) | guaranteed by the enclave's checks and its key |
| Abort | the payer's empty update | either party's refresh, checked by the enclave |
| Extra pieces needed by the TEE | none | attestation and enclave registration, resealing after a crash, uniform refusals, idempotent settlement |
| User-held state, spent-serial check, public log, issuance | as in the paper | the same |

## 12. Possible solutions for balance integrity

**The goal:** the bank checks balance conservation itself, as it already checks ownership, while keeping Platypus's privacy. Without a cryptographic proof, the bank can only take a TEE's word on balances. The options either add a proof, or move that trust from the enclave's own key to the hardware vendor. For discussion:

| Option | Balance rests on | The bank sees who pays whom | Amounts hidden | Role of the TEE | Cost |
|---|---|---|---|---|---|
| **Zero-knowledge proofs as in Platypus** | mathematics | no | yes | computes the proofs for weak devices; a break leaks what it saw | one proof per party per payment |
| **Public accounts with additive commitments and range proofs** | mathematics | yes | yes | not needed for integrity | small proofs, cheap checks |
| **The same, with the TEE batching payments** | mathematics | only which batch | yes | hides who pays whom inside a batch; a break reveals that pairing | batch rounds, all participants online |
| **The enclave attests every result** | the hardware vendor and correct code: the vendor's attestation key is not in enclave memory, so reading the memory is not enough to forge a result | no | yes | as in round 1 | one attestation per payment |

## Overview map

![Round 1 overview](maps/overview.png)

## Appendix A: messages

| Message | From → to | Content |
|---|---|---|
| Attestation | enclave → Bob → Alice | code measurement, a fresh channel key for this payment, Bob's nonce. The enclave's signing key is registered with the bank separately, at boot. |
| Request | Bob → Alice | `v`, `pk_B`, `C_B'` |
| Offer | Alice → Bob | `pk_A`, `C_A'`, `sig_A = Sign(sk_A, m)`, sealed opening = `Enc(channel key, b_A, r_A, σ_A, pk_A⁺, r_A⁺)` |
| Receive | Bob → enclave, encrypted to the channel key | `v`, the transaction `(pk_A, C_A', pk_B, C_B')`, `sig_A`, `sig_B`, Alice's sealed opening, and Bob's opening `b_B, r_B, σ_B, pk_B⁺, r_B⁺` |
| Result | enclave → Bob | `"pay"`, `pk_A, C_A', sig_A, pk_B, C_B', sig_B`, signed by the enclave |
| Settle / Settled | Bob ↔ bank | the result / the bank's signatures `σ_A'`, `σ_B'` on the new states |
| Receipt | Bob → Alice | `σ_A'` |
| Public log entry | bank → anyone | the result and both bank signatures |
| Enroll | user → enclave → bank | opening `(0, pk_0, r_0)`; result `"enroll", C_0`, signed by the enclave; the bank returns `σ_0` |
| Refresh | user → enclave → bank | opening `b, r, σ`, the transaction `(pk, C')`, next key and blind, `Sign(sk, H("refresh", pk, C'))`; result `"refresh", pk, C'`, signature, signed by the enclave; the bank returns `σ'` |

## Appendix B: notation

| Symbol | Meaning |
|---|---|
| `S = (b, pk, r)` | a state: balance, one-time public key (the serial), blind |
| `Com(b, pk, r)` | hiding, binding commitment to a state |
| `C`, `C'` | the commitment of a current or new state |
| `σ`, `σ'` | the bank's signature on a current or new commitment |
| `v` | the amount of a payment |
| `sk_i, pk_i` | the `i`-th one-time key pair; `pk_i` is the serial |
| seed | the user's only secret; `sk_i` and `r_i` are derived from it with separate labels |
| `⁺` | the value for the next state (for example `pk_A⁺ = pk_{A,i+1}`) |
| `H` | a collision-resistant hash, with a label for each kind of message |
| `m` | the transaction both owners sign: `H("pay", pk_A, C_A', pk_B, C_B')` |
| `Sign`, `sig` | an owner's signature with a one-time key |
| `Enc(channel key, …)` | encryption to the channel key of an attested enclave |
| `B_max` | the maximum balance of a user's state |
