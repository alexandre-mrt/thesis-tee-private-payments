# tee-pay-v2: specification

Prototype of round 1 as revised at the advisor meeting of 2026-11-10: **the enclave runs inside the bank** (same machine, private channel), one-time key serials, owner signatures checked by the bank. Design reference: github.com/alexandre-mrt/thesis-tee-private-payments (round-1/README.md, FOUNDATIONS.md). This file is the ground truth for the code.

## 0. Trust model and properties

| Party | Integrity | Privacy |
|---|---|---|
| Bank (process `tv-bank`) | trusted | honest-but-curious: must never see amounts, balances, or links between a spent serial and the state it spends |
| Enclave (`tv-enclave`, behind the bank, reached only by the bank's process) | runs the attested code correctly; its memory may be read (then only privacy is lost) | protects what it processes |
| Users (`tv-cli`) | untrusted | the protected party |

Properties the tests must demonstrate, named after Platypus (Wüst et al., CCS 2022, Section 5):
- **P1 ownership integrity** (Platypus transaction unforgeability, Claim 5.1): nobody spends, redirects or changes a payment of a state without the owner's signature under its one-time key. Holds even if the enclave's memory and keys are read.
- **P2 balance integrity** (Platypus balance invariance, Claim 5.2): no money is created or destroyed: every payment moves exactly `v`, `0 < v <= b_A`, `b_B + v <= B_MAX` (except bank states), each state is spent once. Rests on the enclave's checks plus the bank's channel: results are accepted only from the bank's own enclave, in answer to a nonce the bank chose.
- **P3 no fund destruction** (Claim 5.4): nobody can burn another user's state.
- **P4 privacy toward the bank** (transaction indistinguishability, Claim 5.3, restricted to the bank): the bank's view contains no amount, balance, or next serial.
- **P5 crash safety**: a crash of the enclave or the bank at any point loses or duplicates no value; a retry gets the stored answer.

## 1. Workspace

Rust 2024, same toolchain and workspace dependencies as `~/projects/thesis/tee-pay/Cargo.toml` (copy that `[workspace.dependencies]` block, drop what is unused, add `proptest` for tests if wanted). Crates:
- `crates/pt-tee`, `crates/pt-host`: vendored unchanged from tee-pay (commit 8e867e1), originally platypus-tee 05cb9c4. Attestation (NSM, mock, verifier), X25519/HKDF/ChaCha20-Poly1305 channel, CBOR framing, TCP/vsock transport. **Do not modify.**
- `crates/tv-core`: primitives, types, wire messages.
- `crates/tv-enclave`: lib + bin `tv-enclave` (`--mock` TCP loopback, else vsock).
- `crates/tv-bank`: lib + bin `tv-bank`: the only server users talk to; durable store; talks to the enclave.
- `crates/tv-client`: lib + bin `tv-cli`: wallet, flows.
- Tests per crate plus `tests/` integration tests in `tv-bank` or a `tv-tests` crate running bank + mock enclave in-process.

Rules: no `unwrap/expect/panic/unsafe` in library code (`tv-tests` is a test-support crate whose library is the harness of the integration tests; it is held to the test-code standard, where a failed setup step panics with an `expect` message), `thiserror` errors, no comments in code except tool directives, files under 400 lines, functions under 50 lines, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` clean.

## 2. Primitives (`tv-core`)

- Signatures: Ed25519 (`ed25519-dalek`). Owner one-time keys, bank state key, bank issuance key, enclave result key.
- Seed: 32 random bytes in the wallet; never sent anywhere.
- Derivation (HKDF-SHA256, salt `tv/v1`, info = label || `i` as u64 big-endian): `sk_i = Ed25519 secret from HKDF(seed, "sk", i)`, `r_i = HKDF(seed, "r", i)` (32 bytes), `pk_i = public(sk_i)`.
- Commitment: `Com(b, pk, r) = SHA-256("tv/v1/com" || b as u64 BE || pk (32) || r (32))`. Hiding by `r`, binding by collision resistance.
- State `S = (b: u64, pk, r)`; a signed state is `(C, σ)` with `σ = Sign(bank_sk, "tv/v1/state" || C)`, or the issuance key for the bank's own states.
- Transaction digest `m = SHA-256("tv/v1/pay" || pk_A || C_A' || pk_B || C_B')`; refresh digest `SHA-256("tv/v1/refresh" || pk || C')`; enroll digest `SHA-256("tv/v1/enroll" || pk_0 || C_0)`. `v` never appears in a digest.
- `B_MAX` is a constant in `tv-core` (for example 1_000_000), not hard-coded elsewhere.
- All wire messages CBOR (`ciborium`), framed with `pt-tee::framing`.

## 3. Flow (revised 2026-11-10)

Users reach only the bank's server (TCP). The bank forwards to the enclave over its private link (vsock on Nitro, loopback TCP with `--mock`). There is no "Result" message to Bob and no "Settle" by Bob: the enclave answers the bank, and the bank answers Bob.

```
1  Bob   -> Bank -> Enclave  Attest(nonce)
2  Enclave -> Bank -> Bob    Attestation(doc: nonce, channel pk, user_data = tag || sha256(manifest{enclave result pk}))
3  Bob   -> Alice            Request(v, pk_B, C_B', attestation)            [out of band, a file in the CLI]
4  Alice -> Bob              Offer(pk_A, C_A', sig_A, sealed opening_A)     [file]
5  Bob   -> Bank             Receive(public part, sealed part)
     bank:    B1 retry on m, B2 owner signatures, B4a serials distinct and unspent
     bank -> enclave: Check(bank nonce n, Receive)
     enclave: open sealed part with the one-time channel key (erase it), E1..E4, sign (n, m, "ok") with the result key
     bank:    B3 result signed by the registered enclave over its own nonce n and this m
              B4b burn both serials atomically, sign C_A', C_B', append to the public log, store the answer under m
6  Bank  -> Bob              Settled(σ_A', σ_B')  (or one uniform Refused)
7  Bob   -> Alice            Receipt(σ_A')  [file]; or Alice finds σ_A' in the public log under pk_A
```

- **Public part** of Receive: `pk_A, C_A', sig_A, pk_B, C_B', sig_B`. The bank sees these at settlement anyway; sending them in clear lets B1, B2 and B4a run before the enclave call. A refused payment therefore shows its serials to the bank: document it; the client refreshes any exposed serial.
- **Sealed part** (sealed to the one-time channel key of step 2, using `pt-tee::channel`): `v`, Alice's opening `(b_A, r_A, σ_A, pk_A⁺, r_A⁺)` which she sealed herself in step 4 (Bob cannot read it), Bob's opening `(b_B, r_B, σ_B, pk_B⁺, r_B⁺)`.
- **Channel keys**: one `EnclaveKeypair` per Attest, held in an in-memory map with a bounded size and age, removed on first use. Alice's and Bob's sealed blobs are both sealed to the same attested key; the enclave accepts at most one Check per key.
- **Enclave checks** (one uniform refusal for any failure, no reason leaked to the bank):
  - E1 each opening recomputes a commitment `C = Com(b, pk, r)` whose `pk` equals the public serial, and `σ` verifies under the bank state key (or the issuance key; then that side is a bank state).
  - E2 `C_A' == Com(b_A - v, pk_A⁺, r_A⁺)` and `C_B' == Com(b_B + v, pk_B⁺, r_B⁺)` (checked arithmetic).
  - E3 `sig_A`, `sig_B` verify on `m` (the bank repeats it in B2).
  - E4 `0 < v <= b_A`, `b_B + v <= B_MAX` unless Bob's side is a bank state.
- **Enclave signature kept (advisor choice)**: the result is signed, the bank checks it (B3) in addition to the channel. The result signature covers the bank's nonce so a result cannot be replayed or submitted from outside; the bank has no API that accepts an enclave result from a user.
- The enclave is stateless across requests except the channel-key map and its per-boot keys; a crash loses only pending channel keys.

Other operations, same pattern (Attest, then one sealed request through the bank):
- **Enroll**: user sends `pk_0, C_0`, signature under `pk_0` on the enroll digest, sealed opening `(0, pk_0, r_0)`. Enclave checks balance 0 and the opening; bank checks the signature, that `C_0` and `pk_0` are fresh, then signs `C_0`. Bank learns one commitment.
- **Refresh**: owner signs the refresh digest; sealed: opening of the current state and `(pk⁺, r⁺)`; enclave checks E1 and same balance; bank runs B1, B2, B4 on one serial, then burns, signs `C'`, publishes.
- **Issue**: the bank holds a wallet for its own state signed with the issuance key and pays users with an ordinary payment (`tv-bank issue --amount v --to-request request.json`, refused unless the request asks for exactly `v`); it logs the issued amount.
- **Redeem**: an ordinary payment to the bank's state (`tv-cli redeem --amount v` pays to a request produced by the bank, refused unless the request asks for exactly `v`).

## 4. Bank (`tv-bank`)

- Keys: state key, issuance key (generated by `tv-bank init`, stored under `--data`, gitignored).
- `register-enclave`: attests the enclave (PCR0 pin, or `--allow-mock`), records the enclave result public key from the manifest.
- Durable store under `--data`: spent set, answers by digest, public log (append-only, one CBOR or JSON line per settled operation: kind, spent serials, new commitments, new signatures). Writes are fsynced before answering; a settle is one atomic append, replayed on start. A crash between the enclave answer and the append loses nothing: the client retries, the channel key is gone, so the client re-attests and resends (reseal), and the deterministic inputs give the same `m`.
- Endpoints: `Attest`, `Receive`, `Enroll`, `Refresh`, `Lookup(serial)` (the log entry spending it), `LogRange` (for recovery by full download). Every refusal is one uniform `Refused`.
- The bank's view (what it logs or could log) must never contain `v`, a balance, an opening, or a next serial: add a test that serializes everything the bank stores and checks it.

## 5. Client (`tv-client`, bin `tv-cli`)

Wallet JSON: seed, current index `i`, current signed state `(b, C, σ)`, pending operation if any. Commands:
- `tv-cli new --wallet W`, `enroll`, `request --amount v --out request.json` (payee), `pay --request request.json --amount v --out offer.json` (payer: `request.json` is written by the payee, so the payer states the agreed `v` and the command refuses a request for any other amount before signing; then verifies the attestation, refuses it if its signed `timestamp` is older than the enclave's channel-key lifetime `MAX_KEY_AGE` or ahead of her clock by more than a small skew, builds `C_A'`, signs `m`, seals her opening), `receive --offer offer.json --out receipt.json` (payee), `finish --receipt receipt.json` or `finish` alone (log lookup), `refresh`, `balance`, `recover` (walks the whole log from `pk_0` using only the seed).
- Attestation freshness: every party that seals to an attested key (enroll, refresh, request, pay) rejects a document whose `timestamp` is `MAX_KEY_AGE` (10 minutes) old or more, or ahead of its clock beyond the skew. Bob's nonce proves freshness to Bob only; without this check a payee colluding with a reader who copied a channel key during a past break could replay that old attestation and read the payer's opening offline.
- Retries: deterministic inputs; after an enclave restart a pending `receive` re-attests, and the payer reseals (`tv-cli reseal`). A payee whose request was used by an aborted payment refreshes.
- Global flags: `--bank ADDR`, `--allow-mock` or `--pcr0 HEX`.

## 6. Binaries, scripts, deploy

- `scripts/demo.sh` (`make demo`): init bank, mock enclave, register, two wallets, issue to Alice, Alice pays Bob, finish, refresh, redeem, recover; prints balances.
- `scripts/crash-demo.sh` (`make crash-demo`): kill the enclave before the answer, kill the bank after the append, show retry gives the stored answer and balances are unchanged.
- `make test`: build, test, clippy `-D warnings`, fmt check.
- `deploy/tv-enclave.Dockerfile`: builds the enclave image for `nitro-cli build-enclave` (adapt `~/projects/thesis/tee-pay/deploy/tp-enclave.Dockerfile`). Not deployed in this pass.

## 7. Tests (definition of done)

Integration tests with bank and mock enclave in-process:
1. Happy path: issue, pay, finish, balances; refresh; enroll; redeem; recover from seed alone.
2. P1: a payment with a forged or reused `sig_A` (different `C_B'`, different payee) is refused by the bank (B2) even when the enclave would accept (simulate with an enclave stub that skips E3); a party without `sk_A` cannot refresh or burn Alice's state (P3).
3. P2: wrong amount, `v = 0`, `v > b_A`, `b_B + v > B_MAX`, unsigned or forged state, state signed by another key: refused. A result signed with the enclave key but over another nonce, or for another `m`, is rejected by B3. There is no path for a user to submit a signed result.
4. Double spend: same serial twice, same serial on both sides: refused.
5. P4: the bank-view serialization test of section 4.
6. P5: enclave killed before answering, bank killed after the append (simulated by dropping the bank and reopening the store): retries return the stored answer, total supply unchanged, no state lost.
7. Leaked enclave memory: with the enclave's result key and channel keys in the test's hands, show it cannot spend Alice's state (P1) and document that minting through the bank requires the bank's own channel (the test has no API to inject).

`docs/DESIGN.md`: the flow above as implemented, what each check rests on, the bank's view, limitations (refused payments show serials; enclave key still a check; Nitro not yet deployed).
