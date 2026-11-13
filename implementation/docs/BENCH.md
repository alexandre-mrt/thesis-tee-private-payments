# tee-pay-v2 performance pass

Every number below was measured with `tv-bench` on the machine named here. "Before" is the tree at commit `8ffabbe` (the bench crate added on top of the unoptimized code); "after" is the tree at the end of this pass. Both runs used the default arguments (`--payments 1000 --checks 4096 --appends 1000 --iterations 200`). Runs vary by a few percent from one invocation to the next; fsync-bound figures vary the most.

## Machine

- `sysctl -n machdep.cpu.brand_string`: Apple M3 Pro
- `sysctl -n hw.ncpu`: 11 logical cores (5 performance, 6 efficiency; `hw.perflevel0.physicalcpu` 5, `hw.perflevel1.physicalcpu` 6)
- `sysctl -n hw.memsize`: 19327352832 (18 GiB)
- macOS 26.3.1, rustc 1.94.1, release profile (`lto = "thin"`, `codegen-units = 1`)
- Disk: the internal APFS volume. The store calls `File::sync_data` (fsync(2), not `F_FULLFSYNC`); one fsync of a small append costs 2.86 ms here, and that single figure shapes most of the latency numbers below.

## Commands

```
make bench                                   # cargo run --release -p tv-bench -- --payments 1000
./target/release/tv-bench --help             # --payments, --checks, --appends, --pairs, --iterations
git checkout 8ffabbe && make bench           # reproduces the "before" column (bench crate, unoptimized code)
```

What each section measures:

- primitive costs: mean per operation over 2000 iterations, in process.
- enclave check throughput: `Enclave::check` on prepared `CheckOp::Pay` requests (one attested channel key each, prepared in batches of half the enclave's global key cap so no prepared key is evicted, both openings sealed, mock attestation), in process, with 1 thread and with 11 threads sharing one `Enclave`. Attestation and request building are outside the timed region.
- bank store: `Store::append` (stage + write + fsync per entry, sequential) and `Store::stage` + `Committer::commit` from N concurrent tokio tasks on one store, on a fresh `log.jsonl`.
- bank settle throughput: `Bank::handle(Receive)` in process with an in-process enclave link, N payer/payee pairs each paying 1 unit in a loop (attest, build, receive); the timed region covers everything a pair does, including its client-side work.
- loopback TCP latency: real `tv_bank::serve` on 127.0.0.1, bank to enclave over `TcpLink` to a real `tv_enclave::serve` on 127.0.0.1 (the `--mock` topology), one client paying 1 unit 1000 times sequentially; per payment the attest round trip, the local offer and payee blob construction, the `Receive` round trip and their sum are recorded; percentiles are nearest rank. "tv-cli flow" runs the same payment through `tv_client::payment::{request, pay, receive}` and `flows::finish` with real wallet files (every wallet step fsyncs), which is what the CLI does.
- client-side cost: `verify_bundle`, `seal_to` of the payer opening and `payment::prepare_pay` (verify the attestation, derive keys, commit, sign, seal) on one wallet, 200 iterations.
- message sizes: CBOR frame bytes including the 4-byte length prefix for wire messages (the bank-to-enclave `Attest`, `Attestation` and `Cancel` frames are encoded from the sampled payment's attestation, not captured on the link), `serde_json` bytes for files (pretty, as `write_json` writes them) and for one `log.jsonl` line (compact plus newline).

## Results

### Throughput

| Measurement | Before (8ffabbe) | After |
|---|---|---|
| enclave checks, 1 thread | 5130.7 /s (0.195 ms each) | 5295.3 /s (0.189 ms each) |
| enclave checks, 11 threads | 27416.9 /s (0.036 ms each) | 27677.9 /s (0.036 ms each) |
| store append, fsync per op, sequential | 350.0 /s (2.857 ms) | 350.0 /s (2.857 ms) |
| store stage + group commit, 1 writer | not available (no group commit) | 349.7 /s (2.860 ms) |
| store stage + group commit, 11 writers | not available | 2321.6 /s (0.431 ms per entry) |
| store stage + group commit, 64 writers | not available | 11751.0 /s (0.085 ms per entry) |
| bank settle, 1 pair | 251.3 /s (3.979 ms) | 244.3 /s (4.093 ms) |
| bank settle, 11 pairs | 411.4 /s | 1895.4 /s |
| bank settle, 44 pairs | not run | 6023.3 /s |

Before the pass the store's fsync ran inside the index mutex, so 11 concurrent pairs settled only 1.6 times faster than one pair. After the pass one fsync covers every settlement staged since the previous one; 44 concurrent pairs settle about 25 times faster than one pair, and the per-entry cost of the store drops from 2.86 ms to 0.085 ms at 64 writers. A single sequential client still pays one fsync per payment (the leader flushes at once when it is alone), so the 1-pair figures are unchanged within run-to-run variance.

### Latency, loopback TCP, sequential payments (n = 1000)

| Phase | Before p50 / p95 / p99 | After p50 / p95 / p99 |
|---|---|---|
| attest round trip (user to bank to enclave and back, attestation verified) | 0.416 / 0.495 / 0.556 ms | 0.416 / 0.495 / 0.524 ms |
| build offer and payee blob (client, local) | 0.431 / 0.451 / 0.478 ms | 0.381 / 0.448 / 0.464 ms |
| receive round trip (B1 to B4, enclave over TCP, fsync, answer) | 2.851 / 4.692 / 5.119 ms | 2.835 / 4.666 / 5.105 ms |
| payment total | 3.742 / 5.541 / 6.050 ms | 3.719 / 5.547 / 6.014 ms |
| tv-cli flow with wallet files (request, pay, receive, finish) | 33.117 / 37.029 / 38.019 ms | 33.010 / 36.979 / 39.586 ms |

Means: payment total 4.180 ms before, 4.060 ms after; receive round trip 3.347 ms before, 3.255 ms after. The sequential receive round trip is the bank's fsync (2.86 ms) plus about 0.4 ms of checks, enclave round trip and framing; the pass does not change it, by design, because a lone request must still be durable before it is answered. The tv-cli flow is dominated by the wallet: each of the four steps saves the wallet with a temp file fsync and a directory fsync before touching the network; eight fsyncs at the 2.86 ms measured for the store's fsync would account for about 23 of the 33 ms (the wallet fsyncs were not timed separately). This is the client's own crash safety and was left alone.

### Client-side cost (n = 200)

| Operation | Before mean / p50 / p99 | After mean / p50 / p99 |
|---|---|---|
| verify attestation bundle (mock document) | 0.001 / 0.001 / 0.005 ms | 0.001 / 0.001 / 0.003 ms |
| seal payer opening | 0.084 / 0.071 / 0.140 ms | 0.082 / 0.075 / 0.131 ms |
| build offer, `prepare_pay` | 0.164 / 0.141 / 0.251 ms | 0.160 / 0.144 / 0.230 ms |

Building an offer costs 0.16 ms: two HKDF derivations, one SHA-256 commitment, one Ed25519 signature and one seal (X25519 key generation, HKDF, ChaCha20-Poly1305 over a 2 KiB padded block). The mock attestation document has no signature chain to verify; on Nitro the COSE and X.509 verification will dominate this step.

### Message sizes (bytes)

| Message | Before | After | Current tree (fix round 9) |
|---|---|---|---|
| wire user to bank `Attest` | 78 | 80 | 151 |
| wire bank to user `Attestation` (mock doc + manifest) | 530 | 526 | 524 |
| wire user to bank `Enroll` | 2478 | 2485 | 2478 |
| wire user to bank `Refresh` | 2480 | 2485 | 2483 |
| wire user to bank `Receive` | 4896 | 4903 | 4902 |
| wire bank to user `Settled` | 168 | 168 | 168 |
| wire bank to enclave `Attest` | not measured | not measured | 152 |
| wire enclave to bank `Attestation` (mock doc + manifest + channel pk) | not measured | not measured | 597 |
| wire bank to enclave `Cancel` | no such message | no such message | 86 |
| wire bank to enclave `Check(Pay)` | 4976 | 4983 | 4985 |
| wire enclave to bank `Result` | 242 | 244 | 242 |
| `log.jsonl` line, Pay | 1106 | 1113 | 1110 |
| file `request.json` | 5176 | 5154 | 5168 |
| file `offer.json` | 24423 | 24417 | 24397 |
| file `receipt.json` | 1446 | 1455 | 1457 |

"Before" and "After" are the two ends of the performance pass; the last column is the second `make bench` run of fix round 9 (below). The user-to-bank `Attest` grew in fix round 1, when it started naming the owner serial.

Sizes move by a few bytes between runs because `[u8; 32]` fields are encoded as arrays of integers (one or two CBOR bytes, one to three JSON characters per element, depending on the random value) rather than as byte strings. Each sealed blob is 2048 + 16 bytes regardless of its plaintext (a few hundred bytes) because `pt_tee::channel` pads to `PAD_BLOCK_LEN = 2048`, so a `Receive` is 4128 bytes of ciphertext and 775 bytes of public part; `offer.json` is large because `serde_json` renders the 2064 ciphertext bytes as a pretty-printed array.

### Primitive costs (after, mean of 2000 iterations)

| Operation | Cost |
|---|---|
| Ed25519 sign of a digest | 0.019 ms |
| Ed25519 `verify_strict`, key parsed per call | 0.033 ms |
| Ed25519 `verify_strict`, parsed key reused | 0.027 ms |
| `VerifyingKey::parse` (point decompression) | 0.002 ms |
| X25519 accept + open a 2 KiB blob + CBOR decode of `PaySecret` | 0.031 ms |
| client seal of a `PaySecret` (X25519 keygen, HKDF, ChaCha20-Poly1305) | 0.041 ms |
| X25519 `EnclaveKeypair::generate` (per attest) | 0.010 ms |
| SHA-256 commitment | under 0.001 ms |
| HKDF `derive_sk` + public key | 0.009 ms |
| CBOR decode of a `Receive` | 0.003 ms |
| JSON encode of a Pay `LogEntry` | 0.001 ms |

A Pay check is two opens (0.062 ms), two state verifications under the bank keys (E1, 0.054 ms with parsed keys), two owner verifications under one-time keys (E3, 0.066 ms), four SHA-256 and one result signature (0.019 ms): 0.201 ms of cryptography by the primitive costs above, against 0.189 ms measured for the whole check. Decoding the request is 0.003 ms, under 2 percent.

## What changed

1. Group commit in the bank store (`crates/tv-bank/src/{store,commit,journal}.rs`). A settlement is staged under the index lock (entry applied to the index, line buffered, ticket returned) and then awaits durability; the first waiter leads one `write_all` + `sync_data` of every staged line, outside the index lock, on the blocking pool, in a detached task so a client disconnect cannot abandon a flight. Nothing is answered before its flight landed; `Lookup`, `LogRange`, `entries` and the B1 answer lookup serve the durable prefix only. A failed flight truncates the file to its durable length, rebuilds the index from the durable prefix and rolls back every ticket of that generation; a failed truncate poisons the store as before. `docs/DESIGN.md` describes the semantics. Effect: the bank settle throughput at 11 pairs went from 411 /s to 1895 /s, at 44 pairs to 6023 /s.
2. Channel key eviction in the enclave (`crates/tv-enclave/src/keys.rs`). Pending channel keys are also kept in a `BTreeSet` ordered by issue time, so eviction pops expired or over-cap keys from the front instead of scanning every pending key under the enclave lock on every `peek`, `take` and `issue`. Effect on this bench: within noise (the lock was already short); it removes an O(pending) section that would grow with the pending set under load (`MAX_PENDING_KEYS` = 65536; the per-source cap of 256 that fix round 1 added to the enclave moved to the bank in fix round 9).
3. Parsed verifying keys for the long-lived keys (`tv_core::{VerifyingKey, BankVerifiers, verify_result_with}`). The enclave parses the bank state and issuance keys once at boot (E1), the bank parses the registered result key once (B3). One-time owner keys are still parsed per signature (B2, E3), there is nothing to reuse there. Effect: 0.195 ms to 0.189 ms per check (two of the four verifications per check use a reused key; a reused key saves 0.006 ms per verification).
4. The bank signs the new states before taking the store lock instead of inside it (`Bank::settle`), shortening the serialized section per settlement by two Ed25519 signatures (0.038 ms).

## What was measured and deliberately not changed

- E3 repeats B2 (owner signatures checked by both the bank and the enclave): SPEC.md requires both, so neither was removed. The enclave's E1 verifies each opening once, under the key of the side it states (the state key for a user side, the issuance key for a bank side), so a bank-side opening costs no extra verification.
- Padding: the 2 KiB blocks of `pt_tee::channel` set 84 percent of a `Receive`; `pt-tee` is vendored unchanged.
- `[u8; 32]` fields serialized as integer arrays: a byte string costs 34 bytes where the array costs between 33 and 65 depending on the values, so byte strings would save on the order of 200 bytes per `Receive` (seven such fields and two nonces; estimated from the encoding, not measured) and a comparable share of each `log.jsonl` line and `LogRange` page; this changes the log format and every wire message, so it is left for a format revision.
- One TCP connection per request (user to bank and bank to enclave): the attest round trip is two such connections plus 0.011 ms of cryptography (key generation and the mock document) and measures 0.416 ms, so a loopback connection round trip costs about 0.2 ms; keeping connections open is a protocol change for both servers and would not move the fsync-bound sequential latency.
- Wallet persistence: eight fsyncs per tv-cli payment are the client's crash safety.
- The fsync itself: `sync_data` is already the cheaper call on macOS; the 2.86 ms is the filesystem's.

## Fix round 1 (2026-11-11)

The audit fixes touched the attest path (the `Attest` request now names the serial the channel key is for, the bank tags it with a digest of the source address, the enclave keeps a per-source index of pending keys and checks the owner before opening a blob) and the client file writes (temp file, fsync, rename). To tell code effects from machine drift, the tree before the fixes (`efe3227`) was rebuilt and run again on the same day, right before the fixed tree, both with `--payments 1000` and the other defaults.

| Measurement | efe3227, re-run 2026-11-11 | fixed tree |
|---|---|---|
| enclave checks, 1 thread | 5335.1 /s (0.187 ms) | 5152.6 /s (0.194 ms) |
| enclave checks, 11 threads | 28214.8 /s (0.035 ms) | 30177.0 /s (0.033 ms) |
| store append, fsync per op | 365.6 /s (2.735 ms) | 380.7 /s (2.627 ms) |
| bank settle, 1 pair | 248.3 /s (4.028 ms) | 240.7 /s (4.154 ms) |
| bank settle, 11 pairs | 1818.3 /s | 1889.0 /s |
| bank settle, 44 pairs | 6247.5 /s | 6253.8 /s |
| attest round trip p50 / p95 / p99 | 0.417 / 0.498 / 0.584 ms | 0.464 / 0.540 / 0.594 ms |
| receive round trip p50 / p95 / p99 | 4.053 / 5.005 / 5.214 ms | 4.104 / 5.070 / 5.524 ms |
| payment total p50 / p95 / p99 | 4.919 / 5.936 / 6.118 ms | 4.964 / 5.993 / 6.467 ms |
| tv-cli flow with wallet files p50 / p95 / p99 | 33.048 / 36.999 / 38.985 ms | 33.994 / 37.942 / 40.877 ms |

The attest round trip costs about 0.05 ms more at p50: the request grew from 80 to 154 bytes (the owner serial), the bank hashes the peer address once per attest and the enclave maintains one more ordered set per key. The 1-thread check rate is 3 percent lower, which is the owner comparison plus run-to-run variance (the 11-thread figure moved the other way). Everything on the fsync-bound path is within the noise of the two runs. Note that the receive round trip measured 4.05 ms on the unchanged `efe3227` code today against 2.84 ms when the table above was written: the loopback receive is one fsync plus 0.4 ms of work, and the fsync cost on this volume moved between the two days, so the paired same-day columns are the ones to compare.

Message sizes after the fixes: `Attest` 154 bytes (80 before: 32 more bytes of owner serial, as a CBOR integer array, plus its key), `log.jsonl` line 1124, everything else within the few bytes of run-to-run variation described above.

`make bench` exports `RUSTUP_TOOLCHAIN` from `rust-toolchain.toml` so that the build scripts of dependencies, which run `rustc` from their own directory, use the pinned toolchain rather than the default channel.

## Fix round 2 (2026-11-12)

This round touched the enclave check path (every E1 to E4 check is evaluated before the outcome is chosen, each opening states its side and is verified under that side's key only, and a refused check signs and discards a result), the `Attest` message (`owner` is now optional; a registration attestation keeps no channel key) and the log replay (a zeroed, newline-terminated tail is dropped). The pre-fix tree (`c97fb3e`) and the fixed tree were built in advance and run back to back on an idle machine, after a 60 second pause, both with `--payments 1000` and the other defaults. A first `make bench` run that started right after a 30 second full recompile had read 0.227 ms per 1-thread check; the paired run below is the one to trust.

| Measurement | c97fb3e, paired run | fixed tree |
|---|---|---|
| enclave checks, 1 thread | 5189.4 /s (0.193 ms) | 5162.3 /s (0.194 ms) |
| enclave checks, 11 threads | 29059.8 /s (0.034 ms) | 30384.0 /s (0.033 ms) |
| store append, fsync per op | 388.1 /s (2.576 ms) | 351.7 /s (2.843 ms) |
| store stage + group commit, 64 writers | 11126.5 /s (0.090 ms) | 11629.5 /s (0.086 ms) |
| bank settle, 1 pair | 236.9 /s (4.222 ms) | 253.5 /s (3.945 ms) |
| bank settle, 11 pairs | 1906.7 /s | 1961.0 /s |
| bank settle, 44 pairs | 6031.1 /s | 6172.4 /s |
| attest round trip p50 / p95 / p99 | 0.454 / 0.596 / 0.728 ms | 0.452 / 0.548 / 0.624 ms |
| receive round trip p50 / p95 / p99 | 4.097 / 5.098 / 5.924 ms | 4.056 / 4.977 / 5.164 ms |
| payment total p50 / p95 / p99 | 4.935 / 6.038 / 7.038 ms | 4.935 / 5.916 / 6.078 ms |
| tv-cli flow with wallet files p50 / p95 / p99 | 31.720 / 36.031 / 38.990 ms | 29.045 / 35.142 / 37.894 ms |

The honest check path does the same work as before (two opens, one state verification per side, two owner verifications, four SHA-256, one signature) and measures the same: 0.193 against 0.194 ms. What changed is the refused path, which now costs the same as the honest one instead of 0.065 to 0.122 ms (`refusal_timing.rs` measures the seven refusal classes within 0.5 percent of the honest check; the pre-fix tree spread them over a factor of 2.9). The fsync-bound figures moved both ways by up to 10 percent, which is the run-to-run variation of this volume described above; the paired columns do not show a code effect there, and the log replay change runs only at startup.

Message sizes after the fixes: `Attest` 152 bytes in both runs (`Option<Bytes32>` serializes to the same CBOR as the serial when present), `Result` 248 (246 before, within the integer-array variation), `log.jsonl` line 1129 (1113 before, same variation; the line format is unchanged), `Receive` 4904 (4897). The `Opening.side` field lives inside the sealed blobs, which are padded to 2 KiB, so it adds nothing on the wire.

## Fix round 7 (2026-11-12)

Since `6d27405` (enroll moves the wallet off `pk_0` and `request` refuses on it) `tv-bench` aborted at the tv-cli flow section: its wallets were enrolled through `flows::enroll` alone and stayed on `pk_0`. They now go through `flows::enroll_and_refresh`, the helper `tv-cli enroll` uses, and `make test` runs `tv-bench` with tiny parameters so a broken bench fails the gate. The same round bounds every bank-to-enclave call with a `tokio::time::timeout` (one timer per call on the loopback path). One `make bench` run of the fixed tree, with the defaults, on a loaded machine (load average 22 when it started), against the fixed column of fix round 2:

| Measurement | fix round 2, fixed tree | fix round 7 |
|---|---|---|
| enclave checks, 1 thread | 5162.3 /s (0.194 ms) | 5151.3 /s (0.194 ms) |
| enclave checks, 11 threads | 30384.0 /s (0.033 ms) | 29780.1 /s (0.034 ms) |
| store append, fsync per op | 351.7 /s (2.843 ms) | 339.3 /s (2.947 ms) |
| store stage + group commit, 64 writers | 11629.5 /s (0.086 ms) | 10162.7 /s (0.098 ms) |
| bank settle, 1 pair | 253.5 /s (3.945 ms) | 250.6 /s (3.991 ms) |
| bank settle, 11 pairs | 1961.0 /s | 1982.4 /s |
| bank settle, 44 pairs | 6172.4 /s | 6061.1 /s |
| attest round trip p50 / p95 / p99 | 0.452 / 0.548 / 0.624 ms | 0.463 / 0.569 / 0.668 ms |
| receive round trip p50 / p95 / p99 | 4.056 / 4.977 / 5.164 ms | 4.120 / 5.042 / 5.781 ms |
| payment total p50 / p95 / p99 | 4.935 / 5.916 / 6.078 ms | 4.968 / 5.964 / 6.718 ms |
| tv-cli flow with wallet files p50 / p95 / p99 | 29.045 / 35.142 / 37.894 ms | 31.948 / 35.702 / 37.902 ms |

Every figure is within the run-to-run variation described above (the 64-writer group commit, 13 percent lower, is the one most sensitive to a loaded machine and does not touch the enclave link); this run is not paired with the pre-fix tree, which could not complete the tv-cli flow section. The tv-cli flow now includes the refresh off `pk_0` in its setup only, outside the timed region. Client-side cost: verify 0.001 ms, seal 0.074 ms, `prepare_pay` 0.198 ms mean; message sizes within the integer-array variation (`Attest` 151, `Receive` 4899, `log.jsonl` line 1101 bytes).

## Fix round 8 (2026-11-12)

This round touched the store's write path: every flight now ends with a trailer line carrying the flight's byte length and its SHA-256 (`crates/tv-bank/src/flight.rs`), written in the same `write_all` and `sync_data` as the flight's lines, so a flight costs one SHA-256 over its lines and 99 more bytes on disk; replay hashes every flight once at startup. The pre-fix tree (`286e904`) and the fixed tree were run back to back twice, in opposite orders (pre-fix first, then fixed first), both with `--payments 1000` and the other defaults, on a machine whose load average fell from 15 to 5 during the four runs. Each cell gives the first and the second run.

| Measurement | 286e904, runs 1 and 2 | fixed tree, runs 1 and 2 |
|---|---|---|
| enclave checks, 1 thread | 0.193, 0.194 ms | 0.194, 0.194 ms |
| store append, fsync per op | 2.908, 3.047 ms | 2.902, 2.915 ms |
| store stage + group commit, 1 writer | 2.901, 2.982 ms | 2.832, 2.920 ms |
| store stage + group commit, 64 writers | 9029.3, 10204.1 /s | 9959.4, 9385.6 /s |
| bank settle, 1 pair | 3.636, 3.900 ms | 4.491, 3.887 ms |
| bank settle, 11 pairs | 1722.8, 1812.0 /s | 1875.7, 1725.3 /s |
| bank settle, 44 pairs | 5597.9, 5571.9 /s | 6006.3, 6039.8 /s |
| receive round trip p50 | 3.881, 3.949 ms | 4.017, 3.752 ms |
| payment total p50 | 4.746, 4.817 ms | 4.906, 4.523 ms |
| tv-cli flow with wallet files p50 | 32.155, 33.074 ms | 33.895, 34.077 ms |

The store figures, which isolate the changed path, are within the run-to-run variation in both directions. The 1-pair settle read 24 percent slower in the first fixed run and matched the pre-fix tree within 0.4 percent in the second, so the first reading is the fsync variance of this volume, not the trailer. The tv-cli flow p50 is about 1 ms higher in both fixed runs: every `refresh` now sends one `Lookup` before its `Attest`, but the flow times `request`, `pay`, `receive` and `finish` only, which this round did not change, so that difference is within the variation the earlier rounds recorded for this figure (29.0 to 34.0 ms). `log.jsonl` line, Pay: 1107 and 1113 bytes (the line format is unchanged; the trailer is a separate line).

## Fix round 9 (2026-11-12)

This round touched the attest path twice. Every client now checks the attestation's timestamp against `MAX_KEY_AGE` in `verify_bundle` (one comparison). The bank no longer sends the enclave a digest of the requester's address: the enclave's `Attest` carries the nonce and the owner serial only, the enclave returns the channel pk next to the document, and the bank counts pending keys per address in its own memory and sends `Cancel` for an address's oldest key beyond 256. Two `make bench` runs of the fixed tree with the defaults, back to back, on a loaded machine (load average 19 before the first run, 8 after the second), not paired with the pre-fix tree. Each cell gives the first and the second run.

| Measurement | fix round 9, runs 1 and 2 |
|---|---|
| enclave checks, 1 thread | 0.188, 0.188 ms |
| enclave checks, 11 threads | 29578.8, 30311.0 /s |
| store append, fsync per op | 2.942, 2.925 ms |
| store stage + group commit, 64 writers | 10052.9, 9597.1 /s |
| bank settle, 1 pair | 4.571, 4.543 ms |
| bank settle, 11 pairs | 1728.8, 1667.6 /s |
| bank settle, 44 pairs | 5946.3, 5789.7 /s |
| attest round trip p50 / p95 / p99 | 0.483 / 0.597 / 0.701, 0.478 / 0.598 / 0.690 ms |
| receive round trip p50 | 4.116, 3.909 ms |
| payment total p50 | 4.982, 4.766 ms |
| tv-cli flow with wallet files p50 | 32.040, 32.002 ms |
| verify attestation bundle, mean | 0.001, 0.001 ms |
| build offer, `prepare_pay`, mean | 0.147, 0.198 ms |

The enclave checks match the earlier rounds (0.188 against 0.193 to 0.194 ms). The attest round trip p50 reads 0.48 ms against 0.45 to 0.46 ms in fix rounds 2 and 7; it now includes one bank-side map update per attest, and this run was not paired with the pre-fix tree on an idle machine, so the difference is not separated from the load. The in-process settle, whose timed region includes the attest step, reads 4.57 and 4.54 ms for 1 pair against 3.89 and 4.49 ms in fix round 8, and 1729 and 1668 /s for 11 pairs against 1876 and 1725 /s; the same caveat applies. The store append (2.94 and 2.93 ms) is within fix round 8's range (2.90 to 3.05 ms). The timestamp check does not show in `verify_bundle` (0.001 ms in both runs). Message sizes: user-to-bank `Attest` 154 and 151 bytes, `log.jsonl` line, Pay, 1099 and 1110 bytes (both within the integer-array variation; neither format changed), bank-to-enclave `Attest` 152 bytes in the second run (the first run did not measure the enclave link frames), enclave-to-bank `Attestation` 597 bytes, `Cancel` 86 bytes.

## Fix round 10 (2026-11-12)

`tv-bench` runs on the system allocator. The shipped `tv-enclave` binary runs on `EnclaveAllocator` (`ZeroAlloc<System>`, which wipes every heap block before freeing it), and since this round `Enclave::check` also zeroes the 64 KiB of stack below its caller after each check. The enclave figures in this file therefore leave out the allocator's cost; the bank does not run on that allocator, so the bank, store and loopback figures are unaffected. To size the gap, `tv-bench` was built four times from this tree (with and without the stack scrub, with and without `#[global_allocator] static ALLOCATOR: tv_enclave::EnclaveAllocator = tv_enclave::ENCLAVE_ALLOCATOR;` in `tv-bench/src/main.rs`) and the four binaries were run in alternation three times with `--payments 30 --checks 4096 --appends 8 --iterations 5 --pairs 2` (load average 7).

| Enclave checks, 1 thread | run 1 | run 2 | run 3 |
|---|---|---|---|
| system allocator, no scrub | 0.188 ms | 0.190 ms | 0.190 ms |
| system allocator, scrub | 0.189 ms | 0.189 ms | 0.190 ms |
| zeroizing allocator, no scrub | 0.194 ms | 0.194 ms | 0.194 ms |
| zeroizing allocator, scrub (the shipped binary) | 0.195 ms | 0.194 ms | 0.195 ms |

The zeroizing allocator costs about 0.005 ms per check (2.6 percent), consistent in all three runs. The stack scrub costs at most 0.001 ms, inside the run-to-run noise. With 11 threads all four builds read between 29022 and 31584 /s, with no order among them. The bench keeps the system allocator so the enclave rows stay comparable with the earlier rounds; add 0.005 ms to them for the shipped binary.
