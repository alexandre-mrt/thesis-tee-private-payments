#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

setup
start_enclave
start_bank
register_enclave

echo "== enroll"
cli alice enroll
cli bob enroll

echo "== issue 500 to alice"
issue_to alice 500

echo "== alice pays bob 120"
cli bob request --amount 120 --out "${DATA}/req-pay.json"
cli alice pay --request "${DATA}/req-pay.json" --amount 120 --out "${DATA}/offer-pay.json"
cli bob receive --offer "${DATA}/offer-pay.json" --out "${DATA}/receipt-pay.json"
cli alice finish --receipt "${DATA}/receipt-pay.json"

echo "== bob refreshes"
cli bob refresh

echo "== bob redeems 50"
bankw request --amount 50 --out "${DATA}/req-redeem.json"
cli bob redeem --request "${DATA}/req-redeem.json" --amount 50 --out "${DATA}/offer-redeem.json"
bankw receive --offer "${DATA}/offer-redeem.json" --out "${DATA}/receipt-redeem.json"
cli bob finish --receipt "${DATA}/receipt-redeem.json"

echo "== recover alice from her seed alone"
SEED="$(cli alice seed)"
cli alice-recovered new --seed "${SEED}" --state-pk "${STATE_PK}" --issuance-pk "${ISSUANCE_PK}"
cli alice-recovered recover
echo "recovered: $(cli alice-recovered balance)"

echo "== recover the bank wallet from its genesis state and the issuance ledger"
bankw recover

echo "== balances"
balances
