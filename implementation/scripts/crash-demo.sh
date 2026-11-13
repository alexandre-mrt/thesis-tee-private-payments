#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

ENCLAVE_CRASH_EXIT=86
BANK_CRASH_EXIT=87

setup
start_enclave
start_bank --dev
register_enclave
cli alice enroll
cli bob enroll
issue_to alice 500
balances

echo "== 1. enclave crashes before answering"
kill "${ENCLAVE_PID}"
wait "${ENCLAVE_PID}" 2>/dev/null || true
wait_port_closed "${ENCLAVE_ADDR}"
export TV_CRASH_BEFORE_ANSWER=1
start_enclave
unset TV_CRASH_BEFORE_ANSWER
register_enclave
cli bob request --amount 100 --out "${DATA}/req1.json"
cli alice pay --request "${DATA}/req1.json" --amount 100 --out "${DATA}/offer1.json"
if cli bob receive --offer "${DATA}/offer1.json" --out "${DATA}/receipt1.json" 2>"${DATA}/receive1.err"; then
  echo "receive unexpectedly succeeded" >&2
  exit 1
fi
echo "receive failed as expected: $(tail -n 1 "${DATA}/receive1.err")"
code=0
wait "${ENCLAVE_PID}" || code=$?
[ "${code}" -eq "${ENCLAVE_CRASH_EXIT}" ] || { echo "enclave exit code ${code}, expected ${ENCLAVE_CRASH_EXIT}" >&2; exit 1; }
echo "enclave exited with ${code}; balances unchanged:"
balances

echo "-- restart the enclave, re-register, re-attest, reseal, retry"
start_enclave
register_enclave
cli bob request --out "${DATA}/req1b.json"
cli alice reseal --request "${DATA}/req1b.json" --out "${DATA}/offer1b.json"
cli bob receive --offer "${DATA}/offer1b.json" --out "${DATA}/receipt1b.json"
cli alice finish --receipt "${DATA}/receipt1b.json"
balances

echo "== 2. bank crashes after its append"
kill "${BANK_PID}"
wait "${BANK_PID}" 2>/dev/null || true
wait_port_closed "${BANK_ADDR}"
export TV_CRASH_AFTER_APPEND=1
start_bank --dev
unset TV_CRASH_AFTER_APPEND
ENTRIES_BEFORE="$(log_entries)"
cli bob request --amount 30 --out "${DATA}/req2.json"
cli alice pay --request "${DATA}/req2.json" --amount 30 --out "${DATA}/offer2.json"
cli bob receive --offer "${DATA}/offer2.json" --out "${DATA}/receipt2.json" 2>"${DATA}/receive2.err" &
RECEIVE_PID=$!
code=0
wait "${BANK_PID}" || code=$?
[ "${code}" -eq "${BANK_CRASH_EXIT}" ] || { echo "bank exit code ${code}, expected ${BANK_CRASH_EXIT}" >&2; exit 1; }
echo "bank exited with ${code} after appending; log has $(log_entries) entries"
wait_port_closed "${BANK_ADDR}"
start_bank
wait "${RECEIVE_PID}"
echo "retry settled from the stored answer: $(grep -c "retrying" "${DATA}/receive2.err") retries logged"
cli alice finish --receipt "${DATA}/receipt2.json"
ENTRIES_AFTER="$(log_entries)"
[ "$((ENTRIES_AFTER - ENTRIES_BEFORE))" -eq 1 ] || { echo "expected exactly one new entry" >&2; exit 1; }
balances
