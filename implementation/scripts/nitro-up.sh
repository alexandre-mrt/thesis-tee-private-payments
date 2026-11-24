#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
EIF="${TV_EIF:-${HOME}/tv-enclave.eif}"
EIF_JSON="${TV_EIF_JSON:-${HOME}/eif.json}"
BANK_ADDR="${TV_BANK_ADDR:-127.0.0.1:7700}"
BANK_DATA="${TV_BANK_DATA:-${HOME}/bank}"
BANK_LOG="${TV_BANK_LOG:-${HOME}/bank.log}"
CID="${TV_ENCLAVE_CID:-16}"
PORT="${TV_ENCLAVE_PORT:-5005}"
CPUS="${TV_ENCLAVE_CPUS:-2}"
MEMORY_MIB="${TV_ENCLAVE_MEMORY_MIB:-2048}"
PCR0_HEX_LEN=96
WAIT_STEPS=150

die() {
  echo "nitro-up: $*" >&2
  exit 1
}

bank_answers() {
  local host="${BANK_ADDR%:*}" port="${BANK_ADDR#*:}"
  (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null
}

read_pcr0() {
  [ -f "${EIF_JSON}" ] || die "no ${EIF_JSON} (the nitro-cli build-enclave output)"
  PCR0="$(grep -o '"PCR0": *"[0-9a-f]*"' "${EIF_JSON}" | grep -o "[0-9a-f]\{${PCR0_HEX_LEN}\}")" ||
    die "no PCR0 in ${EIF_JSON}"
  echo "PCR0 ${PCR0}"
}

start_enclave() {
  local described
  described="$(nitro-cli describe-enclaves)"
  if grep -q '"State": "RUNNING"' <<<"${described}"; then
    grep -q "\"PCR0\": \"${PCR0}\"" <<<"${described}" ||
      die "an enclave with another PCR0 is running; stop it with scripts/nitro-down.sh"
    echo "enclave already running"
    return
  fi
  [ -f "${EIF}" ] || die "no ${EIF}"
  nitro-cli run-enclave --eif-path "${EIF}" --cpu-count "${CPUS}" --memory "${MEMORY_MIB}" \
    --enclave-cid "${CID}"
  nitro-cli describe-enclaves | grep -q '"Flags": "NONE"' || die "enclave started in debug mode"
}

start_bank() {
  if bank_answers; then
    echo "bank already answering on ${BANK_ADDR}"
    return
  fi
  [ -x "${BIN}/tv-bank" ] || die "build first: cargo build --release -p tv-bank -p tv-client -p tv-bench"
  nohup "${BIN}/tv-bank" serve --data "${BANK_DATA}" --listen "${BANK_ADDR}" \
    --enclave "vsock://${CID}:${PORT}" --pcr0 "${PCR0}" >>"${BANK_LOG}" 2>&1 &
  for _ in $(seq 1 "${WAIT_STEPS}"); do
    bank_answers && return
    sleep 0.1
  done
  tail -5 "${BANK_LOG}" >&2
  die "bank did not answer on ${BANK_ADDR}"
}

main() {
  read_pcr0
  start_enclave
  start_bank
  echo "enclave result key $("${BIN}/tv-bank" register-enclave --bank "${BANK_ADDR}")"
}

main "$@"
