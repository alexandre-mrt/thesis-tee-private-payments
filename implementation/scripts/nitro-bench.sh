#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
BANK_ADDR="${TV_BANK_ADDR:-127.0.0.1:7700}"
BANK_DATA="${TV_BANK_DATA:-${HOME}/bank}"
EIF_JSON="${TV_EIF_JSON:-${HOME}/eif.json}"
PAYMENTS="${TV_BENCH_PAYMENTS:-1000}"
OUT="${TV_BENCH_OUT:-${HOME}/bench-results/$(date -u +%Y%m%dT%H%M%SZ)}"
IMDS="http://169.254.169.254/latest"
PCR0_HEX_LEN=96

die() {
  echo "nitro-bench: $*" >&2
  exit 1
}

pcr0_of_eif() {
  [ -f "${EIF_JSON}" ] || die "no ${EIF_JSON}; set PCR0 or TV_EIF_JSON"
  grep -o '"PCR0": *"[0-9a-f]*"' "${EIF_JSON}" | grep -o "[0-9a-f]\{${PCR0_HEX_LEN}\}"
}

trust_args() {
  if [ "${ALLOW_MOCK:-0}" = "1" ]; then
    echo "--allow-mock"
    return
  fi
  echo "--pcr0 ${PCR0}"
}

check_enclave() {
  [ "${ALLOW_MOCK:-0}" = "1" ] && return
  local described
  described="$(nitro-cli describe-enclaves)"
  echo "${described}" > "${OUT}/enclave.json"
  grep -q '"State": "RUNNING"' <<<"${described}" || die "no running enclave"
  grep -q '"Flags": "NONE"' <<<"${described}" || die "enclave is in debug mode: its attestation carries a zero PCR0"
  grep -q "\"PCR0\": \"${PCR0}\"" <<<"${described}" || die "running enclave PCR0 differs from ${PCR0}"
}

check_bank() {
  local host="${BANK_ADDR%:*}" port="${BANK_ADDR#*:}"
  (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null || die "no bank answers on ${BANK_ADDR}"
  [ -f "${BANK_DATA}/bank-wallet.json" ] || die "no bank wallet in ${BANK_DATA}"
}

instance_type() {
  local token
  token="$(curl -sf -m 2 -X PUT "${IMDS}/api/token" -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" || {
    echo "unknown"
    return
  }
  curl -sf -m 2 -H "X-aws-ec2-metadata-token: ${token}" "${IMDS}/meta-data/instance-type" || echo "unknown"
}

record_context() {
  {
    echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "commit=$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "instance_type=$(instance_type)"
    echo "kernel=$(uname -sr)"
    echo "bank=${BANK_ADDR}"
    echo "pcr0=${PCR0:-mock}"
    echo "payments=${PAYMENTS}"
  } | tee "${OUT}/context.txt"
}

main() {
  [ -x "${BIN}/tv-bench" ] || die "build first: cargo build --release -p tv-bench"
  mkdir -p "${OUT}"
  if [ "${ALLOW_MOCK:-0}" != "1" ]; then
    PCR0="${PCR0:-$(pcr0_of_eif)}"
    [ "${#PCR0}" -eq "${PCR0_HEX_LEN}" ] || die "PCR0 must be ${PCR0_HEX_LEN} hex characters"
  fi
  check_bank
  check_enclave
  record_context
  echo "== 1/2 local mock baseline on this machine"
  "${BIN}/tv-bench" --payments "${PAYMENTS}" | tee "${OUT}/mock.txt"
  echo "== 2/2 running bank with the enclave behind it"
  # shellcheck disable=SC2046 # trust_args is two words on purpose
  "${BIN}/tv-bench" --payments "${PAYMENTS}" --remote "${BANK_ADDR}" --bank-data "${BANK_DATA}" \
    $(trust_args) | tee "${OUT}/nitro.txt"
  echo "results in ${OUT}"
}

main "$@"
