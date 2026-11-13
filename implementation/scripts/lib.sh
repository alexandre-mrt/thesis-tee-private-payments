#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release"
export PATH="$HOME/.cargo/bin:$PATH"
RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")"
export RUSTUP_TOOLCHAIN
BANK_ADDR="${TV_BANK_ADDR:-127.0.0.1:7700}"
ENCLAVE_ADDR="${TV_ENCLAVE_ADDR:-127.0.0.1:5005}"
DATA="$(mktemp -d "${TMPDIR:-/tmp}/tv-demo.XXXXXX")"
BANK_DATA="$DATA/bank"
WALLETS="$DATA/wallets"
PIDS=()
ENCLAVE_PID=""
BANK_PID=""

cleanup() {
  local status=$?
  for pid in "${PIDS[@]:-}"; do
    [ -n "${pid}" ] || continue
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
  if [ "${status}" -ne 0 ]; then
    local log
    for log in "${DATA}/bank.log" "${DATA}/enclave.log"; do
      [ -f "${log}" ] || continue
      echo "---- ${log}" >&2
      cat "${log}" >&2
    done
    echo "failed with status ${status}; kept ${DATA}" >&2
    return
  fi
  rm -rf "${DATA}"
}
trap cleanup EXIT

wait_port() {
  local host="${1%:*}" port="${1#*:}" i
  for i in $(seq 1 150); do
    if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "timeout waiting for $1" >&2
  return 1
}

port_answers() {
  local host="${1%:*}" port="${1#*:}"
  (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null
}

refuse_if_taken() {
  if port_answers "$1"; then
    echo "$1 already answers; another process holds the port" >&2
    return 1
  fi
}

require_alive() {
  if ! kill -0 "$1" 2>/dev/null; then
    echo "$2 exited during startup; see its log" >&2
    return 1
  fi
}

wait_port_closed() {
  local host="${1%:*}" port="${1#*:}" i
  for i in $(seq 1 150); do
    if ! (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "timeout waiting for $1 to close" >&2
  return 1
}

cli() {
  local wallet="$1"
  shift
  "${BIN}/tv-cli" --wallet "${WALLETS}/${wallet}.json" --bank "${BANK_ADDR}" --allow-mock "$@"
}

bankw() {
  "${BIN}/tv-bank" "$1" --data "${BANK_DATA}" --bank "${BANK_ADDR}" --allow-mock "${@:2}"
}

start_enclave() {
  refuse_if_taken "${ENCLAVE_ADDR}"
  "${BIN}/tv-enclave" --mock --state-pk "${STATE_PK}" --issuance-pk "${ISSUANCE_PK}" --listen "${ENCLAVE_ADDR}" \
    2>>"${DATA}/enclave.log" &
  ENCLAVE_PID=$!
  PIDS+=("${ENCLAVE_PID}")
  wait_port "${ENCLAVE_ADDR}"
  require_alive "${ENCLAVE_PID}" tv-enclave
}

start_bank() {
  refuse_if_taken "${BANK_ADDR}"
  "${BIN}/tv-bank" serve --data "${BANK_DATA}" --listen "${BANK_ADDR}" --enclave "tcp://${ENCLAVE_ADDR}" --allow-mock "$@" \
    2>>"${DATA}/bank.log" &
  BANK_PID=$!
  PIDS+=("${BANK_PID}")
  wait_port "${BANK_ADDR}"
  require_alive "${BANK_PID}" tv-bank
}

register_enclave() {
  local key
  key="$("${BIN}/tv-bank" register-enclave --bank "${BANK_ADDR}")"
  echo "registered enclave result key: ${key}"
}

setup() {
  (cd "${ROOT}" && cargo build --workspace --release)
  local keys
  keys="$("${BIN}/tv-bank" init --data "${BANK_DATA}")"
  STATE_PK="$(sed -n 's/^state_pk=//p' <<<"${keys}")"
  ISSUANCE_PK="$(sed -n 's/^issuance_pk=//p' <<<"${keys}")"
  echo "bank state key:    ${STATE_PK}"
  echo "bank issuance key: ${ISSUANCE_PK}"
  mkdir -p "${WALLETS}"
  for name in alice bob; do
    cli "${name}" new --state-pk "${STATE_PK}" --issuance-pk "${ISSUANCE_PK}"
  done
}

log_entries() {
  grep -c '^{"seq":' "${BANK_DATA}/log.jsonl" || true
}

balances() {
  echo "alice: $(cli alice balance)"
  echo "bob:   $(cli bob balance)"
  echo "bank:  $("${BIN}/tv-bank" balance --data "${BANK_DATA}" 2>/dev/null)"
  echo "log:   $(log_entries) entries"
}

issue_to() {
  local wallet="$1" amount="$2"
  cli "${wallet}" request --amount "${amount}" --out "${DATA}/req-issue.json"
  bankw issue --amount "${amount}" --to-request "${DATA}/req-issue.json" --out "${DATA}/offer-issue.json"
  cli "${wallet}" receive --offer "${DATA}/offer-issue.json" --out "${DATA}/receipt-issue.json"
  bankw finish --receipt "${DATA}/receipt-issue.json"
}
