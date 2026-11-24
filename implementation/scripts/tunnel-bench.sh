#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
HOST="${1:-}"
KEY="${TV_SSH_KEY:-${HOME}/.ssh/tee-pay-ec2.pem}"
LOCAL_PORT="${TV_TUNNEL_PORT:-17700}"
REMOTE_BANK="${TV_REMOTE_BANK:-127.0.0.1:7700}"
REMOTE_BANK_DATA="${TV_REMOTE_BANK_DATA:-bank}"
REMOTE_EIF_JSON="${TV_REMOTE_EIF_JSON:-eif.json}"
PAYMENTS="${TV_BENCH_PAYMENTS:-300}"
PAIRS="${TV_BENCH_PAIRS:-32}"
OUT="${TV_BENCH_OUT:-${HOME}/bench-results/tunnel-$(date -u +%Y%m%dT%H%M%SZ)}"
WALLET="bank-wallet.json"
AWAY_SUFFIX=".on-laptop"
PCR0_HEX_LEN=96
WAIT_STEPS=100
SSH_OPTS=(-i "${KEY}" -o BatchMode=yes -o ExitOnForwardFailure=yes)
TUNNEL_PID=""
WALLET_TAKEN=0

die() {
  echo "tunnel-bench: $*" >&2
  exit 1
}

on_host() {
  # shellcheck disable=SC2029 # the remote paths are computed here on purpose
  ssh "${SSH_OPTS[@]}" "${HOST}" "$@"
}

trust_args() {
  if [ "${ALLOW_MOCK:-0}" = "1" ]; then
    echo "--allow-mock"
    return
  fi
  echo "--pcr0 ${PCR0}"
}

read_pcr0() {
  if [ "${ALLOW_MOCK:-0}" = "1" ]; then
    PCR0="mock"
    return
  fi
  PCR0="$(on_host cat "${REMOTE_EIF_JSON}" | grep -o '"PCR0": *"[0-9a-f]*"' |
    grep -o "[0-9a-f]\{${PCR0_HEX_LEN}\}")" || die "no PCR0 in ${REMOTE_EIF_JSON} on ${HOST}"
}

port_answers() {
  (exec 3<>"/dev/tcp/127.0.0.1/${LOCAL_PORT}") 2>/dev/null
}

open_tunnel() {
  port_answers && die "local port ${LOCAL_PORT} is taken; set TV_TUNNEL_PORT"
  ssh "${SSH_OPTS[@]}" -N -L "${LOCAL_PORT}:${REMOTE_BANK}" "${HOST}" &
  TUNNEL_PID=$!
  for _ in $(seq 1 "${WAIT_STEPS}"); do
    port_answers && return
    sleep 0.1
  done
  die "the tunnel to ${REMOTE_BANK} did not come up"
}

take_wallet() {
  local remote="${REMOTE_BANK_DATA}/${WALLET}"
  on_host test -f "${remote}" -a ! -e "${remote}${AWAY_SUFFIX}" ||
    die "${remote} missing on ${HOST}, or a ${AWAY_SUFFIX} copy is already set aside"
  mkdir -p "${OUT}/bank"
  scp -q "${SSH_OPTS[@]}" "${HOST}:${remote}" "${OUT}/bank/${WALLET}"
  on_host mv "${remote}" "${remote}${AWAY_SUFFIX}"
  WALLET_TAKEN=1
}

give_wallet_back() {
  [ "${WALLET_TAKEN}" = "1" ] || return 0
  local remote="${REMOTE_BANK_DATA}/${WALLET}"
  if scp -q "${SSH_OPTS[@]}" "${OUT}/bank/${WALLET}" "${HOST}:${remote}" &&
    on_host rm -f "${remote}${AWAY_SUFFIX}"; then
    WALLET_TAKEN=0
    echo "bank wallet returned to ${HOST}:${remote}"
    return 0
  fi
  echo "tunnel-bench: WARNING the bank wallet was not returned." >&2
  echo "  The current one is ${OUT}/bank/${WALLET}; copy it to ~/${remote} on the instance" >&2
  echo "  and delete ~/${remote}${AWAY_SUFFIX} there." >&2
}

cleanup() {
  give_wallet_back
  [ -n "${TUNNEL_PID}" ] && kill "${TUNNEL_PID}" 2>/dev/null
  return 0
}

record_context() {
  {
    echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "commit=$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "client=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
    echo "host=${HOST}"
    echo "pcr0=${PCR0}"
    echo "payments=${PAYMENTS}"
    echo "pairs=${PAIRS}"
  } | tee "${OUT}/context.txt"
}

main() {
  [ -n "${HOST}" ] || die "usage: scripts/tunnel-bench.sh ec2-user@<instance IP>"
  [ -x "${BIN}/tv-bench" ] || die "build first: cargo build --release -p tv-bench"
  [ -f "${KEY}" ] || die "no SSH key at ${KEY}; set TV_SSH_KEY"
  mkdir -p "${OUT}"
  trap cleanup EXIT
  read_pcr0
  record_context
  open_tunnel
  take_wallet
  # shellcheck disable=SC2046 # trust_args is two words on purpose
  "${BIN}/tv-bench" --payments "${PAYMENTS}" --pairs "${PAIRS}" \
    --remote "127.0.0.1:${LOCAL_PORT}" --bank-data "${OUT}/bank" $(trust_args) |
    tee "${OUT}/tunnel.txt"
  echo "results in ${OUT}"
}

main "$@"
