#!/usr/bin/env bash
set -euo pipefail

if pkill -f "tv-bank serve"; then
  echo "bank stopped"
else
  echo "no bank running"
fi
nitro-cli terminate-enclave --all
