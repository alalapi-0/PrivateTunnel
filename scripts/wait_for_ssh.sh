#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-}"
TIMEOUT="${2:-600}"

if [ -z "$HOST" ]; then
  echo "Usage: $0 <host> [timeout_seconds]" >&2
  exit 1
fi

DEADLINE=$(( $(date +%s) + TIMEOUT ))

while true; do
  if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$HOST" exit 0; then
    exit 0
  fi
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then
    echo "Timeout waiting for SSH on $HOST" >&2
    exit 2
  fi
  sleep 10
done
