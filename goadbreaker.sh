#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -eq 0 ]]; then
  set -- run
fi
if [[ "${1:-}" == "run" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo -E python3 "$ROOT_DIR/domainbreaker.py" "$@"
fi
exec python3 "$ROOT_DIR/domainbreaker.py" "$@"
