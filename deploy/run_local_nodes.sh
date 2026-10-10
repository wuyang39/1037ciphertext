#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-artifacts/evidence/local-three-node.json}"

cd "${REPO_ROOT}"
python -m infra.local_three_node --output "${OUTPUT}"
echo "Local three-node TLS result: ${OUTPUT}"
