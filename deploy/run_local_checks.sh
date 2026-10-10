#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_ROOT="${1:-artifacts/local-validation}"
EVIDENCE="${REPO_ROOT}/${EVIDENCE_ROOT}"
MODEL_PACKAGE="${EVIDENCE}/model-package"

cd "${REPO_ROOT}"
mkdir -p "${EVIDENCE}"

python -m pytest -q
python -m compileall -q client contracts crypto kas model mpc tee tests infra benchmark deploy
git diff --check

python -m infra.security_negative --output "${EVIDENCE}/negative-checks.json"
python -m infra.attack_matrix --output "${EVIDENCE}/attack-matrix.json"
python -m infra.d1_environment_check --output "${EVIDENCE}/d1-environment.json"
python -m infra.local_three_node --output "${EVIDENCE}/local-three-node.json"
python -m infra.validate_gramine_manifest \
  --template tee/gramine/a122.manifest.template \
  --values deploy/gramine-values.example.json \
  --output "${EVIDENCE}/a122.manifest" \
  --evidence "${EVIDENCE}/gramine-manifest-validation.json"
python -m infra.build_model_package --output "${MODEL_PACKAGE}" --encrypt-local
python -m infra.build_model_package --output "${MODEL_PACKAGE}" --verify
python -m infra.collect_evidence --root . --output "${EVIDENCE}/source-scan.json"

RELEASE="${EVIDENCE}/a122-local.zip"
python -m infra.build_release --root . --output "${RELEASE}" --version local-linux-checkpoint
python -m infra.validate_release "${RELEASE}" \
  --manifest "${RELEASE%.zip}.manifest.json" \
  --output "${EVIDENCE}/release-validation.json"

python -m infra.seal_evidence seal "${EVIDENCE}"
python -m infra.seal_evidence verify "${EVIDENCE}"

echo "Local Linux validation complete: ${EVIDENCE}"
