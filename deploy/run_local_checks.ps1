param(
    [string]$EvidenceRoot = "artifacts/local-validation"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$Evidence = Join-Path $RepoRoot $EvidenceRoot
$ModelPackage = Join-Path $Evidence "model-package"
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null

python -m pytest -q
python -m compileall -q client contracts crypto kas model mpc tee tests infra benchmark deploy
git diff --check

python -m infra.security_negative --output (Join-Path $Evidence "negative-checks.json")
python -m infra.attack_matrix --output (Join-Path $Evidence "attack-matrix.json")
python -m infra.d1_environment_check --output (Join-Path $Evidence "d1-environment.json")
python -m infra.local_three_node --output (Join-Path $Evidence "local-three-node.json")
python -m infra.validate_gramine_manifest `
  --template tee/gramine/a122.manifest.template `
  --values deploy/gramine-values.example.json `
  --output (Join-Path $Evidence "a122.manifest") `
  --evidence (Join-Path $Evidence "gramine-manifest-validation.json")
python -m infra.build_model_package --output $ModelPackage --encrypt-local
python -m infra.build_model_package --output $ModelPackage --verify
python -m infra.collect_evidence --root . --output (Join-Path $Evidence "source-scan.json")

$Release = Join-Path $Evidence "a122-local.zip"
python -m infra.build_release --root . --output $Release --version local-linux-checkpoint
python -m infra.validate_release $Release --manifest ($Release -replace "\.zip$", ".manifest.json") --output (Join-Path $Evidence "release-validation.json")

python -m infra.seal_evidence seal $Evidence
python -m infra.seal_evidence verify $Evidence

Write-Host "Local Linux validation complete: $Evidence"
