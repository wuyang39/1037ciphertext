param(
    [string]$EvidencePath = "artifacts/evidence/local-checks.json",
    [string]$NegativePath = "artifacts/evidence/negative-checks.json"
)

$ErrorActionPreference = "Stop"
python -m pytest -q
python -m compileall -q client contracts crypto kas model mpc tee tests infra
git diff --check
python infra/security_negative.py --output $NegativePath
python infra/collect_evidence.py --root . --output $EvidencePath
Write-Host "Local checks complete. Evidence: $EvidencePath"
