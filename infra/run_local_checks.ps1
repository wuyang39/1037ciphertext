param(
    [string]$EvidenceRoot = "artifacts/local-validation"
)

$ErrorActionPreference = "Stop"
$Entrypoint = Join-Path $PSScriptRoot "..\deploy\run_local_checks.ps1"
& $Entrypoint -EvidenceRoot $EvidenceRoot
