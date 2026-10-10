param(
    [string]$Output = "artifacts/evidence/local-three-node.json"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

python -m infra.local_three_node --output $Output
Write-Host "Local three-node TLS result: $Output"
