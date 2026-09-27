<#
.SYNOPSIS
    One-shot setup for the AI Attack Mapper local stack: brings up Ollama
    (GPU-accelerated), pulls the models the project needs, and verifies
    GPU passthrough is actually being used rather than falling back to CPU.

.NOTES
    Run from the ai-attack-mapper/ directory in PowerShell:
        .\scripts\setup.ps1
    Requires Docker Desktop with WSL2 + "Use NVIDIA GPU" enabled
    (Settings > Resources > GPU).
#>

$ErrorActionPreference = "Stop"

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example -- edit it if you need non-default ports/models." -ForegroundColor Yellow
}

Write-Host "`n=== Bringing up Ollama ===" -ForegroundColor Cyan
docker compose up -d ollama

Write-Host "`n=== Waiting for Ollama to become healthy ===" -ForegroundColor Cyan
$attempts = 0
do {
    Start-Sleep -Seconds 3
    $status = docker inspect --format='{{.State.Health.Status}}' aam-ollama 2>$null
    $attempts++
} while ($status -ne "healthy" -and $attempts -lt 20)

if ($status -ne "healthy") {
    Write-Host "Ollama did not become healthy in time. Run 'docker logs aam-ollama' to investigate." -ForegroundColor Red
    exit 1
}
Write-Host "Ollama is up." -ForegroundColor Green

Write-Host "`n=== Verifying GPU passthrough ===" -ForegroundColor Cyan
docker exec aam-ollama nvidia-smi
if ($LASTEXITCODE -ne 0) {
    Write-Host "nvidia-smi failed inside the container -- GPU passthrough is not working. Ollama will fall back to CPU (slow)." -ForegroundColor Red
    Write-Host "Check Docker Desktop > Settings > Resources > GPU is enabled, and that NVIDIA drivers are up to date." -ForegroundColor Red
} else {
    Write-Host "GPU visible inside the Ollama container." -ForegroundColor Green
}

Write-Host "`n=== Pulling models ===" -ForegroundColor Cyan
& "$PSScriptRoot\pull_models.ps1"

Write-Host "`n=== Bringing up the testbed ===" -ForegroundColor Cyan
docker compose up -d testbed

Write-Host "`n=== Smoke-testing the testbed ===" -ForegroundColor Cyan
Start-Sleep -Seconds 3
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8000/healthz" -TimeoutSec 10
    Write-Host "Testbed healthy: $($health | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
    Write-Host "Testbed did not respond -- run 'docker logs aam-testbed' to investigate." -ForegroundColor Red
}

Write-Host "`nSetup complete. 'docker compose ps' to see running services." -ForegroundColor Cyan
