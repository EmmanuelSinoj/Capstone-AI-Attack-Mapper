<#
.SYNOPSIS
    Pulls the Ollama models this project needs into the running
    aam-ollama container. Sized for an 8GB-class GPU (RTX 5060 laptop):
    all three are 8B-or-smaller quantized models.

.NOTES
    Run standalone with: .\scripts\pull_models.ps1
    Or via setup.ps1, which calls this automatically.
#>

$ErrorActionPreference = "Stop"

$models = @(
    "llama3:8b",          # testbed model (candidate) / classification pilot
    "mistral:7b",         # testbed model (candidate) -- compare against llama3
    "llama-guard3:8b"     # detection judge model
    # Prompt-Guard-86M is not an Ollama-native model; it's pulled from
    # Hugging Face directly by the detection component when that's built
    # (see live_attack_path/detection/README.md).
)

foreach ($model in $models) {
    Write-Host "`nPulling $model ..." -ForegroundColor Cyan
    docker exec aam-ollama ollama pull $model
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to pull $model" -ForegroundColor Red
        continue
    }

    # Warm the model: a model's *first* inference after being pulled (or
    # after sitting idle past OLLAMA_KEEP_ALIVE) has to load its weights
    # into VRAM, which alone can take longer than a typical HTTP timeout.
    # Running one throwaway generation here means the testbed's first
    # real request doesn't pay that cost.
    Write-Host "Warming $model (loading weights into VRAM) ..." -ForegroundColor DarkCyan
    docker exec aam-ollama ollama run $model "hi" | Out-Null
}

Write-Host "`n=== Models available in Ollama ===" -ForegroundColor Cyan
docker exec aam-ollama ollama list
