# AI Attack Mapper

Classifies AI-enabled cyberattacks against MITRE ATT&CK, MITRE ATLAS, and
the OWASP LLM Top 10, and applies an automated defensive response to
confirmed live attacks. RIT capstone (Emmanuel Sinoj Periyil, Gladwin
Mathews, Aneeq Razak, Shadi), built on the team's 240/248-study summer
research co-op literature review.

Full design writeup: see the Capstone Group document, Section VII
(Design), and `docs/architecture.md` in this repo for the developer-facing
version of the same architecture.

## Architecture at a glance

Two paths write to one shared alert schema:

- **Live Attack Path** -- Garak + PyRIT attack a self-hosted testbed
  (Llama 3 / Mistral via Ollama); a heuristic + judge-model detector
  watches both input and output; confirmed high-confidence alerts trigger
  Auto-Hardening on the testbed's system prompt.
- **Synthetic Alert Path** -- the remaining taxonomy categories
  (poisoning, extraction, supply-chain, agentic) are represented through
  human-verified synthetic alerts drafted from MITRE ATLAS case studies
  and the literature corpus.

Both feed the **Classification Engine** (structured prompting against
all three frameworks, no fine-tuning), which drives **Playbook
Generation** for every alert and feeds the two-part **Evaluation**
(classification accuracy + defensive effectiveness).

See `docs/architecture.md` for the full breakdown.

## Repository layout

```
ai-attack-mapper/
├── docker-compose.yml          # Ollama + testbed services
├── .env.example                # copy to .env, adjust ports/models
├── live_attack_path/
│   ├── testbed/                 # FastAPI wrapper around Ollama (protected app)
│   ├── attack_generation/       # Garak + PyRIT runners
│   ├── detection/                # heuristics + judge-model detection
│   └── dashboard/                 # read-only live ops console (web UI)
├── synthetic_alert_path/
│   └── generator/                # ATLAS/corpus-derived synthetic alerts
├── alert_store/                 # shared SQLite schema + helper
├── classification_engine/       # taxonomy + framework mapping, playbooks
├── evaluation/                  # accuracy + attack-success-rate metrics
├── scripts/                      # setup + model-pull automation
└── docs/                         # architecture writeup
```

Each track's README states what's implemented, what's planned, and who
owns it (matches the Team Structure table in the Capstone Group doc).

## Setup

**Prerequisites:** Docker Desktop with WSL2 backend and NVIDIA GPU
support enabled (Settings > Resources > GPU). Tested against an RTX
5060 laptop GPU (8GB VRAM) -- model choices below assume that class of
hardware.

```powershell
git clone <team-repo-url> ai-attack-mapper
cd ai-attack-mapper
.\scripts\setup.ps1
```

This copies `.env.example` to `.env`, brings up Ollama, verifies GPU
passthrough (`nvidia-smi` inside the container), pulls the models listed
in `scripts/pull_models.ps1`, brings up the testbed, and smoke-tests it.

To run steps individually:

```powershell
docker compose up -d ollama
.\scripts\pull_models.ps1
docker compose up -d testbed
docker compose ps
```

Testbed health check: `http://localhost:8000/healthz`
Ollama API: `http://localhost:11434`
Dashboard (live ops console -- see `live_attack_path/dashboard/README.md`): `http://localhost:8080`

## Models

| Model | Role | Size (quantized) |
|---|---|---|
| `llama3:8b` | Testbed candidate / classification pilot | ~4.7GB |
| `mistral:7b` | Testbed candidate (comparison) | ~4.1GB |
| `llama-guard3:8b` | Detection judge model | ~4.7GB |
| Claude Sonnet 5 | Synthetic alert drafting; classification fallback if the local pilot underperforms | hosted, API |

All local models fit comfortably on an 8GB-class GPU. If VRAM pressure
shows up running two models concurrently (testbed + judge), drop
`OLLAMA_KEEP_ALIVE` in `.env` so idle models unload sooner.

## Status

Infra scaffold: done (this commit). Component implementation follows
the track ownership and weekly plan in the Capstone Group document,
Section IX.
