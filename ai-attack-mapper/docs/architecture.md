# Architecture

This mirrors Figure 1 in the Capstone Group document (Design section).
The rendered diagram lives at `docs/architecture-diagram.png` (copy the
current version in from the Capstone doc's media, or from the Cowork
artifact, whenever the diagram is revised, so this stays in sync).

## Two entry paths, one shared schema

**Live Attack Path.** Garak + PyRIT generate known and adaptive
prompt-injection / jailbreak payloads against the self-hosted `testbed`
service (Llama 3 or Mistral via Ollama). Every interaction is logged and
passed through detection (heuristic rules + a judge model -- Llama Guard
or Prompt-Guard-86M) checking **both** the input to and the output of
the testbed. Flagged interactions become structured alerts.

**Synthetic Alert Path.** The remaining four taxonomy categories
(poisoning, extraction, supply-chain compromise, agentic threats) can't
be safely or meaningfully demonstrated against a hosted model, so
they're represented through synthetic alerts drafted from MITRE ATLAS
case studies and the team's literature corpus, one-time batch generated
and human-verified against source before entering the store.

Both paths write to the same `alerts` table (`alert_store/schema.sql`),
so the classification engine treats live and synthetic alerts
identically -- classification coverage spans the full taxonomy even
though only prompt injection is demonstrated live.

## Classification and response

The classification engine maps every alert to category, lifecycle
phase, and all three frameworks (ATT&CK, ATLAS, OWASP LLM Top 10) via
structured prompting -- no fine-tuning. Model choice (local Ollama vs.
Claude Sonnet 5) is being decided empirically; see
`classification_engine/README.md`.

Confirmed, high-confidence **live** prompt-injection alerts additionally
trigger **Auto-Hardening**: a targeted countermeasure clause is
generated and appended to the testbed's versioned system prompt
(`live_attack_path/testbed/system_prompt.txt`). This is live-path-only
-- there's no live system to patch on the synthetic side.

Every classified alert, regardless of path or confidence, produces a
recommended **playbook** grounded in the team's defensive-controls
crosswalk.

## Evaluation

Independent of the model-selection pilot: (1) classification accuracy
via precision/recall/confusion matrix against ground truth, and (2)
defensive effectiveness via attack-success-rate replay (original +
paraphrased payloads) before/after hardening. See `evaluation/README.md`.
