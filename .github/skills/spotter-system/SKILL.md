---
name: spotter-system
description: "Use when maintaining or installing SPOTTER, changing its n8n workflows, compose stack, graph integration, secrets, or release documentation."
---

# SPOTTER System Maintenance

## System shape

SPOTTER is a self-hosted OSINT and red-team reconnaissance platform for authorized engagements and intelligence-analysis education. n8n workflows implement ingest and analysis; Flowsint and Neo4j provide the graph/data tier; the dashboard is in `frontend/`; Open WebUI and vLLM provide optional natural-language analysis. There are 29 active workflows in `n8n-workflows/`.

## Installation and deployment

- Treat `INSTALL.md` as the authoritative fresh-install guide and `README.md` as the system reference.
- Use `scripts/bootstrap.sh` for a fresh install. The current bootstrap requires Linux, Docker Compose v2, root access for its RAM-only decrypted-secret mount, SOPS, and age-keygen.
- Use `scripts/spotter_compose.sh` for Compose commands. Its Flowsint-first file order and omitted `--project-directory` are intentional; do not replace them with ad hoc Compose invocations.
- Deploy workflow changes with `scripts/deploy_workflow.sh`, never by importing JSON through the n8n UI. Only workflows marked `active: true` are republished.
- Every graph operation must use the active campaign's sketch ID. The fallback `FLOWSINT_SKETCH_ID` is not a substitute for campaign scoping.

## Model tiers

- `none` and `remote` do not start local vLLM and do not require a local GPU.
- `local-small` does not select a smaller model automatically. Set `VLLM_MODEL` and `VLLM_MAX_MODEL_LEN` together and validate VRAM/KV cache for that model and context.
- The default `local-large` model downloads about 30-32 GB of weights. Budget additional space for Docker images, graph data, and backups.
- The optional embedding service is a separate profile and defaults to GPU index 1; verify GPU assignment before enabling it.

## Secrets and data

- `.env` contains configuration. Credentials belong in encrypted local SOPS tiers, managed with `scripts/spotter_secret.py`.
- `.sops.yaml` and all `secrets/` contents are install-local, gitignored, and must not be added to Git. A fresh install creates its own age identity and recipient configuration.
- Never inspect, expose, upload, or publish client engagement data, local credentials, database state, screenshots, ingest staging, or tunnel keys unless explicitly asked and appropriate for the task.
- Do not delete runtime or client-data directories as general cleanup. Verify generated/unneeded status and preserve local copies when excluding files from the public repository.

## Validation

- Run `python3 scripts/check_workflow_regressions.py` after changes to workflows, environment guards, or secret handling.
- Use focused `scripts/smoke_*.py` and `scripts/smoke_*.js` checks for the touched subsystem; they are intended to run offline unless explicitly described otherwise.
- Do not claim RAM/disk minimums as validated without clean-host measurements. State model/context and cache requirements separately from engagement-data growth.
