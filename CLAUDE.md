# SPOTTER

Self-hosted OSINT and red-team recon platform, built for authorized engagements
under documented Rules of Engagement and for intelligence-analysis education.
The code is distributed under the MIT License; intended use is described in
`README.md`.

## What it is

Ingests SharpHound/BloodHound, Cobalt Strike, Brute Ratel, PingCastle, Nessus, nmap, Amass,
EyeWitness, CloudSchism, Flare.io, and freeform recon; correlates it into a Neo4j graph via **Flowsint**; runs the
analysis loop as **n8n** workflows; exposes it through an operator dashboard and an
**Open WebUI + vLLM** natural-language interface. Ollama was removed from the stack 2026-09-04.

`README.md` documents system behavior; `INSTALL.md` is the authoritative fresh-install
guide. `issues.md` tracks actionable open work. The repository skill under
`.github/skills/spotter-system/` contains system-specific maintenance guidance.

## Layout

| Path | What lives there |
|---|---|
| `n8n-workflows/` | 29 active n8n workflow JSONs (WF01–WF29). The system's actual logic. |
| `flowsint-custom/` | Custom Flowsint node types and the graph client. |
| `frontend/` | Operator dashboard (`index.html`) + `nginx.conf`. Bind-mounted. |
| `scripts/` | Deploy, ingest, enrichment, and smoke tests. |
| `deployment/` | Compose stack and container configs. |
| `llm/`, `auth-api/`, `maigret-api/`, `ssh-tunnel-api/`, `titus-sidecar/` | Sidecar services. |
| `vendor/flowsint/` | The pinned, patched Flowsint checkout (gitignored). The data tier, and the **first `-f`** of every launch. |
| `tunnel-keys/` | SSH keys for the managed tunnel (gitignored, 0700). Written by the Infrastructure tab's uploader. |

## Conventions that cost time when missed

- **Install/bootstrap:** `INSTALL.md` is the authoritative fresh-install runbook.
  `scripts/bootstrap.sh` takes a fresh host from clone to running stack;
  `deployment/setup-secrets.sh` seeds `.env` from `.env.example`. SOPS config and all
  secret tiers are local-only and must not be tracked.
  `FLOWSINT_API_KEY` is a login JWT that EXPIRES (~2.5 days by default), not a durable key:
  `scripts/refresh_flowsint_token.py --show-expiry`.
- **Deploy workflows with `scripts/deploy_workflow.sh`** — never by hand-importing. It only
  republishes JSONs marked `active: true`, and a repo JSON that disagrees with the live active
  flag takes that webhook offline.
- **Every graph query is scoped to the active campaign's sketch.** A wrong or empty sketch id
  returns clean zeros rather than an error — "the data isn't there" is usually this.
- **Compose:** always through `scripts/spotter_compose.sh`. It supplies `-p spotter`, the env
  file, the LLM/embed profiles and absolute `-f` paths, and deliberately omits
  `--project-directory`: the project directory is therefore `vendor/flowsint`, which is exactly
  where Flowsint's own `./flowsint-app/nginx.conf` has to resolve. Adding it would point that at
  a path that does not exist, and Docker would create it as a directory rather than erroring.
  Do not add it "for tidiness". A relative override of any `SPOTTER_*_DIR` still resolves against
  `vendor/flowsint`, not here — and upstream ships its own `sharphound-drops/`, so a relative
  value lands somewhere real and wrong instead of failing. The launcher now refuses to start on
  one, and `check_env_dirs_are_absolute` catches it offline.
- **Ingest can fail green.** Unparseable input still reports success, and a wrong or empty
  sketch id returns clean zeros — verify by counting nodes *and* their labels in the sketch.
  Oversize and password-protected uploads are rejected (`accepted: false`), not a green success.
- A browser upload larger than 32 MB is chunked into `ingest-staging/`; the n8n item carries a
  staged id, not the bytes.
- **Prefer targeted Neo4j reads** (`get_nodes_by_type` / `get_edges_by_type`) over a full graph
  read, which is slow and silently truncates.
- Smoke tests under `scripts/smoke_*.py|js` run offline; use them instead of a live round-trip.

## Data handling

Sketches, ingest staging, and `.env` hold **client engagement data**. Keep it local: no external
services, no third-party tools, and nothing from it in published or shared output unless asked.
