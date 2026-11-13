# SPOTTER project status and roadmap

Developer context for work on this repo: what is in place on `dev`, how to
validate it, and what is still open. Confirm anything you change against the
code; this file is a snapshot, not a substitute for `README.md` or `INSTALL.md`.

As of the commit that added this document, `origin/dev` was at `985cf38`
(`feat(objectives): enrich domains for additional orgs and surface clone findings`).
Update that tip commit in this intro when you land follow-up work.

Authoritative references:

- `README.md` — system behavior (Active tab, Domain Recon, secrets, tests)
- `INSTALL.md` — fresh install, token lifetime, Site Clone host steps
- `issues.md` — open issues (empty as of 2026-09-26)
- `.github/skills/spotter-system/SKILL.md` — maintenance conventions

## 1. Active tab and Site Clone

Activities that contact the target live in the **Active** tab. The first (and
currently only) feature there is **Site Clone**. Live full-site crawl was
removed from Domain Recon (WF13); that card keeps a single proxied homepage
title probe and points operators at Active.

### Pipeline

The dashboard talks to n8n workflow 32 (`n8n-workflows/32-site-clone.json`,
webhook `POST /webhook/site-clone`). WF32 is a thin proxy onto
`site-clone-api` (`spotter-site-clone`, port 7052). Long-running work runs in
that sidecar, not in the n8n task runner.

Typical job, in order:

1. **Start** — `POST /clone` with URL, campaign id, options, and the
   Infrastructure OPSEC/proxy envelope. Jobs are async; the UI polls
   `action=status`.
2. **HTTrack** — writes the raw tree to
   `data/clones/<campaignId>/<jobId>/mirror/`. Defaults (also the Active form
   defaults): depth 2, 20s connect timeout, 300s max time, 100 MiB, 2000 files,
   same host, honor robots.txt, keep images/JS/CSS/other, no external wander
   (`external`: `none` | `same_registrable` | `all`).
3. **OPSEC / DNS** — **Respect OPSEC profile** is on by default and is
   fail-closed: the job will not start if origin DNS would fall through to
   Docker's resolver, unless **Allow Docker DNS (leaks lookups)** is checked
   (off by default). Bookworm HTTrack 3.49.4 does not HTTP CONNECT for HTTPS,
   so OPSEC does not use HTTrack `-P`.
   - SOCKS5, TOR, and "Use Tunnel as SOCKS Proxy" go through proxychains-ng
     (`strict_chain` + `proxy_dns`). The proxy *endpoint* hostname (often a
     compose name such as `ssh-tunnel-api`) is resolved once via Docker DNS to
     a numeric IP before the conf is written — proxychains-ng rejects a
     non-numeric first hop. That lookup is not the target. Job card:
     `DNS: via SOCKS5` or `DNS: via TOR`.
   - HTTP proxies also use proxychains-ng (`http` + `proxy_dns`), not HTTrack
     `-P`.
   - No-proxy jobs bind a per-job `resolv.conf` in a user+mount namespace, or
     an in-tree DoH stub when Infrastructure resolvers are DoH-only/mixed.
   - proxychains-ng may invent `224.0.0.0/8` stub addresses on the TOR/SOCKS
     path; those are expected and are not published as target IPs.
4. **User-Agent** — HTTrack 3.49.x exits immediately with
   `User-agent length too long` if `-F` is over ~120 characters (a common
   OPSEC UA length). Over-long UAs are replaced with a short Firefox-like UA
   and a warning. Failure text includes the `httrack.log` tail at the job root
   (not only `mirror/hts-log.txt`).
5. **JavaScript deobfuscation** (on by default; timeout default 180s) —
   recovers embedded sourcemaps, then runs pinned webcrack 2.16.0 on cloned
   `.js` / `.mjs` / `.cjs` (size and job caps; heap and address-space caps).
   Output lands in `deobf/` beside the untouched mirror. Under OPSEC, webcrack
   runs in `spotter-site-clone-deobf` (`site-clone-deobf`, `network_mode: none`,
   shared clone volume, queue at `<job>/deobf-queue/`). `unshare --net` is not
   used; many hosts (Fedora/Nobara included) refuse it inside the clone
   container. If the worker is down, deobfuscation is skipped (job still
   finishes) and the card names
   `sudo ./spotter compose up -d --build site-clone-deobf`.
6. **OCR** (on by default) — Tesseract on cloned images (and image-based PDF
   pages via `pdftoppm`). Caps default to 8 MiB/file, 40 images/job, 15s/image,
   5 PDF pages. Text goes under `job_dir/ocr/`, is mined with the same
   analyzers, and is tagged `ocr=true`. Fail-open if Tesseract is missing.
7. **Analyzer** (`scripts/site_clone_analyze.py`) — offline pass over the
   tree: emails, phones, names, HTML/JS comments, hidden form fields, meta
   tags, links, JS endpoints, sourcemaps, secret-shaped strings (always
   redacted/masked), documents, EXIF. Findings from recovered JS are tagged
   `deobfuscated=true`.
8. **View source** — Open findings can load a read-only, secret-scrubbed
   snippet of a `deobf/` / `ocr/` / mirror file through
   `POST /jobs/<id>/source`. Rendered as text; never executed in the browser.
   The modal closes with X, Escape, or a backdrop click.
9. **Sketch ingest** — when status is `done`, WF32 calls
   `site_clone_ingest.ingest_findings()` once (see §3).
10. **Prompt index** — WF32 then calls `site_rag.index_offline_tree()` on
    `mirror/`, recovered JS under `deobf/`, and OCR text, writing the
    per-campaign `company_site__<sketch_id>` collection the Prompt tab already
    queries. The target is not contacted again. Re-cloning one host replaces
    that host only. Indexing is fail-open and retried on later status polls.

Cancel is supported. Job list is persisted on the campaign (including
export/import). Frontend is bind-mounted (`frontend/` → nginx html); HTML/JS
edits need a hard refresh, not an image rebuild.

Key paths: `site-clone-api/app.py`, `scripts/site_clone.py`,
`scripts/site_clone_dns.py`, `scripts/site_clone_deobfuscate.py`,
`scripts/site_clone_deobf_worker.py`, `scripts/site_clone_ocr.py`,
`scripts/site_clone_analyze.py`, `scripts/site_clone_ingest.py`,
`scripts/site_rag.py`, `n8n-workflows/32-site-clone.json`,
`deployment/docker-compose.flowsint.yml`, Active UI in `frontend/index.html`.

Host rebuild after clone-sidecar changes:

```bash
sudo ./spotter compose up -d --build --force-recreate site-clone-api site-clone-deobf
sudo ./spotter doctor
```

`git pull` does not import n8n workflows. If the webhook is missing or
inactive (`The requested webhook "POST site-clone" is not registered`):

```bash
sudo scripts/deploy_workflow.sh n8n-workflows/32-site-clone.json
```

`./spotter doctor` flags a missing/inactive repo workflow and probes
`POST /webhook/site-clone` plus both Site Clone containers.

## 2. Flowsint API token

Flowsint has no key-issuing endpoint. Upstream login JWTs last a hardcoded
60 hours (`ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 60` in flowsint-core
`core/auth.py`). When that expires, n8n, the task runners, and Open WebUI all
start getting 401 at once.

SPOTTER signs its own token of the same shape with `AUTH_SECRET` (already in
the machine secret tier). Flowsint accepts any HS256 JWT whose `sub` is an
existing account and whose `exp` is in the future
(`flowsint-api/app/api/deps.py`):

`{"sub": <FLOWSINT_ADMIN_EMAIL>, "exp": now + FLOWSINT_TOKEN_DAYS}`

`FLOWSINT_TOKEN_DAYS` defaults to **365** (plain config in `.env`).
`scripts/refresh_flowsint_token.py` and `scripts/rotate_flowsint_token.py`
mint that token (`scripts/flowsint_token.py`), verify it live against
`GET /api/investigations`, and only then store `FLOWSINT_API_KEY` in the
encrypted machine tier (`secrets/machine.sops.env`). If the live check fails
they fall back to password login (`/api/auth/token`), which still yields the
60-hour token. `--login` forces that path.

The value is baked into containers at **create** time. After a refresh:

```bash
sudo python3 scripts/refresh_flowsint_token.py
sudo ./spotter compose up -d --no-deps --force-recreate n8n task-runners open-webui
sudo ./spotter check-flowsint    # also: python3 scripts/refresh_flowsint_token.py --show-expiry
```

Bootstrap mints the long-lived token automatically. Optional systemd timer
(`sudo scripts/install_flowsint_rotation.sh`): checks every 12 hours and
renews when fewer than 7 days remain (`rotate_flowsint_token.py --renew-days 7`),
then recreates the same three containers. With the 365-day default this fires
about once a year. `FLOWSINT_ADMIN_EMAIL` lives in `.env`;
`FLOWSINT_ADMIN_PASSWORD` in the machine tier.
`/etc/spotter/flowsint-admin.env` can override either.

Trade-offs: anyone holding the token can act as that account until `exp`. The
only revocation is rotating `AUTH_SECRET`, which also ends every Flowsint
session — mint a new token afterwards. Re-check `deps.py` / `core/auth.py`
whenever `deployment/flowsint.lock` moves (extra claims, revocation, or an
issued-at check would break self-signed tokens). `./spotter check-flowsint`
catches a rejected token either way.

## 3. Enrich Domains and how clone findings flow

Landed in `985cf38`. Each additional Target Organization card has **ENRICH
DOMAIN** next to **Send URLs to Active**. It saves Objectives, then runs
Domain Recon (WF13) against that card's domains (parsed from the card's
domains, emails, and URLs), up to **5 per click** (`OBJ_ORG_ENRICH_MAX`).
Identity fields for the run are seeded from that card's name and email, not
the primary target. The primary Company Email **ENRICH DOMAIN** path is
unchanged. Live Analysis › Domain Recon keeps one cached record per domain
and shows a switcher when more than one has been enriched.

A finished Site Clone already feeds some, but not all, downstream flows:

| Destination | What arrives |
|---|---|
| Campaign sketch (`site_clone_ingest`) | Cloned site as a WebAsset (`{host} (clone)`); emails and names as `individual` nodes; secret-shaped JS hits as `credential` nodes (hash + mask only, never the raw value); JS endpoints as WebAssets (same-registrable also linked `FOUND_ON` to the clone and any existing `{domain} (web)` apex; external hosts stay separate, provenance `site-clone`, `deobfuscated` when recovered from JS); `generator=` meta as Technology |
| Prompt tab | Offline tree indexed into `company_site__<sketch_id>` (HTML/text, recovered JS, OCR). Inventory and `search_intel` also list finished clone jobs, so sketch-ingested and job-card findings are visible in chat. Ask the Company Website uses the clone and does not contact the target again |
| Active job card only (and campaign export) | Phones, HTML/JS comments, hidden form fields, documents, EXIF, links, sourcemaps, and other non-ingested categories |

### Known gaps (still true on current `dev`)

- **WF13 recons one domain per run.** The org-card loop issues one webhook
  call per domain (capped at five). There is no single WF13 request that
  enriches a list of domains.
- **Phones, comments, hidden fields, EXIF, and similar findings stay on the
  job card.** They are not graph nodes.
- **Ingested individuals are not auto-scored.** Newly written people and
  credentials show up in Targets / Dossier / Live Analysis only after a
  Targets refresh or a re-run of analysis.
- **No auto-enrich after a clone.** A finished job does not start Domain
  Recon or Enrich Domain.

## 4. Dev workflow conventions

- **`dev` is the testing branch.** Land work there. Open a PR to `main` only
  after the operator has validated the change on their host. Do not push
  directly to `main`.
- **Do not name third-party coding assistants or their vendors** in code,
  comments, commit messages, documentation, or any other file in this
  repository. That includes UI copy. The product must not advertise or depend
  on a particular assistant.
- **Secrets vs config.** `.env` holds configuration only. Credentials live in
  local SOPS + age tiers under `secrets/` (`machine.sops.env`,
  `vendors.sops.env`, `engagement.sops.env`), managed with
  `scripts/spotter_secret.py` / `spotter_env`. `.sops.yaml` and `secrets/`
  are install-local and gitignored. Never commit them or the age key
  (`$HOME/.config/sops/age/keys.txt`).
- **Compose** always through `./spotter compose …` or
  `scripts/spotter_compose.sh` (project `-p spotter`, Flowsint-first `-f`
  order, no `--project-directory`).
- **Workflows.** Editing a file in `n8n-workflows/` changes nothing on a
  running stack. Deploy with `scripts/deploy_workflow.sh <file>` or
  `--all`. The script imports, publishes only JSONs marked `active: true`,
  repairs publication pointers, and restarts n8n. Do not hand-import in the
  n8n UI. Bootstrap is the only install step that deploys new workflows on
  its own.
- **Frontend** is bind-mounted; hard-refresh the dashboard after HTML/JS
  edits. Rebuild `site-clone-api` / `site-clone-deobf` only when the sidecar
  image or its Python changes.
- **Graph work is sketch-scoped.** A wrong or empty sketch id often returns
  clean zeros rather than an error.
- **Client data stays local.** Sketches, ingest staging, clone trees, and
  `.env` hold engagement data. Do not ship it out or paste it into shared
  output unless asked.

### Tests

Offline unless a script says otherwise. Run the guard after workflow or
secret-handling changes; run the smoke that pins a fix before claiming the
fix works. See README "Validation Checks" for the full list.

```bash
python3 scripts/check_workflow_regressions.py

# Site Clone / token / Objectives (the recent work)
python3 scripts/smoke_site_clone.py
python3 scripts/smoke_site_rag.py
python3 scripts/smoke_flowsint_token.py
node scripts/smoke_frontend_active.js
node scripts/smoke_frontend_objectives.js
node scripts/smoke_frontend_gates.js
node scripts/smoke_frontend_notifications.js

# Broader frontend pack (jsdom, no browser, no stack)
node scripts/smoke_frontend_sort.js
node scripts/smoke_frontend_assets.js
# …and the other scripts/smoke_frontend_*.js files
```

`./spotter smoke` runs `scripts/smoke_postinstall.sh` against a live stack.
`./spotter doctor` is the Flowsint + n8n webhook + Site Clone container
preflight.

`e6a61c5` fixed the two frontend smokes that were failing on `dev`:
`smoke_frontend_gates.js` (DOMContentLoaded race left `#llmEndpoint` empty)
and `smoke_frontend_notifications.js` (comments about the login-page stamp
were treated as a regression). No other frontend smoke failures are recorded
on current `dev`; re-run the pack before merging to `main`.

## 5. Next steps

1. Close the gaps in §3: consider ingesting or otherwise surfacing job-card
   findings that never become graph nodes; refresh or re-score Targets when
   clone ingest writes individuals; optional auto-enrich (or a clear prompt)
   after a successful clone; if multi-domain enrich should be one WF13 run
   rather than a frontend loop, that is a workflow change, not just UI.
2. **Make Active more than cloning.** Site Clone is the first Active feature.
   Candidates for the same tab, under the same OPSEC envelope and caps:
   port scans, screenshots, and header/TLS checks. Not started; product
   choice of which to add is still open. Do not confuse this with existing
   Ingest-tab EyeWitness or nmap upload paths, which are offline artifact
   ingest, not Active-tab probing.
3. Re-run and fix any remaining frontend smoke failures before merge (none
   currently recorded after `e6a61c5`).
4. After the operator validates Site Clone, Enrich Domain, token rotation,
   and the smokes on their host, open a PR from `dev` to `main`. Do not
   merge until that local validation is done.

When an item above lands, update this file (and the "current as of" commit)
in the same change.
