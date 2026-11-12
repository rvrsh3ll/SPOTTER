# Installing SPOTTER

This is the install guide. `README.md` is the reference for how the system works
once it is running; you do not need it yet.

This guide follows the repository's current bootstrap path. The troubleshooting
table at the end is keyed by common symptoms; hardware figures are reference
configuration details, not minimums validated by a clean-host benchmark.

---

## Quickstart — zero to running in 5 commands

```bash
# 1. Clone and enter the repo
git clone <spotter-repo-url> spotter && cd spotter

# 2. Generate secrets (creates .env + encrypted tiers)
sudo deployment/setup-secrets.sh

# 3. Edit .env — set SPOTTER_LLM_TIER (local-large|local-small|remote|none)
#    For local-small, also set VLLM_MODEL and VLLM_MAX_MODEL_LEN
sudo nano .env

# 4. Bootstrap (interactive — asks for operator, Flowsint, and OWUI credentials)
sudo scripts/bootstrap.sh

# 5. Verify
python3 scripts/smoke_deploy.py --user <your-operator-name>
scripts/smoke_postinstall.sh
```

Open **https://spotter.localhost:5443** and log in. Done.

**Optional but recommended** — enable automatic Flowsint token rotation:
```bash
sudo scripts/install_flowsint_rotation.sh
```

**No GPU?** Set `SPOTTER_LLM_TIER=remote` or `none` in step 3. Everything except
AI analysis and the Prompt tab works without a model.

**First time seeing 4 logins?** See [§6 — The four separate logins](#6-the-four-separate-logins).

---

## 1. What you need

**A Linux host** with:

| | |
|---|---|
| Docker Engine + Compose v2 | `docker compose version` must print v2.x or later |
| `git`, `curl`, `jq`, `openssl`, `python3`, `sops`, `age-keygen` | required by bootstrap and encrypted-secret handling |
| Root access | the launcher mounts a RAM-only filesystem for decrypted secrets |
| Memory | no tested minimum is published; the current reference deployment host has 125 GiB |
| Disk | the default model alone downloads about 30-32 GB; reserve additional space for images, graph data, and backups; no tested minimum is published |

Use the official installation instructions for [Docker Engine](https://docs.docker.com/engine/install/),
[SOPS](https://github.com/getsops/sops), [age](https://github.com/FiloSottile/age),
and the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
when using a local model. Install the toolkit only after the host's NVIDIA driver
is working.

**A GPU is optional.** SPOTTER ingests, correlates and serves the graph with
`remote` or `none`; local inference requires a compatible NVIDIA GPU and the
VRAM needed by the selected model and context. These figures are planning
guidance, not a measured minimum for every workload.

You do **not** need any of the API keys (Shodan, Censys, BinaryEdge, Flare, FOFA,
SerpAPI, Tavily, GrayhatWarfare, NVD) or a C2 teamserver to stand the stack up.
Each one enables one feature and is inert when absent.

---

## 2. Get the code

SPOTTER does not contain the data tier. Neo4j, Postgres, Redis, the Flowsint API
and the Flowsint UI all live in a separate project, **Flowsint**, whose compose
file SPOTTER includes. The bootstrap clones it for you, at a pinned commit, and
applies the patches this repo carries — one of which closes a hole where the
Flowsint UI is reachable from the LAN without passing the SPOTTER login.

```bash
git clone <spotter-repo-url> spotter    # replace with wherever this repo is hosted
cd spotter
```

Clone it wherever you like. Nothing is tied to a particular path: every host path
is derived from the checkout's own location, and the bootstrap puts Flowsint in
`vendor/flowsint` **inside** this directory, so the whole stack is one directory
you can move, copy or back up as a unit.

The current first-install path requires root because the Compose launcher mounts
ramfs for decrypted secrets. Run setup and bootstrap from a root shell, with the
checkout readable and writable there. SOPS uses
`$HOME/.config/sops/age/keys.txt` for that account by default; set
`SOPS_AGE_KEY_FILE` in that root environment if the identity is stored elsewhere,
and use the same setting for later Compose commands. `sudo` may remove exported
variables; pass a custom path explicitly, for example:

```bash
sudo env SOPS_AGE_KEY_FILE=/secure/path/keys.txt deployment/setup-secrets.sh
sudo env SOPS_AGE_KEY_FILE=/secure/path/keys.txt scripts/bootstrap.sh
```

One rule if you edit `.env` by hand afterwards: every `*_DIR` value must be
**absolute**. Compose resolves a relative bind source against `vendor/flowsint`,
not this repo, and Docker creates a missing bind source instead of erroring — so a
relative value fails silently. `scripts/spotter_compose.sh` refuses to start on one.

---

## 3. Choose an LLM tier

Choose a tier before bootstrap. The default is `local-large`, so configure a
different tier before the first launch if the host does not have a suitable GPU.

| `SPOTTER_LLM_TIER` | Needs | What you get |
|---|---|---|
| `local-large` | NVIDIA GPU; reference deployment uses an RTX 6000 Ada (48 GB) | Default Qwen3.8-27B-FP8 with 49,152-token configured context; about 30-32 GB model download |
| `local-small` | NVIDIA GPU sized for the selected model and context | No smaller model is selected automatically. Set `VLLM_MODEL` and `VLLM_MAX_MODEL_LEN` together in `.env`. |
| `remote` | Nothing local | Uses an OpenAI-compatible endpoint you administer or are authorized to use. |
| `none` | Nothing | Everything except AI analysis and the Prompt tab. |

The reference deployment host currently has 125 GiB RAM and two RTX 6000 Ada
GPUs with about 48 GiB each. The default model uses one GPU; the optional
embedding profile defaults to GPU index 1. This is a reference configuration,
not a supported minimum. Other GPU/model/context combinations need their own
VRAM and KV-cache validation. The previous 8 GB RAM and 20 GB disk figures were
not validated. Allow for model cache, Docker images, and graph growth separately.
For `remote`, set `VLLM_URL` and `VLLM_API_KEY` in `.env`.

---

## 4. Configure and run the bootstrap

Seed `.env` and generate the local SOPS identity first, then select the tier.
For a GPU-less host, set `SPOTTER_LLM_TIER=remote` or `none` before bootstrap:

```bash
sudo deployment/setup-secrets.sh
sudo nano .env
sudo scripts/bootstrap.sh
```

Do not use `sudoedit` / `sudo -e` when the checkout lives under a user-writable
directory (for example `~/SPOTTER`). Modern sudo refuses that with
`editing files in a writable directory is not permitted`. Prefer `sudo nano .env`
(or another editor via `sudo`), or open a root shell (`sudo -i`), `cd` into the
checkout, and edit `.env` normally.

For `local-small`, set both `VLLM_MODEL` and `VLLM_MAX_MODEL_LEN`. For `remote`,
also set `VLLM_URL` and `VLLM_API_KEY`. Keep credential values out of published files.

It is idempotent — if it fails partway, fix the cause and run it again; it skips
what it already did. It will:

1. Generate every secret that must be unique to your install, into
   `secrets/machine.sops.env` (encrypted; `.env` itself holds configuration only).
2. Clone and patch Flowsint.
3. Build the task-runner image (a few minutes, once).
4. Start the stack.
5. **Ask you for a SPOTTER operator username and password.** This is the login for
   the dashboard itself. Nothing in a browser works before this exists — the auth
   gate covers the dashboard, n8n and the Flowsint UI alike.
6. **Ask you for a Flowsint account email and password.** It registers the account,
   mints an API token and stores it encrypted in `secrets/machine.sops.env`.
7. Create a fallback sketch.
8. Recreate the three containers that bake those values in.
9. Register the Flowsint custom node types and deploy every workflow in n8n-workflows/ (currently 32, including Site Clone).
10. **Ask you for an Open WebUI admin email and password**, then install the
    SPOTTER tools into it.

---

## 5. Check it worked

```bash
python3 scripts/smoke_deploy.py --user <your-operator-name>
scripts/smoke_postinstall.sh
```

Every line should read `PASS`. The post-install script checks all 4 login layers (SPOTTER portal, Flowsint API, Open WebUI, n8n), container health, vLLM model status (if local tier), and whether the Flowsint token rotation timer is active.

The `*.localhost` hostnames below resolve to `127.0.0.1` on
their own in any current browser/OS (RFC 6761) — no `/etc/hosts` edit needed. Open
**https://spotter.localhost:5443** and log in with the operator account from step 4. The
browser will warn once per hostname until Caddy's internal root CA is trusted:
```bash
sudo ./spotter trust-cert
# or: sudo scripts/trust_caddy_cert.sh
```

| Port | What |
|---|---|
| 5443 | Caddy TLS front door — everything below is reached through it, by hostname |
| spotter.localhost:5443 | Operator dashboard |
| n8n.spotter.localhost:5443 | n8n workflow editor — SPOTTER portal login, then n8n's own owner login |
| graph.spotter.localhost:5443 | Flowsint graph UI — same login |
| chat.spotter.localhost:5443 | Open WebUI chat — **its own** account |

---

## 6. The four separate logins

This catches everyone, so it is worth reading once:

| Login | Where it lives | How to change it |
|---|---|---|
| **SPOTTER portal** — the dashboard, n8n and Flowsint UI all sit behind it | `deployment/auth-data/auth.db` | first visit opens administrator setup if no account exists; later accounts are requested at `/register.html` and approved from the Admin tab, or `scripts/spotter_user.py` |
| **Flowsint account** — issues the API token | Flowsint's Postgres | Flowsint UI, then `scripts/refresh_flowsint_token.py` |
| **Open WebUI account** | `webui.db` in a Docker volume | Open WebUI's own Settings → Account |
| **n8n owner account** | n8n's own user DB in the `n8n_data` volume (or `SPOTTER_N8N_DATA` bind) | First open of the editor shows **Set up owner account** — pick an email and a password (≥8 chars, one capital letter, one number). After that you get n8n's normal login. Change the password in n8n Settings. The SPOTTER portal still gates access in front. |


n8n 1.0+ removed HTTP basic auth and `N8N_USER_MANAGEMENT_DISABLED`. The
current image (`n8nio/n8n:2.26.6`) always uses built-in user management, so a
fresh volume shows **Set up owner account** once. Compose may still set the
old `N8N_BASIC_AUTH_*` / `N8N_USER_MANAGEMENT_DISABLED` variables and
`setup-secrets.sh` may still generate `N8N_USER` / `N8N_PASSWORD`; those are
ignored by this n8n version and do not create or change the owner. Bootstrap
does not provision the owner for you today.

The dashboard's **Prompt tab has no login of its own.** Its "API key" is a token
that LLM CONFIG → Connect mints from the Open WebUI account.

`OWUI_ADMIN_EMAIL` (in `.env`) and `OWUI_ADMIN_PASSWORD` (in
`secrets/machine.sops.env`) are a **record** of the Open WebUI account, not
configuration that creates it. Editing them changes no
credential and no restart propagates them.

---

## 7. Running the stack afterwards

Always through the launcher, which supplies the project name, env file, profiles
and absolute paths that the stack needs and that are easy to get wrong by hand:

```bash
./spotter status
./spotter up
./spotter logs -f n8n

# Equivalent long form (also used by ./spotter under the hood):
# scripts/spotter_compose.sh ps
# scripts/spotter_compose.sh up -d
# scripts/spotter_compose.sh logs -f n8n
```

`./spotter` is a thin sudo wrapper for common actions (`up`, `down`, `status`,
`logs`, `smoke`, `trust-cert`, `bootstrap`, and `compose …` pass-through).

Two things that are not obvious:

- **Container environment is fixed when the container is created.** After editing
  a value in `.env`, a `restart` does nothing — the container must be recreated:
  `scripts/spotter_compose.sh up -d --no-deps --force-recreate n8n task-runners open-webui`
- **Workflows deploy with `scripts/deploy_workflow.sh`**, never by importing JSON
  through the n8n UI. The script also repairs the publication pointers, which a
  hand-import does not.

---

## 7b. Automatic Flowsint token rotation (recommended)

Flowsint's JWT token expires every ~60 hours. Without rotation, everything
Flowsint-related returns 401 after about 2.5 days. The rotation script
(`scripts/rotate_flowsint_token.py`) can run automatically via a systemd timer:

```bash
sudo scripts/install_flowsint_rotation.sh
```

This installs a systemd timer that checks the token every 12 hours and rotates
it if it expires within 24 hours. `bootstrap.sh` offers to install it, and stores
the Flowsint email (`FLOWSINT_ADMIN_EMAIL`, `.env`) and password
(`FLOWSINT_ADMIN_PASSWORD`, machine tier) it needs. `/etc/spotter/flowsint-admin.env`
(root-only, mode 600) can override either one.

Check status:

```bash
systemctl list-timers spotter-flowsint-rotation.timer
journalctl -u spotter-flowsint-rotation.service
```

Without the timer, you must rotate manually when you see 401s:

```bash
sudo python3 scripts/rotate_flowsint_token.py --force
```

---

## Flowsint API token lifetime

Flowsint has no API keys, and its login token lasts a hardcoded 60 hours
(`ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 60` in flowsint-core `core/auth.py`; no env var
changes it). Flowsint accepts any HS256 token signed with `AUTH_SECRET` whose `sub`
is an existing account and whose `exp` is in the future (`flowsint-api/app/api/deps.py`).
SPOTTER already holds `AUTH_SECRET` in its machine tier, so
`scripts/refresh_flowsint_token.py` now signs its own token, `{"sub": FLOWSINT_ADMIN_EMAIL,
"exp": now + FLOWSINT_TOKEN_DAYS}` (default **365 days**), checks it live against
`/api/investigations`, and only then stores it in `FLOWSINT_API_KEY` (encrypted tier).
If the live check fails it falls back to the password login; `--login` forces that.

```bash
sudo python3 scripts/refresh_flowsint_token.py           # mint + verify + store
sudo ./spotter compose up -d --no-deps --force-recreate n8n task-runners open-webui
sudo ./spotter check-flowsint                             # shows days left
```

Bootstrap does this automatically. The optional systemd timer still checks every 12h
but renews only when fewer than 7 days remain (`--renew-days`), i.e. about once a year.

Trade-offs:

* Anyone who obtains the token can act as that Flowsint account until it expires.
  The only revocation is rotating `AUTH_SECRET`, which also signs out every Flowsint
  session; mint a new token afterwards. Shorten `FLOWSINT_TOKEN_DAYS` if that matters.
* This relies on Flowsint's current token validation. When `deployment/flowsint.lock`
  moves to a new commit, re-check `flowsint-api/app/api/deps.py` and `core/auth.py`
  (extra claims, revocation lists, or an issued-at check would break self-signed tokens);
  `sudo ./spotter check-flowsint` catches a rejected token either way.

## Active tab / Site Clone

After bootstrap, rebuild the clone worker once if the image is not yet on the host:

```bash
sudo ./spotter compose up -d --build site-clone-api
```

Then open **Active** in the dashboard, paste or send a target URL, review the
caps, and click **Start clone**. Jobs appear in the list. If a job fails with
`Site Clone workflow not active` or n8n logs `The requested webhook "POST
site-clone" is not registered`, workflow 32 is not imported or not active —
the clone worker can be healthy and the webhook still missing. From the repo
root (this imports, activates, repairs publication pointers, and restarts n8n):

```bash
sudo ./scripts/deploy_workflow.sh n8n-workflows/32-site-clone.json
```

`sudo ./spotter doctor` flags the same gap. If a job fails with
`site-clone-api unreachable`, the worker container is not running. After a
clone (and optional JS deobfuscation), Tesseract OCRs images in the
sidecar when **OCR images** is on; findings are tagged `ocr=true` and the
text under `ocr/` is indexed with the rest of the tree. Rebuild
`site-clone-api` to pick up the Tesseract packages and the read-only
source-snippet route used by **View source** in Open findings. Refresh
workflow 32 so `action=source` and JS-endpoint ingest are live. A
finished clone is also indexed into the Prompt tab's company-site corpus
(the task-runners container now mounts `data/clones` read-only). Redeploy
Open WebUI tools so the *Ask the Company Website* hint names Site Clone:

```bash
sudo python3 scripts/setup_openwebui.py
```

Import or refresh workflow 32 with `sudo ./scripts/deploy_workflow.sh
n8n-workflows/32-site-clone.json` if that workflow is already on the host, then
recreate `n8n` / `task-runners` so they pick up the clones mount and
`SITE_CLONE_DATA`.

OPSEC DNS uses a user+mount namespace to bind-mount a per-job `resolv.conf`
(no `SYS_ADMIN`). The clone service is started with `apparmor:unconfined`
because docker-default AppArmor denies `mount(2)`. To confirm lookups are not
leaking through Docker DNS: with Respect OPSEC on, no proxy, and an
Infrastructure resolver selected, start a clone and check the job card shows
`DNS: <resolver>` (for example `DNS: 77.88.8.8`). Optionally:

```bash
sudo tcpdump -n -i docker0 udp port 53 or tcp port 53
```

while the clone runs — the *target* hostname should not appear. If a job fails
with "mount namespace not permitted", the host may have user namespaces
disabled; either enable them or check **Allow Docker DNS (leaks lookups)** as
an explicit override.

Live website crawling was removed from Domain Recon / Organization enrichment;
that card now points here. Domain Recon still makes one proxied request for the
homepage title.

## 8. Troubleshooting, by symptom

| What you see | What it is |
|---|---|
| **"Sketch provisioning failed" on a new campaign** (WF16: "could not resolve or create investigation") | n8n cannot list or create Flowsint investigations: the Flowsint API or Neo4j is down, or `FLOWSINT_API_KEY` is missing or expired. Run `sudo ./spotter check-flowsint` (also run automatically at the end of bootstrap). It checks from inside the n8n task-runners container, where WF16 runs, and prints PASS/FAIL with a fix for each item. Once it passes, press **Retry Provision** in the campaign panel; there is no need to recreate the campaign. |
| **WF16 / n8n logs show `NameResolutionError: Failed to resolve 'flowsint-api'`** | Your stored `FLOWSINT_API_URL` is the old default `http://flowsint-api:5001`. Flowsint names its API container `flowsint-api-prod` (port 5001). Fix it with `sudo python3 scripts/migrate_flowsint_url.py`, which rewrites the value in `.env` (`./spotter up` and bootstrap also do this automatically), then `sudo ./spotter compose up -d --no-deps --force-recreate api n8n task-runners open-webui`. `api` picks up the `flowsint-api` alias, so either name resolves. Confirm with `sudo ./spotter check-flowsint`, then press **Retry Provision**. |
| **"My campaigns disappeared"**, or the graph reads empty | Usually the Neo4j password. It is applied only when the data volume is first created; changing `NEO4J_PASSWORD` afterwards makes every client send a password the database does not have. The campaign read swallows the auth error and returns an empty list, so it looks like missing data. Check `scripts/spotter_compose.sh ps` for an unhealthy `neo4j`. |
| **Everything Flowsint-related returns 401 at once** | `FLOWSINT_API_KEY` expired. Run `sudo python3 scripts/refresh_flowsint_token.py` (mints a long-lived token, see below), then recreate `n8n task-runners open-webui`. `--show-expiry` reports the date; `sudo ./spotter check-flowsint` shows days left and warns under 14. |
| **A page loads but a panel shows zeros** | Almost always the sketch, not the data. Every graph query is scoped to the active campaign's sketch, and a wrong or empty sketch id returns clean zeros rather than an error. |
| **An ingest reports success but nothing appears** | Ingest can fail green. Unparseable input still reports success, and a wrong or empty sketch id returns clean zeros. Verify by counting nodes *and* their labels in the sketch. Oversize and password-protected uploads are rejected, not a green success. |
| **Upload refused, or the ack names a host command** | The file is over a cap in the Ingest tab limits table in `README.md`. The browser checks before any chunk is sent. A file over 4 GB never starts. A file over 1 GB is warned and not uploaded unless the operator stages it anyway; only then does the ack name the path and the matching `scripts/ingest_*.py` command. Do not raise `N8N_PAYLOAD_SIZE_MAX`. |
| **`spotter-ui` will not start** | Check `docker logs spotter-ui` — nginx.conf is templated by envsubst, so a bad `SPOTTER_DASHBOARD_HOST`/`SPOTTER_CADDY_PORT` value will fail the template render. |
| **Browser warns about an untrusted certificate on :5443** | Expected on first use of each hostname — Caddy's internal CA is self-signed. Trust it once: `docker exec spotter-caddy cat /data/caddy/pki/authorities/local/root.crt`. |
| **A code node dies with `ModuleNotFoundError`** on a module that is clearly allowlisted | The runner is mounting a different `n8n-task-runners.json` than you are reading. Check `SPOTTER_RUNNERS_CONFIG` is an absolute path. |
| **`restart` succeeds but nothing restarted** | Compose was run without `-p spotter`, so it found nothing under that project name and exited 0. Use the launcher. |
| **Open WebUI signup is refused** | An account already exists — only the first one can be created that way. Sign in instead. |
| **`setup_openwebui.py` fails to sign in** | Either the account has not been created yet (visit https://chat.spotter.localhost:5443 and sign up) or `OWUI_ADMIN_*` in `.env` no longer matches it. |
| **vLLM will not start / the engine dies** | On `local-small`, `VLLM_MAX_MODEL_LEN` is probably larger than the KV cache can hold. Read the "GPU KV cache size" line in `docker logs spotter-vllm` and set the window below it. |
| **`sudoedit .env` fails with "editing files in a writable directory is not permitted"** | Expected when the checkout is under a user-writable path such as `~/SPOTTER`. Use `sudo nano .env` (or another editor via `sudo`), or edit from a root shell instead. |
| **`fatal: destination path '.../vendor/flowsint' already exists and is not an empty directory`** | A previous interrupted clone left a partial Flowsint checkout. Remove it and re-run bootstrap: `sudo rm -rf vendor/flowsint` then `sudo scripts/bootstrap.sh`. Bootstrap also clears an incomplete checkout (present, but no `.git`) automatically. |

---

## 9. Before you put real data in it

SPOTTER is for authorized engagements under a documented Rule of Engagement, and
for intelligence-analysis education. See `## License & Usage` in `README.md`.

Two practical points:

- **Sketches, ingest staging and `.env` hold client data.** `.gitignore` covers the
  known paths, but it is your responsibility not to commit or share them.
- **Credentials are encrypted, the data is not.** The API keys and passwords live in
  `secrets/*.sops.env`, encrypted with SOPS + age, so a clone of this repo is complete
  but inert without the matching age key. That protects the *secrets*; it does nothing
  for the engagement graph, which sits in Neo4j in the clear unless the host itself has
  full-disk encryption. Check with `lsblk -o NAME,TYPE,FSTYPE | grep crypt` — if that
  prints nothing, there is no FDE, and a copy of the disk is a copy of the client data.
- **The age key is the one thing that must not travel with the repo.** It lives at
  `$HOME/.config/sops/age/keys.txt` (0600) by default for the account running setup. Back it up separately from any
  archive that contains the encrypted tiers; a backup holding both protects nothing.
- **`clear-graph` is not a dry run**, and there is no Neo4j backup on a default
  install. Take your own before you experiment.

---

## 10. Teardown — securely uninstalling SPOTTER

To completely remove SPOTTER from a host, run these steps in order. **This is destructive and irreversible.**

### Stop and remove containers

```bash
# Stop all SPOTTER containers
sudo scripts/spotter_compose.sh down

# Remove all containers, networks, and images
sudo docker compose -p spotter -f deployment/docker-compose.n8n.yml down --volumes --remove-orphans
sudo docker volume rm spotter_vllm_model_cache 2>/dev/null || true
```

### Remove the systemd timer (if installed)

```bash
sudo systemctl disable --now spotter-flowsint-rotation.timer
sudo rm /etc/systemd/system/spotter-flowsint-rotation.{service,timer}
sudo systemctl daemon-reload
```

### Remove data directories

```bash
# Engagement data (Neo4j, Postgres, screenshots, ingest staging)
sudo rm -rf data/

# Encrypted secrets (SOPS tiers)
sudo rm -rf secrets/

# Vendor checkout (Flowsint)
sudo rm -rf vendor/

# Cache and artifacts
sudo rm -rf .spotter-cache/ screenshots/ sharphound-drops/ deployment/auth-data/

# Environment config
sudo rm -f .env
```

### Remove the Caddy CA certificate (if trusted system-wide)

Installed by `sudo ./spotter trust-cert` (or `scripts/trust_caddy_cert.sh`):

```bash
# On Nobara/Fedora:
sudo rm /etc/pki/ca-trust/source/anchors/spotter-caddy-root.crt
sudo update-ca-trust

# On Debian/Ubuntu/Kali:
# sudo rm /usr/local/share/ca-certificates/spotter-caddy-root.crt
# sudo update-ca-certificates
```

### Remove the SOPS age key (⚠️ back up first if you plan to reinstall)

```bash
# The age key decrypts secrets/*.sops.env. Without it, encrypted secrets are unrecoverable.
# Back up before deleting if you might reinstall or migrate:
# cp ~/.config/sops/age/keys.txt ~/age-key-backup.txt

rm -f ~/.config/sops/age/keys.txt
```

### Remove the repository (optional)

```bash
cd ..
sudo rm -rf spotter/
```

### Verification

After teardown, confirm nothing remains:

```bash
sudo docker ps -a | grep spotter    # should be empty
sudo docker volume ls | grep spotter  # should be empty
ls -la ~/.config/sops/age/          # keys.txt should be gone
```

**What this does NOT remove:**
- Host packages (Docker, SOPS, age, NVIDIA drivers) — uninstall via your package manager
- Browser localStorage/cache for `*.localhost:5443` — clear manually
- Any backups you made (age key, database dumps)
- Full-disk encryption keys (if you set up FDE)

---

## 11. Trained model (optional)

SPOTTER includes a fine-tuned LoRA adapter for Qwen2.5-7B-Instruct that improves performance on OSINT analysis, AD attack paths, and SPOTTER tool-calling. The adapter is distributed as a release artifact, not in the git repo.

### Install the trained model

```bash
# When a release asset exists, or you have a tarball/URL:
scripts/install_trained_model.sh /path/to/spotter-model-v1.tar.gz
# scripts/install_trained_model.sh https://…/spotter-model-v1.tar.gz

# Or copy an adapter directory you already built:
# mkdir -p models && cp -a /path/to/lora models/spotter-qwen25-7b-lora
```

No GitHub release currently publishes `spotter-model-v1.tar.gz`. Running the
script with no arguments exits with a clear message instead of hitting a 404.
When you have a tarball or adapter directory, the script installs it to
`models/spotter-qwen25-7b-lora/`.

### Enable the trained model

After installation, update `.env`:

```bash
sudo nano .env
```

Set:
```
VLLM_MODEL=Qwen/Qwen2.5-7B-Instruct
VLLM_QUANTIZATION=fp8
VLLM_GPU_MEMORY_UTILIZATION=0.92
VLLM_ENABLE_LORA=true
VLLM_LORA_MODULES=/home/user/SPOTTER/models/spotter-qwen25-7b-lora
```

Then recreate vLLM:

```bash
sudo scripts/spotter_compose.sh up -d --no-deps --force-recreate vllm
```

The compose file consumes both variables (wired 2026-10-23): the adapter directory is bind-mounted read-only at the same absolute path, and vLLM serves the module under its **basename** — `spotter-qwen25-7b-lora` — which is the model id to enter in the Prompt tab's MODEL field (LLM CONFIG) or select in Open WebUI. `VLLM_ENABLE_LORA` must be exactly `true` (or `1`/`yes`); any other value, including `false`, leaves vLLM's command line untouched.

### Serving recipe (verified 2026-10-24 on a 12 GB RTX 5070)

The adapter serves on the **fp16 `Qwen/Qwen2.5-7B-Instruct` base with on-the-fly fp8 quantization** (the `.env` block above): weights ~7.6 GB, leaving a 36,288-token KV cache — 1.11x concurrency at the 32768 window. vLLM then serves two model ids: the base and **`spotter-qwen25-7b-lora`** (the adapter directory's basename), which is what the Prompt tab's MODEL field selects. Plain fp16 does not fit the card; fp8 is what makes base + adapter + 32k window fit together.

**The trap that misdiagnosed this for a day:** invoking `python3 -m vllm.entrypoints.openai.api_server <model>` directly — as this compose file did until 2026-10-24 — parses the positional into `model_tag`, and only the `vllm serve` subcommand copies it onto `model` (`entrypoints/cli/serve.py`). The engine silently falls back to vLLM's built-in default **`Qwen/Qwen3-0.6B`**, comes up **healthy**, and serves that. Every LoRA load then failed with `add_lora ... size of tensor a (1024) must match tensor b (3584)`, which reads like an adapter/quantization incompatibility but is just the 0.6B default's hidden size meeting the adapter's. The compose service now execs `vllm serve`; if the engine-init log line ever names a model you did not configure, check this first.

### What the model knows

See [TRAINING_QUERIES.md](TRAINING_QUERIES.md) for an operator playbook of the queries and scenarios the trained model handles well.

The adapter was trained on 64 pairs covering:
- **OSINT methodology** — breach analysis, domain recon, social media enrichment, certificate transparency
- **AD attack paths** — kerberoasting, AS-REP roasting, delegation abuse, ADCS escalation, DCSync
- **SPOTTER tool-calling** — correct tool names, parameter shapes, campaign scoping

Training: Unsloth QLoRA, rank 16, 4-bit, 15 epochs, final loss 0.02088. Base model: Qwen2.5-7B-Instruct.

### Without the trained model

SPOTTER works fine with the base Qwen2.5-7B-Instruct (or any compatible model). The trained adapter is an optional enhancement. If you skip it, the LLM will still work but may be less accurate on SPOTTER-specific tasks and tool-calling.
