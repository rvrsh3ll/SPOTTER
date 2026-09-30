# Installing SPOTTER

This is the install guide. `README.md` is the reference for how the system works
once it is running; you do not need it yet.

This guide follows the repository's current bootstrap path. The troubleshooting
table at the end is keyed by common symptoms; hardware figures are reference
configuration details, not minimums validated by a clean-host benchmark.

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

You do **not** need any of the API keys (Shodan, Flare, FOFA, SerpAPI, Tavily,
GrayhatWarfare, NVD) or a C2 teamserver to stand the stack up. Each one enables
one feature and is inert when absent.

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
sudoedit .env
sudo scripts/bootstrap.sh
```

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
9. Register the Flowsint custom node types and deploy all 29 workflows.
10. **Ask you for an Open WebUI admin email and password**, then install the
    SPOTTER tools into it.

---

## 5. Check it worked

```bash
python3 scripts/smoke_deploy.py --user <your-operator-name>
```

Every line should read `PASS`. The `*.localhost` hostnames below resolve to `127.0.0.1` on
their own in any current browser/OS (RFC 6761) — no `/etc/hosts` edit needed. Open
**https://spotter.localhost:5443** and log in with the operator account from step 4. The
browser will warn once per hostname until Caddy's internal root CA is trusted:
```bash
docker exec spotter-caddy cat /data/caddy/pki/authorities/local/root.crt
```

| Port | What |
|---|---|
| 5443 | Caddy TLS front door — everything below is reached through it, by hostname |
| spotter.localhost:5443 | Operator dashboard |
| n8n.spotter.localhost:5443 | n8n workflow editor — same login |
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
| **n8n basic auth** | `N8N_USER` in `.env`; `N8N_PASSWORD` in `secrets/machine.sops.env` | `scripts/spotter_secret.py set N8N_PASSWORD`, recreate `n8n` |

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
scripts/spotter_compose.sh ps
scripts/spotter_compose.sh up -d
scripts/spotter_compose.sh logs -f n8n
```

Two things that are not obvious:

- **Container environment is fixed when the container is created.** After editing
  a value in `.env`, a `restart` does nothing — the container must be recreated:
  `scripts/spotter_compose.sh up -d --no-deps --force-recreate n8n task-runners open-webui`
- **Workflows deploy with `scripts/deploy_workflow.sh`**, never by importing JSON
  through the n8n UI. The script also repairs the publication pointers, which a
  hand-import does not.

---

## 8. Troubleshooting, by symptom

| What you see | What it is |
|---|---|
| **"My campaigns disappeared"**, or the graph reads empty | Usually the Neo4j password. It is applied only when the data volume is first created; changing `NEO4J_PASSWORD` afterwards makes every client send a password the database does not have. The campaign read swallows the auth error and returns an empty list, so it looks like missing data. Check `scripts/spotter_compose.sh ps` for an unhealthy `neo4j`. |
| **Everything Flowsint-related returns 401 at once**, a few days in | `FLOWSINT_API_KEY` expired. It is a login token, not a permanent key — Flowsint's default lifetime is about 2.5 days. Run `python3 scripts/refresh_flowsint_token.py`, then recreate the three containers. Check it any time with `--show-expiry`. |
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
