#!/usr/bin/env bash
# Install the trained SPOTTER LoRA adapter for use with vLLM.
#
# Usage:
#   scripts/install_trained_model.sh [RELEASE_URL_OR_TARBALL]
#
# If an argument is provided it may be an http(s) URL or a local .tar.gz path.
# If no argument is provided, the script looks for a GitHub release asset named
# spotter-model-v1.tar.gz. When no release asset exists (the public repo does
# not currently publish one), the script exits with a clear message instead of
# inventing a download URL that 404s.
#
# The adapter is installed to $SPOTTER_HOME/models/spotter-qwen25-7b-lora/
#
# After installation, update .env to use the trained model:
#   VLLM_MODEL=Qwen/Qwen2.5-7B-Instruct      (fp16 base — see the recipe note below)
#   VLLM_QUANTIZATION=fp8
#   VLLM_GPU_MEMORY_UTILIZATION=0.92         (12 GB card)
#   VLLM_ENABLE_LORA=true
#   VLLM_LORA_MODULES=/home/user/SPOTTER/models/spotter-qwen25-7b-lora
#       (the adapter DIRECTORY — vLLM serves it under its basename; see
#        deployment/docker-compose.llm.yml, wired 2026-10-23)
# Then recreate vLLM: sudo scripts/spotter_compose.sh up -d --no-deps --force-recreate vllm
#
# NOTE (the model_tag trap): the compose service must exec `vllm serve`, NOT
# `python3 -m vllm.entrypoints.openai.api_server`. In vLLM v0.17.0 the module
# form parses the model positional into `model_tag` and never copies it onto
# `model`, so the engine silently serves vLLM's default Qwen/Qwen3-0.6B while
# looking healthy — and every add_lora then fails with a 1024-vs-3584 shape
# error that mimics an adapter incompatibility. See INSTALL.md §11.
#
# Alternative when no release is published: copy an existing adapter directory:
#   cp -a ~/spotter-train/out/spotter-5070/lora "$SPOTTER_HOME/models/spotter-qwen25-7b-lora"

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL_DIR="$ROOT_DIR/models/spotter-qwen25-7b-lora"
ASSET_NAME="spotter-model-v1.tar.gz"

BOLD=$'\033[1m'; RESET=$'\033[0m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
log()  { echo "[install-model] $*"; }
warn() { echo "[install-model] ${YELLOW}WARN${RESET}: $*" >&2; }
die()  { echo "[install-model] ERROR: $*" >&2; exit 1; }

skip_no_source() {
    # Exit non-zero so callers that care notice, but with an actionable path
    # rather than a raw HTTP 404 from a guessed URL.
    cat >&2 <<MSG
[install-model] ERROR: no trained-model release asset is available to download.

  This repository does not currently publish a GitHub release containing
  ${ASSET_NAME}. Refusing to guess a URL that would 404.

  Provide a source explicitly:

    scripts/install_trained_model.sh /path/to/${ASSET_NAME}
    scripts/install_trained_model.sh https://example.invalid/path/${ASSET_NAME}

  Or copy an adapter directory you already have:

    mkdir -p "$ROOT_DIR/models"
    cp -a /path/to/lora "$MODEL_DIR"

  The trained adapter is optional — SPOTTER runs with the base model without it.
  See INSTALL.md section 11.
MSG
    exit 1
}

resolve_source() {
    if [[ $# -ge 1 && -n "${1:-}" ]]; then
        printf '%s' "$1"
        return 0
    fi

    local url=""
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        url="$(gh release view --repo rvrsh3ll/SPOTTER --json assets \
            --jq ".assets[] | select(.name==\"${ASSET_NAME}\") | .url" 2>/dev/null || true)"
    fi

    if [[ -z "$url" ]]; then
        # Probe the releases API once; do not construct a fake tag URL.
        local api_json="" http_code=""
        http_code="$(curl -sS -o /tmp/spotter-releases.$$ -w '%{http_code}' \
            https://api.github.com/repos/rvrsh3ll/SPOTTER/releases/latest || true)"
        if [[ "$http_code" == "200" ]]; then
            api_json="$(cat /tmp/spotter-releases.$$)"
            url="$(printf '%s' "$api_json" | ASSET_NAME="$ASSET_NAME" python3 -c '
import json, os, sys
data = json.load(sys.stdin)
name = os.environ["ASSET_NAME"]
for a in data.get("assets") or []:
    if a.get("name") == name:
        print(a.get("browser_download_url") or "")
        break
' 2>/dev/null || true)"
        fi
        rm -f /tmp/spotter-releases.$$
    fi

    if [[ -z "$url" ]]; then
        return 1
    fi
    printf '%s' "$url"
}

SOURCE="$(resolve_source "$@" || true)"
if [[ -z "${SOURCE:-}" ]]; then
    skip_no_source
fi

TMPFILE="$(mktemp /tmp/spotter-model-XXXXXX.tar.gz)"
trap 'rm -f "$TMPFILE"' EXIT

if [[ -f "$SOURCE" ]]; then
    log "Using local tarball: $SOURCE"
    cp -f "$SOURCE" "$TMPFILE"
elif [[ "$SOURCE" == http://* || "$SOURCE" == https://* ]]; then
    log "Downloading trained model from: $SOURCE"
    if command -v curl >/dev/null 2>&1; then
        # Show HTTP failures clearly (no silent 404).
        http_code="$(curl -sS -L -o "$TMPFILE" -w '%{http_code}' "$SOURCE" || true)"
        if [[ "$http_code" != "200" ]]; then
            die "Download failed (HTTP ${http_code:-unknown}) from $SOURCE"
        fi
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$TMPFILE" "$SOURCE" || die "Download failed from $SOURCE"
    else
        die "Neither curl nor wget found"
    fi
else
    die "Not a local file or http(s) URL: $SOURCE"
fi

if ! tar -tzf "$TMPFILE" >/dev/null 2>&1; then
    die "File is not a valid gzipped tarball"
fi

log "Extracting to $MODEL_DIR"
mkdir -p "$ROOT_DIR/models"
rm -rf "$MODEL_DIR"
tar -xzf "$TMPFILE" -C "$ROOT_DIR/models"

# The tarball contains lora/ directory, rename it
if [[ -d "$ROOT_DIR/models/lora" ]]; then
    mv "$ROOT_DIR/models/lora" "$MODEL_DIR"
fi

if [[ ! -f "$MODEL_DIR/adapter_config.json" ]]; then
    die "Installation failed — adapter_config.json not found under $MODEL_DIR"
fi

log "${GREEN}ok${RESET} Model installed to $MODEL_DIR"
log ""
log "To use the trained model, update .env:"
log "  VLLM_ENABLE_LORA=true"
log "  VLLM_LORA_MODULES=$MODEL_DIR"
log ""
log "Then recreate vLLM:"
log "  sudo scripts/spotter_compose.sh up -d --no-deps --force-recreate vllm"
