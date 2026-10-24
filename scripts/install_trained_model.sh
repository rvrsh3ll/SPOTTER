#!/usr/bin/env bash
# Install the trained SPOTTER LoRA adapter for use with vLLM.
#
# Usage:
#   scripts/install_trained_model.sh [RELEASE_URL]
#
# If RELEASE_URL is not provided, downloads from the latest GitHub release.
# The adapter is installed to $SPOTTER_HOME/models/spotter-qwen25-7b-lora/
#
# After installation, update .env to use the trained model:
#   VLLM_MODEL=Qwen/Qwen2.5-7B-Instruct-AWQ
#   VLLM_ENABLE_LORA=true
#   VLLM_LORA_MODULES=/home/user/SPOTTER/models/spotter-qwen25-7b-lora
#       (the adapter DIRECTORY — vLLM serves it under its basename; see
#        deployment/docker-compose.llm.yml, wired 2026-10-23)
# Then recreate vLLM: sudo scripts/spotter_compose.sh up -d --no-deps --force-recreate vllm
#
# NOTE: vLLM v0.17.0 cannot load this adapter onto the AWQ base (shape
# mismatch in vLLM's LoRA-on-AWQ packing) — see INSTALL.md §11 "Known
# limitation" before enabling.
#
# Where the GitHub repo is private and the release download 404s, pass a
# release-asset URL as $1, or copy an existing adapter directory instead:
#   cp -a ~/spotter-train/out/spotter-5070/lora "$SPOTTER_HOME/models/spotter-qwen25-7b-lora"

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL_DIR="$ROOT_DIR/models/spotter-qwen25-7b-lora"

BOLD=$'\033[1m'; RESET=$'\033[0m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
log()  { echo "[install-model] $*"; }
warn() { echo "[install-model] ${YELLOW}WARN${RESET}: $*" >&2; }
die()  { echo "[install-model] ERROR: $*" >&2; exit 1; }

# Determine download URL
if [[ $# -ge 1 ]]; then
    URL="$1"
else
    # Try to get latest release URL from GitHub API
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        URL=$(gh release view --repo rvrsh3ll/SPOTTER --json assets --jq '.assets[] | select(.name=="spotter-model-v1.tar.gz") | .url' 2>/dev/null || true)
    fi
    
    if [[ -z "${URL:-}" ]]; then
        # Fallback: construct URL from latest release tag
        TAG=$(curl -sf https://api.github.com/repos/rvrsh3ll/SPOTTER/releases/latest 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || echo "v1.0.0-model")
        URL="https://github.com/rvrsh3ll/SPOTTER/releases/download/$TAG/spotter-model-v1.tar.gz"
    fi
fi

log "Downloading trained model from: $URL"

# Download to temp file
TMPFILE=$(mktemp /tmp/spotter-model-XXXXXX.tar.gz)
trap 'rm -f "$TMPFILE"' EXIT

if command -v curl >/dev/null 2>&1; then
    curl -fL -o "$TMPFILE" "$URL" || die "Download failed"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$TMPFILE" "$URL" || die "Download failed"
else
    die "Neither curl nor wget found"
fi

# Verify it's a valid tarball
if ! tar -tzf "$TMPFILE" >/dev/null 2>&1; then
    die "Downloaded file is not a valid tarball"
fi

# Extract
log "Extracting to $MODEL_DIR"
mkdir -p "$ROOT_DIR/models"
rm -rf "$MODEL_DIR"
tar -xzf "$TMPFILE" -C "$ROOT_DIR/models"

# The tarball contains lora/ directory, rename it
if [[ -d "$ROOT_DIR/models/lora" ]]; then
    mv "$ROOT_DIR/models/lora" "$MODEL_DIR"
fi

# Verify
if [[ ! -f "$MODEL_DIR/adapter_config.json" ]]; then
    die "Installation failed — adapter_config.json not found"
fi

log "${GREEN}✓${RESET} Model installed to $MODEL_DIR"
log ""
log "To use the trained model, update .env:"
log "  VLLM_ENABLE_LORA=true"
log "  VLLM_LORA_MODULES=$MODEL_DIR"
log ""
log "Then recreate vLLM:"
log "  sudo scripts/spotter_compose.sh up -d --no-deps --force-recreate vllm"
