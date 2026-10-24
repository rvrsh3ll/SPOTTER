# SPOTTER Open Issues

Actionable product and test work confirmed against the repository on 2026-09-26. Fixed incident reports and host-specific debugging notes are intentionally not retained here.

## TODO — publish the trained-model GitHub release

`INSTALL.md` §11 documents `scripts/install_trained_model.sh`, which downloads `spotter-model-v1.tar.gz` from the latest GitHub release — but no release exists yet (`releases/latest` → 404), so the documented install path fails on every fresh host. Blocked on interactive GitHub auth (`gh` is not logged in on the host; no token in the sops tiers).

Staged and ready (2026-10-24):

- Asset: `~/spotter-train/out/spotter-model-v1.tar.gz` — 63 MB, `lora/` layout that the install script renames to `models/spotter-qwen25-7b-lora/`; content-scanned clean (boilerplate adapter card, no credentials, no engagement data).
- sha256: `1b31fa2d25ce6ce5cec263e76cc4612a349ff1c360f8d5cc2495494463bb955a`

Publish (tag and asset name are load-bearing — the install script resolves `releases/latest` and selects the asset by exact name):

```bash
gh auth login
gh release create v1.0.0-model ~/spotter-train/out/spotter-model-v1.tar.gz \
  --repo rvrsh3ll/SPOTTER \
  --title "SPOTTER trained model v1 — Qwen2.5-7B-Instruct LoRA adapter"
```

(or drag-drop at https://github.com/rvrsh3ll/SPOTTER/releases/new with tag `v1.0.0-model` and asset name `spotter-model-v1.tar.gz`.)

Verify: `curl -s https://api.github.com/repos/rvrsh3ll/SPOTTER/releases/latest | jq '.tag_name, .assets[].name'`, then a fresh `scripts/install_trained_model.sh` run lands `models/spotter-qwen25-7b-lora/adapter_config.json`.

Note: the repo is public — publishing makes the adapter world-downloadable. That is the intended distribution model (2026-10-21 decision); re-affirm before uploading.
