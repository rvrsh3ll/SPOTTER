#!/usr/bin/env python3
"""Rewrite a stored FLOWSINT_API_URL that points at a host no container answers to.

Older SPOTTER configs shipped FLOWSINT_API_URL=http://flowsint-api:5001, but
Flowsint's prod compose names the API container flowsint-api-prod and gives it no
alias, so every container lookup of `flowsint-api` failed DNS and campaign sketch
provisioning reported "could not resolve or create investigation".

Idempotent: a value that is unset, already correct, or deliberately customised
is left alone. Prints one line describing what it did. Never prints secrets
(FLOWSINT_API_URL is ordinary config).

    python3 scripts/migrate_flowsint_url.py [--check]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

OLD = {"http://flowsint-api:5001", "http://flowsint-api:5001/"}
NEW = "http://flowsint-api-prod:5001"


def main() -> int:
    check = "--check" in sys.argv[1:]
    try:
        import spotter_env
        current = (spotter_env.get("FLOWSINT_API_URL") or "").strip()
    except Exception as e:
        print(f"migrate_flowsint_url: could not read SPOTTER config ({e}); skipped")
        return 0
    if current not in OLD:
        print(f"FLOWSINT_API_URL ok ({current or 'unset; compose default ' + NEW})")
        return 0
    if check:
        print(f"FLOWSINT_API_URL={current} is stale; run: sudo python3 scripts/migrate_flowsint_url.py")
        return 1
    path = spotter_env.set_value("FLOWSINT_API_URL", NEW)
    print(f"FLOWSINT_API_URL migrated {current} -> {NEW} in {path}")
    print("recreate the containers that read it: "
          "./spotter compose up -d --no-deps --force-recreate n8n task-runners open-webui")
    return 0


if __name__ == "__main__":
    sys.exit(main())
