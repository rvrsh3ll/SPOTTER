#!/usr/bin/env python3
"""Network-less JavaScript deobfuscation worker for Site Clone.

Intended to run as the site-clone-deobf compose service
(network_mode: none). It shares the clone volume with site-clone-api
and processes jobs dropped under <job>/deobf-queue/.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get("SPOTTER_SCRIPTS_DIR") or "/data/scripts")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from site_clone_deobfuscate import worker_main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(worker_main())
