"""
Parse EyeWitness (RedSiege fork) web-recon output into Flowsint nodes/edges.

EyeWitness screenshots web endpoints and writes, per run, an output directory
zipped for upload:

    report*.html   Requests.csv   ew.db   screens/*.png   source/*.txt

`Requests.csv` is the only flat, per-target export (ew.db stores pickled Python
objects and is not a clean ingest target), so it is the record source here. Its
columns, verbatim (note the leading space before "Source Path"):

    Protocol,Port,Domain,URL,Resolved,Request Status,Title,Category,
    Default Creds,Screenshot Path, Source Path

Each row becomes one built-in `Website` node (keyed on its URL, which is also its
nodeLabel — so re-ingesting a run updates rather than duplicates). When a row's
`Resolved` value is an IP, an `Ip` node is created and joined with a `RESOLVES_TO`
edge, reusing the label _parse_nmap already writes so web endpoints share the host
anchor with nmap/Nessus and become joinable to AD hosts by IP later.

Screenshots are NOT stored in the graph — the runner sandbox has no image library
to thumbnail with, and full-res PNGs would bloat Neo4j. Instead each PNG is copied
to `<screenshots_dir>/<sketch_id>/` (a host dir served, auth-gated, at /screenshots/)
and the node carries the relative URL.

Gotchas handled here:
  * The screenshot PNG filename (EyeWitness `sanitize_filename`) differs from the
    page-source filename, and error rows point `Screenshot Path` at a file that was
    never written — so the PNG is located by the basename of the CSV `Screenshot
    Path` column against the zip's `screens/` members, and simply skipped if absent.
  * `Default Creds` may contain embedded newlines (multiple signatures joined), so
    the CSV must be read with a real RFC-4180 parser.
  * `Website.url` is a required, HttpUrl-validated field — a node missing/failing it
    would 500 the whole sketch on read, so rows without a usable http(s) URL are
    dropped with an error rather than emitted.

This module is reached only through upload_router (WF06's Parse node imports
upload_router, not this file), so it does not need a runner import-allowlist entry.
It also runs on the host for scripts/ingest_eyewitness.py. It avoids getattr/hasattr,
which the n8n Python task-runner sandbox does not provide.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple

# Categories EyeWitness assigns that are worth flagging for an operator: management
# interfaces, embedded devices and virtualization consoles are classic footholds.
# A default-credential match flags a node high-value on its own, independent of this.
HIGH_VALUE_CATEGORIES = frozenset({
    "highval", "idrac", "printer", "camera", "nas", "voip",
    "virtualization", "kvm", "netdev", "infrastructure",
})

# Members that identify a zip as EyeWitness output. Any one is sufficient.
_EW_MEMBER_MARKERS = ("ew.db", "requests.csv")
_SCREENS_PREFIX = "screens/"

_MAX_ROWS = 20000  # a defensive ceiling; a real web sweep is far smaller


def is_eyewitness_zip(data: bytes) -> bool:
    """True when `data` is a zip carrying EyeWitness's characteristic members."""
    if data[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception:
        return False
    for n in names:
        base = os.path.basename(n).lower()
        if base in _EW_MEMBER_MARKERS:
            return True
        # a screens/ directory of PNGs is the other tell
        norm = n.replace("\\", "/").lower()
        if _SCREENS_PREFIX in norm and norm.endswith(".png"):
            return True
    return False


def _norm_header(cols: List[str]) -> Dict[str, int]:
    """Map normalized header names → column index (handles the ' Source Path' space)."""
    idx: Dict[str, int] = {}
    for i, c in enumerate(cols):
        key = str(c or "").strip().lower()
        if key and key not in idx:
            idx[key] = i
    return idx


def _cell(row: List[str], idx: Dict[str, int], name: str) -> str:
    i = idx.get(name)
    if i is None or i >= len(row):
        return ""
    return str(row[i] or "").strip()


def _screenshot_members(zf: zipfile.ZipFile) -> Dict[str, str]:
    """basename(lower) → member name, for every PNG under a screens/ directory."""
    out: Dict[str, str] = {}
    for n in zf.namelist():
        norm = n.replace("\\", "/")
        low = norm.lower()
        if _SCREENS_PREFIX in low and low.endswith(".png"):
            out.setdefault(os.path.basename(norm).lower(), n)
    return out


def _safe_shot_name(url: str) -> str:
    """A deterministic, filesystem- and URL-safe screenshot name for a URL.

    Stable across re-ingest (so the node's screenshot_url stays valid) and
    collision-free per URL. Mirrors the relative-path charset the frontend's
    safeShotUrl() accepts.
    """
    stripped = re.sub(r"^https?://", "", url.strip(), flags=re.IGNORECASE)
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", stripped)[:180].strip("._-") or "shot"
    return name + ".png"


class EyewitnessResult:
    """Symmetric with the nessus/cloudschism parsers: nodes/edges + report + errors."""

    def __init__(self) -> None:
        self.nodes: List[dict] = []
        self.edges: List[dict] = []
        self.errors: List[str] = []
        self.report: Dict[str, Any] = {
            "hosts": 0,
            "with_screenshot": 0,
            "with_default_creds": 0,
            "high_value": 0,
            "by_category": {},
        }

    def to_flowsint_batch(self) -> Tuple[List[dict], List[dict]]:
        return self.nodes, self.edges

    def summary(self) -> Dict[str, Any]:
        return dict(self.report)


_DEFAULT_PORT = {"http": "80", "https": "443"}


def _synth_url(protocol: str, domain: str, port: str) -> str:
    """Reconstruct an http(s) URL from the Protocol/Domain/Port columns of the
    older EyeWitness export that carries no ready-made URL column. The port is
    only appended when non-default, mirroring how EyeWitness names its files."""
    domain = (domain or "").strip()
    if not domain:
        return ""
    proto = (protocol or "").strip().lower()
    port = (port or "").strip()
    if proto not in ("http", "https"):
        proto = "https" if port == "443" else "http"
    if port and port != _DEFAULT_PORT[proto]:
        return f"{proto}://{domain}:{port}/"
    return f"{proto}://{domain}/"


def _emit_rows(
    csv_text: str,
    sketch_id: Optional[str],
    shot_dir: Optional[str],
    shot_names: set,
    read_shot,           # (member_key) -> bytes, or None
    res: EyewitnessResult,
) -> None:
    """Turn Requests.csv rows into Website (+ Ip) nodes; copy screenshots.

    `shot_names` is the set of available screenshot basenames (lowercased); a row's
    PNG is located by the basename of its `Screenshot Path` column. `read_shot`
    returns the bytes for a chosen basename (from a zip member or a file). When
    `shot_dir` is a writable path, each located PNG is written there and the node
    carries the relative /screenshots/ URL; otherwise the node still lands without
    an image.
    """
    reader = csv.reader(io.StringIO(csv_text))
    try:
        header = next(reader)
    except StopIteration:
        res.errors.append("Requests.csv is empty.")
        return
    idx = _norm_header(header)
    # Newer EyeWitness exports carry a ready-made `URL` column. Older/other builds
    # export only Protocol,Port,Domain (+ Screenshot Path / Source Path) and leave
    # the URL to be reconstructed. Accept either, as long as a URL can be built.
    has_url_col = "url" in idx
    if not has_url_col and not ("protocol" in idx and "domain" in idx):
        res.errors.append(
            "Requests.csv has neither a 'URL' column nor 'Protocol'+'Domain' "
            "columns to build one from — not EyeWitness output."
        )
        return

    seen_ips: set = set()
    seen_urls: set = set()
    dropped = 0

    for row in reader:
        if not row or all(not str(c).strip() for c in row):
            continue
        if res.report["hosts"] >= _MAX_ROWS:
            res.errors.append(f"Row cap {_MAX_ROWS} reached; remaining rows skipped.")
            break

        protocol = _cell(row, idx, "protocol")
        port = _cell(row, idx, "port")
        domain = _cell(row, idx, "domain")
        url = _cell(row, idx, "url") if has_url_col else _synth_url(protocol, domain, port)
        if not re.match(r"^https?://[^\s/]+", url, re.IGNORECASE):
            dropped += 1
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)

        resolved = _cell(row, idx, "resolved")
        title = _cell(row, idx, "title")
        category = _cell(row, idx, "category")
        status = _cell(row, idx, "request status")
        creds = _cell(row, idx, "default creds")
        shot_path = _cell(row, idx, "screenshot path")

        # EyeWitness writes the literal string "None" when a field is unset.
        if title.lower() == "none":
            title = ""
        if category.lower() == "none":
            category = ""
        if creds.lower() == "none":
            creds = ""

        has_creds = bool(creds)
        is_high_value = has_creds or category.lower() in HIGH_VALUE_CATEGORIES

        # Locate + copy the screenshot by the basename of the CSV path. The PNG
        # name (EyeWitness sanitize_filename) differs from the source name, and an
        # error row points at a file that was never written — so a miss is normal.
        screenshot_url = ""
        if shot_path and shot_dir:
            key = os.path.basename(shot_path).lower()
            if key in shot_names:
                blob = read_shot(key)
                if blob is not None:
                    out_name = _safe_shot_name(url)
                    try:
                        with open(os.path.join(shot_dir, out_name), "wb") as fh:
                            fh.write(blob)
                        screenshot_url = (
                            f"/screenshots/{sketch_id or 'default'}/{out_name}"
                        )
                    except Exception as exc:
                        res.errors.append(f"Screenshot write failed for {url}: {exc}")

        wid = f"website:{url}"
        data_props: Dict[str, Any] = {
            "label": url,
            "type": "Website",
            "url": url,               # Website's required primary field
            "active": status.lower() == "successful",
            "source": "eyewitness",
            "resolved": resolved,
            "ew_category": category,
            "request_status": status,
            "default_creds": creds,
            "has_default_creds": has_creds,
            "is_high_value": is_high_value,
            "protocol": protocol,
            "port": port,
            "screenshot_url": screenshot_url,
            "screenshot_present": bool(screenshot_url),
        }
        if title:
            data_props["title"] = title
        res.nodes.append({
            "id": wid,
            "entity_type": "Website",
            "nodeLabel": url,
            "data": data_props,
            "include": True,
            "node_id": wid,
        })

        res.report["hosts"] += 1
        if screenshot_url:
            res.report["with_screenshot"] += 1
        if has_creds:
            res.report["with_default_creds"] += 1
        if is_high_value:
            res.report["high_value"] += 1
        cat_key = category or "uncategorized"
        res.report["by_category"][cat_key] = res.report["by_category"].get(cat_key, 0) + 1

        # Anchor the endpoint to a host IP: prefer the Resolved column, but fall
        # back to Domain when the target itself is a bare IP (the Protocol/Port/
        # Domain-only export has no Resolved column, and its Domain is the IP).
        ip_str = ""
        for _cand in (resolved, domain):
            try:
                ipaddress.ip_address(_cand)
                ip_str = _cand
                break
            except ValueError:
                continue
        if ip_str:
            iid = f"ip:{ip_str}"
            if iid not in seen_ips:
                seen_ips.add(iid)
                res.nodes.append({
                    "id": iid,
                    "entity_type": "IP",
                    "nodeLabel": ip_str,
                    # `address` is Ip's required primary field; `ip` is kept
                    # because llm/tools/tech_context_tool.py searches on it.
                    "data": {"label": ip_str, "type": "IP", "address": ip_str,
                             "ip": ip_str, "source": "eyewitness"},
                    "include": True,
                    "node_id": iid,
                })
            res.edges.append({"from_id": wid, "to_id": iid, "label": "RESOLVES_TO"})

    if dropped:
        res.errors.append(
            f"{dropped} row(s) had no usable http(s) URL and were skipped."
        )


def _make_shot_dir(res: EyewitnessResult, screenshots_dir: Optional[str],
                   sketch_id: Optional[str]) -> Optional[str]:
    if not screenshots_dir:
        return None
    shot_dir = os.path.join(screenshots_dir, str(sketch_id or "default"))
    try:
        os.makedirs(shot_dir, exist_ok=True)
        return shot_dir
    except Exception as exc:
        res.errors.append(
            f"Could not create screenshot dir {shot_dir}: {exc}. "
            f"Metadata still ingested; screenshots skipped."
        )
        return None


def parse_bytes(
    data: bytes,
    sketch_id: Optional[str] = None,
    screenshots_dir: Optional[str] = None,
) -> EyewitnessResult:
    """Parse an EyeWitness output zip.

    `screenshots_dir` is the writable root that nginx serves at /screenshots/.
    When provided, each captured PNG is copied to `<screenshots_dir>/<sketch>/` and
    the node carries the relative URL `/screenshots/<sketch>/<name>.png`. When None
    (a dry parse), nodes are still built but no image is written.
    """
    res = EyewitnessResult()

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:
        res.errors.append(f"Not a readable zip: {exc}")
        return res

    with zf:
        csv_member = None
        for n in zf.namelist():
            if os.path.basename(n).lower() == "requests.csv":
                csv_member = n
                break
        if csv_member is None:
            res.errors.append(
                "No Requests.csv in the archive. Re-run EyeWitness in multi mode "
                "(-f urls.txt / -x scan.xml); --single and --validate-urls skip it."
            )
            return res
        try:
            csv_text = zf.read(csv_member).decode("utf-8", errors="replace")
        except Exception as exc:
            res.errors.append(f"Could not read {csv_member}: {exc}")
            return res

        shots = _screenshot_members(zf)   # basename(lower) -> member name
        shot_dir = _make_shot_dir(res, screenshots_dir, sketch_id)
        _emit_rows(csv_text, sketch_id, shot_dir, set(shots),
                   lambda k: zf.read(shots[k]), res)

    return res


def parse_directory(
    root: str,
    sketch_id: Optional[str] = None,
    screenshots_dir: Optional[str] = None,
) -> EyewitnessResult:
    """Parse an EyeWitness output directory in place (host-side, no zip).

    Reads `<root>/Requests.csv` and copies PNGs from `<root>/screens/`. Used by
    scripts/ingest_eyewitness.py for runs too large to base64 through the UI.
    """
    res = EyewitnessResult()

    csv_path = None
    for name in os.listdir(root):
        if name.lower() == "requests.csv":
            csv_path = os.path.join(root, name)
            break
    if csv_path is None:
        res.errors.append(
            f"No Requests.csv in {root}. Point --input at an EyeWitness output "
            f"directory produced by a -f/-x run (multi mode)."
        )
        return res
    try:
        with open(csv_path, "rb") as fh:
            csv_text = fh.read().decode("utf-8", errors="replace")
    except Exception as exc:
        res.errors.append(f"Could not read {csv_path}: {exc}")
        return res

    screens_dir = os.path.join(root, "screens")
    shot_paths: Dict[str, str] = {}
    if os.path.isdir(screens_dir):
        for name in os.listdir(screens_dir):
            if name.lower().endswith(".png"):
                shot_paths.setdefault(name.lower(), os.path.join(screens_dir, name))

    def _read(key: str):
        try:
            with open(shot_paths[key], "rb") as fh:
                return fh.read()
        except Exception:
            return None

    shot_dir = _make_shot_dir(res, screenshots_dir, sketch_id)
    _emit_rows(csv_text, sketch_id, shot_dir, set(shot_paths), _read, res)
    return res
