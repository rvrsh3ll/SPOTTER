#!/usr/bin/env python3
"""Deobfuscate cloned JavaScript without touching the raw HTTrack tree.

Runs after a clone, before analysis. Writes recovered sources and webcrack
output under a sibling ``deobf/`` directory. Never overwrites the mirror.
Never fetches URLs. Fail-open: a missing binary, a timeout or a crash is
recorded as a warning and the raw tree is still analyzed.

webcrack evaluates decoder functions inside isolated-vm. This module still
applies a hard timeout, a heap cap, an address-space cap and (when permitted)
a network-less namespace around each invocation.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

WEBCRACK_PINNED = "2.16.0"
JS_EXTS = {".js", ".mjs", ".cjs"}
MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT = 180
PER_FILE_TIMEOUT = 60
NODE_HEAP_MB = 768
# V8 reserves a large virtual address space, so RLIMIT_AS must stay well
# above the heap cap. This is only a runaway brake.
RLIMIT_AS_BYTES = 4 * 1024 * 1024 * 1024
SOURCEMAP_RE = re.compile(r"sourceMappingURL\s*=\s*(\S+)")
SKIP_DIR_NAMES = {"hts-cache"}

ProgressCb = Callable[[dict[str, Any]], None] | None


def tool_status() -> dict[str, Any]:
    """Return whether webcrack is on PATH and which version it reports."""
    bin_path = _webcrack_cmd()
    if not bin_path:
        return {"available": False, "version": "", "pinned": WEBCRACK_PINNED, "path": ""}
    version = _webcrack_version(bin_path) or WEBCRACK_PINNED
    return {
        "available": True,
        "version": version,
        "pinned": WEBCRACK_PINNED,
        "path": bin_path[0] if bin_path else "",
        "cmd": bin_path,
    }


def deobfuscate_tree(
    mirror: str | Path,
    dest: str | Path,
    options: dict[str, Any] | None = None,
    progress_cb: ProgressCb = None,
) -> dict[str, Any]:
    """Recover sourcemaps and run webcrack over JS under ``mirror`` into ``dest``.

    The mirror is read-only. Returns a status dict with warnings; ``ok`` is
    True whenever the function itself completed (including skip / fail-open).
    """
    options = options or {}
    mirror_p = Path(mirror)
    dest_p = Path(dest)
    timeout_total = int(options.get("deobf_timeout") or DEFAULT_TIMEOUT)
    timeout_total = max(15, min(1800, timeout_total))
    max_files = int(options.get("max_files") or 2000)
    max_files = max(1, min(20000, max_files))
    warnings: list[str] = []
    result: dict[str, Any] = {
        "ok": True,
        "enabled": True,
        "available": False,
        "tool": "webcrack",
        "version": "",
        "pinned": WEBCRACK_PINNED,
        "files_considered": 0,
        "files_deobfuscated": 0,
        "files_unpacked": 0,
        "sourcemaps_applied": 0,
        "skipped": 0,
        "timed_out": False,
        "isolated_network": False,
        "warnings": warnings,
        "output_dir": str(dest_p),
    }
    if not mirror_p.is_dir():
        warnings.append("clone tree not found; skipped JavaScript deobfuscation")
        return result

    js_files = list(_iter_js(mirror_p, max_files=max_files))
    result["files_considered"] = len(js_files)
    dest_p.mkdir(parents=True, exist_ok=True)

    started = time.time()
    deadline = started + timeout_total

    for path, rel in js_files:
        if time.time() >= deadline:
            result["timed_out"] = True
            remaining = len(js_files) - (result["sourcemaps_applied"] + result["skipped"]
                                         + result["files_deobfuscated"])
            # Count not-yet-processed files once; sourcemap + webcrack share the budget.
            break
        try:
            text = path.read_bytes()[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
        except OSError as e:
            warnings.append("could not read %s: %s" % (rel, type(e).__name__))
            result["skipped"] += 1
            continue
        applied = _apply_sourcemap(path, rel, text, mirror_p, dest_p, warnings)
        if applied:
            result["sourcemaps_applied"] += 1
        if progress_cb:
            try:
                progress_cb({
                    "stage": "deobfuscate",
                    "step": "sourcemap",
                    "file": rel,
                    "files": result["sourcemaps_applied"],
                    "total": len(js_files),
                    "elapsed": int(time.time() - started),
                })
            except Exception:
                pass

    status = tool_status()
    result["available"] = bool(status.get("available"))
    result["version"] = str(status.get("version") or "")
    if not status.get("available"):
        warnings.append(
            "webcrack is not installed; skipped JavaScript deobfuscation "
            "(expected webcrack %s on PATH)" % WEBCRACK_PINNED
        )
        _write_manifest(dest_p, result)
        return result

    isolated, isolate_cmd = _network_isolation_prefix()
    result["isolated_network"] = isolated
    require_iso = bool(options.get("require_isolated_network"))
    if not isolated:
        if require_iso:
            warnings.append(
                "OPSEC DNS: webcrack was not run because a network-less namespace "
                "(unshare --net) is unavailable. Refusing to deobfuscate with the "
                "container network."
            )
            result["ok"] = False
            result["skipped"] += len(js_files)
            _write_manifest(dest_p, result)
            return result
        warnings.append(
            "network isolation for webcrack is unavailable; deobfuscation ran with the container network"
        )

    for index, (path, rel) in enumerate(js_files):
        remaining = deadline - time.time()
        if remaining <= 1:
            result["timed_out"] = True
            result["skipped"] += len(js_files) - index
            warnings.append(
                "JavaScript deobfuscation hit the job timeout after %s file(s); remaining files were skipped"
                % result["files_deobfuscated"]
            )
            break
        per_file = max(5, min(PER_FILE_TIMEOUT, int(remaining)))
        work = dest_p / ".work" / ("%s.out" % rel.replace("/", "__"))
        try:
            work.mkdir(parents=True, exist_ok=True)
            ok, unpacked, err, used_isolation = _run_webcrack(
                path, work, status["cmd"], per_file, isolate_cmd,
                require_isolated=require_iso,
            )
            if used_isolation:
                result["isolated_network"] = True
            if not ok:
                result["skipped"] += 1
                if err:
                    warnings.append("%s: %s" % (rel, err))
                if err and "timed out" in err:
                    result["timed_out"] = True
                continue
            copied, modules = _harvest_webcrack_output(work, dest_p, rel)
            if copied:
                result["files_deobfuscated"] += 1
            else:
                result["skipped"] += 1
                warnings.append("webcrack produced no JS for %s" % rel)
            result["files_unpacked"] += modules
        except Exception as e:
            result["skipped"] += 1
            warnings.append("%s: %s" % (rel, type(e).__name__))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if progress_cb:
            try:
                progress_cb({
                    "stage": "deobfuscate",
                    "step": "webcrack",
                    "file": rel,
                    "files": result["files_deobfuscated"],
                    "total": len(js_files),
                    "elapsed": int(time.time() - started),
                })
            except Exception:
                pass

    shutil.rmtree(dest_p / ".work", ignore_errors=True)
    # Keep warnings short and unique-ish for the job panel.
    dedup: list[str] = []
    seen: set[str] = set()
    for w in warnings:
        if w in seen:
            continue
        seen.add(w)
        dedup.append(w[:300])
    result["warnings"] = dedup[:40]
    _write_manifest(dest_p, result)
    return result


def _write_manifest(dest: Path, result: dict[str, Any]) -> None:
    try:
        payload = {k: v for k, v in result.items() if k != "output_dir"}
        (dest / "manifest.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        )
    except OSError:
        pass


def _iter_js(root: Path, max_files: int) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        # Do not follow a symlink that leaves the tree.
        for name in filenames:
            if name.startswith(".") or name.startswith("hts-"):
                continue
            path = Path(dirpath) / name
            if path.suffix.lower() not in JS_EXTS:
                continue
            if not path.is_file() or path.is_symlink():
                # Symlinked JS is skipped unless the target stays inside the tree.
                if path.is_symlink():
                    try:
                        resolved = path.resolve()
                        resolved.relative_to(root.resolve())
                        if not resolved.is_file():
                            continue
                        path = resolved
                    except (ValueError, OSError):
                        continue
                else:
                    continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= 0 or size > MAX_FILE_BYTES:
                continue
            try:
                rel = str(path.resolve().relative_to(root.resolve()))
            except ValueError:
                continue
            out.append((path, rel))
            if len(out) >= max_files:
                return out
    return out


def _safe_join(root: Path, rel: str) -> Path | None:
    if not rel or rel.startswith("/") or ":" in rel.split("/", 1)[0]:
        return None
    parts: list[str] = []
    for p in rel.replace("\\", "/").split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            return None
        parts.append(p)
    if not parts:
        return None
    out = root.joinpath(*parts)
    try:
        out.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    return out


def _apply_sourcemap(
    js_path: Path, rel: str, text: str, mirror: Path, dest: Path, warnings: list[str],
) -> int:
    written = 0
    for m in SOURCEMAP_RE.finditer(text):
        smap = _load_sourcemap(js_path, m.group(1).rstrip("\\").strip(), mirror)
        if not smap:
            continue
        sources = smap.get("sources") or []
        contents = smap.get("sourcesContent") or []
        if not isinstance(sources, list) or not isinstance(contents, list):
            continue
        base = dest / "sourcemaps" / (rel + ".src")
        for i, src in enumerate(sources):
            if i >= len(contents) or not contents[i]:
                continue
            name = _sourcemap_source_name(str(src or ""), i)
            out = _safe_join(base, name)
            if out is None:
                continue
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
                body = contents[i] if isinstance(contents[i], str) else str(contents[i])
                out.write_text(body[:MAX_FILE_BYTES], encoding="utf-8")
                written += 1
            except OSError as e:
                warnings.append("sourcemap write failed for %s: %s" % (rel, type(e).__name__))
        # One map per file is enough.
        if written:
            break
    return written


def _sourcemap_source_name(src: str, index: int) -> str:
    name = src.replace("\\", "/")
    for prefix in ("webpack://", "webpack-internal://", "ng://", "vite://"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    name = name.split("?", 1)[0].lstrip("/")
    parts = [p for p in name.split("/") if p and p not in (".", "..")]
    if not parts:
        return "source_%d.js" % index
    return "/".join(parts)


def _load_sourcemap(js_path: Path, ref: str, mirror: Path) -> dict[str, Any] | None:
    ref = (ref or "").strip().rstrip("\\")
    if not ref:
        return None
    raw = b""
    if ref.startswith("data:"):
        raw = _decode_data_url(ref)
    elif ref.startswith(("http://", "https://", "//")):
        # Offline only: never fetch a remote map.
        return None
    else:
        ref = ref.split("#", 1)[0].split("?", 1)[0]
        cand = _safe_join(js_path.parent, ref)
        if cand is None:
            return None
        try:
            cand.resolve().relative_to(mirror.resolve())
        except (ValueError, OSError):
            return None
        if not cand.is_file():
            return None
        try:
            if cand.stat().st_size > MAX_FILE_BYTES * 2:
                return None
            raw = cand.read_bytes()[: MAX_FILE_BYTES * 2]
        except OSError:
            return None
    if not raw:
        return None
    try:
        obj = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _decode_data_url(ref: str) -> bytes:
    # data:[mediatype][;base64],payload
    try:
        header, payload = ref.split(",", 1)
    except ValueError:
        return b""
    if len(payload) > MAX_FILE_BYTES * 2:
        return b""
    if ";base64" in header.lower():
        try:
            return base64.b64decode(payload, validate=False)
        except Exception:
            return b""
    from urllib.parse import unquote_to_bytes
    try:
        return unquote_to_bytes(payload)
    except Exception:
        return payload.encode("utf-8", errors="replace")


def _webcrack_exists(path: str) -> bool:
    try:
        return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)
    except OSError:
        return False


def _webcrack_cmd() -> list[str] | None:
    override = (os.environ.get("SPOTTER_WEBCRACK") or "").strip()
    if override:
        return [override] if _webcrack_exists(override) else None
    found = shutil.which("webcrack")
    if not found:
        return None
    node = shutil.which("node")
    # Prefer invoking via node so NODE_OPTIONS (heap cap) is applied reliably.
    if node:
        return [node, found]
    return [found]


def _webcrack_version(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(
            cmd + ["--version"],
            capture_output=True, text=True, timeout=8,
            env=_child_env(),
        )
    except Exception:
        return ""
    text = (proc.stdout or proc.stderr or "").strip()
    m = re.search(r"\d+\.\d+\.\d+", text)
    return m.group(0) if m else text.splitlines()[0][:40] if text else ""


def _child_env() -> dict[str, str]:
    env = os.environ.copy()
    env["NODE_OPTIONS"] = (
        (env.get("NODE_OPTIONS") or "") + " --max-old-space-size=%d" % NODE_HEAP_MB
    ).strip()
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
              "https_proxy", "all_proxy", "FTP_PROXY", "NO_PROXY"):
        env.pop(k, None)
    # Empty proxies so a stray inherited value cannot leak.
    env["NO_PROXY"] = "*"
    return env


def _network_isolation_prefix() -> tuple[bool, list[str]]:
    unshare = shutil.which("unshare")
    if not unshare:
        return False, []
    # Prefer a user namespace plus --net so this works without CAP_SYS_ADMIN
    # (plain `unshare --net` needs SYS_ADMIN in the current user ns).
    candidates = [
        [unshare, "--user", "--map-root-user", "--net", "--"],
        [unshare, "--net", "--"],
    ]
    for prefix in candidates:
        probe = prefix + ["/bin/true"]
        try:
            r = subprocess.run(probe, capture_output=True, timeout=3)
            if r.returncode == 0:
                return True, prefix
        except Exception:
            continue
    return False, []


def _memory_prefix(memory_bytes: int = RLIMIT_AS_BYTES) -> list[str]:
    # prlimit avoids preexec_fn, which is unsafe in the threaded API server.
    prlimit = shutil.which("prlimit")
    if not prlimit:
        return []
    return [prlimit, "--as=%d" % memory_bytes, "--core=0", "--"]


def _run_webcrack(
    source: Path,
    out_dir: Path,
    cmd: list[str],
    timeout: int,
    isolate_prefix: list[str],
    require_isolated: bool = False,
) -> tuple[bool, int, str, bool]:
    """Run webcrack -o out_dir. Returns (ok, unpacked_hint, error, used_isolation)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = list(cmd) + [str(source), "-o", str(out_dir), "-f"]
    mem = _memory_prefix()
    used_isolation = False
    prefixes: list[list[str]] = []
    if isolate_prefix:
        prefixes.append(isolate_prefix)
    if not require_isolated:
        prefixes.append([])  # fail open without unshare when OPSEC is off
    if not prefixes:
        return False, 0, "network isolation for webcrack is unavailable", False
    last_err = ""
    for prefix in prefixes:
        try:
            proc = subprocess.Popen(
                prefix + mem + argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_child_env(),
                start_new_session=True,
                cwd=str(out_dir),
            )
        except OSError as e:
            last_err = "could not start webcrack: %s" % type(e).__name__
            continue
        used_isolation = bool(prefix)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill(proc)
            return False, 0, "timed out after %ss" % timeout, used_isolation
        except Exception as e:
            _kill(proc)
            last_err = type(e).__name__
            if prefix:
                used_isolation = False
                continue
            return False, 0, last_err, False
        if proc.returncode == 0:
            return True, 0, "", used_isolation
        err = (stderr or stdout or b"").decode("utf-8", errors="replace").strip()
        last_err = (err.splitlines()[-1] if err else "webcrack exited %s" % proc.returncode)[:200]
        # If isolation itself caused the failure, retry without it.
        if prefix and proc.returncode not in (0,):
            used_isolation = False
            continue
        return False, 0, last_err, used_isolation
    return False, 0, last_err or "webcrack failed", used_isolation


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=2)
        except Exception:
            os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def _harvest_webcrack_output(work: Path, dest: Path, rel: str) -> tuple[bool, int]:
    """Copy webcrack output into dest, mirroring rel. Returns (copied_main, module_count)."""
    if not work.is_dir():
        return False, 0
    files = [p for p in work.rglob("*") if p.is_file() and p.suffix.lower() in JS_EXTS]
    if not files:
        return False, 0
    main = None
    for name in ("deobfuscated.js", "index.js"):
        cand = work / name
        if cand.is_file():
            main = cand
            break
    if main is None:
        # Prefer a file at the work root.
        root_js = [p for p in files if p.parent == work]
        main = root_js[0] if root_js else files[0]
    target = _safe_join(dest, rel)
    if target is None:
        return False, 0
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_bytes(main.read_bytes()[:MAX_FILE_BYTES])
    except OSError:
        return False, 0
    modules = 0
    others = [p for p in files if p != main]
    if others:
        mod_root = Path(str(target) + ".modules")
        for p in others:
            try:
                rel_mod = str(p.relative_to(work))
            except ValueError:
                rel_mod = p.name
            out = _safe_join(mod_root, rel_mod)
            if out is None:
                continue
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(p.read_bytes()[:MAX_FILE_BYTES])
                modules += 1
            except OSError:
                continue
    return True, modules
