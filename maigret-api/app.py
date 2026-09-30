"""
Maigret API — thin Flask wrapper around the Maigret CLI and socid-extractor.

Exposes:
  POST /search   { "username": "jdoe", "timeout": 60, "top_sites": 150,
                   "tags": "ru", "proxy_url": "socks5h://host:1080" }
  POST /extract  { "url": "https://vk.com/jdoe", "timeout": 15,
                   "proxy_url": "...", "user_agent": "...", "cookies": "..." }
  GET  /health

/search answers "where does this username exist" — a list of claimed social
profiles.  All CPU/network work runs inside Maigret; this service just marshals
the subprocess and parses the JSON report file.

/extract is the second stage: given a profile URL that /search (or an operator)
already found, open the page and pull the structured identifiers out of it —
numeric user id, real name, bio, contact emails, links to the same person on
other platforms.  socid-extractor is not a new dependency here: Maigret depends
on it and calls it internally for recursive extraction (its --no-extracting flag
turns that off), so it is already installed at a version Maigret is tested
against.  Housing both tools in one image keeps that pin from drifting.
"""

import glob
import json
import os
import subprocess
import tempfile
import uuid

import requests
import socid_extractor
from flask import Flask, jsonify, request

app = Flask(__name__)

# Upper bound on the URLs one /extract call will fetch: the raw profile URL plus
# whatever API-endpoint variants socid-extractor's url_mutations produce for it.
# GitHub yields 2 (api.github.com/users/X and .../social_accounts); most sites
# yield none, so this is a guard against a pathological scheme table, not a
# routine limit.
_EXTRACT_MAX_CANDIDATES = 6

# socid-extractor's own default browser headers. We resend these rather than
# import its private HEADERS so an upstream rename cannot break the fetch.
_EXTRACT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/94.0.3729.169 Safari/537.36"
    ),
    "accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
        "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
    ),
}

# ── Site-name → platform slug normalisation ───────────────────────────────────
# Maigret uses display names like "GitHub", "LinkedIn", "X (Twitter)".
# We map to lowercase slugs that match the SocialProfile.platform field.
_PLATFORM_MAP: dict[str, str] = {
    "linkedin":       "linkedin",
    "twitter":        "twitter",
    "x":              "twitter",
    "x (twitter)":   "twitter",
    "github":         "github",
    "gitlab":         "gitlab",
    "bitbucket":      "bitbucket",
    "instagram":      "instagram",
    "facebook":       "facebook",
    "youtube":        "youtube",
    "telegram":       "telegram",
    "reddit":         "reddit",
    "tiktok":         "tiktok",
    "mastodon":       "mastodon",
    "twitch":         "twitch",
    "discord":        "discord",
    "medium":         "medium",
    "dev.to":         "devto",
    "devto":          "devto",
    "keybase":        "keybase",
    "soundcloud":     "soundcloud",
    "spotify":        "spotify",
    "steam":          "steam",
    "steamcommunity": "steam",
    "hackerrank":     "hackerrank",
    "hackerone":      "hackerone",
    "bugcrowd":       "bugcrowd",
    "pastebin":       "pastebin",
    "gravatar":       "gravatar",
    "pinterest":      "pinterest",
    "tumblr":         "tumblr",
    "vimeo":          "vimeo",
    "flickr":         "flickr",
    "snapchat":       "snapchat",
    "whatsapp":       "whatsapp",
    "signal":         "signal",
    "slack":          "slack",
    "stackoverflow":  "stackoverflow",
    "stack overflow": "stackoverflow",
}


def _site_to_platform(site_name: str) -> str:
    key = site_name.lower().strip()
    return _PLATFORM_MAP.get(key, key.replace(" ", "_").replace(".", "_"))


def _parse_report(report: dict, username: str) -> list[dict]:
    """Extract claimed profiles from a Maigret JSON report.

    Maigret 0.6.x `--json simple` writes a FLAT dict keyed by site name
    ({"GitHub": {...}, "GitHubGist": {...}}) — there is no "sites" wrapper.
    Each site_data carries status (dict with .status=="Claimed"), url_user,
    and a nested "site" object with category/tags.
    """
    profiles = []
    for site_name, site_data in (report or {}).items():
        # Skip non-site scalar keys (e.g. a top-level "username") and bad shapes.
        if not isinstance(site_data, dict):
            continue

        status = site_data.get("status")
        if isinstance(status, dict):
            claimed = status.get("status") == "Claimed"
            url = site_data.get("url_user") or status.get("urlOfExists") or ""
        elif isinstance(status, str):
            claimed = status == "Claimed"
            url = site_data.get("url_user") or ""
        else:
            # Older/alternate shapes — fall back to presence of a user URL.
            claimed = bool(site_data.get("url_user"))
            url = site_data.get("url_user") or ""

        if not claimed or not url:
            continue

        site_meta = site_data.get("site") or {}
        profiles.append({
            "platform":  _site_to_platform(site_name),
            "site_name": site_name,
            "username":  site_data.get("username") or username,
            "url":       url,
            "category":  site_meta.get("type") or site_data.get("category"),
            "tags":      site_meta.get("tags") or site_data.get("tags") or [],
        })

    return profiles


def _extract_candidates(url: str) -> list[tuple[str, dict]]:
    """The URLs to try for one profile, as (url, extra_headers) pairs.

    The raw URL always goes first — socid-extractor has url_mutations for only a
    minority of its 164 schemes (GitHub yes, VK/Instagram/Odnoklassniki no), so
    relying on mutations alone would silently skip most sites.

    Note the header default in socid_extractor.mutate_url is `set()`, not `{}`,
    so it cannot be splatted into a headers dict without this type guard.
    """
    candidates: list[tuple[str, dict]] = [(url, {})]
    try:
        for mutated, extra in (socid_extractor.mutate_url(url) or []):
            candidates.append((mutated, extra if isinstance(extra, dict) else {}))
    except Exception:
        # A broken mutation regex must not cost us the raw-URL attempt.
        pass
    return candidates[:_EXTRACT_MAX_CANDIDATES]


def _fetch_page(url, timeout, proxies, user_agent, cookies, extra_headers):
    """GET one URL for extraction. Returns page text, or raises for the caller."""
    headers = dict(_EXTRACT_HEADERS)
    headers.update(extra_headers or {})
    if user_agent:
        headers["User-Agent"] = user_agent
    resp = requests.get(
        url,
        headers=headers,
        cookies=socid_extractor.parse_cookies(cookies) if cookies else None,
        proxies=proxies,
        allow_redirects=True,
        timeout=(timeout, timeout),
    )
    return resp.text


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/search")
def search():
    body      = request.get_json(force=True, silent=True) or {}
    username  = (body.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username required"}), 400

    timeout   = max(10, int(body.get("timeout",   60)))
    top_sites = max(10, int(body.get("top_sites", 150)))
    # Comma-separated Maigret site tags. Country codes ('ru', 'us', 'cn') are the
    # interesting ones for SPOTTER: they select regional platform families that
    # the global top-sites sweep never reaches. Callers pass ONE region per call
    # and merge the results themselves, which keeps this endpoint stateless.
    tags      = (body.get("tags") or "").strip()
    proxy_url = (body.get("proxy_url") or "").strip()
    # No Maigret CLI flag sets the User-Agent, so a user_agent in the body is
    # accepted and ignored here. /extract does honour it.

    with tempfile.TemporaryDirectory() as tmpdir:
        # Maigret 0.6.x: -J/--json takes a FORMAT ('simple'|'ndjson'), not a path.
        # Reports are written into --folderoutput as report_<username>_<fmt>.json.
        cmd = [
            "python3", "-m", "maigret",
            "--json", "simple",
            "--folderoutput", tmpdir,
            "--timeout", str(timeout),
            "--top-sites", str(top_sites),
            "--no-progressbar",
            "--retries", "1",
        ]
        if tags:
            cmd += ["--tags", tags]
        if proxy_url:
            cmd += ["--proxy", proxy_url]
        cmd.append(username)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * 3 + 60,   # give maigret headroom over per-site timeout
            )
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Maigret process timed out"}), 504
        except Exception as exc:
            return jsonify({"error": f"Subprocess error: {exc}"}), 500

        # Locate the produced report (filename derives from a sanitised username).
        matches = sorted(glob.glob(os.path.join(tmpdir, "report_*_simple.json")))
        if not matches:
            return jsonify({
                "error":  "Maigret produced no output file",
                "stderr": proc.stderr[-2000:],
                "rc":     proc.returncode,
            }), 500

        try:
            with open(matches[0]) as fh:
                report = json.load(fh)
        except json.JSONDecodeError as exc:
            return jsonify({"error": f"JSON parse error: {exc}"}), 500

    profiles = _parse_report(report, username)
    return jsonify({
        "username": username,
        "tags":     tags,
        "proxied":  bool(proxy_url),
        "count":    len(profiles),
        "profiles": profiles,
    })


@app.post("/extract")
def extract():
    """Pull structured identifiers out of one already-known profile page.

    Fails soft: an unreachable page, a scheme that matches nothing, or a hostile
    anti-bot response all return HTTP 200 with found=false and the reason in
    `errors`.  A non-200 means the REQUEST was wrong, not the target — callers
    batch dozens of these and must not have to distinguish "nothing there" from
    "service broken" by status code alone.
    """
    body = request.get_json(force=True, silent=True) or {}
    url  = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400

    timeout    = max(3, int(body.get("timeout", 15)))
    proxy_url  = (body.get("proxy_url") or "").strip()
    user_agent = (body.get("user_agent") or "").strip()[:256]
    cookies    = (body.get("cookies") or "").strip()

    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    merged: dict = {}
    schemes: list[str] = []
    errors: list[str] = []

    for candidate, extra_headers in _extract_candidates(url):
        try:
            page = _fetch_page(candidate, timeout, proxies, user_agent, cookies, extra_headers)
        except Exception as exc:
            errors.append(f"{candidate}: {type(exc).__name__}: {str(exc)[:160]}")
            continue

        try:
            data = socid_extractor.extract(page) or {}
        except Exception as exc:
            errors.append(f"{candidate}: extract failed: {type(exc).__name__}: {str(exc)[:160]}")
            continue

        scheme = data.pop("_extractor", None)
        if not data:
            continue
        if scheme:
            schemes.append(scheme)
        # First candidate to produce a key wins. The raw profile page is tried
        # first and is usually the richest; API-endpoint mutations then fill gaps
        # (e.g. GitHub's HTML page has no numeric id, api.github.com does).
        for key, value in data.items():
            merged.setdefault(key, value)

    return jsonify({
        "url":     url,
        "found":   bool(merged),
        "scheme":  schemes[0] if schemes else None,
        "schemes": schemes,
        "count":   len(merged),
        "data":    merged,
        "proxied": bool(proxy_url),
        "errors":  errors[:5],
    })
