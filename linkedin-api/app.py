"""
LinkedIn OSINT Lookup API — SPOTTER sidecar service.

Searches for LinkedIn profiles matching a target individual using name,
email, company, and location as signals.  Returns the best match with a
confidence score (0.0–1.0) and whatever profile metadata could be obtained.

Search strategy (in priority order):
  1. SerpAPI (if SERP_API_KEY env var is set) — Google results, most reliable
  2. DuckDuckGo HTML search — no API key needed, reasonable rate limits
  3. Bing HTML search — fallback if DDG is rate-limited

After finding a URL, the service attempts a lightweight fetch of the public
LinkedIn page to extract job title and employer from og:title metadata.

Endpoints:
  POST /lookup  { full_name, email?, company?, location?, linkedin_url? }
  GET  /health

Environment:
  SERP_API_KEY                Optional SerpAPI key (https://serpapi.com)
  LI_TIMEOUT                  Per-request HTTP timeout in seconds (default: 15)
  LI_CONFIDENCE_THRESHOLD     Minimum score to return a result (default: 0.40)
  LI_FETCH_PROFILE            Fetch LinkedIn page for extra metadata 1/0 (default: 1)
"""

from __future__ import annotations

import os
import re
import time
import urllib.parse
from typing import Optional

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
SERP_API_KEY      = os.environ.get("SERP_API_KEY", "").strip()
LI_TIMEOUT        = int(os.environ.get("LI_TIMEOUT", "15"))
CONF_THRESHOLD    = float(os.environ.get("LI_CONFIDENCE_THRESHOLD", "0.40"))
FETCH_PROFILE     = os.environ.get("LI_FETCH_PROFILE", "1").strip() not in ("0", "false", "no")
# LinkedIn serves the photo-bearing page only intermittently to anonymous requests,
# so retry the profile fetch a few times until a real photo appears.
_PROFILE_FETCH_TRIES = int(os.environ.get("LI_PROFILE_FETCH_TRIES", "3"))

_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
)
_HEADERS_BASE = {
    "User-Agent": _BROWSER_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
}

_LI_URL_RE = re.compile(
    r"https?://(?:www\.)?linkedin\.com/in/([a-zA-Z0-9_\-\.%]+)/?",
    re.IGNORECASE,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean_li_url(raw: str) -> Optional[str]:
    """Normalise a LinkedIn URL: strip query params, trailing slashes."""
    m = _LI_URL_RE.search(urllib.parse.unquote(raw))
    if not m:
        return None
    slug = m.group(1).rstrip("/")
    return f"https://www.linkedin.com/in/{slug}/"


def _build_query(full_name: str, company: Optional[str], location: Optional[str]) -> str:
    # IMPORTANT: use "site:linkedin.com/in" WITHOUT a trailing slash. The trailing
    # form ("site:linkedin.com/in/") returns ZERO results on DuckDuckGo/Bing HTML
    # search, which silently breaks the whole lookup. The name is quoted for
    # precision; company/location are left as loose ranking terms (unquoted) so a
    # slightly different company string still returns the profile — scoring, not
    # the query, decides the match. site: goes last (yields the most hits).
    parts = [f'"{full_name}"']
    if company:
        parts.append(company)
    if location:
        parts.append(location)
    parts.append("site:linkedin.com/in")
    return " ".join(parts)


def _score_result(
    url: str,
    title: str,
    snippet: str,
    full_name: str,
    company: Optional[str],
    location: Optional[str],
    email: Optional[str],
) -> float:
    score = 0.0
    t_low = (title + " " + snippet).lower()
    name_low = full_name.lower()

    # Name match (primary signal)
    if name_low in t_low:
        score += 0.50
    else:
        # Partial: both first and last name present
        parts = name_low.split()
        if len(parts) >= 2 and all(p in t_low for p in parts):
            score += 0.35

    # Company match
    if company and company.lower() in t_low:
        score += 0.25

    # Location match
    if location and location.lower() in t_low:
        score += 0.10

    # Email username appears in the LinkedIn URL slug
    if email and "@" in email:
        email_user = email.split("@")[0].lower().replace(".", "").replace("_", "")
        slug_m = _LI_URL_RE.search(url)
        if slug_m:
            slug = slug_m.group(1).lower().replace("-", "").replace(".", "")
            if email_user and (email_user in slug or slug in email_user):
                score += 0.15

    # Name parts in slug
    slug_m = _LI_URL_RE.search(url)
    if slug_m:
        slug = slug_m.group(1).lower()
        name_parts = [p for p in name_low.split() if len(p) > 1]
        matched = sum(1 for p in name_parts if p in slug)
        score += min(0.10, matched * 0.05)

    return min(1.0, score)


# Strong organization signals only. Generic words like "systems", "services",
# "group", "solutions", "department" are intentionally EXCLUDED — they appear in
# job titles ("VP of Information Systems") as often as in company names.
_COMPANY_HINTS = (
    "inc", "inc.", "llc", "l.l.c.", "ltd", "ltd.", "corp", "corp.", "corporation",
    "company", "co.", "gmbh", "plc", "credit union", "bank", "university",
    "college", "hospital", "holdings", "enterprises", "capital", "ventures",
)


def _looks_like_company(s: str) -> bool:
    """Heuristic: does this segment read like an organization name rather than a role?

    Only strong org signals count. A bare "&" is deliberately NOT one — it appears
    in job headlines ("P&L", "M&A", "R&D", "Sales & Marketing") as often as in
    company names, so keying on it misclassifies titles as employers.
    """
    low = f" {s.lower().strip()} "
    return any(f" {h} " in low or low.rstrip().endswith(" " + h) for h in _COMPANY_HINTS)


def _parse_li_title(og_title: str) -> dict:
    """
    Parse LinkedIn og:title format: "Name - Title at Company | LinkedIn"
    or "Name - Title - Company | LinkedIn" into components. Handles the 2-segment
    "Name - Company" case (no headline title) so the employer isn't mislabeled as
    the job title.
    """
    cleaned = re.sub(r"\s*\|\s*LinkedIn\s*$", "", og_title, flags=re.IGNORECASE).strip()
    parts = [p.strip() for p in re.split(r" - | · | at ", cleaned) if p.strip()]
    result = {}
    if parts:
        result["display_name"] = parts[0]
    if len(parts) >= 3:
        result["job_title"] = parts[1]
        result["employer"] = parts[2]
    elif len(parts) == 2:
        # Ambiguous "Name - X": X is either a headline job title or the employer.
        # Treat it as the employer only when it clearly reads like an org name.
        if _looks_like_company(parts[1]):
            result["employer"] = parts[1]
        else:
            result["job_title"] = parts[1]
    return result


# ── Search backends ───────────────────────────────────────────────────────────

def _search_serpapi(query: str) -> list[dict]:
    """Search via SerpAPI — returns list of {url, title, snippet}."""
    try:
        r = requests.get(
            "https://serpapi.com/search.json",
            params={"q": query, "api_key": SERP_API_KEY, "num": 5, "gl": "us", "hl": "en"},
            timeout=LI_TIMEOUT,
            headers={"User-Agent": _BROWSER_UA},
        )
        r.raise_for_status()
        results = []
        for item in r.json().get("organic_results", []):
            url = item.get("link", "")
            if _LI_URL_RE.search(url):
                results.append({
                    "url":     url,
                    "title":   item.get("title", ""),
                    "snippet": item.get("snippet", ""),
                })
        return results
    except Exception:
        return []


def _search_duckduckgo(query: str) -> list[dict]:
    """Search DuckDuckGo HTML — no API key needed."""
    try:
        resp = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query, "kl": "us-en"},
            headers=_HEADERS_BASE,
            timeout=LI_TIMEOUT,
        )
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        results = []
        for result_div in soup.select(".result"):
            title_a = result_div.select_one(".result__title a, .result__a")
            if not title_a:
                continue
            href = title_a.get("href", "")
            # DDG wraps links: //duckduckgo.com/l/?uddg=<encoded_url>
            if "uddg=" in href:
                parsed = urllib.parse.urlparse(href)
                qs = urllib.parse.parse_qs(parsed.query)
                href = qs.get("uddg", [href])[0]
            url = _clean_li_url(href)
            if not url:
                continue
            snippet_el = result_div.select_one(".result__snippet")
            results.append({
                "url":     url,
                "title":   title_a.get_text(strip=True),
                "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
            })
        return results
    except Exception:
        return []


def _search_bing(query: str) -> list[dict]:
    """Search Bing HTML — fallback."""
    try:
        resp = requests.get(
            "https://www.bing.com/search",
            params={"q": query, "setlang": "en"},
            headers={**_HEADERS_BASE, "Accept": "text/html"},
            timeout=LI_TIMEOUT,
        )
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        results = []
        for li in soup.select("li.b_algo"):
            a = li.select_one("h2 a")
            if not a:
                continue
            href = a.get("href", "")
            url = _clean_li_url(href)
            if not url:
                continue
            cap = li.select_one(".b_caption p, .b_snippet")
            results.append({
                "url":     url,
                "title":   a.get_text(strip=True),
                "snippet": cap.get_text(strip=True) if cap else "",
            })
        return results
    except Exception:
        return []


def _is_real_photo(u: str) -> bool:
    """True only for an actual member photo. LinkedIn member photos are served from
    media.licdn.com (…/profile-displayphoto…). static.licdn.com URLs are LinkedIn's
    own branding/placeholder image served when a profile has no public photo — we
    must NOT surface that as the person's face."""
    u = (u or "").lower()
    if not u.startswith("http") or "static.licdn.com" in u:
        return False
    return "media.licdn.com" in u or "displayphoto" in u


def _fetch_profile_meta(url: str) -> dict:
    """
    Fetch the public LinkedIn profile page and extract og:title → display_name,
    job_title, employer and og:image → photo_url.

    LinkedIn serves the full public page (the one carrying the member photo) only
    intermittently to unauthenticated requests — the same URL alternately returns a
    stripped page with no og:image. So retry up to LI_PROFILE_FETCH_TRIES times,
    keeping the richest result and stopping as soon as a real photo appears.
    Returns {} on total failure.
    """
    best: dict = {}
    for attempt in range(max(1, _PROFILE_FETCH_TRIES)):
        try:
            resp = requests.get(
                url,
                headers={**_HEADERS_BASE, "Accept": "text/html"},
                timeout=LI_TIMEOUT,
                allow_redirects=True,
            )
            # 999 (LinkedIn's bot block), 429, 403 → we're rate-limited; further
            # retries only deepen the block, so stop and return what we have.
            if resp.status_code in (999, 429, 403):
                break
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")

                def _meta(names, attr="property"):
                    for n in names:
                        t = soup.find("meta", attrs={attr: n})
                        if t and (t.get("content") or "").strip():
                            return t["content"].strip()
                    return ""

                og_title = _meta(["og:title"]) or _meta(["twitter:title"], "name")
                if not og_title:
                    t = soup.find("title")
                    og_title = t.get_text(strip=True) if t else ""
                og_image = (_meta(["og:image", "og:image:secure_url"])
                            or _meta(["twitter:image", "twitter:image:src"], "name"))
                if not og_image:
                    link = soup.find("link", rel="image_src")
                    if link and link.get("href"):
                        og_image = link["href"].strip()

                result = _parse_li_title(og_title) if og_title else {}
                if og_image and _is_real_photo(og_image):
                    result["photo_url"] = og_image
                if result.get("photo_url"):
                    return result
                if len(result) > len(best):
                    best = result
        except Exception:
            pass
        time.sleep(0.4)
    return best


# ── Core lookup ───────────────────────────────────────────────────────────────

def _find_best_match(
    full_name: str,
    email: Optional[str],
    company: Optional[str],
    location: Optional[str],
    linkedin_url: Optional[str],
) -> Optional[dict]:
    """
    Search all backends, score every candidate, return the best above threshold.
    If linkedin_url is provided (e.g., already found by Maigret), skip search
    and score it directly.
    """
    candidates: list[dict] = []

    # Shortcut: caller already has a URL (e.g. from Maigret enrichment)
    if linkedin_url:
        clean = _clean_li_url(linkedin_url)
        if clean:
            candidates.append({"url": clean, "title": full_name, "snippet": ""})

    if not candidates:
        query = _build_query(full_name, company, location)

        if SERP_API_KEY:
            candidates = _search_serpapi(query)
            time.sleep(0.3)

        if not candidates:
            candidates = _search_duckduckgo(query)
            time.sleep(0.5)

        if not candidates:
            candidates = _search_bing(query)

    if not candidates:
        return None

    # Score each candidate
    best: Optional[dict] = None
    best_score = 0.0
    for c in candidates:
        s = _score_result(
            c["url"], c["title"], c["snippet"],
            full_name, company, location, email,
        )
        if s > best_score:
            best_score = s
            best = {**c, "confidence": round(s, 3)}

    if best is None or best_score < CONF_THRESHOLD:
        return None

    # Optionally enrich with profile page metadata
    profile_meta: dict = {}
    if FETCH_PROFILE:
        profile_meta = _fetch_profile_meta(best["url"])

    # Merge: prefer profile_meta values (more authoritative), fall back to
    # what we parsed from the search snippet title
    title_meta = _parse_li_title(best.get("title", ""))
    merged = {**title_meta, **profile_meta}

    return {
        "url":          best["url"],
        "confidence":   best["confidence"],
        "display_name": merged.get("display_name") or full_name,
        "job_title":    merged.get("job_title"),
        "employer":     merged.get("employer"),
        "photo_url":    merged.get("photo_url"),
        "source_title": best.get("title", ""),
    }


# ── Flask endpoints ───────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/lookup")
def lookup():
    body = request.get_json(force=True, silent=True) or {}

    full_name    = (body.get("full_name") or "").strip()
    email        = (body.get("email") or "").strip() or None
    company      = (body.get("company") or "").strip() or None
    location     = (body.get("location") or "").strip() or None
    linkedin_url = (body.get("linkedin_url") or "").strip() or None

    if not full_name:
        return jsonify({"error": "full_name is required"}), 400

    match = _find_best_match(full_name, email, company, location, linkedin_url)

    if match is None:
        return jsonify({
            "full_name":  full_name,
            "found":      False,
            "confidence": 0.0,
            "url":        None,
        })

    return jsonify({
        "full_name":    full_name,
        "found":        True,
        "confidence":   match["confidence"],
        "url":          match["url"],
        "display_name": match.get("display_name"),
        "job_title":    match.get("job_title"),
        "employer":     match.get("employer"),
        "photo_url":    match.get("photo_url"),
    })
