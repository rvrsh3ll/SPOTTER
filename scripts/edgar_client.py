#!/usr/bin/env python3
"""
edgar_client.py — SEC EDGAR company records for SPOTTER.

WHAT IT IS FOR
--------------
The Organization card's other providers are all inference. hh.ru reports what a
job board knows, the SERP provider reports what LinkedIn profiles claim, and the
website crawl reports what a company says about itself. EDGAR is the only source
on the card that is a **filing of record**: a legal name, a state of
incorporation, a registered address, and — in Exhibit 21 — the company's own
signed list of its subsidiaries with their jurisdictions.

That makes it the authoritative answer to "what is this company actually called
and what does it own", where every other provider is a best guess.

WHAT IT COVERS, AND WHAT IT DOES NOT
------------------------------------
Only SEC filers. That is US public companies plus certain funds and large
private issuers — NOT the typical private engagement target, which appears
nowhere in EDGAR. A miss here is the normal case and means nothing about the
company; the card says `no_match`, not `error`, and the website crawl remains
the provider that always works.

Deliberately NOT region-gated. Whether a company files with the SEC is a fact
about the company, not about which regions an operator ticked in Objectives, so
requiring a US tick to discover that a target is a registrant would hide a fact
for no reason.

THE FALSE-MATCH TRAP
--------------------
EDGAR name search is loose. Searching "example harbor" returns EXAMPLE HARBOR
CORP, an unrelated manufacturer with CIK 0000000002 — which has nothing to do
with Example Harbor Information Security. A confident wrong company is worse
than no company: its subsidiaries, address and state of incorporation would all
be presented as the target's.

So `resolve_cik` scores candidates and `organization_profile` refuses anything
below `min_score`, and every result carries `matched_name` and `cik` so an
operator can see exactly which registrant was matched.

ENDPOINTS (all free, no key, verified 2026-09-20)
-------------------------------------------------
    https://www.sec.gov/files/company_tickers.json      name -> CIK, ~10.4k public cos
    https://www.sec.gov/cgi-bin/browse-edgar?...&output=atom   any filer, incl. non-ticker
    https://data.sec.gov/submissions/CIK##########.json  the company record
    https://www.sec.gov/Archives/edgar/data/<cik>/<acc>/index.json  a filing's files
    .../<acc>/<something>ex21<something>.htm             Exhibit 21, the subsidiary list

SEC REQUIRES A USER-AGENT, AND THE TWO HOSTS DISAGREE ABOUT WHAT COUNTS.
data.sec.gov accepts any non-empty UA. www.sec.gov requires a CONTACT ADDRESS in
it and answers 403 otherwise -- verified from one container in one minute:

    "SPOTTER-recon/1.0 (security-assessment tooling)"   -> 403
    "SPOTTER-recon/1.0 (recon@example.com)"             -> 200

The company record lives on data.sec.gov and Exhibit 21 on www.sec.gov, so
without a contact address a run returns a full profile and NO subsidiaries --
losing the one thing here that no other provider can supply. EDGAR_USER_AGENT is
therefore effectively required, and the client says so explicitly rather than
letting the subsidiary list quietly vanish. It does not invent an address.

SEC also asks for no more than 10 requests/second. This client paces itself well
under that and caps total requests per run.

Environment:
    EDGAR_ENABLED        1 to query EDGAR                  (default: 1)
    EDGAR_USER_AGENT     "AppName (contact@email)"         (default: a SPOTTER id)
    EDGAR_TIMEOUT        per-request seconds               (default: 20)
    EDGAR_MAX_REQUESTS   per run                           (default: 12)
    EDGAR_MIN_SCORE      0-100 name-match floor            (default: 72)
"""

from __future__ import annotations

import html as _html
import json
import os
import re
import time
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

SEC_WWW = "https://www.sec.gov"
SEC_DATA = "https://data.sec.gov"
TICKERS_URL = SEC_WWW + "/files/company_tickers.json"

_DEFAULT_TIMEOUT = 20
_DEFAULT_MAX_REQUESTS = 12
_DEFAULT_MAX_SECONDS = 120
_DEFAULT_MAX_BYTES = 8 * 1024 * 1024        # company_tickers.json is ~800 KB
_DEFAULT_MIN_SCORE = 72
# SEC asks for <= 10 req/s. 150 ms is comfortably polite and still fast enough
# that a whole profile costs about a second of wall clock.
_REQUEST_DELAY = 0.15

# Identifies the tool without fabricating a contact address on the operator's
# behalf. This is NOT sufficient for www.sec.gov -- see _ua_has_contact.
_DEFAULT_UA = "SPOTTER-recon/1.0 (security-assessment tooling)"

# www.sec.gov's WAF requires a CONTACT ADDRESS in the User-Agent; data.sec.gov
# does not. Measured from one container, same minute, same path:
#
#   "SPOTTER-recon/1.0 (security-assessment tooling)"   -> 403, 403
#   "SPOTTER-recon/1.0 (recon@example.com)"             -> 200, 200
#   "SAMPLE SPOTTER recon@example.com"                  -> 200, 200
#
# That split is why a run can return a full company record and no subsidiaries:
# the profile comes from data.sec.gov and Exhibit 21 from www.sec.gov. Since
# Exhibit 21 is the most valuable thing EDGAR offers, a UA with no contact
# address quietly costs the feature its headline.
_UA_HAS_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")


def ua_has_contact(ua: str) -> bool:
    """Does this User-Agent carry a contact address www.sec.gov will accept?"""
    return bool(_UA_HAS_EMAIL.search(ua or ""))

# Corporate-form noise that should not influence a name match. "Sample Corp" and
# "Sample Corporation" are the same company; "Sample" and "Beta" are not.
_SUFFIXES = (
    "incorporated", "corporation", "company", "holdings", "holding", "group",
    "limited", "limited liability company", "inc", "corp", "co", "llc", "llp",
    "lp", "ltd", "plc", "sa", "nv", "ag", "gmbh", "pbc", "the", "and", "&",
)

# Exhibit 21 filenames vary a lot across filers and decades:
#   xcto-ex21.htm                  ex-21_1.htm            exhibit21.txt
#   a2234567zex-21.htm             xfab-2025x12x31xex211.htm
# That last one is the trap: EX-21.1 written with NO separator, so a `\b` after
# "21" never matches and one large filer's subsidiary list was invisible. Allow
# a single run-on sub-number, and use a negative lookahead so ex2110 (a
# different exhibit) is not swept in.
_EX21_RE = re.compile(r"(?:ex|exhibit)[-_ ]?21(?:[-_.]?\d)?(?!\d)", re.I)

# Before trusting a file the filename matched, check it says what it should.
# "ex21" is occasionally EX-2.1 (a merger agreement) written without
# punctuation, and parsing one of those as a subsidiary table yields confident
# nonsense.
_SUBSIDIARY_HINT = re.compile(r"subsidiar", re.I)


class EdgarError(Exception):
    """A request-level failure the caller should record, not raise through."""


def _as_int(v: Any, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def normalise_company(name: str) -> str:
    """Strip punctuation and corporate suffixes for comparison."""
    s = re.sub(r"[^a-z0-9 ]+", " ", (name or "").lower())
    words = [w for w in s.split() if w and w not in _SUFFIXES]
    return " ".join(words)


def name_score(query: str, candidate: str) -> int:
    """0-100 similarity between a search term and a registrant's legal name.

    Exact match on the suffix-stripped form is 100; a containment relationship
    scores high; everything else falls back to a sequence ratio. Deliberately
    conservative, because a wrong CIK presents another company's subsidiaries
    and registered address as the target's.
    """
    q, c = normalise_company(query), normalise_company(candidate)
    if not q or not c:
        return 0
    if q == c:
        return 100

    qw, cw = q.split(), c.split()

    def _contiguous(needle, hay):
        """Is `needle` a run of whole words inside `hay`?

        Word-aligned on purpose. A raw `q in c` substring test matches ACROSS
        word boundaries: normalising "NFO INC" gives "nfo", which is a substring
        of "iNFOrmation" in "example harbor information security", so an
        unrelated registrant scored 70 against a security consultancy. Only
        whole-word runs count.
        """
        n = len(needle)
        return n > 0 and any(hay[i:i + n] == needle for i in range(len(hay) - n + 1))

    if _contiguous(qw, cw) or _contiguous(cw, qw):
        # A real containment ("sample" in "sample corporation"). How much of the
        # longer name the shorter one accounts for decides how much it is worth:
        # "example harbor" is half of "example harbor information security",
        # which is a weak claim to be the same company.
        ratio = min(len(qw), len(cw)) / max(len(qw), len(cw))
        return 95 if ratio >= 0.8 else (82 if ratio >= 0.6 else 64)

    qt, ct = set(qw), set(cw)
    if qt and ct:
        overlap = len(qt & ct) / len(qt | ct)
        if overlap >= 0.8:
            return 85
        if overlap == 0:
            # No shared word at all. SequenceMatcher still returns 0.4-0.5 for
            # unrelated company names of similar length, which is high enough to
            # look like a near miss in the candidate list.
            return min(40, int(round(SequenceMatcher(None, q, c).ratio() * 100)))
    return int(round(SequenceMatcher(None, q, c).ratio() * 100))


def _strip_html(s: Any, limit: int = 2000) -> str:
    if not s:
        return ""
    txt = re.sub(r"<[^>]+>", " ", str(s))
    txt = _html.unescape(txt)
    return re.sub(r"\s+", " ", txt).strip()[:limit]


class EdgarClient:
    def __init__(
        self,
        *,
        proxy_url: str = "",
        user_agent: str = "",
        timeout: Optional[int] = None,
        max_requests: Optional[int] = None,
        max_seconds: int = _DEFAULT_MAX_SECONDS,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        min_score: Optional[int] = None,
        cache_dir: Optional[str] = None,
    ):
        # The operator's opsec UA is NOT used here. SEC wants an identifying
        # contact string, and a browser User-Agent is the opposite of that.
        self.user_agent = (user_agent
                           or os.environ.get("EDGAR_USER_AGENT", "").strip()
                           or _DEFAULT_UA)
        self.proxy_url = (proxy_url or "").strip()
        self.proxies = ({"http": self.proxy_url, "https": self.proxy_url}
                        if self.proxy_url else None)
        self.timeout = timeout or _as_int(os.environ.get("EDGAR_TIMEOUT"), _DEFAULT_TIMEOUT)
        self.max_requests = (max_requests
                             or _as_int(os.environ.get("EDGAR_MAX_REQUESTS"), _DEFAULT_MAX_REQUESTS))
        self.max_seconds = max_seconds
        self.max_bytes = max_bytes
        self.min_score = (min_score if min_score is not None
                          else _as_int(os.environ.get("EDGAR_MIN_SCORE"), _DEFAULT_MIN_SCORE))
        self.cache_dir = cache_dir or os.environ.get("SPOTTER_CACHE_DIR") or ""

        self.errors: List[str] = []
        if not ua_has_contact(self.user_agent):
            # Said once, before anything fails: the subsidiary list is the
            # reason to use EDGAR at all, and it is the part that breaks.
            self.errors.append(
                "EDGAR_USER_AGENT carries no contact address, so www.sec.gov "
                "will refuse Exhibit 21 and no filed subsidiary list will be "
                "retrieved. The company record itself still loads. Set it to "
                "'AppName (you@example.com)'.")
        self._throttled = False
        self._requests = 0
        self._started = time.time()
        self._last = 0.0

    # ── budget + transport ────────────────────────────────────────────────────

    def budget_exhausted(self) -> bool:
        return (self._requests >= self.max_requests
                or (time.time() - self._started) >= self.max_seconds)

    def _note(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def _fetch_once(self, url: str, accept: str) -> requests.Response:
        gap = time.time() - self._last
        if gap < _REQUEST_DELAY:
            time.sleep(_REQUEST_DELAY - gap)
        self._requests += 1
        try:
            r = requests.get(url, headers={
                "User-Agent": self.user_agent,
                "Accept": accept,
                "Accept-Encoding": "gzip, deflate",
            }, timeout=self.timeout, proxies=self.proxies, stream=True)
        except requests.exceptions.ProxyError as e:
            raise EdgarError("EDGAR proxy unreachable; refusing to fall back to "
                             "direct egress: %s" % e)
        except Exception as e:
            raise EdgarError("EDGAR request failed (%s): %s" % (url, e))
        finally:
            self._last = time.time()

        body = b""
        try:
            for chunk in r.iter_content(64 * 1024):
                body += chunk
                if len(body) >= self.max_bytes:
                    body = body[: self.max_bytes]
                    break
        finally:
            r.close()
        r._content = body           # noqa: SLF001
        r._content_consumed = True  # noqa: SLF001
        return r

    def _get(self, url: str, accept: str = "application/json") -> requests.Response:
        if self.budget_exhausted():
            raise EdgarError("EDGAR budget exhausted (%d requests / %ds)"
                             % (self.max_requests, self.max_seconds))
        r = self._fetch_once(url, accept)

        # SEC answers 403 for BOTH "no acceptable User-Agent" and "you are going
        # too fast", with no way to tell them apart from the response. Measured:
        # the identical request with the identical UA returned 403 three times
        # in a row and 200 a minute later, from the same IP -- pure throttling,
        # while the error text sent the operator off to fix a User-Agent that
        # was never the problem.
        #
        # The window is longer than a courtesy pause, so back off properly:
        # 2s then 6s. Bounded at ~8s added to a run that is otherwise ~1s.
        for _pause in (2.0, 6.0):
            if r.status_code not in (403, 429) or self.budget_exhausted():
                break
            time.sleep(_pause)
            r = self._fetch_once(url, accept)

        if r.status_code in (403, 429):
            self._throttled = True
            if not ua_has_contact(self.user_agent):
                # The overwhelmingly likely cause, and an exactly fixable one.
                raise EdgarError(
                    "SEC returned %s for %s. www.sec.gov requires a CONTACT "
                    "ADDRESS in the User-Agent (data.sec.gov does not, which is "
                    "why the company record may have loaded while this did not). "
                    "Set EDGAR_USER_AGENT to 'AppName (you@example.com)'. The "
                    "current value is %r, which carries no address."
                    % (r.status_code, url.split("//")[-1][:60], self.user_agent[:60])
                )
            raise EdgarError(
                "SEC returned %s for %s on three attempts over ~8s, with a "
                "contact address set. That points at rate limiting from this IP; "
                "it usually clears within a minute or two."
                % (r.status_code, url.split("//")[-1][:60])
            )
        if r.status_code == 404:
            raise EdgarError("EDGAR 404 for %s" % url)
        if not r.ok:
            raise EdgarError("EDGAR returned HTTP %s for %s" % (r.status_code, url))
        return r

    # ── name -> CIK ───────────────────────────────────────────────────────────

    def _ticker_table(self) -> List[Dict[str, Any]]:
        """company_tickers.json, cached on disk (it changes slowly, ~800 KB)."""
        path = ""
        if self.cache_dir:
            path = os.path.join(self.cache_dir, "edgar_company_tickers.json")
            try:
                st = os.stat(path)
                if time.time() - st.st_mtime < 7 * 86400:
                    with open(path, "r", encoding="utf-8") as f:
                        return json.load(f)
            except Exception:
                pass
        r = self._get(TICKERS_URL)
        try:
            raw = r.json() or {}
        except Exception as e:
            raise EdgarError("company_tickers.json did not parse: %s" % e)
        rows = [{"cik": str(v.get("cik_str") or "").zfill(10),
                 "name": str(v.get("title") or ""),
                 "ticker": str(v.get("ticker") or "")}
                for v in raw.values() if isinstance(v, dict)]
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rows, f)
                try:
                    from spotter_cache import ensure_cache_path
                    ensure_cache_path(path, is_dir=False)
                except Exception:
                    pass
            except Exception:
                pass
        return rows

    def resolve_cik(self, company: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Candidate registrants for a company name, best first, with scores."""
        company = (company or "").strip()
        if not company:
            return []
        out: List[Dict[str, Any]] = []
        try:
            for row in self._ticker_table():
                sc = name_score(company, row["name"])
                if sc >= 60:
                    out.append({**row, "score": sc, "via": "company_tickers"})
        except EdgarError as e:
            self._note(str(e))

        # browse-edgar also covers filers with no ticker, which company_tickers
        # omits entirely.
        if not any(c["score"] >= self.min_score for c in out) and not self.budget_exhausted():
            try:
                r = self._get(
                    "%s/cgi-bin/browse-edgar?action=getcompany&company=%s"
                    "&type=10-K&dateb=&owner=include&count=10&output=atom"
                    % (SEC_WWW, requests.utils.quote(company)),
                    accept="application/atom+xml")
                text = r.text or ""
                cik = re.search(r"<cik>(\d+)</cik>", text, re.I)
                nm = re.search(r"<conformed-name>([^<]+)</conformed-name>", text, re.I)
                if cik:
                    name = _html.unescape(nm.group(1)).strip() if nm else company
                    out.append({"cik": cik.group(1).zfill(10), "name": name,
                                "ticker": "", "score": name_score(company, name),
                                "via": "browse-edgar"})
            except EdgarError as e:
                self._note(str(e))

        seen, uniq = set(), []
        for c in sorted(out, key=lambda r: -r["score"]):
            if c["cik"] in seen:
                continue
            seen.add(c["cik"])
            uniq.append(c)
        return uniq[:limit]

    # ── the company record ────────────────────────────────────────────────────

    def get_submissions(self, cik: str) -> Dict[str, Any]:
        cik = str(cik or "").strip().zfill(10)
        if not cik.strip("0"):
            return {}
        r = self._get("%s/submissions/CIK%s.json" % (SEC_DATA, cik))
        try:
            d = r.json() or {}
        except Exception as e:
            raise EdgarError("submissions JSON did not parse: %s" % e)

        addr = ((d.get("addresses") or {}).get("business") or {})
        parts = [addr.get("street1"), addr.get("street2"), addr.get("city"),
                 addr.get("stateOrCountry"), addr.get("zipCode")]
        return {
            "cik": cik,
            "name": str(d.get("name") or ""),
            "sic": str(d.get("sic") or ""),
            "industry": str(d.get("sicDescription") or ""),
            "entity_type": str(d.get("entityType") or ""),
            "state_of_incorporation": str(d.get("stateOfIncorporation") or ""),
            "tickers": [str(t) for t in (d.get("tickers") or [])],
            "exchanges": [str(x) for x in (d.get("exchanges") or [])],
            "former_names": [str((f or {}).get("name") or "")
                             for f in (d.get("formerNames") or []) if f],
            "website": str(d.get("website") or ""),
            "phone": str(d.get("phone") or ""),
            "address": ", ".join(str(p) for p in parts if p),
            "ein": str(d.get("ein") or ""),
            "fiscal_year_end": str(d.get("fiscalYearEnd") or ""),
            "profile_url": "%s/cgi-bin/browse-edgar?action=getcompany&CIK=%s"
                           "&type=10-K&dateb=&owner=include&count=40" % (SEC_WWW, cik),
            "_filings": d.get("filings") or {},
        }

    # ── Exhibit 21: the signed subsidiary list ────────────────────────────────

    def latest_filing(self, submissions: Dict[str, Any],
                      forms: Tuple[str, ...] = ("10-K", "20-F", "40-F")) -> Dict[str, str]:
        recent = ((submissions.get("_filings") or {}).get("recent") or {})
        forms_l = recent.get("form") or []
        accs = recent.get("accessionNumber") or []
        dates = recent.get("filingDate") or []
        for i, f in enumerate(forms_l):
            if str(f).upper() in forms:
                return {"form": str(f), "accession": str(accs[i]) if i < len(accs) else "",
                        "date": str(dates[i]) if i < len(dates) else ""}
        return {}

    def get_subsidiaries(self, cik: str, submissions: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Dict[str, str]]:
        """Exhibit 21 rows: (subsidiaries, the filing they came from).

        This is the company's own filed list, which is why it is worth two extra
        requests: every other subsidiary signal on the card is inferred from a
        name resembling the parent's.
        """
        filing = self.latest_filing(submissions)
        if not filing.get("accession"):
            return [], {}
        acc = filing["accession"].replace("-", "")
        base = "%s/Archives/edgar/data/%s/%s" % (SEC_WWW, str(int(cik)), acc)
        try:
            idx = self._get("%s/index.json" % base).json() or {}
        except EdgarError:
            raise
        except Exception as e:
            raise EdgarError("filing index did not parse: %s" % e)

        name = ""
        for item in ((idx.get("directory") or {}).get("item") or []):
            n = str(item.get("name") or "")
            if _EX21_RE.search(n) and n.lower().endswith((".htm", ".html", ".txt")):
                name = n
                break
        if not name:
            return [], filing

        body = self._get("%s/%s" % (base, name), accept="text/html").text or ""
        if not _SUBSIDIARY_HINT.search(body[:20000]):
            raise EdgarError(
                "%s matched the Exhibit 21 filename pattern but its text never "
                "says 'subsidiar' — refusing to parse it as a subsidiary list "
                "(it is most likely EX-2.1, a merger agreement)." % name)
        rows: List[Dict[str, str]] = []

        def cells(tr: str) -> List[str]:
            return [_strip_html(c, 300) for c in
                    re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", tr, re.S)]

        for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", body, re.S):
            cs = [c for c in cells(tr) if c]
            if len(cs) < 2:
                continue
            nm, juris = cs[0], cs[1]
            # Header detection has to be fuzzy: real exhibits use "Name of
            # Subsidiary" / "Jurisdiction of Incorporation", not bare "Name",
            # and an exact-match filter let that row through as a subsidiary
            # called "Name of Subsidiary".
            low_n, low_j = nm.lower(), juris.lower()
            if len(nm) < 2:
                continue
            if (low_n in ("name", "subsidiary", "entity", "subsidiaries", "company")
                    or low_n.startswith(("name of", "subsidiary name", "entity name",
                                         "legal name", "list of"))
                    or "jurisdiction" in low_n
                    or low_j.startswith(("jurisdiction", "state or", "state/", "place of",
                                         "country of", "domestic"))):
                continue        # a header row
            rows.append({"name": nm[:200], "jurisdiction": juris[:120]})

        if not rows:
            # Older exhibits are plain text, one entity per line.
            text = _strip_html(body, 20000)
            for line in re.split(r"[\r\n]+", re.sub(r"\s{2,}", "\n", text)):
                line = line.strip(" .\t")
                if 3 < len(line) < 160 and re.search(r"[A-Za-z]{3}", line):
                    rows.append({"name": line[:200], "jurisdiction": ""})
            rows = rows[:200]

        filing["document"] = "%s/%s" % (base, name)
        return rows[:300], filing

    # ── the whole profile in one call ─────────────────────────────────────────

    def organization_profile(self, company_name: str,
                             aliases: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """Mirrors hh_client/serp_client's never-raises contract.

        `aliases` are the target's other names — the operator's Additional
        Identifiers, the LinkedIn company name, the WHOIS registrant. Each is
        resolved in turn until one clears the match floor, because a registrant
        files under its LEGAL name and the campaign is usually named after the
        trading one; "Sample" finding nothing says nothing about whether "Sample
        Holdings Incorporated" is a filer. Every attempt's candidates are
        pooled, so a near miss under any alias still reaches the card.
        """
        out: Dict[str, Any] = {
            "matched": False,
            "source": "sec-edgar",
            "query": company_name,
            "queries": [],
            "profile": {},
            "related": [],
            "candidates": [],
            "filing": {},
            "errors": self.errors,
        }
        queries: List[str] = []
        for term in [company_name] + list(aliases or []):
            text = str(term or "").strip()
            if text and text.lower() not in {q.lower() for q in queries}:
                queries.append(text)
        if not queries:
            self._note("EDGAR needs a company name; none was resolved")
            return out
        out["queries"] = queries

        cands: List[Dict[str, Any]] = []
        pooled: List[Dict[str, Any]] = []
        seen_cik = set()
        for term in queries:
            if self.budget_exhausted():
                self._note("EDGAR request budget exhausted before %r was tried" % term)
                break
            try:
                got = self.resolve_cik(term)
            except Exception as e:                    # noqa: BLE001
                self._note("EDGAR name resolution failed for %r: %r" % (term, e))
                continue
            for row in got:
                if row.get("cik") in seen_cik:
                    continue
                seen_cik.add(row.get("cik"))
                pooled.append(row)
            if got and got[0]["score"] >= self.min_score:
                # Cleared the floor: stop spending requests on weaker names.
                company_name = term
                break
        # Strongest first across every alias tried, so `cands[0]` is still the
        # best available match and the floor check below is unchanged.
        cands = sorted(pooled, key=lambda c: -int(c.get("score") or 0))

        out["candidates"] = [{k: c[k] for k in ("cik", "name", "ticker", "score", "via")}
                             for c in cands[:5]]
        if not cands:
            if self._throttled:
                # Critically different from a real miss: we never got to look.
                self._note("EDGAR was throttled before any lookup completed, so "
                           "%r was never actually searched. This is NOT evidence "
                           "that the company is not an SEC filer." % company_name)
            else:
                self._note("no SEC registrant matched %s. Most companies are not "
                           "SEC filers, so this is the normal case rather than a "
                           "failure." % " / ".join(repr(q) for q in queries))
            return out

        best = cands[0]
        if best["score"] < self.min_score:
            # Refused deliberately. "example harbor" matches EXAMPLE HARBOR CORP,
            # an unrelated manufacturer -- adopting it would attribute another
            # company's subsidiaries and registered address to the target.
            self._note(
                "closest SEC registrant %r (CIK %s) scored %d, below the %d "
                "match floor — not adopted. Set Primary Target to the exact "
                "legal name if this is the right company."
                % (best["name"], best["cik"], best["score"], self.min_score))
            return out

        try:
            subs_src = self.get_submissions(best["cik"])
        except EdgarError as e:
            self._note(str(e))
            return out
        except Exception as e:                        # noqa: BLE001
            self._note("EDGAR submissions failed: %r" % (e,))
            return out

        filings = subs_src.pop("_filings", {})
        out["profile"] = subs_src
        out["profile"]["match_score"] = best["score"]
        out["matched"] = bool(subs_src.get("name"))

        try:
            subs, filing = self.get_subsidiaries(best["cik"], {"_filings": filings})
            out["related"] = [{"name": s["name"], "jurisdiction": s["jurisdiction"],
                               "kind": "subsidiary", "source": "sec-edgar"}
                              for s in subs]
            out["filing"] = filing
        except EdgarError as e:
            self._note(str(e))
        except Exception as e:                        # noqa: BLE001
            self._note("EDGAR Exhibit 21 read failed: %r" % (e,))
        return out
