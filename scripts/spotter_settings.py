#!/usr/bin/env python3
"""Runtime-tunable workflow settings, editable from the SPOTTER Configuration panel.

Why this exists
---------------
Every knob here used to be environment-only, which made it effectively untunable:
a code node reads `os.environ`, but the Python task runner only receives the vars
named in `allowed-env` (see scripts/check_workflow_regressions.py), and changing
an env var at all requires recreating the container. An operator cannot do that
from a browser, and several of these values are things you genuinely want to
change per engagement -- how hard the bucket probe pushes, how deep attack-path
search goes.

So the value a workflow uses is resolved in three tiers, first hit wins:

    1. (:SpotterMeta {key:'settings'})   -- written by WF22 from the UI
    2. the environment variable          -- deployment default, needs a recreate
    3. SETTINGS_SPEC[...]["default"]     -- the built-in, always correct

Tier 1 takes effect on the *next workflow run*: there is no restart and no cache.
Tier 2 is preserved deliberately -- an operator who has pinned a value in .env
keeps it until someone deliberately overrides it from the panel, and a fresh
install with an empty registry behaves exactly as it did before this module.

Storage mirrors the campaign registry: one global (:SpotterMeta) node holding a
JSON blob, carrying no sketch_id so it is global to every campaign, and excluded
from WF07's orphan sweep (which is guarded `AND NOT n:SpotterMeta`) so clearing a
graph never resets an operator's tuning.

Reading never raises. A settings lookup happening while Neo4j is restarting must
degrade to the env/default value rather than take a scan down with it, so every
read path swallows its exception and falls through to the next tier.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

# spotter_campaign_acl already owns the Neo4j HTTP transaction helper and the
# webhook identity helpers, and is on the runner's import allowlist. Reusing it
# keeps one Cypher path and one definition of "who is calling".
import spotter_campaign_acl as _acl

META_KEY = "settings"


# ── The tunables ─────────────────────────────────────────────────────────────
# `lo`/`hi` are hard clamps, not suggestions: they are applied to whatever tier
# supplies the value, so neither a typo in .env nor a hostile webhook body can
# push a workflow outside a sane range. The bucket bounds are copied verbatim
# from WF13's original `_env_int` calls so this module is a drop-in for them.
#
# `group` and `label` drive the Configuration panel; `help` is the hint text.
SETTINGS_SPEC: Dict[str, Dict[str, Any]] = {
    # --- Attack path analysis (workflow 04) ---
    "MAX_ATTACK_HOPS": {
        "type": "int", "default": 4, "lo": 1, "hi": 8,
        "group": "Attack path analysis", "label": "Max hops",
        "help": "Longest attack chain to search. Cost grows sharply with depth.",
    },
    "MAX_ATTACK_PATHS_PER_IND": {
        "type": "int", "default": 1500, "lo": 1, "hi": 20000,
        "group": "Attack path analysis", "label": "Max paths per individual",
        "help": "Ceiling on paths retained for one identity before truncating.",
    },
    "MAX_ATTACK_DOSSIER_WRITES": {
        "type": "int", "default": 400, "lo": 1, "hi": 10000,
        "group": "Attack path analysis", "label": "Max dossier writes",
        "help": "Upper bound on dossier records a single run may write back.",
    },
    "EXPLOIT_PATH_MAX_BONUS": {
        "type": "int", "default": 8, "lo": 0, "hi": 20,
        "group": "Attack path analysis", "label": "Exploit bonus cap",
        "help": "Most a target with public exploit code may add to one path hop. "
                "The built-in 8 equals the Domain Admins bonus, so exploit "
                "availability can decide ties but never outweighs reaching DA. "
                "0 removes it from the ranking entirely -- worth doing on an "
                "estate whose CVEs are mostly product-name guesses.",
    },
    "CLOUD_EXPOSURE_MAX_BONUS": {
        "type": "int", "default": 8, "lo": 0, "hi": 20,
        "group": "Attack path analysis", "label": "Cloud exposure cap",
        "help": "Most a publicly readable cloud bucket may contribute when WF04 "
                "ranks cloud exposure. Scored at the ASSET, not the person: with "
                "MANAGES excluded from path scoring a bucket has no route to an "
                "Individual, so this never moves an attack_score on its own. The "
                "built-in 8 equals the Domain Admins bonus, so reading a client's "
                "payroll out of an open bucket can decide which target you pick "
                "first but never outranks reaching DA. 0 removes cloud exposure "
                "from the ranking entirely.",
    },
    "CLOUD_OWNER_MAX_BONUS": {
        "type": "int", "default": 0, "lo": 0, "hi": 8,
        "group": "Attack path analysis", "label": "Cloud owner credit",
        "help": "Most a cloud bucket may add to the attack_score of the person "
                "WF13 attributed it to, via the asset-scoped OWNS_ASSET edge "
                "only -- somebody holding AD control over the host that serves the "
                "asset, or a cloud IAM permission on the resource itself. DEFAULT "
                "0, i.e. off: crediting an owner at all reverses the standing "
                "decision that ownership is not hosting (issues.md, Confirmed "
                "limitations item 2), so it is an explicit operator choice. "
                "HAS_ACCESS -- reach without control -- is not scored here either; "
                "WF04 credits control only. Plain MANAGES, the domain registrant "
                "that WF13 attaches to every asset in a sweep including CDN "
                "endpoints, is never scored at any setting.",
    },
    # --- Credential scanning (workflow 11) ---
    "SPOTTER_CRED_SCAN_MAX_BYTES": {
        "type": "int", "default": 10 * 1024 * 1024, "lo": 1024, "hi": 200 * 1024 * 1024,
        "group": "Credential scanning", "label": "Max file bytes",
        "help": "Largest single file handed to Titus for credential scanning.",
    },
    # --- Vulnerability scanning (workflows 06 + 25) ---
    "SPOTTER_NESSUS_MAX_ROWS": {
        "type": "int", "default": 300000, "lo": 1000, "hi": 2000000,
        "group": "Vulnerability scanning", "label": "Max Nessus CSV rows",
        "help": "Rows read from one export. A capped upload says so in its "
                "errors rather than looking like a clean estate — but the "
                "report is genuinely incomplete, so split it or raise this.",
    },
    "SPOTTER_NESSUS_INCLUDE_INFO": {
        "type": "int", "default": 0, "lo": 0, "hi": 1,
        "group": "Vulnerability scanning", "label": "Ingest informational rows",
        "help": "0 skips severity-None plugins (roughly two thirds of a report: "
                "banners, enumeration) and only mines them for OS and CPE facts. "
                "1 makes each one a graph node too. The skipped count is always "
                "reported either way.",
    },
    "NESSUS_CONTEXT_MAX_NODES": {
        "type": "int", "default": 1000, "lo": 1, "hi": 20000,
        "group": "Vulnerability scanning", "label": "Max findings per context run",
        "help": "Vulnerability nodes contextualized in one pass of workflow 25. "
                "A capped run reports the shortfall instead of looking complete.",
    },
    # --- Cloud bucket exposure (workflow 13) ---
    "BUCKET_PROBE_MAX_CANDIDATES": {
        "type": "int", "default": 150, "lo": 0, "hi": 5000,
        "group": "Cloud bucket exposure", "label": "Max probe candidates",
        "help": "0 disables active name-guessing entirely; GrayhatWarfare still runs.",
    },
    "BUCKET_PROBE_CONCURRENCY": {
        "type": "int", "default": 8, "lo": 1, "hi": 64,
        "group": "Cloud bucket exposure", "label": "Probe concurrency",
        "help": "Parallel probe requests. Raising this makes AWS throttling likelier.",
    },
    "BUCKET_PROBE_TIMEOUT": {
        "type": "int", "default": 6, "lo": 1, "hi": 30,
        "group": "Cloud bucket exposure", "label": "Probe timeout (s)",
        "help": "Per-request timeout for a single bucket check.",
    },
    "BUCKET_PROBE_MAX_SECONDS": {
        "type": "int", "default": 90, "lo": 5, "hi": 540,
        "group": "Cloud bucket exposure", "label": "Probe wall-clock cap (s)",
        "help": "Hard ceiling so a slow provider cannot hang the webhook.",
    },
    "BUCKET_ALERT_MIN_SCORE": {
        "type": "int", "default": 40, "lo": 1, "hi": 50,
        "group": "Cloud bucket exposure", "label": "Bucket alert min score",
        "help": "Minimum exposure score (0-50) for an open bucket to raise an alerts-feed notification.",
    },
    # --- Passive DNS / reverse DNS, ip.thc.org (workflow 13) ---
    # Free and unauthenticated, so the only thing to tune is how much of a
    # shared, per-source-IP allowance one scan is allowed to spend.
    "THC_SUBDOMAIN_LIMIT": {
        "type": "int", "default": 300, "lo": 0, "hi": 5000,
        "group": "Passive DNS (ip.thc.org)", "label": "Max names per lookup",
        "help": "Rows requested for the subdomain and CNAME lookups. 0 disables "
                "both; reverse DNS is budgeted separately.",
    },
    "THC_RDNS_MAX_IPS": {
        "type": "int", "default": 8, "lo": 0, "hi": 64,
        "group": "Passive DNS (ip.thc.org)", "label": "Reverse-DNS IP budget",
        "help": "How many resolved A records get a reverse lookup. Each costs one "
                "request from a ~250 allowance that refills at 0.5/sec.",
    },
    "THC_TIMEOUT": {
        "type": "int", "default": 15, "lo": 1, "hi": 60,
        "group": "Passive DNS (ip.thc.org)", "label": "Request timeout (s)",
        "help": "Per-request timeout. The service is free and best-effort, so "
                "treat slowness as expected rather than exceptional.",
    },
    # --- Flare.io domain breach export (workflow 13) ---
    # The domain credential search is paged to completion; these bound how much
    # it pulls and how much of it the default (masked) response carries. The
    # website export has no equivalent cap, so raise these to match a large one.
    "FLARE_DOMAIN_MAX_CREDS": {
        "type": "int", "default": 50000, "lo": 200, "hi": 500000,
        "group": "Flare breach export", "label": "Max credentials per domain",
        "help": "Safety ceiling on total credentials pulled for one domain. The "
                "search follows Flare's `next` cursor until this many are "
                "collected; also the size of a full (revealed) export.",
    },
    "FLARE_DOMAIN_PAGE_SIZE": {
        "type": "int", "default": 1000, "lo": 100, "hi": 10000,
        "group": "Flare breach export", "label": "Page size",
        "help": "Credentials requested per API call. Larger pages mean fewer "
                "requests and less rate-limit exposure; Flare accepts up to 10000.",
    },
    "FLARE_DOMAIN_LIST_CAP": {
        "type": "int", "default": 1000, "lo": 50, "hi": 200000,
        "group": "Flare breach export", "label": "Masked rows in default response",
        "help": "How many masked credential rows the normal run returns for the "
                "UI, campaign export, and localStorage. The exposed-credential "
                "count is always the true total regardless of this cap; the full "
                "unmasked list comes only from the explicit reveal/export action.",
    },
    "FLARE_DOMAIN_MATCH_CAP": {
        "type": "int", "default": 500, "lo": 50, "hi": 200000,
        "group": "Flare breach export", "label": "Graph credential-match rows",
        "help": "How many breach-to-graph credential matches the response carries "
                "for the UI, campaign export, and localStorage. Matches are sorted "
                "admins-first then by breach count, so the cap keeps the rows that "
                "matter; `credential_matches_total` always reports the true count. "
                "This list was uncapped until 2026-09-08, which on a large domain "
                "pushed one cached recon record past the browser's ~5MB budget.",
    },
    "FLARE_DOMAIN_PROMOTE": {
        "type": "int", "default": 1, "lo": 0, "hi": 1,
        "group": "Flare breach export", "label": "Promote unmatched emails to targets (on/off)",
        "help": "1 = every breach email on the searched domain (or a subdomain) that "
                "has no existing individual becomes a provisional People target, so it "
                "appears in the Targets tab — no count cap, since these are all in-scope "
                "users of the target. Personal/offsite addresses (gmail, combolist noise) "
                "are never promoted. The only upper bound is how many records the Flare "
                "pull fetches (FLARE_DOMAIN_MAX_CREDS). 0 = disable and keep breach "
                "emails as evidence only.",
    },
    # --- Super-Enrich identity pivot (workflow 27) ---
    # An on-demand, per-person action (1-5 at a time), so these bound one
    # person's pivot, not a sweep. Higher values mean more sidecar calls and a
    # longer synchronous response.
    "SUPERENRICH_MAX_USERNAMES": {
        "type": "int", "default": 5, "lo": 1, "hi": 10,
        "group": "Super-Enrich", "label": "Max username variants",
        "help": "Username variants swept through maigret per person: the SAM name, "
                "the corp-email localpart, and the localparts of any known personal "
                "emails, deduped. WF03's sweep caps this at 1; the pivot wants more.",
    },
    "SUPERENRICH_MAX_SOCID_URLS": {
        "type": "int", "default": 12, "lo": 1, "hi": 50,
        "group": "Super-Enrich", "label": "Max profiles mined (socid)",
        "help": "Discovered profile pages opened with socid-extractor to mine real "
                "name, bio, contact emails and cross-platform links.",
    },
    "SUPERENRICH_MAX_ALT_EMAILS": {
        "type": "int", "default": 25, "lo": 1, "hi": 200,
        "group": "Super-Enrich", "label": "Max alternate emails searched",
        "help": "Discovered personal/alternate emails each searched against Flare "
                "with an EXACT-email query (never a username keyword).",
    },
    "SUPERENRICH_MAX_EVENTS": {
        "type": "int", "default": 15, "lo": 1, "hi": 100,
        "group": "Super-Enrich", "label": "Max Flare deep events",
        "help": "Stealer-log records deepened via Flare's firework events endpoint "
                "for physical address / IP / device. Only runs when the operator "
                "sets reveal_events; each query tells Flare which identity interests "
                "you, so keep it modest.",
    },
    "SUPERENRICH_MAIGRET_TOP_SITES": {
        "type": "int", "default": 40, "lo": 10, "hi": 500,
        "group": "Super-Enrich", "label": "Maigret top sites",
        "help": "Global platform breadth for the maigret sweep. The regional passes "
                "use their own per-region budget on top of this.",
    },
    "SUPERENRICH_MAIGRET_TIMEOUT": {
        "type": "int", "default": 8, "lo": 1, "hi": 60,
        "group": "Super-Enrich", "label": "Maigret per-site timeout (s)",
        "help": "Per-site timeout for the maigret sweep. Higher finds more but "
                "lengthens the synchronous response.",
    },
    # --- hh.ru organization intelligence (workflow 13, `org` source) ---
    "HH_MAX_EMPLOYERS": {
        "type": "int", "default": 25, "lo": 1, "hi": 100,
        "group": "Organization", "label": "Max employer search results",
        "help": "Employers kept from the hh.ru name search. The best match becomes "
                "the target company and the REST become its subsidiary / sibling "
                "brands, so lowering this trims the partner-company list.",
    },
    "HH_MAX_VACANCIES": {
        "type": "int", "default": 100, "lo": 10, "hi": 500,
        "group": "Organization", "label": "Max vacancies listed",
        "help": "Vacancy rows paged from the employer's listing. These give the "
                "department names and office addresses. Cheap -- 100 rows is one "
                "or two page fetches -- but the department counts describe only "
                "what was fetched, unlike the role histogram.",
    },
    "HH_MAX_VACANCY_DETAILS": {
        "type": "int", "default": 15, "lo": 0, "hi": 100,
        "group": "Organization", "label": "Max vacancy detail fetches",
        "help": "The knob that actually costs: one extra page fetch per vacancy, "
                "and pages run to 3.2 MB. It is also the ONLY source of recruiter "
                "contacts and key skills, so 0 disables both. Each fetch is one "
                "more request telling hh.ru this company interests you.",
    },
    "HH_TIMEOUT": {
        "type": "int", "default": 20, "lo": 5, "hi": 120,
        "group": "Organization", "label": "Per-request timeout (s)",
        "help": "Per-request timeout for hh.ru. Raise it when running through a "
                "slow proxy or Tor, where the default will time out on the larger "
                "employer pages.",
    },
    # --- LinkedIn via search engines (workflow 13, `org` source) ---
    "SERP_MAX_SEARCHES": {
        "type": "int", "default": 12, "lo": 0, "hi": 40,
        "group": "Organization", "label": "Max SERP searches",
        "help": "SerpAPI bills per search, so this is the whole budget: 2 company "
                "identifiers + 1 org-units + 6 role queries + 1 open-roles query "
                "= 10 by default, with slack. It was 8 while the legs already "
                "wanted 9, which truncated the people sweep on every run without "
                "saying so. 0 disables the LinkedIn provider.",
    },
    "ORG_JOBS_MAX": {
        "type": "int", "default": 60, "lo": 0, "hi": 200,
        "group": "Organization", "label": "Max open roles kept",
        "help": "Ceiling on the open roles kept per run, after the employer-name "
                "gate has rejected postings belonging to other companies. These "
                "feed the Job Title Match card and are never written to the "
                "graph. 0 keeps none, which disables the open-roles leg.",
    },
    "SERP_TIMEOUT": {
        "type": "int", "default": 45, "lo": 5, "hi": 180,
        "group": "Organization", "label": "SERP timeout (s)",
        "help": "Per-request timeout for the search provider. 45 rather than "
                "20 because SerpAPI proxies a real Google query: a live run "
                "lost the company lookup -- and with it the org-unit list -- to "
                "a 20s read timeout while the people sweep succeeded.",
    },
    # --- LinkedIn via Tavily (workflow 13, `org` source) ---
    "TAVILY_MAX_SEARCHES": {
        "type": "int", "default": 10, "lo": 0, "hi": 40,
        "group": "Organization", "label": "Max Tavily searches",
        "help": "Tavily bills per search, so this is the whole budget: 2 company "
                "identifiers + 6 role queries = 8 by default, with slack. Lower "
                "than the SerpAPI equivalent because there is no separate "
                "org-units query and no jobs leg -- Tavily restricts by domain "
                "rather than by path, so one company search returns the "
                "sub-brand pages AND profiles, and the people sweep reuses them "
                "for free. 0 disables the Tavily provider.",
    },
    "TAVILY_TIMEOUT": {
        "type": "int", "default": 45, "lo": 5, "hi": 180,
        "group": "Organization", "label": "Tavily timeout (s)",
        "help": "Per-request timeout. 45 for the same reason SERP_TIMEOUT is 45: "
                "a search API that queries the live web behind your request is "
                "not a 20-second call, and losing the company lookup takes the "
                "org-unit list and every linkedin_* key with it.",
    },
    "TAVILY_MAX_RESULTS": {
        "type": "int", "default": 15, "lo": 1, "hi": 20,
        "group": "Organization", "label": "Tavily results per search",
        "help": "Rows requested per search. 20 is Tavily's own ceiling and costs "
                "no more than 1 -- billing is per SEARCH, not per result -- so "
                "lowering this saves nothing and only narrows the candidate set "
                "the company matcher and the people sweep work from.",
    },
    "TAVILY_SEARCH_DEPTH_ADVANCED": {
        "type": "int", "default": 0, "lo": 0, "hi": 1,
        "group": "Organization", "label": "Tavily advanced depth (on/off)",
        "help": "1 = search_depth 'advanced', which DOUBLES the bill (2 credits "
                "per search instead of 1) in exchange for deeper retrieval. "
                "Worth it on a target whose basic-depth sweep came back thin; "
                "wasteful as a default.",
    },
    "TAVILY_MAX_CREDITS": {
        "type": "int", "default": 50, "lo": 0, "hi": 2000,
        "group": "Organization", "label": "Tavily credit ceiling",
        "help": "Projected credits ONE run may spend across every Tavily "
                "endpoint -- search, extract, crawl and map share this single "
                "counter, because they share one billed account and two "
                "counters would drain the key at twice the configured rate. "
                "Enforced on a local projection, not on the figure Tavily "
                "reports back, which is absent unless asked for and reads 0 "
                "until five extractions have succeeded. 0 refuses to spend "
                "anything.",
    },
    # --- Company-website crawl (workflow 13, `org` source) ---
    "SITE_TAVILY": {
        "type": "int", "default": 0, "lo": 0, "hi": 2,
        "group": "Organization", "label": "Website crawl backend",
        "help": "0 = SPOTTER's own crawler: sitemap-first discovery, requests "
                "leave from the campaign egress, and nothing but the target's "
                "own domain is ever fetched. 1 = Tavily /map + /extract: Tavily "
                "discovers the URLs, SPOTTER still ranks them with its own path "
                "scoring and pays to extract only the best Max website pages. "
                "2 = Tavily /crawl: one call, roughly a third of the credits, "
                "and Tavily chooses the pages. BOTH Tavily modes fetch the "
                "client's site from Tavily's IP addresses rather than yours, so "
                "the client's logs will not show the engagement, and coverage "
                "may be lower: Tavily will not read what Googlebot cannot and "
                "offers no way to change that. 0 is the only backend that "
                "disregards robots.txt, because it is the only one doing its "
                "own fetching.",
    },
    "SITE_TAVILY_BREADTH": {
        "type": "int", "default": 20, "lo": 1, "hi": 500,
        "group": "Organization", "label": "Tavily crawl breadth",
        "help": "Links followed per page level on the Tavily backends. 20 "
                "matches what the built-in crawler takes, so switching backend "
                "does not silently change the shape of the crawl. Ignored when "
                "the backend is 0.",
    },
    "SITE_TAVILY_ADVANCED": {
        "type": "int", "default": 0, "lo": 0, "hi": 1,
        "group": "Organization", "label": "Tavily advanced extraction",
        "help": "1 = extract_depth 'advanced', which doubles the credit cost per "
                "page and additionally recovers tables. Ignored when the backend "
                "is 0.",
    },
    "SITE_MAX_PAGES": {
        "type": "int", "default": 60, "lo": 0, "hi": 500,
        "group": "Organization", "label": "Max website pages",
        "help": "Pages fetched from the target's own site, after every "
                "discovered URL is ranked by how organizationally interesting "
                "its path looks. 0 disables the crawl. This is the main cost "
                "knob and the main footprint in the client's logs.",
    },
    "SITE_MAX_SECONDS": {
        "type": "int", "default": 180, "lo": 10, "hi": 900,
        "group": "Organization", "label": "Website crawl ceiling (s)",
        "help": "Wall-clock stop for the crawl, whatever the page count. The "
                "crawl is rate-limited, so a large page budget needs a matching "
                "ceiling or it stops early and silently.",
    },
    # --- SEC EDGAR (workflow 13, `org` source) ---
    "EDGAR_MIN_SCORE": {
        "type": "int", "default": 72, "lo": 0, "hi": 100,
        "group": "Organization", "label": "EDGAR name-match floor",
        "help": "How close a registrant's legal name must be before EDGAR data "
                "is adopted. EDGAR's search is loose -- 'Example Harbor Information "
                "Security' returns EXAMPLE HARBOR CORP, an unrelated filer -- and "
                "a wrong match presents another company's subsidiaries and "
                "registered address as the target's. Below the floor the card "
                "names what it declined instead of using it.",
    },
    "EDGAR_MAX_REQUESTS": {
        "type": "int", "default": 12, "lo": 0, "hi": 60,
        "group": "Organization", "label": "Max EDGAR requests",
        "help": "A full profile costs about four: name resolution, the company "
                "record, the filing index and Exhibit 21. 0 disables the source. "
                "Free and keyless, so this bounds politeness rather than cost.",
    },
    "EDGAR_TIMEOUT": {
        "type": "int", "default": 20, "lo": 5, "hi": 120,
        "group": "Organization", "label": "EDGAR timeout (s)",
        "help": "Per-request timeout for sec.gov and data.sec.gov.",
    },
    # --- Company identification gate (workflow 13, Organization profile) ---
    # One level ABOVE the employment gate: which organisation the providers are
    # allowed to call the target at all. Before this existed each provider took
    # one seed string and adopted its top result, and a job board whose employer
    # search matches description text handed back a company in the same field
    # rather than the company itself.
    "ORG_COMPANY_MATCH_MIN": {
        "type": "int", "default": 72, "lo": 0, "hi": 100,
        "group": "Organization", "label": "Company identification floor",
        "help": "How close a provider's result must be to one of the target's "
                "identifiers (Objectives \u203a Primary Target, Additional "
                "Identifiers) before it is adopted as the target company. A "
                "candidate whose own website is one of the target's domains is "
                "accepted whatever it is called, so this floor only decides the "
                "name-only cases. Lower it for a target whose identifiers are all "
                "translations or transliterations of each other; 0 restores the "
                "old behaviour, which is to adopt whatever a provider ranked "
                "first and present it as the target.",
    },
    # --- Employment evidence gate (workflow 13, People & Positions) ---
    # The people providers return CANDIDATES, not employees: a quoted
    # company-name search on LinkedIn also surfaces former staff, vendors,
    # recruiters and anyone who merely mentions the company. These bound how much
    # evidence a candidate needs before the card counts them and the graph gets a
    # WORKS_FOR edge. See scripts/employment_evidence.py.
    "ORG_PEOPLE_EMPLOYER_MIN": {
        "type": "int", "default": 72, "lo": 0, "hi": 100,
        "group": "Organization", "label": "Employer name-match floor",
        "help": "How close the employer named on someone's profile must be to the "
                "target's name before it counts as evidence they work there. Same "
                "matcher and same floor as the EDGAR one above, for the same "
                "reason: below 72, a half-name containment like 'Example Harbor "
                "Corp' against 'Example Harbor Information Security' starts "
                "matching, and "
                "people are attributed to a company they have no connection to.",
    },
    "ORG_PEOPLE_MIN_SCORE": {
        "type": "int", "default": 25, "lo": 0, "hi": 100,
        "group": "Organization", "label": "Employment evidence floor",
        "help": "How much evidence a person needs before they are counted in "
                "People & Positions and written to the graph. 25 is one verified "
                "employer claim on their own profile. Lowering it re-admits people "
                "a search engine merely returned for a company-name query; 0 "
                "disables the gate entirely and restores the old behaviour. Note "
                "the CONFIRMED floor is deliberately not tunable — no amount of "
                "profile-side evidence can confirm employment, only corroborate it.",
    },
    "ORG_PEOPLE_GEO_GATE": {
        "type": "int", "default": 1, "lo": 0, "hi": 1,
        "group": "Organization", "label": "Location contradiction rule (on/off)",
        "help": "1 = a person whose stated location is in a different country "
                "from the target loses evidence, so a US-based profile is not "
                "reported as staff of a Russian company on the strength of a name "
                "match. It only ever arms when the target's country has two "
                "independent attestations (WHOIS, profile, ccTLD, hh.ru), because "
                "a registrant country is often the privacy proxy's. 0 = off, for a "
                "genuinely distributed target.",
    },
    "ORG_PEOPLE_MAX_WRITES": {
        "type": "int", "default": 120, "lo": 0, "hi": 500,
        "group": "Organization", "label": "Max people written to graph",
        "help": "Ceiling on Individual + WORKS_FOR/CLAIMS_WORKS_FOR writes per "
                "run. The list is sorted best-evidenced first, so the cap keeps "
                "the rows that matter. 0 renders the card and writes nothing.",
    },
    # --- Notification ticker (workflow 24) ---
    "NOTIFY_SWEEP_INTERVAL": {
        "type": "int", "default": 120, "lo": 30, "hi": 3600,
        "group": "Notifications", "label": "Sweep interval (s)",
        "help": "Minimum gap between graph sweeps. Every open browser polls, so "
                "this -- not the poll rate -- is what bounds the cost.",
    },
    "NOTIFY_MAX_PER_SWEEP": {
        "type": "int", "default": 25, "lo": 1, "hi": 200,
        "group": "Notifications", "label": "Max new per sweep",
        "help": "Ceiling on notifications one sweep may raise. The overflow is "
                "reported as a single rollup rather than dropped silently.",
    },
    "NOTIFY_RETENTION": {
        "type": "int", "default": 500, "lo": 50, "hi": 5000,
        "group": "Notifications", "label": "Retained per campaign",
        "help": "Older notifications beyond this count are deleted.",
    },
    "NOTIFY_ACTIVE_MINUTES": {
        "type": "int", "default": 30, "lo": 5, "hi": 1440,
        "group": "Notifications", "label": "Agent live threshold (min)",
        "help": "Check-in age past which an agent counts as stale. Keep this in "
                "step with the Agents tab or the two views will disagree.",
    },
    # --- Technology context + exploit availability (workflow 14) ---
    "TECH_ENRICH_MAX_NODES": {
        "type": "int", "default": 500, "lo": 1, "hi": 5000,
        "group": "Exploit intelligence", "label": "Max tech nodes per run",
        "help": "Technology/Service nodes enriched in one pass. A capped run says "
                "so in its errors rather than looking complete.",
    },
    "CVE_MAX_PER_TECH": {
        "type": "int", "default": 10, "lo": 1, "hi": 50,
        "group": "Exploit intelligence", "label": "Max CVEs per technology",
        "help": "Kept low on purpose: without an NVD_API_KEY each lookup costs 6 "
                "seconds, and product-name matches get noisy past the top few.",
    },
    "POC_MAX_PER_CVE": {
        "type": "int", "default": 10, "lo": 1, "hi": 50,
        "group": "Exploit intelligence", "label": "Max PoC repos per CVE",
        "help": "Public exploit repositories reported per CVE, best-ranked first. "
                "Log4Shell alone has over 400, so this is a display cap.",
    },
    "POC_MIN_STARS": {
        "type": "int", "default": 0, "lo": 0, "hi": 1000,
        "group": "Exploit intelligence", "label": "Min stars for a PoC repo",
        "help": "0 keeps everything and lets the trust tier do the filtering. "
                "Raise it only if low-trust stubs are drowning the view — a "
                "genuine fresh PoC can legitimately have no stars yet.",
    },
    "POC_MIRROR_MAX_AGE_DAYS": {
        "type": "int", "default": 30, "lo": 1, "hi": 365,
        "group": "Exploit intelligence", "label": "PoC mirror stale after (days)",
        "help": "Past this age the mirror is flagged stale everywhere it is read. "
                "It does not refresh anything — run scripts/sync_poc_mirror.py on "
                "the host for that.",
    },
}

# Panel section order. Anything not listed falls to the end alphabetically.
GROUP_ORDER = [
    "Organization",
    "Flare breach export",
    "Super-Enrich",
    "Cloud bucket exposure",
    "Passive DNS (ip.thc.org)",
    "Vulnerability scanning",
    "Exploit intelligence",
    "Attack path analysis",
    "Credential scanning",
    "Notifications",
]


# ── Identity ─────────────────────────────────────────────────────────────────

def caller(_items: Any) -> str:
    """Authenticated operator name, or '' — delegates to the campaign ACL."""
    return _acl.caller(_items)


def is_admin(_items: Any) -> bool:
    """True when nginx stamped X-Spotter-Admin for this request.

    Trustworthy for exactly the same reason X-Spotter-User is: the header is set
    by `proxy_set_header` from an auth_request subrequest, which *always*
    overwrites whatever the client sent, and n8n publishes no host port, so the
    only route to the webhook is through the authenticating gate. Fails closed:
    anything other than an explicit truthy value is treated as non-admin.
    """
    try:
        item = _items[0].get("json", {}) if _items else {}
    except (IndexError, AttributeError, TypeError):
        return False
    headers = item.get("headers") or {}
    if not isinstance(headers, dict):
        return False
    raw = headers.get("x-spotter-admin") or headers.get("X-Spotter-Admin") or ""
    return str(raw).strip().lower() in ("1", "true", "yes")


def body_of(_items: Any) -> Dict[str, Any]:
    return _acl.body_of(_items)


# ── Storage ──────────────────────────────────────────────────────────────────

def read_settings() -> Dict[str, Any]:
    """Stored overrides only (NOT effective values). {} on any failure."""
    try:
        d = _acl._cypher(
            "MATCH (m:SpotterMeta {key:$k}) RETURN m.data AS data LIMIT 1",
            {"k": META_KEY},
        )
        rows = d["results"][0]["data"]
        raw = rows[0]["row"][0] if rows else None
        stored = json.loads(raw) if raw else {}
        return stored if isinstance(stored, dict) else {}
    except Exception:
        # Neo4j down, node absent, malformed JSON — the caller falls back to env.
        return {}


def write_settings(values: Dict[str, Any], user: str = "") -> Dict[str, Any]:
    """Validate and persist overrides. Returns the stored map.

    Only keys in SETTINGS_SPEC survive, every value is coerced and clamped, and a
    key whose value is None/'' is *removed* — that is how the panel's "reset to
    default" works, and why an empty map means "behave exactly as before".
    """
    if not isinstance(values, dict):
        raise ValueError("values must be an object")

    stored = read_settings()
    for name, raw in values.items():
        spec = SETTINGS_SPEC.get(name)
        if spec is None:
            continue  # ignore unknown keys rather than persisting junk
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            stored.pop(name, None)
            continue
        stored[name] = _coerce(spec, raw)

    _acl._cypher(
        "MERGE (m:SpotterMeta {key:$k}) "
        "SET m.data = $data, m.updated_at = timestamp(), m.updated_by = $user",
        {"k": META_KEY, "data": json.dumps(stored), "user": user or "unknown"},
    )
    return stored


def _coerce(spec: Dict[str, Any], raw: Any) -> Any:
    if spec.get("type") == "int":
        value = int(str(raw).strip())
        return max(spec["lo"], min(spec["hi"], value))
    return str(raw).strip()


# ── Resolution ───────────────────────────────────────────────────────────────

def resolve_int(name: str, _stored: Optional[Dict[str, Any]] = None) -> int:
    """Effective integer value for `name`: SpotterMeta -> env -> default.

    `_stored` lets a caller read the registry once and resolve several settings
    against it — WF13 pulls eight in a row and should not make eight round trips.
    """
    stored = read_settings() if _stored is None else _stored

    # Version skew between workflow code and a stale runner module must degrade
    # safely rather than crash a scan. If the spec key is unknown, accept a
    # numeric override from SpotterMeta/env and otherwise return 0.
    spec = SETTINGS_SPEC.get(name)
    if spec is None:
        for candidate in (stored.get(name), os.environ.get(name)):
            if candidate is None or (isinstance(candidate, str) and not candidate.strip()):
                continue
            try:
                return int(str(candidate).strip())
            except (TypeError, ValueError):
                continue
        return 0

    for candidate in (stored.get(name), os.environ.get(name)):
        if candidate is None or (isinstance(candidate, str) and not candidate.strip()):
            continue
        try:
            return _coerce(spec, candidate)
        except (TypeError, ValueError):
            continue  # a junk override must not defeat a good env value
    return int(spec["default"])


def resolve_many(names: List[str]) -> Dict[str, int]:
    """Resolve several settings against a single registry read."""
    stored = read_settings()
    return {n: resolve_int(n, stored) for n in names}


def effective() -> List[Dict[str, Any]]:
    """Every setting with its value and where that value came from.

    Drives the Configuration panel, which shows the source so an operator can
    tell "this is the built-in" from "someone pinned this in .env".
    """
    stored = read_settings()
    out: List[Dict[str, Any]] = []
    for name, spec in SETTINGS_SPEC.items():
        if name in stored:
            source = "override"
        elif (os.environ.get(name) or "").strip():
            source = "env"
        else:
            source = "default"
        out.append({
            "name": name,
            "value": resolve_int(name, stored),
            "source": source,
            "default": spec["default"],
            "lo": spec["lo"], "hi": spec["hi"],
            "group": spec["group"], "label": spec["label"], "help": spec["help"],
            "env_value": (os.environ.get(name) or "").strip() or None,
        })
    order = {g: i for i, g in enumerate(GROUP_ORDER)}
    out.sort(key=lambda r: (order.get(r["group"], len(order)), r["group"], r["label"]))
    return out
