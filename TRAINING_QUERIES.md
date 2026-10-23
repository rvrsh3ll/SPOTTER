# TRAINING_QUERIES.md — Operator Query Playbook for the Trained Model

SPOTTER ships an optional fine-tuned LoRA adapter for Qwen2.5-7B-Instruct
(install: [INSTALL.md](INSTALL.md) §11). The adapter was trained on 64 pairs
covering three skill areas, and this document shows you **what to ask, where to
ask it, and what you get back**:

1. **SPOTTER tool-calling** — correct tool names, parameter shapes, campaign scoping
2. **AD attack paths** — the 10 attack scenarios from the GOAD lab pipeline
3. **OSINT methodology** — 7 intelligence categories plus 5 investigation-plan shapes

Everything works on the base Qwen2.5-7B-Instruct too; the adapter makes routing
and scenario answers more reliable on SPOTTER-specific phrasing.

> **Authorization required.** All queries assume a scoped engagement under
> documented Rules of Engagement.

---

## 1. Where to ask

| Surface | Tools? | Best for |
|---|---|---|
| **Open WebUI chat** (`https://chat.spotter.localhost:5443`, select the **SPOTTER** model) | Yes — all 11 tool plugins registered as callable functions | The full tool set, including the AD finder tools (§3), tech/CVE context, and the company-site RAG tool. The most complete surface. |
| **Dashboard → PROMPT tab** | Yes — its own 12-tool loop: 7 tools run client-side against the browser-cached campaign stores (`get_campaign_context`, `get_osint_recon`, `get_tech_intel`, `get_vulnerabilities`, `get_analysis`, `list_targets`, `search_intel`), and 5 graph tools proxy through the WF08 gateway (`search_entities`, `get_dossier`, `get_attack_paths`, `run_cypher`, `get_graph_schema`) | Campaign-scoped questions without leaving the dashboard. Does **not** have the AD finder, tech-context, or company-site tools — ask those in Open WebUI chat. |
| **Dashboard → Live Analysis → Security Analysis** (WF10) | Runs its own analysis | Attack-path narratives per campaign, filed by triage status. Click, don't chat. |

Rule of thumb: **AD-finder scenarios → Open WebUI chat. Graph and dossier
questions → either chat surface (the PROMPT tab is scoped to the campaign open
in the dashboard). Methodology questions → any surface. Attack narratives →
Live Analysis.**

---

## 2. Tool-calling queries (trained)

These phrasings map directly onto the routing table the adapter was trained on.
Ask them in Open WebUI chat with the **SPOTTER** model selected. The PROMPT tab
also handles `search_entities`, `get_dossier`, `get_attack_paths`, and
`run_cypher` (proxied to Neo4j via workflow 08); `get_shortest_path_to_tier0`
and the §3 finder tools are registered in chat only.

### Dossiers & personal intelligence

| Ask | Tool called | You get |
|---|---|---|
| "What do we know about jdoe?" | `get_dossier("jdoe")` | Identity, professional role, social media, breach exposure, AD permissions, beacons |
| "What's jdoe's job and where do they work?" | `get_dossier` | specialty, job_title, employer, office_address, LinkedIn URL |
| "Show me all breach data for jdoe" | `get_dossier` | Breach section: count, event types, stealer-log details, credential sources |

### Enumeration & graph questions

| Ask | Tool called | You get |
|---|---|---|
| "What groups exist in the domain?" | `search_entities("", "organization")` | Full group list |
| "List all users" | `search_entities("", "individual")` | Full user list |
| "Who are members of Domain Admins?" | `run_cypher` (MEMBER_OF query) | Membership table. **Never** `get_attack_paths` — groups are not individuals and that call always fails. |
| "Who are our highest-value targets?" | `search_entities("", "individual")` | Sorted by priority_score, with specialty and breach_count |
| "Who has stealer logs in the graph?" | `run_cypher` (has_stealer_log) | Table ordered by last_seen |
| "Which users have both high AD rights AND been breached?" | `run_cypher` (cross-correlate) | Sorted by ad_score, stealer_log flagged |
| "Find all users with GenericAll on any node" | `run_cypher` | ACE table |

### Attack paths

| Ask | Tool called |
|---|---|
| "What attack paths does jdoe have?" | `get_attack_paths("jdoe")` — scored paths with recommended actions |
| "What's the shortest path from jdoe to Domain Admins?" | `get_shortest_path_to_tier0("jdoe")` — hop-by-hop chain with exploitation action + OpSec note |

`get_attack_paths` accepts **Individual (user) names only**. For anything
group-shaped ("who can reach Domain Admins?"), the trained model routes to
`run_cypher` instead.

---

## 3. AD attack-path scenario playbook (trained — 10 GOAD scenarios)

Each scenario below was trained end-to-end: trigger question → correct tool →
interpretation of results → attack narrative. Use the trigger phrasings for the
most reliable routing. The finder tools behind these scenarios are registered in
Open WebUI chat only — from the PROMPT tab the same questions fall back to
`run_cypher`, which works but loses the trained one-shot routing.

**Starting context defaults to non-privileged.** Scenarios assume your foothold
is a breached low-privileged user, phishing victim, or external-facing service
account. Privileged accounts (Domain Admins, KRBTGT, built-in Administrator) are
targets, not starting points, unless the ROE explicitly marks them compromised.

| # | Scenario | Trigger queries | Tool | Detection risk |
|---|---|---|---|---|
| 1 | **Kerberoasting** | "Who is kerberoastable?" / "Show me SPN accounts" / "Which users have service principal names we can attack?" | `find_kerberoastable` | Low–Med — RC4 (etype 23) requests are a classic detection; target `rc4_only` accounts, avoid mass SPN sweeps |
| 2 | **AS-REP roasting** | "Which accounts don't require Kerberos pre-authentication?" / "Find AS-REP roastable users" | `find_asrep_roastable` | Low — one AS-REQ per target, but 4768-without-preauth is watched |
| 3 | **Shortest path to Tier 0** | "What's the shortest path from {user} to Domain Admins?" / "Show me the shortest attack path to tier 0 from {user}" | `get_shortest_path_to_tier0` | per-hop |
| 4 | **Attack path scoring** | "What attack paths does {user} have?" / "Score the attack paths from {user}" / "How can we escalate privileges from {user}?" | `get_attack_paths` | per-path |
| 5 | **ADCS abuse (ESC1/ESC8)** | "Any ADCS misconfigurations?" / "Show me vulnerable certificate templates" / "What ESC vulnerabilities exist in this forest?" | `find_adcs_esc` | Low for ESC1 (looks like normal PKI traffic); ESC8 relay is louder |
| 6 | **Delegation abuse** | "Show delegation issues in this domain" / "Find unconstrained, constrained, and RBCD delegation paths" | `find_delegation_paths` | Med — RBCD write is a 5136 event; the S4U itself is quiet |
| 7 | **GPO abuse** | "Who can abuse GPOs in this domain?" / "Which principals have write access to high-value GPOs?" | `find_gpo_abuse` | Med — GPO edit + gpupdate propagation is auditable |
| 8 | **Coercion + NTLM relay** | "Where can we do NTLM relay or coercion?" / "Show coercion and relay targets" | `find_coercion_relay_targets` | Med — auth events from the coerced host, noisy relay listener |
| 9 | **Cross-domain trust** | "Show cross-domain trust relationships" / "What inter-domain attack paths exist?" / "Map the domain trust edges" | `run_cypher` (TrustedBy) | — |
| 10 | **Full domain assessment** | "Give me a full assessment of this domain" / "Walk me through the complete attack surface" | chained: kerberoast → AS-REP → delegation → ADCS → coercion → GPO → shortest path | — |

**Follow-up queries that work well after any scenario:**

- "Narrate the attack chain from {user} using these results" — phase-by-phase: initial access → escalation → objective
- "Which of these paths is quietest?" — re-ranks by the OpSec table
- "What tool do I use for step 2?" — expect Rubeus/Impacket (Kerberos), Certipy/Certify (ADCS), Coercer/PetitPotam/krbrelayx/ntlmrelayx (coercion+relay), SharpGPOAbuse (GPO), Impacket-secretsdump (replication)

**DCSync note:** if a path ends in replication rights, expect the model to flag
DCSync as **High** detection risk (4662 events off a non-DC) and prefer targeted
`GetChanges` over full `GetChangesAll`.

---

## 4. OSINT methodology queries (trained — 7 categories)

These work on **any** surface including the PROMPT tab — they ask the model for
methodology, not graph lookups. The trained answers name concrete tools and a
step-by-step approach.

| Category | Ask | Tools the answer should name |
|---|---|---|
| **Username enumeration** | "What is the OSINT methodology for username enumeration?" | Maigret, Sherlock, WhatsMyName, Blackbird |
| **Email intelligence** | "How do I investigate an email address for breaches and linked accounts?" | Holehe, HIBP, Hunter.io, h8mail, EmailRep |
| **Domain recon** | "Walk me through domain reconnaissance for a target" | subfinder, Amass, crt.sh, httpx, Shodan, Censys, FOFA, BuiltWith |
| **Social media intel** | "How do I mine intelligence from social media profiles?" | Osintgram, Toutatis, Telepathy, Epieos |
| **Breach intelligence** | "What's the methodology for breach and infostealer-log research?" | HIBP, DeHashed, LeakCheck, Hudson Rock, Intelligence X |
| **Corporate intel** | "How do I map a company's structure and key personnel?" | OpenCorporates, LinkedIn, CrunchBase, SEC EDGAR, Apollo.io |
| **Infrastructure intel** | "How do I analyze a target's IP ranges and hosting?" | Shodan, GreyNoise, AbuseIPDB, BGP.tools, IPVoid |

Also trained: **"Which tools should I use for {category}?"** — tool-selection
answers with type (cli/api/web) and trade-off notes per tool.

### Investigation plans (5 trained scenario shapes)

Ask for a plan and the model chains the right categories in order:

| Target | Example prompt |
|---|---|
| **Individual** | "Build an OSINT investigation plan targeting a system administrator for an authorized red team engagement" — username enum → email intel → social media → breach |
| **Organization** | "Plan an external attack surface assessment for a mid-size company" — domain recon → corporate intel → infrastructure → breach |
| **Domain** | "Plan domain reconnaissance for initial access planning" — domain recon → infrastructure → breach |
| **Email address** | "Investigate this email address for credential discovery" — email intel → breach → username enum |
| **Full campaign** | "Design a comprehensive OSINT assessment combining all intelligence types" — all 7 categories, sequenced |

---

## 5. Adjacent capabilities (not fine-tuned — driven by the system prompt and workflows)

These work through `llm/system-prompt.md` routing and the n8n workflows rather
than the adapter's training data. Phrasing is freer; the workflows do the work.
From the PROMPT tab, the local `get_tech_intel` and `get_vulnerabilities` tools
read the same WF12/WF25 data from the campaign cache.

### Russian OSINT — see [RUSSIAN_OSINT_IMPLEMENTATION.md](RUSSIAN_OSINT_IMPLEMENTATION.md)

- **WF30 (Russian Corporate Intelligence):** run from the dashboard with an
  **INN, OGRN, company name, or person name**. Queries 5 free/keyless government
  portals (EGRUL, rupep.org, procurement, courts, bailiffs); writes Company and
  PEP nodes to the graph.
- **WF13 extension (RU region only):** leak-DB search via Reveng.ee (needs
  `REVENG_API_KEY`) and prefix-based phone carrier/region lookup (keyless).
  Select the **RU** region in Domain Recon to activate.
- **Telegram bot OSINT:** VkHistoryRobot / AllOSINTrobot enrichment via WF03/WF13
  (needs `TELEGRAM_BOT_TOKEN`).
- After WF30/WF13 runs, results are graph nodes — ask chat: *"What do we know
  about {company}?"* / *"Show PEPs linked to {INN}"*.

### LinkedIn override (WF31) — see [LINKEDIN_OVERRIDE.md](LINKEDIN_OVERRIDE.md)

Mark LinkedIn false positives from the UI; the override webhook suppresses them
in enrichment. This is a button-driven workflow, not a chat query.

### Technology & CVE intelligence

| Ask | Tool called |
|---|---|
| "What OS versions exist and which are EOL?" | `get_tech_inventory()` |
| "What's on jdoe's computer?" | `get_user_tech_profile("jdoe")` |
| "What CVEs affect Apache httpd 2.4.41 here?" | `get_cves_for_tech(...)` |
| "Show MITRE ATT&CK techniques for KeePass users" | `get_mitre_for_tech("KeePass")` |
| "What is the attack surface of 192.168.1.10?" | `get_attack_surface_for_host(...)` |
| "Any working exploits for CVE-2021-44228?" | `get_pocs_for_cve(...)` — repos are **unvetted**; trust tier + stars always reported |
| "Build an attack plan against {user}" | `generate_attack_narrative(...)` — also produced by Live Analysis (WF10) |

### Nessus vulnerability findings (after scan ingest)

| Ask | Tool called |
|---|---|
| "What did the vulnerability scan find?" | `get_vulnerability_summary()` |
| "Confirmed CVEs on {host}?" | `get_vulnerabilities_for_host(...)` |
| "Which hosts are affected by CVE-X?" | `get_hosts_for_cve(...)` |
| "What can we exploit right now?" | `get_exploitable_findings()` |
| "Vulnerable hosts that are also privileged?" | `get_vulnerable_high_value_hosts()` |

An **empty result never means clean** — it means no scan was ingested (or the
Vulnerability custom type wasn't registered at ingest). The model is trained to
report the `empty_reason`.

---

## 6. Query tips

- **Campaign scoping.** All registered tools filter to the active campaign's
  `sketch_id`. For cross-campaign questions, ask for `run_cypher` explicitly:
  *"Run a Cypher query across all campaigns: which individuals appear in more
  than one sketch?"* — omitting the sketch filter searches the whole graph; tag
  results with `sketch_id` to attribute them.
- **Phrasing matters most in chat.** The trigger queries in §2–§4 are close to
  the training data; free-form variants still route correctly most of the time,
  but if the model picks the wrong tool, re-ask with the documented phrasing.
- **Two tool sets, one graph.** The PROMPT tab runs its own loop: 7 tools read
  the browser-cached campaign stores (recon, tech, vulnerabilities, analysis,
  targets, keyword sweep) and 5 graph tools proxy to Neo4j through workflow 08.
  Open WebUI chat adds the AD finders (§3), tech/CVE context, and the
  company-site RAG tool on top. Lookups work on both surfaces; the finder-tool
  scenarios are chat-only.
- **Attack narratives belong to Live Analysis.** WF10 generates and files them
  per campaign with triage status; Tech Intel panels answer technology
  questions, not attack planning.
- **Groups vs individuals.** `get_attack_paths` and `get_shortest_path_to_tier0`
  take user names. Group questions ("who's in Domain Admins?") go to
  `run_cypher`. The adapter was trained on this distinction — if you see
  "No Individual found", the query named a group.

---

## Related documentation

- [INSTALL.md](INSTALL.md) §11 — install and enable the trained model
- [README.md](README.md) — platform overview, workflows, Open WebUI tool list
- [RUSSIAN_OSINT_IMPLEMENTATION.md](RUSSIAN_OSINT_IMPLEMENTATION.md) — WF30/WF13 RU capabilities
- [LINKEDIN_OVERRIDE.md](LINKEDIN_OVERRIDE.md) — WF31 false-positive override
- `llm/system-prompt.md` — the full routing table, Cypher library, and OpSec matrix the model works from
