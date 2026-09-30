#!/usr/bin/env python3
"""
job_titles.py — Free-text job title → normalized job-function category.

WHY THIS EXISTS
---------------
`derive_specialty()` already existed, but only inside
`flowsint-custom/types/social_profile.py`, where it runs as a pydantic
`@model_validator` on the SocialProfile custom type. That file lives in the
Flowsint container's type package; the n8n Python runner cannot import it (only
`scripts/` is bind-mounted there, at /data/scripts, and only modules named in
N8N_RUNNERS_EXTERNAL_ALLOW may be imported at all).

WF13's organization block needs the *same* normalization to answer "which of the
people already in this campaign's graph map onto the roles this company is
hiring for". Matching raw strings would fail on the obvious pairs -- "Senior
DevOps Engineer" vs "SRE", "Ведущий системный администратор" vs "Systems
Administrator" -- and comparing a normalized title against an unnormalized one
is worse than not comparing at all, because it looks like it worked.

So this module is a deliberate second copy of the rule table, placed where the
runner can reach it. `flowsint-custom/types/social_profile.py` carries a pointer
back here. IF YOU EDIT ONE TABLE, EDIT BOTH -- a silent drift shows up as a
job-title match block that quietly stops matching, not as an error.
check_job_title_rules() in scripts/check_workflow_regressions.py compares the two
tables and fails when they diverge.

ORDER IS SEMANTIC, NOT ALPHABETICAL
-----------------------------------
The list is scanned top to bottom and the first keyword hit wins, so the specific
rules must precede the generic ones. "Security Engineer" has to reach
"Security Professional" before the catch-all "engineer" rule claims it, and
"Engineering Manager" has to reach "Manager" before "engineer". Re-sorting this
table changes its output.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

# Mirror of _SPECIALTY_RULES in flowsint-custom/types/social_profile.py.
_SPECIALTY_RULES: List[Tuple[List[str], str]] = [
    (["database", "dba", "sql server", "oracle dba", "mysql admin", "postgres dba"], "Database Engineer"),
    (["ciso", "penetration test", "pentest", "red team", "soc analyst", "threat hunt", "infosec", "cybersecurity", "information security"], "Security Professional"),
    (["devops", "site reliability", "sre ", " sre", "platform engineer", "cloud engineer", "devsecops"], "DevOps / Cloud"),
    (["data scientist", "data analyst", "machine learning", "ml engineer", " ai ", "artificial intel", "data engineer", "analytics engineer"], "Data / ML"),
    (["software engineer", "software developer", "swe", "programmer", "full stack", "frontend", "backend", "web developer", "mobile developer"], "Software Engineer"),
    (["network engineer", "network admin", "infrastructure", "systems admin", "sysadmin", "it admin", "it manager", "systems engineer"], "Infrastructure / IT"),
    (["finance", "financial analyst", "accounting", "accountant", "controller", "cfo", "treasurer", "bookkeeper", "payroll"], "Finance"),
    (["human resources", " hr ", "talent acquisition", "recruiting", "recruiter", "people ops", "people partner"], "Human Resources"),
    (["marketing", "growth hacker", "brand manager", "content strategist", "digital marketing", "seo specialist", "demand gen"], "Marketing"),
    (["sales", "account executive", "business development", "bdr", "sdr", "account manager", "revenue"], "Sales"),
    (["ceo", "chief executive", "cto", "chief technology", "coo", "chief operating", "president", "vice president", " vp ", "head of"], "Executive"),
    (["director", "senior director", "managing director"], "Director"),
    (["manager", "team lead", "principal ", "staff ", "engineering manager"], "Manager"),
    (["analyst"], "Analyst"),
    (["engineer", "developer", "architect"], "Engineer"),
]

# Russian-language job titles, for hh.ru. These map onto the SAME specialty
# vocabulary as the English rules above, which is the whole point -- an hh.ru
# vacancy for "Системный администратор" and a LinkedIn profile reading "Systems
# Administrator" must both normalize to "Infrastructure / IT" or the match block
# has nothing to join on.
#
# This table is NOT mirrored in social_profile.py: SocialProfile titles come from
# LinkedIn and socid-extractor, which return English. It is consulted first,
# because several Cyrillic titles contain Latin substrings that the English table
# would mis-claim ("PHP-разработчик" would hit nothing, but "SRE-инженер" would
# hit " sre" correctly while "HR-менеджер" would hit "manager" instead of HR).
_SPECIALTY_RULES_RU: List[Tuple[List[str], str]] = [
    (["безопасност", "пентест", "информационной безопасн", "киберб", "soc-аналитик"], "Security Professional"),
    (["базы данных", "баз данных", "субд"], "Database Engineer"),
    (["devops", "sre", "облачн", "платформенный инженер"], "DevOps / Cloud"),
    (["данных", "машинного обучения", "аналитик данных", "искусственн"], "Data / ML"),
    (["системный администратор", "системным администратор", "сетевой инженер", "сетевым инженер", "администратор сети", "инфраструктур", "эникей", "технической поддержки"], "Infrastructure / IT"),
    (["разработчик", "программист", "фронтенд", "бэкенд", "фулстек"], "Software Engineer"),
    (["финанс", "бухгалтер", "казначей", "экономист"], "Finance"),
    (["персонал", "рекрут", "подбор", "кадр", "hr-"], "Human Resources"),
    (["маркетинг", "бренд-менеджер", "smm"], "Marketing"),
    (["продаж", "менеджер по работе с клиент", "развитию бизнеса"], "Sales"),
    (["директор", "руководитель департамента", "генеральный"], "Executive"),
    (["руководител", "начальник", "тимлид", "team lead"], "Manager"),
    (["аналитик"], "Analyst"),
    (["инженер", "архитектор"], "Engineer"),
    (["юрист", "юрисконсульт", "правов"], "Legal"),
]


def derive_specialty(job_title: Optional[str]) -> Optional[str]:
    """Map a free-text job title to a normalized specialty category.

    Returns None for an empty title, and falls back to a Title-Cased copy of the
    input when no rule matches -- the same contract as the SocialProfile copy, so
    a value derived here can be compared against one derived there.
    """
    if not job_title:
        return None
    t = str(job_title).lower()
    for keywords, specialty in _SPECIALTY_RULES_RU:
        if any(k in t for k in keywords):
            return specialty
    for keywords, specialty in _SPECIALTY_RULES:
        if any(k in t for k in keywords):
            return specialty
    return str(job_title).title()


def _known_row(entry: object) -> Tuple[str, str, str]:
    """Normalize one `known` entry to (name, title, node_id).

    Callers pass either the original (name, title) tuple, a (name, title, id)
    triple, or a dict with name/title/id. The id is what lets the card link a
    chip to the RIGHT graph node instead of re-searching by display name, so it
    is carried through rather than derived later -- but it stays optional,
    because the tuple form is what the smoke tests and every pre-existing
    caller use.
    """
    if isinstance(entry, dict):
        return (str(entry.get("name") or ""),
                str(entry.get("title") or ""),
                str(entry.get("id") or ""))
    seq = list(entry)  # type: ignore[arg-type]
    name = str(seq[0]) if len(seq) > 0 and seq[0] else ""
    title = str(seq[1]) if len(seq) > 1 and seq[1] else ""
    node_id = str(seq[2]) if len(seq) > 2 and seq[2] else ""
    return (name, title, node_id)


def match_titles(
    known: Iterable[object],
    offered: Iterable[str],
) -> List[Dict[str, object]]:
    """Join people we already know against roles a company is hiring for.

    `known`   — people from the campaign graph, each as (name, job_title),
                (name, job_title, node_id), or {"name","title","id"}.
    `offered` — raw job titles from the employer's open vacancies. REAL open
                roles only. Passing the `known` people's own titles in here
                makes every specialty match by construction and turns
                open_role_count into a lie -- see the caller in WF13.

    Both sides go through derive_specialty(), and the result is one row per
    specialty that BOTH sides have, carrying the people and the sample titles
    that produced it. Specialties present on only one side are dropped: a
    company hiring for a role nobody in the graph holds is not a "match", and
    surfacing it as one is how an operator ends up chasing a nonexistent pivot.
    """
    people: Dict[str, List[Dict[str, str]]] = {}
    for entry in known:
        name, title, node_id = _known_row(entry)
        spec = derive_specialty(title)
        if not spec or not name:
            continue
        people.setdefault(spec, []).append(
            {"name": name, "title": title, "id": node_id})

    roles: Dict[str, List[str]] = {}
    for title in offered:
        spec = derive_specialty(title)
        if not spec:
            continue
        bucket = roles.setdefault(spec, [])
        if title not in bucket:
            bucket.append(str(title))

    rows: List[Dict[str, object]] = []
    for spec in sorted(set(people) & set(roles)):
        rows.append({
            "specialty": spec,
            "people": people[spec],
            "open_roles": roles[spec],
            "people_count": len(people[spec]),
            "open_role_count": len(roles[spec]),
        })
    # Densest overlap first -- that is the most useful pivot, not the alphabet.
    rows.sort(key=lambda r: (-(r["people_count"] + r["open_role_count"]), r["specialty"]))
    return rows


# ── Empty-state vocabulary ───────────────────────────────────────────────────
# An empty card that used to be full reads as a regression unless it says which
# KIND of empty it is. Same contract, and the same reason, as EMPTY_MESSAGES /
# empty_kind() in employment_evidence.py -- the card renders whichever message
# the workflow hands it.
#
# TITLE_NO_ROLE_SOURCE means no leg returned a vacancy. Two can: hh.ru, gated on
# the RU objective, and the LinkedIn/google_jobs open-roles leg, which needs a
# SerpAPI key. Before these messages existed the block papered over an empty
# offered side by matching the people roster against ITSELF, which always
# "matched" -- so an empty card here is the honest answer, not a regression.

TITLE_NO_ROLE_SOURCE = "no_role_source"      # nothing advertised any open roles
TITLE_NO_TITLED_PEOPLE = "no_titled_people"  # roles exist; nobody in the graph has a title
TITLE_NO_OVERLAP = "no_overlap"              # both sides populated; no shared specialty

TITLE_MATCH_EMPTY_MESSAGES: Dict[str, str] = {
    TITLE_NO_ROLE_SOURCE: (
        "No open-role source returned a vacancy, so there is nothing to match "
        "against. Open roles come from the LinkedIn/Google Jobs leg, which "
        "needs a SerpAPI key, and from hh.ru, which is gated on the RU "
        "objective. Check the provider rows on the Profile card for which ran. "
        "This is not a finding that the company is not hiring."),
    TITLE_NO_TITLED_PEOPLE: (
        "Open roles were found, but nobody in this campaign's graph carries a "
        "job title to match them against."),
    TITLE_NO_OVERLAP: (
        "Open roles and titled people were both found, but they share no "
        "specialty. A role nobody holds is not a match."),
}


def title_match_empty_kind(*, offered: int, known: int, matches: int) -> str:
    """Classify an empty job-title match. '' when it is not empty."""
    if matches:
        return ""
    if not offered:
        return TITLE_NO_ROLE_SOURCE
    if not known:
        return TITLE_NO_TITLED_PEOPLE
    return TITLE_NO_OVERLAP
