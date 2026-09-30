#!/usr/bin/env python3
"""
Offline smoke test for scripts/hh_client.py.

Runs HHClient against synthetic hh.ru pages whose state blobs are trimmed copies
of real responses captured 2026-09-19, so the parsing path under test is the one
that runs in production. No network, no stack.

What it pins, and why each one is here rather than trusted:

  * The scrape path reads `company.department`, not the top-level `department`.
    The top-level key EXISTS on every real row and is always null -- reading it
    yields an empty org-structure block and no error at all.
  * `/employers_list?query=` is the employer-search URL. `/search/employer` and
    `/employers` both answer 404 on the web site.
  * Non-exact employer matches become `related`, which is how subsidiary brands
    reach the card. A change that drops them loses the partner-company feature
    without failing anything.
  * Facet histograms come from `searchClusters`, which counts the employer's
    WHOLE vacancy set -- not the capped page we fetched.
  * Withheld recruiter contacts report hidden=True rather than looking like an
    employer with no recruiters.
  * A configured-but-dead proxy FAILS CLOSED. A regression here leaks a direct
    request to a Russian job board from an engagement that asked to be proxied.
  * mode='auto' flips to the API only when a credential exists, and the API path
    sends the mandatory HH-User-Agent header (without it hh.ru rejects the call
    even with a valid Bearer token).

Usage:
    python3 scripts/smoke_hh_client.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402  (imported for the exception types we simulate)

import hh_client  # noqa: E402
from hh_client import HHClient, HHError  # noqa: E402
import employment_evidence  # noqa: E402  (the shared company matcher under test here)


_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s%s" % (label, (" -- " + detail) if detail else ""))
        FAILURES.append(label)


def page(state: dict) -> str:
    """Wrap a state dict the way hh.ru wraps it: HTML-escaped, in a template."""
    raw = json.dumps(state, ensure_ascii=False)
    esc = raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        "<!DOCTYPE html><html><body>"
        '<template style="display:none" id="HH-Lux-InitialState">%s</template>'
        "</body></html>" % esc
    )


# ── fixtures (trimmed from real 2026-09-19 captures) ─────────────────────────

EMPLOYERS_LIST = {
    "employersList": {
        "totalEmployersFound": 3,
        "employers": {
            # Keyed by first letter, exactly as hh.ru groups them.
            "р": [
                {"id": 100001, "name": "Ромашка", "organizationFormId": 10, "vacanciesOpen": 350},
                {"id": 100002, "name": "Ромашка.Доставка", "organizationFormId": 10, "vacanciesOpen": 80},
                {"id": 100003, "name": "Ромашка.Еда", "organizationFormId": 10, "vacanciesOpen": 1043},
            ]
        },
        "paging": None,
    }
}

EMPLOYER_PAGE = {
    "employerInfo": {
        "id": 100001,
        "name": "Ромашка",
        "industries": [{"id": 7, "trl": "Информационные технологии, системная интеграция, интернет"}],
        "description": "<p><strong>Пример описания</strong></p> <p>Вымышленная IT-компания.</p>",
        "site": "https://romashka.test/jobs/",
        "area": {"@id": 1, "name": "Москва"},
        "address": {"rawAddress": "Москва, Примерная улица, 1"},
        "employerCountryCode": "RU",
        "sizeCategory": "MORE_THAN_5000",
        "accreditedITEmployer": True,
        "isTrusted": True,
        "hasDivisions": True,
    },
    "employerOrganizationSchema": {
        "name": "Ромашка",
        "logoUrl": "/employer-logo/100001.png",
        "siteUrl": "https://romashka.test/jobs/",
        "aggregateRating": {"ratingValue": "4.4", "ratingCount": 5250},
    },
    "activeEmployerVacancyCount": 350,
    "employerHasHoldingOrDepartments": True,
}

VACANCY_SEARCH = {
    "vacancySearchResult": {
        "totalResults": 350,
        "paging": None,
        "vacancies": [
            {
                "vacancyId": 900000001,
                "name": "Старший юрисконсульт (онлайн-сервисы)",
                # Present and null on every real row -- the trap this test pins.
                "department": None,
                "company": {
                    "id": 100001,
                    "name": "Ромашка",
                    "department": {"@name": "Финтех ", "@code": "romashka-100001-finteh"},
                },
                "area": {"@id": 1, "name": "Москва", "path": ".113.232.1."},
                "workExperience": "between3And6",
                "professionalRoleIds": [{"professionalRoleId": [145]}],
                "links": {"desktop": "https://hh.ru/vacancy/900000001"},
                "address": {
                    "city": "Москва",
                    "street": "Примерная улица",
                    "building": "1",
                    "displayName": "Москва, Примерная улица, 1",
                    "metroStations": {"metro": [{"@id": 103, "name": "Примерная"}]},
                },
            },
            {
                "vacancyId": 900000002,
                "name": "Системный администратор",
                "department": None,
                "company": {
                    "id": 100001,
                    "name": "Ромашка",
                    "department": {"@name": "Romashka Infrastructure", "@code": "romashka-100001-infra"},
                },
                "area": {"@id": 2, "name": "Санкт-Петербург"},
                "workExperience": "between1And3",
                "professionalRoleIds": [{"professionalRoleId": [96]}],
                "links": {"desktop": "https://hh.ru/vacancy/900000002"},
                "address": {"city": "Санкт-Петербург", "displayName": "Санкт-Петербург, Тестовый проспект, 2"},
            },
        ],
        "clusters": None,
    },
    "searchClusters": {
        "professional_role": {
            "groups": {
                "121": {"count": 54, "order": 1, "title": "Специалист технической поддержки", "id": "121"},
                "96": {"count": 28, "order": 3, "title": "Программист, разработчик", "id": "96"},
            }
        },
        "area": {
            "groups": {
                "1": {"count": 169, "order": 1, "title": "Москва", "id": "1"},
                "2": {"count": 37, "order": 2, "title": "Санкт-Петербург", "id": "2"},
            }
        },
    },
}

VACANCY_HIDDEN = {
    "vacancyView": {
        "vacancyId": 900000001,
        "name": "Старший юрисконсульт (онлайн-сервисы)",
        "description": "<p>Ищем юрисконсульта.</p><ul><li>Python</li></ul>",
        "keySkills": None,
        "department": None,
        "contactInfo": {"contactsHidden": True, "phones": {"phones": []}},
    }
}

VACANCY_EXPOSED = {
    "vacancyView": {
        "vacancyId": 900000002,
        "name": "Системный администратор",
        "description": "<p>Требуется опыт с Active Directory и VMware.</p>",
        "keySkills": {"keySkill": [{"name": "Active Directory"}, {"name": "VMware"}]},
        "contactInfo": {
            "fio": "Пётр Петров",
            "email": "hr@example.ru",
            "phones": {"phones": [{"country": "7", "city": "495", "number": "1234567"}]},
        },
    }
}

ROUTES = {
    "/employers_list": page(EMPLOYERS_LIST),
    "/employer/100001": page(EMPLOYER_PAGE),
    "/search/vacancy": page(VACANCY_SEARCH),
    "/vacancy/900000001": page(VACANCY_HIDDEN),
    "/vacancy/900000002": page(VACANCY_EXPOSED),
}


# install_fake_transport() replaces HHClient._get on the CLASS, so it stays
# replaced until something puts the real one back. The proxy and budget tests
# need the real _get (that is where the behaviour they assert lives), so keep a
# handle on the original.
_REAL_GET = HHClient._get


def restore_transport() -> None:
    HHClient._get = _REAL_GET


class FakeResponse:
    def __init__(self, text: str, status: int = 200):
        self.text = text
        self.status_code = status
        self.ok = 200 <= status < 400

    def json(self):
        return json.loads(self.text)


def install_fake_transport(routes=None, fail_with=None):
    """Replace HHClient._get. Returns the list that records each call."""
    calls: list[tuple] = []
    table = ROUTES if routes is None else routes

    def _get(self, url, headers, params=None):
        calls.append((url, dict(headers or {}), dict(params or {})))
        if fail_with is not None:
            raise fail_with
        for suffix, body in table.items():
            if url.endswith(suffix):
                return FakeResponse(body)
        return FakeResponse("<html>not found</html>", 404)

    HHClient._get = _get
    return calls


# ── tests ────────────────────────────────────────────────────────────────────

def test_employer_search():
    print("employer search")
    install_fake_transport()
    c = HHClient(mode="scrape")
    rows = c.search_employers("Ромашка")
    check("returns every grouped employer", len(rows) == 3, str(rows))
    check("ids and names normalise", rows[0]["id"] == "100001" and rows[0]["name"] == "Ромашка")
    check("open-vacancy count survives as an int", rows[0]["vacancies_open"] == 350)

    best, rest = HHClient._pick_best("Ромашка", rows)
    check("exact name wins the match", best["id"] == "100001", best["name"])
    check("siblings become the related/subsidiary list", len(rest) == 2,
          str([r["name"] for r in rest]))


def test_employer_profile():
    print("employer profile")
    install_fake_transport()
    c = HHClient(mode="scrape")
    p = c.get_employer(100001)
    check("name", p["name"] == "Ромашка")
    check("industry from the trl field", p["industries"] == ["Информационные технологии, системная интеграция, интернет"])
    check("description is flattened out of HTML",
          "<p>" not in p["description"] and "Пример описания" in p["description"], p["description"][:60])
    check("site url", p["site"] == "https://romashka.test/jobs/")
    check("IT accreditation flag", p["it_accredited"] is True)
    check("holding flag drives the subsidiary read", p["has_divisions"] is True)
    check("rating parsed as a number", p["rating"] == 4.4, str(p["rating"]))
    check("open vacancies from activeEmployerVacancyCount", p["open_vacancies"] == 350)


def test_vacancies_and_departments():
    print("vacancies, departments, offices")
    install_fake_transport()
    c = HHClient(mode="scrape")
    vs = c.list_vacancies(100001, cap=50)
    check("both rows parsed", len(vs) == 2, str(len(vs)))

    depts = [v["department"] for v in vs]
    check("department read from company.department, not the null top-level key",
          depts == ["Финтех ", "Romashka Infrastructure"], str(depts))

    a = vs[0]["address"]
    check("address label", a["label"] == "Москва, Примерная улица, 1", str(a))
    check("metro station", a["metro"] == "Примерная", str(a))
    check("second office is a distinct city", vs[1]["address"]["city"] == "Санкт-Петербург")
    check("vacancy url", vs[0]["url"] == "https://hh.ru/vacancy/900000001")
    check("experience band", vs[0]["experience"] == "between3And6")


def test_facets():
    print("facet histograms")
    install_fake_transport()
    c = HHClient(mode="scrape")
    f = c.vacancy_facets(100001)
    check("roles present", "roles" in f, str(list(f)))
    check("counts describe the WHOLE vacancy set, not the fetched page",
          f["roles"][0]["count"] == 54, str(f["roles"][:2]))
    check("roles sorted densest first",
          [r["count"] for r in f["roles"]] == sorted((r["count"] for r in f["roles"]), reverse=True))
    check("areas present", f["areas"][0]["name"] == "Москва", str(f.get("areas")))
    check("api mode returns no facets", HHClient(mode="api", app_token="t").vacancy_facets(100001) == {})


def test_contacts():
    print("recruiter contacts")
    install_fake_transport()
    c = HHClient(mode="scrape")

    hidden = c.get_vacancy(900000001)["contacts"]
    check("withheld contacts report hidden, not 'no recruiters'",
          hidden["hidden"] is True and hidden["phones"] == [], str(hidden))

    shown = c.get_vacancy(900000002)
    ct = shown["contacts"]
    check("published recruiter name", ct["name"] == "Пётр Петров", str(ct))
    check("published recruiter email", ct["email"] == "hr@example.ru")
    check("phone reassembled from country/city/number", ct["phones"] == ["74951234567"], str(ct["phones"]))
    check("hidden is False once anything is published", ct["hidden"] is False)
    check("key skills parsed", shown["key_skills"] == ["Active Directory", "VMware"], str(shown["key_skills"]))


def test_organization_profile():
    print("organization_profile end to end")
    install_fake_transport()
    c = HHClient(mode="scrape")
    r = c.organization_profile("Ромашка", max_vacancies=50, max_details=2)
    check("matched", r["matched"] is True)
    check("source label", r["source"] == "hh.ru-scrape", r["source"])
    check("related carried through", len(r["related"]) == 2)
    check("vacancies carried through", len(r["vacancies"]) == 2)
    check("facets carried through", bool(r["facets"].get("roles")))
    check("details capped and fetched", len(r["details"]) == 2, str(len(r["details"])))
    check("no errors on the happy path", r["errors"] == [], str(r["errors"]))


def test_no_match_is_not_an_error():
    print("unmatched company")
    install_fake_transport({"/employers_list": page({"employersList": {"employers": {}}})})
    c = HHClient(mode="scrape")
    r = c.organization_profile("NoSuchCompanyLtd")
    check("matched is False", r["matched"] is False)
    check("reason is recorded", any("no employer matching" in e for e in r["errors"]), str(r["errors"]))
    check("profile stays empty rather than half-built", r["profile"] == {})


def test_layout_change_is_named():
    print("layout change / interstitial")
    install_fake_transport({"/employer/100001": "<html><body>captcha</body></html>"})
    c = HHClient(mode="scrape")
    try:
        c.get_employer(100001)
        check("missing state blob raises", False, "no exception")
    except HHError as e:
        check("missing state blob names the cause, not 'no data'",
              "InitialState" in str(e), str(e))


def test_proxy_fails_closed():
    print("proxy fail-closed")
    # This one must exercise the REAL _get, because the fail-closed behaviour is
    # the ProxyError->HHError conversion inside it. Patch requests.get instead.
    restore_transport()
    real_get = hh_client.requests.get
    calls: list[dict] = []

    def dead_proxy(url, **kw):
        calls.append(kw)
        raise requests.exceptions.ProxyError("tunnel refused")

    hh_client.requests.get = dead_proxy
    try:
        c = HHClient(mode="scrape", proxy_url="socks5h://127.0.0.1:9050")
        check("proxies configured", c.proxies == {"http": "socks5h://127.0.0.1:9050",
                                                  "https": "socks5h://127.0.0.1:9050"})
        try:
            c.get_employer(100001)
            check("a dead proxy raises instead of going direct", False, "no exception")
        except HHError as e:
            check("a dead proxy raises instead of going direct",
                  "refusing to fall back to direct egress" in str(e), str(e))
        check("the proxy was actually handed to requests",
              bool(calls) and calls[0].get("proxies"), str(calls[:1]))
        check("no direct retry followed the failure", len(calls) == 1, str(len(calls)))

        # And through the never-raises wrapper: the note must reach the operator.
        c2 = HHClient(mode="scrape", proxy_url="socks5h://127.0.0.1:9050")
        r = c2.organization_profile("Ромашка")
        check("organization_profile surfaces the proxy failure",
              any("proxy unreachable" in e for e in r["errors"]), str(r["errors"]))
        check("nothing is reported as matched when egress never worked",
              r["matched"] is False)
    finally:
        hh_client.requests.get = real_get


def test_mode_selection():
    print("transport selection")
    for k in ("HH_MODE", "HH_APP_TOKEN", "HH_CLIENT_ID", "HH_CLIENT_SECRET"):
        os.environ.pop(k, None)
    check("auto with no credential scrapes", HHClient().mode == "scrape")
    check("auto with an app token uses the API", HHClient(app_token="tok").mode == "api")
    check("auto with id+secret uses the API",
          HHClient(client_id="a", client_secret="b").mode == "api")
    check("explicit scrape overrides a credential",
          HHClient(mode="scrape", app_token="tok").mode == "scrape")
    check("source label tracks the mode",
          HHClient(app_token="tok").source_label == "hh.ru-api")

    calls = install_fake_transport({"/employers": json.dumps({"items": []})})
    c = HHClient(mode="api", app_token="tok", api_user_agent="SPOTTER (recon@example.org)")
    try:
        c.search_employers("Example")
    except HHError:
        pass
    check("API path sends the mandatory HH-User-Agent header",
          bool(calls) and "HH-User-Agent" in calls[0][1], str(calls[:1]))
    check("API path sends the Bearer token",
          bool(calls) and calls[0][1].get("Authorization") == "Bearer tok")


def test_api_user_agent_format():
    print("HH-User-Agent format")
    # hh.ru answers HTTP 400 for anything that is not "AppName (contact@email)",
    # regardless of the Bearer token. Catching it here turns a mystery 400 into
    # one sentence naming the variable.
    install_fake_transport({"/employers": json.dumps({"items": []})})

    def refuses(ua, why):
        c = HHClient(mode="api", app_token="tok", api_user_agent=ua)
        try:
            c.search_employers("Example")
            check("refuses %s" % why, False, "no exception")
        except HHError as e:
            check("refuses %s" % why, "HH_USER_AGENT" in str(e), str(e)[:90])

    refuses("", "an unset HH_USER_AGENT")
    refuses("SPOTTER", "an app name with no contact email")
    refuses("SPOTTER (not-an-email)", "parentheses without an address")
    refuses(_BROWSER_UA, "a browser User-Agent")

    ok = HHClient(mode="api", app_token="tok", api_user_agent="HH (email@example.com)")
    check("accepts the documented form 'HH (email@example.com)'",
          ok._api_ua() == "HH (email@example.com)")
    ok2 = HHClient(mode="api", app_token="tok",
                   api_user_agent="SPOTTER-recon/1.0 (recon@example.org)")
    check("accepts a versioned app name with a contact", bool(ok2._api_ua()))

    # The scrape path must not be held hostage to an API-only header.
    install_fake_transport()
    scraped = HHClient(mode="scrape", api_user_agent="").get_employer(100001)
    check("scrape mode works with no HH_USER_AGENT at all", scraped["name"] == "Ромашка")


def test_budget_and_byte_cap():
    print("request budget and byte cap")
    # The budget and the byte cap both live in the real _get, so this exercises
    # it against a streaming stand-in for requests.get.
    restore_transport()
    real_get = hh_client.requests.get
    body = page(EMPLOYER_PAGE).encode("utf-8")

    class StreamResponse:
        def __init__(self):
            self.status_code = 200
            self.ok = True
            self._content = b""
            self._content_consumed = False

        def iter_content(self, n):
            for i in range(0, len(body), n):
                yield body[i:i + n]

        def close(self):
            pass

        @property
        def text(self):
            return self._content.decode("utf-8", "replace")

    hh_client.requests.get = lambda url, **kw: StreamResponse()
    try:
        c = HHClient(mode="scrape", max_requests=2)
        c.get_employer(100001)
        c.get_employer(100001)
        check("budget is reported exhausted", c.budget_exhausted() is True)
        try:
            c.get_employer(100001)
            check("over-budget request is refused", False, "no exception")
        except HHError as e:
            check("over-budget request is refused", "budget exhausted" in str(e), str(e))

        # hh.ru pages run to 3.2 MB; the reader must stop, not buffer the lot.
        capped = HHClient(mode="scrape", max_bytes=64)
        try:
            capped.get_employer(100001)
            check("a truncated page is reported, not silently half-parsed", False, "no exception")
        except HHError as e:
            check("a truncated page is reported, not silently half-parsed",
                  "InitialState" in str(e), str(e))
    finally:
        hh_client.requests.get = real_get


# ── the wrong-company regression ─────────────────────────────────────────────
#
# hh.ru's employer search matches DESCRIPTION text, not just names, so a query
# about a target's field returns organisations that merely work in that field.
# A campaign against an aviation manufacturer produced an Organization card for
# a military-history journal this way: no candidate's name related to the query
# at all, so the old _pick_best fell through to its tie-break -- most open
# vacancies -- and the journal was the busiest recruiter in the set.
#
# Everything below that follows from that pick is why this matters more than one
# wrong heading: the adopted name becomes org_profile.name, org_aliases() feeds
# it back as an alias, and the employment gate then scores every candidate
# person against the WRONG company for the rest of the run.

OFF_TARGET_LIST = {
    "employersList": {
        "totalEmployersFound": 2,
        "employers": {
            "d": [
                # Nothing to do with the target; simply the busiest recruiter
                # whose description mentions the same subject matter.
                {"id": 88001, "name": "Placeholder History Journal", "vacanciesOpen": 41},
                {"id": 88002, "name": "Kompaniya Obrazets",
                 "vacanciesOpen": 3},
            ]
        },
        "paging": None,
    }
}

OFF_TARGET_EMPLOYER = {
    "employerInfo": {
        "id": 88002,
        "name": "Kompaniya Obrazets",
        "industries": [],
        "description": "Proizvodstvo bespilotnykh sistem.",
        # The employer's OWN website, and the target's domain. This is what
        # identifies a legal entity as the company behind a trading name when
        # the two share not one word.
        "site": "https://maket-aero.test",
        "area": {"@id": 1, "name": "Moskva"},
        "employerCountryCode": "RU",
    },
    "employerOrganizationSchema": {"name": "Kompaniya Obrazets"},
}


def test_unrelated_employer_is_refused():
    print("an unrelated employer set is refused, not ranked")
    install_fake_transport({"/employers_list": page(OFF_TARGET_LIST)})
    c = HHClient(mode="scrape")
    ident = employment_evidence.build_identity(
        primary_name="Maket Aero", domain="maket-aero.test")
    r = c.organization_profile("Maket Aero", identity=ident, max_probes=0)
    check("no company is adopted", r["matched"] is False, str(r["profile"]))
    check("...and the profile stays empty rather than half-built",
          r["profile"] == {}, str(r["profile"]))
    check("the busiest unrelated recruiter is NOT the target",
          r["profile"].get("name") != "Placeholder History Journal", str(r["profile"]))
    names = [x["name"] for x in r["rejected"]]
    check("the near misses are reported so the operator can recognise one",
          "Placeholder History Journal" in names, str(names))
    check("...with a reason, not a bare empty card", bool(r["match_reason"]),
          r["match_reason"])
    check("an unrelated employer is never offered as a subsidiary",
          all("History Journal" not in x.get("name", "") for x in r["related"]),
          str(r["related"]))
    check("...it is kept as a mention instead of being discarded",
          any("History Journal" in x.get("name", "") for x in r["mentions"]),
          str(r["mentions"]))


def test_legal_entity_is_searched_and_matched():
    print("the operator's other identifiers are searched")
    calls = install_fake_transport({"/employers_list": page(OFF_TARGET_LIST),
                                    "/employer/88002": page(OFF_TARGET_EMPLOYER)})
    c = HHClient(mode="scrape")
    # Exactly what Objectives holds on the campaign that failed: the trading
    # name, the legal entity and the domain.
    ident = employment_evidence.build_identity(
        primary_name="Maket Aero",
        additional_ids="maket-aero.test, Kompaniya Obrazets",
        company_email="info@maket-aero.test",
        domain="maket-aero.test")
    r = c.organization_profile("Maket Aero", identity=ident)
    check("the legal entity is matched, not the busiest recruiter",
          r["profile"].get("name") == "Kompaniya Obrazets",
          str(r["profile"].get("name")))
    check("matched", r["matched"] is True)
    check("every identifier was queried, not just the display name",
          len(r["queries"]) >= 2, str(r["queries"]))
    check("the card can state WHY this is the target",
          bool(r["match_evidence"]), str(r["match_evidence"]))
    queried = [params.get("query") for _u, _h, params in calls if params.get("query")]
    check("the legal entity reached the wire", 
          any("Obrazets" in str(q) for q in queried), str(queried))


def test_domain_probe_identifies_a_renamed_entity():
    print("a candidate serving the target's domain is the target")
    install_fake_transport({"/employers_list": page(OFF_TARGET_LIST),
                            "/employer/88002": page(OFF_TARGET_EMPLOYER)})
    c = HHClient(mode="scrape")
    # ONLY the trading name and the domain -- the operator never typed the legal
    # entity. The name comparison cannot bridge that gap, so the probe fetches
    # the strongest near misses and checks their website.
    ident = employment_evidence.build_identity(
        primary_name="Maket Aero", company_email="info@maket-aero.test",
        domain="maket-aero.test")
    r = c.organization_profile("Maket Aero", identity=ident)
    check("the entity serving the target's domain is adopted",
          r["profile"].get("name") == "Kompaniya Obrazets",
          str(r["profile"].get("name")))
    check("...and the evidence names the domain, not a name similarity",
          any("maket-aero.test" in e for e in r["match_evidence"]),
          str(r["match_evidence"]))


def main() -> int:
    for t in (
        test_employer_search,
        test_employer_profile,
        test_vacancies_and_departments,
        test_facets,
        test_contacts,
        test_organization_profile,
        test_unrelated_employer_is_refused,
        test_legal_entity_is_searched_and_matched,
        test_domain_probe_identifies_a_renamed_entity,
        test_no_match_is_not_an_error,
        test_layout_change_is_named,
        test_proxy_fails_closed,
        test_mode_selection,
        test_api_user_agent_format,
        test_budget_and_byte_cap,
    ):
        t()
    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all hh_client checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
