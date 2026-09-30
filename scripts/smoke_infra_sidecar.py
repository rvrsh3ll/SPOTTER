#!/usr/bin/env python3
"""Offline smoke test for the egress control-plane sidecar (ssh-tunnel-api/app.py).

Covers the three things that have no visible failure mode in the UI:

  * torrc generation — a country code carrying a newline would append arbitrary
    Tor directives, and a torrc that quietly drops ExitNodes looks exactly like
    one that honours it;
  * proxy-spec resolution — socks5 vs socks5h decides whether DNS resolves at
    the proxy or leaks to the local resolver, and both "work";
  * egress response parsing — no egress source's shape is contractually stable,
    so the parser has to survive JSON, nested JSON, bare text and an HTML page,
    must never report a private address as the egress identity, and must fill
    the country from the geo second hop when the source that answered is
    IP-only (the failure that showed as "geo unavailable from https://ip.me/");
  * key_path root enforcement — the allowed roots are paths inside the
    container, so the host path a key really lives at is absolute, exists, and
    is still refused; the rejection has to explain that by itself.

No network, no container, no Tor binary required: every outbound call is
monkeypatched. Needs only flask on the import path.

    python3 scripts/smoke_infra_sidecar.py

Exit 0 = pass, 1 = assertion failure, 2 = could not run.
"""

from __future__ import annotations

import io
import os
import stat
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="spotter-tor-smoke-")
# Must be set BEFORE the import: app.py resolves its config at module load.
os.environ.setdefault("TOR_DATA_DIR", _TMP)
os.environ.setdefault("TOR_GEOIP_FILE", os.path.join(_TMP, "missing-geoip"))
os.environ.setdefault("TOR_GEOIP6_FILE", os.path.join(_TMP, "missing-geoip6"))
# A real token, not "": /tunnel/* now fails closed when it is unset, so an
# empty value here would 503 every route below instead of exercising it.
_SMOKE_TOKEN = "smoke-tunnel-token"
os.environ.setdefault("TUNNEL_API_TOKEN", _SMOKE_TOKEN)
os.environ.setdefault("TOR_RUN_AS", "")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ssh-tunnel-api"))

try:
    import app  # noqa: E402
except ImportError as exc:  # pragma: no cover - environment problem, not a test failure
    print(f"Could not import ssh-tunnel-api/app.py: {exc}")
    print("Run it where flask is available, e.g.:")
    print("  docker compose -p spotter exec -T ssh-tunnel-api python3 - "
          "< scripts/smoke_infra_sidecar.py")
    sys.exit(2)

FAILURES = 0
CHECKS = 0


def _client():
    """A test client that carries the API token on every request.

    app.py reads TUNNEL_API_TOKEN at import time, so the value asserted here is
    the one the module already resolved; environ_base applies the header to
    every call from this client rather than each call site repeating it.
    """
    c = app.app.test_client()
    c.environ_base["HTTP_X_TUNNEL_TOKEN"] = app._API_TOKEN
    return c


def ok(cond, label, extra=None) -> bool:
    global FAILURES, CHECKS
    CHECKS += 1
    if cond:
        return True
    FAILURES += 1
    print(f"  FAIL  {label}" + (f"\n        got: {extra!r}" if extra is not None else ""))
    return False


def section(name: str) -> None:
    print(f"\n── {name}")


# ── country sanitising ──────────────────────────────────────────────────────
section("country codes")
codes, err = app._normalise_countries(["US", "de", "US"])
ok(codes == ["us", "de"] and not err, "lowercases and dedupes", (codes, err))
codes, err = app._normalise_countries("us, nl ro")
ok(codes == ["us", "nl", "ro"] and not err, "accepts a comma/space string", (codes, err))
codes, err = app._normalise_countries(["{de}"])
ok(codes == ["de"], "tolerates torrc brace syntax", codes)
codes, err = app._normalise_countries([])
ok(codes == [] and not err, "empty is valid — Tor chooses freely", (codes, err))

_, err = app._normalise_countries(["usa"])
ok(bool(err), "rejects a three-letter code", err)
# The injection that matters: a torrc is newline-delimited config.
_, err = app._normalise_countries(["us\nExitNodes {ru}"])
ok(bool(err), "rejects a code carrying a newline", err)
_alphabet = "abcdefghijklmnopqrstuvwxyz"
_many = [a + b for a in _alphabet for b in _alphabet][: app._TOR_MAX_COUNTRIES + 1]
_, err = app._normalise_countries(_many)
ok(bool(err), "caps the selection size", err)

# ── torrc generation ────────────────────────────────────────────────────────
section("torrc")
path = app._tor_write_torrc(9050, ["de", "ro"], ["nl"], True)
body = open(path, encoding="utf-8").read()
ok("EntryNodes {de},{ro}" in body, "entry countries become an EntryNodes line", body)
ok("ExitNodes {nl}" in body, "exit countries become an ExitNodes line", body)
ok("StrictNodes 1" in body, "strict is emitted when countries are set")
ok("SocksPort 0.0.0.0:9050" in body or "SocksPort " in body, "SocksPort is written", body)
ok("ClientOnly 1" in body, "runs client-only — never a relay")
ok(any(l.startswith("SocksPolicy") for l in body.splitlines()),
   "a SocksPolicy is always written", body)
ok("reject *" in body, "the policy ends in a reject", body)

path = app._tor_write_torrc(9050, [], [], True)
body = open(path, encoding="utf-8").read()
ok("StrictNodes" not in body, "strict alone is dropped — it means nothing without nodes", body)
ok("EntryNodes" not in body and "ExitNodes" not in body, "no node lines when nothing is selected")

# ── proxy spec resolution ───────────────────────────────────────────────────
section("proxy spec")
proxies, via, err = app._proxy_from_spec(None)
ok(proxies is None and via == "direct" and not err, "absent spec is direct, not an error", (via, err))
proxies, via, err = app._proxy_from_spec({"type": "none"})
ok(proxies is None and not err, "type=none is direct", (via, err))
proxies, via, err = app._proxy_from_spec({"enabled": False, "type": "socks5",
                                          "socks": {"host": "h", "port": 1080}})
ok(proxies is None, "a disabled profile is not used", proxies)

proxies, via, err = app._proxy_from_spec({"type": "http", "http_url": "http://p:8080"})
ok(proxies == {"http": "http://p:8080", "https": "http://p:8080"}, "http proxy maps both schemes", proxies)
_, _, err = app._proxy_from_spec({"type": "http", "http_url": "p:8080"})
ok(bool(err), "an http_url without a scheme is rejected", err)

proxies, via, err = app._proxy_from_spec(
    {"type": "socks5", "socks": {"host": "10.0.0.5", "port": 1080, "username": "u", "password": "p@ss"}})
ok(proxies and proxies["https"].startswith("socks5h://"),
   "SOCKS resolves DNS remotely (socks5h)", proxies)
ok(proxies and "p%40ss" in proxies["https"], "credentials are percent-encoded", proxies)

proxies, via, err = app._proxy_from_spec({"type": "tor"})
ok(proxies and proxies["https"] == f"socks5h://{app._PROXY_HOST}:{app._TOR_SOCKS_PORT}",
   "tor falls back to the managed client's endpoint", proxies)
ok(via == "Tor", "and is labelled Tor", via)

_, _, err = app._proxy_from_spec({"type": "socks5", "socks": {"host": "h;rm -rf /", "port": 1080}})
ok(bool(err), "a hostile SOCKS host is rejected", err)
_, _, err = app._proxy_from_spec({"type": "wireguard"})
ok(bool(err), "an unknown proxy type is rejected", err)

# ── egress response parsing ─────────────────────────────────────────────────
# Sample addresses are deliberately NOT the RFC 5737 documentation ranges
# (192.0.2/198.51.100/203.0.113): CPython made those `is_private` (backported
# into 3.11.10+), so _valid_public_ip rejects them — correctly, since a
# documentation address is never a real egress IP. Using them here made every
# assertion in this section fail permanently against the deployed interpreter.
section("ip parsing")
ok(app._valid_public_ip("93.184.216.34") == "93.184.216.34", "accepts a public v4")
ok(app._valid_public_ip("192.168.1.5") == "", "rejects RFC1918 — that is never the egress IP")
ok(app._valid_public_ip("127.0.0.1") == "", "rejects loopback")
ok(app._valid_public_ip("not-an-ip") == "", "rejects junk")
ok(app._first_ip_in_text("Your IP address is 93.184.216.35 (approx)") == "93.184.216.35",
   "pulls an IP out of an HTML/text page")
ok(app._first_ip_in_text("router at 10.0.0.1, you are 93.184.216.35") == "93.184.216.35",
   "skips a private address on the way to the public one")

ok(app._ip_from_payload({"ip": "93.184.216.34"}) == "93.184.216.34", "reads a flat ip field")
ok(app._ip_from_payload({"query": "93.184.216.34"}) == "93.184.216.34", "reads an aliased ip field")
ok(app._ip_from_payload({"data": {"ip_address": "93.184.216.34"}}) == "93.184.216.34",
   "reads a nested ip field")

geo = app._normalise_geo({"country_code": "nl", "city": "Amsterdam", "asn": "AS64500",
                          "org": "Example B.V."})
ok(geo.get("country_code") == "NL", "country code is upper-cased", geo)
ok(geo.get("country") == "Netherlands", "a bare country code still yields a country name", geo)
ok(geo.get("city") == "Amsterdam" and geo.get("asn") == "AS64500", "city/asn survive", geo)
geo = app._normalise_geo({"location": {"city": "Berlin", "country_name": "Germany"}})
ok(geo.get("city") == "Berlin" and geo.get("country") == "Germany",
   "nested geo is flattened", geo)
ok(app._normalise_geo("just a string") == {}, "a non-dict payload yields no geo")

# The three default geo-bearing sources, in their real 2026-09-20 shapes. These
# are what keep the strip from falling back to "geo unavailable", so a vendor
# renaming a field has to fail HERE rather than as a blank bar mid-engagement.
geo = app._normalise_geo({"ip": "93.184.216.34", "country": "Germany", "country_iso": "DE",
                          "region_name": "Berlin", "city": "Berlin", "asn": "AS64500",
                          "asn_org": "Example Transit", "time_zone": "Europe/Berlin"})
ok(geo.get("country_code") == "DE" and geo.get("city") == "Berlin",
   "ifconfig.co/json: country_iso + city are read", geo)
ok(geo.get("asn") == "AS64500" and geo.get("org") == "Example Transit",
   "ifconfig.co/json: asn_org lands in org", geo)

geo = app._normalise_geo({"ip": "93.184.216.34", "success": True, "country": "Germany",
                          "country_code": "DE", "region": "Berlin", "city": "Berlin",
                          "connection": {"asn": 64500, "org": "Example Transit",
                                         "isp": "Example ISP"},
                          "timezone": {"id": "Europe/Berlin", "abbr": "CET"}})
ok(geo.get("country_code") == "DE" and geo.get("city") == "Berlin",
   "ipwho.is: top-level geo is read", geo)
ok(geo.get("asn") == "AS64500",
   "ipwho.is: a bare numeric ASN is prefixed, so the strip never renders '64500'", geo)
ok(geo.get("org") == "Example Transit", "ipwho.is: nested connection.org is flattened out", geo)
ok(geo.get("timezone") == "Europe/Berlin", "ipwho.is: nested timezone.id is read", geo)

geo = app._normalise_geo({"ip": "93.184.216.34", "company": "Example Corp",
                          "asn": "AS64500 Example Transit", "city": "Berlin",
                          "region": "Berlin", "country": "Germany"})
ok(geo.get("org") == "Example Corp", "api.ipapi.is: company is read as the org", geo)
ok(geo.get("country") == "Germany" and geo.get("city") == "Berlin",
   "api.ipapi.is: country/city are read", geo)

# A lookup that declines to place the address answers HTTP 200 with a body that
# still carries stray fields. Half a location on this bar is worse than none.
ok(app._normalise_geo({"ip": "93.184.216.34", "success": False,
                       "message": "Reserved range", "country": "-"}) == {},
   "an explicit success:false yields NO geo rather than a half-built one")

# ── the /tunnel/egress route, with requests stubbed ─────────────────────────
section("/tunnel/egress")


class _FakeResp:
    def __init__(self, text, ctype="text/plain", status=200):
        self.text = text
        self.status_code = status
        self.headers = {"content-type": ctype}

    def json(self):
        import json as _json
        return _json.loads(self.text)


class _FakeSession:
    def __init__(self, owner):
        self._owner = owner
        self.trust_env = True

    def get(self, url, headers=None, proxies=None, timeout=None, allow_redirects=True):
        self._owner.seen.append({"url": url, "headers": headers or {}, "proxies": proxies})
        return self._owner._handler(url, headers or {})


class _FakeRequests:
    def __init__(self, handler):
        self._handler = handler
        self.seen = []
        self.sessions = []

    def Session(self):  # noqa: N802 — mirrors the requests API
        s = _FakeSession(self)
        self.sessions.append(s)
        return s


def run_egress(handler, body):
    fake = _FakeRequests(handler)
    sys.modules["requests"] = fake
    try:
        with _client() as client:
            resp = client.post("/tunnel/egress", json=body)
            return resp.get_json(), fake
    finally:
        sys.modules.pop("requests", None)


data, fake = run_egress(
    lambda url, h: _FakeResp('{"ip":"93.184.216.34","country_code":"nl","city":"Amsterdam"}',
                             "application/json"),
    {"proxy": {"type": "none"}, "user_agent": "curl/8.5.0"})
ok(data["ok"] is True and data["ip"] == "93.184.216.34", "JSON answer is parsed", data)
ok(data["geo"].get("city") == "Amsterdam", "geo comes back with it", data.get("geo"))
ok(data["proxied"] is False and data["via"] == "direct", "an unproxied check says so", data)
ok(fake.seen[0]["headers"].get("User-Agent") == "curl/8.5.0",
   "the requested User-Agent is the one sent", fake.seen[0]["headers"])
ok(fake.sessions and fake.sessions[0].trust_env is False,
   "env proxies are disabled — 'direct' must really mean direct",
   fake.sessions and fake.sessions[0].trust_env)

_geo_url = app._EGRESS_GEO_URL
app._EGRESS_GEO_URL = ""  # second hop refused: the IP-only source is the whole answer
try:
    data, _ = run_egress(lambda url, h: _FakeResp("93.184.216.34\n"),
                         {"proxy": {"type": "none"}})
    ok(data["ok"] is True and data["ip"] == "93.184.216.34", "a bare-text answer is parsed", data)
    ok(data["geo"] == {}, "and reports no geo rather than inventing one", data.get("geo"))
    ok(data["geo_source"] == "", "with no geo_source claimed", data.get("geo_source"))
finally:
    app._EGRESS_GEO_URL = _geo_url

# ── the geo second hop ──────────────────────────────────────────────────────
# Only fires when the source that answered was IP-only. This is the path that
# used to leave the strip blank, so it is asserted end-to-end: the hop must run,
# must reuse the SAME proxy as the first hop, and must attribute itself.
section("/tunnel/egress — geo second hop")
app._EGRESS_GEO_URL = "https://geo.example.test/{ip}"
try:
    def _ip_only_then_geo(url, h):
        if url.startswith("https://geo.example.test/"):
            return _FakeResp('{"success":true,"country":"Germany","country_code":"DE",'
                             '"city":"Berlin","connection":{"asn":64500,"org":"Ex"}}',
                             "application/json")
        return _FakeResp("93.184.216.34\n")

    data, fake = run_egress(_ip_only_then_geo,
                            {"proxy": {"type": "socks5",
                                       "socks": {"host": "10.0.0.5", "port": 1080}}})
    ok(data["ip"] == "93.184.216.34", "the IP still comes from the first hop", data)
    ok(data["geo"].get("country_code") == "DE" and data["geo"].get("city") == "Berlin",
       "the second hop fills in the country an IP-only source could not", data.get("geo"))
    ok(data["geo_source"] == "https://geo.example.test/{ip}",
       "and the response says where the location came from", data.get("geo_source"))
    geo_calls = [c for c in fake.seen if c["url"].startswith("https://geo.example.test/")]
    ok(len(geo_calls) == 1 and geo_calls[0]["url"].endswith("/93.184.216.34"),
       "{ip} is substituted, and the hop runs exactly once", [c["url"] for c in geo_calls])
    ok(geo_calls and geo_calls[0]["proxies"] == {"http": "socks5h://10.0.0.5:1080",
                                                 "https": "socks5h://10.0.0.5:1080"},
       "the geo hop takes the SAME proxy — it must never leak around Tor",
       geo_calls and geo_calls[0]["proxies"])

    # A geo source that answers 200 but declines to place the IP.
    def _ip_only_then_refusal(url, h):
        if url.startswith("https://geo.example.test/"):
            return _FakeResp('{"success":false,"message":"Reserved range"}', "application/json")
        return _FakeResp("93.184.216.34\n")

    data, _ = run_egress(_ip_only_then_refusal, {"proxy": {"type": "none"}})
    ok(data["ok"] is True and data["geo"] == {},
       "a declined geo lookup leaves the location empty, not half-built", data.get("geo"))
    ok(data["geo_source"] == "",
       "and claims no geo_source for a hop that produced nothing", data.get("geo_source"))
    ok(any("could not place" in e for e in data["errors"]),
       "errors[] explains the blank rather than leaving the operator guessing",
       data.get("errors"))

    # A first hop that already carries geo must NOT trigger the second one.
    data, fake = run_egress(
        lambda url, h: _FakeResp('{"ip":"93.184.216.34","country_iso":"DE","city":"Berlin"}',
                                 "application/json"),
        {"proxy": {"type": "none"}})
    ok(data["geo"].get("country_code") == "DE", "a geo-bearing first hop is used as-is", data.get("geo"))
    ok(not [c for c in fake.seen if c["url"].startswith("https://geo.example.test/")],
       "and the second hop does not fire — it is not a cost on the normal path",
       [c["url"] for c in fake.seen])
finally:
    app._EGRESS_GEO_URL = _geo_url

section("/tunnel/egress")

data, _ = run_egress(
    lambda url, h: _FakeResp("<html><body>Your IP is 93.184.216.35</body></html>", "text/html"),
    {"proxy": {"type": "none"}})
ok(data["ip"] == "93.184.216.35", "an HTML page still yields the address", data)

data, _ = run_egress(lambda url, h: _FakeResp("<html>no address here</html>", "text/html"),
                     {"proxy": {"type": "none"}})
ok(data["ok"] is False and data["ip"] == "", "an unparseable answer is a reported failure", data)
ok(len(data["errors"]) >= 1, "and errors[] says which URL failed and why", data.get("errors"))
ok(bool(data["error"]), "with a human-readable error string", data.get("error"))


def _boom(url, h):
    raise RuntimeError("Connection refused")


data, _ = run_egress(_boom, {"proxy": {"type": "socks5",
                                       "socks": {"host": "10.0.0.5", "port": 1080}}})
ok(data["ok"] is False, "a dead proxy is a failure, never a silent direct answer", data)
ok(any("Connection refused" in e for e in data["errors"]),
   "and the transport error is reported verbatim", data.get("errors"))
ok(data["proxied"] is True, "the response still records that a proxy was requested", data)

data, _ = run_egress(lambda url, h: _FakeResp("93.184.216.34"),
                     {"proxy": {"type": "http", "http_url": "not-a-url"}})
ok(data is not None and data.get("code") == "invalid_request",
   "an invalid proxy spec is rejected before any request is made", data)

# ── country catalogue ───────────────────────────────────────────────────────
section("/tunnel/tor/countries")
with _client() as client:
    cat = client.get("/tunnel/tor/countries").get_json()
ok(cat["ok"] is True and cat["count"] > 100, "falls back to the built-in ISO list", cat.get("count"))
ok(cat["source"] == "iso3166-builtin", "and says the geoip file was not the source", cat.get("source"))
ok(all(len(c["code"]) == 2 and c["name"] for c in cat["countries"]),
   "every entry has a two-letter code and a name")

geoip = os.path.join(_TMP, "geoip-real")
with open(geoip, "w", encoding="utf-8") as fh:
    fh.write("# comment\n16777216,16777471,AU\n16777472,16777727,CN\n999,1000,??\n")
app._TOR_GEOIP = geoip
app._countries_cache["codes"] = None
cat = app._country_catalogue()
ok([c["code"] for c in cat["countries"]] == ["au", "cn"],
   "a real geoip file is the authority when present", cat["countries"])
ok(cat["countries"][0]["name"] == "Australia", "codes are named from the ISO table", cat["countries"])

# ── SSH key path roots ──────────────────────────────────────────────────────
# The roots are paths inside the container, so the host path a key actually
# lives at is absolute, exists, and is still wrong. The rejection has to say so
# on its own — an operator reading it has no reason to suspect a mount.
section("key_path roots")
# Two roots now: the read-only SSH_KEY_DIR mount and the writable one the
# Infrastructure tab uploads into. Both must be readable for tunnel start.
ok("/ssh-keys" in app._ALLOWED_KEY_ROOTS,
   "the read-only container mount point is an allowed root", app._ALLOWED_KEY_ROOTS)
ok(app._UPLOAD_KEY_ROOT in app._ALLOWED_KEY_ROOTS,
   "and the upload root is too \u2014 otherwise a key could be uploaded and then "
   "refused by /tunnel/start", (app._UPLOAD_KEY_ROOT, app._ALLOWED_KEY_ROOTS))
ok(app._path_allowed(app._UPLOAD_KEY_ROOT + "/uploaded") is True,
   "a key under the upload root is accepted")
ok(app._path_allowed("/ssh-keys/id_ed25519") is True, "a key under the root is accepted")
ok(app._path_allowed("/root/.ssh/id_ed25519") is False, "a host path is rejected")
ok(app._path_allowed("ssh-keys/id_ed25519") is False, "a relative path is rejected")
ok(app._path_allowed("~/.ssh/id_ed25519") is False, "a ~-prefixed path is rejected")
ok(app._path_allowed("") is False, "an empty path is rejected")
ok(app._path_allowed("/ssh-keys/../etc/passwd") is False,
   "traversal out of the root is rejected after realpath()")

_base = {"ssh_user": "op", "ssh_host": "10.0.0.9", "local_socks_port": 1080, "auth_method": "key"}
res = app._validate_start_payload(dict(_base, key_path="/root/.ssh/id_ed25519"))
ok(res["ok"] is False, "the validator refuses a host key path", res)
msg = res.get("error", "")
ok("/ssh-keys" in msg, "and the message names the configured root", msg)
ok("/root/.ssh/id_ed25519" in msg, "and echoes the path it was given", msg)
ok("/id_ed25519" in msg and any(r in msg for r in app._ALLOWED_KEY_ROOTS),
   "and suggests the translated container path under an allowed root", msg)

# The whole chain, with a root that exists on this host so the existence check
# is reached rather than short-circuited by the root rule.
_keydir = os.path.join(_TMP, "keys")
os.makedirs(_keydir, exist_ok=True)
_keyfile = os.path.join(_keydir, "id_engagement")
with open(_keyfile, "w", encoding="utf-8") as fh:
    fh.write("not a real key\n")
app._ALLOWED_KEY_ROOTS = [_keydir]

res = app._validate_start_payload(dict(_base, key_path=_keyfile))
ok(res["ok"] is True, "a key inside the root validates end to end", res.get("error"))

res = app._validate_start_payload(dict(_base, key_path=os.path.join(_keydir, "absent")))
ok(res["ok"] is False, "a missing key inside the root is still refused", res)
ok("does not exist" in res.get("error", ""),
   "with the existence error, not the root error", res.get("error"))
ok("absent" in res.get("error", ""), "and names the file it could not find", res.get("error"))

# ── key discovery (/tunnel/keys) ────────────────────────────────────────────
# The saved key path outlives the deployment it was written for, so the tab has
# to be able to ask what the container can actually reach. Everything here is
# crafted on disk: no ssh-keygen, no container, no network.
section("key discovery")

import base64 as _b64  # noqa: E402


def _openssh_key(cipher: str) -> str:
    """A key file whose openssh-key-v1 header names `cipher` ("none" = plain)."""
    blob = b"openssh-key-v1\x00" + len(cipher).to_bytes(4, "big") + cipher.encode()
    body = _b64.b64encode(blob).decode()
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"


_kd = os.path.join(_TMP, "keydisco")
os.makedirs(_kd, exist_ok=True)
_files = {
    "plain":            _openssh_key("none"),
    "locked":           _openssh_key("aes256-ctr"),
    "legacy":           "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,1\n\nzzz\n-----END RSA PRIVATE KEY-----\n",
    "pkcs8":            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nzzz\n-----END ENCRYPTED PRIVATE KEY-----\n",
    "plain.pub":        "ssh-ed25519 AAAA test\n",
    "authorized_keys":  "ssh-ed25519 AAAA someone\n",
    "known_hosts":      "host ssh-ed25519 AAAA\n",
    "config":           "Host *\n",
    ".hidden":          _openssh_key("none"),
    "notes.txt":        "just a file\n",
}
for _name, _body in _files.items():
    with open(os.path.join(_kd, _name), "w", encoding="utf-8") as fh:
        fh.write(_body)

app._ALLOWED_KEY_ROOTS = [_kd]
found = app._list_available_keys()
names = sorted(k["name"] for k in found)
ok(names == ["legacy", "locked", "pkcs8", "plain"],
   "only private keys are listed \u2014 .pub, authorized_keys, known_hosts, config, dotfiles and plain files are not",
   names)

by = {k["name"]: k for k in found}
ok(by["plain"]["encrypted"] is False, "an openssh key with cipher 'none' reads as unencrypted", by["plain"])
ok(by["locked"]["encrypted"] is True, "a cipher other than 'none' reads as encrypted", by["locked"])
ok(by["legacy"]["encrypted"] is True, "a legacy PEM with Proc-Type ENCRYPTED reads as encrypted", by["legacy"])
ok(by["pkcs8"]["encrypted"] is True, "BEGIN ENCRYPTED PRIVATE KEY reads as encrypted", by["pkcs8"])
ok(all(k["path"].startswith(_kd + os.sep) for k in found),
   "every listed path is absolute and inside the root", [k["path"] for k in found])

with _client() as client:
    body = client.get("/tunnel/keys").get_json()
ok(body["ok"] is True and body["count"] == 4, "the endpoint reports the same set", body.get("count"))
ok(body["roots"] == [_kd], "and names the roots it searched", body.get("roots"))

# A garbage file that merely contains the words is not classified as encrypted:
# "has a passphrase" and "is not a key" must not collapse into one answer.
_junk = os.path.join(_kd, "junk")
with open(_junk, "w", encoding="utf-8") as fh:
    fh.write("PRIVATE KEY but not really\n")
ok(app._key_is_encrypted(_junk) is False, "an unparseable file is not reported as encrypted",
   app._key_is_encrypted(_junk))
ok(app._key_is_encrypted(os.path.join(_kd, "nonexistent")) is None,
   "a missing file reports unknown, not a guess")

# ── key upload (POST/DELETE /tunnel/keys) ───────────────────────────────────
# The first write path this service has ever had. What matters is that it cannot
# be made to write outside the upload root, cannot be driven by a non-admin, and
# leaves the key at 0600 — a key readable by anyone else on the host is a finding
# in itself. All offline: crafted bytes, a temp dir, no ssh-keygen required for
# the assertions that matter.
section("key upload")

_up = os.path.join(_TMP, "uploads")
_ro = os.path.join(_TMP, "mounted-ro")
os.makedirs(_up, exist_ok=True)
os.makedirs(_ro, exist_ok=True)
with open(os.path.join(_ro, "mounted"), "w", encoding="utf-8") as fh:
    fh.write(_openssh_key("none"))

app._ALLOWED_KEY_ROOTS = [_up, _ro]
app._UPLOAD_KEY_ROOT = _up

_ADMIN = {"X-Spotter-Admin": "1"}


def _post_key(name, body, overwrite=False, headers=_ADMIN):
    payload = {"filename": name, "key_b64": _b64.b64encode(body).decode()}
    if overwrite:
        payload["overwrite"] = True
    with _client() as c:
        r = c.post("/tunnel/keys", json=payload, headers=headers)
        return r.status_code, (r.get_json() or {})


_plain = _openssh_key("none").encode()
_locked = _openssh_key("aes256-ctr").encode()

# --- the admin gate -------------------------------------------------------
st, res = _post_key("nogate", _plain, headers={})
ok(st == 403 and res.get("code") == "forbidden",
   "upload without the admin header is refused", (st, res.get("code")))
st, res = _post_key("nogate", _plain, headers={"X-Spotter-Admin": "0"})
ok(st == 403, "and X-Spotter-Admin: 0 is refused too", st)
ok(not os.path.exists(os.path.join(_up, "nogate")), "the refused upload wrote nothing")

with _client() as c:
    st = c.delete("/tunnel/keys/mounted", headers={"X-Spotter-Admin": "0"}).status_code
ok(st == 403, "delete is admin-gated as well", st)

# --- the happy path -------------------------------------------------------
st, res = _post_key("engagement", _plain)
ok(st == 200 and res.get("ok") is True, "a valid key uploads", (st, res.get("error")))
_dest = os.path.join(_up, "engagement")
ok(os.path.isfile(_dest), "and lands in the upload root", res.get("path"))
ok(res.get("path") == _dest, "the response names the CONTAINER path to use", res.get("path"))
ok(stat.S_IMODE(os.stat(_dest).st_mode) == 0o600,
   "the key is written 0600 — never readable by anyone else on the host",
   oct(stat.S_IMODE(os.stat(_dest).st_mode)))
ok(res.get("encrypted") is False, "an unencrypted key is reported as such", res.get("encrypted"))

st, res = _post_key("locked-key", _locked)
ok(st == 200 and res.get("encrypted") is True,
   "a passphrase-protected key is flagged, so the UI can pick the right auth mode",
   res.get("encrypted"))

# It must be visible to the reader the moment it lands; a key that uploads but
# does not appear in /tunnel/keys is indistinguishable from a silent failure.
_listed = sorted(k["name"] for k in app._list_available_keys())
ok(_listed == ["engagement", "locked-key", "mounted"],
   "an uploaded key is immediately listed alongside the mounted ones", _listed)

# --- no temp files left behind -------------------------------------------
ok(not [f for f in os.listdir(_up) if f.startswith(".upload-")],
   "no partial temp file is left in the upload root", os.listdir(_up))

# --- overwrite protection -------------------------------------------------
st, res = _post_key("engagement", _locked)
ok(st == 409 and res.get("code") == "key_exists",
   "re-uploading an existing name is refused by default", (st, res.get("code")))
ok(app._key_is_encrypted(_dest) is False, "and the original is untouched")
st, res = _post_key("engagement", _locked, overwrite=True)
ok(st == 200 and app._key_is_encrypted(_dest) is True,
   "overwrite replaces it only when explicitly asked", res.get("error"))
ok(stat.S_IMODE(os.stat(_dest).st_mode) == 0o600, "and the replacement is still 0600")

# --- filenames that must not be accepted ----------------------------------
for _bad, _why in [
    ("../escape",          "traversal"),
    ("../../etc/passwd",   "deep traversal"),
    ("/etc/passwd",        "an absolute path"),
    (".hidden",            "a dotfile"),
    ("authorized_keys",    "an SSH config file"),
    ("known_hosts",        "a known_hosts"),
    ("config",             "an SSH config"),
    ("key.pub",            "a public half"),
    ("key.bak",            "a backup suffix"),
    ("",                   "an empty name"),
    ("a" * 65,             "an over-long name"),
    ("sp ace",             "a name with a space"),
    ("semi;colon",         "a name with a shell metacharacter"),
]:
    st, res = _post_key(_bad, _plain)
    ok(st == 400, f"{_why} is refused ({_bad!r})", (st, res.get("code")))

# Nothing above may have escaped the upload root.
ok(sorted(os.listdir(_up)) == ["engagement", "locked-key"],
   "after every rejected filename the upload root holds only the two real keys",
   sorted(os.listdir(_up)))
ok(sorted(os.listdir(_ro)) == ["mounted"], "and the read-only root is untouched",
   sorted(os.listdir(_ro)))

# --- bodies that must not be accepted -------------------------------------
st, res = _post_key("notakey", b"ssh-ed25519 AAAA notaprivatekey\n")
ok(st == 400 and res.get("code") == "not_a_private_key",
   "a public key body is refused", (st, res.get("code")))
st, res = _post_key("empty", b"")
ok(st == 400, "an empty body is refused", st)

with _client() as c:
    r = c.post("/tunnel/keys", json={"filename": "badb64", "key_b64": "!!!not base64!!!"},
               headers=_ADMIN)
ok(r.status_code == 400 and (r.get_json() or {}).get("code") == "invalid_encoding",
   "a body that is not valid base64 is refused", r.status_code)

# Oversize is rejected on the ENCODED length, before the decode is attempted.
_huge = "A" * (app._MAX_KEY_BYTES * 2 + 4)
with _client() as c:
    r = c.post("/tunnel/keys", json={"filename": "huge", "key_b64": _huge}, headers=_ADMIN)
ok(r.status_code == 413 and (r.get_json() or {}).get("code") == "key_too_large",
   "an oversize body is refused before it is decoded", r.status_code)
ok(not os.path.exists(os.path.join(_up, "huge")), "and nothing is written for it")

# --- CRLF normalisation ---------------------------------------------------
# A key pasted out of Windows fails inside ssh with nothing useful on stderr,
# which is indistinguishable from a wrong key.
_crlf = _openssh_key("none").replace("\n", "\r\n").encode()
st, res = _post_key("crlfkey", _crlf)
ok(st == 200, "a CRLF key uploads", res.get("error"))
_body = open(os.path.join(_up, "crlfkey"), "rb").read()
ok(b"\r" not in _body, "and its line endings are normalised to LF")
ok(_body.endswith(b"\n"), "and it ends with the trailing newline OpenSSH expects")

# A key with no trailing newline at all gets one.
st, res = _post_key("nonewline", _openssh_key("none").rstrip("\n").encode())
ok(st == 200 and open(os.path.join(_up, "nonewline"), "rb").read().endswith(b"\n"),
   "a key with no trailing newline is given one")

# --- delete ---------------------------------------------------------------
with _client() as c:
    r = c.delete("/tunnel/keys/crlfkey", headers=_ADMIN)
ok(r.status_code == 200 and not os.path.exists(os.path.join(_up, "crlfkey")),
   "delete removes an uploaded key", r.status_code)

with _client() as c:
    r = c.delete("/tunnel/keys/mounted", headers=_ADMIN)
ok(r.status_code == 404, "a key in the READ-ONLY root cannot be deleted from the UI",
   r.status_code)
ok(os.path.isfile(os.path.join(_ro, "mounted")), "and it is still there")

with _client() as c:
    r = c.delete("/tunnel/keys/%2e%2e%2fescape", headers=_ADMIN)
ok(r.status_code in (400, 404), "a traversal delete is refused", r.status_code)

with _client() as c:
    r = c.delete("/tunnel/keys/neverexisted", headers=_ADMIN)
ok(r.status_code == 404, "deleting something absent is a clean 404", r.status_code)

# --- a misconfigured upload root refuses rather than half-works ------------
_saved_root = app._UPLOAD_KEY_ROOT
app._UPLOAD_KEY_ROOT = os.path.join(_TMP, "not-a-mounted-root")
st, res = _post_key("anywhere", _plain)
ok(st == 500 and res.get("code") in ("upload_root_not_allowed", "upload_root_missing"),
   "an upload root outside the allowed roots refuses the write outright",
   (st, res.get("code")))
ok(not os.path.exists(os.path.join(_TMP, "not-a-mounted-root")),
   "and it is NOT created on the way past")
app._UPLOAD_KEY_ROOT = _saved_root

# --- the upload root must be usable for tunnel start ----------------------
# The whole point: a key written here has to be one /tunnel/start will accept.
# "engagement" was overwritten with the encrypted body above, so it also has to
# carry a passphrase -- which is itself the contract: the mode follows the key.
_v = app._validate_start_payload({
    "ssh_user": "op", "ssh_host": "10.0.0.1", "auth_method": "key",
    "local_socks_port": 1080,
    "key_path": os.path.join(_up, "engagement"),
    "key_passphrase": "hunter2",
})
ok(_v.get("ok") is True,
   "a freshly uploaded key passes start-payload validation \u2014 the upload root is "
   "genuinely usable, not just writable", _v.get("error"))
ok(_v.get("ok") and _v["payload"]["auth_method"] == "key_passphrase",
   "and an encrypted one is routed to sshpass whatever the dropdown said")

# ── listener timeout reporting ──────────────────────────────────────────────
# The timeout used to be reported as a bare stopwatch reading. ssh almost
# always said why; the branch just threw it away.
section("listener timeout reporting")


class _FakeProc:
    def __init__(self, text):
        self.stderr = io.StringIO(text) if text is not None else None


ok(app._drain_stderr(_FakeProc("Warning: blah\nroot@h: Permission denied (publickey).\n"))
   == "Warning: blah / root@h: Permission denied (publickey).",
   "the meaningful stderr tail is what gets reported")
# The line naming the cause is often the one BEFORE the verdict, so a one-line
# drain threw away exactly the half worth having.
ok(app._drain_stderr(_FakeProc(
    "Load key \"/ssh-keys/k\": incorrect passphrase supplied to decrypt private key\n"
    "root@h: Permission denied (publickey).\n"
)) == ("Load key \"/ssh-keys/k\": incorrect passphrase supplied to decrypt private key"
       " / root@h: Permission denied (publickey)."),
   "the cause line preceding the verdict survives")
ok(app._drain_stderr(_FakeProc("a\nb\nc\nd\ne\n")) == "c / d / e",
   "at most the last three lines are kept")
ok(app._drain_stderr(_FakeProc("")) == "", "no output yields no detail")
ok(app._drain_stderr(_FakeProc(None)) == "", "a missing stderr pipe is survivable")
ok(app._drain_stderr(_FakeProc("Enter passphrase for key '/ssh-keys/k': \n")) == "",
   "the echoed passphrase prompt is noise, not a cause")

msg = app._listener_timeout_error("root@h: Permission denied (publickey).", "key")
ok("Permission denied (publickey)" in msg, "ssh's reason reaches the operator", msg)
# The mode now always matches the key, so a pubkey rejection really is the far
# end -- and the next step is a specific one worth naming.
ok("authorized_keys" in msg and "Show public key" in msg,
   "a pubkey rejection names the actual next step", msg)
ok("authorized_keys" not in app._listener_timeout_error("kex_exchange: no route", "key"),
   "and that hint is not bolted onto unrelated failures")
# The same explanation has to reach the OTHER failure branch. A far end that
# refuses outright dies inside the 0.35s early-exit window and never reaches the
# listener check, so it used to get a bare verdict purely for being fast.
ok(app._pubkey_hint("root@h: Permission denied (publickey).").startswith(" The far end"),
   "the pubkey hint is shared, not owned by the timeout branch")
ok(app._pubkey_hint("Connection refused") == "",
   "and stays out of unrelated failures")
ok(".. " not in ("root@h: Permission denied (publickey)."
                 + app._pubkey_hint("root@h: Permission denied (publickey).")),
   "and does not double the full stop ssh already wrote")
ok(app._pubkey_hint("Permission denied (publickey)").startswith(". The far end"),
   "while still punctuating a line that lacks one")
msg = app._listener_timeout_error("", "key_passphrase")
ok("passphrase" in msg.lower() and "ssh-keygen -y" in msg,
   "silence under key_passphrase names the likely cause and how to check it", msg)
msg = app._listener_timeout_error("", "key")
ok("reachable" in msg, "silence under key auth points at reachability", msg)

# ── host key policy ─────────────────────────────────────────────────────────
# A redirector that gets rebuilt presents a new host key, and accept-new refuses
# a CHANGED key -- which surfaces as a startup timeout, not as anything naming
# host keys. The policy has to be selectable, and "no" has to be stateless or it
# just defers the same failure.
section("host key policy")

_payload = {"auth_method": "key", "ssh_user": "op", "ssh_host": "h",
            "local_socks_port": 1080, "key_path": "/ssh-keys/k",
            "password": "", "key_passphrase": ""}


def _cmd_with_policy(policy):
    app._HOST_KEY_POLICY = policy
    return app._build_start_command(dict(_payload))["cmd"]


cmd = _cmd_with_policy("accept-new")
ok("StrictHostKeyChecking=accept-new" in cmd, "accept-new is passed through", cmd)
ok("UserKnownHostsFile=/dev/null" not in cmd,
   "and still records what it accepted", cmd)

cmd = _cmd_with_policy("no")
ok("StrictHostKeyChecking=no" in cmd, "'no' is passed through", cmd)
ok("UserKnownHostsFile=/dev/null" in cmd and "GlobalKnownHostsFile=/dev/null" in cmd,
   "'no' is stateless, so a rebuilt far end can never be a CHANGED key", cmd)

cmd = _cmd_with_policy("yes")
ok("StrictHostKeyChecking=yes" in cmd, "'yes' is passed through", cmd)
ok("UserKnownHostsFile=/dev/null" not in cmd, "'yes' keeps its store", cmd)

app._HOST_KEY_POLICY = "accept-new"

# Under 'no' ssh announces every host it adds. That is the newest line on
# stderr, so it must not displace the actual cause of a failure.
ok(app._drain_stderr(_FakeProc(
    "root@h: Permission denied (publickey).\n"
    "Warning: Permanently added '1.2.3.4' (ED25519) to the list of known hosts.\n"
)) == "root@h: Permission denied (publickey).",
   "the host-key add notice never displaces the real cause")

# ── auth method derived from the key ────────────────────────────────────────
# The bug this closes: a passphrase-protected key started under "SSH key (no
# passphrase)" gets -o BatchMode=yes. ssh reads the PUBLIC half out of an
# encrypted key without the passphrase and offers it quite happily; it only
# needs to decrypt when the far end ACCEPTS that offer and a signature is due.
# Under BatchMode it cannot prompt there, so it gives up and the server answers
# "Permission denied (publickey)" -- a message about the far end, for a key the
# far end had just accepted. The mode must come from the key, not the dropdown.
section("auth method derived from the key")

_ad = os.path.join(_TMP, "authderive")
os.makedirs(_ad, exist_ok=True)
_ad_files = {
    "plain":   _openssh_key("none"),
    "locked":  _openssh_key("aes256-ctr"),
    # Decodes, but carries no openssh-key-v1 magic: _key_is_encrypted() cannot
    # classify it and returns None. A key we cannot read must never be blocked.
    "opaque":  "-----BEGIN OPENSSH PRIVATE KEY-----\nQUJD\n-----END OPENSSH PRIVATE KEY-----\n",
}
for _n, _b in _ad_files.items():
    with open(os.path.join(_ad, _n), "w", encoding="utf-8") as fh:
        fh.write(_b)

_saved_roots = list(app._ALLOWED_KEY_ROOTS)
app._ALLOWED_KEY_ROOTS = [_ad]


def _start(auth_method, key_name, passphrase=""):
    return app._validate_start_payload({
        "ssh_user": "op", "ssh_host": "h", "local_socks_port": 1080,
        "auth_method": auth_method,
        "key_path": os.path.join(_ad, key_name) if key_name else "",
        "key_passphrase": passphrase,
    })


# An encrypted key with nothing to unlock it: refused by name, before ssh runs.
v = _start("key", "locked")
ok(not v.get("ok"), "an encrypted key with no passphrase is refused", v)
ok(v.get("code") == "key_needs_passphrase", "with a code that names the cause", v.get("code"))
ok("locked" in v.get("error", ""), "the message names the key", v.get("error"))
ok("Permission denied (publickey)" in v.get("error", ""),
   "and pre-empts the far-end message it would otherwise be mistaken for", v.get("error"))

# Same key, passphrase supplied: the dropdown said "key", the key says otherwise.
v = _start("key", "locked", "hunter2")
ok(v.get("ok"), "an encrypted key with a passphrase is accepted under either mode", v)
ok(v["payload"]["auth_method"] == "key_passphrase",
   "and is promoted to the sshpass path", v["payload"]["auth_method"])
ok(v["payload"]["requested_auth_method"] == "key", "while recording what was asked for")
cmd = app._build_start_command(dict(v["payload"]))["cmd"]
ok(cmd[0] == "sshpass", "which really does wrap ssh in sshpass", cmd[:3])
ok("BatchMode=yes" not in cmd, "and never sets BatchMode, which is what broke it", cmd)

# An unencrypted key under the passphrase mode: works, and says what it ignored.
v = _start("key_passphrase", "plain", "pointless")
ok(v.get("ok"), "an unencrypted key under key_passphrase is not refused", v)
ok(v["payload"]["auth_method"] == "key", "it is demoted to BatchMode", v["payload"]["auth_method"])
ok(any("ignored" in note for note in v["payload"]["notes"]),
   "and says the passphrase was ignored", v["payload"]["notes"])
ok(v["payload"]["key_passphrase"] == "",
   "a secret made irrelevant is not carried any further")
cmd = app._build_start_command(dict(v["payload"]))["cmd"]
ok(cmd[0] == "ssh" and "BatchMode=yes" in cmd, "and runs plain ssh", cmd[:2])

# This used to be a hard refusal ("key_passphrase auth selected but no
# key_passphrase provided") for a key that never needed one.
v = _start("key_passphrase", "plain")
ok(v.get("ok") and v["payload"]["auth_method"] == "key",
   "an unencrypted key needs no passphrase even when the mode asks for one", v)

# A format the parser cannot classify must fall back to what was asked, never block.
v = _start("key", "opaque")
ok(v.get("ok") and v["payload"]["auth_method"] == "key",
   "an unclassifiable key is not blocked under key", v)
v = _start("key_passphrase", "opaque", "maybe")
ok(v.get("ok") and v["payload"]["auth_method"] == "key_passphrase",
   "an unclassifiable key honours the selected mode", v)
ok(any("could not tell" in note for note in v["payload"]["notes"]),
   "and says it could not tell", v["payload"]["notes"])

# IdentitiesOnly: without it ssh may offer a default identity first, and the
# rejection then describes a key nobody selected.
for _m in ("key", "key_passphrase"):
    _c = app._build_start_command({
        "auth_method": _m, "ssh_user": "op", "ssh_host": "h", "local_socks_port": 1080,
        "key_path": os.path.join(_ad, "plain"), "password": "", "key_passphrase": "x",
    })["cmd"]
    ok("-i" in _c and "IdentitiesOnly=yes" in _c,
       f"-i is always paired with IdentitiesOnly under {_m}", _c)
_c = app._build_start_command({
    "auth_method": "password", "ssh_user": "op", "ssh_host": "h", "local_socks_port": 1080,
    "key_path": "", "password": "p", "key_passphrase": "",
})["cmd"]
ok("IdentitiesOnly=yes" not in _c, "and never appears without -i", _c)

# A key_path that is not there is recoverable when there is only one candidate.
_one = os.path.join(_TMP, "onlykey")
os.makedirs(_one, exist_ok=True)
with open(os.path.join(_one, "solo"), "w", encoding="utf-8") as fh:
    fh.write(_openssh_key("none"))
app._ALLOWED_KEY_ROOTS = [_one]
v = _start("key", None)      # blank path -> TUNNEL_DEFAULT_KEY_PATH, which need not exist
ok(v.get("ok"), "a blank key path resolves when exactly one key is present", v)
ok(v["payload"]["key_path"] == os.path.join(_one, "solo"),
   "to the only key there", v["payload"]["key_path"])
ok(any("only key present" in note for note in v["payload"]["notes"]),
   "and says so rather than substituting silently", v["payload"]["notes"])

app._ALLOWED_KEY_ROOTS = [_ad]
v = _start("key", None)
ok(not v.get("ok") and v.get("code") == "key_not_found",
   "with several keys it refuses rather than guessing", v)
ok("plain" in v.get("error", "") and "locked" in v.get("error", ""),
   "and names the ones that ARE present", v.get("error"))

_empty = os.path.join(_TMP, "nokeys")
os.makedirs(_empty, exist_ok=True)
app._ALLOWED_KEY_ROOTS = [_empty]
v = _start("key", None)
ok(not v.get("ok") and "Upload one" in v.get("error", ""),
   "an empty root points at the uploader", v.get("error"))

app._ALLOWED_KEY_ROOTS = _saved_roots

# ── the token gate fails closed ─────────────────────────────────────────────
section("API token gate")

_saved_token = app._API_TOKEN
try:
    # The unconfigured case. This used to serve every /tunnel/* route with no
    # credential at all; it must now refuse, because a secrets store that drops
    # a variable would otherwise silently open the tunnel control plane.
    app._API_TOKEN = ""
    with app.app.test_client() as c:          # deliberately no token header
        r = c.get("/tunnel/tor/countries")
    ok(r.status_code == 503, "an unset TUNNEL_API_TOKEN refuses /tunnel/*", r.status_code)
    body = r.get_json() or {}
    ok(body.get("code") == "not_configured",
       "and says the server is misconfigured, not that the caller is unauthorized",
       body.get("code"))
    ok("TUNNEL_API_TOKEN" in (body.get("error") or ""),
       "naming the variable to set", body.get("error"))

    # /health stays open, or the container healthcheck would fail the service
    # precisely when it is misconfigured.
    with app.app.test_client() as c:
        ok(c.get("/health").status_code == 200,
           "while /health stays open for the container healthcheck")

    # A configured token still rejects a wrong one, and accepts the right one.
    app._API_TOKEN = "correct-horse"
    with app.app.test_client() as c:
        r = c.get("/tunnel/tor/countries", headers={"X-Tunnel-Token": "wrong"})
    ok(r.status_code == 401, "a wrong token is unauthorized, not misconfigured", r.status_code)
    with app.app.test_client() as c:
        r = c.get("/tunnel/tor/countries", headers={"X-Tunnel-Token": "correct-horse"})
    ok(r.status_code == 200, "and the right token passes", r.status_code)
finally:
    app._API_TOKEN = _saved_token


print(f"\n{'FAILED' if FAILURES else 'PASSED'} — {CHECKS - FAILURES}/{CHECKS} checks")
sys.exit(1 if FAILURES else 0)
