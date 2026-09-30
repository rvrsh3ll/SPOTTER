#!/usr/bin/env node
/*
 * Headless smoke test for the Infrastructure tab's TOR proxy type, the egress
 * identity notifier and the OPSEC User-Agent control (frontend/index.html).
 *
 * Why this exists
 * ---------------
 * Every failure mode this covers is a SILENT one in a manual click-through:
 *
 *   * a saved country set that does not survive a reload looks identical to
 *     "the operator never picked one" — and the profile keeps sending it;
 *   * a User-Agent that never reaches the webhook envelope looks identical to
 *     a working override, because nothing in the UI echoes what was sent;
 *   * `direct` egress rendered green looks identical to proxied egress, which
 *     is the exact mistake this notifier exists to catch;
 *   * a proxy type whose block never un-hides just looks like a dead select.
 *
 * Runs entirely offline: every sidecar call is stubbed, so no request leaves
 * the host. No npm install needed — jsdom ships inside the n8n install here.
 *
 *   node scripts/smoke_frontend_infra_opsec.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed (all are reported).
 *
 * What it CANNOT tell you: jsdom has no layout engine, so the multi-select
 * height, the egress strip's wrapping at narrow widths and the option:checked
 * colours are unevaluated. Those still need one browser pass in both themes.
 */

'use strict';

const fs = require('fs');
const vm = require('vm');


const { INDEX, loadJsdom } = require('./smoke_frontend_lib');
const { JSDOM, VirtualConsole } = loadJsdom();

let failures = 0, checks = 0;
function ok(cond, label, extra) {
  checks++;
  if (cond) return true;
  failures++;
  console.error(`  FAIL  ${label}${extra !== undefined ? `\n        got: ${extra}` : ''}`);
  return false;
}
function section(name) { console.log(`\n── ${name}`); }
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ── stub sidecar ─────────────────────────────────────────────────────────
   Answers the four /infra/tunnel/ routes the panel talks to. `calls` records
   every request so the tests can assert on what was actually sent. */
const COUNTRIES = {
  ok: true, source: '/usr/share/tor/geoip', count: 4,
  countries: [
    { code: 'de', name: 'Germany' },
    { code: 'nl', name: 'Netherlands' },
    { code: 'ro', name: 'Romania' },
    { code: 'us', name: 'United States' },
  ],
};

function makeStub(w, calls, overrides = {}) {
  return async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : null;
    calls.push({ url: String(url), body, headers: opts.headers || {} });
    const reply = data => ({
      ok: true,
      status: 200,
      headers: { get: h => (h.toLowerCase() === 'content-type' ? 'application/json' : null) },
      json: async () => data,
    });
    if (/tor\/countries$/.test(url)) return reply(overrides.countries || COUNTRIES);
    if (/tor\/status$/.test(url))    return reply(overrides.torStatus || { ok: true, available: true, running: false, tor: null, error: '' });
    if (/tor\/start$/.test(url))     return reply(overrides.torStart || { ok: true, available: true, running: true, error: '', last_log: '',
                                                   tor: { id: 't1', pid: 42, socks_host: 'ssh-tunnel-api', socks_port: 9050,
                                                          entry_countries: body?.entry_countries || [], exit_countries: body?.exit_countries || [],
                                                          strict_nodes: !!body?.strict_nodes, bootstrap_percent: 5, bootstrapped: false, uptime_seconds: 0 } });
    if (/tor\/stop$/.test(url))      return reply({ ok: true, running: false, tor: null, error: '' });
    if (/tunnel\/egress$/.test(url)) return reply(overrides.egress || {
      ok: true, error: '', ip: '198.51.100.7',
      geo: { country: 'Netherlands', country_code: 'NL', city: 'Amsterdam', asn: 'AS64500', org: 'Example B.V.' },
      via: 'Tor', proxied: true, source: 'https://ifconfig.co/json', geo_source: 'https://ifconfig.co/json',
      user_agent: 'curl/8.5.0', elapsed_ms: 410, checked_at: 1, errors: [],
    });
    if (/tunnel\/status$/.test(url)) return reply({ ok: true, running: false, tunnel: null, error: '' });
    /* Write routes. Ordered before the plain /tunnel/keys match because a POST
       and a GET share that path and only the method tells them apart. */
    if (/tunnel\/keys\/[^/]+\/public$/.test(url)) {
      return reply(overrides.keyPublic || { ok: true, name: 'uploaded', path: '/ssh-keys-uploaded/uploaded',
                                            encrypted: false, public_key: 'ssh-ed25519 AAAAPUB test',
                                            fingerprint: '256 SHA256:abc uploaded (ED25519)' });
    }
    if (/tunnel\/keys\/[^/]+$/.test(url) && (opts.method || 'GET').toUpperCase() === 'DELETE') {
      return reply(overrides.keyDelete || { ok: true, name: 'uploaded', deleted: true });
    }
    if (/tunnel\/keys$/.test(url) && (opts.method || 'GET').toUpperCase() === 'POST') {
      return reply(overrides.keyUpload || { ok: true, name: 'uploaded', path: '/ssh-keys-uploaded/uploaded',
                                            encrypted: false, fingerprint: '256 SHA256:abc uploaded (ED25519)',
                                            bytes: 411, overwritten: false });
    }
    if (/tunnel\/keys$/.test(url))   return reply(overrides.keys || {
      ok: true, roots: ['/ssh-keys'], default_key_path: '/ssh-keys/id_ed25519', count: 1,
      keys: [{ path: '/ssh-keys/spotter-tunnel', name: 'spotter-tunnel', encrypted: false }],
    });
    return reply({ ok: true });
  };
}

async function main() {
  const html = fs.readFileSync(INDEX, 'utf8');

  /* ── Step 0: the inline script still parses ────────────────────────── */
  section('Step 0 — inline script parses');
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const main_js = blocks.reduce((a, b) => (b.length > a.length ? b : a), '');
  ok(main_js.length > 100000, 'main script block looks like the big one', main_js.length);
  try {
    new vm.Script(main_js, { filename: 'index.html-inline.js' });
    ok(true, 'inline script parses');
  } catch (e) {
    ok(false, 'inline script parses', e.message);
    // Nothing below can run against a syntax error.
    console.error('\nAborting: the page does not parse.');
    process.exit(1);
  }

  /* ── Step 1: clean load ────────────────────────────────────────────── */
  section('Step 1 — loads with zero errors');
  const vc = new VirtualConsole();
  const errs = [];
  vc.on('jsdomError', e => errs.push(e.message));
  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    url: 'http://localhost/',
    virtualConsole: vc,
    pretendToBeVisual: true,
  });
  const w = dom.window;
  const d = w.document;
  /* jsdom does not put TextEncoder on window, but every browser does and the
     page uses it in several places (the campaign bundle crypto as well as the
     key uploader). Supply it rather than making the page work around a gap
     that only exists in this harness. */
  if (typeof w.TextEncoder === 'undefined') w.TextEncoder = TextEncoder;
  if (typeof w.TextDecoder === 'undefined') w.TextDecoder = TextDecoder;
  await sleep(80);
  ok(errs.length === 0, 'no jsdomError during load', errs.join(' | '));

  // The page-load init calls infraLoadForm(). It must NOT have fired an egress
  // check: that call leaves the network, and nobody opened the tab.
  ok(!/EGRESS — checking/.test(d.getElementById('infra-egress-ip').textContent),
     'page load does not auto-run the egress check',
     d.getElementById('infra-egress-ip').textContent);

  /* ── Step 2: structure ─────────────────────────────────────────────── */
  section('Step 2 — DOM structure');
  const pnl = d.getElementById('pnl-infra');
  const egress = d.getElementById('infra-egress');
  ok(!!egress, '#infra-egress exists');
  ok(egress && egress.parentElement === pnl, 'egress strip lives directly in the infra panel');
  ok(pnl && pnl.firstElementChild === egress, 'egress strip is the FIRST element on the panel',
     pnl && pnl.firstElementChild && pnl.firstElementChild.id);

  const ptype = d.getElementById('infra-proxy-type');
  const values = Array.from(ptype.options).map(o => o.value);
  ok(values.includes('tor'), 'proxy type offers "tor"', values.join(','));

  ok(!!d.getElementById('infra-tor-block'), '#infra-tor-block exists');
  ok(d.getElementById('infra-tor-block').style.display === 'none', 'tor block starts hidden');
  ok(!!d.getElementById('infra-tor-entry'), 'entry country select exists');
  ok(d.getElementById('infra-tor-entry').multiple === true, 'entry select is multi-select');
  ok(d.getElementById('infra-tor-exit').multiple === true, 'exit select is multi-select');
  ok(!!d.getElementById('infra-ua-preset'), 'OPSEC user-agent select exists');
  ok(d.getElementById('infra-ua-custom-row').style.display === 'none', 'custom UA row starts hidden');

  // Fallback catalogue rendered synchronously, so the control is never empty
  // even with the sidecar unreachable (which is the case on this load).
  ok(d.getElementById('infra-tor-entry').options.length > 10,
     'entry select is populated from the fallback catalogue',
     d.getElementById('infra-tor-entry').options.length);

  /* ── Step 3: tab open — live catalogue + egress check ──────────────── */
  section('Step 3 — opening the tab');
  const calls = [];
  w.fetch = makeStub(w, calls);
  // The failed page-load fetch must not have poisoned the memo.
  ok(w.eval('_infraCountriesPromise') === null,
     'a failed catalogue fetch is not memoised', w.eval('_infraCountriesPromise'));

  w.sw('infra');
  await sleep(60);

  const urls = calls.map(c => c.url);
  ok(urls.some(u => /tor\/countries$/.test(u)), 'fetched the country catalogue', urls.join(' '));
  ok(urls.some(u => /tunnel\/egress$/.test(u)), 'ran the egress check on tab open', urls.join(' '));

  const entrySel = d.getElementById('infra-tor-entry');
  ok(entrySel.options.length === 4, 'catalogue replaced the fallback list', entrySel.options.length);
  ok(entrySel.options[0].value === 'de' && /Germany \(DE\)/.test(entrySel.options[0].textContent),
     'options are code-valued and name-labelled', entrySel.options[0].textContent);

  const egIp = d.getElementById('infra-egress-ip');
  ok(/198\.51\.100\.7/.test(egIp.textContent), 'egress strip shows the IP', egIp.textContent);
  ok(!/DIRECT/.test(egIp.textContent), 'proxied egress is not marked DIRECT', egIp.textContent);
  ok(egress.className === 'infra-egress', 'proxied egress renders in the ok style', egress.className);
  const egMeta = d.getElementById('infra-egress-meta').textContent;
  ok(/Amsterdam/.test(egMeta) && /Netherlands/.test(egMeta), 'geo is rendered', egMeta);
  ok(/AS64500/.test(egMeta), 'ASN/org is rendered', egMeta);
  ok(/via Tor/.test(egMeta), 'the route is named', egMeta);

  /* ── Step 4: TOR selection round-trips through storage ─────────────── */
  section('Step 4 — TOR config round-trip');
  d.getElementById('infra-enabled').checked = true;
  d.getElementById('infra-proxy-type').value = 'tor';
  w.infraDirty();
  ok(d.getElementById('infra-tor-block').style.display === '', 'tor block unhides on selection',
     d.getElementById('infra-tor-block').style.display);
  ok(d.getElementById('infra-socks-block').style.display === 'none', 'socks block hides again');

  w.infraCcSetSelection('infra-tor-entry', ['de', 'ro']);
  w.infraCcSetSelection('infra-tor-exit', ['nl']);
  d.getElementById('infra-tor-strict').checked = true;
  w.infraCcChanged();
  ok(/2 selected: DE, RO/.test(d.getElementById('infra-tor-entry-count').textContent),
     'entry count label reflects the selection', d.getElementById('infra-tor-entry-count').textContent);

  const form = w.infraReadForm();
  ok(JSON.stringify(form.torEntryCountries) === '["de","ro"]', 'form reads entry countries',
     JSON.stringify(form.torEntryCountries));
  ok(JSON.stringify(form.torExitCountries) === '["nl"]', 'form reads exit countries',
     JSON.stringify(form.torExitCountries));

  w.infraSave();
  await sleep(20);
  const stored = JSON.parse(w.localStorage.getItem(w.infraKey()));
  ok(JSON.stringify(stored.torEntryCountries) === '["de","ro"]', 'entry countries persisted',
     JSON.stringify(stored.torEntryCountries));
  ok(stored.torStrictNodes === true, 'strict flag persisted', stored.torStrictNodes);

  // Wipe the DOM selection, reload the form, and confirm it comes back.
  w.infraCcSetSelection('infra-tor-entry', []);
  w.infraLoadForm();
  await sleep(40);
  ok(JSON.stringify(w.infraCcSelected('infra-tor-entry')) === '["de","ro"]',
     'selection is restored after a reload', JSON.stringify(w.infraCcSelected('infra-tor-entry')));

  /* ── Step 5: a code the catalogue does not list is not swallowed ───── */
  section('Step 5 — unknown country code survives');
  w.infraCcSetSelection('infra-tor-exit', ['nl', 'is']);   // 'is' is not in the stub catalogue
  ok(JSON.stringify(w.infraCcSelected('infra-tor-exit')) === '["nl","is"]',
     'unlisted code stays selected instead of vanishing',
     JSON.stringify(w.infraCcSelected('infra-tor-exit')));
  const isOpt = Array.from(d.getElementById('infra-tor-exit').options).find(o => o.value === 'is');
  ok(isOpt && /not in catalogue/.test(isOpt.textContent), 'and is labelled as unlisted',
     isOpt && isOpt.textContent);
  w.infraCcSetSelection('infra-tor-exit', ['nl']);

  /* ── Step 6: the webhook envelope ──────────────────────────────────── */
  section('Step 6 — proxy + opsec envelope');
  d.getElementById('infra-ua-preset').value = 'firefox_linux';
  w.infraUaChanged();
  w.infraSave();
  await sleep(20);

  const env = w.withInfraPayload({ target_labels: ['x'] });
  ok(env.target_labels && env.target_labels[0] === 'x', 'the caller body survives');
  ok(env.proxy && env.proxy.type === 'tor', 'envelope carries proxy.type=tor',
     env.proxy && env.proxy.type);
  ok(env.proxy && env.proxy.socks_url === 'socks5h://ssh-tunnel-api:9050',
     'socks5h URL points at the managed Tor client', env.proxy && env.proxy.socks_url);
  ok(env.proxy && env.proxy.socks_url.startsWith('socks5h://'),
     'socks5h (remote DNS), never socks5', env.proxy && env.proxy.socks_url);
  ok(env.proxy && env.proxy.tor && JSON.stringify(env.proxy.tor.entry_countries) === '["de","ro"]',
     'envelope carries the entry countries', JSON.stringify(env.proxy && env.proxy.tor));
  ok(env.proxy && env.proxy.tor && env.proxy.tor.strict_nodes === true,
     'envelope carries strict_nodes');
  ok(env.opsec && /Firefox\/129/.test(env.opsec.user_agent), 'envelope carries the User-Agent',
     env.opsec && env.opsec.user_agent);

  /* ── Step 7: UA is independent of the proxy toggle ─────────────────── */
  section('Step 7 — OPSEC User-Agent');
  d.getElementById('infra-enabled').checked = false;
  w.infraSave();
  await sleep(20);
  const env2 = w.withInfraPayload({});
  ok(!env2.proxy, 'disabling the profile drops the proxy', JSON.stringify(env2.proxy));
  ok(env2.opsec && /Firefox\/129/.test(env2.opsec.user_agent),
     'but the User-Agent still ships', JSON.stringify(env2.opsec));

  d.getElementById('infra-ua-preset').value = 'custom';
  w.infraUaChanged();
  ok(d.getElementById('infra-ua-custom-row').style.display === '', 'custom row appears');
  ok(/not overridden/.test(d.getElementById('infra-ua-effective').textContent),
     'an empty custom UA is reported as no override',
     d.getElementById('infra-ua-effective').textContent);

  const beforeBad = w.localStorage.getItem(w.infraKey());
  w.infraSave();
  await sleep(10);
  ok(w.localStorage.getItem(w.infraKey()) === beforeBad,
     'saving an empty custom UA is refused, not silently stored');

  d.getElementById('infra-ua-custom').value = 'SPOTTER-Recon/9.9 (engagement 42)';
  w.infraUaChanged();
  ok(d.getElementById('infra-ua-effective').textContent === 'SPOTTER-Recon/9.9 (engagement 42)',
     'effective UA echoes the custom string', d.getElementById('infra-ua-effective').textContent);
  w.infraSave();
  await sleep(20);
  ok(w.withInfraPayload({}).opsec.user_agent === 'SPOTTER-Recon/9.9 (engagement 42)',
     'custom UA reaches the envelope');

  d.getElementById('infra-ua-preset').value = 'default';
  w.infraUaChanged();
  w.infraSave();
  await sleep(20);
  ok(w.withInfraPayload({}).opsec === undefined,
     'the default preset sends no opsec block at all',
     JSON.stringify(w.withInfraPayload({})));

  /* ── Step 7b: OPSEC DNS resolvers ──────────────────────────────────── */
  section('Step 7b — OPSEC DNS resolvers');
  // Entry state (from Step 7): profile disabled, UA preset = default.
  ok(!!d.getElementById('infra-dns-preset'), 'OPSEC DNS resolver select exists');
  ok(d.getElementById('infra-dns-custom-row').style.display === 'none',
     'custom DNS row starts hidden', d.getElementById('infra-dns-custom-row').style.display);

  // A preset ships as a list, independent of the (still disabled) proxy toggle.
  d.getElementById('infra-dns-preset').value = 'cloudflare';
  w.infraDnsChanged();
  w.infraSave();
  await sleep(20);
  const envD = w.withInfraPayload({});
  ok(!envD.proxy, 'a DNS override does not resurrect the disabled proxy', JSON.stringify(envD.proxy));
  ok(envD.opsec && JSON.stringify(envD.opsec.dns_resolvers) === '["1.1.1.1","1.0.0.1"]',
     'a preset ships as opsec.dns_resolvers', JSON.stringify(envD.opsec));

  // Custom + empty → refused, exactly like an empty custom User-Agent.
  d.getElementById('infra-dns-preset').value = 'custom';
  w.infraDnsChanged();
  ok(d.getElementById('infra-dns-custom-row').style.display === '', 'custom DNS row appears');
  const beforeEmptyDns = w.localStorage.getItem(w.infraKey());
  w.infraSave();
  await sleep(10);
  ok(w.localStorage.getItem(w.infraKey()) === beforeEmptyDns,
     'an empty custom resolver list is refused, not silently stored');

  // A malformed resolver is refused rather than saved to fail at lookup time.
  d.getElementById('infra-dns-custom').value = '999.1.1.1';
  w.infraDnsChanged();
  const beforeBadDns = w.localStorage.getItem(w.infraKey());
  w.infraSave();
  await sleep(10);
  ok(w.localStorage.getItem(w.infraKey()) === beforeBadDns,
     'a malformed resolver (999.1.1.1) is refused');
  ok(w.infraValidateDnsResolver('http://dns.google/dns-query') !== '',
     'DoH over http:// is rejected');
  ok(w.infraValidateDnsResolver('https://dns.google/dns-query') === '',
     'DoH over https:// is accepted');
  ok(w.infraValidateDnsResolver('[2606:4700:4700::1111]:853') === '',
     'a bracketed IPv6 with port is accepted');
  ok(w.infraValidateDnsResolver('8.8.8.8:53') === '', 'an IPv4 with port is accepted');

  // A valid mixed list (IPs + DoH, comma- and newline-separated) round-trips.
  d.getElementById('infra-dns-custom').value = '1.1.1.1, 9.9.9.9\nhttps://dns.quad9.net/dns-query';
  w.infraDnsChanged();
  ok(/1\.1\.1\.1, 9\.9\.9\.9, https:\/\/dns\.quad9\.net\/dns-query/.test(
       d.getElementById('infra-dns-effective').textContent),
     'effective echoes the parsed resolver list', d.getElementById('infra-dns-effective').textContent);
  w.infraSave();
  await sleep(20);
  ok(JSON.stringify(w.withInfraPayload({}).opsec.dns_resolvers)
       === '["1.1.1.1","9.9.9.9","https://dns.quad9.net/dns-query"]',
     'the custom resolver list reaches the envelope', JSON.stringify(w.withInfraPayload({}).opsec));

  // The list survives a storage round-trip and repopulates the textarea.
  w.infraLoadForm();
  await sleep(40);
  ok(d.getElementById('infra-dns-preset').value === 'custom', 'custom preset restored after reload');
  ok(/dns\.quad9\.net/.test(d.getElementById('infra-dns-custom').value),
     'custom resolver text restored after reload', d.getElementById('infra-dns-custom').value);

  // Back to default → no dns_resolvers, and with UA also default, no opsec block.
  d.getElementById('infra-dns-preset').value = 'default';
  w.infraDnsChanged();
  w.infraSave();
  await sleep(20);
  ok(w.withInfraPayload({}).opsec === undefined,
     'default DNS + default UA sends no opsec block', JSON.stringify(w.withInfraPayload({})));

  /* ── Step 8: the egress check reports what it is told ──────────────── */
  section('Step 8 — egress rendering');
  // Step 7 left the profile disabled; put it back so the check has a proxy to
  // report on, and let any save-triggered check settle first.
  d.getElementById('infra-enabled').checked = true;
  d.getElementById('infra-proxy-type').value = 'tor';
  w.infraDirty();
  await sleep(30);
  const calls2 = [];
  w.fetch = makeStub(w, calls2, {
    // ip.me on purpose: it is the IP-only floor at the end of EGRESS_IP_URLS,
    // so this is the one case that still reaches the strip with no location —
    // the readout must name the source rather than imply the proxy is down.
    egress: { ok: true, error: '', ip: '203.0.113.4', geo: {}, via: 'direct', proxied: false,
              source: 'https://ip.me/', geo_source: '', user_agent: 'curl/8.5.0',
              elapsed_ms: 90, checked_at: 2, errors: [] },
  });
  await w.infraRefreshEgress(true);
  await sleep(20);
  ok(/DIRECT/.test(d.getElementById('infra-egress-ip').textContent),
     'unproxied egress is labelled DIRECT', d.getElementById('infra-egress-ip').textContent);
  ok(/st-warn/.test(egress.className), 'and rendered amber, never green', egress.className);
  ok(/geo unavailable/.test(d.getElementById('infra-egress-meta').textContent),
     'a geo-less answer says so rather than showing an empty location',
     d.getElementById('infra-egress-meta').textContent);

  const sent = calls2.find(c => /egress$/.test(c.url));
  ok(sent && sent.body && sent.body.proxy && sent.body.proxy.type === 'tor',
     'the check is made through the profile currently in the form',
     sent && JSON.stringify(sent.body && sent.body.proxy));

  w.fetch = makeStub(w, [], {
    egress: { ok: false, error: 'No usable public IP was returned by any configured source',
              ip: '', geo: {}, via: 'Tor', proxied: true, source: '', geo_source: '',
              user_agent: 'curl/8.5.0', elapsed_ms: 12000, checked_at: 3,
              errors: ['https://ifconfig.co/json: ConnectTimeout: timed out'] },
  });
  await w.infraRefreshEgress(true);
  await sleep(20);
  ok(/st-err/.test(egress.className), 'a failed check renders as an error', egress.className);
  ok(/ConnectTimeout/.test(d.getElementById('infra-egress-meta').textContent),
     'and surfaces the underlying reason, not a generic message',
     d.getElementById('infra-egress-meta').textContent);

  /* ── Step 9: Tor control plane ─────────────────────────────────────── */
  section('Step 9 — Tor start/stop');
  const calls3 = [];
  w.fetch = makeStub(w, calls3);
  d.getElementById('infra-proxy-type').value = 'tor';
  d.getElementById('infra-tor-strict').checked = false;
  w.infraCcSetSelection('infra-tor-entry', ['de']);
  w.infraCcSetSelection('infra-tor-exit', ['nl']);
  w.infraCcChanged();

  await w.infraTorStart();
  await sleep(30);
  const start = calls3.find(c => /tor\/start$/.test(c.url));
  ok(!!start, 'a start request was sent');
  ok(start && JSON.stringify(start.body.entry_countries) === '["de"]',
     'start carries the entry countries', start && JSON.stringify(start.body));
  ok(start && start.body.socks_port === 9050, 'start carries the SOCKS port',
     start && start.body.socks_port);
  ok(d.getElementById('infra-enabled').checked === true,
     'starting Tor points the profile at it');
  const torBar = d.getElementById('infra-tor-status');
  ok(/bootstrap 5%/.test(torBar.textContent), 'status shows bootstrap progress', torBar.textContent);
  ok(/still building/.test(torBar.textContent),
     'an unbootstrapped Tor is not reported as ready', torBar.textContent);
  ok(torBar.className === 'wbar', 'and is amber until circuits exist', torBar.className);
  ok(d.getElementById('infra-tor-start-btn').disabled === true, 'start button disables while running');

  // Strict with no countries is refused before it reaches the sidecar.
  const before = calls3.length;
  d.getElementById('infra-tor-strict').checked = true;
  w.infraCcSetSelection('infra-tor-entry', []);
  w.infraCcSetSelection('infra-tor-exit', []);
  await w.infraTorStart();
  ok(calls3.length === before, 'strict-with-no-countries never reaches the sidecar',
     calls3.length - before);

  // A sidecar without tor installed says so instead of failing obscurely.
  w.infraRenderTorStatus({ ok: true, available: false, running: false, tor: null, error: '' });
  ok(/not installed/.test(d.getElementById('infra-tor-status').textContent),
     'a tor-less sidecar is named explicitly', d.getElementById('infra-tor-status').textContent);
  ok(d.getElementById('infra-tor-start-btn').disabled === true,
     'and the start button is disabled');


  /* ── Step 10: key discovery reconciles a stale saved path ──────────
     The path is typed by hand and kept in localStorage, so it outlives the
     deployment it was written for. Repointing SSH_KEY_DIR leaves it naming a
     key the container cannot see, and the only symptom used to be a failed
     Start. */
  section('Step 10 — key discovery');
  w.fetch = makeStub(w, []);

  const keyInput = d.getElementById('infra-ssh-key-path');
  const keyNote  = d.getElementById('infra-ssh-key-note');
  const keyList  = d.getElementById('infra-ssh-key-list');
  ok(!!keyInput && !!keyNote && !!keyList, 'the field, its datalist and its note all exist');

  keyInput.value = '/ssh-keys/extravm';          // the exact field failure
  d.getElementById('infra-ssh-auth-method').value = 'key';
  await w.infraLoadKeys();

  ok(keyList.querySelectorAll('option').length === 1,
     'the datalist is populated from what the sidecar reports', keyList.innerHTML);
  ok(keyInput.value === '/ssh-keys/spotter-tunnel',
     'a stale path auto-corrects when exactly one key exists', keyInput.value);
  ok(/extravm/.test(keyNote.textContent) && /switched/i.test(keyNote.textContent),
     'and the note names both the dead path and the replacement', keyNote.textContent);

  // Two candidates is ambiguous: guessing would be worse than reporting.
  w.fetch = makeStub(w, [], { keys: { ok: true, roots: ['/ssh-keys'], default_key_path: '', count: 2,
    keys: [{ path: '/ssh-keys/a', name: 'a', encrypted: false },
           { path: '/ssh-keys/b', name: 'b', encrypted: false }] } });
  keyInput.value = '/ssh-keys/gone';
  await w.infraLoadKeys();
  ok(keyInput.value === '/ssh-keys/gone', 'with more than one key it never guesses', keyInput.value);
  ok(/\/ssh-keys\/a/.test(keyNote.textContent) && /\/ssh-keys\/b/.test(keyNote.textContent),
     'it lists what is available instead', keyNote.textContent);

  // The other combination that can only fail as a bare startup timeout.
  w.fetch = makeStub(w, [], { keys: { ok: true, roots: ['/ssh-keys'], default_key_path: '', count: 1,
    keys: [{ path: '/ssh-keys/locked', name: 'locked', encrypted: true }] } });
  keyInput.value = '/ssh-keys/locked';
  d.getElementById('infra-ssh-auth-method').value = 'key';
  await w.infraLoadKeys();
  ok(/passphrase-protected/.test(keyNote.textContent),
     'an encrypted key under no-passphrase mode is flagged before Start', keyNote.textContent);

  w.fetch = makeStub(w, [], { keys: { ok: true, roots: ['/ssh-keys'], default_key_path: '', count: 0, keys: [] } });
  await w.infraLoadKeys();
  ok(/No SSH keys found/.test(keyNote.textContent),
     'an empty key root is stated outright', keyNote.textContent);

  // Advisory only: a sidecar that cannot answer must not break the tab.
  w.fetch = async () => { throw new Error('down'); };
  await w.infraLoadKeys();
  ok(true, 'a failed lookup is swallowed rather than thrown');

  /* ── Step 11: secrets survive the form verbatim ────────────────────
     Trimming is right for a host or a path and wrong for a secret: a
     passphrase with an edge space is legal, and silently altering it fails as
     an unexplained timeout rather than an auth error. */
  section('Step 11 — secrets are not trimmed');
  d.getElementById('infra-ssh-user').value = '  op  ';
  d.getElementById('infra-ssh-key-pass').value = '  pass phrase  ';
  d.getElementById('infra-ssh-password').value = ' pw ';
  const secretCfg = w.infraReadForm();
  ok(secretCfg.sshUser === 'op', 'ordinary fields are still trimmed', secretCfg.sshUser);
  ok(secretCfg.sshKeyPass === '  pass phrase  ',
     'a passphrase keeps its leading and trailing spaces', JSON.stringify(secretCfg.sshKeyPass));
  ok(secretCfg.sshPassword === ' pw ',
     'so does a password', JSON.stringify(secretCfg.sshPassword));


  /* ── Step 12: key upload ───────────────────────────────────────────
     Before this existed the only route for an identity was a host shell and a
     bind mount. The two things worth pinning are that the uploaded path is
     SELECTED afterwards (otherwise Start still uses the stale one and the
     upload looks like it did nothing), and that no key material is persisted
     anywhere — the passphrase blanking in saveInfraConfig() would be pointless
     if the key body itself survived in localStorage. */
  section('Step 12 — key upload');

  const upCalls = [];
  w.fetch = makeStub(w, upCalls);
  w.eval("CURRENT_USER = { username: 'op', is_admin: true }");

  const fileEl  = d.getElementById('infra-key-file');
  const pasteEl = d.getElementById('infra-key-paste');
  const nameEl  = d.getElementById('infra-key-name');
  const upNote  = d.getElementById('infra-key-upload-note');
  ok(!!fileEl && !!pasteEl && !!nameEl && !!upNote, 'the upload controls exist');

  const PEM = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----';

  // Nothing selected and nothing pasted: refuse rather than post an empty body.
  upCalls.length = 0;
  await w.infraUploadKey();
  ok(upCalls.length === 0, 'with no file and no paste it does not call the sidecar');
  ok(/Choose a key file or paste one/i.test(upNote.textContent),
     'and says what to do', upNote.textContent);

  // A pasted key with no filename cannot be saved under a name.
  pasteEl.value = PEM;
  nameEl.value = '';
  upCalls.length = 0;
  await w.infraUploadKey();
  ok(upCalls.length === 0, 'a pasted key with no filename is refused locally');
  ok(/filename/i.test(upNote.textContent), 'and asks for one', upNote.textContent);

  // The real path.
  d.getElementById('infra-ssh-key-path').value = '/ssh-keys/stale';
  pasteEl.value = PEM;
  nameEl.value = 'engagement';
  upCalls.length = 0;
  await w.infraUploadKey();

  const post = upCalls.find(c => /tunnel\/keys$/.test(c.url));
  ok(!!post, 'the key is posted to tunnel/keys', upCalls.map(c => c.url));
  ok(post && post.body && typeof post.body.key_b64 === 'string' && post.body.key_b64.length > 0,
     'as base64 in a JSON body, matching how ingest travels', post && Object.keys(post.body || {}));
  ok(post && Buffer.from(post.body.key_b64, 'base64').toString('utf8').includes('BEGIN OPENSSH PRIVATE KEY'),
     'and the base64 really decodes to the key that was pasted');
  ok(post && post.body.filename === 'engagement', 'under the requested filename', post && post.body.filename);
  ok(post && !('X-Tunnel-Token' in (post.headers || {})),
     'still no token from the browser — nginx supplies it');

  ok(d.getElementById('infra-ssh-key-path').value === '/ssh-keys-uploaded/uploaded',
     'the uploaded path is selected, so Start uses it without retyping',
     d.getElementById('infra-ssh-key-path').value);
  ok(pasteEl.value === '', 'the pasted key is cleared from the DOM immediately');
  ok(/uploaded/.test(upNote.textContent) && /SHA256/.test(upNote.textContent),
     'and the fingerprint is reported back', upNote.textContent);

  // An encrypted key must move the operator to the matching auth mode, or the
  // start fails as a silent ssh re-prompt.
  d.getElementById('infra-ssh-auth-method').value = 'key';
  pasteEl.value = PEM;
  nameEl.value = 'locked';
  w.fetch = makeStub(w, upCalls, { keyUpload: { ok: true, name: 'locked', path: '/ssh-keys-uploaded/locked',
                                                encrypted: true, fingerprint: '256 SHA256:def locked (ED25519)',
                                                bytes: 500, overwritten: false } });
  await w.infraUploadKey();
  ok(d.getElementById('infra-ssh-auth-method').value === 'key_passphrase',
     'an encrypted upload switches the auth mode to key_passphrase',
     d.getElementById('infra-ssh-auth-method').value);

  // A rejected key must not be left sitting in the textarea.
  w.fetch = async () => ({
    ok: false, status: 400,
    headers: { get: h => (h.toLowerCase() === 'content-type' ? 'application/json' : null) },
    json: async () => ({ ok: false, error: 'that file does not look like an SSH private key', code: 'not_a_private_key' }),
  });
  pasteEl.value = 'not a key at all';
  nameEl.value = 'junk';
  await w.infraUploadKey();
  ok(pasteEl.value === '', 'a REJECTED key is cleared from the DOM too');
  ok(/private key/i.test(upNote.textContent), 'and the sidecar reason is shown', upNote.textContent);

  /* Key material must never be persisted. saveInfraConfig() already blanks the
     passphrase; the uploader must not undo that by leaving the body anywhere. */
  w.fetch = makeStub(w, upCalls);
  pasteEl.value = PEM;
  nameEl.value = 'persisted';
  await w.infraUploadKey();
  w.infraSave();
  const dump = JSON.stringify(w.localStorage);
  ok(!/BEGIN OPENSSH PRIVATE KEY/.test(dump) && !/b3BlbnNzaA/.test(dump),
     'no key material reaches localStorage, in any form');

  // Delete asks first, and a refusal must not call the sidecar.
  d.getElementById('infra-ssh-key-path').value = '/ssh-keys-uploaded/uploaded';
  w.confirm = () => false;
  upCalls.length = 0;
  await w.infraDeleteKey();
  ok(!upCalls.some(c => /keys\//.test(c.url)), 'a cancelled delete calls nothing');

  w.confirm = () => true;
  upCalls.length = 0;
  await w.infraDeleteKey();
  const del = upCalls.find(c => /tunnel\/keys\/uploaded$/.test(c.url));
  ok(!!del, 'a confirmed delete targets the selected key by name', upCalls.map(c => c.url));
  ok(d.getElementById('infra-ssh-key-path').value === '',
     'and the now-dead path is cleared from the form');

  // Public-key derivation, for pasting into the far end's authorized_keys.
  d.getElementById('infra-ssh-key-path').value = '/ssh-keys-uploaded/uploaded';
  upCalls.length = 0;
  await w.infraShowPublicKey();
  const pub = upCalls.find(c => /tunnel\/keys\/uploaded\/public$/.test(c.url));
  ok(!!pub, 'the public half is requested for the selected key', upCalls.map(c => c.url));
  ok(d.getElementById('infra-key-pub-out').value === 'ssh-ed25519 AAAAPUB test',
     'and rendered for copying', d.getElementById('infra-key-pub-out').value);

  // Writes are admin-only in the sidecar; the UI says so rather than failing opaquely.
  w.eval("CURRENT_USER = { username: 'analyst', is_admin: false }");
  w.infraApplyKeyAdminGate();
  ok(d.getElementById('infra-key-upload').disabled === true,
     'a non-admin sees the upload control disabled');
  ok(d.getElementById('infra-key-delete').disabled === true, 'and delete disabled');
  ok(/administrator/i.test(upNote.textContent), 'and is told why', upNote.textContent);

  w.eval("CURRENT_USER = { username: 'op', is_admin: true }");
  w.infraApplyKeyAdminGate();
  ok(d.getElementById('infra-key-upload').disabled === false,
     'and an admin gets them back');

  /* ── Step 13: the passphrase follows the KEY, not the dropdown ─────
     The failure this closes: a passphrase-protected key started under "SSH key
     (no passphrase)" gets -o BatchMode=yes. ssh offers the PUBLIC half of an
     encrypted key quite happily and only needs to decrypt once the far end
     ACCEPTS it, so the error arrives as the far end's "Permission denied
     (publickey)" for a key the far end had just accepted — and sends the
     operator to audit an authorized_keys file that was never wrong. */
  section('Step 13 — passphrase follows the key');

  const TWO_KEYS = {
    ok: true, roots: ['/ssh-keys-uploaded'], default_key_path: '', count: 2,
    keys: [
      { path: '/ssh-keys-uploaded/plain',  name: 'plain',  encrypted: false },
      { path: '/ssh-keys-uploaded/locked', name: 'locked', encrypted: true  },
    ],
  };
  w.fetch = makeStub(w, upCalls, { keys: TWO_KEYS });

  const pathEl = d.getElementById('infra-ssh-key-path');
  const passEl = d.getElementById('infra-ssh-key-pass');
  const modeEl = d.getElementById('infra-ssh-auth-method');
  const advice = d.getElementById('infra-ssh-key-note');

  pathEl.value = '/ssh-keys-uploaded/locked';
  modeEl.value = 'key';
  await w.infraLoadKeys();

  ok(w.infraKeyEncrypted('/ssh-keys-uploaded/locked') === true &&
     w.infraKeyEncrypted('/ssh-keys-uploaded/plain') === false,
     'the encrypted flag from the listing is kept, not dropped into the datalist');
  ok(w.infraKeyEncrypted('/ssh-keys-uploaded/never-listed') === null,
     'and an unlisted path gets no opinion rather than a guess');

  ok(passEl.disabled === false,
     'an encrypted key enables the passphrase box even under the no-passphrase mode');
  ok(/passphrase-protected/i.test(advice.textContent),
     'and the note says so', advice.textContent);

  // The block itself: this is the request that used to reach the sidecar.
  d.getElementById('infra-ssh-user').value = 'root';
  d.getElementById('infra-ssh-host').value = '203.0.113.9';
  d.getElementById('infra-ssh-local-port').value = '1080';
  passEl.value = '';
  let built = w.infraBuildStartPayload(w.infraReadForm());
  ok(!!built.error, 'an encrypted key with no passphrase never leaves the browser', built);
  ok(/locked/.test(built.error || ''), 'the error names the key', built.error);
  ok(/Permission denied \(publickey\)/.test(built.error || ''),
     'and pre-empts the far-end message it would be mistaken for', built.error);

  // With the passphrase it goes, and it goes even though the dropdown says "key".
  passEl.value = 'hunter2';
  built = w.infraBuildStartPayload(w.infraReadForm());
  ok(!built.error, 'with the passphrase it is allowed through', built.error);
  ok(built.payload && built.payload.key_passphrase === 'hunter2',
     'and the passphrase is sent under auth_method "key" too',
     built.payload && Object.keys(built.payload));

  // The converse: a key with no passphrase can never use one.
  pathEl.value = '/ssh-keys-uploaded/plain';
  modeEl.value = 'key_passphrase';
  w.infraToggleAuthFields();
  ok(passEl.disabled === true, 'an unencrypted key disables the passphrase box');
  ok(passEl.value === '', 'and clears whatever was in it');
  built = w.infraBuildStartPayload(w.infraReadForm());
  ok(!built.error,
     'and key_passphrase mode on an unencrypted key is no longer a refusal', built.error);
  ok(built.payload && !('key_passphrase' in built.payload),
     'with no passphrase sent', built.payload && Object.keys(built.payload));

  /* The ordering bug: infraLoadKeys() refreshes BEFORE the uploader asserts its
     selection (deliberately — otherwise the listing reverts it), so its advisory
     described the PREVIOUSLY selected key. Here the listing is a beat behind and
     does not contain the upload at all. */
  pathEl.value = '/ssh-keys-uploaded/plain';
  modeEl.value = 'key';
  passEl.value = '';
  pasteEl.value = PEM;
  nameEl.value = 'fresh';
  w.fetch = makeStub(w, upCalls, {
    keys: TWO_KEYS,                       // stale: no 'fresh' in it
    keyUpload: { ok: true, name: 'fresh', path: '/ssh-keys-uploaded/fresh',
                 encrypted: true, fingerprint: '256 SHA256:xyz fresh (ECDSA)',
                 bytes: 557, overwritten: false },
  });
  await w.infraUploadKey();
  ok(pathEl.value === '/ssh-keys-uploaded/fresh',
     'the freshly uploaded key is still the selected one', pathEl.value);
  ok(/fresh/.test(advice.textContent) && /passphrase-protected/i.test(advice.textContent),
     'and the advisory describes THAT key, not the one selected before it',
     advice.textContent);
  ok(passEl.disabled === false,
     'with the passphrase box live, from the upload response rather than the stale listing');

  w.eval('clearTimeout(_infraTorPoll)');   // stop the bootstrap watcher

  console.log(`\n${failures ? 'FAILED' : 'PASSED'} — ${checks - failures}/${checks} checks`);
  process.exit(failures ? 1 : 0);
}

main().catch(e => {
  console.error('FATAL', e);
  process.exit(2);
});
