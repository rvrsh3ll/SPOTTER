#!/usr/bin/env node
/*
 * Headless smoke test for the Domain Recon localStorage cache under quota pressure.
 *
 * Why this exists
 * ---------------
 * saveDomainRecons() used to be a bare localStorage.setItem. A full recon record for
 * a large domain runs to ~1MB (up to 1000 masked Flare rows, an uncapped
 * credential_matches list, plus every discovered web/cloud/service asset), and
 * s.domainRecon holds one record per campaign+domain, so a handful of campaigns can
 * exhaust the ~5MB origin quota on their own.
 *
 * When it did, QuotaExceededError propagated out of the write, through
 * runDomainRecon's catch, and the operator was told:
 *
 *   Connection failed: Failed to execute 'setItem' on 'Storage': Setting the value
 *   of 's.domainRecon' exceeded the quota.
 *   Ensure n8n is running and workflow 13 is imported and active.
 *
 * Both halves were wrong and expensive: the recon had SUCCEEDED (WF13 and n8n were
 * healthy, and the message sent the operator to debug them), and because the throw
 * happened before renderDomainRecon, the results of a multi-minute multi-source pull
 * were discarded unseen.
 *
 * Asserted invariants:
 *   1. isQuotaError() recognises the real browser messages
 *   2. a normal record still writes verbatim — no compaction, no toast
 *   3. under pressure the write degrades (compact → shed) instead of failing, and
 *      the run in hand is the LAST thing sacrificed
 *   4. compaction keeps every scalar total exact and records the true list lengths
 *   5. saveDomainRecons NEVER throws, even with no room at all, and reports false
 *   6. a non-quota storage error is still propagated (not silently swallowed)
 *   7. end to end: a recon that overflows storage still renders, and the failure
 *      banner does not blame n8n/workflow 13
 *   8. the credential-match cap is DISCLOSED — WF13 now caps the list server-side
 *      (FLARE_DOMAIN_MATCH_CAP, the root cause of the oversized record), so a
 *      silent cap would leave a specific exposed admin absent with nothing on
 *      screen to say why
 *   9. reclaimLocalStorage() frees dead weight and spares live campaign data
 *
 *   node scripts/smoke_frontend_recon_cache.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed (all are reported).
 */

'use strict';

const fs = require('fs');

const { INDEX, loadJsdom } = require('./smoke_frontend_lib');
const { JSDOM, VirtualConsole } = loadJsdom();

let failures = 0, checks = 0;
function ok(cond, label, extra) {
  checks++;
  if (cond) { console.log(`  ok    ${label}`); return true; }
  failures++;
  console.error(`  FAIL  ${label}${extra !== undefined ? `\n        got: ${extra}` : ''}`);
  return false;
}
function section(t) { console.log(`\n── ${t}`); }

const vc = new VirtualConsole();
vc.on('jsdomError', () => { /* CSS/layout noise jsdom cannot do */ });

const dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
  runScripts: 'dangerously', pretendToBeVisual: true,
  url: 'http://localhost:8080/', virtualConsole: vc,
});
const w = dom.window;
const d = w.document;

/* A localStorage with a byte budget, so the quota ladder can actually be walked.
   `budget` is total bytes across all keys; setItem throws the same DOMException
   name Chrome/Firefox raise. */
function installFakeStorage(budget) {
  const map = new Map();
  const used = (skipKey) => {
    let n = 0;
    for (const [k, v] of map) if (k !== skipKey) n += k.length + v.length;
    return n;
  };
  const fake = {
    budget,
    writes: 0,
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    removeItem(k) { map.delete(k); },
    key(i) { return [...map.keys()][i] ?? null; },
    clear() { map.clear(); },
    setItem(k, v) {
      k = String(k); v = String(v);
      fake.writes++;
      if (used(k) + k.length + v.length > fake.budget) {
        const e = new Error(`Failed to execute 'setItem' on 'Storage': `
          + `Setting the value of '${k}' exceeded the quota.`);
        e.name = 'QuotaExceededError';
        throw e;
      }
      map.set(k, v);
    },
    get length() { return map.size; },
  };
  Object.defineProperty(w, 'localStorage', { value: fake, configurable: true, writable: true });
  return fake;
}

/* A recon record whose heavy lists are long enough to be worth compacting.
   `scale` multiplies the list lengths; the scalar totals deliberately do NOT match
   the list lengths, exactly as WF13 ships them (ct_total is the CT log's totalCount,
   while ct_certificates is capped at 100 server-side). */
function reconRecord(domain, scale) {
  const list = (n, mk) => Array.from({ length: n }, (_, i) => mk(i));
  return {
    id: 'rec-' + domain,
    campaignId: 'camp-1',
    domain,
    timestamp: '2026-09-08T00:00:00.000Z',
    // scalar totals — must survive compaction exactly
    ct_total: 91234,
    fofa_total: 4567,
    // Why FOFA looks the way it does. It must survive compaction with the
    // fofa_* keys it explains, or a reloaded record shows data with no reason
    // attached -- or worse, a reason with no data.
    fofa_status: { state: 'ok', detail: '', fields: 'host,ip,port', attempts: 1 },
    flare_exposed_creds: 88123,
    bucket_candidates_tested: 412,
    registrar: 'Example Registrar, Inc.',
    // high-signal short lists — never trimmed
    open_buckets: [{ name: 'example-backups', provider: 'aws' }],
    shodan_vulns: ['CVE-2021-44228'],
    errors: [],
    // long tails — trimmed under pressure
    flare_domain_breaches: list(1000 * scale, i => ({
      email: `user${i}@${domain}`, source: 'stealer_logs', event_type: 'leak',
      has_password: true, breach_date: '2025-04-01', padding: 'x'.repeat(80),
    })),
    credential_matches: list(600 * scale, i => ({
      email: `user${i}@${domain}`, graph_user: `EXAMPLE\\user${i}`,
      node_id: 'n-' + i, breach_source: 'stealer_logs', event_type: 'leak',
      has_password: true, is_admin: false, breach_count: 3, has_stealer: true,
    })),
    // The pairing that creates an orphaned value tag: fofa_results is capped at
    // 25 by _RECON_CACHE_CAPS, fofa_ports is NOT capped, so after a reload the
    // card paints ports whose host rows are gone. The FOFA card has to render
    // those inert and blame the cache -- see smoke_frontend_perimeter.js.
    fofa_ports: [80, 443, 8443, 9999],
    fofa_results: list(40 * scale, i => ({
      host: `fh${i}.${domain}`, ip: `203.0.113.${i % 250}`, port: i === 0 ? '9999' : '443',
      protocol: 'https', server: 'nginx', country: 'US', title: 'T' + i,
    })),
    subdomains: list(800 * scale, i => `host${i}.${domain}`),
    web_assets: list(400 * scale, i => ({ url: `https://host${i}.${domain}`, platform: 'nginx' })),
    services: list(300 * scale, i => ({ ip: `10.0.${i % 250}.${i % 250}`, ports: [80, 443, 8080] })),
  };
}

const bytes = (o) => JSON.stringify(o).length;

setTimeout(() => {
  console.log('Domain Recon — localStorage cache under quota pressure');

  /* ── 1. the quota-error test itself ───────────────────────────────────────── */
  section('isQuotaError');
  const chrome = new Error("Failed to execute 'setItem' on 'Storage': "
    + "Setting the value of 's.domainRecon' exceeded the quota.");
  chrome.name = 'QuotaExceededError';
  ok(w.isQuotaError(chrome) === true,
     'recognises the Chrome QuotaExceededError the operator actually reported');
  const ff = new Error('The quota has been exceeded.');
  ff.name = 'NS_ERROR_DOM_QUOTA_REACHED';
  ok(w.isQuotaError(ff) === true, 'recognises the Firefox variant');
  ok(w.isQuotaError(new w.TypeError('x is not a function')) === false,
     'does not classify an unrelated TypeError as a storage failure');
  ok(w.isQuotaError(null) === false, 'tolerates a null error');

  /* ── 2. the ordinary path is untouched ────────────────────────────────────── */
  section('Normal write · plenty of room');
  installFakeStorage(5 * 1024 * 1024);
  const toasts = [];
  w.eval('window.__toasts = [];');
  w.toast = (m, t) => { toasts.push({ m: String(m), t }); };

  const small = { id: 'r1', campaignId: 'camp-1', domain: 'example.com', ct_total: 12, subdomains: ['a.example.com'] };
  ok(w.saveDomainRecons([small]) === true, 'a small record writes and reports true');
  const readBack = w.getDomainRecons();
  ok(readBack.length === 1 && readBack[0].domain === 'example.com',
     'the record round-trips through getDomainRecons', JSON.stringify(readBack.length));
  ok(readBack[0]._cache_compact === undefined,
     'no compaction marker on a record that fit as-is');
  ok(toasts.length === 0, 'no operator toast on the happy path', JSON.stringify(toasts));

  /* ── 3. compaction is lossless for scalars, honest about lists ───────────── */
  section('_compactReconForCache');
  const full = reconRecord('example.com', 1);
  const comp = w._compactReconForCache(full);
  ok(bytes(comp) < bytes(full) / 2,
     'compaction more than halves the record', `${bytes(full)} → ${bytes(comp)}`);
  ok(comp.ct_total === 91234 && comp.fofa_total === 4567
     && comp.flare_exposed_creds === 88123 && comp.bucket_candidates_tested === 412,
     'every scalar total survives compaction exactly',
     JSON.stringify({ ct: comp.ct_total, fofa: comp.fofa_total, creds: comp.flare_exposed_creds }));
  ok(comp.domain === 'example.com' && comp.campaignId === 'camp-1' && comp.id === full.id,
     'identity fields survive (campaign scoping + merge keys)');
  ok(comp.open_buckets.length === 1 && comp.shodan_vulns.length === 1,
     'short high-signal findings are never trimmed');
  ok(comp.fofa_status && comp.fofa_status.state === 'ok',
     'fofa_status survives compaction alongside the fofa_* keys it explains',
     JSON.stringify(comp.fofa_status));
  // The orphaned-value-tag precondition, pinned end to end: the rows get capped,
  // the roll-up they were derived from does not, and the true pre-trim count is
  // recorded so the card can say WHY a port has no hosts behind it rather than
  // implying nothing listens there.
  ok(comp.fofa_results.length === 25 && comp.fofa_ports.length === 4
     && comp._cache_trimmed.fofa_results === full.fofa_results.length,
     'compaction caps fofa_results but leaves fofa_ports whole, and records the true count',
     JSON.stringify({ rows: comp.fofa_results.length, ports: comp.fofa_ports.length,
                      trimmed: comp._cache_trimmed.fofa_results }));
  ok(comp._cache_compact === true, 'the record is marked as compact');
  ok(comp._cache_trimmed.flare_domain_breaches === 1000
     && comp._cache_trimmed.credential_matches === 600,
     'the TRUE pre-trim lengths are recorded, so the UI cannot overstate the cache',
     JSON.stringify(comp._cache_trimmed));
  ok(comp.flare_domain_breaches.length === 150 && comp.credential_matches.length === 200,
     'the long tails are capped to their documented caps',
     `${comp.flare_domain_breaches.length}/${comp.credential_matches.length}`);
  ok(full.flare_domain_breaches.length === 1000,
     'compaction does not mutate the caller\'s record');
  const twice = w._compactReconForCache(comp);
  ok(twice._cache_trimmed.flare_domain_breaches === 1000,
     'a second compaction pass keeps the original length, not the trimmed one',
     JSON.stringify(twice._cache_trimmed));

  /* ── 4. degrade rather than fail; newest record is sacrificed last ────────── */
  section('Under pressure · history is trimmed before the run in hand');
  const fresh = reconRecord('example.com', 1);
  const older = [reconRecord('old1.example', 1), reconRecord('old2.example', 1)];
  // Room for the new record whole plus compacted history, but not for three full ones.
  installFakeStorage(bytes([fresh, ...older.map(r => w._compactReconForCache(r))]) + 512);
  toasts.length = 0;
  ok(w.saveDomainRecons([fresh, ...older]) === true,
     'the write succeeds by degrading instead of throwing');
  const stored = w.getDomainRecons();
  ok(stored.length === 3, 'all three records are still cached', JSON.stringify(stored.length));
  ok(stored[0].domain === 'example.com' && stored[0].flare_domain_breaches.length === 1000,
     'the run in hand is kept WHOLE — the history is what gets trimmed',
     `${stored[0].domain} / ${stored[0].flare_domain_breaches.length}`);
  ok(stored[1]._cache_compact === true && stored[2]._cache_compact === true,
     'the older records are the compacted ones');
  ok(toasts.some(t => /older domain recon/i.test(t.m)),
     'the operator is told the history lost detail', JSON.stringify(toasts.map(t => t.m)));

  section('Under heavy pressure · records are shed oldest-first');
  installFakeStorage(bytes([w._compactReconForCache(fresh)]) + 256);
  toasts.length = 0;
  ok(w.saveDomainRecons([fresh, ...older]) === true, 'still succeeds with room for only one');
  const shed = w.getDomainRecons();
  ok(shed.length === 1 && shed[0].domain === 'example.com',
     'the surviving record is the newest, not an arbitrary one', JSON.stringify(shed.map(r => r.domain)));
  ok(shed[0].ct_total === 91234 && shed[0].flare_exposed_creds === 88123,
     'the surviving record still reports exact totals');

  /* ── 5. no room at all: report, never throw ───────────────────────────────── */
  section('No room at all');
  installFakeStorage(64);
  toasts.length = 0;
  let threw = null;
  let ret;
  try { ret = w.saveDomainRecons([reconRecord('example.com', 1)]); }
  catch (e) { threw = e; }
  ok(threw === null,
     'saveDomainRecons does not throw — this is the bug that reported a healthy WF13 as down',
     threw && threw.message);
  ok(ret === false, 'it reports false so the caller can withhold the "cached" label', String(ret));
  ok(toasts.some(t => /ran successfully/i.test(t.m) && /storage is full/i.test(t.m)),
     'the operator is told the recon SUCCEEDED but was not cached',
     JSON.stringify(toasts.map(t => t.m)));
  ok(!toasts.some(t => /n8n|workflow 13|connection/i.test(t.m)),
     'nothing in the storage-failure path blames n8n or workflow 13',
     JSON.stringify(toasts.map(t => t.m)));

  /* ── 6. a non-quota error must not be swallowed ───────────────────────────── */
  section('Non-quota storage errors still surface');
  installFakeStorage(5 * 1024 * 1024);
  w.localStorage.setItem = () => { throw new w.TypeError('storage is disabled'); };
  let boom = null;
  try { w.saveDomainRecons([small]); } catch (e) { boom = e; }
  ok(boom !== null && /storage is disabled/.test(boom.message),
     'a real (non-quota) failure is propagated rather than reported as a cache trim',
     boom && boom.message);

  /* ── 7b. the server-side credential-match cap is disclosed ───────────────── */
  section('credential_matches cap disclosure');
  installFakeStorage(5 * 1024 * 1024);
  // WF13 capped 1,284 matches down to 500 and shipped the true total.
  const capped = { credential_matches: Array.from({ length: 500 }, (_, i) => ({ email: `u${i}@example.com` })),
                   credential_matches_total: 1284, credential_matches_truncated: true };
  const cc = w._credMatchCount(capped);
  ok(cc.shown === 500 && cc.total === 1284 && cc.truncated === true,
     'the server cap is reported as 500 of 1,284', JSON.stringify(cc));
  const note = w._credMatchNote(capped);
  ok(/1,284/.test(note) && /500/.test(note),
     'the disclosure note names both the shown and the true count', JSON.stringify(note));
  ok(/Configuration/.test(note),
     'the note says where to raise the cap', JSON.stringify(note));

  // A client-side compaction is the same question to the operator, so one number.
  const trimmedRec = { credential_matches: Array.from({ length: 200 }, (_, i) => ({ email: `u${i}@example.com` })),
                       _cache_trimmed: { credential_matches: 640 } };
  const tc = w._credMatchCount(trimmedRec);
  ok(tc.shown === 200 && tc.total === 640 && tc.truncated === true,
     'a locally COMPACTED list reports its pre-trim length through the same helper',
     JSON.stringify(tc));

  const plain = { credential_matches: [{ email: 'a@example.com' }, { email: 'b@example.com' }] };
  ok(w._credMatchCount(plain).truncated === false && w._credMatchNote(plain) === '',
     'an uncapped list discloses nothing — no note where none is warranted');
  ok(w._credMatchCount({}).total === 0 && w._credMatchCount(null).total === 0,
     'tolerates a missing list and a null record');

  /* ── 9. reclaim frees dead weight without touching live campaigns ─────────── */
  section('reclaimLocalStorage');
  installFakeStorage(5 * 1024 * 1024);
  w.eval(`localStorage.setItem('s.campaigns', JSON.stringify([{ id: 'camp-live', name: 'Live' }]));`);
  // One legacy entry with an inlined blob, one current metadata-only entry, one
  // belonging to a campaign that no longer exists, one with no campaign at all.
  w.eval(`localStorage.setItem('s.ingest_log', JSON.stringify([
    { id: 'a', campaignId: 'camp-live', filename: 'legacy.zip', dataUrl: 'data:application/zip;base64,${'A'.repeat(4000)}' },
    { id: 'b', campaignId: 'camp-live', filename: 'current.zip', size: 1024 },
    { id: 'c', campaignId: 'camp-dead', filename: 'orphan.zip', size: 2048 },
    { id: 'd', filename: 'pre-campaign.csv', size: 16 }
  ]));`);
  w.eval(`localStorage.setItem('s.pinned::camp-dead', JSON.stringify({ x: 1 }));`);
  w.eval(`localStorage.setItem('s.pinned::camp-live', JSON.stringify({ y: 1 }));`);
  w.eval(`localStorage.setItem('s.backup.campaignScope.v1', ${JSON.stringify('"' + 'z'.repeat(3000) + '"')});`);

  const usedBefore = w.lsUsage().total;
  ok(usedBefore > 0, 'lsUsage reports a non-zero total', usedBefore);
  const rec = w.reclaimLocalStorage();
  ok(rec.freed > 0, 'the reclaim frees bytes', `${usedBefore} → ${w.lsUsage().total} (freed ${rec.freed})`);
  ok(rec.blobs === 1, 'exactly the one legacy blob entry was stripped', rec.blobs);
  const afterLog = w.getIngestLog();
  const ids = afterLog.map(e => e.id).sort().join(',');
  ok(ids === 'a,b,d',
     'the orphaned campaign entry is dropped; the legacy, current and pre-campaign entries stay',
     ids);
  ok(afterLog.find(e => e.id === 'a').dataUrl === undefined
     && afterLog.find(e => e.id === 'a').filename === 'legacy.zip',
     'the legacy entry keeps its provenance metadata and loses only the inlined blob');
  ok(w.localStorage.getItem('s.pinned::camp-dead') === null,
     'the dead campaign\'s annotation map is removed');
  ok(w.localStorage.getItem('s.pinned::camp-live') !== null,
     'the LIVE campaign\'s annotation map is untouched');
  ok(w.localStorage.getItem('s.backup.campaignScope.v1') === null,
     'the one-time migration backup is dropped');
  const rec2 = w.reclaimLocalStorage();
  ok(rec2.blobs === 0 && rec2.orphans === 0,
     'a second reclaim is a no-op — it is idempotent', JSON.stringify(rec2));

  /* ── 7. end to end: results render, banner does not blame n8n ─────────────── */
  section('runDomainRecon · storage overflows mid-run');
  installFakeStorage(64);              // nothing will fit
  toasts.length = 0;
  const payload = reconRecord('example.com', 1);
  w.eval(`window.getActiveCamp = () => ({ id: 'camp-1', name: 'Example', sketchId: 'sk-1', objectives: {} });`);
  w.eval(`window._companyDomain = () => 'example.com';`);
  w.fetchJson = async () => payload;

  const emptyEl = d.getElementById('dr-empty');
  const contEl  = d.getElementById('dr-content');
  if (emptyEl) { emptyEl.innerHTML = ''; emptyEl.style.display = 'none'; }
  if (contEl)  contEl.innerHTML = '';

  w.runDomainRecon('example.com', ['dns']).then(() => {
    const banner = (emptyEl && emptyEl.style.display !== 'none') ? (emptyEl.innerHTML || '') : '';
    ok(!/Ensure n8n is running/i.test(banner),
       'the "Ensure n8n is running and workflow 13 is imported" banner does NOT appear '
       + 'for a storage failure', JSON.stringify(banner.slice(0, 200)));
    ok((contEl.innerHTML || '').length > 0,
       'the recon results still render — a failed cache write does not discard the run',
       `#dr-content length ${(contEl.innerHTML || '').length}`);
    ok((contEl.innerHTML || '').includes('example.com') || /example/i.test(contEl.innerHTML || ''),
       'the rendered panel is this run\'s data');
    const age = (d.getElementById('dr-cache-age') || {}).textContent || '';
    ok(!/cached/i.test(age),
       'the "cached" age label is withheld when nothing was cached', JSON.stringify(age));
    ok(toasts.some(t => t.t === 'ok' || /Domain recon \(/.test(t.m)),
       'the run is still reported as a success to the operator',
       JSON.stringify(toasts.map(t => `${t.t}:${t.m.slice(0, 60)}`)));

    console.log(`\n${failures ? 'FAIL' : 'PASS'} — ${checks - failures}/${checks} checks passed`);
    process.exit(failures ? 1 : 0);
  }).catch(e => {
    ok(false, 'runDomainRecon rejected — a storage failure escaped the run', e && e.stack);
    console.log(`\n${failures ? 'FAIL' : 'PASS'} — ${checks - failures}/${checks} checks passed`);
    process.exit(1);
  });
}, 120);
