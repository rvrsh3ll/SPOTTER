#!/usr/bin/env node
/*
 * Headless smoke test for the "Out of Scope" (OoS) entity mark.
 *
 * Why this exists
 * ---------------
 * OoS is a THIRD operator mark alongside Compromised and Of Interest, but it is
 * not cosmetic like "Hide". An OoS entity must be genuinely excluded — from the
 * Targets tab views, from the roster export, from the list_targets chat tool, and
 * (server-side, in WF10) from scoring and the analysis output. "Hide" only tidies
 * the roster and still ships every row; OoS removes the entity from the engagement.
 *
 * This test pins the operator-visible client-side invariants:
 *
 *   1. People view: an OoS person is gone from the roster; the footer says
 *      "N out of scope"; the reveal toggle shows the row again, struck through
 *      (tr-oos) and badged OoS; clearing the mark restores it to the roster.
 *   2. Assets view: same for an OoS asset (keyed by name).
 *   3. markOutOfScope()/unmarkOutOfScope() via selected checkboxes write the
 *      per-campaign store and re-render.
 *   4. buildTargetRosterReport() DROPS OoS rows entirely (not flagged like hidden)
 *      and records the excluded count in its meta — and no longer throws (this
 *      function also carried a stale `devs` reference that is now `assets`).
 *   5. _toolListTargets() never returns an OoS individual or host to the chat LLM.
 *
 *   node scripts/smoke_frontend_oos.js
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

function tres() { return d.getElementById('tres'); }
function footerText() {
  const divs = [...d.querySelectorAll('#tres > div')];
  return divs.length ? (divs[divs.length - 1].textContent || '').trim() : '';
}
function rowByLabel(label) {
  // A data table row whose checkbox carries this label.
  const cb = [...d.querySelectorAll('#tres .trow-cb')].find(c => c.dataset.label === label);
  return cb ? cb.closest('tr') : null;
}

function renderPeople(list) {
  w.eval(`_targetsView='individuals';
          _targetsCache=${JSON.stringify({ list, assets: [], deviceDossier: {}, dossierTotal: list.length, assetTotal: 0, listCap: 0, ts: 1 })};`);
  w.renderTargetsView();
}
function renderAssets(assets) {
  w.eval(`_targetsView='assets';
          _targetsCache=${JSON.stringify({ list: [], assets, deviceDossier: {}, dossierTotal: 0, assetTotal: assets.length, listCap: 0, ts: 1 })};`);
  w.renderTargetsView();
}

setTimeout(async () => {
  console.log('Targets tab — Out of Scope (OoS) mark');

  const people = [
    { label: 'Alice Admin', username: 'aadmin', attack_score: 30 },
    { label: 'Bob User',    username: 'buser',  attack_score: 10 },
  ];
  const assets = [
    { id: 'a0', name: 'DC01', type: 'HOST', os: 'Windows', score: 40 },
    { id: 'a1', name: 'WS02', type: 'HOST', os: 'Windows', score: 12 },
  ];

  /* ── 1. People: OoS removes from view, reveal, badge, footer ────────────── */
  section('People · removed from view');
  w.saveOOSTargets({});                 // clean slate
  w.setShowOOS(false);
  w.saveOOSTargets({ 'Alice Admin': { ts: 1 } });
  renderPeople(people);
  ok(rowByLabel('Alice Admin') === null, 'OoS person is absent from the roster by default');
  ok(rowByLabel('Bob User')    !== null, 'a non-OoS person still renders');
  ok(/1 out of scope/i.test(footerText()), 'footer discloses "1 out of scope"', footerText());
  const oosBtn = d.getElementById('show-oos-btn');
  ok(oosBtn && oosBtn.style.display !== 'none', 'the "Out of scope" reveal button is shown');
  ok(oosBtn && /out of scope \(1\)/i.test(oosBtn.textContent), 'the reveal button counts 1', oosBtn && oosBtn.textContent);

  section('People · reveal to manage');
  w.setShowOOS(true);
  w.renderTargetsView();
  const revealed = rowByLabel('Alice Admin');
  ok(revealed !== null, 'revealing shows the OoS person again');
  ok(revealed && /\btr-oos\b/.test(revealed.className), 'the revealed row carries the tr-oos class', revealed && revealed.className);
  ok(revealed && /OoS/.test(revealed.innerHTML) && /badge-oos/.test(revealed.innerHTML), 'the revealed row shows an OoS badge');

  /* ── 2. mark / unmark via selection ─────────────────────────────────────── */
  section('People · markOutOfScope() / unmarkOutOfScope() via checkboxes');
  w.saveOOSTargets({});
  w.setShowOOS(false);
  renderPeople(people);
  const bobCb = [...d.querySelectorAll('#tres .trow-cb')].find(c => c.dataset.label === 'Bob User');
  bobCb.checked = true;
  w.markOutOfScope();
  ok(!!w.getOOSTargets()['Bob User'], 'markOutOfScope() wrote the mark to the per-campaign store');
  ok(rowByLabel('Bob User') === null, 'the marked person left the roster immediately');
  // re-select the (now hidden) row by revealing, then clear
  w.setShowOOS(true); w.renderTargetsView();
  [...d.querySelectorAll('#tres .trow-cb')].find(c => c.dataset.label === 'Bob User').checked = true;
  w.unmarkOutOfScope();
  ok(!w.getOOSTargets()['Bob User'], 'unmarkOutOfScope() cleared the mark');

  /* ── 3. Assets: OoS removes from view (keyed by name) ───────────────────── */
  section('Assets · removed from view');
  w.saveDevOOSTargets({});
  w.setShowOOS(false);
  w.saveDevOOSTargets({ 'DC01': { ts: 1 } });
  renderAssets(assets);
  ok(rowByLabel('DC01') === null, 'OoS asset is absent from the roster by default');
  ok(rowByLabel('WS02') !== null, 'a non-OoS asset still renders');
  ok(/1 out of scope/i.test(footerText()), 'asset footer discloses "1 out of scope"', footerText());
  w.setShowOOS(true); w.renderTargetsView();
  const dc = rowByLabel('DC01');
  ok(dc !== null && /\btr-oos\b/.test(dc.className), 'revealed OoS asset carries tr-oos', dc && dc.className);
  ok(dc !== null && /badge-oos/.test(dc.innerHTML), 'revealed OoS asset shows an OoS badge');

  /* ── 4. roster export drops OoS rows + records the count, and does not throw */
  section('Roster export · OoS excluded, no throw');
  w.saveOOSTargets({ 'Alice Admin': { ts: 1 } });
  w.saveDevOOSTargets({ 'DC01': { ts: 1 } });
  w.eval(`_targetsCache=${JSON.stringify({ list: people, assets, deviceDossier: {}, dossierTotal: 2, assetTotal: 2, ts: 1 })};`);
  let report = null, threw = null;
  try { report = w.buildTargetRosterReport(); } catch (e) { threw = e; }
  ok(threw === null, 'buildTargetRosterReport() does not throw (stale `devs` ref fixed)', threw && String(threw));
  if (report) {
    const indSec   = report.sections.find(s => s.key === 'individuals');
    const assetSec = report.sections.find(s => s.key === 'assets');
    const indNames = indSec ? indSec.blocks[0].rows.map(r => r[1]) : [];
    const assetNames = assetSec ? assetSec.blocks[0].rows.map(r => r[2]) : [];
    ok(!indNames.includes('Alice Admin') && indNames.includes('Bob User'),
       'export individuals drop the OoS person, keep the rest', JSON.stringify(indNames));
    ok(!assetNames.includes('DC01') && assetNames.includes('WS02'),
       'export assets drop the OoS host, keep the rest', JSON.stringify(assetNames));
    const oosMeta = (report.meta || []).find(m => m[0] === 'Out of scope');
    ok(oosMeta && /2 excluded/i.test(oosMeta[1]), 'export meta records "2 excluded"', oosMeta && oosMeta[1]);
    const devMeta = (report.meta || []).find(m => m[0] === 'Devices');
    ok(devMeta && devMeta[1] === '1', 'export meta "Devices" count reflects the surviving asset', devMeta && devMeta[1]);
  }

  /* ── 5. list_targets chat tool never returns an OoS entity ───────────────── */
  section('list_targets · OoS entities never surface to the chat LLM');
  w.saveOOSTargets({ 'Alice Admin': { ts: 1 } });
  w.saveDevOOSTargets({ 'DC01': { ts: 1 } });
  w.eval(`_targetsCache=${JSON.stringify({
    list: people,
    devices: [{ hostname: 'DC01', attack_score: 40 }, { hostname: 'WS02', attack_score: 12 }],
    assets: [], deviceDossier: {}, dossierTotal: 2, assetTotal: 0, ts: Date.now(),
  })};`);
  const res = await w._toolListTargets({ kind: 'both', limit: 50 });
  const indRows = (((res.data || {}).individuals || {}).rows || []).map(r => r.name);
  const devRows = (((res.data || {}).devices || {}).rows || []).map(r => r.hostname);
  ok(!indRows.includes('Alice Admin') && indRows.includes('Bob User'),
     'list_targets omits the OoS individual', JSON.stringify(indRows));
  ok(res.data.individuals.total === 1, 'list_targets total counts only in-scope individuals', res.data.individuals.total);
  ok(!devRows.includes('DC01') && devRows.includes('WS02'),
     'list_targets omits the OoS host', JSON.stringify(devRows));
  ok(res.data.devices.total === 1, 'list_targets total counts only in-scope hosts', res.data.devices.total);

  /* ── 6. Cloud buckets: recon-panel marking shares the Assets store ───────── */
  section('Buckets · recon panel marking + exclusion (shared with Assets tab)');
  w.saveDevOOSTargets({}); w.saveDevCompromised({}); w.saveDevOITargets({});
  w.setShowOOS(false);
  const reconData = {
    domain: 'example.com',
    open_buckets: [
      { bucket: 'example-public', endpoint: 'example-public.s3.amazonaws.com', provider: 'aws', service: 's3', exposure_score: 70, object_count: 5, listable: true, sensitive_categories: [] },
      { bucket: 'example-logs',   endpoint: 'example-logs.s3.amazonaws.com',   provider: 'aws', service: 's3', exposure_score: 40, object_count: 2, listable: true, sensitive_categories: [] },
    ],
    bucket_findings: [{ category: 'secret', endpoint: 'example-logs.s3.amazonaws.com', key: 'aws_keys.txt' }],
  };
  const drContent = () => (d.getElementById('dr-content').innerHTML || '');

  w.renderDomainRecon(reconData);
  ok(/example-public/.test(drContent()) && /example-logs/.test(drContent()), 'both buckets render in the recon panel');
  ok(/bkt-mk/.test(drContent()) && />COMP</.test(drContent()) && />OoS</.test(drContent()),
     'each bucket row shows clickable COMP/OI/OoS mark chips');

  w.toggleBucketMark('oos', 'example-logs');
  ok(!!w.getDevOOSTargets()['example-logs'],
     'toggleBucketMark writes the shared device/asset OoS store, keyed by bucket name');
  w.renderDomainRecon(reconData);
  ok(/example-public/.test(drContent()) && !/example-logs\.s3/.test(drContent()),
     'the OoS bucket drops out of the recon list by default');
  ok(/Out of scope \(1\)/.test(drContent()), 'the recon bucket section offers a reveal toggle');

  w.setShowOOS(true);
  w.renderDomainRecon(reconData);
  ok(/example-logs\.s3/.test(drContent()) && /dr-oos/.test(drContent()),
     'revealing shows the OoS bucket struck through (dr-oos)');

  const owReport = w.buildAssetOwnershipReport(reconData);
  const bktSec = owReport.sections.find(s => s.key === 'buckets');
  const bktCells = bktSec ? bktSec.blocks.filter(b => b.type === 'table').flatMap(b => b.rows).map(r => r.join(' ')) : [];
  ok(bktCells.some(x => /example-public/.test(x)) && !bktCells.some(x => /example-logs/.test(x)),
     'recon report export drops the OoS bucket and its flagged object', JSON.stringify(bktCells));

  // The recon mark is the SAME fact in the Assets tab (CLOUD row keyed by name==bucket).
  w.setShowOOS(false);
  w.eval(`_targetsView='assets'; _targetsCache=${JSON.stringify({
    list: [], deviceDossier: {}, dossierTotal: 0, assetTotal: 2, ts: 1,
    assets: [{ id: 'c0', name: 'example-logs', type: 'CLOUD', score: 40 }, { id: 'c1', name: 'example-public', type: 'CLOUD', score: 70 }],
  })};`);
  w.renderTargetsView();
  ok(rowByLabel('example-logs') === null && rowByLabel('example-public') !== null,
     'the recon OoS mark also hides the bucket in the Assets tab (one shared store)');

  /* ── 7. Web tab: card marking + exclusion (shared with Assets tab) ───────── */
  section('Web tab · marking + exclusion (shared with Assets tab)');
  w.saveDevOOSTargets({}); w.saveDevCompromised({}); w.saveDevOITargets({});
  w.setWebFilter('all'); w.searchWeb('');
  w.setShowOOS(false);
  w.eval(`_webCache = ${JSON.stringify({ sites: [
    { id: 'w0', url: 'https://portal.example.com', title: 'Login', resolved: '10.0.0.5', has_screenshot: true, is_high_value: true },
    { id: 'w1', url: 'https://blog.example.com',   title: 'Blog',  resolved: '10.0.0.6', has_screenshot: false },
  ], stats: { total: 2 }, ts: Date.now() })};`);
  const webRes = () => (d.getElementById('web-res').innerHTML || '');

  w.renderWeb();
  ok(/portal\.example/.test(webRes()) && /blog\.example/.test(webRes()), 'both web endpoints render');
  ok(/bkt-mk/.test(webRes()) && />OoS</.test(webRes()), 'each web card shows COMP/OI/OoS mark chips');

  w.toggleWebMark('oos', 'https://blog.example.com');
  ok(!!w.getDevOOSTargets()['https://blog.example.com'],
     'toggleWebMark writes the shared device/asset OoS store, keyed by url');
  ok(/portal\.example/.test(webRes()) && !/blog\.example/.test(webRes()),
     'the OoS endpoint drops from the Web tab by default');
  const wbtn = d.getElementById('web-oos-btn');
  ok(wbtn && wbtn.style.display !== 'none' && /out of scope \(1\)/i.test(wbtn.textContent),
     'the Web tab reveal toggle shows the OoS count', wbtn && wbtn.textContent);

  w.toggleShowOOSWeb();
  ok(/blog\.example/.test(webRes()) && /web-oos/.test(webRes()),
     'revealing shows the OoS endpoint struck through (web-oos)');

  // Same mark, same fact in the Assets tab (WEBSITE row keyed by name==url).
  w.setShowOOS(false);
  w.eval(`_targetsView='assets'; _targetsCache=${JSON.stringify({
    list: [], deviceDossier: {}, dossierTotal: 0, assetTotal: 2, ts: 1,
    assets: [{ id: 'x0', name: 'https://blog.example.com', type: 'WEBSITE', score: 10 },
             { id: 'x1', name: 'https://portal.example.com', type: 'WEBSITE', score: 20 }],
  })};`);
  w.renderTargetsView();
  ok(rowByLabel('https://blog.example.com') === null && rowByLabel('https://portal.example.com') !== null,
     'the Web tab OoS mark also hides the endpoint in the Assets tab (one shared store)');

  console.log(`\n${failures ? 'FAIL' : 'PASS'} — ${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 100);
