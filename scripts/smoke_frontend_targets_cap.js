#!/usr/bin/env node
/*
 * Headless smoke test for the Targets tab's server-side result cap disclosure.
 *
 * Why this exists
 * ---------------
 * On a large SharpHound sketch (tens of thousands of individuals and devices) WF05's dossier
 * endpoint used to return the ENTIRE population — well over 100 MB, tens of seconds — and the
 * browser could not JSON.parse + render that many table rows, so the Targets tab
 * rendered nothing while the Tech tab (a small aggregated WF12 response) worked.
 * It read as "no targets data" when the data was in fact fine.
 *
 * The fix caps both lists to the top `list_cap` rows by score server-side and
 * ships `dossier_total` / `asset_total` so the UI can say so. A capped list
 * that does NOT disclose the cap is the dangerous state: the operator believes
 * they are looking at the whole environment when they are seeing the top slice,
 * and a specific low-ranked host/person is simply absent with nothing on screen
 * to say why. This test asserts the operator-visible invariant:
 *
 *   1. when total > shown, the footer says "top N of TOTAL by score"
 *   2. the tab badge shows the full population, not the shown count
 *   3. when total == shown (small sketch), NO cap note appears — the tab
 *      behaves exactly as it always did
 *   4. both views (people and assets) disclose independently
 *
 *   node scripts/smoke_frontend_targets_cap.js
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

function footerText() {
  // The summary line is the last <div> the render appends after the table.
  const divs = [...d.querySelectorAll('#tres > div')];
  return divs.length ? (divs[divs.length - 1].textContent || '').trim() : '';
}

// Build N minimal rows with descending scores so the ordering is unambiguous.
function inds(n)   { return Array.from({length: n}, (_, i) => ({ label: 'User'+i, username: 'u'+i, attack_score: n - i })); }
function assetsF(n){ return Array.from({length: n}, (_, i) => ({ id: 'a'+i, name: 'HOST'+i, type: 'HOST', os: 'Windows', score: n - i })); }

function render(view, list, assets, dossierTotal, assetTotal, listCap) {
  w.eval(`_targetsView = ${JSON.stringify(view)};
          _targetsCache = ${JSON.stringify({ list, assets, deviceDossier: {}, dossierTotal, assetTotal, listCap, ts: 1 })};`);
  w.renderTargetsView();
}

setTimeout(() => {
  console.log('Targets tab — server-side cap disclosure');

  /* ── CAPPED people: 3 shown, 34,790 exist ──────────────────────────────── */
  section('People · capped');
  render('individuals', inds(3), assetsF(3), 34790, 53222, 2000);
  const capFoot = footerText();
  ok(/top\s+3\s+of\s+[\d,]+\s+by score/i.test(capFoot),
     'footer discloses "top 3 of 34,790 by score" when the list is capped', capFoot);
  ok(/34[,]?790/.test(capFoot),
     'the disclosed total is the full population, not the shown count', capFoot);
  const indBadge = (d.getElementById('tv-ind-count').textContent || '');
  ok(/34[,]?790/.test(indBadge),
     'the People tab badge shows the full population', JSON.stringify(indBadge));

  /* ── UNCAPPED people: total == shown, small sketch ─────────────────────── */
  section('People · not capped (small sketch)');
  render('individuals', inds(3), assetsF(3), 3, 3, 0);
  const smallFoot = footerText();
  ok(!/top\s+\d+\s+of/i.test(smallFoot),
     'no cap note when total equals shown — behaves as it always did', smallFoot);
  ok(/3 targets/.test(smallFoot),
     'the plain count line still renders', smallFoot);

  /* ── CAPPED assets ─────────────────────────────────────────────────────── */
  section('Assets · capped');
  render('assets', inds(3), assetsF(3), 34790, 53222, 2000);
  const devFoot = footerText();
  ok(/top\s+3\s+of\s+[\d,]+\s+by score/i.test(devFoot),
     'asset footer discloses "top 3 of 53,222 by score" when capped', devFoot);
  ok(/53[,]?222/.test(devFoot),
     'the disclosed asset total is the full asset population', devFoot);
  const devBadge = (d.getElementById('tv-asset-count').textContent || '');
  ok(/53[,]?222/.test(devBadge),
     'the Assets tab badge shows the full asset population', JSON.stringify(devBadge));

  /* ── UNCAPPED assets ───────────────────────────────────────────────────── */
  section('Assets · not capped');
  render('assets', inds(3), assetsF(3), 3, 3, 0);
  const devSmall = footerText();
  ok(!/top\s+\d+\s+of/i.test(devSmall),
     'no cap note on a small asset list', devSmall);

  console.log(`\n${failures ? 'FAIL' : 'PASS'} — ${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 100);
