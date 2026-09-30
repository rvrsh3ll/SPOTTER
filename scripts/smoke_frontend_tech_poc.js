#!/usr/bin/env node
/*
 * Headless smoke test for the Vulnerable Technology card's exploit-availability
 * block (frontend/index.html, renderTechIntel).
 *
 * Why this exists
 * ---------------
 * This block renders operator-facing links to UNVETTED third-party code, built
 * from strings a stranger on GitHub chose. Four things must hold, and every one
 * of them fails silently in a click-through:
 *
 *   1. The unvetted warning renders on the card, next to the links it applies
 *      to. A warning that is present in the source but not in the DOM is worse
 *      than none, because it looks handled.
 *   2. A hostile repository name is escaped. `esc()` is applied by hand at each
 *      interpolation, so a single missed call is a stored-XSS in a red-team
 *      console -- and it would look completely normal until someone in the
 *      corpus tries it.
 *   3. Clicking a PoC link does not also fire the card's drilldown handler. The
 *      links sit inside a clickable card; without the closest() guard the panel
 *      opens behind the new tab every time.
 *   4. The empty state offers a working "Run enrichment" button. That text used
 *      to say "run enrichment" while no code path existed to do it.
 *
 * It also pins the JSON-string contract: WF12 parses top_pocs/mitre_techniques
 * out of the node property before sending them. If that regresses, the frontend
 * receives a raw string, .slice(0,4) walks CHARACTERS, and the card fills with
 * one tag per letter -- which renders without error.
 *
 *   node scripts/smoke_frontend_tech_poc.js
 *
 * Exit 0 = pass, 1 = at least one assertion failed (all are reported).
 *
 * What it CANNOT tell you: jsdom has no layout engine, so the amber/red badge
 * contrast and the card's overflow behaviour still need a real browser.
 */

const fs = require('fs');


// jsdom lives inside the global n8n install; fall back to a normal resolution
// so this keeps working if it is ever installed properly.
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

const XSS_NAME = 'evil"><img src=x onerror=window.__pwned=1>/poc';

const FIXTURE = {
  os_inventory: [], tech_catalog: {}, user_tech_profiles: [], attack_narratives: [],
  legacy_systems: [], total_devices: 1, total_individuals: 1,
  tech_user_map: {}, os_device_map: {}, device_dossier_map: {},
  vulnerable_tech: [{
    name: 'Apache HTTP Server', vendor: 'Apache', version: '2.4.41',
    cve_count: 5, composite_risk: 12,
    exploit_available: true, poc_count: 7,
    mitre_techniques: [{ id: 'T1190', technique_id: 'T1190', name: 'Exploit Public-Facing Application' }],
    affected_users: ['ALICE@EXAMPLE'],
    top_pocs: [
      { full_name: 'example-author/CVE-2021-41773-poc', url: 'https://github.com/example-author/CVE-2021-41773-poc',
        stars: 211, is_fork: false, trust: 'high', trust_score: 18.2,
        trust_signals: ['211 stars', 'not a fork'], cve_id: 'CVE-2021-41773', unvetted: true },
      { full_name: XSS_NAME, url: 'https://github.com/x/y',
        stars: 0, is_fork: true, trust: 'low', trust_score: -6,
        trust_signals: [], cve_id: 'CVE-2021-41773', unvetted: true },
    ],
  }],
};

const vc = new VirtualConsole();
vc.on('jsdomError', () => { /* CSS/layout noise jsdom cannot do */ });

const dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
  runScripts: 'dangerously', pretendToBeVisual: true,
  url: 'http://localhost:8080/', virtualConsole: vc,
});
const w = dom.window;

setTimeout(() => {
  console.log('Vulnerable Technology / exploit availability');

  // tiShowTech is a top-level function declaration, so it IS on window and can
  // be stubbed. (Top-level `let` in this file is not -- see the jsdom memo.)
  w.eval('window.__tiShown = null; tiShowTech = function (t) { window.__tiShown = t; };');

  w.renderTechIntel(FIXTURE);
  const card = w.document.querySelector('.ti-vuln-card');
  if (!ok(!!card, 'a vulnerable-technology card rendered')) { finish(); return; }

  const badge = card.querySelector('.ti-poc-badge');
  ok(badge && /7\s*PoC/i.test(badge.textContent), 'PoC count badge shows the repo count',
     badge && badge.textContent.trim());

  const warn = card.querySelector('.ti-poc-warn');
  ok(warn && /unvetted/i.test(warn.textContent),
     'unvetted warning renders on the card itself');

  ok(card.querySelectorAll('.ti-poc-row').length === 2, 'both PoC rows render',
     card.querySelectorAll('.ti-poc-row').length);

  const tiers = [...card.querySelectorAll('.ti-poc-trust')].map(e => e.textContent.trim());
  ok(tiers.join(',') === 'high,low', 'trust tiers render per repo', tiers.join(','));

  // --- escaping ---
  ok(!w.__pwned && !card.querySelector('img'),
     'hostile repository name is escaped, not parsed as markup');
  ok(card.textContent.includes(XSS_NAME),
     'hostile repository name still displays as literal text');

  // --- link hardening ---
  const link = card.querySelector('.ti-poc-link');
  ok(link && link.getAttribute('target') === '_blank' &&
     /noopener/.test(link.getAttribute('rel') || '') &&
     /noreferrer/.test(link.getAttribute('rel') || ''),
     'PoC links are target=_blank with noopener noreferrer',
     link && link.getAttribute('rel'));

  // --- click isolation ---
  w.__tiShown = null;
  link.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  ok(w.__tiShown === null,
     'clicking a PoC link does not also open the tech drilldown', w.__tiShown);

  w.__tiShown = null;
  card.querySelector('.ti-vuln-name').dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  ok(w.__tiShown === 'Apache HTTP Server',
     'clicking the card body still opens the tech drilldown', w.__tiShown);

  // --- external-service marker ---
  // A Service entry is external attack surface from domain recon, not software on
  // a workstation. Without the marker the card reads as "an endpoint runs this".
  w.renderTechIntel({ ...FIXTURE, vulnerable_tech: [{
    ...FIXTURE.vulnerable_tech[0], kind: 'service',
    host: '203.0.113.10', port: '[443]', name: 'AkamaiGHost',
    }, {
     ...FIXTURE.vulnerable_tech[0], kind: 'service',
     host: '203.0.113.11', port: '[8443]', name: 'AkamaiGHost', composite_risk: 14,
    }] });
  const svcCard = w.document.querySelector('.ti-vuln-card');
    ok(w.document.querySelectorAll('.ti-vuln-card').length === 1,
      'duplicate service entries are grouped by product',
      w.document.querySelectorAll('.ti-vuln-card').length);
  ok(!!svcCard.querySelector('.ti-kind-tag'), 'service entries are tagged as external');
  ok(/203\.0\.113\.10/.test(svcCard.textContent), 'service entries show their host',
     svcCard.textContent.slice(0, 90));
    ok(/203\.0\.113\.11/.test(svcCard.textContent), 'grouped service entries preserve additional hosts',
      svcCard.textContent.slice(0, 140));

  w.renderTechIntel(FIXTURE);
  ok(!w.document.querySelector('.ti-vuln-card .ti-kind-tag'),
     'technology entries are NOT tagged as external');

  // --- weak-match labelling ---
  // A keyword-derived CVE set must not read with the same confidence as a CPE
  // or scanner match; the difference is invisible without this tag.
  w.renderTechIntel({ ...FIXTURE, vulnerable_tech: [
    { ...FIXTURE.vulnerable_tech[0], cve_match_basis: 'keyword' }] });
  ok(/name-matched/.test(w.document.querySelector('.ti-vuln-card').textContent),
     'keyword-derived CVE sets are flagged as name-matched');

  w.renderTechIntel({ ...FIXTURE, vulnerable_tech: [
    { ...FIXTURE.vulnerable_tech[0], cve_match_basis: 'cpe' }] });
  ok(!/name-matched/.test(w.document.querySelector('.ti-vuln-card').textContent),
     'CPE-derived CVE sets are NOT flagged');

  // --- JSON-string contract: WF12 must parse before sending ---
  w.renderTechIntel({ ...FIXTURE, vulnerable_tech: [{
    ...FIXTURE.vulnerable_tech[0],
    mitre_techniques: '[{"id":"T1190","name":"Exploit Public-Facing Application"}]',
  }] });
  const tagCount = w.document.querySelectorAll('.ti-vuln-card .ti-mitre-tag').length;
  ok(tagCount <= 4,
     'a raw JSON string does not explode into one MITRE tag per character ' +
     '(WF12 must json.loads it first)', tagCount);

  // --- empty state ---
  w.renderTechIntel({ ...FIXTURE, vulnerable_tech: [] });
  ok(!!w.document.getElementById('ti-enrich'),
     'empty state offers a Run enrichment button');
  ok(typeof w.runTechEnrich === 'function',
     'runTechEnrich() exists for that button to call');

  finish();
}, 1200);

function finish() {
  console.log(`\n${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}
