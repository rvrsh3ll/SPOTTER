#!/usr/bin/env node
/*
 * Headless smoke test for the Vulnerability Findings panel (frontend/index.html).
 *
 * Why this exists
 * ---------------
 * Every failure mode this panel has reads as GOOD NEWS, which is the worst kind:
 *
 *   - findings that were never contextualized carry no exploit data at all, so a
 *     zero in the "Exploitable" tile can mean "nothing is exploitable" or "we
 *     have not looked yet", and only the note distinguishes them
 *   - a PoC mirror that was never synced answers "no public exploit" for every
 *     CVE, which is not the same as there being none
 *   - an empty result can mean "no scan ingested" OR "the scan ingested but the
 *     Vulnerability custom type was not registered, so every finding was
 *     dropped" — different actions, and collapsing them into "no vulnerabilities
 *     found" is how an operator concludes an estate is clean when it is not
 *
 * None of those is visible in a manual click-through of a healthy install,
 * because a healthy install never shows them.
 *
 *   node scripts/smoke_frontend_vulnscan.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed (all are reported, the
 * run does not stop at the first).
 *
 * What it CANNOT tell you: jsdom has no layout engine, so nothing about how the
 * stat row wraps or how the findings grid reflows is evaluated here. Those still
 * need one manual browser pass, in BOTH themes.
 */

'use strict';

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
  sketch_id: 'test-sketch',
  scanned: true,
  total_findings: 4,
  total_hosts: 2,
  contextualized: 4,
  cve_count: 3,
  exploitable_findings: 1,
  severity_counts: { critical: 1, high: 1, medium: 1, low: 1, info: 0 },
  poc_mirror: { available: true, stale: false, age_days: 2 },
  top_findings: [{
    plugin_id: '12345',
    name: 'Apache Log4j Remote Code Execution',
    family: 'Web Servers',
    severity: 'critical',
    priority_score: 97,
    priority_tier: 'critical',
    hosts: 2,
    cves: ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105', 'CVE-2021-44832', 'CVE-2019-17571'],
    cve_count: 5,
    cvss3: 10.0,
    exploit_available: true,
    exploit_frameworks: ['Metasploit'],
    poc_count: 7,
    synopsis: 'The remote service is vulnerable to remote code execution.',
    solution: 'Upgrade to 2.17.0.',
    mitre_techniques: [{ id: 'T1190', technique_id: 'T1190', name: 'Exploit Public-Facing Application' }],
    top_pocs: [
      { full_name: 'example-author/log4j-shell-poc', url: 'https://github.com/example-author/log4j-shell-poc',
        stars: 1800, is_fork: false, trust: 'high', trust_score: 22.4,
        trust_signals: ['1800 stars', 'not a fork'], cve_id: 'CVE-2021-44228', unvetted: true },
      { full_name: XSS_NAME, url: 'https://github.com/x/y',
        stars: 0, is_fork: true, trust: 'low', trust_score: -6,
        trust_signals: [], cve_id: 'CVE-2021-44228', unvetted: true },
    ],
  }],
  top_hosts: [
    // Carries the per-host rollup Contextualize writes, so the host pop-out and
    // the finding's "seen on" list have something to match on.
    { host: 'DC01.CORP.LOCAL', node_type: 'device', risk_score: 23, critical: 1,
      high: 0, medium: 1, low: 0, cve_exposure: 5, exploitable_findings: 1,
      os: 'Microsoft Windows Server 2016 Standard', scan_date: '2026-08-14',
      top_findings: [
        { plugin_id: '12345', name: 'Apache Log4j Remote Code Execution', severity: 'critical',
          priority_score: 97, exploit_available: true, poc_count: 7, cves: ['CVE-2021-44228'] },
        { plugin_id: '55555', name: 'SMB Signing not required', severity: 'medium',
          priority_score: 41, exploit_available: false, poc_count: 0, cves: [] },
      ] },
    // Deliberately WITHOUT a rollup: an un-contextualized host must say so rather
    // than render as a host with no findings.
    { host: '10.10.0.12', node_type: 'ip', risk_score: 10, critical: 1,
      high: 0, medium: 0, low: 0, cve_exposure: 5, exploitable_findings: 1,
      os: '', scan_date: '2026-08-14' },
  ],
};

const vc = new VirtualConsole();
vc.on('jsdomError', () => { /* CSS/layout noise jsdom cannot do */ });

const dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
  runScripts: 'dangerously', pretendToBeVisual: true,
  url: 'http://localhost:8080/', virtualConsole: vc,
});
const w = dom.window;

setTimeout(() => {
  console.log('Vulnerability Findings panel');

  ok(typeof w.renderVulnScan === 'function', 'renderVulnScan() exists');
  ok(typeof w.runVulnScan === 'function', 'runVulnScan() exists for Load Findings');
  ok(typeof w.runVulnContext === 'function', 'runVulnContext() exists for Contextualize');
  ok(typeof w.loadVulnScan === 'function', 'loadVulnScan() exists for the tab switch');

  // --- happy path ---
  w.renderVulnScan(FIXTURE);
  const card = w.document.querySelector('#vs-findings .ti-vuln-card');
  if (!ok(!!card, 'a finding card rendered')) { finish(); return; }

  ok(w.document.getElementById('vs-content').style.display !== 'none',
     'the content block is shown when there are findings');
  ok(w.document.getElementById('vs-empty').style.display === 'none',
     'the empty state is hidden when there are findings');

  const stats = w.document.getElementById('vs-stats').textContent;
  ok(/Critical/.test(stats) && /Exploitable/.test(stats) && /Hosts Scanned/.test(stats),
     'the stat row names the severity, exploitability and coverage tiles', stats.slice(0, 120));

  ok(/priority 97/.test(card.textContent),
     'the card leads with the priority score, not severity alone', card.textContent.slice(0, 120));
  ok(/2 hosts/.test(card.textContent), 'the card says how many hosts it fired on');
  ok(/plugin 12345/.test(card.textContent), 'the card names the plugin id');

  // A five-CVE finding must not print five badges and hide the count.
  const cveBadges = [...card.querySelectorAll('.ti-cve-badge')].map(e => e.textContent.trim());
  ok(cveBadges.length === 5 && cveBadges[4] === '+1',
     'CVE badges are capped with a +N overflow marker', cveBadges.join(','));

  const pocBadge = [...card.querySelectorAll('.ti-poc-badge')].map(e => e.textContent.trim());
  ok(pocBadge.some(t => /7\s*PoC/.test(t)), 'PoC count badge shows the repo count', pocBadge.join('|'));
  ok(pocBadge.some(t => /Metasploit/.test(t)),
     'a framework exploit is shown separately from PoC repos', pocBadge.join('|'));

  ok(!!card.querySelector('.ti-mitre-tag'), 'ATT&CK techniques render as tags');

  // --- unvetted warning must travel with the links, not live at the top ---
  const warn = card.querySelector('.ti-poc-warn');
  ok(warn && /unvetted/i.test(warn.textContent),
     'the unvetted warning renders on the card itself');
  ok(card.querySelectorAll('.ti-poc-row').length === 2, 'both PoC rows render',
     card.querySelectorAll('.ti-poc-row').length);

  const link = card.querySelector('.ti-poc-link');
  ok(link && link.getAttribute('target') === '_blank' &&
     /noopener/.test(link.getAttribute('rel') || '') &&
     /noreferrer/.test(link.getAttribute('rel') || ''),
     'PoC links are target=_blank with noopener noreferrer',
     link && link.getAttribute('rel'));

  // --- escaping ---
  ok(!w.__pwned && !card.querySelector('img'),
     'hostile repository name is escaped, not parsed as markup');
  ok(card.textContent.includes(XSS_NAME),
     'hostile repository name still displays as literal text');

  // --- hosts table ---
  const rows = w.document.querySelectorAll('#vs-host-body tr');
  ok(rows.length === 2, 'both hosts render', rows.length);
  ok(/DC01\.CORP\.LOCAL/.test(rows[0].textContent),
     'the worst host sorts first', rows[0].textContent.trim().slice(0, 60));

  // ══════════════════════════════════════════════════════════════════════
  // FINDING CARDS: pop out, and export on their own
  //
  // A card is a summary by construction — four of five CVE badges, no
  // remediation at all — so "the operator has seen the card" is not the same as
  // "the operator has seen the finding". These check the full record is actually
  // reachable, and that the escape hatch out of the browser exists.
  // ══════════════════════════════════════════════════════════════════════
  console.log('\nFinding card pop-out and export');

  ok(!!card.dataset.vsF, 'the card carries its row index for the pop-out');
  const cardExp = card.querySelectorAll('.card-exp .xbtn');
  ok(cardExp.length === 4, 'the card carries its own CSV/MD/HTML/PDF buttons', cardExp.length);
  ok([...cardExp].every(b => /stopPropagation/.test(b.getAttribute('onclick') || '')),
     'a card export button stops the click, so exporting does not also open the pop-out');

  card.click();
  const dm = w.document.getElementById('vs-dm');
  ok(dm && !dm.classList.contains('hidden'), 'clicking a card opens the pop-out');
  const dmTxt = w.document.getElementById('vs-dm-body').textContent;

  // The five-CVE finding shows four badges + "+1" on the card. All five must be
  // in the pop-out, or the clipping is a dead end rather than a summary.
  ok(FIXTURE.top_findings[0].cves.every(c => dmTxt.includes(c)),
     'every CVE is listed in the pop-out, not just the four the card had room for');
  ok(/Upgrade to 2\.17\.0/.test(dmTxt),
     'the remediation text is in the pop-out — the card never showed it at all');
  ok(/vulnerable to remote code execution/.test(dmTxt), 'the synopsis is in the pop-out body');
  ok(/Exploit Public-Facing Application/.test(dmTxt),
     'the ATT&CK technique NAME is shown, not just the T-number');
  ok(/Metasploit/.test(dmTxt), 'the shipping exploit framework is called out');
  ok(/[Uu]nvetted/.test(dmTxt), 'the unvetted-PoC warning travels into the pop-out');

  // Derived from each host's own top-8 list, so it is a PARTIAL blast radius and
  // must never read as the whole one.
  ok(/DC01\.CORP\.LOCAL/.test(dmTxt),
     'the pop-out lists the hosts whose rollup carries this plugin');
  ok(/1 of the 2 affected hosts/.test(dmTxt.replace(/\s+/g, ' ')),
     'it counts what it found against what the finding claims, rather than implying completeness',
     dmTxt.replace(/\s+/g, ' ').slice(-260));
  ok(/only the loaded Worst Hosts rows were searched|own 8 worst/.test(dmTxt),
     'the "seen on" list names why it is partial',
     dmTxt.replace(/\s+/g, ' ').slice(-260));

  ok(!w.__pwned && !w.document.querySelector('#vs-dm-body img'),
     'the hostile repo name is escaped in the pop-out too');

  const dmActs = w.document.querySelectorAll('#vs-dm-actions .xbtn');
  ok(dmActs.length >= 4, 'the pop-out footer offers its own exports', dmActs.length);

  w.vsCloseDetail();
  ok(dm.classList.contains('hidden'), 'the pop-out closes');

  // ══════════════════════════════════════════════════════════════════════
  // WORST HOSTS: sortable, markable, openable
  // ══════════════════════════════════════════════════════════════════════
  console.log('\nWorst Hosts table');

  const hostNames = () => [...w.document.querySelectorAll('#vs-host-body tr')]
    .map(tr => tr.children[1].textContent.trim());

  const sortable = w.document.querySelectorAll('#vs-hosts th.th-sort');
  ok(sortable.length >= 9, 'every data column is a sort handle', sortable.length);
  ok(!!w.document.querySelector('#vs-hosts th.th-active'),
     'the active sort column is marked');

  w.sortVsHosts('host');
  ok(/^10\.10\.0\.12/.test(hostNames()[0]),
     'sorting by host name ascends', hostNames().join(','));
  w.sortVsHosts('host');
  ok(/^DC01/.test(hostNames()[0]),
     'clicking the same column again reverses it', hostNames().join(','));
  w.sortVsHosts('risk');
  ok(/^DC01/.test(hostNames()[0]),
     'risk sorts worst-first, matching its ▼ arrow', hostNames().join(','));

  // --- marks ---------------------------------------------------------------
  // These must land in the SAME store the Targets tab's device marks use: that
  // store is the only one shipped to WF10 in operator_tags.devices, so a mark
  // written anywhere else would look like it worked and reach nothing.
  const cbs = w.document.querySelectorAll('.vsrow-cb');
  ok(cbs.length === 2, 'every host row is selectable', cbs.length);
  ok(w.document.getElementById('vs-act-btn').disabled,
     'the action button is disabled with nothing selected');

  cbs[0].checked = true;
  w._vsUpdateSelCount();
  ok(!w.document.getElementById('vs-act-btn').disabled,
     'selecting a host enables the action menu');
  ok(/1 selected/.test(w.document.getElementById('vs-sel-count').textContent),
     'the selection count updates');

  // The mark maps are per-campaign ('::'+campId), so read them through the app's
  // own accessors rather than a bare key — a bare-key read passes vacuously.
  const markKey = (base) => base + w.campSuffix();

  w.vsMarkHosts('comp', true);
  const devComp = JSON.parse(w.localStorage.getItem(markKey('s.dev_compromised')) || '{}');
  ok(Object.keys(devComp).some(k => /DC01/i.test(k)),
     'the mark lands in s.dev_compromised — the store WF10 actually reads',
     JSON.stringify(devComp));
  ok(/COMP/.test(w.document.querySelectorAll('#vs-host-body tr')[0].textContent),
     'the row repaints with the COMP badge');
  // Mark and Export sit in the same menu, so a mark that clears the selection
  // makes "mark these, now export these" fail with "Nothing selected".
  ok([...w.document.querySelectorAll('.vsrow-cb:checked')]
       .some(cb => /DC01/i.test(cb.dataset.host || '')),
     'the selection survives the repaint a mark triggers');

  // The Targets tab and Nessus spell the same host differently (SharpHound
  // uppercases FQDNs). WF10 folds case when matching, so this table must too, or
  // one host looks like two.
  w.localStorage.setItem(markKey('s.dev_oi_targets'), JSON.stringify({ 'dc01.corp.local': { ts: 'x' } }));
  w._vsRenderHosts();
  ok(/OI/.test(w.document.querySelectorAll('#vs-host-body tr')[0].textContent),
     'a mark written in the Targets tab\'s spelling is recognised here (case-folded)');

  // Clearing must remove every spelling, not just the exact one on screen.
  const cbs2 = w.document.querySelectorAll('.vsrow-cb');
  cbs2[0].checked = true; w._vsUpdateSelCount();
  w.vsMarkHosts('oi', false);
  ok(Object.keys(JSON.parse(w.localStorage.getItem(markKey('s.dev_oi_targets')) || '{}')).length === 0,
     'clearing removes the differently-cased twin too, so the badge cannot linger');

  // --- host pop-out ---------------------------------------------------------
  // A <tr> cannot take focus, so the row also carries a real button: without it
  // the detail view is mouse-only.
  const hint = w.document.querySelector('#vs-host-body .vs-open-hint');
  ok(hint && hint.tagName === 'BUTTON',
     'the row\'s detail affordance is a focusable button, not a styled span', hint && hint.tagName);

  w.document.querySelectorAll('#vs-host-body tr')[0].click();
  ok(!dm.classList.contains('hidden'), 'clicking a host row opens its pop-out');
  const hostTxt = w.document.getElementById('vs-dm-body').textContent;
  ok(/Windows Server 2016/.test(hostTxt), 'the host pop-out names the OS');
  ok(/COMPROMISED/.test(hostTxt), 'the host pop-out reflects the operator mark');
  ok(/SMB Signing not required/.test(hostTxt),
     'the host pop-out lists this host\'s own worst findings — reachable nowhere else in the panel');
  ok(/public exploit/.test(hostTxt),
     'a per-host finding says whether exploit code exists for it');
  ok(/No AD computer object|device dossier/.test(hostTxt),
     'the pop-out states whether an AD object backs this host, rather than staying silent',
     hostTxt.replace(/\s+/g, ' ').slice(-200));
  w.vsCloseDetail();

  // An un-contextualized host has an EMPTY per-host list, which reads exactly
  // like a clean host. It must name the step that fills it instead.
  w.document.querySelectorAll('#vs-host-body tr')[1].click();
  const ipTxt = w.document.getElementById('vs-dm-body').textContent;
  ok(/Contextualize/.test(ipTxt),
     'a host with no rollup names the step that writes one, rather than reading as clean',
     ipTxt.replace(/\s+/g, ' ').slice(0, 200));
  ok(/\bip\b/i.test(ipTxt),
     'an Ip row is identified as such — it has no AD computer object behind it');
  w.vsCloseDetail();

  // Marking from inside the pop-out keeps the row underneath in step.
  w.document.querySelectorAll('#vs-host-body tr')[0].click();
  w.vsMarkDetail('comp', false);
  ok(Object.keys(JSON.parse(w.localStorage.getItem(markKey('s.dev_compromised')) || '{}')).length === 0,
     'a mark can be cleared from inside the pop-out');
  ok(!/COMP/.test(w.document.querySelectorAll('#vs-host-body tr')[0].textContent),
     'the row behind the pop-out repaints, so badge and button cannot disagree');
  w.vsCloseDetail();

  // ══════════════════════════════════════════════════════════════════════
  // EXPORTS
  // The panel previously had none, so a Nessus pass could be read on screen and
  // nowhere else. Assert on the built report rather than the download, and check
  // the caveats travel: a file that omits them reads as a complete estate.
  // ══════════════════════════════════════════════════════════════════════
  console.log('\nExports');

  ok(!!w.document.querySelector('#vs-export .xbtn'), 'the panel header offers a whole-report export');
  ok(!!w.document.querySelector('#vs-find-exp .xbtn'), 'the findings section exports as a table');
  ok(!!w.document.querySelector('#vs-host-exp .xbtn'), 'the hosts section exports as a table');

  const panelCsv = w.eval(
    `_reportToCSV(buildVulnScanReport(${JSON.stringify({ ...FIXTURE, contextualized: 1 })}))`);
  ok(/Apache Log4j Remote Code Execution/.test(panelCsv), 'the panel export carries the findings');
  ok(/DC01\.CORP\.LOCAL/.test(panelCsv), 'the panel export carries the hosts');
  ok(/Upgrade to 2\.17\.0/.test(panelCsv), 'the panel export carries the remediation column');
  ok(/not looked at|never contextualized/.test(panelCsv),
     'an export of a partly-contextualized run says so, so a blank exploit column is not read as safety');

  const stalePanel = w.eval(`_reportToCSV(buildVulnScanReport(${JSON.stringify(
    { ...FIXTURE, poc_mirror: { available: true, stale: true, age_days: 190 } })}))`);
  ok(/not evidence none exists/.test(stalePanel),
     'a stale PoC mirror is recorded in the exported file, not just on screen');

  const findMd = w.eval(
    `_reportToMarkdown(buildVulnFindingReport(_vsFindings[0], _vsData))`);
  ok(/CVE-2019-17571/.test(findMd), 'a single-finding export lists every CVE');
  ok(/example-author\/log4j-shell-poc/.test(findMd), 'a single-finding export lists the PoC repositories');
  ok(/UNVETTED/.test(findMd), 'a single-finding export shouts the unvetted warning');
  ok(/partial blast radius/.test(findMd),
     'a single-finding export says its affected-host list is partial');

  const hostMd = w.eval(`_reportToMarkdown(buildVulnHostReport(_vsHosts[0], _vsData))`);
  ok(/DC01\.CORP\.LOCAL/.test(hostMd), 'a single-host export names the host');
  ok(/Windows Server 2016/.test(hostMd), 'a single-host export carries the OS');

  // Subsetting must not quietly produce an empty file.
  const hostsOnly = w.eval(`JSON.stringify(_reportSubset(buildVulnScanReport(_vsData), 'hosts').sections)`);
  ok(JSON.parse(hostsOnly).length === 1, 'the hosts section subsets to exactly one section');

  // Exports order the hosts the way the screen does — an operator sorted it for a
  // reason and a file that re-sorts is a different document.
  w.sortVsHosts('host');
  const asShown = w.eval(`JSON.stringify(buildVulnScanReport(_vsData).sections.find(s => s.key === 'hosts').blocks[0].rows.map(r => r[0]))`);
  ok(JSON.parse(asShown)[0] === '10.10.0.12',
     'the exported host table follows the on-screen sort', asShown);
  w.sortVsHosts('risk');

  // --- the three "reads as good news" states ---
  // 1. Findings that were never contextualized carry NO exploit data.
  w.renderVulnScan({ ...FIXTURE, contextualized: 1 });
  ok(/not been contextualized/.test(w.document.getElementById('vs-note').textContent),
     'un-contextualized findings are called out, so a zero exploit count is not read as safety',
     w.document.getElementById('vs-note').textContent.slice(0, 120));

  // 2. A stale mirror answers "no exploit" for everything.
  w.renderVulnScan({ ...FIXTURE, poc_mirror: { available: true, stale: true, age_days: 190 } });
  ok(/not evidence none exists/.test(w.document.getElementById('vs-note').textContent),
     'a stale PoC mirror is reported as a blind spot, not a clean result',
     w.document.getElementById('vs-note').textContent.slice(0, 140));

  // 3. A mirror that was never synced at all.
  w.renderVulnScan({ ...FIXTURE, poc_mirror: { available: false } });
  ok(/not present/.test(w.document.getElementById('vs-note').textContent),
     'a missing PoC mirror is reported', w.document.getElementById('vs-note').textContent.slice(0, 140));

  // A healthy pass says nothing — the note must not cry wolf.
  w.renderVulnScan(FIXTURE);
  ok(w.document.getElementById('vs-note').textContent.trim() === '',
     'a fully contextualized run with a fresh mirror shows no warning',
     w.document.getElementById('vs-note').textContent);

  // --- empty state carries the REASON ---
  w.renderVulnScan({
    total_findings: 0, total_hosts: 0, severity_counts: {}, top_findings: [], top_hosts: [],
    empty_reason: 'no Vulnerability nodes in this campaign - check register_nessus_type.py has been run',
  });
  const emptyEl = w.document.getElementById('vs-empty');
  ok(emptyEl.style.display !== 'none', 'the empty state is shown when there are no findings');
  ok(/register_nessus_type/.test(emptyEl.textContent),
     'the empty state repeats the backend reason instead of "no vulnerabilities found"',
     emptyEl.textContent.slice(0, 140));
  ok(w.document.getElementById('vs-content').style.display === 'none',
     'the content block is hidden when there are no findings');

  // --- JSON-string contract: a raw string must not explode per character ---
  w.renderVulnScan({ ...FIXTURE, top_findings: [{
    ...FIXTURE.top_findings[0],
    mitre_techniques: '[{"id":"T1190","name":"Exploit Public-Facing Application"}]',
    top_pocs: '[]',
  }] });
  const tagCount = w.document.querySelectorAll('#vs-findings .ti-mitre-tag').length;
  ok(tagCount <= 3, 'a JSON-string property does not render one tag per character', tagCount);

  // --- the LLM tool sees the same numbers, with the same caveats ---
  // Top-level `const` is not on window (see the jsdom memo), so reach the store
  // through w.eval rather than w.VULN_SCAN_KEY.
  w.eval(`localStorage.setItem(VULN_SCAN_KEY, JSON.stringify({
    _default: { data: ${JSON.stringify({ ...FIXTURE, contextualized: 1 })}, ts: Date.now() }
  }));`);
  const tool = w.eval('JSON.stringify(_toolVulnerabilities({ section: "summary" }))');
  const parsed = JSON.parse(tool);
  ok(parsed.status === 'ok', 'the get_vulnerabilities tool reads the cache', parsed.status);
  ok(parsed.total_findings === 4, 'the tool reports the finding count', parsed.total_findings);
  ok((parsed.caveats || []).some(c => /not been contextualized/.test(c)),
     'the tool carries the un-contextualized caveat to the model',
     JSON.stringify(parsed.caveats));
  ok(/UNVETTED/.test(parsed.poc_warning || ''),
     'the tool carries the unvetted-PoC warning to the model');

  const empty = JSON.parse(w.eval(
    'localStorage.removeItem(VULN_SCAN_KEY); JSON.stringify(_toolVulnerabilities({}))'));
  ok(empty.status === 'empty' && /Ingest tab/.test(empty.message),
     'with no cache the tool names the tab that fills it, and does not claim no access',
     empty.message);

  finish();
}, 1200);

function finish() {
  console.log(`\n${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}
