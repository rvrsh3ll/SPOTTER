#!/usr/bin/env node
/*
 * Headless smoke test for EVERY sortable table in frontend/index.html.
 *
 * Why this exists
 * ---------------
 * On 2026-08-18 the Targets tab and its Devices view were found sorting the
 * wrong way round. `_targetsSortDir === -1` is "descending" and _thSort() paints
 * it ▼, but the comparator returned `dir` when `av < bv` — and a comparator
 * returning a NEGATIVE number puts its first argument FIRST, so the smaller
 * value came first. The default `score/-1` view therefore rendered the
 * LOWEST-scoring target at the top under a ▼ arrow: on a red-team target list,
 * the host worth hitting first sat at the bottom and nothing on screen said so.
 *
 * It survived because it is invisible. There is no error, no console warning,
 * and no way to tell a mis-sorted list from a correctly-sorted one by looking at
 * it — you have to know which end the big numbers belong at. The AGENTS tab, in
 * the same file, had the sign right the whole time, so reading one table's code
 * to learn the convention taught you the wrong convention.
 *
 * What this asserts is the operator-visible invariant, not the implementation:
 *
 *   1. the ▼ arrow means the first row holds the LARGEST value in that column,
 *      and ▲ means the smallest — read out of the RENDERED CELL, so the test
 *      makes no assumption about which field feeds which column
 *   2. clicking a column twice exactly reverses the rows
 *   3. each column sorts by its OWN key — the fixtures are built so that name
 *      order, score order and every other column's order all DISAGREE, which a
 *      monotone fixture would hide
 *
 * Covers all four sortable tables: Targets · individuals, Targets · assets,
 * AGENTS, and Tech Intel's Worst Hosts. A new sortable table should be added
 * here, because the bug class is per-table.
 *
 *   node scripts/smoke_frontend_sort.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed (all are reported).
 *
 * What it CANNOT tell you: nothing about the arrow GLYPH's legibility or the
 * header's hover affordance — jsdom has no layout. One browser pass still owed.
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

/* ── reading the rendered table ──────────────────────────────────────────
   Values come out of the cell the operator is looking at. A numeric column is
   read as a number and a text column as a lowercased string; a cell holding a
   glyph placeholder ('—', '●', '⚠', '✓') is ranked by presence, which is what
   those columns sort on. */
function cellValue(td, kind) {
  const txt = (td.textContent || '').trim();
  if (kind === 'num')  { const n = parseFloat(txt.replace(/[^\d.-]/g, '')); return isNaN(n) ? 0 : n; }
  if (kind === 'flag') return /^(—|-|)$/.test(txt) ? 0 : 1;
  return txt.toLowerCase();
}

function readColumn(rowSel, idx, kind) {
  return [...d.querySelectorAll(rowSel)].map(tr => cellValue(tr.children[idx], kind));
}

function activeArrow(headSel) {
  const th = d.querySelector(headSel + ' th.th-active');
  if (!th) return null;
  const t = th.textContent;
  return t.includes('▲') ? 'asc' : t.includes('▼') ? 'desc' : null;
}

function isMonotone(vals, dir) {
  for (let i = 1; i < vals.length; i++) {
    const a = vals[i - 1], b = vals[i];
    if (dir === 'desc' ? a < b : a > b) return false;
  }
  return true;
}

/* One table, one column: click it, assert the order matches the arrow it just
   painted, click again, assert the reverse. */
function checkColumn(name, sortFn, col, rowSel, headSel, idx, kind) {
  sortFn(col);
  const dir1  = activeArrow(headSel);
  const vals1 = readColumn(rowSel, idx, kind);
  ok(dir1 !== null, `${name}.${col}: the header marks itself active with an arrow`, dir1);
  ok(isMonotone(vals1, dir1),
     `${name}.${col}: rows follow the ${dir1 === 'desc' ? '▼ (largest first)' : '▲ (smallest first)'} arrow`,
     `${dir1} → ${JSON.stringify(vals1)}`);

  sortFn(col);
  const dir2  = activeArrow(headSel);
  const vals2 = readColumn(rowSel, idx, kind);
  ok(dir2 && dir2 !== dir1, `${name}.${col}: clicking again flips the arrow`, `${dir1} → ${dir2}`);
  ok(isMonotone(vals2, dir2),
     `${name}.${col}: and flips the rows with it`, `${dir2} → ${JSON.stringify(vals2)}`);
  ok(JSON.stringify(vals2) === JSON.stringify([...vals1].reverse()),
     `${name}.${col}: the two directions are exact reverses`,
     `${JSON.stringify(vals1)} vs ${JSON.stringify(vals2)}`);
}

setTimeout(() => {
  console.log('Sortable tables — arrow direction vs rendered order');

  /* ══════════════════════════════════════════════════════════════════════
     TARGETS · INDIVIDUALS
     Every column's ordering disagrees with every other, so a column that
     silently sorts by the wrong key cannot pass.
     Cells: 0 cb | 1 # | 2 Name | 3 Username | 4 Email | 5 Score | 6 Status
            7 Beacon | 8 Alert | 9 Flare | 10 Creds | 11 Social
  ══════════════════════════════════════════════════════════════════════ */
  section('Targets · individuals');

  const INDS = [
    { label: 'Delta',   username: 'zulu',  email: 'm@example.org', attack_score: 7,  breach_count: 12, cred_score: 1, cred_count: 1, active_beacon: true,  alert: false, social_enriched: false },
    { label: 'Alpha',   username: 'yankee',email: 'z@example.org', attack_score: 91, breach_count: 3,  cred_score: 9, cred_count: 4, active_beacon: false, alert: true,  social_enriched: true  },
    { label: 'Charlie', username: 'xray',  email: 'a@example.org', attack_score: 44, breach_count: 0,  cred_score: 5, cred_count: 2, active_beacon: false, alert: false, social_enriched: false },
  ];
  w.eval(`_targetsCache = { list: ${JSON.stringify(INDS)}, devices: [], deviceDossier: {}, ts: Date.now() };
          _targetsView = 'individuals';`);
  w.renderTargetsView();

  // The default view is the one an operator sees without touching anything, and
  // it is the one that was wrong: score/-1 painted ▼ and rendered lowest-first.
  ok(w.eval('[_targetsSortCol, _targetsSortDir].join("/")') === 'score/-1',
     'the tab still defaults to score, descending', w.eval('[_targetsSortCol,_targetsSortDir].join("/")'));
  const defaultScores = readColumn('#tres tbody tr', 5, 'num');
  ok(activeArrow('#tres thead') === 'desc', 'the default Score header shows ▼');
  ok(JSON.stringify(defaultScores) === JSON.stringify([91, 44, 7]),
     'the default view puts the HIGHEST-scoring target first — the regression this file exists for',
     JSON.stringify(defaultScores));

  const tCols = [
    ['name',     2,  'text'],
    ['username', 3,  'text'],
    ['email',    4,  'text'],
    ['score',    5,  'num'],
    ['beacon',   7,  'flag'],
    ['alert',    8,  'flag'],
    ['flare',    9,  'num'],
    ['creds',    10, 'num'],
    ['social',   11, 'flag'],
  ];
  tCols.forEach(([col, idx, kind]) =>
    checkColumn('targets', w.sortTargets, col, '#tres tbody tr', '#tres thead', idx, kind));

  /* ══════════════════════════════════════════════════════════════════════
     TARGETS · ASSETS  (AD computers + scanned IPs + web/DNS/cloud/service)
     Cells: 0 cb | 1 # | 2 Name | 3 Type | 4 Detail | 5 Ports | 6 Status | 7 Score
     Detail and Status are not sortable. The fixture mixes host and infra rows
     so a column that silently sorts by the wrong key cannot pass.
  ══════════════════════════════════════════════════════════════════════ */
  section('Targets · assets');

  const ASSETS = [
    { id: 'a1', name: 'z-host',   type: 'HOST',    os: 'Windows 7', os_risk: 'critical', ports: 3, score: 12 },
    { id: 'a2', name: 'a-portal', type: 'WEBSITE', detail: 'wordpress',                   ports: 1, score: 88 },
    { id: 'a3', name: 'm-bucket', type: 'CLOUD',   detail: 'public',                      ports: 5, score: 40 },
  ];
  w.eval(`_targetsCache = { list: [], assets: ${JSON.stringify(ASSETS)}, deviceDossier: {}, ts: Date.now() };`);
  w.setTargetsView('assets');

  ok(w.eval('[_assetSortCol, _assetSortDir].join("/")') === 'score/-1',
     'the assets view defaults to score, descending', w.eval('[_assetSortCol,_assetSortDir].join("/")'));
  const asDefault = readColumn('#tres tbody tr', 7, 'num');
  ok(JSON.stringify(asDefault) === JSON.stringify([88, 40, 12]),
     'the assets view puts the HIGHEST-scoring asset first', JSON.stringify(asDefault));

  const aCols = [
    ['name',  2, 'text'],
    ['type',  3, 'text'],
    ['ports', 5, 'num'],
    ['score', 7, 'num'],
  ];
  aCols.forEach(([col, idx, kind]) =>
    checkColumn('assets', w.sortAssets, col, '#tres tbody tr', '#tres thead', idx, kind));

  /* ══════════════════════════════════════════════════════════════════════
     AGENTS — the table that had it right, pinned so it stays right.
     Its default is status/1, and status is a rank word, so only the numeric
     columns are direction-checked.
     Cells (renderAgentsView): see the header order below at runtime.
  ══════════════════════════════════════════════════════════════════════ */
  section('AGENTS');

  const AGENTS = [
    { session_id: 's1', node_label: 'a1', framework: 'cobalt_strike', framework_label: 'Cobalt Strike',
      hostname: 'z-box', username: 'zeta', status: 'live',  age_minutes: 2,  pid: 9001, sleep_seconds: 60,
      is_admin: true,  internal_ip: '10.0.0.9' },
    { session_id: 's2', node_label: 'a2', framework: 'brute_ratel', framework_label: 'Brute Ratel',
      hostname: 'a-box', username: 'alpha', status: 'stale', age_minutes: 90, pid: 111,  sleep_seconds: 5,
      is_admin: false, internal_ip: '10.0.0.1' },
    { session_id: 's3', node_label: 'a3', framework: 'cobalt_strike', framework_label: 'Cobalt Strike',
      hostname: 'm-box', username: 'mike', status: 'live',  age_minutes: 40, pid: 5000, sleep_seconds: 30,
      is_admin: false, internal_ip: '10.0.0.5' },
    /* Adaptix (WF28) — a third framework in the roster must not disturb the
       sort, and its pill/filter must render like the other two. */
    { session_id: 's4', node_label: 'a4', framework: 'adaptix', framework_label: 'Adaptix C2',
      hostname: 'k-box', username: 'kilo', status: 'live',  age_minutes: 6,  pid: 7300, sleep_seconds: 45,
      is_admin: true,  internal_ip: '10.0.0.7' },
  ];
  /* by_framework comes from WF23's stats block, NOT from the agents array — the
     count spans read s.by_framework directly, so a fixture with empty stats
     renders every count blank and proves nothing about the wiring. */
  const AGENT_STATS = { by_framework: { cobalt_strike: 2, brute_ratel: 1, adaptix: 1 } };
  w.eval(`_agentsCache = { agents: ${JSON.stringify(AGENTS)}, `
       + `stats: ${JSON.stringify(AGENT_STATS)}, ts: Date.now() };`);
  w.renderAgentsView();

  const agtHead = [...d.querySelectorAll('#agt-res thead th')].map(t => t.textContent.replace(/[▲▼]/g, '').trim());
  const agtIdx  = (label) => agtHead.findIndex(h => h.toLowerCase() === label);
  ok(agtHead.length > 3, 'the agents table rendered a header', agtHead.join('|'));

  [['pid', 'pid', 'num'], ['sleep', 'sleep', 'num']].forEach(([col, header, kind]) => {
    const idx = agtIdx(header);
    if (idx < 0) { ok(false, `agents.${col}: header "${header}" found`, agtHead.join('|')); return; }
    checkColumn('agents', w.sortAgents, col, '#agt-res tbody tr', '#agt-res thead', idx, kind);
  });

  /* The framework filter is a hardcoded list in three places (the buttons, the
     setAgentsFw toggle loop, the count wiring). A framework missing from any of
     them is only reachable via "All", which is how a whole C2 goes unnoticed. */
  w.setAgentsFw('adaptix');
  ok(d.getElementById('agt-fw-adaptix')?.classList.contains('tv-active'),
     'agents: the adaptix filter button activates');
  ok([...d.querySelectorAll('#agt-res tbody tr')].length === 1,
     'agents: filtering to adaptix leaves exactly the one adaptix row');
  ok(d.querySelector('#agt-res tbody .agt-fw.fw-adaptix')?.textContent.trim() === 'Adaptix C2',
     'agents: the adaptix pill carries its framework label and class');
  w.setAgentsFw('all');
  /* Each framework's count span has a hand-picked id that does NOT match its
     discriminator (cs/br/ax vs cobalt_strike/brute_ratel/adaptix), so a new
     framework wired to the wrong span fails silently at zero. */
  [['agt-fw-cs-count', '2', 'cobalt strike'], ['agt-fw-br-count', '1', 'brute ratel'],
   ['agt-fw-ax-count', '1', 'adaptix']].forEach(([id, want, label]) => {
    ok(d.getElementById(id)?.textContent.trim() === want,
       `agents: the ${label} filter shows its count`, d.getElementById(id)?.textContent);
  });

  /* ══════════════════════════════════════════════════════════════════════
     TECH INTEL · WORST HOSTS
     Cells: 0 cb | 1 Host | 2 OS | 3 Risk | 4 Crit | 5 High | 6 Med
            7 Exploitable | 8 CVEs | 9 Status | 10 detail
  ══════════════════════════════════════════════════════════════════════ */
  section('Tech Intel · Worst Hosts');

  w.renderVulnScan({
    total_findings: 3, total_hosts: 3, contextualized: 3, cve_count: 9,
    exploitable_findings: 2, severity_counts: { critical: 1, high: 1, medium: 1, low: 0, info: 0 },
    poc_mirror: { available: true, stale: false, age_days: 1 },
    top_findings: [{ plugin_id: '1', name: 'F1', severity: 'critical', priority_score: 90, hosts: 1, cves: [] }],
    top_hosts: [
      { host: 'z-host', node_type: 'device', risk_score: 12, critical: 0, high: 3, medium: 1, low: 0,
        cve_exposure: 2,  exploitable_findings: 0, os: 'Windows 7',  scan_date: '2026-08-14' },
      { host: 'a-host', node_type: 'device', risk_score: 90, critical: 4, high: 0, medium: 2, low: 0,
        cve_exposure: 11, exploitable_findings: 5, os: 'Windows 11', scan_date: '2026-08-14' },
      { host: 'm-host', node_type: 'device', risk_score: 40, critical: 1, high: 1, medium: 9, low: 0,
        cve_exposure: 7,  exploitable_findings: 2, os: 'Windows 10', scan_date: '2026-08-14' },
    ],
  });

  const vsDefault = readColumn('#vs-host-body tr', 3, 'num');
  ok(activeArrow('#vs-hosts thead') === 'desc', 'Worst Hosts defaults to a ▼ arrow');
  ok(JSON.stringify(vsDefault) === JSON.stringify([90, 40, 12]),
     'Worst Hosts puts the highest-risk host first', JSON.stringify(vsDefault));

  // 'marked' sorts on operator marks, which this fixture sets none of, so it
  // would be an all-ties no-op — covered in smoke_frontend_vulnscan.js instead.
  const vCols = [
    ['host', 1, 'text'], ['os',   2, 'text'], ['risk', 3, 'num'],
    ['crit', 4, 'num'],  ['high', 5, 'num'],  ['med',  6, 'num'],
    ['expl', 7, 'num'],  ['cves', 8, 'num'],
  ];
  vCols.forEach(([col, idx, kind]) =>
    checkColumn('worst-hosts', w.sortVsHosts, col, '#vs-host-body tr', '#vs-hosts thead', idx, kind));

  /* ══════════════════════════════════════════════════════════════════════
     LIVE ANALYSIS · CREDENTIAL & BREACH EXPOSURE
     Fifth sortable table (2026-09-06). Every column disagrees with every
     other, so a column sorting by the wrong key cannot pass.
     Cells: 0 Identity | 1 Creds | 2 Breaches | 3 Exposure | 4 Sources | 5 Records
     Admins are pinned above everyone else regardless of column, so the fixture
     deliberately has NO admin — otherwise the pin would mask a broken sort.
  ══════════════════════════════════════════════════════════════════════ */
  section('Live Analysis · credential & breach exposure');
  w.localStorage.setItem('s.activeCamp', JSON.stringify({ id: 'cx', name: 'X' }));
  const fxRec = {
    id: 'dr-x', campaignId: 'cx', domain: 'example.com', timestamp: new Date().toISOString(),
    flare_exposed_creds: 3,
    credential_matches: [
      { graph_user: 'zulu',    email: 'z@example.com' },
      { graph_user: 'alpha',   email: 'a@example.com' },
      { graph_user: 'mike',    email: 'm@example.com' },
    ],
    flare_domain_breaches: [
      { email: 'z@example.com', source: 's', event_type: 'leaked_credentials' },
      { email: 'a@example.com', source: 's', event_type: 'leaked_credentials' },
      { email: 'a@example.com', source: 's', event_type: 'leaked_credentials' },
      { email: 'm@example.com', source: 's', event_type: 'leaked_credentials' },
      { email: 'm@example.com', source: 's', event_type: 'leaked_credentials' },
      { email: 'm@example.com', source: 's', event_type: 'leaked_credentials' },
    ],
  };
  const fxAn = {
    id: 'an-x', campaignId: 'cx', timestamp: new Date().toISOString(), status: 'complete',
    breachIntel: [
      { name: 'zulu',  breach_count: 9 },
      { name: 'alpha', breach_count: 2 },
      { name: 'mike',  breach_count: 5 },
    ],
    credentialIntel: [
      { name: 'zulu',  cred_count: 1, validated_cred_count: 0 },
      { name: 'alpha', cred_count: 7, validated_cred_count: 3 },
      { name: 'mike',  cred_count: 4, validated_cred_count: 1 },
    ],
  };
  w.localStorage.setItem('s.domainRecon', JSON.stringify([fxRec]));
  w.localStorage.setItem('s.analyses',    JSON.stringify([fxAn]));
  w.renderExposure({ recon: fxRec, analysis: fxAn });

  // Only the identity rows: the offsite bucket and any expanded detail rows are
  // not peers of these and must never be swept into the ordering assertion.
  const FX_ROWS = '#fx-content tbody tr:not(.fx-det)';
  const fxCols = [
    ['person', 0, 'text'], ['creds', 1, 'num'], ['breaches', 2, 'num'], ['records', 5, 'num'],
  ];
  fxCols.forEach(([col, idx, kind]) =>
    checkColumn('exposure', w.sortExposure, col, FX_ROWS, '#fx-content thead', idx, kind));

  /* ══════════════════════════════════════════════════════════════════════
     The helper itself. Every table above funnels through one convention; this
     states it outright so a future reader cannot re-derive it backwards.
  ══════════════════════════════════════════════════════════════════════ */
  section('the comparator convention');
  ok(w.eval('_cmpDir(1, 2, -1)') > 0,
     '_cmpDir: descending sends the SMALLER value later', w.eval('_cmpDir(1,2,-1)'));
  ok(w.eval('_cmpDir(1, 2, 1)') < 0,
     '_cmpDir: ascending sends the smaller value first', w.eval('_cmpDir(1,2,1)'));
  ok(w.eval('_cmpDir(2, 2, -1)') === 0, '_cmpDir: equal values tie');
  ok(w.eval('JSON.stringify([3,1,2].sort((a,b) => _cmpDir(a,b,-1)))') === '[3,2,1]',
     '_cmpDir sorts descending when handed -1', w.eval('JSON.stringify([3,1,2].sort((a,b)=>_cmpDir(a,b,-1)))'));

  console.log(`\n${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 1200);
