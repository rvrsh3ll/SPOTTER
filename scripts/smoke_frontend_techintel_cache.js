#!/usr/bin/env node
/*
 * Headless smoke test for the Tech Intel cache as the chat tools see it.
 *
 * Why this exists
 * ---------------
 * On 2026-10-24 the Prompt tab answered an external-attack-surface question
 * with "No technology inventory has been established yet" even though WF12 had
 * been run and the Tech Intel tab was showing data. Two frontend defects
 * contributed, and both fail silently in a click-through:
 *
 *   1. The chat tools read ONLY the localStorage store (s.techIntel). The tab
 *      renders from in-memory _tiData. When saveTechIntelData loses its write
 *      to browser quota — a path it survives by design, with a toast — the
 *      operator watches the inventory render and the chat tool reports the
 *      store empty. _activeTechIntel() now falls back to _tiData, which is
 *      campaign-scoped: loadTechIntel() replaces or nulls it on every campaign
 *      switch, so the fallback can serve the session in hand and nothing else.
 *
 *   2. The get_tech_intel schema's `section` enum had drifted from the runtime
 *      TECH_SECTIONS map: it advertised `pasted` (not a real section) and omitted
 *      `perimeter` and `cloud` (real sections). A model can only ask for the
 *      sections it is told exist — and a section name it invents is evidence it
 *      is not reading the schema, which is how the incident was diagnosed.
 *
 * Asserted invariants:
 *   1. empty store + no in-memory data → get_tech_intel says 'empty' (the
 *      grounded message that names the Tech Intel tab, never "no access")
 *   2. empty store + rendered data (the quota-loss state) → get_tech_intel
 *      answers from _tiData with status 'ok' and cached_at null, and
 *      spotterDataInventory() reports the store AVAILABLE
 *   3. a real store record always WINS over the in-memory fallback
 *   4. loadTechIntel() with an empty store clears the fallback — this is the
 *      campaign-switch path; without it the previous campaign's inventory
 *      would answer under the next campaign's name
 *   5. the schema's section enum is exactly Object.keys(TECH_SECTIONS)+['all']
 *      — drift in either direction fails
 *
 *   node scripts/smoke_frontend_techintel_cache.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed (all are reported).
 * Exit 2 = cannot run (jsdom missing — see smoke_frontend_lib.js).
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

const FIXTURE = {
  os_inventory: [], tech_catalog: { 'Apache HTTP Server': {} },
  user_tech_profiles: [], attack_narratives: [],
  legacy_systems: [], stale_devices: [], perimeter_tech: [], cloud_exposure: [],
  total_devices: 2, total_individuals: 1,
  tech_user_map: {}, os_device_map: {}, device_dossier_map: {},
  vulnerable_tech: [{ name: 'Apache HTTP Server', vendor: 'Apache', version: '2.4.41', cve_count: 5 }],
};

const vc = new VirtualConsole();
vc.on('jsdomError', () => { /* CSS/layout noise jsdom cannot do */ });

const dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
  runScripts: 'dangerously', pretendToBeVisual: true,
  url: 'http://localhost:8080/', virtualConsole: vc,
});
const w = dom.window;

const techIntel = () => w.executeSpotterTool('get_tech_intel', { section: 'summary' });
const inventoryStatus = () => w.eval(
  `spotterDataInventory().items.find(i => i.tool === 'get_tech_intel').status`);

setTimeout(async () => {
  try {
    section('1 — cold start: empty store, nothing rendered');
    w.eval(`safeSetItem(TECH_INTEL_KEY, '{}')`);
    let r = await techIntel();
    ok(r.status === 'empty', 'get_tech_intel reports the store empty', r.status);
    ok(/Tech Intel tab/.test(r.message || ''),
       'the empty message names the tab that fills the store (not "no access")',
       r.message);
    ok(inventoryStatus() === 'EMPTY', 'data inventory says EMPTY', inventoryStatus());

    section('2 — quota-loss state: tab rendered from memory, store empty');
    w.renderTechIntel(FIXTURE);            // sets _tiData; the store stays empty
    r = await techIntel();
    ok(r.status === 'ok', 'get_tech_intel answers from the in-memory fallback', r.status);
    ok(r.cached_at === null, 'cached_at is null — the fallback has no timestamp', r.cached_at);
    ok(r.data && r.data.total_devices === 2, 'summary carries the rendered data',
       JSON.stringify(r.data));
    ok(inventoryStatus() === 'AVAILABLE', 'data inventory says AVAILABLE', inventoryStatus());

    section('3 — a real store record wins over the fallback');
    w.eval(`(function(){
      var s={}; s[tiCampKey()]={data:{ total_devices:9 }, ts:123};
      safeSetItem(TECH_INTEL_KEY, JSON.stringify(s));
    })();`);
    r = await techIntel();
    ok(r.status === 'ok', 'still ok', r.status);
    ok(r.data && r.data.total_devices === 9, 'store record served, not the fixture',
       JSON.stringify(r.data));
    ok(r.cached_at === new Date(123).toISOString(), 'cached_at comes from the record ts',
       r.cached_at);

    section('4 — campaign-switch path: loadTechIntel() clears the fallback');
    w.eval(`safeSetItem(TECH_INTEL_KEY, '{}')`);
    w.loadTechIntel();                     // refreshScopedViews() calls this on every switch
    r = await techIntel();
    ok(r.status === 'empty', 'with store and memory both empty the tool says so', r.status);
    ok(inventoryStatus() === 'EMPTY', 'data inventory back to EMPTY', inventoryStatus());

    section('5 — schema enum matches the runtime section map');
    const desc = w.eval(`SPOTTER_TOOLS.find(t => t.function.name === 'get_tech_intel')
                           .function.parameters.properties.section.description`);
    const runtime = w.eval(`Object.keys(TECH_SECTIONS).concat(['all'])`);
    const advertised = String(desc).split('|').map(s => s.trim()).filter(Boolean);
    const missing = runtime.filter(s => !advertised.includes(s));
    const phantom = advertised.filter(s => !runtime.includes(s));
    ok(missing.length === 0, 'every runtime section is advertised', missing.join(','));
    ok(phantom.length === 0, 'every advertised section exists at runtime', phantom.join(','));
    ok(advertised.includes('perimeter') && advertised.includes('cloud'),
       'perimeter and cloud are advertised (2026-10-24 drift)');
    ok(!advertised.includes('pasted'), 'the phantom "pasted" section is gone');
  } catch (e) {
    failures++;
    console.error(`  FAIL  suite threw: ${e && e.stack || e}`);
  }
  console.log(`\n${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 1200);
