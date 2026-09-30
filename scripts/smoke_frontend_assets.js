#!/usr/bin/env node
/*
 * Headless smoke test for the Targets tab's Assets view (WF05 asset_list).
 *
 * Why this exists
 * ---------------
 * The Targets tab used to be AD-only: a People view (:individual) and a Devices
 * view (:device). 2026-08 broadened it so a single "Assets" view carries every
 * non-person target — AD computers AND scanned :ip hosts AND the web / DNS /
 * cloud / service attack surface — each tagged with a Type column. The two
 * click behaviours are the part most likely to rot silently:
 *
 *   - HOST / IP rows open the existing device-dossier modal (device_dossier_map)
 *   - every other type opens a lightweight inline-props modal (openAssetDetail)
 *     built from the row itself, with NO extra fetch
 *
 * This asserts the operator-visible invariants:
 *   1. the view renders one row per asset with its Type badge
 *   2. a HOST/IP row wires the device-dossier open; an infra row wires
 *      openAssetDetail — a dispatch that sends a website to the device modal
 *      (or vice-versa) is the failure this pins
 *   3. openAssetDetail actually opens the shared modal and renders the row's
 *      type-specific properties
 *   4. the Detail column shows OS+risk for a host and the row's detail otherwise
 *
 *   node scripts/smoke_frontend_assets.js
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

// One row per supported asset type, plus a host that also has dossier detail.
const ASSETS = [
  { id: 'h1', name: 'DC01', type: 'HOST', os: 'Windows Server 2012 R2', os_risk: 'high', is_dc: true, ip: '10.0.0.1', ports: 0, score: 22 },
  { id: 'i1', name: '10.0.0.5', type: 'IP', os: 'Linux', os_risk: 'supported', fqdn: 'linux01.example.com', ports: 3, score: 19 },
  { id: 'w1', name: 'https://portal.example.com', type: 'WEBSITE', title: 'Corp Portal', detail: 'Corp Portal',
    url: 'https://portal.example.com', hostname: 'portal.example.com', has_default_creds: true, is_wordpress: true, ports: 1, score: 23 },
  { id: 's1', name: 'vpn.example.com', type: 'SUBDOMAIN', detail: 'web / example.com', parent_domain: 'example.com', has_web: true, ports: 1, score: 6 },
  { id: 'c1', name: 'example-backups', type: 'CLOUD', detail: 'public / listable / 120 objects', provider: 'aws',
    service: 's3', public: true, listable: true, object_count: 120, exposure_score: 80,
    sensitive_categories: ['credential'], ports: 0, score: 42 },
  { id: 'v1', name: '443/tcp (https nginx 1.18.0)', type: 'SERVICE', detail: 'nginx 1.18.0', product: 'nginx',
    version: '1.18.0', is_internet_exposed: true, cve_count: 4, host_ip: '203.0.113.9',
    hostnames: '["vpn.example.com","www.example.com"]', ports: 0, score: 12 },
  { id: 'd1', name: 'example.com', type: 'DOMAIN', detail: '', ports: 0, score: 1 },
];
const DOSSIER = {
  'DC01': { hostname: 'DC01', os: 'Windows Server 2012 R2', os_risk: 'high', is_dc: true,
            users_with_sessions: ['DOE, JOHN'], local_admins: [], ace_access: [], tech_stack: [] },
};

setTimeout(() => {
  console.log('Targets tab — Assets view');

  w.eval(`_targetsView = 'assets';
          _targetsCache = ${JSON.stringify({ list: [], assets: ASSETS, deviceDossier: DOSSIER, dossierTotal: 0, assetTotal: ASSETS.length, listCap: 0, ts: 1 })};`);
  w.renderTargetsView();

  /* ── 1. every asset renders, with a Type badge ─────────────────────────── */
  section('rows + type column');
  const trs = [...d.querySelectorAll('#tres tbody tr')];
  ok(trs.length === ASSETS.length, `renders one row per asset (${ASSETS.length})`, trs.length);
  const typeCells = trs.map(tr => (tr.children[3] && tr.children[3].textContent || '').trim());
  const wantTypes = ['HOST', 'IP', 'WEBSITE', 'SUBDOMAIN', 'CLOUD', 'SERVICE', 'DOMAIN'];
  wantTypes.forEach(t => ok(typeCells.includes(t), `Type column shows a ${t} badge`, typeCells.join('|')));

  /* ── 2. click dispatch differs for hosts vs infra ──────────────────────── */
  section('per-type click dispatch');
  // Key on the row's stable data-label (the pure name), since the Name cell now
  // also carries the paired address (IP↔FQDN) for HOST/IP rows.
  const byName = Object.fromEntries(trs.map(tr => {
    const cb = tr.querySelector('.trow-cb');
    return [cb ? cb.dataset.label : (tr.children[2].textContent || '').trim(), tr];
  }));
  const hostRow = byName['DC01'] || byName['10.0.0.5'];
  ok(/openDeviceDossierFromTargets/.test((byName['DC01'] || {}).outerHTML || ''),
     'a HOST row opens the device-dossier modal', (byName['DC01'] || {}).getAttribute && byName['DC01'].getAttribute('onclick'));
  ok(/openDeviceDossierFromTargets/.test((byName['10.0.0.5'] || {}).outerHTML || ''),
     'an IP row opens the device-dossier modal too');
  ['https://portal.example.com', 'vpn.example.com', 'example-backups', '443/tcp (https nginx 1.18.0)', 'example.com'].forEach(nm => {
    const tr = byName[nm];
    ok(tr && /openAssetDetail/.test(tr.getAttribute('onclick') || ''),
       `an infra row (${nm.slice(0, 18)}) opens openAssetDetail`, tr && tr.getAttribute('onclick'));
  });

  /* ── 2b. IP↔FQDN pairing inline in the Name cell (no new column) ───────── */
  section('IP/FQDN pairing in the Name cell');
  const ipNameCell = (byName['10.0.0.5'].children[2].textContent || '');
  ok(/10\.0\.0\.5/.test(ipNameCell) && /linux01\.example\.com/.test(ipNameCell),
     'an IP row shows its resolved FQDN beside the address', ipNameCell);
  const hostNameCell = (byName['DC01'].children[2].textContent || '');
  ok(/DC01/.test(hostNameCell) && /10\.0\.0\.1/.test(hostNameCell),
     'a HOST row shows its captured IP beside the hostname', hostNameCell);

  /* ── 3. openAssetDetail opens the shared modal with type-specific props ─── */
  section('inline asset detail modal');
  w.openAssetDetail('c1');
  const modal = d.getElementById('dev-dm');
  ok(modal && !modal.classList.contains('hidden'), 'openAssetDetail un-hides the dev-dm modal');
  const body = (d.getElementById('ddm-body').textContent || '');
  ok(/Provider/i.test(body) && /aws/i.test(body), 'cloud detail shows Provider = aws', body.slice(0, 120));
  ok(/Exposure/i.test(body) && /80/.test(body), 'cloud detail shows the exposure score', body.slice(0, 200));
  ok(/credential/i.test(body), 'cloud detail lists sensitive categories', body.slice(0, 240));
  ok((d.getElementById('ddm-hostname').textContent || '') === 'example-backups', 'modal header names the asset');
  w.closeDeviceDossier();

  w.openAssetDetail('w1');
  const wbody = (d.getElementById('ddm-body').textContent || '');
  ok(/Default creds/i.test(wbody) && /Yes/i.test(wbody), 'website detail shows Default creds = Yes', wbody.slice(0, 200));
  ok(/FQDN/i.test(wbody) && /portal\.example\.com/.test(wbody), 'website detail shows the FQDN', wbody.slice(0, 240));
  w.closeDeviceDossier();

  w.openAssetDetail('v1');
  const vbody = (d.getElementById('ddm-body').textContent || '');
  ok(/Host/i.test(vbody) && /203\.0\.113\.9/.test(vbody), 'service detail shows the host IP', vbody.slice(0, 240));
  ok(/Hostnames/i.test(vbody) && /vpn\.example\.com/.test(vbody) && /www\.example\.com/.test(vbody),
     'service detail joins the hostnames JSON array', vbody.slice(0, 260));
  w.closeDeviceDossier();

  /* ── 4. Detail column: OS+risk for hosts, row.detail for infra ─────────── */
  section('detail column');
  const dcDetail = (byName['DC01'].children[4].textContent || '');
  ok(/Windows Server 2012 R2/.test(dcDetail), 'a host row shows its OS in the Detail column', dcDetail);
  const cloudDetail = (byName['example-backups'].children[4].textContent || '');
  ok(/public/.test(cloudDetail), 'an infra row shows its detail string', cloudDetail);

  /* ── 5. host rows still resolve the device modal via device_dossier_map ── */
  section('host modal via device_dossier_map');
  w.openDeviceDossierFromTargets('DC01');
  const dm = d.getElementById('dev-dm');
  ok(dm && !dm.classList.contains('hidden'), 'openDeviceDossierFromTargets opens the modal for a host');
  ok(/DOE, JOHN/.test(d.getElementById('ddm-body').textContent || ''), 'host modal renders its session user');
  w.closeDeviceDossier();

  console.log(`\n${failures ? 'FAIL' : 'PASS'} — ${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 200);
