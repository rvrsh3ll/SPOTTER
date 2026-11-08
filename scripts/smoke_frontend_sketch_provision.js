#!/usr/bin/env node
/*
 * Headless smoke for campaign sketch provisioning (WF16 create-sketch).
 *
 * Pins three failure modes that made a provisioning error look like "something
 * didn't resolve" and then vanish:
 *
 *   1. An error toast must outlive the 3-second info/ok window, and must not be
 *      silently dropped by the two-toast cap — otherwise the operator never
 *      reads the WF16 reason (e.g. "could not resolve or create investigation").
 *   2. provisionSketch must persist sketchStatus='failed' and sketchError on the
 *      campaign so the campaign panel can show the reason after the toast is gone.
 *   3. A successful provision must clear sketchError and set sketchId.
 *
 *   node scripts/smoke_frontend_sketch_provision.js
 *
 * Exit 0 = pass. Exit 1 = assertion failed. Exit 2 = cannot run.
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
vc.on('jsdomError', () => {});

const dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
  runScripts: 'dangerously', pretendToBeVisual: true,
  url: 'http://localhost:8080/', virtualConsole: vc,
});
const w = dom.window;
const d = w.document;

w.CURRENT_USER = { username: 'alice', is_admin: false };

/* Fake clocks so we can assert toast lifetime without waiting 12 real seconds. */
const timers = [];
const realSetTimeout = w.setTimeout.bind(w);
w.setTimeout = function (fn, ms) {
  const id = { fn, ms, cleared: false };
  timers.push(id);
  return id;
};
w.clearTimeout = function (id) { if (id) id.cleared = true; };
function flushTimers(uptoMs) {
  // Run every pending timer whose delay is <= uptoMs, in order, once.
  const due = timers.filter(t => !t.cleared && t.ms <= uptoMs);
  due.forEach(t => { t.cleared = true; try { t.fn(); } catch {} });
}

function setupEmpty() {
  w.localStorage.clear();
  timers.length = 0;
  const host = d.getElementById('tc');
  if (host) host.innerHTML = '';
  w.tc = 0;
}

function mockFetch(handler) {
  w.fetch = async (url, opts) => {
    const body = opts && opts.body ? JSON.parse(opts.body) : null;
    const json = await handler(url, body, opts);
    return {
      ok: true, status: 200,
      headers: { get: () => 'application/json' },
      json: async () => json,
      text: async () => JSON.stringify(json),
    };
  };
}

(async () => {
  /* ── 1. toast: errors bypass the cap and linger ─────────────────────────── */
  section('error toast lifetime');
  setupEmpty();
  w.toast('info one', 'inf');
  w.toast('info two', 'inf');
  w.toast('info three should drop', 'inf');
  ok(d.querySelectorAll('#tc .toast').length === 2,
     'info/ok toasts are still capped at two',
     d.querySelectorAll('#tc .toast').length);

  w.toast('provisioning blew up: could not resolve or create investigation', 'err');
  const errToasts = [...d.querySelectorAll('#tc .toast.terr')];
  ok(errToasts.length === 1, 'an error toast is shown even when the info cap is full',
     errToasts.length);
  ok(errToasts[0].textContent.includes('could not resolve or create investigation'),
     'the full error reason is in the toast text', errToasts[0].textContent);

  const errTimer = timers.find(t => !t.cleared && t.fn && t.ms > 3000);
  ok(!!errTimer && errTimer.ms >= 10000,
     'error toasts linger at least 10 seconds (info is 3s)',
     errTimer && errTimer.ms);

  /* ── 2. provisionSketch failure persists sketchError ────────────────────── */
  section('provisionSketch failure persists sketchError');
  setupEmpty();
  const camp = {
    id: 'ACME', name: 'ACME Corp', created: '2026-01-01T00:00:00Z',
    sketchId: null, sketchStatus: 'needs-sketch',
    objectives: w.objDefaults(),
  };
  w.localStorage.setItem('s.campaigns', JSON.stringify([camp]));
  w.localStorage.setItem('s.activeCamp', JSON.stringify(camp));

  mockFetch(async (url) => {
    if (url.includes('save-campaigns')) return { rejected: [], quota: { used: 1, limit: 3 } };
    if (url.includes('create-sketch')) {
      return { error: 'could not resolve or create investigation', sketch_id: '' };
    }
    return {};
  });

  const okFail = await w.provisionSketch('ACME');
  ok(okFail === false, 'provisionSketch returns false on a handled WF16 error');

  const after = JSON.parse(w.localStorage.getItem('s.campaigns'))[0];
  ok(after.sketchStatus === 'failed', 'sketchStatus is failed', after.sketchStatus);
  ok(after.sketchId == null || after.sketchId === '', 'sketchId stays empty', after.sketchId);
  ok(after.sketchError === 'could not resolve or create investigation',
     'sketchError carries the WF16 reason', after.sketchError);
  ok(Array.isArray(after.objectives.organizations),
     'objectives.organizations survives the failed provision',
     JSON.stringify(after.objectives.organizations));

  const toastText = [...d.querySelectorAll('#tc .toast')].map(t => t.textContent).join(' | ');
  ok(/could not resolve or create investigation/.test(toastText),
     'the failure toast names the WF16 reason', toastText);

  /* Panel must surface the persisted error so it is still readable after the
     toast is gone. */
  w.renderCampaignPanel();
  const panel = d.getElementById('camp-panel').textContent;
  ok(/could not resolve/.test(panel),
     'campaign panel shows the sketchError after the toast is gone', panel);
  ok(/Retry Provision/.test(d.getElementById('camp-panel').innerHTML),
     'failed campaigns offer Retry Provision');

  /* ── 3. provisionSketch success clears sketchError ──────────────────────── */
  section('provisionSketch success clears sketchError');
  setupEmpty();
  const camp2 = {
    id: 'BETA', name: 'Beta', created: '2026-01-01T00:00:00Z',
    sketchId: null, sketchStatus: 'failed',
    sketchError: 'previous failure',
    objectives: w.objDefaults(),
  };
  w.localStorage.setItem('s.campaigns', JSON.stringify([camp2]));
  w.localStorage.setItem('s.activeCamp', JSON.stringify(camp2));

  mockFetch(async (url) => {
    if (url.includes('save-campaigns')) return { rejected: [], quota: { used: 1, limit: 3 } };
    if (url.includes('create-sketch')) {
      return { sketch_id: 'sk-NEW', investigation_id: 'inv-1', campaign_id: 'BETA' };
    }
    return {};
  });

  const okSucc = await w.provisionSketch('BETA');
  ok(okSucc === true, 'provisionSketch returns true on success');
  const after2 = JSON.parse(w.localStorage.getItem('s.campaigns'))[0];
  ok(after2.sketchId === 'sk-NEW', 'sketchId is stored', after2.sketchId);
  ok(after2.sketchStatus === 'ready', 'sketchStatus is ready', after2.sketchStatus);
  ok(!after2.sketchError, 'sketchError is cleared on success', after2.sketchError);

  /* ── 4. createCampaign still calls provisionSketch and keeps multi-org defaults ── */
  section('createCampaign wires through to provisionSketch');
  setupEmpty();
  const seen = [];
  mockFetch(async (url, body) => {
    seen.push({ url, body });
    if (url.includes('save-campaigns')) return { rejected: [], quota: { used: 1, limit: 3 } };
    if (url.includes('create-sketch')) {
      return { error: 'could not resolve or create investigation', sketch_id: '' };
    }
    return {};
  });
  d.getElementById('cnew-name').value = 'Gamma Org';
  d.getElementById('cnew-id').value = 'GAMMA';
  await w.createCampaign();
  const createCall = seen.find(c => c.url.includes('create-sketch'));
  ok(!!createCall, 'createCampaign invokes create-sketch');
  ok(createCall && createCall.body.campaign_id === 'GAMMA'
     && createCall.body.campaign_name === 'Gamma Org',
     'create-sketch body carries campaign_id and campaign_name',
     JSON.stringify(createCall && createCall.body));
  const gamma = JSON.parse(w.localStorage.getItem('s.campaigns')).find(c => c.id === 'GAMMA');
  ok(!!gamma, 'the new campaign is stored');
  ok(gamma && gamma.sketchStatus === 'failed'
     && gamma.sketchError === 'could not resolve or create investigation',
     'createCampaign surfaces the provisioning failure on the new campaign',
     gamma && gamma.sketchError);
  ok(gamma && Array.isArray(gamma.objectives.organizations)
     && gamma.objectives.organizations.length === 0,
     'new campaigns still get the multi-org objectives defaults');

  console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${checks - failures}/${checks} checks`);
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
