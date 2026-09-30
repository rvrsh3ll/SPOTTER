#!/usr/bin/env node
/*
 * Headless smoke test for the header notification ticker (frontend/index.html).
 *
 * Why this exists
 * ---------------
 * The ticker is the first piece of this SPA with a background timer, a rotating
 * animation and a popup that lives outside its trigger, and every one of those
 * fails SILENTLY in a way a manual click-through does not reveal: an unguarded
 * matchMedia throws only where matchMedia is absent, a hidden tab that keeps
 * polling looks identical to one that does not, and an outside-click handler
 * that closes the panel before a row's own handler runs just looks like "the
 * click did nothing".
 *
 * This is the first JS harness in scripts/ -- everything else here is Python.
 * It needs no npm install: jsdom already ships inside the n8n install on this
 * host.
 *
 *   node scripts/smoke_frontend_notifications.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed (all are reported, the
 * run does not stop at the first).
 *
 * What it CANNOT tell you: jsdom has no layout engine, so clip-path,
 * position:fixed clipping, #hdr's overflow:hidden and the
 * @media (max-width:1180px) collapse are all unevaluated. Those still need one
 * manual browser pass at ~1400px and ~1000px, in BOTH themes.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');


// jsdom lives inside the global n8n install; fall back to a normal resolution
// so this keeps working if it is ever installed properly.
const { INDEX, loadJsdom } = require('./smoke_frontend_lib');
const { JSDOM, VirtualConsole } = loadJsdom();

/* ── tiny assertion harness ── */
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

const FIXTURE = {
  notifications: [
    { id: 'n1', ts: new Date(Date.now() - 60000).toISOString(), kind: 'attack_path',
      severity: 'critical', title: 'High-value attack path — j.doe', detail: 'score 22',
      target_label: 'j.doe', target_kind: 'individual', campaign_id: 'c-1', read: false },
    { id: 'n2', ts: new Date(Date.now() - 300000).toISOString(), kind: 'agent_status',
      severity: 'warn', title: 'Agent went stale — WS-014', detail: 'WS-014 · brute_ratel',
      target_label: 'WS-014', target_kind: 'agent', target_id: 'sess-9',
      campaign_id: 'c-1', read: false },
    { id: 'n3', ts: new Date(Date.now() - 900000).toISOString(), kind: 'breach',
      severity: 'critical', title: "Stealer log — O'Brien", detail: 'stealer_log',
      target_label: "O'Brien", target_kind: 'individual', campaign_id: 'c-1', read: true },
  ],
  unread: 2,
  generated_at: new Date().toISOString(),
  errors: [],
};

async function main() {
  const html = fs.readFileSync(INDEX, 'utf8');

  /* ── Step 0: syntax of the inline script ───────────────────────────── */
  section('Step 0 — inline script parses');
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  ok(blocks.length >= 2, 'expected at least two <script> blocks', blocks.length);
  const main_js = blocks.reduce((a, b) => (b.length > a.length ? b : a), '');
  ok(main_js.length > 100000, 'main script block looks like the big one', main_js.length);
  try {
    new vm.Script(main_js, { filename: 'index.html-inline.js' });
    ok(true, 'inline script parses');
  } catch (e) {
    ok(false, 'inline script parses', e.message);
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
    // REQUIRED: _ntfRotateStep uses requestAnimationFrame, which jsdom only
    // provides when pretending to be visual.
    pretendToBeVisual: true,
  });
  const w = dom.window;
  const d = w.document;
  await sleep(60);   // let DOMContentLoaded handlers settle
  // Captured BEFORE anything stubs it. `delete w.fetchJson` would not bring it
  // back: a top-level function declaration is a non-configurable property of
  // the global object, so the delete silently no-ops and Step 10 would end up
  // testing a stub instead of the real scoping path.
  const realFetchJson = w.fetchJson;
  ok(typeof realFetchJson === 'function', 'fetchJson resolved off window');
  // This is the assertion that catches an unguarded matchMedia: jsdom does not
  // implement it, so _ntfReduceMotion()'s try/catch is what keeps this green.
  ok(errs.length === 0, 'no jsdomError during load', errs.join(' | '));
  ok(typeof w.matchMedia === 'undefined', 'jsdom really has no matchMedia (guard is load-bearing)');

  /* ── Step 2: structure ─────────────────────────────────────────────── */
  section('Step 2 — DOM structure');
  ok(d.getElementById('classbar') === null, '#classbar is gone');
  ok(!html.includes('AUTHORIZED ENGAGEMENT'), 'index.html no longer carries the classification stamp');
  const login = fs.readFileSync(path.join(path.dirname(INDEX), 'login.html'), 'utf8');
  ok(login.includes('AUTHORIZED ENGAGEMENT'), 'login.html still carries the stamp');
  ok(!html.includes('margin-right: 120px'), 'the hand-reserved #ql gutter is gone');

  const wedge = d.getElementById('ntf-wedge');
  ok(!!wedge, '#ntf-wedge exists');
  ok(wedge && wedge.tagName === 'BUTTON', '#ntf-wedge is a real button', wedge && wedge.tagName);
  ok(wedge && wedge.getAttribute('aria-haspopup') === 'dialog', 'wedge is aria-haspopup=dialog');
  ok(wedge && wedge.getAttribute('aria-controls') === 'ntf-panel', 'wedge is aria-controls=ntf-panel');
  ok(wedge && !wedge.hasAttribute('aria-hidden'), 'wedge is NOT aria-hidden any more');

  const panel = d.getElementById('ntf-panel');
  ok(!!panel, '#ntf-panel exists');
  // Proves the panel is not nested inside #hdr, which is overflow:hidden and
  // would clip it to the 44px header band.
  ok(panel && panel.parentElement === d.body, '#ntf-panel is a direct child of <body>',
     panel && panel.parentElement && panel.parentElement.id);
  ok(panel && panel.classList.contains('hidden'), 'panel starts hidden');
  const sr = d.getElementById('ntf-sr');
  ok(sr && sr.getAttribute('aria-live') === 'polite',
     'live region is polite, not assertive (#tc already owns assertive)');

  /* ── Step 3: renders a stubbed feed ────────────────────────────────── */
  section('Step 3 — renders a stubbed feed');
  const calls = [];
  w.fetchJson = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) });
    return JSON.parse(JSON.stringify(FIXTURE));
  };
  w.getActiveCamp = () => ({ id: 'c-1', sketchId: 'sk-1', name: 'EXAMPLE' });

  await w.ntfFetch();
  const badge = d.getElementById('ntf-badge');
  ok(badge && badge.hidden === false, 'badge is visible with unread > 0');
  ok(badge && badge.textContent === '2', 'badge shows the unread count', badge && badge.textContent);
  ok(badge && badge.className.includes('sev-critical'),
     'badge takes the most-urgent unread severity', badge && badge.className);
  const line = d.getElementById('ntf-line');
  ok(line && /ATTACK PATH|j\.doe/i.test(line.textContent), 'wedge shows the newest headline',
     line && line.textContent);
  ok(wedge.getAttribute('aria-label').includes('2 unread'),
     'accessible name carries the count', wedge.getAttribute('aria-label'));
  ok(calls.length === 1 && calls[0].body.action === 'list', 'posted action=list');

  /* ── Step 4: rotation, deterministically ───────────────────────────── */
  section('Step 4 — rotation');
  // Drive the step directly rather than sleeping 5s. Read the non-window `let`
  // via eval: top-level let bindings are not properties of window.
  ok(w.eval('_ntfIdx') === 0, 'starts on headline 0', w.eval('_ntfIdx'));
  w._ntfRotateStep();
  await sleep(220);
  ok(w.eval('_ntfIdx') === 1, 'advances to headline 1', w.eval('_ntfIdx'));
  w._ntfRotateStep();
  await sleep(220);
  // Only 2 unread, so _ntfHeadlines() has length 2 and it wraps back to 0.
  ok(w.eval('_ntfIdx') === 0, 'wraps back round', w.eval('_ntfIdx'));

  /* ── Step 5: reduced motion ────────────────────────────────────────── */
  section('Step 5 — prefers-reduced-motion');
  w.matchMedia = () => ({ matches: true, addEventListener() {}, removeEventListener() {} });
  w.eval('_ntfIdx = 0');
  w._ntfStartRotate();
  ok(w.eval('_ntfRotTimer') === null, 'no rotation timer is scheduled under reduced motion',
     w.eval('_ntfRotTimer'));
  delete w.matchMedia;
  let threw = null;
  try { w._ntfStartRotate(); } catch (e) { threw = e.message; }
  ok(threw === null, 'start-rotate survives matchMedia being absent again', threw);

  /* ── Step 6: hidden tab polls nothing ──────────────────────────────── */
  section('Step 6 — hidden tab');
  const before = calls.length;
  Object.defineProperty(d, 'hidden', { configurable: true, get: () => true });
  d.dispatchEvent(new w.Event('visibilitychange'));
  ok(w.eval('_ntfPollTimer') === null, 'poll timer cleared while hidden', w.eval('_ntfPollTimer'));
  await sleep(120);
  ok(calls.length === before, 'no fetches while hidden', calls.length - before);
  Object.defineProperty(d, 'hidden', { configurable: true, get: () => false });
  d.dispatchEvent(new w.Event('visibilitychange'));
  ok(w.eval('_ntfPollTimer') !== null, 'poll timer restored on return');

  /* ── Step 7: outside-click containment ─────────────────────────────── */
  section('Step 7 — outside click vs row click');
  w.ntfOpen();
  ok(!panel.classList.contains('hidden'), 'panel opens');
  d.body.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  ok(panel.classList.contains('hidden'), 'outside click closes the panel');

  // The real trap: a click on a ROW also bubbles to document. If the outside
  // handler did not test containment it would close the panel before the row's
  // own handler could navigate, and the click would appear to do nothing.
  const navs = [];
  w.sw = t => navs.push(['sw', t]);
  w.jump = label => navs.push(['jump', label]);
  w.loadTargets = async () => {};
  w.loadAgents = async () => {};
  w.openAgentDetail = id => navs.push(['agent', id]);
  w.ntfOpen();
  const row = d.querySelector('#ntf-list .ntf-row');
  ok(!!row, 'panel rendered rows');
  if (row) {
    row.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
    await sleep(30);
    ok(navs.some(n => n[0] === 'jump' && n[1] === 'j.doe'),
       'row click actually navigated (was not swallowed by the outside handler)',
       JSON.stringify(navs));
  }

  /* ── Step 8: keyboard + focus ──────────────────────────────────────── */
  section('Step 8 — keyboard');
  w.ntfClose(false);
  wedge.focus();
  wedge.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
  ok(!panel.classList.contains('hidden'), 'ArrowDown on the closed wedge opens the panel');
  ok(d.activeElement && d.activeElement.classList.contains('ntf-row'),
     'ArrowDown lands focus on the first row', d.activeElement && d.activeElement.className);
  panel.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'ArrowUp', bubbles: true }));
  ok(d.activeElement === wedge, 'ArrowUp off the top returns to the wedge, never traps',
     d.activeElement && d.activeElement.id);
  w.ntfOpen();
  panel.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  ok(panel.classList.contains('hidden'), 'Escape closes');
  ok(d.activeElement === wedge, 'Escape restores focus to the wedge',
     d.activeElement && d.activeElement.id);

  /* ── Step 9: escaping ──────────────────────────────────────────────── */
  section('Step 9 — output escaping');
  w.fetchJson = async () => ({
    notifications: [{
      id: 'x1', ts: new Date().toISOString(), kind: 'breach', severity: 'warn',
      title: '<img src=x onerror=alert(1)>', detail: 'xss',
      target_label: "O'Brien", target_kind: 'individual', campaign_id: 'c-1', read: false,
    }],
    unread: 1, generated_at: new Date().toISOString(), errors: [],
  });
  await w.ntfFetch();
  w.ntfOpen();
  const listHtml = d.getElementById('ntf-list').innerHTML;
  ok(listHtml.includes('&lt;img'), 'title is HTML-escaped');
  ok(d.querySelectorAll('#ntf-list img').length === 0, 'no element was injected',
     d.querySelectorAll('#ntf-list img').length);
  // Proves the index-based onclick is immune to esc() not escaping apostrophes.
  const oRow = d.querySelector('#ntf-list .ntf-row');
  ok(oRow && /ntfActivate\(\d+\)/.test(oRow.getAttribute('onclick')),
     "row handler takes an index, not a label with an apostrophe in it",
     oRow && oRow.getAttribute('onclick'));
  w.ntfClose(false);

  /* ── Step 10: campaign scoping (the highest-value contract test) ───── */
  section('Step 10 — campaign scoping');
  // Stub window.fetch, NOT fetchJson, so _scopeWebhookOpts actually runs. If
  // the body were not a JSON object the scope stamp would silently not happen
  // and the backend would have no campaign to answer for.
  w.fetchJson = realFetchJson;
  const seen = [];
  w.fetch = async (url, opts) => {
    seen.push(JSON.parse(opts.body));
    return {
      ok: true, status: 200,
      headers: { get: () => 'application/json' },
      json: async () => JSON.parse(JSON.stringify(FIXTURE)),
      text: async () => JSON.stringify(FIXTURE),
    };
  };
  await w.ntfFetch();
  ok(seen.length === 1, 'one request went out', seen.length);
  ok(seen[0] && seen[0].campaign_id === 'c-1', 'campaign_id was stamped into the body',
     JSON.stringify(seen[0]));
  ok(seen[0] && seen[0].sketch_id === 'sk-1', 'sketch_id was stamped into the body',
     JSON.stringify(seen[0]));

  /* ── Step 11: campaign switch clears the feed ──────────────────────── */
  section('Step 11 — campaign switch');
  w.getActiveCamp = () => ({ id: 'c-2', sketchId: 'sk-2', name: 'OTHER' });
  w._ntfOnCampaignChange();
  ok(w.eval('_ntfItems.length') === 0, 'items cleared on campaign switch',
     w.eval('_ntfItems.length'));
  ok(w.eval('_ntfUnread') === 0, 'unread cleared on campaign switch', w.eval('_ntfUnread'));
  ok(d.getElementById('ntf-badge').hidden === true, 'badge hidden after the switch');

  /* ── done ──────────────────────────────────────────────────────────── */
  console.log(`\n${failures ? 'FAILED' : 'PASSED'} — ${checks - failures}/${checks} checks`);
  if (!failures) {
    console.log('\nStill needs a manual browser pass (jsdom evaluates no layout):');
    console.log('  · ~1400px and ~1000px wide, in BOTH themes');
    console.log('  · focus ring visible on the wedge\'s clipped corner');
    console.log('  · #ql does not shift when a long headline rotates in');
  }
  process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
