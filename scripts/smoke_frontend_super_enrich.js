#!/usr/bin/env node
/*
 * Frontend smoke for the Super-Enrich (WF27 identity pivot) action.
 *
 * Loads the real frontend/index.html under jsdom and checks:
 *   - the inline script parses and loads with zero errors
 *   - superEnrichSelected / renderSuperEnrich / openSuperEnrich / closeSuperEnrich
 *     resolve off window, the #se-dm modal shell exists, and the Action-menu item
 *     is present
 *   - renderSuperEnrich shows the report and, when a credential_value is present,
 *     renders the "not saved" caveat and the plaintext — but that plaintext NEVER
 *     lands in localStorage or the targets cache
 *   - superEnrichSelected enforces the 1-5 cap (6 selected -> blocked, no fetch)
 *   - the happy path fires one object-body request per person with
 *     include_credentials + reveal_events, opens the modal, and does not persist
 *     any cleartext
 *
 * What it CANNOT tell you: jsdom has no layout. One browser pass still owed.
 *
 *   node scripts/smoke_frontend_super_enrich.js
 */
'use strict';

const fs = require('fs');
const vm = require('vm');


const { INDEX, loadJsdom } = require('./smoke_frontend_lib');
const { JSDOM, VirtualConsole } = loadJsdom();

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

const CLEARTEXT = 'Summer2023!';

function synthReport() {
  return {
    status: 'ok',
    subject: { id: 'ind-1', label: 'CN=Jane Doe', username: 'jdoe', department: 'IT' },
    identity: {
      real_name: 'Jane A. Doe', department: 'IT', company: 'Corp Inc',
      groups: ['Domain Admins'], personal_emails: ['jane.doe@gmail.com'],
      personal_phones: ['555-0100'], addresses: ['123 Main St'],
      locations_lived: ['Portland, OR'], work_history: [],
      social_profiles: [{ platform: 'github', url: 'https://github.com/janedoe', display_name: null }],
      ips: ['1.2.3.4'], devices: ['Windows 10'], event_urls: [],
    },
    breaches: [{
      account: 'jane.doe@gmail.com', source: 'RedLine', event_type: 'stealer_logs',
      has_stealer: true, hash_type: 'plaintext', password_exposed: true,
      credential_value: CLEARTEXT,
    }],
    correlation: {
      password_reuse: 'HIGH', corp_breach_match: true,
      reuse_groups: [{ accounts: ['jdoe@corp.local', 'jane.doe@gmail.com'], count: 2, value: CLEARTEXT }],
      format_families: [{ mask: 'WDS', base: 'summer', accounts: ['a', 'b'] }],
      plaintext_accounts: ['jdoe@corp.local', 'jane.doe@gmail.com'],
    },
    sources: { linkedin: true, maigret: 2, socid: 1, flare_emails: 1, flare_events: 1 },
    notes: ['opsec: queried Flare firework events for 1 record(s)'],
    flare_status: 'ok', breaches_imported: 1, include_credentials: true, reveal_events: true,
  };
}

function localStorageHasCleartext(w) {
  for (let i = 0; i < w.localStorage.length; i++) {
    const k = w.localStorage.key(i);
    if ((w.localStorage.getItem(k) || '').includes(CLEARTEXT)) return k;
  }
  return null;
}

async function main() {
  const html = fs.readFileSync(INDEX, 'utf8');

  /* ── Step 0: inline script parses ──────────────────────────────────── */
  section('Step 0 — inline script parses');
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const main_js = blocks.reduce((a, b) => (b.length > a.length ? b : a), '');
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
    runScripts: 'dangerously', url: 'http://localhost/',
    virtualConsole: vc, pretendToBeVisual: true,
  });
  const w = dom.window, d = w.document;
  await sleep(60);
  ok(errs.length === 0, 'no jsdomError during load', errs.join(' | '));

  /* ── Step 2: functions + shell present ─────────────────────────────── */
  section('Step 2 — functions and shell present');
  ['superEnrichSelected', 'renderSuperEnrich', 'openSuperEnrich', 'closeSuperEnrich']
    .forEach(fn => ok(typeof w[fn] === 'function', `${fn} is defined`, typeof w[fn]));
  ok(!!d.getElementById('se-dm'), '#se-dm modal shell exists');
  ok(!!d.getElementById('sedm-body'), '#sedm-body exists');
  ok(/superEnrichSelected\(\)/.test(html), 'Action-menu item wired to superEnrichSelected');

  /* ── Step 3: renderSuperEnrich shows report + caveat, no persistence ─ */
  section('Step 3 — renderSuperEnrich (plaintext shown, never persisted)');
  const before = localStorageHasCleartext(w);
  ok(before === null, 'no cleartext in localStorage before render');
  w.renderSuperEnrich([{ target: { label: 'CN=Jane Doe', id: 'ind-1' }, data: synthReport() }]);
  const seBody = d.getElementById('sedm-body').innerHTML;
  ok(!d.getElementById('se-dm').classList.contains('hidden'), 'modal opened');
  ok(/Jane A\. Doe/.test(seBody), 'real name rendered');
  // Name is surfaced as its own identified field, split into first / last.
  const seDoc = d.getElementById('sedm-body');
  const nameRow = [...seDoc.querySelectorAll('.se-idname')][0];
  ok(!!nameRow && /Jane A\. Doe/.test(nameRow.textContent), 'dedicated Name field rendered');
  ok(!!nameRow && /first:\s*Jane/.test(nameRow.textContent) && /last:\s*A\. Doe/.test(nameRow.textContent),
     'Name field split into first + last');
  // Social profiles wrap in their own container (was one unbreakable line).
  const soc = seDoc.querySelector('.se-social');
  ok(!!soc, 'social links rendered inside .se-social wrapper');
  ok(!!soc && soc.querySelectorAll('a').length === 1, 'social wrapper holds the anchor(s)');
  ok(/jane\.doe@gmail\.com/.test(seBody), 'discovered personal email rendered');
  ok(/reuse: HIGH/.test(seBody), 'reuse verdict pill rendered');
  ok(/corp.{0,3}personal password match/.test(seBody), 'corp-breach match badge rendered');
  ok(seBody.includes(CLEARTEXT), 'plaintext shown in panel (include_credentials)');
  ok(/not<\/strong>? saved|not.{0,20}saved/.test(seBody), 'plaintext caveat banner present');
  ok(localStorageHasCleartext(w) === null, 'render did NOT write cleartext to localStorage',
     localStorageHasCleartext(w));

  /* ── Step 3b: name anchors on the corp email; a conflicting pivot name
        is flagged as an unverified alias, not shown as THE name ────────── */
  section('Step 3b — Name anchors on corp email, collision flagged');
  const collide = synthReport();
  collide.subject = { id: 'ind-2', label: 'john.smith@example.com',
                      username: 'jsmith', email: 'john.smith@example.com', department: 'Sales' };
  collide.identity.real_name = 'Alex Example';   // socid username collision
  w.renderSuperEnrich([{ target: { label: 'john.smith@example.com', id: 'ind-2' }, data: collide }]);
  const nrow = d.getElementById('sedm-body').querySelector('.se-idname');
  ok(!!nrow && /John Smith/.test(nrow.textContent), 'Name derived from email first.last (John Smith)');
  ok(!!nrow && /first:\s*John/.test(nrow.textContent) && /last:\s*Smith/.test(nrow.textContent),
     'email-derived name split into first + last');
  ok(!!nrow && !/Alex Example<\/(strong|div)>?\s*$/.test(nrow.innerHTML.split('se-alias')[0]) &&
     /se-alias/.test(nrow.innerHTML), 'conflicting pivot name is not the headline name');
  const alias = d.getElementById('sedm-body').querySelector('.se-alias');
  ok(!!alias && /Alex Example/.test(alias.textContent), 'conflicting pivot name flagged as alias');
  ok(!!alias && /collision/i.test(alias.textContent), 'alias flag warns of a possible username collision');

  // Role / single-token mailbox → no email split, fall back to discovered name.
  const roleRep = synthReport();
  roleRep.subject = { id: 'ind-3', label: 'sales@example.com', email: 'sales@example.com' };
  roleRep.identity.real_name = 'Real Person';
  w.renderSuperEnrich([{ target: { label: 'sales@example.com', id: 'ind-3' }, data: roleRep }]);
  const rrow = d.getElementById('sedm-body').querySelector('.se-idname');
  ok(!!rrow && /Real Person/.test(rrow.textContent) && !d.getElementById('sedm-body').querySelector('.se-alias'),
     'role mailbox falls back to discovered name with no false collision flag');

  /* ── Step 4: 1-5 cap ───────────────────────────────────────────────── */
  section('Step 4 — 1-5 cap blocks 6 selected');
  const toasts = [];
  w.toast = (m, t) => toasts.push({ m, t });
  let fetchCalls = [];
  w.fetchJson = async (url, opts) => { fetchCalls.push({ url, opts }); return synthReport(); };
  w.loadTargets = async () => {};

  // Inject a minimal targets toolbar + selection into the document.
  const holder = d.createElement('div');
  holder.innerHTML = '<button id="act-btn"></button><div id="act-menu"></div>' +
                     '<span id="tact-sp"></span><span id="tsel-count"></span>';
  d.body.appendChild(holder);
  function selectRows(n) {
    [...d.querySelectorAll('.trow-cb')].forEach(e => e.remove());
    for (let i = 0; i < n; i++) {
      const cb = d.createElement('input');
      cb.type = 'checkbox'; cb.className = 'trow-cb'; cb.checked = true;
      cb.dataset.label = 'Person ' + i; cb.dataset.eid = 'id-' + i;
      d.body.appendChild(cb);
    }
  }

  selectRows(6);
  fetchCalls = []; toasts.length = 0;
  await w.superEnrichSelected();
  await sleep(10);
  ok(fetchCalls.length === 0, '6 selected -> no request fired', fetchCalls.length);
  ok(toasts.some(t => /1.{0,3}5|Super-Enrich/i.test(t.m)), 'cap toast shown',
     JSON.stringify(toasts));

  /* ── Step 5: happy path (2 selected) ───────────────────────────────── */
  section('Step 5 — happy path fans out per person, no cleartext persisted');
  selectRows(2);
  fetchCalls = []; toasts.length = 0;
  w.closeSuperEnrich();
  await w.superEnrichSelected();
  await sleep(10);
  ok(fetchCalls.length === 2, 'one request per selected person', fetchCalls.length);
  let bodyObj = null;
  try { bodyObj = JSON.parse(fetchCalls[0].opts.body); } catch { /* */ }
  ok(bodyObj && typeof bodyObj === 'object' && !Array.isArray(bodyObj),
     'request body is a JSON object (sketch scoping)');
  ok(bodyObj && bodyObj.include_credentials === true, 'include_credentials set');
  ok(bodyObj && bodyObj.reveal_events === true, 'reveal_events set');
  ok(/\/webhook\/super-enrich$/.test(fetchCalls[0].url), 'posts to /webhook/super-enrich',
     fetchCalls[0].url);
  ok(!d.getElementById('se-dm').classList.contains('hidden'), 'report modal opened');
  ok(localStorageHasCleartext(w) === null, 'happy path persisted no cleartext',
     localStorageHasCleartext(w));

  /* ── done ──────────────────────────────────────────────────────────── */
  console.log(`\n${failures ? 'FAILED' : 'OK'} — ${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error('FATAL', e); process.exit(2); });
