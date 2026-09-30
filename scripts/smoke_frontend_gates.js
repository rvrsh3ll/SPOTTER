#!/usr/bin/env node
/*
 * Headless smoke test for the header's quick-launch GATES (Graph / Workflows / Chat).
 *
 *   node scripts/smoke_frontend_gates.js
 *
 * WHAT IT PINS, and why each one is here rather than assumed:
 *
 *  1. THE BOOT HANDLER SURVIVES A FIRST-EVER VISIT. gatewayUrl() takes a KEY of
 *     GATES ('chat'), not a port number. Two callers passed the literal 3000,
 *     which made `g` undefined and threw a TypeError out of DOMContentLoaded at
 *     its fourth statement -- so pinGatewayLinks(), renderCampaignHeader(),
 *     ntfInit() and everything after them never ran. The visible symptom was
 *     narrow and misleading: Graph and Workflows still worked (their raw
 *     placeholder hrefs happen to equal their defaults) while Chat opened
 *     http://localhost:3000 and showed nothing. Only a browser with no
 *     s.llmEndpoint in localStorage hit it, which is why it survived so long.
 *     A jsdomError during load is therefore a FAILURE here, not noise.
 *
 *  2. EVERY GATE RESOLVES TO THE CADDY FRONT DOOR. One hostname set, one
 *     forwarded port. A gate that drifts back onto a service's own container
 *     port is unreachable for any operator who is not sitting on the docker host.
 *
 *  3. THE PLACEHOLDER HREFS MATCH THE DEFAULTS. They are what a browser
 *     navigates to when the pin never happens, so a stale one is a silent trap
 *     of exactly the kind (1) describes.
 *
 *  4. migrateLlmEndpoint() retires a stored :3000 override but leaves a
 *     deliberate custom forward alone.
 *
 * Exit 0 = pass, 1 = a failed assertion, 2 = jsdom missing.
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
function section(t) { console.log(`\n-- ${t}`); }

/* The dashboard vhost, so the test sees what an operator's browser sees. */
const PAGE_URL = 'https://spotter.localhost:5443/';

/* Resolves only AFTER the page's DOMContentLoaded handler has run. Asserting
   synchronously on the JSDOM constructor's return value tests the page before
   boot, which passes for the wrong reason (nothing has thrown YET). */
function boot(localStorageSeed) {
  const jsdomErrors = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => jsdomErrors.push((e && e.detail && e.detail.message) || e.message));

  const dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
    runScripts: 'dangerously', pretendToBeVisual: true,
    url: PAGE_URL, virtualConsole: vc,
    beforeParse(w) {
      /* Seed BEFORE any script runs: the boot handler reads localStorage, and
         seeding afterwards would test the wrong branch. */
      Object.entries(localStorageSeed || {}).forEach(([k, v]) => {
        try { w.localStorage.setItem(k, v); } catch {}
      });
      /* No /config.js in jsdom -- index.html loads it from nginx. Absent, the
         GATES defaults apply, which is exactly the fallback worth pinning. */
    },
  });
  const w = dom.window;
  return new Promise(resolve => {
    const done = () => setTimeout(() => resolve({ w, jsdomErrors }), 0);
    if (w.document.readyState === 'loading') {
      w.document.addEventListener('DOMContentLoaded', done);
    } else {
      done();
    }
  });
}

async function main() {
  /* -- 1. a first-ever visit (no stored endpoint) must not throw ----------- */
  section('Boot with an empty localStorage');
  const { w, jsdomErrors } = await boot({});

  ok(jsdomErrors.length === 0,
     'DOMContentLoaded completes without throwing',
     jsdomErrors.join(' | '));

  /* The tell-tale that the handler ran past statement four: boot sets this and
     nothing else does, so an empty field means it died early. */
  ok(w.document.getElementById('llmEndpoint').value !== '',
     'boot filled the Prompt tab ENDPOINT field',
     JSON.stringify(w.document.getElementById('llmEndpoint').value));

  const gwChat = w.eval('gatewayUrl("chat")');
  ok(gwChat === 'https://chat.spotter.localhost:5443',
     'gatewayUrl("chat") is the Caddy chat vhost', gwChat);

  /* The miscall itself. It must no longer take the page down. */
  let threw = false, byPort;
  try { byPort = w.eval('gatewayUrl(3000)'); } catch (e) { threw = true; byPort = e.message; }
  ok(!threw, 'gatewayUrl() with an unknown key returns instead of throwing', byPort);

  section('Every gate resolves to the Caddy front door');
  const port = String(w.eval('GATES.n8n.port'));
  ['n8n', 'graph', 'chat'].forEach(name => {
    const url = w.eval(`gatewayUrl(${JSON.stringify(name)})`);
    ok(url.startsWith('https://'), `${name}: https`, url);
    ok(url.endsWith(':' + port), `${name}: on the one Caddy port (${port})`, url);
    /* Reaching a service's own container port means a second forward the
       operator does not have -- the bug this suite exists for. */
    ok(!/:(3000|5678|5173|8080|8081|8082|8083)$/.test(url),
       `${name}: not a bare container port`, url);
  });

  section('Each gate expects a distinct identity from /_spotter/gate');
  const ids = ['n8n', 'graph', 'chat'].map(n => w.eval(`GATES[${JSON.stringify(n)}].id`));
  ok(ids.every(Boolean), 'every gate declares an id to verify against', JSON.stringify(ids));
  ok(new Set(ids).size === ids.length, 'the ids are distinct', JSON.stringify(ids));
  ok(ids[2] === 'open-webui', 'chat verifies against the Open WebUI vhost', ids[2]);

  section('Placeholder hrefs match the pinned defaults');
  /* Compared against gatewayUrl(), not against a literal, so this keeps
     agreeing with the defaults when an install renames a vhost. jsdom
     normalises an href to a trailing slash; the gate URLs carry none.
     Read off a FRESH parse, because pinGatewayLinks() rewrites these in place. */
  const raw = new JSDOM(fs.readFileSync(INDEX, 'utf8'), { url: PAGE_URL }).window.document;
  [['ql-n8n', 'n8n'], ['ql-graph', 'graph'], ['ql-chat', 'chat']].forEach(([id, name]) => {
    const href = raw.getElementById(id).getAttribute('href').replace(/\/$/, '');
    ok(href === w.eval(`gatewayUrl(${JSON.stringify(name)})`),
       `${id} placeholder equals gatewayUrl(${name})`, href);
  });

  /* -- 1b. a dead gate must name the likely cause -------------------------- */
  section('gateLikelyUntrustedCert()');
  /* The page is served from https://spotter.localhost:5443 (PAGE_URL). */
  const CERT_CASES = [
    ['https://chat.spotter.localhost:5443',  true,  'sibling vhost, same port -- the transport is proven'],
    ['https://n8n.spotter.localhost:5443',   true,  'likewise'],
    ['https://spotter.localhost:5443',       false, 'this page itself, not a sibling'],
    ['https://chat.spotter.localhost:6000',  false, 'different port -- transport is NOT proven'],
    ['http://chat.spotter.localhost:5443',   false, 'plain http -- no certificate to distrust'],
    ['https://owui.example.com:5443',        false, 'unrelated host that merely shares a port'],
  ];
  CERT_CASES.forEach(([url, want, why]) => {
    const got = w.eval(`gateLikelyUntrustedCert(${JSON.stringify(url)})`);
    ok(got === want, `${want ? 'cert hint ' : 'plain     '} ${url}  (${why})`, got);
  });

  /* -- 2. the stored-override migration ----------------------------------- */
  section('migrateLlmEndpoint()');
  const CASES = [
    ['http://localhost:3000',               true,  'the old computed default'],
    ['http://127.0.0.1:3000',               true,  'the loopback spelling of it'],
    ['https://spotter.localhost:3000',      true,  'the dashboard hostname on :3000'],
    ['http://localhost:13000',              false, 'a deliberate custom forward'],
    ['https://chat.spotter.localhost:5443', false, 'the new default'],
    ['http://owui.internal:3000',           false, 'a different host on :3000'],
  ];
  for (const [stored, shouldClear, why] of CASES) {
    const { w: wc } = await boot({ 's.llmEndpoint': stored });
    let after = null;
    try { after = wc.localStorage.getItem('s.llmEndpoint'); } catch {}
    ok(shouldClear ? after === null : after === stored,
       `${shouldClear ? 'retires' : 'keeps  '} ${stored}  (${why})`,
       JSON.stringify(after));
    const shown = wc.document.getElementById('llmEndpoint').value;
    if (shouldClear) {
      /* Retiring it must hand the field the new default, never leave it blank. */
      ok(shown === wc.eval('gatewayUrl("chat")'),
         `  ...and the ENDPOINT field falls back to the chat vhost`, JSON.stringify(shown));
    } else {
      /* A kept override must still be what the Prompt tab and Chat link use. */
      ok(shown === stored, `  ...and the ENDPOINT field shows it`, JSON.stringify(shown));
    }
  }

  console.log(`\n${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error('FATAL', e); process.exit(2); });
