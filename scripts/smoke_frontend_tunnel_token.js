#!/usr/bin/env node
/*
 * Regression guard for the Infrastructure tab's managed tunnel / Tor controls.
 *
 * The bug this exists to catch (2026-08-17): the Managed Tunnel API Token field
 * was blanked by infraLoadForm(), which is ALSO the sw('infra') tab-open
 * handler — so a token pasted by the operator vanished the moment they visited
 * another tab and came back. Every /infra/tunnel/ call then 401'd, and the UI
 * rendered that as "Tor status check failed" with Stop greyed out, which is
 * indistinguishable from a dead tunnel. The Tor process was fine throughout.
 *
 * The fix removed the field entirely: nginx now injects X-Tunnel-Token from
 * TUNNEL_API_TOKEN (frontend/nginx.conf, mounted as an envsubst template), so
 * the browser never holds the secret. The stub here therefore answers 200 for
 * requests carrying NO token, which is what the page now sees, and asserts:
 *   1. no request from the page carries X-Tunnel-Token;
 *   2. the Tor bar survives a tab switch instead of flipping to an auth error;
 *   3. a cold load needs no operator input to show live tunnel state.
 *
 * Needs no npm install: jsdom ships inside the n8n install on this host.
 *
 *   node scripts/smoke_frontend_tunnel_token.js
 *
 * Exit 0 = pass. What it CANNOT tell you: whether nginx is actually rendering
 * the token — that is a deployment fact, checked with
 *   docker exec spotter-ui grep -c 'X-Tunnel-Token' /etc/nginx/nginx.conf
 * (and a 401 in the UI now means nginx and the sidecar disagree on the value).
 */
'use strict';
const fs = require('fs');
const { INDEX, loadJsdom } = require('./smoke_frontend_lib');
const { JSDOM, VirtualConsole } = loadJsdom();
const sleep = ms => new Promise(r => setTimeout(r, ms));

const LIVE_TOR = {
  available: true, error: '', ok: true, running: true,
  last_log: 'Aug 17 18:36:35.000 [notice] Bootstrapped 100% (done): Done',
  tor: { bootstrap_percent: 100, bootstrapped: true, entry_countries: ['us'], exit_countries: ['us'],
         id: 'bb85a213', pid: 35838, socks_host: 'ssh-tunnel-api', socks_port: 9050,
         strict_nodes: true, uptime_seconds: 19401 },
};

let fails = 0;
const ok = (cond, label, extra) => {
  if (cond) { console.log('  PASS  ' + label); return true; }
  fails++; console.log('  FAIL  ' + label + (extra !== undefined ? '\n        got: ' + extra : ''));
  return false;
};

const calls = [];
(async () => {
  const dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
    runScripts: 'dangerously', url: 'http://localhost:8080/',
    virtualConsole: new VirtualConsole(), pretendToBeVisual: true,
  });
  const w = dom.window, d = w.document;
  await sleep(120);
  w.fetch = async (url, opts = {}) => {
    const h = opts.headers || {};
    calls.push({ url: String(url), tokenHeader: h['X-Tunnel-Token'] || h['x-tunnel-token'] || null });
    const reply = data => ({ ok: true, status: 200,
      headers: { get: k => (k.toLowerCase() === 'content-type' ? 'application/json' : null) },
      json: async () => data });
    if (/tor\/status$/.test(url))    return reply(LIVE_TOR);
    if (/tor\/countries$/.test(url)) return reply({ ok: true, countries: [{ code: 'us', name: 'United States' }] });
    if (/tunnel\/status$/.test(url)) return reply({ ok: true, running: false, tunnel: null, error: '' });
    return reply({ ok: true });
  };

  const bar = () => d.getElementById('infra-tor-status');
  const stop = () => d.getElementById('infra-tor-stop-btn');

  console.log('\n── the field is gone');
  ok(d.getElementById('infra-tunnel-token') === null, 'Managed Tunnel API Token input removed from the DOM');

  console.log('\n── first visit to Infrastructure');
  w.sw('infra');
  await sleep(300);
  ok(/obar/.test(bar().className), 'Tor bar renders green', bar().className);
  ok(/Tor running on ssh-tunnel-api:9050/.test(bar().textContent), 'Tor bar shows the live tunnel',
     bar().textContent.trim().slice(0, 90));
  ok(stop().disabled === false, 'Stop button is live');

  console.log('\n── leave the tab and come back (the reported failure)');
  w.sw('targets'); await sleep(60);
  w.sw('infra');  await sleep(300);
  ok(/obar/.test(bar().className), 'Tor bar still green after a tab round-trip', bar().className);
  ok(stop().disabled === false, 'Stop button still live', bar().textContent.trim().slice(0, 90));

  console.log('\n── full page reload (fresh DOM, nothing carried over)');
  const dom2 = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
    runScripts: 'dangerously', url: 'http://localhost:8080/',
    virtualConsole: new VirtualConsole(), pretendToBeVisual: true });
  const w2 = dom2.window, d2 = dom2.window.document;
  await sleep(120);
  w2.fetch = w.fetch;
  w2.sw('infra');
  await sleep(300);
  ok(/obar/.test(d2.getElementById('infra-tor-status').className),
     'Tor bar green on a cold load with no operator input',
     d2.getElementById('infra-tor-status').className);

  console.log('\n── what the browser actually sent');
  const infra = calls.filter(c => /\/infra\/tunnel\//.test(c.url));
  ok(infra.length > 0, 'the page did call the tunnel control plane', infra.length);
  ok(infra.every(c => c.tokenHeader === null),
     'no request carried X-Tunnel-Token (nginx supplies it)',
     JSON.stringify(infra.filter(c => c.tokenHeader).map(c => c.url)));

  console.log(fails === 0 ? '\nPASSED' : `\nFAILED — ${fails} check(s)`);
  process.exit(fails === 0 ? 0 : 1);
})();
