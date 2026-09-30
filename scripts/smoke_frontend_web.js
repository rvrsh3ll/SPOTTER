#!/usr/bin/env node
/*
 * Headless smoke test for the WEB tab (EyeWitness web-recon endpoints).
 *
 * Loads the real frontend/index.html in jsdom, seeds _webCache the way WF26
 * (/webhook/web-inventory) would fill it, and asserts the operator-visible
 * behaviour of the screenshot gallery, filters, search and detail modal.
 *
 * Load-bearing invariant it pins: safeShotUrl(). Screenshots are same-origin
 * files served (auth-gated) at /screenshots/, but the global safeUrl() rejects
 * anything that is not http(s):// — so the Web tab has its OWN validator, and if
 * that ever loosened to accept data:/javascript:/../ it would be a stored-XSS or
 * path-traversal hole rendered straight into an <img>/<a href>. This asserts it
 * stays strict.
 *
 *   node scripts/smoke_frontend_web.js
 *
 * Exit 0 = pass, 1 = a failed assertion (all are reported). jsdom has no layout,
 * so glyph legibility and the gallery grid still owe one real browser pass.
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

const SITES = [
  { id: 'e1', url: 'https://10.0.0.5:8443/login', title: 'iDRAC Login', resolved: '10.0.0.5',
    category: 'idrac', default_creds: '(Dell iDRAC) root/calvin', has_default_creds: true,
    is_high_value: true, screenshot_url: '/screenshots/sk1/10.0.0.5_8443_login.png',
    has_screenshot: true, protocol: 'https', port: '8443', active: true,
    request_status: 'Successful', source: 'eyewitness' },
  { id: 'e2', url: 'http://host9.corp.local/', title: '', resolved: '10.0.0.9',
    category: '', default_creds: '', has_default_creds: false, is_high_value: false,
    screenshot_url: '', has_screenshot: false, protocol: 'http', port: '80', active: false,
    request_status: 'Timeout', source: 'eyewitness' },
];
const STATS = { total: 2, with_screenshot: 1, with_default_creds: 1, high_value: 1, active: 1,
                by_category: { idrac: 1, uncategorized: 1 } };

function cards() { return [...d.querySelectorAll('#web-res .web-card')]; }

setTimeout(() => {
  console.log('WEB tab — gallery, filters, screenshot URL guard, detail modal');

  /* ── modal CSS wiring ────────────────────────────────────────────────────
     .hidden is NOT a global utility in this file — each overlay names its own
     `#id.hidden { display:none }` and its own `#id { position:fixed;inset:0 }`.
     A new modal left out of BOTH renders as a static full-width block from page
     load that × / CLOSE cannot dismiss (it happened to #web-dm). jsdom has no
     layout, so this is asserted against the stylesheet text, not computed style. */
  section('modal CSS wiring (#web-dm must share the overlay rules)');
  const rawHtml = fs.readFileSync(INDEX, 'utf8');
  ok(/#web-dm\.hidden/.test(rawHtml),
     '#web-dm is wired into a `.hidden { display:none }` rule (else un-closable)');
  ok(/#web-dm\s*[,{][^}]*position:\s*fixed|#dev-dm,\s*#agt-dm,\s*#web-dm/.test(rawHtml),
     '#web-dm shares the fixed-overlay rule with #dev-dm/#agt-dm');

  /* ── safeShotUrl: the security-relevant helper ───────────────────────── */
  section('safeShotUrl');
  ok(w.safeShotUrl('/screenshots/sk1/a.png') === '/screenshots/sk1/a.png',
     'accepts a same-origin /screenshots/ PNG path');
  ok(w.safeShotUrl('/screenshots/sk-1/a_b.JPEG') === '/screenshots/sk-1/a_b.JPEG',
     'accepts jpeg/webp and mixed case');
  ok(w.safeShotUrl('/screenshots/sk1/../../etc/passwd') === null,
     'rejects path traversal (..)');
  ok(w.safeShotUrl('https://evil.example/x.png') === null,
     'rejects an absolute http(s) URL (not same-origin)');
  ok(w.safeShotUrl('data:image/png;base64,AAAA') === null,
     'rejects a data: URI');
  ok(w.safeShotUrl('/screenshots/sk1/a.txt') === null,
     'rejects a non-image extension');
  ok(w.safeShotUrl('/other/a.png') === null,
     'rejects a path outside /screenshots/');

  /* ── render the gallery ──────────────────────────────────────────────── */
  section('gallery render');
  w.eval(`_webCache = { sites: ${JSON.stringify(SITES)}, stats: ${JSON.stringify(STATS)}, ts: Date.now() };
          _webFilter = 'all'; _webSearch = '';`);
  w.renderWeb();

  ok(cards().length === 2, 'renders one card per endpoint', cards().length);

  const stat0 = d.querySelector('#web-stats .ti-stat .ti-sv');
  ok(stat0 && stat0.textContent.trim() === '2', 'stats row shows the endpoint count', stat0 && stat0.textContent);

  const c0 = cards()[0];
  ok(c0 && c0.textContent.includes('10.0.0.5:8443'), 'first card shows the iDRAC URL');
  ok(c0 && c0.querySelector('.web-hv'), 'high-value endpoint carries the ★ high-value badge');
  ok(c0 && c0.querySelector('.web-cr'), 'default-cred endpoint carries the creds badge');
  const img0 = c0 && c0.querySelector('img.web-thumb');
  ok(img0 && img0.getAttribute('src') === '/screenshots/sk1/10.0.0.5_8443_login.png',
     'the thumbnail <img> points at the served screenshot', img0 && img0.getAttribute('src'));

  const c1 = cards()[1];
  ok(c1 && c1.querySelector('.web-thumb-none') && !c1.querySelector('img'),
     'the screenshot-less endpoint shows a placeholder, not a broken <img>');

  /* ── FQDN beside the resolved IP ─────────────────────────────────────────
     A website's FQDN is the host portion of its own URL (derived client-side,
     no backend). It shows only when it is a real hostname distinct from the IP. */
  ok(c0 && !c0.querySelector('.web-fqdn'),
     'an IP-host URL shows no FQDN chip (it would just duplicate the IP)');
  const fq1 = c1 && c1.querySelector('.web-fqdn');
  ok(fq1 && fq1.textContent.trim() === 'host9.corp.local',
     'a hostname URL shows its FQDN beside the resolved IP', fq1 && fq1.textContent);
  ok(c1 && c1.textContent.includes('10.0.0.9'),
     'the resolved IP still shows alongside the FQDN');

  /* ── filters ─────────────────────────────────────────────────────────── */
  section('filters');
  w.setWebFilter('screenshot');
  ok(cards().length === 1 && cards()[0].querySelector('img.web-thumb'),
     'Screenshots filter shows only endpoints with an image', cards().length);
  w.setWebFilter('highvalue');
  ok(cards().length === 1 && cards()[0].querySelector('.web-hv'),
     'High-value filter shows only high-value endpoints', cards().length);
  w.setWebFilter('creds');
  ok(cards().length === 1 && cards()[0].querySelector('.web-cr'),
     'Default-creds filter shows only endpoints with a cred hit', cards().length);
  w.setWebFilter('all');
  ok(cards().length === 2, 'All filter restores the full list', cards().length);

  /* ── search ──────────────────────────────────────────────────────────── */
  section('search');
  w.searchWeb('corp.local');
  ok(cards().length === 1 && cards()[0].textContent.includes('host9.corp.local'),
     'search matches the FQDN derived from the URL host', cards().length);
  w.searchWeb('10.0.0.9');
  ok(cards().length === 1 && cards()[0].textContent.includes('host9.corp.local'),
     'search matches the resolved IP', cards().length);
  w.searchWeb('idrac');
  ok(cards().length === 1 && cards()[0].textContent.includes('10.0.0.5'),
     'search matches the category', cards().length);
  w.searchWeb('');

  /* ── detail modal ────────────────────────────────────────────────────── */
  section('detail modal');
  w.setWebFilter('all');
  const modal = d.getElementById('web-dm');
  ok(modal.classList.contains('hidden'), 'modal starts hidden');
  w.openWebDetail(0);
  ok(!modal.classList.contains('hidden'), 'openWebDetail reveals the modal');
  ok(d.getElementById('webdm-url').textContent === 'https://10.0.0.5:8443/login',
     'modal header shows the endpoint URL');
  const shot = d.querySelector('#webdm-body img.web-shot');
  ok(shot && shot.getAttribute('src') === '/screenshots/sk1/10.0.0.5_8443_login.png',
     'modal shows the full screenshot', shot && shot.getAttribute('src'));
  ok(d.getElementById('webdm-body').textContent.includes('root/calvin'),
     'modal surfaces the identified default credentials');
  w.closeWebDetail();
  ok(modal.classList.contains('hidden'), 'closeWebDetail hides the modal again');

  // A screenshot-less endpoint must not fabricate an image in the modal.
  w.openWebDetail(1);
  ok(!d.querySelector('#webdm-body img.web-shot'),
     'a screenshot-less endpoint shows no <img> in the modal');
  ok(d.getElementById('webdm-body').textContent.includes('host9.corp.local'),
     'modal surfaces the FQDN derived from the URL');
  ok(d.getElementById('webdm-host').textContent.includes('host9.corp.local'),
     'modal subtitle shows the FQDN');
  w.closeWebDetail();

  console.log(`\n${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 1200);
