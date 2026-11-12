#!/usr/bin/env node
/*
 * Headless smoke test for the Active tab and Site Clone UI.
 *
 *   node scripts/smoke_frontend_active.js
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

function setupCampaign(extra) {
  w.localStorage.clear();
  const camp = {
    id: 'camp-1', name: 'Smoke', sketchId: 'sk-1', created: '2026-01-01T00:00:00Z',
    objectives: w.objDefaults(), activeJobs: [],
    ...(extra || {}),
  };
  w.localStorage.setItem('s.campaigns', JSON.stringify([camp]));
  w.localStorage.setItem('s.activeCamp', JSON.stringify(camp));
  return camp;
}

section('tab wiring');
ok(!!d.getElementById('tb-active'), 'Active tab button exists');
ok(!!d.getElementById('pnl-active'), 'Active panel exists');
ok(typeof w.sw === 'function' && typeof w.acloneDefaults === 'function',
   'sw() and acloneDefaults() are defined');
setupCampaign();
w.sw('active');
ok(d.getElementById('tb-active').classList.contains('on'), 'sw("active") selects the tab');
ok(d.getElementById('pnl-active').classList.contains('on'), 'sw("active") shows the panel');
ok(!d.getElementById('tb-targets').classList.contains('on'), 'other tabs are deselected');

section('defaults');
const def = w.acloneDefaults();
ok(def.maxDepth === 2 && def.maxTime === 300 && def.connectTimeout === 20,
   'default depth 2, connect 20s, max time 300s', JSON.stringify(def));
ok(def.sameHost === true && def.robots === true && def.external === 'none',
   'default stay-on-host, follow robots, no externals');
ok(def.includeImages && def.includeJs && def.includeCss && def.includeOther && def.respectOpsec,
   'default includes images/js/css/other and respects OPSEC');
ok(def.deobfuscate === true && def.deobfuscateTimeout === 180,
   'default deobfuscates JavaScript with a 180s timeout', JSON.stringify({d: def.deobfuscate, t: def.deobfuscateTimeout}));
ok(d.getElementById('aclone-depth').value === '2', 'form max depth default is 2', d.getElementById('aclone-depth').value);
ok(d.getElementById('aclone-robots').checked, 'form follow-robots is checked');
ok(d.getElementById('aclone-opsec').checked, 'form respect-OPSEC is checked');
ok(d.getElementById('aclone-deobf') && d.getElementById('aclone-deobf').checked,
   'form Deobfuscate JavaScript is checked');
ok(d.getElementById('aclone-ocr') && d.getElementById('aclone-ocr').checked,
   'form OCR images is checked');
ok(def.ocrImages === true, 'defaults.ocrImages is true');
ok(d.getElementById('aclone-docker-dns') && !d.getElementById('aclone-docker-dns').checked,
   'form Allow Docker DNS (leaks lookups) is present and unchecked');
ok(def.allowDockerDns === false, 'defaults.allowDockerDns is false');
ok(d.getElementById('aclone-deobf-timeout') && d.getElementById('aclone-deobf-timeout').value === '180',
   'form deobfuscation timeout default is 180s', d.getElementById('aclone-deobf-timeout') && d.getElementById('aclone-deobf-timeout').value);

section('options round-trip');
const edited = { ...def, maxDepth: 3, maxTime: 120, robots: false, external: 'same_registrable', includeImages: false, deobfuscate: false, deobfuscateTimeout: 90, ocrImages: false };
w.acloneWriteOptions(edited);
const read = w.acloneReadOptions();
ok(read.maxDepth === 3 && read.maxTime === 120, 'numeric options survive a write/read', JSON.stringify(read));
ok(read.robots === false && read.includeImages === false && read.external === 'same_registrable',
   'toggles and external mode survive a write/read', JSON.stringify(read));
ok(read.deobfuscate === false && read.deobfuscateTimeout === 90,
   'deobfuscate toggle and timeout survive a write/read', JSON.stringify(read));
ok(read.ocrImages === false, 'OCR images toggle survives a write/read', JSON.stringify(read));
w.acloneWriteOptions({ ...def, allowDockerDns: true });
ok(w.acloneReadOptions().allowDockerDns === true,
   'allowDockerDns survives a write/read');
w.acloneWriteOptions(def);
ok(!d.getElementById('aclone-docker-dns').checked,
   'writing defaults clears the Docker DNS override');

section('send to Active');
setupCampaign({
  objectives: {
    ...w.objDefaults(),
    targetType: 'organization',
    targetName: 'Example Corp',
    companyEmail: 'ops@example.com',
    organizations: [{ name: 'Partner', domains: 'partner.test', urls: 'https://careers.partner.test', emails: '', tech: '', notes: '' }],
  },
});
w.acloneSend('example.com', 'test');
ok(d.getElementById('tb-active').classList.contains('on'), 'acloneSend switches to the Active tab');
ok((d.getElementById('aclone-url').value || '').indexOf('example.com') !== -1,
   'URL input is filled', d.getElementById('aclone-url').value);

setupCampaign({
  objectives: {
    ...w.objDefaults(),
    organizations: [{ name: 'Partner', domains: 'partner.test', urls: 'https://careers.partner.test', emails: '', tech: '', notes: '' }],
  },
});
w.sw('objectives');
const sendBtn = [...d.querySelectorAll('[data-obj-org] button')].find(b => /Active/i.test(b.textContent || ''));
ok(!!sendBtn, 'org card has Send URLs to Active', sendBtn && sendBtn.textContent);
if (sendBtn) sendBtn.click();
ok((d.getElementById('aclone-url').value || '').indexOf('partner.test') !== -1,
   'org-card send fills a URL from the card', d.getElementById('aclone-url').value);

section('job persistence + export allowlist');
setupCampaign();
w.acloneSaveJobs([{
  id: 'sc-1', url: 'https://example.com', status: 'done',
  finding_count: 4, summary: { email: 2 }, findings: [{ category: 'email', value: 'a@b.c', severity: 'medium', source_path: 'index.html' }],
}]);
const reloaded = JSON.parse(w.localStorage.getItem('s.campaigns'))[0];
ok(Array.isArray(reloaded.activeJobs) && reloaded.activeJobs[0].id === 'sc-1',
   'jobs persist on the campaign record');
ok(reloaded.activeJobs[0].findings[0].value === 'a@b.c', 'finding values survive save');
const normed = w.acloneNormaliseJobs([{ id: 'x', url: 'https://a.test', status: 'queued', secret: 'nope', junk: 1, warnings: ['webcrack skipped'], deobfuscation: { tool: 'webcrack' } }]);
ok(normed.length === 1 && !('secret' in normed[0]) && !('junk' in normed[0]),
   'normaliser drops unknown fields', JSON.stringify(normed[0]));
ok(normed[0].warnings && normed[0].warnings[0] === 'webcrack skipped' && normed[0].deobfuscation.tool === 'webcrack',
   'normaliser keeps warnings and deobfuscation status', JSON.stringify(normed[0]));

section('DNS label on the job card');
setupCampaign();
w.sw('active');
w.acloneSaveJobs([{
  id: 'sc-dns-tor', url: 'https://example.com', status: 'running',
  dns: { label: 'via TOR', via: 'tor', resolver: 'TOR ssh-tunnel-api:9050' },
}]);
w.acloneRender();
const cardTor = d.querySelector('.aclone-job[data-job="sc-dns-tor"]');
ok(cardTor && /DNS:\s*via TOR/.test(cardTor.textContent || ''),
   'job card renders DNS: via TOR', cardTor && cardTor.textContent);
w.acloneSaveJobs([{
  id: 'sc-dns-ip', url: 'https://example.com', status: 'done',
  dns: { label: '77.88.8.8', via: 'resolver', resolver: '77.88.8.8' },
}]);
w.acloneRender();
const cardIp = d.querySelector('.aclone-job[data-job="sc-dns-ip"]');
ok(cardIp && /DNS:\s*77\.88\.8\.8/.test(cardIp.textContent || ''),
   'job card renders DNS: 77.88.8.8', cardIp && cardIp.textContent);
w.acloneSaveJobs([{
  id: 'sc-dns-ov', url: 'https://example.com', status: 'queued',
  dns: { label: 'Docker (override)', via: 'docker_override' },
}]);
w.acloneRender();
const cardOv = d.querySelector('.aclone-job[data-job="sc-dns-ov"]');
ok(cardOv && /DNS:\s*Docker \(override\)/.test(cardOv.textContent || ''),
   'job card renders DNS: Docker (override)', cardOv && cardOv.textContent);
const normDns = w.acloneNormaliseJobs([
  { id: 'x', url: 'https://a.test', status: 'queued', dns: { label: 'via SOCKS5', via: 'socks5' }, leak: 1 },
]);
ok(normDns[0].dns && normDns[0].dns.label === 'via SOCKS5' && !('leak' in normDns[0]),
   'normaliser keeps dns and still drops unknown fields', JSON.stringify(normDns[0]));

section('Prompt index label on the job card');
setupCampaign();
w.sw('active');
w.acloneSaveJobs([{
  id: 'sc-rag', url: 'https://example.com', status: 'done',
  ingested: { ok: true, written: 2, site_rag: { ok: true, chunks_indexed: 7, pages: 3, collection: 'company_site__sk-1' } },
}]);
w.acloneRender();
const cardRag = d.querySelector('.aclone-job[data-job="sc-rag"]');
ok(cardRag && /Prompt:\s*7 chunks/.test(cardRag.textContent || ''),
   'job card renders Prompt: 7 chunks', cardRag && cardRag.textContent);
w.acloneShowFindings('sc-rag');
const findings = d.getElementById('aclone-findings');
ok(findings && /Prompt index: 7 chunk/.test(findings.textContent || ''),
   'findings pane names the Prompt index', findings && findings.textContent);

section('candidate URLs from multi-org objectives');
setupCampaign({
  objectives: {
    ...w.objDefaults(),
    targetType: 'organization',
    targetName: 'Primary',
    companyEmail: 'it@primary.test',
    additionalIds: 'https://intranet.primary.test',
    organizations: [{ name: 'Sub', domains: 'sub.primary.test', urls: '', emails: '', tech: '', notes: '' }],
  },
});
const cands = w.acloneCandidateUrls();
ok(cands.some(u => u.indexOf('primary.test') !== -1), 'includes company-email domain', cands);
ok(cands.some(u => u.indexOf('intranet.primary.test') !== -1), 'includes additional identifier URL', cands);
ok(cands.some(u => u.indexOf('sub.primary.test') !== -1), 'includes additional org domain', cands);

section('View source on recovered findings');
setupCampaign();
w.sw('active');
ok(!!d.getElementById('aclone-src-modal'), 'View source dialog is in the page');
ok(typeof w.acloneCanViewSource === 'function' && typeof w.acloneViewSource === 'function',
   'View source helpers are defined');
ok(w.acloneCanViewSource({ source_path: 'deobf/js/app.js', deobfuscated: true }),
   'deobfuscated findings can be opened');
ok(w.acloneCanViewSource({ source_path: 'ocr/example.com/banner.png.txt', ocr: true }),
   'OCR findings can be opened');
ok(w.acloneCanViewSource({ source_path: 'deobf/sourcemaps/js/hidden.js' }),
   'sourcemap paths can be opened');
ok(!w.acloneCanViewSource({ source_path: 'index.html', category: 'email' }),
   'raw HTML findings do not get View source');
w.acloneSaveJobs([{
  id: 'sc-src', url: 'https://example.com', status: 'done',
  ingested: { ok: true, written: 4, endpoints: 2 },
  findings: [
    { category: 'js_endpoint', severity: 'medium', value: 'https://api.example.com/v1',
      source_path: 'deobf/js/app.js', source_line: 4, deobfuscated: true, deobfuscator: 'webcrack',
      evidence: "const api_base = 'https://api.example.com/v1'" },
    { category: 'email', severity: 'medium', value: '<script>alert(1)</script>@evil.test',
      source_path: 'index.html' },
  ],
}]);
w.acloneRender();
w.acloneShowFindings('sc-src');
const findingsSrc = d.getElementById('aclone-findings');
ok(findingsSrc && /2 endpoints/.test(findingsSrc.textContent || ''),
   'findings pane names ingested endpoints', findingsSrc && findingsSrc.textContent);
const viewBtn = findingsSrc && findingsSrc.querySelector('.aclone-src-btn');
ok(viewBtn && viewBtn.getAttribute('data-path') === 'deobf/js/app.js'
   && viewBtn.getAttribute('data-line') === '4',
   'View source is offered on the recovered JS finding', viewBtn && viewBtn.outerHTML);
ok(findingsSrc && findingsSrc.querySelectorAll('.aclone-src-btn').length === 1,
   'View source is only offered on recovered sources');
ok(findingsSrc && findingsSrc.innerHTML.indexOf('<script>alert(1)</script>') === -1
   && findingsSrc.innerHTML.indexOf('&lt;script&gt;') !== -1,
   'finding values are escaped and not executed', findingsSrc && findingsSrc.innerHTML);

const srcCalls = [];
const origFetchJson = w.fetchJson;
w.fetchJson = async function (url, opts) {
  srcCalls.push({ url, body: JSON.parse((opts && opts.body) || '{}') });
  return {
    ok: true, path: 'deobf/js/app.js', start_line: 3, end_line: 5, focus_line: 4,
    text: "const other = 2;\nconst api_base = 'https://api.example.com/v1';\nconst tail = 3;",
  };
};
section('domain recon CTA');
ok(!!d.getElementById('dr-clone-active'), 'Domain Recon has Clone in Active button');
ok(typeof w.acloneSendFromDomainRecon === 'function', 'acloneSendFromDomainRecon is defined');
ok(typeof w.acloneSendSelectedAssets === 'function', 'acloneSendSelectedAssets is defined');

(async () => {
  // Finish the View source click after helpers above stubbed fetchJson.
  // If the stub is still in place from the previous section, reuse it;
  // otherwise this is a no-op when the button or stub is missing.
  if (typeof origFetchJson !== 'undefined' && d.querySelector('.aclone-src-btn')) {
    try {
      await w.acloneViewSource(d.querySelector('.aclone-src-btn'));
      const modal = d.getElementById('aclone-src-modal');
      const pre = d.getElementById('aclone-src-content');
      const meta = d.getElementById('aclone-src-meta');
      ok(modal && !modal.classList.contains('hidden'), 'View source dialog opens');
      ok(srcCalls[0] && srcCalls[0].body && srcCalls[0].body.action === 'source'
         && srcCalls[0].body.path === 'deobf/js/app.js'
         && srcCalls[0].body.job_id === 'sc-src',
         'View source posts action=source to the site-clone webhook',
         srcCalls[0]);
      ok(pre && pre.textContent.indexOf('api.example.com/v1') !== -1
         && pre.querySelector('.aclone-src-focus'),
         'dialog shows the snippet as text with the focus line marked',
         pre && pre.innerHTML);
      ok(pre && pre.querySelectorAll('script').length === 0,
         'recovered source is not inserted as a script element');
      ok(meta && /never executed/.test(meta.textContent || ''),
         'dialog states the snippet is not executed', meta && meta.textContent);
      w.acloneCloseSource();
      ok(modal.classList.contains('hidden'), 'View source dialog can be closed');
      const cssText = [...d.styleSheets].flatMap((sheet) => {
        try { return [...sheet.cssRules].map((r) => r.cssText || ''); }
        catch (e) { return []; }
      }).join('\n');
      ok(/#aclone-src-modal\.hidden/.test(cssText) && /display:\s*none/.test(cssText),
         'View source modal CSS hides #aclone-src-modal.hidden with display:none');
      ok(w.getComputedStyle(modal).display === 'none',
         'closed View source modal is actually display:none (not a stuck overlay)',
         w.getComputedStyle(modal).display);

      await w.acloneViewSource(d.querySelector('.aclone-src-btn'));
      ok(!modal.classList.contains('hidden') && w.getComputedStyle(modal).display !== 'none',
         'View source modal is visible after reopen');
      const xBtn = modal.querySelector('.ilm-close');
      ok(!!xBtn, 'View source modal has an X close button');
      xBtn.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
      ok(modal.classList.contains('hidden') && w.getComputedStyle(modal).display === 'none',
         'X button closes the View source modal');

      await w.acloneViewSource(d.querySelector('.aclone-src-btn'));
      d.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      ok(modal.classList.contains('hidden') && w.getComputedStyle(modal).display === 'none',
         'Escape closes the View source modal');

      await w.acloneViewSource(d.querySelector('.aclone-src-btn'));
      modal.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
      ok(modal.classList.contains('hidden') && w.getComputedStyle(modal).display === 'none',
         'clicking the backdrop closes the View source modal');
    } finally {
      w.fetchJson = origFetchJson;
    }
  }

  section('unregistered site-clone webhook');
  const origFetch = w.fetch;
  async function withFetch(status, body, contentType, requestUrl) {
    w.fetch = async () => ({
      status,
      ok: status >= 200 && status < 300,
      headers: { get: (k) => (String(k).toLowerCase() === 'content-type' ? contentType : null) },
      text: async () => body,
    });
    try {
      return await w.fetchJson(requestUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'start', url: 'https://example.com' }),
      });
    } finally {
      w.fetch = origFetch;
    }
  }
  const siteUrl = 'http://localhost:8080/webhook/site-clone';
  try {
    await withFetch(404, JSON.stringify({
      code: 404,
      message: 'The requested webhook "POST site-clone" is not registered.',
    }), 'application/json', siteUrl);
    ok(false, 'JSON 404 unregistered site-clone should throw');
  } catch (e) {
    ok(/Site Clone workflow not active/.test(e.message)
       && /32-site-clone\.json/.test(e.message)
       && /deploy_workflow\.sh/.test(e.message),
       'JSON 404 unregistered site-clone names WF32 and the deploy command',
       e && e.message);
  }
  try {
    await withFetch(500,
      '<html><head><title>Error</title></head><body>The requested webhook "POST site-clone" is not registered.</body></html>',
      'text/html', siteUrl);
    ok(false, 'HTML 500 unregistered site-clone should throw');
  } catch (e) {
    ok(/Site Clone workflow not active/.test(e.message),
       'HTML 500 with not-registered text names WF32', e && e.message);
  }
  try {
    await withFetch(500,
      '<html><head><title>Error</title></head><body><pre>Internal Server Error</pre></body></html>',
      'text/html', siteUrl);
    ok(false, 'generic HTML 500 on site-clone should throw');
  } catch (e) {
    ok(/Site Clone workflow not active/.test(e.message),
       'generic HTML 500 on site-clone is treated as an unregistered WF32',
       e && e.message);
  }
  try {
    await withFetch(500,
      '<html><head><title>Error</title></head><body><pre>Internal Server Error</pre></body></html>',
      'text/html', 'http://localhost:8080/webhook/create-sketch');
    ok(false, 'generic HTML 500 on another webhook should throw');
  } catch (e) {
    ok(/n8n workflow crashed/.test(e.message)
       && !/Site Clone workflow not active/.test(e.message),
       'generic HTML 500 on another webhook still reports a crash',
       e && e.message);
  }

  console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${checks - failures}/${checks} checks`);
  process.exit(failures ? 1 : 0);
})();
