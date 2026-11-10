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
ok(d.getElementById('aclone-deobf-timeout') && d.getElementById('aclone-deobf-timeout').value === '180',
   'form deobfuscation timeout default is 180s', d.getElementById('aclone-deobf-timeout') && d.getElementById('aclone-deobf-timeout').value);

section('options round-trip');
const edited = { ...def, maxDepth: 3, maxTime: 120, robots: false, external: 'same_registrable', includeImages: false, deobfuscate: false, deobfuscateTimeout: 90 };
w.acloneWriteOptions(edited);
const read = w.acloneReadOptions();
ok(read.maxDepth === 3 && read.maxTime === 120, 'numeric options survive a write/read', JSON.stringify(read));
ok(read.robots === false && read.includeImages === false && read.external === 'same_registrable',
   'toggles and external mode survive a write/read', JSON.stringify(read));
ok(read.deobfuscate === false && read.deobfuscateTimeout === 90,
   'deobfuscate toggle and timeout survive a write/read', JSON.stringify(read));

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

section('domain recon CTA');
ok(!!d.getElementById('dr-clone-active'), 'Domain Recon has Clone in Active button');
ok(typeof w.acloneSendFromDomainRecon === 'function', 'acloneSendFromDomainRecon is defined');
ok(typeof w.acloneSendSelectedAssets === 'function', 'acloneSendSelectedAssets is defined');

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${checks - failures}/${checks} checks`);
process.exit(failures ? 1 : 0);
