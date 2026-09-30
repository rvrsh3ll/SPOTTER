#!/usr/bin/env node
/*
 * Headless smoke test for the "False Positive" (FP) result mark.
 *
 * Why this exists
 * ---------------
 * FP is the FOURTH operator mark and the second that EXCLUDES rather than
 * annotates. It is applied from the Live Analysis card — the one place an operator
 * reads machine-scored results and previously had no way to push back — and it must
 * genuinely remove the result: from the card and its "+N more" drilldown, from every
 * other surface that shows the same entity, from the exports, from every chat tool,
 * and (server-side, in WF10) from the next analysis run.
 *
 * The invariants this pins, in order:
 *
 *   A. The card renders exactly one FP chip per row on all four markable row kinds,
 *      carrying the right namespace and key — including a name with an apostrophe,
 *      which is why the key rides in a data attribute rather than the handler.
 *   B. Marking hides the row and the card header discloses the count.
 *   C. The DRILLDOWN is filtered too, and its "of N" total is adjusted. This is the
 *      easy bug: each row renderer's HTML is re-emitted into the overflow modal, so
 *      filtering only the painted slice leaves the hidden row one click away.
 *   D. Revealing restores the row struck-through with the chip reading ON.
 *   E. Globality — one fact, five surfaces: Targets (People + Assets), Web tab,
 *      Domain Recon buckets, Worst Hosts, and the roster export.
 *   F. Case folding. FP folds (OoS deliberately does not), and clearing must remove
 *      every spelling or a differently-cased twin keeps the row hidden.
 *   G. Chat context: the FP'd name reaches NO tool. The same six assertions run for
 *      an OoS entity, which is where the pre-2026-09-07 leaks through get_analysis /
 *      get_osint_recon / get_tech_intel / get_vulnerabilities get pinned shut.
 *   H. spotterDataInventory() counts are post-exclusion and the new
 *      "Operator exclusions" item reports the shortfall.
 *   I. buildAnalysisReport() drops the rows and says so in its meta.
 *   J. runAnalysis() ships both false_positive buckets to WF10.
 *   K. Scenario marks are record-scoped and die with their record.
 *
 *   node scripts/smoke_frontend_fp.js
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

const CAMP = { id: 'fp-test', name: 'FPTest', sketchId: 'sk-fp' };
const APOS = "Sean O'Brien";

/* The analysis card gates on the active campaign, and campSuffix() keys every store
   off it — so unlike the OoS test this one must set a campaign before anything. */
function setCampaign() {
  w.localStorage.setItem('s.campaigns', JSON.stringify([CAMP]));
  w.localStorage.setItem('s.activeCamp', JSON.stringify(CAMP));   // the whole object, not an id
}

function analysisRecord(over) {
  return Object.assign({
    id: 'rec1', campaignId: CAMP.id, campaignName: CAMP.name,
    timestamp: '2026-09-07T10:00:00.000Z', status: 'under-review',
    individualsCount: 300,
    targets: [
      { name: 'Alice Admin', score: 90, rationale: 'DA' },
      { name: APOS,          score: 80, rationale: 'admin' },
      ...Array.from({ length: 10 }, (_, i) => ({ name: `Filler ${i}`, score: 50 - i, rationale: 'x' })),
    ],
    targetsTotal: 500,
    deviceTargets: [
      { name: 'DC01.CORP.LOCAL', score: 60, os: 'Windows', sessions: 2,
        session_users: [{ name: 'Alice Admin', score: 90 }, { name: 'Bob User', score: 10 }] },
      { name: 'WS02', score: 20, os: 'Windows' },
    ],
    deviceTargetsTotal: 40,
    attackSurface: [
      { type: 'CloudAsset', label: 'example-logs', keys: ['example-logs', 'example-logs.s3.amazonaws.com'],
        owners: ['Alice Admin'], vulns: [] },
      { type: 'WebAsset', label: 'blog.example.com',
        keys: ['blog.example.com', 'https://blog.example.com'], owners: [], vulns: [] },
    ],
    scenarios: [
      { id: 'SCENARIO-1', name: 'Kerberoast to DA', chain: 'a→b', difficulty: 'medium', techniques: ['T1558'] },
      { id: 'SCENARIO-2', name: 'Phish the helpdesk', chain: 'c→d', difficulty: 'low', techniques: ['T1566'] },
    ],
    breachIntel:     [{ name: 'Alice Admin', breach_count: 2 }],
    credentialIntel: [{ name: 'Alice Admin', cred_count: 1 }],
  }, over || {});
}

function renderCard(rec) {
  w.localStorage.setItem('s.analyses', JSON.stringify([rec || analysisRecord()]));
  w.renderAnalysisList();
}
function cardHtml() { return d.getElementById('analysis-list').innerHTML; }
function chips() { return [...d.querySelectorAll('#analysis-list .an-mk')]; }
function chipFor(key) { return chips().find(c => c.dataset.fpk === key) || null; }
function rowTextIncludes(s) { return cardHtml().includes(s); }
function anMeta() { const e = d.querySelector('#analysis-list .an-meta'); return e ? e.textContent : ''; }

/* The "+N more" chip registers its full item list in the _OVF map; read it back to
   prove the drilldown carries the same filtered set the card painted. */
function ovfSpecFor(title) {
  const ids = [...d.querySelectorAll('#analysis-list [data-ovf-open]')].map(e => e.dataset.ovfOpen);
  for (const id of ids) {
    const spec = w.eval(`_OVF.get(${JSON.stringify(id)})`);
    if (spec && spec.title === title) return spec;
  }
  return null;
}
function ovfLabelFor(title) {
  const el = [...d.querySelectorAll('#analysis-list [data-ovf-open]')]
    .find(e => { const s = w.eval(`_OVF.get(${JSON.stringify(e.dataset.ovfOpen)})`); return s && s.title === title; });
  return el ? el.textContent : '';
}

function renderPeople(list) {
  w.eval(`_targetsView='individuals';
          _targetsCache=${JSON.stringify({ list, assets: [], deviceDossier: {}, dossierTotal: list.length, assetTotal: 0, listCap: 0, ts: 1 })};`);
  w.renderTargetsView();
}
function renderAssets(assets) {
  w.eval(`_targetsView='assets';
          _targetsCache=${JSON.stringify({ list: [], assets, deviceDossier: {}, dossierTotal: 0, assetTotal: assets.length, listCap: 0, ts: 1 })};`);
  w.renderTargetsView();
}
function rowByLabel(label) {
  const cb = [...d.querySelectorAll('#tres .trow-cb')].find(c => c.dataset.label === label);
  return cb ? cb.closest('tr') : null;
}

function clearMarks() {
  w.saveFPTargets({}); w.saveDevFPTargets({}); w.saveFPScenarios({});
  w.saveOOSTargets({}); w.saveDevOOSTargets({});
  w.setShowFP(false); w.setShowOOS(false);
}

setTimeout(async () => {
  console.log('Live Analysis — False Positive (FP) mark');
  setCampaign();
  clearMarks();

  /* ── A. chips render on all four row kinds ───────────────────────────────── */
  section('A · the chip renders on every markable row kind');
  renderCard();
  const nsFor = k => { const c = chipFor(k); return c ? c.dataset.fpns : null; };
  ok(nsFor('Alice Admin') === 'people', 'High-Value Target row carries a people-namespace FP chip', nsFor('Alice Admin'));
  ok(nsFor('DC01.CORP.LOCAL') === 'assets', 'High-Value System row carries an assets-namespace FP chip', nsFor('DC01.CORP.LOCAL'));
  const surfChip = chips().find(c => c.dataset.fpmulti && String(c.dataset.fpk).includes('example-logs'));
  ok(!!surfChip, 'Attack Surface row carries a chip');
  ok(surfChip && surfChip.dataset.fpns === 'assets', 'the Attack Surface chip is assets-namespace');
  let surfKeys = [];
  try { surfKeys = JSON.parse(surfChip.dataset.fpk); } catch {}
  ok(surfKeys.length === 2 && surfKeys.includes('example-logs.s3.amazonaws.com'),
     'the Attack Surface chip carries the whole alias set WF10 shipped, not just the label', JSON.stringify(surfKeys));
  const scenChip = chips().find(c => c.dataset.fpns === 'scenario');
  ok(!!scenChip, 'a scenario block carries a scenario-namespace chip');
  ok(scenChip && scenChip.dataset.fpk.startsWith('rec1|0|SCENARIO-1'),
     'the scenario key is record-scoped (recordId|index|llmId)', scenChip && scenChip.dataset.fpk);
  ok(chipFor(APOS) !== null, `an apostrophe'd name survives into dataset.fpk intact`);
  ok(!cardHtml().includes(`fpk="Sean O'Brien"` .replace("O'B", 'O&#39;B')),
     'the key is not injected into an inline handler string');

  /* ── B. marking hides the row, header discloses ──────────────────────────── */
  section('B · marking hides the row and the card says so');
  w.toggleAnalysisFP('people', 'Alice Admin', null);
  ok(!!w.getFPTargets()['Alice Admin'], 'the mark landed in s.fp_targets');
  ok(chipFor('Alice Admin') === null, 'the target row is gone from the card');
  ok(rowTextIncludes(APOS), 'the other targets still render');
  ok(/1 hidden \(1 false positive\)/.test(anMeta()), 'the card header discloses the hidden count', anMeta());

  w.toggleAnalysisFP('assets', 'WS02', null);
  ok(!rowTextIncludes('WS02'), 'a marked High-Value System is gone');
  w.toggleAnalysisFP('scenario', scenChip.dataset.fpk, null);
  ok(!rowTextIncludes('Kerberoast to DA'), 'a marked scenario block is gone');
  ok(rowTextIncludes('Phish the helpdesk'), 'the other scenario still renders');

  /* ── C. the drilldown is filtered, and its total is adjusted ─────────────── */
  section('C · the "+N more" drilldown is filtered too');
  const spec = ovfSpecFor('High-Value Targets');
  ok(!!spec, 'the targets overflow chip is registered');
  ok(spec && spec.items.length === 11, 'the drilldown carries 11 of 12 targets — the FP one is not one click away',
     spec && spec.items.length);
  ok(spec && !JSON.stringify(spec.items).includes('Alice Admin'),
     'the FP target appears nowhere in the drilldown items');
  const lbl = ovfLabelFor('High-Value Targets');
  ok(/of 49[0-9]/.test(lbl) && !/of 500/.test(lbl),
     'the chip total subtracts the exclusions rather than blaming WF10\'s rank clip', lbl);
  ok(spec && /false positive/.test(spec.subtitle || ''),
     'the drilldown subtitle names the operator exclusion', spec && spec.subtitle);
  const devSpecTitle = 'High-Value Systems — AD computers';
  const dspec = ovfSpecFor(devSpecTitle);
  ok(dspec === null || !JSON.stringify(dspec.items).includes('WS02'),
     'the systems drilldown also excludes its FP row');

  /* ── D. reveal ───────────────────────────────────────────────────────────── */
  section('D · reveal restores the row, struck through, chip ON');
  w.setShowFP(true);
  w.renderAnalysisList();
  const revealed = chipFor('Alice Admin');
  ok(revealed !== null, 'the FP target is back when revealed');
  ok(revealed && revealed.classList.contains('on-fp'), 'its chip reads ON so the mark can be cleared');
  ok(revealed && revealed.closest('.tgt-row').classList.contains('an-fp'), 'the row is styled as excluded');
  const spec2 = ovfSpecFor('High-Value Targets');
  ok(spec2 && spec2.items.length === 12, 'the drilldown is whole again when revealed', spec2 && spec2.items.length);
  ok(!/hidden/.test(anMeta()), 'the header no longer claims anything is hidden', anMeta());
  w.setShowFP(false);
  w.renderAnalysisList();

  /* ── E. globality: one fact, five surfaces ───────────────────────────────── */
  section('E · one fact, five surfaces');
  renderPeople([{ label: 'Alice Admin', username: 'aadmin', attack_score: 30 },
                { label: 'Bob User', username: 'buser', attack_score: 10 }]);
  ok(rowByLabel('Alice Admin') === null, 'Targets · People hides the same person');
  ok(rowByLabel('Bob User') !== null, 'an unmarked person still renders there');
  ok(/1 false positive/.test((d.querySelector('#tres') || {}).textContent || ''),
     'the People footer discloses the count');

  renderAssets([{ id: 'a0', name: 'WS02', type: 'HOST', os: 'Windows', score: 12 },
                { id: 'a1', name: 'DC01.CORP.LOCAL', type: 'HOST', os: 'Windows', score: 40 }]);
  ok(rowByLabel('WS02') === null, 'Targets · Assets hides the FP host');

  // Web tab — the asset namespace, keyed by url
  w.toggleAnalysisFP('assets', 'https://blog.example.com', null);
  w.eval(`_webCache={sites:[{url:'https://blog.example.com',title:'Blog'},{url:'https://ok.example.com',title:'OK'}],stats:{},ts:1};`);
  w.renderWeb();
  const webHtml = d.getElementById('web-res').innerHTML;
  ok(!webHtml.includes('blog.example.com'), 'the Web tab hides the FP endpoint');
  ok(webHtml.includes('ok.example.com'), 'an unmarked endpoint still renders');
  ok(webHtml.includes(">FP<"), 'the Web tab offers its own FP chip');

  // Domain Recon buckets
  w.toggleAnalysisFP('assets', 'example-logs', null);
  w.renderDomainRecon({ domain: 'example.com', timestamp: '2026-09-07T00:00:00Z',
    open_buckets: [{ bucket: 'example-logs', endpoint: 'example-logs.s3', exposure_score: 70, listable: true },
                   { bucket: 'example-pub', endpoint: 'example-pub.s3', exposure_score: 40, listable: true }],
    bucket_findings: [] });
  const drHtml = d.getElementById('dr-content').innerHTML;
  ok(!drHtml.includes('example-logs.s3'), 'the Domain Recon bucket list hides the FP bucket');
  ok(drHtml.includes('example-pub.s3'), 'an unmarked bucket still renders');
  ok(/False positives \(\d+\)/.test(drHtml), 'the bucket panel offers a reveal toggle');

  /* ── E2. Asset Ownership & Attack Surface ────────────────────────────────
     An ownership row names two entities — a person and an asset — and either one
     excluding drops the row, which is the rule the report and the chat tools use. */
  section('E2 · Asset Ownership & Attack Surface');
  /* Persisted, not just passed in: toggleBucketMark repaints from the stored record
     (_currentDomainRecon), which is how the real panel refreshes after a mark. */
  const reconAO = {
    id: 'ao1', campaignId: CAMP.id,
    domain: 'example.com', timestamp: '2026-09-07T00:00:00Z',
    asset_owners: [
      { individual: 'Carol Ops',  asset: 'https://vpn.example.com',  asset_type: 'WebAsset', relationship: 'MANAGES' },
      { individual: 'Dave Ops',   asset: 'https://mail.example.com', asset_type: 'WebAsset', relationship: 'MANAGES' },
      { individual: 'Erin Ops',   asset: 'https://wiki.example.com', asset_type: 'WebAsset', relationship: 'MANAGES' },
    ],
    web_assets: [
      { url: 'https://vpn.example.com',  manager_candidates: [{ name: 'Carol Ops', role: 'IT' }] },
      { url: 'https://shop.example.com', manager_candidates: [{ name: 'Dave Ops', role: 'Web' }, { name: 'Erin Ops', role: 'Web' }] },
    ],
    cloud_assets: [], services: [], open_buckets: [], bucket_findings: [],
  };
  clearMarks();
  w.localStorage.setItem('s.domainRecon', JSON.stringify([reconAO]));
  w.renderDomainRecon(reconAO);
  let ao = d.getElementById('dr-content').innerHTML;
  ok(ao.includes('Asset Ownership'), 'the section renders');
  ok((ao.match(/data-ao=/g) || []).length >= 4, 'every ownership row and candidate card carries mark chips',
     (ao.match(/data-ao=/g) || []).length);

  // exclude by the ASSET
  w.toggleBucketMark('fp', 'https://vpn.example.com');
  ao = d.getElementById('dr-content').innerHTML;
  ok(!ao.includes('vpn.example.com'), 'an FP asset drops its ownership row AND its candidate card');
  ok(ao.includes('mail.example.com'), 'an unmarked ownership row survives');
  ok(/False positives \(\d+\)/.test(ao), 'the section offers a reveal toggle');
  ok(/false positive hidden/.test(ao), 'the header discloses what it is withholding', ao.match(/[^>]*hidden[^<]*/));

  // exclude by the PERSON — the other end of the same relationship
  w.saveFPTargets({ 'Dave Ops': { ts: 1 } });
  w.renderDomainRecon(reconAO);
  ao = d.getElementById('dr-content').innerHTML;
  ok(!ao.includes('mail.example.com'), 'an FP person drops the ownership row they are the manager of');
  ok(ao.includes('wiki.example.com'), 'a row with neither end excluded survives');
  ok(!/>Dave Ops</.test(ao), 'an FP person is not offered as a likely manager either');
  ok(/>Erin Ops</.test(ao), 'the other candidate on that same card still renders');

  // reveal
  w.setShowFP(true);
  w.renderDomainRecon(reconAO);
  ao = d.getElementById('dr-content').innerHTML;
  ok(ao.includes('vpn.example.com') && ao.includes('mail.example.com'),
     'revealing brings both kinds of excluded row back');
  ok(/dr-oos/.test(ao), 'a revealed row is styled as excluded');
  w.setShowFP(false);

  // the section must survive its own contents being entirely excluded
  w.saveDevFPTargets({ 'https://vpn.example.com': { ts: 1 }, 'https://shop.example.com': { ts: 1 } });
  w.saveFPTargets({ 'Dave Ops': { ts: 1 }, 'Erin Ops': { ts: 1 }, 'Carol Ops': { ts: 1 } });
  w.renderDomainRecon(reconAO);
  ao = d.getElementById('dr-content').innerHTML;
  ok(ao.includes('Asset Ownership'), 'the section still renders when everything in it is excluded');
  ok(/Every asset here is excluded/.test(ao), 'and says so rather than reading as "no assets found"');
  ok(/False positives \(\d+\)/.test(ao), 'so the reveal toggle is still reachable');

  // the report drops the same rows
  clearMarks();
  w.saveDevFPTargets({ 'https://vpn.example.com': { ts: 1 } });
  const aoRep = w.buildAssetOwnershipReport(reconAO);
  ok(!JSON.stringify(aoRep.sections).includes('vpn.example.com'),
     'buildAssetOwnershipReport drops the FP asset');
  ok(JSON.stringify(aoRep.sections).includes('mail.example.com'),
     'and keeps the unmarked ones');

  /* ── E3. Ownership evidence tiers and the empty state ────────────────────
     Ownership is no longer a name-token guess, so the panel has to say HOW it
     knows. The edge label is the only carrier -- Flowsint drops edge properties
     -- so the tier has to survive from WF13's relationship type all the way to
     the chip an operator reads. */
  clearMarks();
  section('E3 · Ownership evidence tiers');
  const reconTiers = {
    id: 'ao2', campaignId: CAMP.id,
    domain: 'example.com', timestamp: '2026-09-07T00:00:00Z',
    graph_import: { ownership_edges: 3, ownership_evidence: {
      owns: 1, access: 1, registrant: 1, cloud_iam: 0,
      ad_edges: 12, devices_with_rights: 2, devices_matched: 1, empty_kind: '' } },
    asset_owners: [
      { individual: 'Carol Ops', asset: 'https://vpn.example.com',  asset_type: 'WebAsset',
        relationship: 'OWNS_ASSET', evidence: 'AD local admin on VPN01' },
      { individual: 'Dave Ops',  asset: 'https://mail.example.com', asset_type: 'WebAsset',
        relationship: 'HAS_ACCESS', evidence: 'AD CanRDP on MAIL01' },
      { individual: 'reg@example.com', asset: 'https://example.com', asset_type: 'WebAsset',
        relationship: 'MANAGES', evidence: 'whois/dns email' },
    ],
    web_assets: [], cloud_assets: [], services: [], open_buckets: [], bucket_findings: [],
  };
  w.localStorage.setItem('s.domainRecon', JSON.stringify([reconTiers]));
  w.renderDomainRecon(reconTiers);
  const tierHtml = d.getElementById('dr-content').innerHTML;
  /* Assert on the RENDERED text, not on the raw label: the whole point is that
     an operator sees the strength rather than the graph's spelling. */
  ok(/>owns</.test(tierHtml),       'a control claim renders as "owns"');
  ok(/>access</.test(tierHtml),     'a reach-only claim renders as "access"');
  ok(/>registrant</.test(tierHtml), 'the domain registrant renders as "registrant"');
  ok(!/>OWNS_ASSET</.test(tierHtml), 'the raw edge label is not shown to the operator');
  ok(/AD local admin on VPN01/.test(tierHtml), 'the evidence names the intermediate host');
  /* The three must be visually distinguishable, or the tiering is decorative. */
  const tierColors = new Set((tierHtml.match(/font-size:8px;\s*color:\s*([^;]+);/g) || []));
  ok(tierColors.size >= 3, 'each tier is styled distinctly', [...tierColors]);

  /* The empty states. After this change an empty ownership block is the COMMON
     case -- an externally hosted apex has no domain-joined host behind it -- so
     it must say which kind of empty it is rather than reading as a regression. */
  const aoEmptyCase = (ev, probe, why) => {
    const rec = { id: 'ao3', campaignId: CAMP.id, domain: 'example.com',
                  timestamp: '2026-09-07T00:00:00Z', asset_owners: [],
                  graph_import: { ownership_evidence: ev },
                  web_assets: [{ url: 'https://example.com' }],
                  cloud_assets: [], services: [], open_buckets: [], bucket_findings: [] };
    w.localStorage.setItem('s.domainRecon', JSON.stringify([rec]));
    w.renderDomainRecon(rec);
    ok(probe.test(d.getElementById('dr-content').innerHTML), why);
  };
  aoEmptyCase({ empty_kind: 'no_ad_data' }, /Ingest SharpHound/,
              'no AD data at all says so, and says what would fix it');
  aoEmptyCase({ empty_kind: 'no_device_match', ad_edges: 12, devices_with_rights: 3 },
              /none of these assets resolves to a domain-joined host/,
              'AD present but nothing matched is named as the expected external case');
  aoEmptyCase({ empty_kind: 'no_device_match', ad_edges: 12, devices_with_rights: 3 },
              /12 rights edges over 3 hosts/,
              'and it shows the AD data it DID have, so "empty" is not read as "broken"');
  aoEmptyCase({ empty_kind: 'no_rights', ad_edges: 12, devices_matched: 2 },
              /nobody in AD holds control or access rights/,
              'hosts matched but no rights is distinguished from no hosts');
  clearMarks();
  w.saveFPTargets({ 'Alice Admin': { ts: 1 } });
  w.saveDevFPTargets({ 'WS02': { ts: 1 } });

  // Worst Hosts — the surface that badged OoS but never hid it before this change
  w.eval(`_vsData={total_hosts:2,total_findings:5,top_hosts:[{host:'WS02',risk_score:9},{host:'SRV9',risk_score:4}],top_findings:[]};`);
  w.eval(`_vsRenderHosts();`);
  const vsHtml = d.getElementById('vs-hosts').innerHTML;
  ok(!vsHtml.includes('>WS02<'), 'Worst Hosts hides the FP host (it used to only badge it)');
  ok(vsHtml.includes('>SRV9<'), 'an unmarked host still ranks');

  // roster export
  const roster = w.buildTargetRosterReport();
  const rosterMeta = JSON.stringify(roster.meta);
  ok(!JSON.stringify(roster.sections).includes('Alice Admin'), 'the roster export drops the FP person');
  ok(/False positives.*excluded from this roster/.test(rosterMeta), 'the roster meta records the exclusion', rosterMeta);

  /* ── F. case folding ─────────────────────────────────────────────────────── */
  section('F · FP folds case, and clearing removes every spelling');
  w.saveDevFPTargets({});
  w.toggleAnalysisFP('assets', 'DC01.CORP.LOCAL', null);   // marked in WF10's spelling
  renderAssets([{ id: 'a0', name: 'dc01.corp.local', type: 'HOST', os: 'Windows', score: 40 }]);
  ok(rowByLabel('dc01.corp.local') === null,
     'a mark made as DC01.CORP.LOCAL hides the dc01.corp.local row (WF10 lowercases every tag it receives)');
  w.saveDevFPTargets(Object.assign(w.getDevFPTargets(), { 'dc01.corp.local': { ts: 1 } }));
  ok(Object.keys(w.getDevFPTargets()).length === 2, 'two spellings are present before the clear');
  w.toggleAnalysisFP('assets', 'DC01.CORP.LOCAL', null);   // toggle OFF
  ok(Object.keys(w.getDevFPTargets()).length === 0,
     'clearing removes every spelling — no differently-cased twin keeps the row hidden',
     JSON.stringify(w.getDevFPTargets()));

  /* ── G. chat context: nothing reaches the model ──────────────────────────── */
  section('G · every chat tool excludes the entity');
  const seedStores = () => {
    w.localStorage.setItem('s.domainRecon', JSON.stringify([{
      id: 'r1', campaignId: CAMP.id, domain: 'example.com', timestamp: '2026-09-07T00:00:00Z',
      web_assets: [{ url: 'https://blog.example.com' }], cloud_assets: [],
      open_buckets: [{ bucket: 'example-logs', endpoint: 'example-logs.s3' }], bucket_findings: [],
      credential_matches: [{ graph_user: 'Alice Admin', email: 'a@example.com' }],
      asset_owners: [{ individual: 'Alice Admin', asset: 'example-logs' }],
    }]));
    w.eval(`_targetsCache={list:[{label:'Alice Admin',attack_score:30},{label:'Bob User',attack_score:5}],
                            devices:[{hostname:'WS02'},{hostname:'SRV9'}],assets:[],deviceDossier:{},ts:1};`);
  };
  const seedTech = () => w.eval(`(function(){
      var s={}; s[tiCampKey()]={data:{ total_devices:2,
        user_tech_profiles:[{user:'Alice Admin'},{user:'Bob User'}],
        stale_devices:[{hostname:'WS02'},{hostname:'SRV9'}],
        tech_user_map:{'Chrome':['Alice Admin','Bob User']},
        os_device_map:{'Windows':['WS02','SRV9']},
        device_dossier_map:{'WS02':{},'SRV9':{}} }, ts:1};
      safeSetItem(TECH_INTEL_KEY, JSON.stringify(s));
    })();`);
  const seedVulns = () => w.eval(`(function(){
      var s={}; s[vsCampKey ? vsCampKey() : tiCampKey()]={data:{ total_hosts:2,
        top_hosts:[{host:'WS02',risk_score:9},{host:'SRV9',risk_score:4}],
        top_findings:[{plugin_id:1,name:'F',hosts:['WS02','SRV9']}] }, ts:1};
      try { safeSetItem(VULN_SCAN_KEY, JSON.stringify(s)); } catch(e) {}
    })();`);

  async function leakCheck(kind, needle) {
    seedStores(); seedTech(); try { seedVulns(); } catch {}
    const results = {
      get_analysis:        w.executeSpotterTool('get_analysis', { which: 'latest', section: 'all' }),
      get_osint_recon:     w.executeSpotterTool('get_osint_recon', { section: 'all' }),
      get_tech_intel:      w.executeSpotterTool('get_tech_intel', { section: 'all' }),
      get_vulnerabilities: w.executeSpotterTool('get_vulnerabilities', { section: 'all' }),
      list_targets:        w.executeSpotterTool('list_targets', { kind: 'both', limit: 50 }),
      search_intel:        w.executeSpotterTool('search_intel', { query: needle.toLowerCase() }),
    };
    for (const [tool, p] of Object.entries(results)) {
      let out;
      try { out = JSON.stringify(await p); } catch (e) { out = 'THREW: ' + e.message; }
      ok(!out.includes(needle), `${kind}: ${tool} does not leak "${needle}"`,
         out.length > 220 ? out.slice(0, 220) + '…' : out);
    }
  }

  clearMarks();
  renderCard();
  w.saveFPTargets({ 'Alice Admin': { ts: 1 } });
  w.saveDevFPTargets({ 'WS02': { ts: 1 } });
  await leakCheck('FP', 'Alice Admin');

  // The same six for OoS — this is where the pre-2026-09-07 leaks stay shut.
  clearMarks();
  w.saveOOSTargets({ 'Alice Admin': { ts: 1 } });
  w.saveDevOOSTargets({ 'WS02': { ts: 1 } });
  await leakCheck('OoS', 'Alice Admin');

  /* ── H. inventory counts are post-exclusion ──────────────────────────────── */
  section('H · the data inventory counts what the tools actually return');
  clearMarks();
  w.saveFPTargets({ 'Alice Admin': { ts: 1 } });
  w.saveOOSTargets({ 'Bob User': { ts: 1 } });
  seedStores();
  const inv = w.spotterDataInventory();
  const lt = inv.items.find(i => i.tool === 'list_targets');
  ok(/^0 individuals/.test(lt.detail), 'list_targets inventory count is post-exclusion', lt.detail);
  const exItem = inv.items.find(i => /Operator exclusions/.test(i.source));
  ok(!!exItem, 'the inventory carries an Operator exclusions item');
  ok(exItem && /1 out of scope, 1 false positive/.test(exItem.detail),
     'it reports both counts', exItem && exItem.detail);
  ok(exItem && !/Alice Admin/.test(exItem.detail),
     'it reports COUNTS, never names — naming them would re-inject what the operator stripped');
  ok(exItem && /run_cypher/.test(exItem.detail),
     'it warns that the graph tools are not filtered, so a discrepancy is not missing data');

  /* ── I. the analysis export ──────────────────────────────────────────────── */
  section('I · buildAnalysisReport drops and discloses');
  clearMarks();
  w.saveFPTargets({ 'Alice Admin': { ts: 1 } });
  const rep = w.buildAnalysisReport(analysisRecord());
  ok(!JSON.stringify(rep.sections).includes('Alice Admin'), 'the analysis export drops the FP target');
  ok(/False positives.*excluded from this report/.test(JSON.stringify(rep.meta)),
     'its meta records the exclusion', JSON.stringify(rep.meta));

  /* ── J. the WF10 payload ─────────────────────────────────────────────────── */
  section('J · runAnalysis ships both false_positive buckets');
  clearMarks();
  w.saveFPTargets({ 'Alice Admin': { ts: 1 } });
  w.saveDevFPTargets({ 'WS02': { ts: 1 } });
  let sent = null;
  w.eval(`window.__origFetchJson = fetchJson;`);
  w.fetchJson = async (url, opts) => {
    if (String(url).includes('security-analysis')) { sent = JSON.parse(opts.body); return { error: 'stubbed' }; }
    return {};
  };
  w.eval(`fetchJson = window.fetchJson;`);
  try { await w.runAnalysis(); } catch { /* the stub errors on purpose */ }
  ok(sent !== null, 'the analysis request was captured');
  const ot = (sent && sent.operator_tags) || {};
  ok(Array.isArray(ot.false_positive) && ot.false_positive.includes('Alice Admin'),
     'operator_tags.false_positive carries the people marks', JSON.stringify(ot.false_positive));
  ok(ot.devices && Array.isArray(ot.devices.false_positive) && ot.devices.false_positive.includes('WS02'),
     'operator_tags.devices.false_positive carries the asset marks', JSON.stringify(ot.devices && ot.devices.false_positive));
  ok(Array.isArray(ot.out_of_scope), 'the existing out_of_scope bucket is still shipped alongside it');

  /* ── K. scenario marks die with their record ─────────────────────────────── */
  section('K · scenario marks are record-scoped');
  clearMarks();
  renderCard();
  const sk = chips().find(c => c.dataset.fpns === 'scenario').dataset.fpk;
  w.toggleAnalysisFP('scenario', sk, null);
  ok(!!w.getFPScenarios()[sk], 'the scenario mark is stored');
  w.saveAnalyses([]);                      // the record is shed
  ok(Object.keys(w.getFPScenarios()).length === 0,
     'the mark is collected when its record goes — it keys on the record id',
     JSON.stringify(w.getFPScenarios()));

  console.log(`\n${failures ? 'FAILED' : 'PASS'} — ${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 150);
