#!/usr/bin/env node
/*
 * Headless smoke test for the Tech Intel tab's Perimeter Technology and Cloud
 * Exposure panels (frontend/index.html, renderTechIntel).
 *
 * Why this exists
 * ---------------
 * These two panels are the operator-facing end of the domain-recon -> tech-intel
 * chain: WF13 writes the perimeter's products, CPEs and DNS-inferred platform
 * into the graph, WF14 attaches CVEs, WF04 ranks cloud exposure, and WF12 reads
 * all of it back. Every one of those steps fails GREEN -- a missing label, an
 * unparsed JSON string or a pruned response key yields clean zeros rather than an
 * error -- so "the panel is empty" has never been evidence of anything, and the
 * only way to tell an empty estate from a broken pipeline is to render it.
 *
 * Three properties are load-bearing and would fail silently:
 *
 *   1. A DNS-inferred platform (mail / CDN / DNS / hosting) carries NO CPE and can
 *      only ever keyword-match in NVD, which WF04 halves. The chip has to say so,
 *      or a guess reads like a CPE-grade identification.
 *   2. Sensitive-category tags come from object NAMES only -- no object body is
 *      ever fetched -- so the caveat has to render beside the tags, not in a
 *      tooltip or once at the top of the page where it scrolls away.
 *   3. Cloud exposure is scored at the ASSET. With ownership excluded from path
 *      scoring a bucket has no route to an Individual, so no attack_score includes
 *      those numbers. The panel must print that next to them.
 *
 * What it CANNOT tell you: jsdom has no layout engine, so column widths and
 * colour contrast are unverified here.
 *
 * Run: node scripts/smoke_frontend_perimeter.js
 */

const fs = require('fs');


// jsdom lives inside the global n8n install; fall back to a normal resolution so
// this keeps working if it is ever installed properly.
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

// A bucket name is attacker-influenced in the passive-discovery path (WF13 reads
// it out of a CNAME chain and a third-party index), so it reaches this panel as
// untrusted text.
const XSS_ASSET = 's3:evil"><img src=x onerror=window.__pwned=1>';

const FIXTURE = {
  os_inventory: [], tech_catalog: {}, user_tech_profiles: [], attack_narratives: [],
  legacy_systems: [], total_devices: 1, total_individuals: 1,
  tech_user_map: {}, os_device_map: {}, device_dossier_map: {}, vulnerable_tech: [],
  perimeter_tech: [
    // A real Shodan CPE: product-accurate, so no weak-match caveat.
    { name: 'nginx', version: '1.18', vendor: 'nginx', category: 'web-server',
      kind: 'service', cpe: 'cpe:/a:nginx:nginx:1.18', confidence: 'high',
      platform_basis: '', ip: '203.0.113.10', is_high_value: false,
      cve_count: 4, cve_match_basis: 'cpe', exploit_available: true, poc_count: 3 },
    // A perimeter appliance flagged high-value before WF14 has attached anything.
    { name: 'Citrix NetScaler ADC', version: '13.1', vendor: 'Citrix',
      category: 'remote-access', kind: 'technology', cpe: '', confidence: 'medium',
      platform_basis: '', ip: '203.0.113.14', is_high_value: true,
      cve_count: 0, cve_match_basis: '', exploit_available: false, poc_count: 0 },
    // Inferred from an MX record: no CPE, keyword-only.
    { name: 'Microsoft 365 Exchange Online', version: '', vendor: 'Microsoft',
      category: 'mail-platform', kind: 'technology', cpe: '', confidence: 'medium',
      platform_basis: 'mx', ip: '', is_high_value: false,
      cve_count: 0, cve_match_basis: '', exploit_available: false, poc_count: 0 },
    // An NVD phrase match, the Ivanti-on-Apache case.
    { name: 'Apache httpd', version: '2.4.49', vendor: 'Apache', category: 'web-server',
      kind: 'service', cpe: '', confidence: 'medium', platform_basis: '',
      ip: '203.0.113.11', is_high_value: false,
      cve_count: 10, cve_match_basis: 'keyword', exploit_available: false, poc_count: 0 },
  ],
  cloud_exposure: [
    { asset: 's3:example-payroll', endpoint: 'example-payroll.s3.amazonaws.com',
      provider: 'aws', service: 's3', url: 'https://example-payroll.s3.amazonaws.com',
      exposure_score: 64, object_count: 12048, categories: ['pii', 'backup'],
      attack_bonus: 8, attack_basis: 'dns' },
    // Discovered but not yet ranked: WF04 has not run since the recon.
    { asset: XSS_ASSET, endpoint: 'example-xss.s3.amazonaws.com', provider: 'aws',
      service: 's3', url: '', exposure_score: 30, object_count: 3,
      categories: [], attack_bonus: 0, attack_basis: '' },
  ],
  cloud_exposure_total: 9,
  cloud_unattributed: true,
};

const vc = new VirtualConsole();
vc.on('jsdomError', () => { /* CSS/layout noise jsdom cannot do */ });

const dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
  runScripts: 'dangerously', pretendToBeVisual: true,
  url: 'http://localhost:8080/', virtualConsole: vc,
});
const w = dom.window;

setTimeout(() => {
  const H = (id) => (w.document.getElementById(id) || {}).innerHTML || '';
  const T = (id) => (w.document.getElementById(id) || {}).textContent || '';

  console.log('Perimeter Technology / Cloud Exposure');

  // ── The panels exist at all ────────────────────────────────────────────────
  ok(!!w.document.getElementById('ti-perimeter'), 'the Perimeter Technology panel exists');
  ok(!!w.document.getElementById('ti-cloud'), 'the Cloud Exposure panel exists');

  w.eval('window.__fx = ' + JSON.stringify(FIXTURE) + ';');
  let threw = '';
  try { w.eval('renderTechIntel(window.__fx);'); } catch (e) { threw = e.message; }
  ok(!threw, 'renderTechIntel accepts the perimeter/cloud payload', threw);

  // ── Perimeter ─────────────────────────────────────────────────────────────
  const perim = H('ti-perimeter');
  ok(/nginx/.test(perim), 'a CPE-identified product renders', perim.slice(0, 160));
  ok(/Citrix NetScaler ADC/.test(perim), 'a perimeter appliance renders');
  ok(/hv-tt/.test(perim), 'a high-value appliance is marked as such');
  ok(/Microsoft 365 Exchange Online/.test(perim), 'a DNS-inferred platform renders');
  // Property 1: a guess must not read like an identification.
  ok(/MX/.test(perim) && /keyword-only/.test(perim),
     'a DNS-inferred platform declares that it can only keyword-match', perim.slice(0, 400));
  ok(/name-matched/.test(perim),
     'an NVD phrase match is tagged name-matched');
  // The CPE-identified row must NOT be tagged weak.
  const nginxChip = (perim.match(/<span class="ti-tt"[^>]*>[\s\S]*?nginx[\s\S]*?<\/span>\s*<\/span>/) || [''])[0];
  ok(!/keyword-only|name-matched/.test(nginxChip),
     'a CPE-identified product is NOT tagged as a weak match', nginxChip.slice(0, 200));
  ok(/internet-facing component/.test(T('ti-perim-note')),
     'the section header counts internet-facing components', T('ti-perim-note'));
  ok(/inferred from DNS/.test(T('ti-perim-note')),
     'the header says how many rows are DNS inferences', T('ti-perim-note'));

  // ── Cloud ─────────────────────────────────────────────────────────────────
  const cloud = H('ti-cloud');
  ok(/<table/.test(cloud), 'cloud exposure renders as a table');
  ok(/s3:example-payroll/.test(cloud), 'a public bucket renders');
  ok(/12,048/.test(cloud), 'object counts are thousands-separated', cloud.slice(0, 300));
  ok(/\+8/.test(cloud), "WF04's bounded bonus renders");
  ok(/not scored/.test(cloud),
     'a bucket WF04 has not ranked yet says so rather than showing 0');
  ok(/attack-path[\s\S]{0,40}sweep/.test(cloud),
     'and the panel says which run would rank it');
  // Property 2.
  ok(/Object names only/.test(cloud),
     'the object-names-only caveat renders beside the sensitive tags');
  // Property 3.
  ok(/no <code>attack_score<\/code> includes/.test(cloud),
     'the unattributed caveat renders next to the numbers', cloud.slice(-400));
  ok(/publicly readable of 9 discovered/.test(T('ti-cloud-note')),
     'the header separates readable from merely discovered', T('ti-cloud-note'));

  // ── Untrusted text ────────────────────────────────────────────────────────
  // Assert STRUCTURALLY, not on the innerHTML string. jsdom hands back the
  // re-serialised DOM rather than the markup that was assigned, so an injected
  // `<img src=x onerror=...>` comes back with quotes normalised and a regex
  // written against the raw payload silently never matches -- which makes the
  // check pass whether or not the value was escaped. Counting elements cannot
  // lie that way. (jsdom also never fires an img error handler without resource
  // loading, so w.__pwned alone proves nothing either.)
  ok(!w.__pwned, 'a bucket name cannot execute script');
  const cloudEl = w.document.getElementById('ti-cloud');
  ok(cloudEl && cloudEl.querySelectorAll('img').length === 0,
     'a bucket name cannot inject an element',
     cloudEl && cloudEl.innerHTML.slice(0, 300));
  ok(/s3:evil/.test(cloudEl.textContent) && /img src=x/.test(cloudEl.textContent),
     'the injected markup renders as literal TEXT, not as markup',
     cloudEl && cloudEl.textContent.slice(0, 200));
  const link = /<a href="([^"]*)"[^>]*>/.exec(cloud);
  ok(!link || /rel="noopener noreferrer"/.test(cloud),
     'an outbound bucket link carries rel=noopener noreferrer');
  // A bucket with no url must not become a live link to nowhere.
  ok(!/<a href=""/.test(cloud), 'a bucket with no url is not rendered as a link');

  // ── Empty state ───────────────────────────────────────────────────────────
  // The whole point: these panels are empty far more often than they are full,
  // and an empty one has to say which run would fill it.
  let threw2 = '';
  try { w.eval('renderTechIntel({});'); } catch (e) { threw2 = e.message; }
  ok(!threw2, 'renderTechIntel survives a response with neither key', threw2);
  ok(/Domain Recon/.test(H('ti-perimeter')),
     'the empty perimeter panel names the run that fills it', H('ti-perimeter').slice(0, 200));
  ok(/Enrich Cloud Buckets/.test(H('ti-cloud')),
     'the empty cloud panel names the run that fills it', H('ti-cloud').slice(0, 200));

  // ── Domain Recon panel: the producing end of the same chain ───────────────
  // The recon panel is where an operator learns whether the run actually wrote
  // the input Tech Intel consumes. Without it, a run that inferred nothing looks
  // identical to one that inferred plenty until the Tech Intel tab is opened.
  const DR = {
    domain: 'example.test',
    dns_mx: ['example-test.mail.protection.outlook.com'],
    dns_ns: ['ns-1234.awsdns-56.org'], dns_cname: [], dns_a: ['203.0.113.10'],
    asn_org: 'Cloudflare, Inc.',
    web_assets: [{ url: 'https://example.test', platform: 'website' }],
    cloud_assets: [], services: [], asset_owners: [],
    technologies: [
      // One host, named: the chip can answer "where" without being opened.
      { name: 'nginx', version: '1.18', vendor: 'nginx', category: 'web-server',
        cpe: 'cpe:/a:nginx:nginx:1.18', basis: 'cpe', confidence: 'high',
        is_high_value: false, evidence: 'shodan-cpe:203.0.113.10', ip: '203.0.113.10',
        port: 443, matched_devices: ['WEB01.corp.example.test'],
        host_count: 1,
        hosts: [{ ip: '203.0.113.10', port: 443, hostnames: ['www.example.test'],
                  devices: ['WEB01.corp.example.test'], basis: 'cpe',
                  evidence: 'shodan-cpe:203.0.113.10' }] },
      // The case the flat ip/port keys could never express: ONE canonical product
      // on three addresses. Only the first ever reached the response before.
      { name: 'Apache httpd', version: '2.4.49', vendor: 'Apache',
        category: 'web-server', cpe: '', basis: 'product', confidence: 'medium',
        is_high_value: false, evidence: 'shodan:203.0.113.11:8443',
        ip: '203.0.113.11', port: 8443, matched_devices: [],
        host_count: 3,
        hosts: [
          { ip: '203.0.113.11', port: 8443, hostnames: [], devices: [],
            basis: 'product', evidence: 'shodan:203.0.113.11:8443' },
          { ip: '203.0.113.21', port: 443, hostnames: ['vpn.example.test'],
            devices: ['VPN01.corp.example.test'], basis: 'product',
            evidence: 'shodan:203.0.113.21:443' },
          { ip: '203.0.113.31', port: 80, hostnames: [], devices: [],
            basis: 'fofa', evidence: 'fofa:203.0.113.31:80' },
        ] },
      // A recon cached before WF13 shipped `hosts`: the one ip/port it carries
      // must still resolve to a host rather than to nothing.
      { name: 'OpenSSH', version: '8.9', vendor: 'OpenBSD', category: 'remote-access',
        cpe: '', basis: 'product', confidence: 'medium', is_high_value: false,
        evidence: 'shodan:203.0.113.41:22', ip: '203.0.113.41', port: 22,
        matched_devices: [] },
    ],
    platform_tech: [
      { name: 'Microsoft 365 Exchange Online', vendor: 'Microsoft',
        category: 'mail-platform', confidence: 'medium', basis: 'mx',
        evidence: 'mx:example-test.mail.protection.outlook.com',
        is_high_value: false, cve_match_limit: 'keyword-only (no CPE)' },
    ],
    graph_import: { web_assets: 1, cloud_assets: 0, services: 0, subdomains: 0,
                    technologies: 3, tech_edges: 3, tech_truncated: false,
                    open_buckets: 0, service_device_links: 0, ownership_edges: 0,
                    total_edges: 3, graph_read_failed: false },
    errors: [],
  };
  console.log('Domain Recon panel');
  let threw3 = '';
  w.eval('window.__dr = ' + JSON.stringify(DR) + ';');
  try { w.eval('renderDomainRecon(window.__dr);'); } catch (e) { threw3 = e.message; }
  ok(!threw3, 'renderDomainRecon accepts the technology keys', threw3);
  const drEl = w.document.getElementById('dr-content');
  const drT = drEl ? drEl.textContent : '';
  ok(/Perimeter tech/.test(drT), 'the perimeter technology block renders', drT.slice(0, 200));
  ok(/nginx/.test(drT) && /Apache httpd/.test(drT),
     'Shodan/FOFA products render');
  ok(/Microsoft 365 Exchange Online/.test(drT),
     'the DNS-inferred platform renders');
  // Same property as the Tech Intel panel: a DNS inference must not read like a
  // CPE-grade identification.
  ok(/keyword-only/.test(drT),
     'a DNS-inferred platform declares its weak CVE matching', drT.slice(0, 400));
  ok(/3 tech/.test(drT),
     'the graph-import summary counts written technologies',
     (drT.match(/graph:[^\n]{0,90}/) || [''])[0]);

  // ── "Which host is that on?" ──────────────────────────────────────────────
  // The chips named the product and stopped, which is the one thing an operator
  // cannot act on: a perimeter product is a finding only once it has an address.
  // Property 1 -- the common case answers without a click.
  ok(/www\.example\.test:443/.test(drT),
     'a single-host component names that host on the chip itself',
     (drT.match(/nginx[^\n]{0,80}/) || [''])[0]);
  // Property 2 -- and when it cannot, it says how many there are instead of
  // silently showing the first one as though it were the only one.
  ok(/3 hosts/.test(drT),
     'a product seen on several hosts advertises the count, not just the first',
     (drT.match(/Apache httpd[^\n]{0,80}/) || [''])[0]);
  // Property 3 -- the field itself expands.
  const perimDrill = [...(drEl ? drEl.querySelectorAll('[data-ovf-open]') : [])]
    .find(e => /component/.test(e.textContent) && /Tech Intel/.test(e.textContent));
  ok(!!perimDrill, 'the Perimeter tech field is expandable',
     drEl && (drEl.innerHTML.match(/Perimeter tech[\s\S]{0,300}/) || [''])[0]);
  if (perimDrill) {
    w.eval(`ovfOpen(${JSON.stringify(perimDrill.dataset.ovfOpen)});`);
    const modal = T('ovf-body');
    ok(/203\.0\.113\.21/.test(modal) && /203\.0\.113\.31/.test(modal),
       'the drilldown lists EVERY host a product was seen on, not just the first',
       modal.slice(0, 400));
    ok(/VPN01\.corp\.example\.test/.test(modal),
       'the matched AD device is named beside the address it was matched to',
       modal.slice(0, 400));
    // A DNS-inferred platform genuinely has no host -- it hangs off the apex so
    // WF04's carrier walk terminates there. Blank would read as "unknown".
    ok(/apex/.test(modal),
       'a DNS-inferred platform says apex rather than leaving the host blank',
       modal.slice(0, 600));
    ok(/203\.0\.113\.41/.test(modal),
       'a record predating hosts[] still resolves to its one ip/port',
       modal.slice(0, 600));
    w.eval('ovfClose();');
  }
  // Property 4 -- each chip opens the hosts behind that one component.
  // Scoped to .dr-perim-tags: the Shodan and FOFA cards also emit
  // .dr-tag[data-ovf-open] value tags now, and they render EARLIER in the grid,
  // so an unscoped .find() by name would pick up one of theirs instead.
  const drNginxChip = [...(drEl ? drEl.querySelectorAll('.dr-perim-tags .dr-tag[data-ovf-open]') : [])]
    .find(e => /nginx/.test(e.textContent));
  ok(!!drNginxChip, 'a technology chip is itself a handle on its hosts');
  if (drNginxChip) {
    w.eval(`ovfOpen(${JSON.stringify(drNginxChip.dataset.ovfOpen)});`);
    const one = T('ovf-body');
    ok(/www\.example\.test/.test(one) && !/Apache/.test(one),
       'the chip drilldown is scoped to that component', one.slice(0, 300));
    w.eval('ovfClose();');
  }

  // ── The deliverable ───────────────────────────────────────────────────────
  // The perimeter block renders inside the Asset Ownership section on screen but
  // was absent from that section's export, so a report could list the assets and
  // name the host of none of the products found on them.
  let rep = null, threwR = '';
  try { rep = JSON.parse(w.eval('JSON.stringify(buildAssetOwnershipReport(window.__dr))')); }
  catch (e) { threwR = e.message; }
  ok(!threwR, 'buildAssetOwnershipReport survives the technology keys', threwR);
  const pSec = ((rep || {}).sections || []).find(s => s.key === 'perimeter');
  ok(!!pSec, 'the Asset Ownership report carries a Perimeter Technology section',
     ((rep || {}).sections || []).map(s => s.key).join(', '));
  const pRows = pSec ? (pSec.blocks[0].rows || []) : [];
  ok(pRows.length === 4, 'one report row per component, platforms included',
     JSON.stringify(pRows.map(r => r[0])));
  const apRow = pRows.find(r => /Apache/.test(r[0])) || [];
  ok(/203\.0\.113\.21/.test(apRow[1] || '') && /203\.0\.113\.31/.test(apRow[1] || ''),
     'a multi-host product names every host in the report too, not just the first',
     apRow[1]);
  ok(/vpn\.example\.test \(203\.0\.113\.21:443\) \u2192 VPN01/.test(apRow[1] || ''),
     'the matched AD device travels with its OWN address, not the whole list',
     apRow[1]);
  const platRow = pRows.find(r => /Exchange/.test(r[0])) || [];
  ok(/apex/.test(platRow[1] || ''),
     'a DNS-inferred platform reads apex in the report, not a blank cell', platRow[1]);
  // The page's columns and the report's columns are one array on purpose.
  ok(pSec && JSON.stringify(pSec.blocks[0].columns)
      === w.eval('JSON.stringify(DR_PERIM_COLUMNS)'),
     'the report and the drilldown share one column list');
  const pNote = pSec ? (pSec.blocks[1] || {}).text || '' : '';
  // A technology is in neither mark namespace, so the OoS/FP exclusions that
  // scrub every other table here do NOT filter this one. A deliverable that does
  // not say so implies an exclusion that was never applied.
  ok(/do not filter this table/.test(pNote),
     'the report states that scope exclusions do not reach this table', pNote.slice(0, 160));
  // It must also survive being exported on its own from the card buttons.
  const sub = w.eval('JSON.stringify(_reportSubset(buildAssetOwnershipReport(window.__dr), "perimeter").sections.map(s => s.key))');
  ok(sub === '["perimeter"]', 'the block exports on its own from its card buttons', sub);
  const csv = w.eval('_reportToCSV(_reportSubset(buildAssetOwnershipReport(window.__dr), "perimeter"))');
  ok(/Apache httpd 2\.4\.49/.test(csv) && /203\.0\.113\.31/.test(csv),
     'the CSV carries the hosts', String(csv).slice(0, 300));

  // A run that inferred ONLY a platform from DNS -- no Shodan, no assets -- must
  // still show it rather than hiding the whole section.
  let threw4 = '';
  try {
    w.eval('window.__dr2 = ' + JSON.stringify({
      ...DR, web_assets: [], technologies: [], graph_import: {},
    }) + '; renderDomainRecon(window.__dr2);');
  } catch (e) { threw4 = e.message; }
  ok(!threw4, 'renderDomainRecon survives a platform-only run', threw4);
  const drT2 = (w.document.getElementById('dr-content') || {}).textContent || '';
  ok(/Microsoft 365 Exchange Online/.test(drT2),
     'a platform-only run still shows what it inferred', drT2.slice(0, 200));

  // ── The FOFA card always renders ──────────────────────────────────────────
  // It used to collapse to '' on anything but a missing API key. FOFA was in
  // fact refusing every query on this account tier, so the operator saw no FOFA
  // card at all and read that as "the feature was never built".
  console.log('FOFA card');
  const drFofa = (extra) => {
    w.eval('window.__drF = ' + JSON.stringify({
      ...DR, web_assets: [], technologies: [], graph_import: {},
      fofa_total: 0, fofa_ports: [], fofa_products: [], fofa_results: [],
      ...extra,
    }) + '; renderDomainRecon(window.__drF);');
    return (w.document.getElementById('dr-content') || {}).textContent || '';
  };

  const fErr = drFofa({ fofa_status: { state: 'error', detail: '[820001] no permission to search product', fields: '', attempts: 3 } });
  ok(/FOFA\.io/.test(fErr) && /820001/.test(fErr),
     'a FOFA that errored shows a card naming the API error, not nothing at all',
     (fErr.match(/FOFA\.io[^\n]{0,200}/) || [''])[0]);
  ok(/reduced field set/.test(fErr),
     'a permission error explains the field-tier fallback',
     (fErr.match(/FOFA\.io[^\n]{0,260}/) || [''])[0]);

  const fNoKey = drFofa({ fofa_status: { state: 'no_key', detail: '', fields: '', attempts: 0 } });
  ok(/FOFA_API_KEY not set/.test(fNoKey),
     'a missing key still reads as a missing key',
     (fNoKey.match(/FOFA\.io[^\n]{0,200}/) || [''])[0]);

  // No status at all: a record cached before fofa_status existed, or a run whose
  // fofa_* keys were pruned because FOFA was not a selected source.
  const fNever = drFofa({});
  ok(/FOFA\.io/.test(fNever) && /has not been run/.test(fNever),
     'a domain FOFA never ran against says so instead of hiding the card',
     (fNever.match(/FOFA\.io[^\n]{0,200}/) || [''])[0]);

  const fOk = drFofa({
    fofa_total: 2, fofa_ports: [80], fofa_products: ['Microsoft-IIS/10.0'],
    fofa_status: { state: 'ok', detail: '', fields: 'host,ip,port', attempts: 1 },
    fofa_results: [{
      host: 'www.example.test', ip: '203.0.113.12', port: '80', protocol: 'https',
      server: 'Microsoft-IIS/10.0', os: 'windows', country: 'US',
      region: 'Virginia', city: 'Ashburn', title: 'Example',
      link: 'http://203.0.113.12',
    }],
  });
  ok(/https/.test(fOk) && /US/.test(fOk) && /Microsoft-IIS\/10\.0/.test(fOk),
     'the card renders the protocol, geo and server banner FOFA returned',
     (fOk.match(/FOFA\.io[\s\S]{0,300}/) || [''])[0]);
  ok(/Server banners/.test(fOk),
     'the banner list is labelled for what it is, not "Products" -- product is a '
     + 'premium FOFA field this tier never returns',
     (fOk.match(/FOFA\.io[\s\S]{0,300}/) || [''])[0]);
  // OPSEC: a clickable target URL would open a direct, un-proxied connection to
  // target infrastructure from the analyst's browser.
  const fofaCardHtml = (w.document.getElementById('dr-content') || {}).innerHTML || '';
  const fofaSlice = (fofaCardHtml.match(/FOFA\.io[\s\S]{0,4000}/) || [''])[0];
  ok(!/<a\s[^>]*href/i.test(fofaSlice),
     'the FOFA card never renders a clickable link to target infrastructure',
     fofaSlice.slice(0, 300));

  // A failed FOFA must export its reason too, or the card and the CSV disagree.
  const fSub = w.eval('JSON.stringify(_reportSubset(buildDomainReconReport(window.__drF), "fofa").sections.map(s => s.key))');
  ok(fSub === '["fofa"]', 'the FOFA card exports on its own from its buttons', fSub);
  const fCsv = w.eval('_reportToCSV(_reportSubset(buildDomainReconReport(window.__drF), "fofa"))');
  ok(/203\.0\.113\.12/.test(fCsv) && /Microsoft-IIS\/10\.0/.test(fCsv) && /Ashburn/.test(fCsv),
     'the FOFA CSV carries the host rows, not just the card headings',
     String(fCsv).slice(0, 400));
  // The reason travels into the export as well, so a report from a failed run is
  // not an unexplained blank.
  w.eval('window.__drFE = Object.assign({}, window.__drF, { fofa_total: 0, fofa_ports: [], fofa_products: [], fofa_results: [], fofa_status: { state: "error", detail: "[820001] denied" } });');
  const fCsvErr = w.eval('_reportToCSV(_reportSubset(buildDomainReconReport(window.__drFE), "fofa"))');
  ok(/820001/.test(fCsvErr),
     'an errored FOFA exports its reason instead of an empty section',
     String(fCsvErr).slice(0, 300));

  // ── Shodan rate limit is not an empty result ──────────────────────────────
  // HTTP 429 used to fall through the same "no data" sentence as a quiet target,
  // including when InternetDB had already contributed rows.
  console.log('Shodan status');
  const drShodan = (extra) => {
    w.eval('window.__drS = ' + JSON.stringify({
      ...DR, web_assets: [], technologies: [], graph_import: {},
      shodan_open_ports: [], shodan_vulns: [], shodan_results: [],
      ...extra,
    }) + '; renderDomainRecon(window.__drS);');
    return (w.document.getElementById('dr-content') || {}).textContent || '';
  };
  const shLimited = drShodan({
    shodan_api_status: { state: 'rate_limited', detail: 'Shodan API returned HTTP 429', http_status: 429, rate_limited: true },
  });
  ok(/rate-limited/.test(shLimited) && /not an empty result/.test(shLimited),
     'a rate-limited Shodan card says so instead of "no data"',
     (shLimited.match(/Shodan[\s\S]{0,220}/) || [''])[0]);
  ok(!/No Shodan data found/.test(shLimited),
     'a rate limit does not also fall through to the empty sentence',
     (shLimited.match(/Shodan[\s\S]{0,220}/) || [''])[0]);
  const shLimitedRows = drShodan({
    shodan_open_ports: [443],
    shodan_results: [{ ip: '203.0.113.11', ports: [443], vulns: [], product: 'Apache httpd' }],
    shodan_api_status: { state: 'ok', rate_limited: true, http_status: 429, detail: 'InternetDB returned HTTP 429' },
  });
  ok(/rate-limited/.test(shLimitedRows) && /203\.0\.113\.11/.test(shLimitedRows)
     && !/No Shodan data found/.test(shLimitedRows),
     'rows do not hide a rate limit, and a rate limit is not an empty card',
     (shLimitedRows.match(/Shodan[\s\S]{0,240}/) || [''])[0]);
  const shRateCsv = w.eval('_reportToCSV(_reportSubset(buildDomainReconReport(window.__drS), "shodan"))');
  ok(/rate-limited/.test(shRateCsv) && /not an empty result/.test(shRateCsv)
     && !/No Shodan data found/.test(shRateCsv),
     'the Shodan export tells the same rate-limit story as the card',
     String(shRateCsv).slice(0, 400));
  const shEmpty = drShodan({
    shodan_api_status: { state: 'empty', detail: 'Shodan API returned no matches', http_status: 200, rate_limited: false },
  });
  ok(/No Shodan data found/.test(shEmpty) && !/rate-limited/.test(shEmpty),
     'an empty Shodan status with no rows still uses the empty sentence',
     (shEmpty.match(/Shodan[\s\S]{0,220}/) || [''])[0]);

  // ── Attack-surface value tags ─────────────────────────────────────────────
  // A port, a country or a CVE used to be dead text: the operator could see that
  // 8443 was open but not ask which hosts. Each value is now its own drilldown
  // handle, scoped to the rows carrying it.
  console.log('Attack-surface value tags');

  // A FOFA server banner is third-party text -- it reaches this card straight
  // from fofa.info, so it is exactly the string that must not become markup.
  const XSS_BANNER = 'nginx"><img src=x onerror=window.__pwned=1>';
  const SURFACE = {
    ...DR, web_assets: [], technologies: [], graph_import: {},
    fofa_total: 3,
    // 9999 is in the roll-up but on no row: the shape left behind when the
    // browser cache trims fofa_results and leaves fofa_ports whole.
    fofa_ports: [80, 443, 9999],
    fofa_products: ['nginx', 'Apache', XSS_BANNER],
    fofa_status: { state: 'ok', detail: '', fields: 'host,ip,port', attempts: 1 },
    fofa_results: [
      { host: 'a.example.test', ip: '203.0.113.1', port: '80',  protocol: 'http',  server: 'nginx',      country: 'US', city: 'Ashburn',  region: 'Virginia', title: 'A' },
      { host: 'b.example.test', ip: '203.0.113.2', port: '443', protocol: 'https', server: 'nginx',      country: 'US', city: 'Ashburn',  region: 'Virginia', title: 'B' },
      // product set AND a different server: WF13 builds fofa_products as
      // (product or server) while the card reads (server or product), so a
      // one-sided matcher would leave the 'Apache' tag silently inert.
      { host: 'c.example.test', ip: '203.0.113.3', port: '443', protocol: 'https', server: XSS_BANNER, product: 'Apache', country: 'DE', city: 'Berlin', region: 'Berlin', title: 'C' },
    ],
    // CVE-2999-9999 is in the roll-up but on no row -- InternetDB caps each
    // host's vuln list at 20 while the roll-up unions the untruncated lists.
    shodan_open_ports: [80, 443, 8080],
    shodan_vulns: ['CVE-2021-1', 'CVE-2999-9999'],
    shodan_results: [
      { ip: '198.51.100.5', ports: [80, 443], vulns: ['CVE-2021-1'], cpes: [], tags: ['cloud', 'self-signed'], hostnames: ['edge.example.test'] },
      { ip: '198.51.100.9', ports: [8080], vulns: [], cpes: [], product: 'nginx', version: '1.18', org: 'Example Hosting' },
    ],
    _cache_trimmed: { fofa_results: 118 },
  };
  w.eval('window.__drS = ' + JSON.stringify(SURFACE) + '; renderDomainRecon(window.__drS);');
  const sEl = () => w.document.getElementById('dr-content');
  // Scoped per card on purpose: both attack-surface cards carry a "443" port tag
  // and Shodan renders first, so an unscoped lookup silently tests the wrong one.
  const cardEl = (name) => [...sEl().querySelectorAll('.dr-card')]
    .find(c => ((c.querySelector('.dr-card-title') || {}).textContent || '').includes(name));
  const valTag = (card, text) => {
    const c = cardEl(card);
    return c && [...c.querySelectorAll('.dr-tag')].find(e => e.textContent.trim() === text);
  };
  // Ids are only valid within the render that produced them -- renderDomainRecon
  // calls _ovfClear('dr'), so a stale id just toasts "no longer loaded".
  const openTag = (card, text) => {
    const el = valTag(card, text);
    if (!el || !el.dataset.ovfOpen) return null;
    w.eval(`ovfOpen(${JSON.stringify(el.dataset.ovfOpen)});`);
    const body = T('ovf-body');
    w.eval('ovfClose();');
    return body;
  };

  const p443 = openTag('FOFA.io', '443');
  ok(p443 && /b\.example\.test/.test(p443) && /c\.example\.test/.test(p443) && !/a\.example\.test/.test(p443),
     'a FOFA port tag opens only the hosts on that port', String(p443).slice(0, 300));
  const cUS = openTag('FOFA.io', 'US');
  ok(cUS && /a\.example\.test/.test(cUS) && /b\.example\.test/.test(cUS) && !/c\.example\.test/.test(cUS),
     'a FOFA country tag is scoped to that country', String(cUS).slice(0, 300));
  const bApache = openTag('FOFA.io', 'Apache');
  ok(bApache && /c\.example\.test/.test(bApache),
     'a banner that came from the product field still finds its host '
     + '(fofa_products prefers product, the card prefers server)', String(bApache).slice(0, 300));
  const proHttps = openTag('FOFA.io', 'https');
  ok(proHttps && /b\.example\.test/.test(proHttps) && !/a\.example\.test/.test(proHttps),
     'a FOFA protocol tag is scoped to that protocol', String(proHttps).slice(0, 300));

  const sh8080 = openTag('Shodan', '8080');
  ok(sh8080 && /198\.51\.100\.9/.test(sh8080) && !/198\.51\.100\.5/.test(sh8080),
     'a Shodan port tag opens only the hosts on that port', String(sh8080).slice(0, 300));
  const shCve = openTag('Shodan', 'CVE-2021-1');
  ok(shCve && /198\.51\.100\.5/.test(shCve) && !/198\.51\.100\.9/.test(shCve),
     'a Shodan CVE tag is scoped to the hosts carrying it', String(shCve).slice(0, 300));
  const shTagCloud = openTag('Shodan', 'cloud');
  ok(shTagCloud && /198\.51\.100\.5/.test(shTagCloud),
     'a Shodan host tag is a drilldown handle too', String(shTagCloud).slice(0, 300));
  ok(/nginx 1\.18/.test(sh8080 || '') && /Example Hosting/.test(sh8080 || ''),
     'the paid-API product/version/org finally reach the operator',
     String(sh8080).slice(0, 300));

  // A tag that matches nothing must NOT advertise a click -- an empty modal
  // reads as a broken drilldown rather than an honest "no row carries this".
  const orphanPort = valTag('FOFA.io', '9999');
  ok(orphanPort && !orphanPort.hasAttribute('data-ovf-open') && orphanPort.getAttribute('role') === null,
     'a value with no host row behind it stays inert',
     orphanPort && orphanPort.outerHTML.slice(0, 200));
  ok(orphanPort && /trimmed|cache/i.test(orphanPort.getAttribute('title') || '')
     && /118/.test(orphanPort.getAttribute('title') || ''),
     'the inert tooltip blames the cache trim, not the data',
     orphanPort && orphanPort.getAttribute('title'));
  const orphanCve = valTag('Shodan', 'CVE-2999-9999');
  ok(orphanCve && !orphanCve.hasAttribute('data-ovf-open')
     && /capped at 20|no host row/i.test(orphanCve.getAttribute('title') || ''),
     'a CVE the per-host cap dropped explains itself instead of opening empty',
     orphanCve && orphanCve.getAttribute('title'));

  ok(sEl().querySelectorAll('.dr-tag[data-ovf-open]:not([role="button"])').length === 0
     && sEl().querySelectorAll('.dr-tag[data-ovf-open]:not([tabindex="0"])').length === 0,
     'every clickable value tag is keyboard-reachable');

  // The banner never becomes markup: it rides in the spec, and only the
  // synthesised "dr#N" id ever enters an attribute.
  ok(w.__pwned === undefined, 'a hostile FOFA banner does not execute', String(w.__pwned));
  const xssTag = valTag('FOFA.io', XSS_BANNER);
  ok(xssTag && xssTag.dataset.ovfOpen && /^dr#\d+$/.test(xssTag.dataset.ovfOpen),
     'a hostile banner still yields a usable drilldown handle',
     xssTag && xssTag.outerHTML.slice(0, 200));

  // The Link column must stay inert inside the modal too, not just on the card.
  w.eval(`ovfOpen(${JSON.stringify((valTag('FOFA.io', '80') || { dataset: {} }).dataset.ovfOpen || '')});`);
  const modalHtml = (w.document.getElementById('ovf-body') || {}).innerHTML || '';
  ok(!/<a\s[^>]*href/i.test(modalHtml),
     'the value drilldown never renders a clickable link to target infrastructure',
     modalHtml.slice(0, 300));
  w.eval('ovfClose();');

  // Specs are per-render; _ovfClear('dr') must still cover every one we add.
  const size1 = Number(w.eval('_OVF.size'));
  w.eval('renderDomainRecon(window.__drS);');
  const size2 = Number(w.eval('_OVF.size'));
  ok(size2 <= size1, 'a re-render does not leak drilldown specs', `${size1} -> ${size2}`);

  // The Shodan export and the drilldowns share one column list.
  const shCols = w.eval('JSON.stringify(buildDomainReconReport(window.__drS).sections.find(s => s.key === "shodan").blocks.filter(b => b.type === "table").map(b => b.columns)[0])');
  ok(shCols === w.eval('JSON.stringify(_SHODAN_COLS)'),
     'the Shodan report table uses the shared column list', shCols);
  const shCsv = w.eval('_reportToCSV(_reportSubset(buildDomainReconReport(window.__drS), "shodan"))');
  ok(/nginx/.test(shCsv) && /1\.18/.test(shCsv) && /Example Hosting/.test(shCsv),
     'the Shodan CSV now carries product, version and org', String(shCsv).slice(0, 400));

  console.log(failures ? `FAILED (${failures} of ${checks})` : `all ${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 350);
