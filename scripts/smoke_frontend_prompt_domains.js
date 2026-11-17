#!/usr/bin/env node
/*
 * Headless smoke test for Prompt-tab multi-domain objectives.
 *
 * Why this exists
 * ---------------
 * Objectives can name several domains: the Company Email Address host plus
 * domain-shaped Additional Identifiers (the placeholder even shows a
 * subsidiary). The Prompt tab treated the email host as THE campaign domain:
 *
 *   * _companyDomain() only reads companyEmail
 *   * get_osint_recon returned recs[0] only
 *   * the system prompt gated the whole objectives block on missionStatement
 *     and, when it did emit one, labelled a single "(domain: …)" from the email
 *
 * An operator with aerokon.su in the email field and two more domains in
 * Additional Identifiers watched every Prompt-tab query search aerokon.su.
 *
 * Asserted invariants:
 *   1. _splitIdentifiers splits the placeholder's middle dots AND commas
 *   2. _objectiveDomains collects every typed domain and rejects CIDRs / names
 *   3. _objectivesPromptBlock lists them all, even with no mission statement,
 *      and tells the model to query every one
 *   4. get_campaign_context.objectives.company_domains is the full list
 *   5. get_osint_recon with one cached recon + extra objective domains
 *      reports the missing ones and does not pretend the email host is alone
 *   6. two cached recon records both appear under by_domain
 *   7. domain= selects one
 *   8. a single-domain campaign keeps the original {domain, data} shape
 *   9. search_intel walks every recon record
 *  10. the data inventory names every objective domain
 *
 *   node scripts/smoke_frontend_prompt_domains.js
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

const CAMP = {
  id: 'camp-aero', name: 'Aero', sketchId: 'sk-aero',
  objectives: {
    targetType: 'organization',
    targetName: 'Aerokon',
    additionalIds: 'other.com · third.ru · 192.168.1.0/24 · OOO Primer',
    companyEmail: 'info@aerokon.su',
    missionStatement: '',
  },
};

function setCampaign(over) {
  const c = JSON.parse(JSON.stringify(Object.assign({}, CAMP, over || {})));
  if (over && over.objectives) c.objectives = Object.assign({}, CAMP.objectives, over.objectives);
  w.localStorage.setItem('s.campaigns', JSON.stringify([c]));
  w.localStorage.setItem('s.activeCamp', JSON.stringify(c));
  return c;
}

function seedRecon(domain, extra) {
  const recs = w.getDomainRecons();
  recs.unshift(Object.assign({
    id: 'r-' + domain, campaignId: CAMP.id, domain,
    timestamp: '2026-11-16T00:00:00Z',
    subdomains: [domain],
    web_assets: [{ url: 'https://www.' + domain + '/' }],
  }, extra || {}));
  w.localStorage.setItem('s.domainRecon', JSON.stringify(recs));
}

(async () => {
  section('helpers');
  ok(typeof w._splitIdentifiers === 'function', '_splitIdentifiers is a function declaration');
  ok(typeof w._objectiveDomains === 'function', '_objectiveDomains is a function declaration');
  ok(typeof w._objectivesPromptBlock === 'function', '_objectivesPromptBlock is a function declaration');
  ok(typeof w._activeRecons === 'function', '_activeRecons is a function declaration');

  ok(w._splitIdentifiers('a · b · c').join('|') === 'a|b|c',
     'middle dots split, matching the Objectives placeholder');
  ok(w._splitIdentifiers('a, b; c').join('|') === 'a|b|c',
     'commas and semicolons still split');
  ok(w._splitIdentifiers('AC/DC Industries').join('|') === 'AC/DC Industries',
     'a slash is left alone');

  setCampaign();
  const domains = w._objectiveDomains();
  ok(domains.includes('aerokon.su'), 'company-email host is a campaign domain', domains);
  ok(domains.includes('other.com'), 'a middle-dot Additional Identifier domain is collected', domains);
  ok(domains.includes('third.ru'), 'every additional domain is collected, not only the first', domains);
  ok(!domains.includes('1.0') && !domains.includes('192.168.1.0'),
     'a CIDR in Additional Identifiers is not a domain', domains);
  ok(!domains.some(d => /primer/i.test(d)),
     'a company name in Additional Identifiers is not a domain', domains);
  ok(domains[0] === 'aerokon.su',
     'the company-email host stays first so email-column derivation is unchanged', domains);

  const comma = w._objectiveDomains({
    companyEmail: 'ops@aerokon.su',
    additionalIds: 'other.com, third.ru',
  });
  ok(comma.includes('other.com') && comma.includes('third.ru'),
     'comma-separated Additional Identifiers parse the same way', comma);

  const fromName = w._objectiveDomains({ targetName: 'holdco.test', additionalIds: '' });
  ok(fromName.includes('holdco.test'),
     'a domain-shaped Primary Target is a campaign domain', fromName);

  section('system prompt');
  const block = w._objectivesPromptBlock();
  ok(/Campaign domains: aerokon\.su, other\.com, third\.ru/.test(block),
     'the Prompt-tab system prompt lists every objective domain', block);
  ok(/Query EVERY domain/.test(block),
     'and tells the model not to restrict itself to the email host', block);
  ok(/info@aerokon\.su/.test(block),
     'the company email is still present', block);
  ok(!/Mission Statement/.test(block),
     'an empty mission statement does not omit the domain list — that was the old gate',
     block);

  setCampaign({ objectives: { missionStatement: 'Stay in scope.' } });
  const withMission = w._objectivesPromptBlock();
  ok(/Stay in scope/.test(withMission) && /Campaign domains:/.test(withMission),
     'a filled mission statement still carries the domain list', withMission);

  section('campaign context');
  setCampaign();
  const ctx = w.executeSpotterTool('get_campaign_context', {});
  const ctxObj = (await ctx).objectives;
  ok(Array.isArray(ctxObj.company_domains)
     && ctxObj.company_domains.includes('aerokon.su')
     && ctxObj.company_domains.includes('other.com')
     && ctxObj.company_domains.includes('third.ru'),
     'get_campaign_context.objectives.company_domains is the full list',
     JSON.stringify(ctxObj.company_domains));
  ok(ctxObj.company_domain === 'aerokon.su',
     'company_domain stays the email host for older readers', ctxObj.company_domain);

  section('get_osint_recon — one cached recon, extra objective domains');
  w.localStorage.setItem('s.domainRecon', '[]');
  seedRecon('aerokon.su', { registrar: 'Example Registrar' });
  const one = await w.executeSpotterTool('get_osint_recon', { section: 'summary' });
  ok(one.status === 'ok', 'recon for the email host is still returned', JSON.stringify(one).slice(0, 200));
  ok(Array.isArray(one.objective_domains) && one.objective_domains.includes('other.com'),
     'objective_domains names the additional identifiers', one.objective_domains);
  ok(Array.isArray(one.domains_without_recon)
     && one.domains_without_recon.includes('other.com')
     && one.domains_without_recon.includes('third.ru'),
     'domains_without_recon names the ones that have not been recon\'d',
     one.domains_without_recon);
  ok(one.by_domain && one.by_domain['aerokon.su'],
     'multi-domain shape groups the cached recon under by_domain',
     Object.keys(one.by_domain || {}));
  ok(/multiple domains/i.test(one.note || '') && /other\.com/.test(one.note || ''),
     'the note tells the model to query every domain, not only aerokon.su', one.note);

  section('get_osint_recon — two cached records');
  seedRecon('other.com', { registrar: 'Other Registrar' });
  const two = await w.executeSpotterTool('get_osint_recon', { section: 'summary' });
  ok(two.by_domain && two.by_domain['aerokon.su'] && two.by_domain['other.com'],
     'both cached domains appear under by_domain', Object.keys(two.by_domain || {}));
  ok((two.domains || []).includes('aerokon.su') && (two.domains || []).includes('other.com'),
     'domains lists both cached hosts', two.domains);
  ok((two.domains_without_recon || []).includes('third.ru'),
     'the third objective domain is still reported missing', two.domains_without_recon);

  const filtered = await w.executeSpotterTool('get_osint_recon', {
    section: 'summary', domain: 'other.com',
  });
  ok(filtered.domain === 'other.com' && filtered.data,
     'domain= selects that recon', filtered.domain);
  ok(!filtered.by_domain, 'a filtered call uses the single-record shape', filtered.by_domain);

  section('get_osint_recon — single-domain campaign keeps the old shape');
  setCampaign({
    objectives: {
      targetType: 'organization', targetName: 'Example',
      additionalIds: '', companyEmail: 'a@example.com', missionStatement: '',
    },
  });
  w.localStorage.setItem('s.domainRecon', JSON.stringify([{
    id: 'r-ex', campaignId: CAMP.id, domain: 'example.com',
    timestamp: '2026-11-16T00:00:00Z', registrar: 'Ex',
  }]));
  const single = await w.executeSpotterTool('get_osint_recon', { section: 'summary' });
  ok(single.domain === 'example.com' && single.data && !single.by_domain,
     'a one-domain campaign still returns {domain, data} with no by_domain wrapper',
     JSON.stringify({ domain: single.domain, keys: Object.keys(single) }));

  section('search_intel walks every recon record');
  setCampaign();
  w.localStorage.setItem('s.domainRecon', '[]');
  seedRecon('aerokon.su', { website_title: 'Aerokon Home' });
  seedRecon('other.com', { website_title: 'Other Home' });
  const hits = await w.executeSpotterTool('search_intel', { query: 'home', limit: 20 });
  const sources = (hits.hits || []).map(h => h.source).join(' ');
  ok(/osint_domain_recon\[aerokon\.su\]/.test(sources),
     'search_intel hits the email-host recon', sources);
  ok(/osint_domain_recon\[other\.com\]/.test(sources),
     'and the additional-identifier recon — it used to scan recs[0] only', sources);

  section('inventory names every objective domain');
  const inv = w.spotterDataInventory();
  const osint = inv.items.find(i => i.tool === 'get_osint_recon');
  ok(osint && /aerokon\.su/.test(osint.detail) && /other\.com/.test(osint.detail),
     'inventory detail names more than the email host', osint && osint.detail);
  ok(osint && /query ALL/i.test(osint.detail),
     'and tells the model to query all of them', osint && osint.detail);

  console.log(`\n${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
})().catch(err => {
  console.error(err);
  process.exit(1);
});
