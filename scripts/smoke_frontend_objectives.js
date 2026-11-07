#!/usr/bin/env node
/*
 * Headless smoke test for the Objectives tab's MULTIPLE target organizations.
 *
 * Why this exists
 * ---------------
 * The Objectives tab grew an `organizations` array so a campaign can target
 * several related organizations at once (name, domains, emails, urls, tech,
 * notes) and have SPOTTER map links between them. Three failure modes are
 * silent and worth pinning:
 *
 *   1. Backward compatibility. The legacy single-target fields (targetName /
 *      companyEmail / additionalIds) must keep working unchanged — saving the
 *      form must never rewrite or drop them, so every existing single-org
 *      consumer (WF13, _companyDomain, the Targets tab) keeps reading them.
 *   2. The unified list new consumers read (objAllOrganizations) must put the
 *      primary org — synthesised from the legacy fields — first, then the
 *      additional orgs. A workflow that reads only element 0 must still get the
 *      primary target.
 *   3. Persistence. The array must survive a save -> load round trip through
 *      the org cards, the export/import allowlist, and reach the WF13 payload
 *      and the LLM campaign-context tool.
 *
 *   node scripts/smoke_frontend_objectives.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed. Exit 2 = cannot run.
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

function setupCampaign(objectives) {
  w.localStorage.clear();
  const camp = { id: 'camp-1', name: 'Smoke', sketchId: 'sk-1', created: '2026-01-01T00:00:00Z',
                 objectives };
  w.localStorage.setItem('s.campaigns', JSON.stringify([camp]));
  w.localStorage.setItem('s.activeCamp', JSON.stringify(camp));
  return camp;
}

/* ── 1. defaults and normalisation ────────────────────────────────────────── */
section('defaults & normalisation');
ok(Array.isArray(w.objDefaults().organizations)
   && w.objDefaults().organizations.length === 0,
   'objDefaults() carries an empty organizations array');

const normed = w.objNormaliseOrgs([
  { name: 'A Corp', domains: 'a.com', emails: '', urls: '', tech: '', notes: '' },
  { name: '', domains: '', emails: '', urls: '', tech: '', notes: '' },   // all-empty -> dropped
  { name: '  B Corp  ', domains: ' b.com ', junk: 'ignored', emails: 42 }, // trim + coerce + drop unknown
  'not-an-object',
]);
ok(normed.length === 2, 'all-empty and non-object entries are dropped', JSON.stringify(normed));
ok(normed[0].name === 'A Corp' && normed[1].name === 'B Corp',
   'surviving names are trimmed', JSON.stringify(normed.map(o => o.name)));
ok(!('junk' in normed[1]), 'unknown fields are dropped', Object.keys(normed[1]).join(','));
ok(normed[1].emails === '42', 'non-string values are coerced to strings', typeof normed[1].emails);
ok(w.objNormaliseOrgs('nope').length === 0 && w.objNormaliseOrgs(undefined).length === 0,
   'a non-array value normalises to []');

/* ── 2. primary org from legacy fields ────────────────────────────────────── */
section('primary org from legacy fields');
const pOrg = w.objPrimaryOrgFromLegacy({
  targetType: 'organization', targetName: 'Example Holding',
  companyEmail: 'a@example.com', additionalIds: 'example.org, OOO Primer' });
ok(pOrg.name === 'Example Holding', 'an org-typed campaign seeds the primary org name', pOrg.name);
ok(pOrg.emails === 'a@example.com', 'the primary org carries the company email', pOrg.emails);
ok(pOrg.domains === 'example.com', 'and derives its domain from that email', pOrg.domains);
ok(pOrg.notes === 'example.org, OOO Primer', 'the additional identifiers land in notes', pOrg.notes);
ok(pOrg.primary === true, 'the primary org is flagged primary');

const pInd = w.objPrimaryOrgFromLegacy({
  targetType: 'individual', targetName: 'John Smith', companyEmail: 'j@corp.com' });
ok(pInd.name === '', 'an individual-typed campaign contributes no company name', pInd.name);
ok(pInd.domains === 'corp.com' && pInd.emails === 'j@corp.com',
   'but its employer domain/email are still carried', JSON.stringify(pInd));

/* ── 3. unified list ordering ─────────────────────────────────────────────── */
section('objAllOrganizations ordering');
const all = w.objAllOrganizations({
  targetType: 'organization', targetName: 'Primary Inc', companyEmail: 'x@primary.com',
  organizations: [{ name: 'Second Ltd', domains: 'second.com' },
                  { name: 'Third GmbH', domains: 'third.de' }] });
ok(all.length === 3, 'the unified list is primary + additional', all.length);
ok(all[0].name === 'Primary Inc' && all[0].primary === true,
   'the primary org is element 0', JSON.stringify(all[0]));
ok(all[1].name === 'Second Ltd' && all[2].name === 'Third GmbH',
   'the additional orgs follow in order', all.map(o => o.name).join(','));

const allEmptyPrimary = w.objAllOrganizations({
  targetType: 'individual', targetName: 'A Person',
  organizations: [{ name: 'Only Org', domains: 'only.com' }] });
ok(allEmptyPrimary.length === 1 && allEmptyPrimary[0].name === 'Only Org',
   'an empty primary org is omitted, leaving just the additional ones',
   JSON.stringify(allEmptyPrimary.map(o => o.name)));

/* ── 4. form round trip ───────────────────────────────────────────────────── */
section('form round trip');
setupCampaign({ targetType: 'organization', targetName: 'Primary Inc',
  additionalIds: 'id-1', companyEmail: 'a@primary.com', missionStatement: 'Mission.',
  socialRegions: ['ru'],
  organizations: [{ name: 'Second Ltd', domains: 'second.com', emails: 'hr@second.com',
                    urls: 'https://second.com', tech: 'Okta', notes: 'partner' }] });
w.loadObjectivesForm();
const cards = d.querySelectorAll('#obj-orgs [data-obj-org]');
ok(cards.length === 1, 'the stored additional org renders one card', cards.length);
ok(d.querySelector('#obj-orgs .oo-name').value === 'Second Ltd',
   'the card hydrates its name', d.querySelector('#obj-orgs .oo-name').value);
ok(d.querySelector('#obj-orgs .oo-tech').value === 'Okta', 'and its technologies');

// Add a second org through the UI entry point, fill it, and save.
w.objAddOrgCard();
const cards2 = d.querySelectorAll('#obj-orgs [data-obj-org]');
ok(cards2.length === 2, 'Add organization appends a blank card', cards2.length);
const nameInputs = d.querySelectorAll('#obj-orgs .oo-name');
nameInputs[1].value = 'Third GmbH';
d.querySelectorAll('#obj-orgs .oo-domains')[1].value = 'third.de';
w.saveObjectives();

const saved = JSON.parse(w.localStorage.getItem('s.activeCamp')).objectives;
ok(saved.organizations.length === 2,
   'both additional orgs persist on save', saved.organizations.length);
ok(saved.organizations[1].name === 'Third GmbH' && saved.organizations[1].domains === 'third.de',
   'the newly added org is saved with its fields', JSON.stringify(saved.organizations[1]));

/* The whole point: legacy single-org fields must survive untouched. */
ok(saved.targetName === 'Primary Inc', 'targetName is unchanged by the save', saved.targetName);
ok(saved.companyEmail === 'a@primary.com', 'companyEmail is unchanged', saved.companyEmail);
ok(saved.additionalIds === 'id-1', 'additionalIds is unchanged', saved.additionalIds);
ok(saved.missionStatement === 'Mission.', 'missionStatement is unchanged');
ok(JSON.stringify(saved.socialRegions) === JSON.stringify(['ru']),
   'socialRegions is unchanged', JSON.stringify(saved.socialRegions));

// An all-empty card must not be persisted as a phantom org.
w.objAddOrgCard();
w.saveObjectives();
const saved2 = JSON.parse(w.localStorage.getItem('s.activeCamp')).objectives;
ok(saved2.organizations.length === 2,
   'a blank card is dropped rather than saved as an empty org', saved2.organizations.length);

/* ── 5. reaching the WF13 payload ─────────────────────────────────────────── */
section('runDomainRecon payload carries organizations');
setupCampaign({ targetType: 'organization', targetName: 'Primary Inc',
  additionalIds: '', companyEmail: 'a@primary.com', missionStatement: '', socialRegions: [],
  organizations: [{ name: 'Second Ltd', domains: 'second.com' }] });
let captured = null;
w.fetchJson = async (url, opts) => {
  if (String(url).includes('/webhook/domain-recon')) {
    captured = { body: JSON.parse(opts.body) };
    return { domain: 'primary.com', errors: [] };
  }
  if (String(url).includes('list-campaigns')) return { campaigns: [] };
  return {};
};
(async () => {
  await w.runDomainRecon('primary.com', ['org']);
  ok(captured !== null, 'the domain-recon webhook was called');
  if (captured) {
    ok(Array.isArray(captured.body.organizations),
       'the payload carries an organizations array', typeof captured.body.organizations);
    ok(captured.body.organizations[0] && captured.body.organizations[0].name === 'Primary Inc',
       'with the primary org first', JSON.stringify(captured.body.organizations[0] || null));
    ok(captured.body.organizations.some(o => o.name === 'Second Ltd'),
       'and the additional org included', JSON.stringify(captured.body.organizations.map(o => o.name)));
    // legacy keys must still be present and unchanged
    ok(captured.body.company_name === 'Primary Inc',
       'the legacy company_name key is still sent', captured.body.company_name);
  }

  /* ── 6. the LLM campaign-context tool ───────────────────────────────────── */
  section('campaign-context tool');
  const ctx = w._toolCampaignContext();
  ok(ctx.objectives && Array.isArray(ctx.objectives.organizations),
     'the campaign-context tool exposes organizations', JSON.stringify(ctx.objectives && Object.keys(ctx.objectives)));
  ok(ctx.objectives.organizations.some(o => o.name === 'Second Ltd'),
     'including the additional org', JSON.stringify(ctx.objectives.organizations.map(o => o.name)));

  /* ── 7. import allowlist ────────────────────────────────────────────────── */
  section('export / import allowlist');
  // The import path rebuilds objectives from an explicit allowlist; organizations
  // must be in it or it silently fails to survive export -> import.
  const normimp = w.objNormaliseOrgs([{ name: 'Imported Co', domains: 'imp.com', bogus: 1 }]);
  ok(normimp.length === 1 && normimp[0].name === 'Imported Co' && !('bogus' in normimp[0]),
     'objNormaliseOrgs (used by the import allowlist) keeps known fields and drops the rest',
     JSON.stringify(normimp));
  const src = fs.readFileSync(INDEX, 'utf8');
  ok(/objectives:\s*\{[\s\S]*organizations:\s*objNormaliseOrgs\(o\.organizations\)/.test(src),
     'the import allowlist includes organizations');

  console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${checks - failures}/${checks} checks`);
  process.exit(failures ? 1 : 0);
})();
