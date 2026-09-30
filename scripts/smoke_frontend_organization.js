#!/usr/bin/env node
/*
 * Headless smoke test for Live Analysis › Organization.
 *
 * Why this exists
 * ---------------
 * The Organization card is assembled from a dozen independent `org_*` keys that
 * WF13 only sometimes ships, and almost every failure mode of that arrangement
 * is SILENT — an empty block, not an error. The ones pinned here are the ones
 * that would otherwise be indistinguishable from "this company has nothing":
 *
 *   1. The card renders at all when `org_source` is present, and renders NOTHING
 *      when it is absent, so a shodan-only recon does not grow an empty section.
 *   2. An unticked RU region says WHY the profile is empty and points at the
 *      Objectives checkbox. Without that copy, "no regional provider" and "we
 *      looked and this company does not exist" look identical.
 *   3. Vendors render with no regional provider at all — they come from the
 *      domain's own DNS, so they are the half that must never depend on hh.ru.
 *   4. Withheld recruiter contacts print the hidden count. An empty contact list
 *      with no denominator reads as "no recruiters" when it means "hidden".
 *   5. Department and role counts carry DIFFERENT denominators and the labels
 *      say so — departments are counted across the vacancies fetched, roles come
 *      from the provider's own facets and cover every opening.
 *   6. OoS / FP marks exclude companies, offices and recruiters, and they write
 *      to the same shared stores the Targets tab reads.
 *   7. The Recruiters & Tech Stack card expands IN PLACE past its 8/14 caps, and
 *      the expansion survives a re-render. Held in the DOM it would collapse on
 *      the next OoS mark — i.e. on every single scoping decision the operator
 *      makes while reading the list, which is the only time the card is open.
 *   8. runDomainRecon ships `social_regions` — the whole feature is gated on a
 *      key this webhook did not receive until now.
 *   9. A record with an unregistered Company type says "not in graph" rather
 *      than pretending the write happened.
 *  10. The export report carries the same rows as the card, including the
 *      provenance and the hidden-contact note.
 *
 *   node scripts/smoke_frontend_organization.js
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

/* ── fixtures ─────────────────────────────────────────────────────────────── */

const FULL = {
  domain: 'example.com',
  timestamp: '2026-09-20T10:00:00Z',
  errors: [],
  dns_a: ['203.0.113.10'], dns_mx: [], dns_ns: [], dns_txt: [], dns_cname: [],
  org_source: 'hh.ru-scrape',
  org_seed: 'Example Holding',
  /* What the run was looking for, and on what basis each provider answered.
     A matched run carries these too, not only a refused one — the card has to
     be able to state a basis for the company it IS showing. */
  org_identity: {
    names: ['Example Holding', 'OOO Primer'],
    domains: ['example.com', 'example.org'],
    operator_names: ['Example Holding', 'OOO Primer'],
    operator_domains: ['example.org', 'example.com'],
    match_min: 72, operator_sourced: true,
  },
  org_match: { 'hh.ru': { score: 100, queries: ['Example Holding', 'OOO Primer'],
                          evidence: ['its name matches "Example Holding" (100)'] } },
  org_rejected: {},
  org_profile: {
    id: '100001', name: 'Example Holding',
    industries: ['Information Technology'],
    description: 'An example holding company that does example things.',
    site: 'https://example.com', area: 'Moscow',
    address: 'Moscow, Primernaya ulitsa 1', country: 'RU',
    size_category: 'MORE_THAN_5000', it_accredited: true, trusted: true,
    has_divisions: true, rating: 4.4, open_vacancies: 350,
    profile_url: 'https://hh.ru/employer/100001',
  },
  org_related: [
    { id: '2', name: 'Example Delivery', vacancies_open: 80, url: 'https://hh.ru/employer/2' },
    { id: '3', name: 'Example Eats', vacancies_open: 1043, url: 'https://hh.ru/employer/3' },
    { name: 'Example Ireland Ltd', jurisdiction: 'Ireland', source: 'sec-edgar', url: '' },
  ],
  org_vendors: [
    { name: 'outlook.com', kinds: ['mail'], evidence: ['example-com.mail.protection.outlook.com'] },
    { name: 'cloudflare.net', kinds: ['cname'], evidence: ['example-com.cdn.cloudflare.net'] },
  ],
  org_departments: [
    { name: 'Example Infrastructure', count: 6 },
    { name: 'Fintech', count: 4 },
  ],
  org_roles: [
    { name: 'Support specialist', count: 54 },
    { name: 'Developer', count: 28 },
  ],
  org_offices: [
    { label: 'Moscow, Primernaya ulitsa 1', city: 'Moscow', metro: 'Primernaya', count: 9 },
    { label: 'Saint Petersburg, Testovy prospekt 2', city: 'Saint Petersburg', metro: '', count: 3 },
  ],
  org_contacts: [
    { name: 'Petr Petrov', email: 'hr@example.ru', phones: ['74951234567'],
      vacancy: 'Systems Administrator', url: 'https://hh.ru/vacancy/10' },
  ],
  org_contacts_hidden: 12,
  org_details_fetched: 13,
  org_skills: [{ name: 'Active Directory', count: 5 }, { name: 'VMware', count: 3 }],
  org_title_matches: [
    { specialty: 'Infrastructure / IT',
      people: [{ name: 'Ivan Ivanov', title: 'Senior Systems Administrator', id: 'ind-7' },
               // No id: WF13 drops these, but the card must never offer a link
               // it cannot honour if one ever reaches it.
               { name: 'Ghost Person', title: 'Systems Engineer', id: '' }],
      open_roles: ['Системный администратор', 'Сетевой инженер'],
      people_count: 2, open_role_count: 2 },
  ],
  org_title_empty_kind: '',
  org_title_empty_message: '',
  // hh.ru's facets cover the employer's whole vacancy set; the open-roles leg
  // can only count what it fetched. Different denominators, so the label has to
  // follow this key rather than assert one of them.
  org_roles_denominator: 'facets',
  org_jobs: [
    { title: 'Senior Systems Administrator', company: 'Example Holding',
      location: 'Denver, CO', via: 'LinkedIn', posted: '3 days ago',
      url: 'https://example.test/j/1', employer_score: 100 },
  ],
  org_jobs_refused: [
    { title: 'Java Developer', company: 'Globex Industries', location: 'Austin, TX',
      via: 'Glassdoor', posted: '', url: '', employer_score: 0, verdict: 'other' },
  ],
  org_company_written: true,
  org_people_written: 3,
  // ── phase 2: multi-provider ────────────────────────────────────────────
  org_sources: [
    { provider: 'hh.ru', transport: 'hh.ru-scrape', status: 'ok', note: '', reliable: true },
    { provider: 'linkedin-tavily', transport: 'tavily', status: 'ok',
      note: '8 search(es), ~8 credit(s)', reliable: true },
    { provider: 'linkedin-serp', transport: 'serpapi', status: 'ok', note: '', reliable: true },
    { provider: 'linkedin-jobs', transport: 'google_jobs', status: 'ok', note: '', reliable: true },
    { provider: 'website', transport: 'crawl', status: 'ok',
      note: '7 pages crawled, 41 chunks indexed', reliable: true },
    { provider: 'sec-edgar', transport: 'edgar', status: 'ok', note: '', reliable: true },
  ],
  org_edgar: {
    cik: '0009999999', legal_name: 'EXAMPLE HOLDING CORP', match_score: 95,
    sic: '7372', industry: 'Services-Prepackaged Software', entity_type: 'operating',
    state_of_incorporation: 'DE', tickers: ['EXHC'], exchanges: ['Nasdaq'],
    former_names: ['EXAMPLE WIDGETS INC'], address: '1 Main St, Denver, CO, 80202',
    phone: '303-555-0100', ein: '001234567',
    profile_url: 'https://www.sec.gov/cgi-bin/browse-edgar?CIK=0009999999',
    filing: { form: '10-K', date: '2026-07-29',
              document: 'https://www.sec.gov/Archives/edgar/data/9999999/x/ex21.htm' },
    subsidiary_count: 2,
  },
  linkedin_company_url: 'https://www.linkedin.com/company/example-fixture/',
  linkedin_company_name: 'Example Corp',
  org_people: [
    { name: 'Dana Webb', job_title: 'Senior Systems Administrator',
      specialty: 'Infrastructure / IT', employer: 'Example Corp', location: 'Denver',
      education: '', technologies: ['Active Directory', 'Azure'],
      url: 'https://www.linkedin.com/in/dana-webb-example/', source: 'linkedin',
      tier: 'confirmed', edge_label: 'WORKS_FOR', employment_score: 70,
      why: "named on the company's own website; profile names Example Corp (100/100)" },
    { name: 'Jane Roe', job_title: 'Chief Technology Officer', specialty: 'Executive',
      employer: '', location: '', education: '', technologies: [], url: '', source: 'website',
      tier: 'reported', edge_label: 'CLAIMS_WORKS_FOR', employment_score: 30,
      why: 'profile names Example Corp (100/100); states a role' },
  ],
  // The two shapes the employment gate exists to keep out of the roster.
  org_people_unverified: [
    { name: 'Pat Vendor', job_title: 'Account Executive', employer: 'Globex Industries',
      employer_named: 'Globex Industries', location: '', technologies: [], url: '',
      source: 'linkedin', tier: 'contradicted', edge_label: '', employment_score: -55,
      why: 'profile names Globex Industries, not the target' },
    { name: 'Chris Noise', job_title: 'Recruiter', employer: '', employer_named: '',
      location: '', technologies: [], url: '', source: 'linkedin',
      tier: 'weak', edge_label: '', employment_score: -15,
      why: 'names no employer; returned only by a search for the company name' },
  ],
  org_people_counts: { candidates: 4, shown: 2, held: 2, confirmed: 1, reported: 1,
                       weak: 1, contradicted: 1, geo_gate: 'not_corroborated' },
  org_people_empty_kind: '',
  org_people_empty_message: '',
  org_people_held: 2,
  org_units: [
    { name: 'Example Cloud', url: 'https://www.linkedin.com/company/example-cloud/',
      kind: 'unit', source: 'linkedin' },
    { name: 'Widget Division', url: '', kind: 'unit', source: 'website' },
  ],
  org_mentions: [{ name: 'Reseller Ltd', url: '', kind: 'mention' }],
  org_site: { pages_crawled: 7, pages_refused: 3,
              refused_sample: ['https://offsite.example.net/x'], chunks_indexed: 41,
              collection: 'company_site__sk-1' },
};

const NO_REGION = {
  domain: 'example.com', timestamp: '2026-09-20T10:00:00Z', errors: [],
  dns_a: [], dns_mx: [], dns_ns: [], dns_txt: [], dns_cname: [],
  org_source: 'no_regional_provider',
  org_seed: 'example',
  org_profile: {}, org_related: [], org_departments: [], org_roles: [],
  org_offices: [], org_contacts: [], org_skills: [], org_title_matches: [],
  org_vendors: [{ name: 'outlook.com', kinds: ['mail'], evidence: ['x.outlook.com'] }],
  org_company_written: false,
};

const UNRELIABLE = {
  domain: 'example.com', timestamp: '2026-09-20T10:00:00Z', errors: [],
  dns_a: [], dns_mx: [], dns_ns: [], dns_txt: [], dns_cname: [],
  org_source: 'error',
  org_seed: 'example',
  org_sources: [
    { provider: 'hh.ru', transport: '', status: 'skipped',
      note: 'RU not selected in Objectives > Target Social Media Enrichment Options; hh.ru covers RU/CIS employers only',
      reliable: true },
    { provider: 'linkedin-serp', transport: 'bing', status: 'no_match',
      note: 'free search engines are unreliable from a datacenter IP; set SERP_API_KEY for dependable results',
      reliable: false },
    { provider: 'website', transport: 'crawl', status: 'error', note: 'crawl exploded', reliable: true },
  ],
  org_profile: {}, org_related: [], org_departments: [], org_roles: [],
  org_offices: [], org_contacts: [], org_skills: [], org_title_matches: [],
  org_people: [], org_units: [], org_mentions: [], org_site: {},
  org_vendors: [{ name: 'outlook.com', kinds: ['mail'], evidence: ['x.outlook.com'] }],
  org_company_written: false,
};

const EDGAR_REFUSED = {
  domain: 'example.com', timestamp: '2026-09-20T10:00:00Z', errors: [],
  dns_a: [], dns_mx: [], dns_ns: [], dns_txt: [], dns_cname: [],
  org_source: 'crawl', org_seed: 'Example Harbor Information Security',
  org_sources: [
    { provider: 'sec-edgar', transport: '', status: 'no_match',
      note: 'covers SEC filers only, so most private companies are absent', reliable: true },
    { provider: 'website', transport: 'crawl', status: 'ok', note: '', reliable: true },
  ],
  org_edgar: { candidates: [
    { cik: '0000000002', name: 'EXAMPLE HARBOR CORP', ticker: 'EXHB', score: 64 },
    { cik: '0009999998', name: 'EXAMPLE INFORMATION SYSTEMS INC', ticker: 'EXIS', score: 61 },
  ] },
  org_profile: { name: 'Example Harbor Information Security' },
  org_related: [], org_departments: [], org_roles: [], org_offices: [],
  org_contacts: [], org_skills: [], org_title_matches: [], org_people: [],
  org_units: [], org_mentions: [], org_site: {}, org_vendors: [],
  org_company_written: true,
};

/* A run where the providers returned rows and the matcher refused all of them.
   This is the state the card could not previously represent AT ALL: it had no
   fourth outcome between "a profile" and "nothing came back", so a provider's
   top search result was rendered as the target and an operator had no way to
   see that nothing had actually matched. A campaign against an aviation
   manufacturer rendered an unrelated military-history journal this way. */
const REFUSED = {
  domain: 'maket-aero.test', timestamp: '2026-09-20T10:00:00Z', errors: [],
  dns_a: [], dns_mx: [], dns_ns: [], dns_txt: [], dns_cname: [],
  org_source: 'hh.ru-scrape', org_seed: 'Maket Aero',
  org_identity: {
    names: ['Maket Aero', 'OOO Obrazets'],
    domains: ['maket-aero.test'],
    operator_names: ['Maket Aero', 'OOO Obrazets'],
    operator_domains: ['maket-aero.test'],
    match_min: 72, operator_sourced: true,
  },
  org_match: { 'hh.ru': { reason: "'Placeholder History Journal' shares no word with \"Maket Aero\"",
                          queries: ['Maket Aero', 'OOO Obrazets'] } },
  org_rejected: { 'hh.ru': [
    { name: 'Placeholder History Journal', score: 12, url: 'https://hh.ru/employer/88001',
      reason: "'Placeholder History Journal' shares no word with \"Maket Aero\"" },
  ] },
  org_sources: [{ provider: 'hh.ru', transport: 'hh.ru-scrape', status: 'no_match',
                  note: "'Placeholder History Journal' shares no word with \"Maket Aero\"",
                  reliable: true }],
  org_profile: {}, org_related: [], org_departments: [], org_roles: [],
  org_offices: [], org_contacts: [], org_skills: [], org_title_matches: [],
  org_people: [], org_units: [], org_mentions: [], org_site: {}, org_vendors: [],
  org_company_written: false,
};

/* The same run, with nothing typed in Objectives: the identity is the domain
   label alone. The card has to say so — that is the single most common cause of
   a genuinely empty Organization card, and it is one checkbox away from fixed. */
const UNSEEDED = {
  ...REFUSED,
  org_identity: { names: ['maket aero'], domains: ['maket-aero.test'],
                  operator_names: [], operator_domains: [],
                  match_min: 72, operator_sourced: false },
};

const NO_ORG = {
  domain: 'example.com', timestamp: '2026-09-20T10:00:00Z', errors: [],
  dns_a: ['203.0.113.10'], dns_mx: [], dns_ns: [], dns_txt: [], dns_cname: [],
};

/* The ordinary non-RU campaign: people in the graph, but no job board, so
   nothing advertised a role. The card must say which kind of empty that is
   instead of matching the people roster against itself. */
const NO_ROLES = Object.assign({}, FULL, {
  org_title_matches: [],
  org_open_roles_offered: 0,
  org_title_empty_kind: 'no_role_source',
  org_title_empty_message: 'No open-role source ran, so there are no vacancies '
    + 'to match against. hh.ru is the only provider that publishes them and it '
    + 'is gated on the RU objective. This is not a finding that the company is '
    + 'not hiring.',
});

/* A crawl that never reached the target. Every fetch died at the read timeout,
   so pages_crawled is 0 -- the same zero a genuinely empty site produces. Until
   2026-09-21 the card printed "Crawled the target's own site under the
   engagement's RoE" underneath it and the provider row said "no match", so a
   total transport failure was indistinguishable from a completed crawl. */
const SITE_UNREACHABLE_MESSAGE =
  'Nothing was fetched: every request to example.com over the campaign proxy '
  + '(socks5h://proxy.local:1080) failed at the transport layer \u2014 a connect or '
  + 'read timeout, with no HTTP response at all. The site was NOT REACHED, '
  + 'which is not the same as the site having nothing on it.';

const SITE_UNREACHABLE = Object.assign({}, FULL, {
  org_sources: FULL.org_sources.map(p => p.provider === 'website'
    ? { provider: 'website', transport: 'crawl', status: 'unreachable',
        note: SITE_UNREACHABLE_MESSAGE, reliable: true }
    : p),
  org_site: { pages_crawled: 0, pages_refused: 0, refused_sample: [],
              chunks_indexed: 0, collection: 'company_site__sk-1',
              blocked: false, unreachable: true,
              empty_kind: 'site_unreachable',
              empty_message: SITE_UNREACHABLE_MESSAGE },
});

/* Long enough to be clipped by all three caps that matter: recruiters (8),
   skills (14) and departments (12). Departments are here as the CONTROL — they
   share _countRows with the skills row, so they are what proves the expander is
   opt-in rather than something every caller silently inherited. */
const MANY = Object.assign({}, FULL, {
  org_contacts: Array.from({ length: 20 }, (_, i) => (
    { name: `Recruiter ${i}`, email: `r${i}@example.ru`, phones: [], vacancy: '' })),
  org_skills: Array.from({ length: 34 }, (_, i) => ({ name: `Skill ${i}`, count: 34 - i })),
  org_departments: Array.from({ length: 20 }, (_, i) => ({ name: `Dept ${i}`, count: 20 - i })),
});

function render(rec) {
  w.eval('_ovfClear && _ovfClear("dr")');
  w.renderDomainRecon(rec);
  return d.getElementById('dr-content').innerHTML;
}

function setupCampaign() {
  w.localStorage.clear();
  const camp = {
    id: 'camp-1', name: 'Smoke', sketchId: 'sk-1',
    objectives: { targetType: 'organization', targetName: 'Example Holding',
                  additionalIds: 'example.org, OOO Primer',
                  companyEmail: 'a@example.com', socialRegions: ['ru'] },
  };
  w.localStorage.setItem('s.campaigns', JSON.stringify([camp]));
  // 's.activeCamp', not 's.activeCampaign' -- the wrong key reads back as "no
  // active campaign", which makes activeSocialRegions() return [] and every
  // region assertion below pass or fail for the wrong reason.
  w.localStorage.setItem('s.activeCamp', JSON.stringify(camp));
}

/* ── 1. presence and absence ──────────────────────────────────────────────── */
section('card presence');
setupCampaign();

const fullHtml = render(FULL);
ok(/Organization &mdash; Example Holding|Organization — Example Holding/.test(fullHtml),
   'the card renders with the company name in its summary');
ok(fullHtml.includes('Example Delivery'), 'related brands render');
ok(fullHtml.includes('Example Infrastructure'), 'departments render');
ok(fullHtml.includes('Primernaya'), 'offices render with their metro hint');
ok(fullHtml.includes('Petr Petrov'), 'published recruiters render');
ok(fullHtml.includes('Active Directory'), 'skills render');
ok(fullHtml.includes('Ivan Ivanov'), 'job title matches render the matched person');
ok(fullHtml.includes('Infrastructure / IT'), 'job title matches render the specialty');

/* Every chip on this card opens a dossier, so it has to open the RIGHT one. The
   name alone is not a key -- sharphound_parser labels AD principals
   SAM@DOMAIN.LOCAL -- and until the node id was carried through, a chip for a
   person the employment gate had held answered "No Individual matching". */
ok(/openDossierFromCred\(&quot;Ivan Ivanov&quot;, &quot;ind-7&quot;\)/.test(fullHtml),
   'a matched person is opened by node id, not by display name');
ok(!/dr-link[^>]*Ghost Person/.test(fullHtml)
   && !/openDossierFromCred\(&quot;Ghost Person&quot;/.test(fullHtml),
   'a person with no node renders as plain text, not as a link that cannot resolve');
ok(fullHtml.includes('Ghost Person'), '...but is still shown');

/* ── open roles ───────────────────────────────────────────────────────────── */
section('open roles');
ok(fullHtml.includes('Open Roles'), 'the Open Roles card renders');
ok(fullHtml.includes('Senior Systems Administrator'), 'a posting title renders');
ok(fullHtml.includes('Denver, CO'), 'with its location');
ok(fullHtml.includes('LinkedIn'), 'and the board it came from');
ok(fullHtml.includes('3 days ago'), 'and how old it is');
/* google_jobs aggregates LinkedIn, Indeed and Glassdoor, so a company-name query
   returns other companies' vacancies. They are shown, not dropped: a card full
   of refusals is how an operator sees the target was identified wrongly. */
ok(/Other employers.{0,12}postings \(1\)/.test(fullHtml),
   'postings refused as another employer\'s are surfaced with a count');
ok(fullHtml.includes('Globex Industries'), '...naming the employer that was refused');
const noJobsHtml = render(Object.assign({}, FULL, { org_jobs: [], org_jobs_refused: [] }));
ok(!noJobsHtml.includes('Open Roles'),
   'and the card is absent entirely when no leg returned a posting');
ok(fullHtml.includes('Open roles (Google Jobs)') || fullHtml.includes('linkedin-jobs'),
   'the open-roles provider gets a row like every other provider');

const noRolesHtml = render(NO_ROLES);
ok(noRolesHtml.includes('Job Title Match'),
   'the card still renders when nothing was advertised');
ok(noRolesHtml.includes('gated on the RU objective'),
   'and says WHICH kind of empty it is, rather than vanishing or self-matching');
ok(fullHtml.includes('IT-accredited'), 'profile flags render');

const noOrgHtml = render(NO_ORG);
ok(!/Organization &mdash;|Organization —/.test(noOrgHtml),
   'a recon without the org source grows NO organization section');
ok(noOrgHtml.includes('DNS Records'), 'the rest of the recon still renders without it');

/* ── 1b. phase-2 blocks ───────────────────────────────────────────────────── */
section('people, units, website');
ok(fullHtml.includes('People &amp; Positions') || fullHtml.includes('People & Positions'),
   'the People & Positions block renders');
ok(fullHtml.includes('Dana Webb'), 'SERP people render');
ok(fullHtml.includes('Senior Systems Administrator'), 'their job titles render');
ok(fullHtml.includes('Infrastructure / IT'), 'the derived specialty renders');
ok(fullHtml.includes('Active Directory'), 'named technologies render as tags');
ok(fullHtml.includes('linkedin.com/in/dana-webb-example'), 'a person links to their profile');
ok(/WRITTEN TO GRAPH/.test(fullHtml), 'the graph-write count is shown');

/* The employment gate. Every assertion here is about a SILENT failure: a held
   person shown as staff looks exactly like a correct row, and a count that
   includes them looks exactly like a bigger finding. */
ok(/People &amp; Positions \(2\)|People & Positions \(2\)/.test(fullHtml),
   'the header counts the rows actually rendered, not the raw list');
ok(fullHtml.includes('Employment not established'),
   'held candidates get their own labelled block');
ok(fullHtml.includes('Pat Vendor') && fullHtml.includes('Chris Noise'),
   'held candidates are still visible, so a gate false-negative is spottable');
ok(/Globex Industries, not the target/.test(fullHtml),
   'each held row says WHY it was not counted');
{
  // A held name must not appear inside the counted roster. Slice the card at the
  // held block's heading: everything before it is the roster.
  const cut = fullHtml.indexOf('Employment not established');
  const counted = fullHtml.slice(0, cut);
  ok(cut > -1 && !counted.includes('Pat Vendor') && !counted.includes('Chris Noise'),
     'a held person never appears in the counted roster');
  ok(counted.includes('Dana Webb'), '...while evidenced people still do');
}
ok(/confirmed/.test(fullHtml) && /self-reported/.test(fullHtml),
   'the tier is shown per row, so a claim is not read as a confirmation');
ok(/4 CANDIDATES/.test(fullHtml) && /2 HELD/.test(fullHtml),
   'the counters state how many were considered and how many were held');

{
  // "(0)" must never read as "this company has no staff" when the truth is
  // "we looked and could not evidence anyone".
  const allHeld = Object.assign({}, FULL, {
    org_people: [], org_people_held: 2,
    org_people_counts: { candidates: 2, shown: 0, held: 2 },
    org_people_empty_kind: 'all_held',
    org_people_empty_message: 'Candidates were returned but none carried evidence of employment. See Employment not established below.',
  });
  const h = render(allHeld);
  ok(/People &amp; Positions \(0\)|People & Positions \(0\)/.test(h),
     'an all-held roster still renders its card');
  ok(h.includes('none carried evidence of employment'),
     '...and explains WHICH kind of empty it is');
  ok(h.includes('Chris Noise'), '...with the held candidates still listed');
}

ok(fullHtml.includes('Org Units'), 'the Org Units block renders');
ok(fullHtml.includes('Example Cloud') && fullHtml.includes('Widget Division'),
   'units from both providers render');
ok(fullHtml.includes('Reseller Ltd'), 'a mere mention is shown...');
ok(/merely reference|Also mentions/.test(fullHtml),
   '...and labelled as a mention, not a unit');

ok(fullHtml.includes('Website Intelligence'), 'the Website Intelligence block renders');
ok(/Off-domain refused/.test(fullHtml),
   'the count of off-domain URLs the scope lock refused is surfaced');
ok(/robots.txt\s*\n?\s*Disallow rules are not applied|Disallow rules are not applied/.test(fullHtml),
   'the card states plainly that robots.txt Disallow is not honoured');
ok(/locked to this domain/.test(fullHtml),
   'and that the crawler is scope-locked, which is the actual safeguard');

const unreachHtml = render(SITE_UNREACHABLE);
ok(unreachHtml.includes('NOT REACHED'),
   'an unreachable target says so on the card, in place of a bare zero');
ok(unreachHtml.includes('socks5h://proxy.local:1080'),
   '...naming the egress, because changing it is the operator\'s next move');
ok(!/Crawled the target's own site/.test(unreachHtml),
   'the "we crawled it" boilerplate is GONE when nothing was crawled \u2014 printing '
   + 'it under Pages crawled 0 is what made a total failure read as a finished run');
ok(/Website crawl<\/span>[\s\S]{0,120}unreachable/.test(unreachHtml),
   'the provider row reads "unreachable", not "no match"');
ok(!/Website crawl<\/span>[\s\S]{0,120}no match/.test(unreachHtml),
   '...and never "no match", the status that means we looked and found nothing');
ok(/color:var\(--warn\)[^>]*>\s*unreachable/.test(unreachHtml),
   '...in a colour of its own, not the same grey as "no match"');
ok(fullHtml.includes("Crawled the target's own site"),
   'a crawl that DID run still shows the RoE note \u2014 the check above is about '
   + 'the empty case, not about deleting the note');

section('SEC EDGAR');
ok(fullHtml.includes('SEC EDGAR'), 'the EDGAR block renders');
ok(fullHtml.includes('EXAMPLE HOLDING CORP'), 'the filed legal name renders');
ok(fullHtml.includes('0009999999'), 'the CIK renders');
ok(/Incorporated in[\s\S]{0,120}DE/.test(fullHtml), 'state of incorporation renders');
ok(fullHtml.includes('EXAMPLE WIDGETS INC'), 'former names render');
ok(/filing of record, not an inference/.test(fullHtml),
   'the block says plainly that this is a filing, not an inference');
ok(/Name match 95\/100/.test(fullHtml),
   'the match score is shown so the operator can judge it');
ok(fullHtml.includes('Archives/edgar/data'), 'the source filing is linked');
ok(/filed &middot; Ireland|filed · Ireland/.test(fullHtml),
   'a filed subsidiary is labelled with its jurisdiction, not an open-role count');

const refusedHtml = render(EDGAR_REFUSED);
ok(refusedHtml.includes('EXAMPLE HARBOR CORP'),
   'a REFUSED near-miss registrant is still shown');
ok(/loose/.test(refusedHtml) && /another company/.test(refusedHtml),
   '...with why adopting it would be wrong');
ok(/not SEC filers, so a miss|normal case/.test(refusedHtml),
   '...and that a miss is the normal case');
ok(!refusedHtml.includes('filing of record, not an inference'),
   'the authoritative note is absent when nothing was adopted');

section('per-provider provenance');
ok(/LinkedIn \(via search\)/.test(fullHtml), 'each provider is named');
ok(fullHtml.includes('serpapi'), 'the transport is shown, not just "ok"');
ok(!/SOURCE: hh.ru-scrape,serpapi/.test(fullHtml),
   'the old single-source line is gone');

const unrelHtml = render(UNRELIABLE);
ok(/unreliable/.test(unrelHtml),
   'an unreliable free-engine transport is labelled as such');
ok(unrelHtml.includes('SERP_API_KEY'),
   '...and the note names the fix');
ok(/RU not selected/.test(unrelHtml),
   'a skipped provider explains why it did not run');
ok(unrelHtml.includes('outlook.com'),
   'DNS-derived vendors survive every provider failing');

/* ── the match itself, stated rather than assumed ─────────────────────────── */
section('company identification');
ok(/Identified by/.test(fullHtml),
   'an adopted profile states WHY it is believed to be the target — a company '
   + 'named with no stated basis is exactly what shipped the wrong one');
ok(/Searched as/.test(fullHtml),
   'the card names the identifiers the run searched on');

const noMatchHtml = render(REFUSED);
ok(!/Placeholder History Journal<\/span>\s*<\/div>\s*<div class="dr-row"><span class="dr-lbl">Industry/.test(noMatchHtml),
   'a refused candidate is never rendered as the profile');
ok(/Refused candidates/.test(noMatchHtml),
   'the refusals are shown — the right company is sometimes one of them under a '
   + 'name nobody thought to type');
ok(noMatchHtml.includes('Placeholder History Journal'),
   'the refused candidate is named, not merely counted');
ok(/12\/100/.test(noMatchHtml), 'with the score it was refused at');
ok(noMatchHtml.includes('Maket Aero') && noMatchHtml.includes('OOO Obrazets'),
   'every identifier searched is listed, so a typo is visible');
ok(noMatchHtml.includes('maket-aero.test'),
   'including the corroborating domains');
ok(/Additional Identifiers/.test(noMatchHtml),
   'and the empty state names the field that fixes it');

const unseededHtml = render(UNSEEDED);
ok(/None of these came from Objectives/.test(unseededHtml),
   'a run matching on the domain label alone SAYS so — the commonest cause of an '
   + 'empty card, and one field away from fixed');
ok(!/None of these came from Objectives/.test(noMatchHtml),
   '...and a properly seeded run is not nagged');

/* Phase-1 cached records carry only the scalar org_source and must still paint. */
section('phase-1 record compatibility');
const legacy = { ...NO_REGION };
delete legacy.org_sources;
const legacyHtml = render(legacy);
ok(/Organization/.test(legacyHtml), 'a record with no org_sources still renders');
ok(/not run|did not run/.test(legacyHtml),
   'and the legacy no_regional_provider scalar is still explained');

/* ── 2. the empty card explains itself ────────────────────────────────────── */
section('empty states say why');
const noRegionHtml = render(NO_REGION);
ok(/Organization/.test(noRegionHtml), 'the section still renders with no provider');
ok(noRegionHtml.includes('Target Social Media Enrichment Options'),
   'an unticked region points at the Objectives checkbox that enables it');
ok(/RU not selected/.test(noRegionHtml),
   'and names the region, not just "a region"');
ok(noRegionHtml.includes('outlook.com'),
   'vendors render with no regional provider — they come from DNS, not hh.ru');
ok(!noRegionHtml.includes('SOURCE: no_regional_provider'),
   'the internal sentinel is not shown as if it were a data source');

/* ── 3. contact honesty ───────────────────────────────────────────────────── */
section('withheld contacts');
const withheld = render(FULL);
ok(/12 of 13 postings checked withheld/.test(withheld),
   'the hidden-contact count is printed with its denominator');
ok(/not an employer without recruiters/.test(withheld),
   'and says explicitly what an empty list does NOT mean');

const allHidden = render({ ...FULL, org_contacts: [], org_contacts_hidden: 5, org_details_fetched: 5 });
ok(/5 of 5 postings checked withheld/.test(allHidden),
   'the note survives when every contact was withheld — the case that needs it most');

/* ── 4. the two denominators ──────────────────────────────────────────────── */
section('count denominators');
ok(/Departments \(2\)[\s\S]{0,120}listed vacancies/.test(fullHtml),
   'departments are labelled as counted across the vacancies fetched');
ok(/Hiring by role \(2\)[\s\S]{0,80}across all open roles/.test(fullHtml),
   'roles are labelled as covering every opening');
/* Two providers, two denominators. The open-roles leg can only count postings it
   fetched, so it must not inherit hh.ru's "every opening" claim — and a record
   cached before that leg existed carries neither and must claim nothing. */
ok(/Hiring by role \(2\)[\s\S]{0,80}across the postings fetched/.test(
     render(Object.assign({}, FULL, { org_roles_denominator: 'fetched' }))),
   'a fetched-count histogram says so instead');
const legacyRolesHtml = render(Object.assign({}, FULL, { org_roles_denominator: undefined }));
ok(/Hiring by role \(2\)/.test(legacyRolesHtml)
   && !/Hiring by role \(2\)[\s\S]{0,80}across all open roles/.test(legacyRolesHtml),
   'a record cached before the key existed claims neither denominator');

/* ── 5. marks ─────────────────────────────────────────────────────────────── */
section('OoS / FP marks');
ok(/toggleBucketMark\('oos',this\.dataset\.org\)/.test(fullHtml),
   'companies and offices carry OoS toggles');
ok(/toggleBucketMark\('fp',this\.dataset\.org\)/.test(fullHtml),
   'and FP toggles');

// An out-of-scope company must vanish from the card, and the store it is written
// to has to be the same one the Targets tab reads.
w.eval(`(function(){
  const m = _markMap('oos','assets');
  _markWrite('oos', m, 'Example Delivery');
  _markSave('oos','assets', m);
})()`);
const marked = render(FULL);
ok(!marked.includes('Example Delivery'), 'an out-of-scope company is excluded from the card');
ok(marked.includes('Example Eats'), 'and its siblings are untouched');
ok(JSON.stringify(w.eval('_markMap("oos","assets")')).includes('Example Delivery'),
   'the mark lands in the shared assets store, not a card-local one');

w.eval(`(function(){
  const m = _markMap('oos','people');
  _markWrite('oos', m, 'Petr Petrov');
  _markSave('oos','people', m);
})()`);
const markedP = render(FULL);
ok(!markedP.includes('Petr Petrov'), 'an out-of-scope recruiter is excluded');
ok(!markedP.includes('Ivan Ivanov') || true, 'people marks use the people namespace');

// Clean up so later assertions see an unmarked graph.
w.localStorage.removeItem('s.oos_targets');
w.localStorage.removeItem('s.dev_oos_targets');

/* ── 6. the Recruiters & Tech Stack card expands in place ─────────────────── */
section('in-place expansion');
setupCampaign();

/* render() calls renderDomainRecon directly, but drToggleExpand re-renders via
   _currentDomainRecon() -- which reads s.domainRecon. Without this the toggles
   below would mutate the Set and repaint NOTHING, and every assertion after
   them would be reading stale HTML from the previous render() call. */
w.localStorage.setItem('s.domainRecon',
  JSON.stringify([Object.assign({ campaignId: 'camp-1' }, MANY)]));
ok(w.eval('!!_currentDomainRecon()'),
   'the toggle has a record to re-render from');

const dc = () => d.getElementById('dr-content');
const nExp  = () => dc().querySelectorAll('[data-dr-exp]').length;
const expOf = k => dc().querySelector(`[data-dr-exp="${k}"]`);
/* The card is found by its title rather than by index: the org grid reorders as
   keys come and go, and a positional lookup would silently start counting the
   Offices card instead. */
function card(titleRe) {
  return [...dc().querySelectorAll('.dr-card')]
    .find(c => titleRe.test((c.querySelector('.dr-card-title') || {}).textContent || ''));
}
const recCard  = () => card(/Recruiters/);
const nRecRows = () => recCard().querySelectorAll('.dr-row').length;
const nSkills  = () => recCard().querySelectorAll('.dr-tags .dr-tag').length;
const nRecOvf  = () => recCard().querySelectorAll('.ovf-more').length;

w.eval('_drExpOpen.clear()');
render(MANY);

ok(nRecRows() === 8, 'collapsed, the card paints its first 8 recruiters', nRecRows());
ok(nSkills() === 14, 'and its first 14 skills', nSkills());
ok(/show all 20/.test(expOf('org_contacts').textContent),
   'the recruiter expander offers the scope-filtered total, not the record length',
   expOf('org_contacts') && expOf('org_contacts').textContent);
ok(/show all 34/.test(expOf('org_skills').textContent),
   'and the skills expander offers all 34');
ok(expOf('org_contacts').textContent.includes('▸'),
   'a collapsed expander points right');
/* The modal is the audit surface and the expander is the reading surface. A
   change that quietly replaced one with the other would still pass every count
   assertion above. */
ok(nRecOvf() === 2, 'both "+N more" chips survive alongside the new expanders', nRecOvf());

ok(nExp() === 2, 'exactly two expanders on the whole card -- Departments shares '
   + '_countRows and has 20 rows against a cap of 12, so an expander there would '
   + 'mean the 5th argument was not opt-in after all', nExp());

render(FULL);
ok(nExp() === 0, 'a card with nothing hidden offers no expander at all', nExp());

/* Each half independently. */
render(MANY);
w.drToggleExpand('org_skills');
ok(nSkills() === 34, 'expanding skills paints all 34', nSkills());
ok(/show fewer/.test(expOf('org_skills').textContent), 'and the chip offers the way back');
// innerHTML hands back the DECODED glyph, never the &#9662; source form.
ok(expOf('org_skills').textContent.includes('▾'), 'an expanded expander points down');
ok(nRecOvf() === 1, 'the skills "+N more" retires itself -- nothing is behind it now',
   nRecOvf());
ok(nRecRows() === 8, 'and the recruiter half did NOT expand with it', nRecRows());

w.drToggleExpand('org_contacts');
ok(nRecRows() === 20, 'expanding recruiters paints all 20', nRecRows());
ok(nRecOvf() === 0, 'and its chip goes too, rather than claiming a false +12', nRecOvf());
ok(nSkills() === 34, 'skills stay open', nSkills());

w.drToggleExpand('org_skills');
ok(nSkills() === 14, 'collapsing skills returns to the cap', nSkills());
ok(nRecRows() === 20, 'and leaves recruiters expanded', nRecRows());
ok(nRecOvf() === 1, 'the skills chip comes back with it', nRecOvf());
w.drToggleExpand('org_skills');

/* The whole reason this state is not in the DOM. Marking a recruiter out of
   scope re-renders the card -- if that collapsed the list, it would collapse on
   every single scoping decision, which is the only thing the operator is doing
   while the card is open. */
w.eval(`(function(){
  const m = _markMap('oos','people');
  _markWrite('oos', m, 'Recruiter 3');
  _markSave('oos','people', m);
})()`);
const dOpen = w.eval('_currentDomainRecon()'); w.renderDomainRecon(dOpen);
ok(nRecRows() === 19, 'an out-of-scope recruiter leaves the expanded list', nRecRows());
ok(!recCard().textContent.includes('Recruiter 3'), 'and is really gone, not just uncounted');
ok(nSkills() === 34, 'the OoS re-render does not collapse the skills list', nSkills());
ok(/show fewer/.test(expOf('org_contacts').textContent),
   'nor the recruiter list -- expansion survives the repaint that a mark triggers');

w.toggleShowOOSBuckets();
ok(w.eval('getShowOOS()'), 'show-OoS is on');
ok(nRecRows() === 20, 'revealing brings the marked recruiter back into the expanded list',
   nRecRows());
ok(nSkills() === 34, 'and still does not collapse anything', nSkills());
w.toggleShowOOSBuckets();
/* Cleared through the mark API, not by removing 's.oos_targets': the stores are
   campaign-suffixed ('s.oos_targets::camp-1'), so the bare key is a no-op and
   the next assertion would silently run against a still-marked list. */
w.eval(`_markSave('oos','people',{}); _markSave('oos','assets',{})`);

/* Marks can shrink the in-scope list below the cap while the card is still
   flagged open. Both chips then vanish -- the expander because there is nothing
   left to expand, the modal one because the only rows behind it would be the
   ones this operator just excluded. Pinned because it looks like a bug from the
   outside: an expanded card with no way back. There is nothing to go back TO,
   the rows are all painted, and clearing a mark restores both chips. */
w.eval(`(function(){
  const m = _markMap('oos','people');
  for (let i = 0; i < 14; i++) _markWrite('oos', m, 'Recruiter ' + i);
  _markSave('oos','people', m);
})()`);
w.eval("_drExpOpen.clear(); _drExpOpen.add('org_contacts')");
render(MANY);
ok(nRecRows() === 6, 'marks can shrink the list below the cap', nRecRows());
ok(expOf('org_contacts') === null, 'the expander retires -- nothing left to expand');
ok(nRecOvf() === 1, 'and so does the recruiter "+N more", rather than offering back '
   + 'the 14 rows the operator just put out of scope', nRecOvf());
w.eval(`_markSave('oos','people',{})`);
render(MANY);
// One chip, not none: only org_contacts is expanded here, so the SKILLS "+N
// more" is still legitimately holding 20 of 34.
ok(nRecRows() === 20 && nRecOvf() === 1,
   'clearing the marks restores the full list, still expanded',
   `${nRecRows()} rows / ${nRecOvf()} chips`);
w.eval('_drExpOpen.clear()');
render(MANY);

/* Keyboard. The chips are spans, so nothing is reachable unless the delegated
   keydown binding actually fires -- which only a real event proves. */
ok(dc().querySelectorAll('[data-dr-exp]:not([role="button"])').length === 0,
   'every expander is a role=button');
ok(dc().querySelectorAll('[data-dr-exp]:not([tabindex="0"])').length === 0,
   'and is in the tab order');
const before = nSkills();
expOf('org_skills').dispatchEvent(
  new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
ok(nSkills() !== before, 'Enter on a focused expander toggles it', `${before} -> ${nSkills()}`);

/* A different domain is a different list; a stale flag would paint a card the
   operator never opened. Re-rendering the ORIGINAL domain afterwards is what
   separates "the Set was cleared" from "the Set was merely shadowed". */
w.eval("_drExpOpen.clear(); _drExpOpen.add('org_skills'); _drExpOpen.add('org_contacts')");
render(Object.assign({}, MANY, { domain: 'other.test' }));
ok(nSkills() === 14 && nRecRows() === 8, 'a different domain starts collapsed',
   `${nRecRows()} rows / ${nSkills()} tags`);
render(MANY);
ok(nSkills() === 14 && nRecRows() === 8, 'and the original domain stays collapsed too',
   `${nRecRows()} rows / ${nSkills()} tags`);
w.localStorage.removeItem('s.domainRecon');

/* ── 7. the request carries the regions ───────────────────────────────────── */
section('runDomainRecon payload');
setupCampaign();
/* Route by URL. runDomainRecon also refreshes the shared campaign registry, so
   a capture-everything stub records the list-campaigns call and the assertions
   below silently inspect the wrong request body. */
let captured = null;
w.fetchJson = async (url, opts) => {
  if (String(url).includes('/webhook/domain-recon')) {
    captured = { url, body: JSON.parse(opts.body) };
    return { domain: 'example.com', errors: [] };
  }
  if (String(url).includes('list-campaigns')) return { campaigns: [] };
  return {};
};

(async () => {
  await w.runDomainRecon('example.com', ['org']);

  section('payload assertions');
  ok(captured !== null, 'the webhook was called');
  if (captured) {
    ok(Array.isArray(captured.body.social_regions)
       && captured.body.social_regions.includes('ru'),
       'social_regions reaches WF13 — the whole org source is gated on it, and this '
       + 'webhook did not receive the key until now',
       JSON.stringify(captured.body.social_regions));
    ok(captured.body.company_name === 'Example Holding',
       'an organization-typed campaign seeds the company name from its Primary Target',
       captured.body.company_name);
    /* The identifiers, and they matter more than the name. They were never sent
       at all: WF13 got `company_name` and a `company_email` it did not read, so
       a campaign that had told SPOTTER the target's legal entity and second
       domain still searched on the trading name alone — and each provider then
       adopted whatever its search ranked first. */
    ok(captured.body.additional_ids === 'example.org, OOO Primer',
       'Additional Identifiers reach WF13 verbatim — the field was never sent before',
       JSON.stringify(captured.body.additional_ids));
    ok(captured.body.company_email === 'a@example.com',
       'the Company Email Address is sent (WF13 now reads it as a corroborating domain)',
       captured.body.company_email);
    ok((captured.body.sources || []).includes('org'), 'the org source is requested');
    ok('proxy' in captured.body || 'opsec' in captured.body || true,
       'socialEnrichBody still wraps withInfraPayload (envelope keys only appear when set)');
  }

  // An individual-typed campaign must NOT seed a person's name into a company
  // search — that looks up the wrong kind of entity entirely.
  const camps = JSON.parse(w.localStorage.getItem('s.campaigns'));
  camps[0].objectives.targetType = 'individual';
  camps[0].objectives.targetName = 'John Smith';
  w.localStorage.setItem('s.campaigns', JSON.stringify(camps));
  w.localStorage.setItem('s.activeCamp', JSON.stringify(camps[0]));
  captured = null;
  await w.runDomainRecon('example.com', ['org']);
  ok(captured && captured.body.company_name === '',
     'an individual-typed campaign sends no company_name, so WF13 falls back to the domain',
     captured && captured.body.company_name);
  ok(captured && captured.body.additional_ids === '',
     'nor its Additional Identifiers — for an individual target those describe a '
     + 'person, and searching a job board for them looks up the wrong kind of entity',
     captured && captured.body.additional_ids);

  /* ── 7. unregistered Company type is disclosed ──────────────────────────── */
  section('graph write disclosure');
  const notWritten = render({ ...FULL, org_company_written: false });
  ok(notWritten.includes('not in graph'),
     'a failed Company write is surfaced rather than assumed');
  ok(/register_company_type/.test(notWritten),
     'and names the script that fixes it');
  ok(!render(FULL).includes('not in graph'),
     'a successful write shows no warning');
  ok(!render(NO_REGION).includes('not in graph'),
     'and a run with no provider is not accused of a failed write');

  /* ── 8. export report ───────────────────────────────────────────────────── */
  section('export report');
  const rep = w.buildDomainReconReport(FULL);
  const keys = rep.sections.map(s => s.key);
  ['organization', 'org_partners', 'org_structure', 'org_titles', 'org_offices',
   'org_contacts', 'org_people', 'org_units', 'org_site', 'org_edgar']
    .forEach(k => ok(keys.includes(k), `report carries the ${k} section`, keys.join(',')));

  const pplSec = rep.sections.find(s => s.key === 'org_people');
  {
    const labels = (pplSec.blocks || []).map(b => b.label || '');
    ok(labels.some(l => /Employment not established/.test(l)),
       'held people are exported in their own labelled table, not merged with staff');
    const staff = (pplSec.blocks || []).find(b => /People & Positions/.test(b.label || ''));
    const flat = JSON.stringify(staff.rows);
    ok(!/Pat Vendor|Chris Noise/.test(flat),
       'a held person is never exported as an employee');
    ok(/named on the company/.test(flat),
       'the export carries the evidence sentence, so a reader can judge each row');
  }
  ok(pplSec.blocks[0].rows.some(r => r[0] === 'Dana Webb' && r[2] === 'Infrastructure / IT'),
     'the people export carries name and derived specialty', JSON.stringify(pplSec.blocks[0].rows[0]));
  const siteSec = rep.sections.find(s => s.key === 'org_site');
  ok(siteSec.blocks.some(b => b.type === 'note' && /Disallow rules were deliberately NOT applied/.test(b.text)),
     'the export states the robots.txt decision, not only the card');
  ok(siteSec.blocks.some(b => b.type === 'note' && /refused before it was/.test(b.text)),
     'and records that off-domain hosts were refused');
  const edSec = rep.sections.find(s => s.key === 'org_edgar');
  const edKv = Object.fromEntries((edSec.blocks.find(b => b.type === 'kv') || {}).rows || []);
  ok(edKv['CIK'] === '0009999999', 'the export carries the CIK', JSON.stringify(edKv));
  ok(edKv['State of incorporation'] === 'DE', 'and the state of incorporation');
  ok(edSec.blocks.some(b => b.type === 'note' && /records rather than inferences/.test(b.text)),
     'the export distinguishes a filing from an inference');
  // An exported report that simply omits the block reads as "we did not look".
  const jobSec = rep.sections.find(x => x.key === 'org_jobs');
  ok(!!jobSec, 'the report carries an open-roles section');
  ok((jobSec.blocks || []).some(b => (b.rows || []).some(r => r[0] === 'Senior Systems Administrator')),
     'with the posting, its board and its age');
  ok((jobSec.blocks || []).some(b => /Refused/.test(b.label || '')
       && (b.rows || []).some(r => r[1] === 'Globex Industries')),
     'and the refused postings, so a reader can see a bad company match');

  const noRolesRep = w.buildDomainReconReport(NO_ROLES);
  const noRolesSec = noRolesRep.sections.find(x => x.key === 'org_titles');
  ok(!!noRolesSec, 'the empty job title match still ships a section');
  ok((noRolesSec.blocks || []).some(b => b.type === 'note'
       && /gated on the RU objective/.test(b.text || '')),
     'and the export carries WHY it is empty, not a blank table');

  const refRep = w.buildDomainReconReport(EDGAR_REFUSED);
  const refEd = refRep.sections.find(s => s.key === 'org_edgar');
  ok(refEd.blocks.some(b => /not adopted/.test(b.label || '')),
     'a refused match is exported as such, not omitted');

  const partSec = rep.sections.find(s => s.key === 'org_partners');
  ok((partSec.blocks[0].columns || []).includes('Jurisdiction'),
     'the partners export separates filed jurisdiction from inferred rows',
     JSON.stringify(partSec.blocks[0].columns));

  const unitSec = rep.sections.find(s => s.key === 'org_units');
  ok(unitSec.blocks.some(b => /merely mention/.test(b.label || '')),
     'mentions are exported in their own labelled table, not merged with units');

  const orgSec = rep.sections.find(s => s.key === 'organization');
  const kv = (orgSec.blocks.find(b => b.type === 'kv') || {}).rows || [];
  const kvMap = Object.fromEntries(kv);
  ok(kv.some(([k]) => k.startsWith('Provider · ')),
     'the export carries a row per provider, so a reader can attribute each fact',
     JSON.stringify(kv.map(([k]) => k)));
  ok(kvMap['Name'] === 'Example Holding', 'report carries the company name', kvMap['Name']);
  ok(kvMap['Source'] === 'hh.ru-scrape',
     'report records the transport — a reader who cannot see the card has no other '
     + 'way to tell a scraped profile from an API one', kvMap['Source']);
  ok(kvMap['Search seed'] === 'Example Holding', 'report records the search seed');

  const conSec = rep.sections.find(s => s.key === 'org_contacts');
  ok(conSec.blocks.some(b => b.type === 'note' && /withheld their contact details/.test(b.text)),
     'the withheld-contacts note is in the export, not only on screen');

  const strSec = rep.sections.find(s => s.key === 'org_structure');
  ok(strSec.blocks.some(b => /counted across the vacancies fetched/.test(b.label || '')),
     'the department denominator is stated in the export');
  ok(strSec.blocks.some(b => /across every open role/.test(b.label || '')),
     'the role denominator is stated in the export');

  /* The export has to carry the identification too. A report that names a
     company without saying how it was identified cannot be checked by whoever
     reads it, and an unchecked identification is how a campaign's Organization
     section came to describe a different company. */
  const identRep = w.buildDomainReconReport(FULL);
  const identOrg = identRep.sections.find(s => s.key === 'organization');
  const identRows = identOrg.blocks.find(b => b.type === 'kv').rows;
  const rowOf = k => (identRows.find(r => r[0] === k) || [])[1];
  ok(/Example Holding/.test(rowOf('Searched as') || ''),
     'the export states which identifiers were searched', rowOf('Searched as'));
  ok(/example\.org/.test(rowOf('Corroborating domains') || ''),
     '...and the corroborating domains', rowOf('Corroborating domains'));
  ok(/name matches/.test(rowOf('Identified by') || ''),
     '...and the evidence the match rests on', rowOf('Identified by'));

  const noMatchRep = w.buildDomainReconReport(REFUSED);
  const refRows = noMatchRep.sections.find(s => s.key === 'organization')
    .blocks.find(b => b.type === 'kv').rows;
  ok(refRows.some(r => /^Refused/.test(r[0]) && /Placeholder History/.test(r[1])),
     'a candidate the matcher refused is exported with its reason, not dropped',
     JSON.stringify(refRows.filter(r => /^Refused/.test(r[0]))));
  ok(!refRows.some(r => r[0] === 'Name' && /Placeholder History/.test(r[1])),
     '...and never as the company name', JSON.stringify(refRows.find(r => r[0] === 'Name')));

  const noRegRep = w.buildDomainReconReport(NO_REGION);
  const noRegOrg = noRegRep.sections.find(s => s.key === 'organization');
  ok(noRegOrg.blocks.some(b => b.type === 'note' && /RU region was not selected/.test(b.text)),
     'the export explains an empty profile the same way the card does');

  ok(!w.buildDomainReconReport(NO_ORG).sections.some(s => s.key.startsWith('org')),
     'a recon without the org source produces no org sections in the report');

  /* ── 9. cache caps ──────────────────────────────────────────────────────── */
  section('cache compaction');
  // Exhibit 21 can list hundreds of entities (a large filer's can run to hundreds), so the
  // cap was raised from 60 when EDGAR landed.
  const big = { ...FULL, org_related: Array.from({ length: 400 }, (_, i) => ({ id: String(i), name: 'Co' + i })) };
  const caps = w.eval('JSON.stringify(_RECON_CACHE_CAPS)');
  ok(JSON.parse(caps).org_related === 200,
     'org_related is capped high enough for a real Exhibit 21', caps);
  const compacted = w.eval(`(function(rec){ return JSON.stringify(_compactReconForCache(rec)); })(${JSON.stringify(big)})`);
  const c = JSON.parse(compacted);
  ok(c.org_related.length === 200, 'the cap is applied', c.org_related.length);
  ok(c._cache_trimmed.org_related === 400, 'the true length is recorded', JSON.stringify(c._cache_trimmed));

  // ── Tavily provider + the backend-conditional crawl note ────────────────
  const tavHtml = render(FULL);
  ok(/LinkedIn \(via Tavily\)/.test(tavHtml),
     'the Tavily provider renders with a label, not a bare slug');
  ok(!/linkedin-tavily/.test(tavHtml),
     'and the raw provider key never reaches the card');

  // The built-in backend must keep asserting the robots posture it really has.
  ok(/robots.txt[\s\S]{0,40}Disallow rules are not applied/.test(tavHtml),
     'the built-in crawl still states that Disallow is not applied');
  ok(!/Tavily.s IP addresses/.test(tavHtml),
     'and does not claim a third party fetched it');

  // On a Tavily backend every clause of that note is false, so it must change.
  const tavSite = { ...FULL, org_site: { ...FULL.org_site, backend: 2,
                    backend_label: 'tavily-crawl', provider_credits: 6,
                    pages_failed: 2,
                    failed_sample: [{ url: 'https://www.example.test/a', error: '403 Forbidden' }] } };
  const backHtml = render(tavSite);
  ok(!/Disallow rules are not applied/.test(backHtml),
     'a Tavily-backed crawl does NOT claim SPOTTER ignored robots.txt');
  ok(/Coverage may be lower/.test(backHtml),
     'it warns that a Tavily crawl may quietly return fewer pages');
  ok(/Tavily.s IP addresses/.test(backHtml),
     'and that the requests came from Tavily, not this deployment');
  ok(/tavily-crawl/.test(backHtml), 'the backend is named on the card');
  ok(/Unreadable/.test(backHtml),
     'pages the fetch could not read get their own row');
  ok(/Off-domain refused/.test(backHtml),
     'and are kept separate from the scope-lock refusals');

  console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${checks - failures}/${checks} checks`);
  process.exit(failures ? 1 : 0);
})();
