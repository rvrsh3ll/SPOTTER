#!/usr/bin/env node
/*
 * Headless smoke test for the Domain Breach Credentials surface on the ANALYSIS
 * tab's Domain Recon section (frontend/index.html).
 *
 * Why this exists
 * ---------------
 * WF13's domain search now pages Flare to completion and returns the full list;
 * the frontend must (a) show every credential (matched to a graph individual or
 * not) so it reaches parity with Flare's website export, and (b) keep cleartext
 * opt-in and TRANSIENT. Both failure modes are silent in a click-through: a
 * masked table and an unmasked one look "fine", and a cleartext password written
 * into s.domainRecon is invisible until someone exports the campaign. So the
 * assertions below check the reveal request body, the rendered cells, the export
 * payload, AND localStorage after the fact.
 *
 *   node scripts/smoke_frontend_domain_creds.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed (all are reported).
 *
 * What it CANNOT tell you: jsdom has no layout, so the table's horizontal scroll
 * and both themes still need one browser pass.
 */

'use strict';

const fs = require('fs');
const vm = require('vm');


const { INDEX, loadJsdom } = require('./smoke_frontend_lib');
const { JSDOM, VirtualConsole } = loadJsdom();

let failures = 0, checks = 0;
function ok(cond, label, extra) {
  checks++;
  if (cond) return true;
  failures++;
  console.error(`  FAIL  ${label}${extra !== undefined ? `\n        got: ${extra}` : ''}`);
  return false;
}
function section(name) { console.log(`\n── ${name}`); }
const sleep = ms => new Promise(r => setTimeout(r, ms));

const CLEARTEXT = 'Summer2024!';

/* A masked domain record as WF13 ships it by default: values stripped, but the
   record self-describes its length so _flareCredCell can show the dots. */
function maskedRow(i) {
  return {
    breach_id: 'b' + i, email: `user${i}@example.com`, source: 'Combolist',
    event_type: 'combolists', has_password: true,
    has_credential: true, credential_length: 8,
    hash_type: 'plaintext', hash_type_reported: 'unknown',
    imported_at: '2026-01-01', record_domain: 'example.com',
  };
}
/* The same records once revealed: WF13 puts the credential in credential_value. */
function revealedRow(i) {
  return Object.assign(maskedRow(i), { credential_value: `${CLEARTEXT}-${i}` });
}

async function main() {
  const html = fs.readFileSync(INDEX, 'utf8');

  /* ── Step 0: inline script parses ──────────────────────────────────── */
  section('Step 0 — inline script parses');
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const main_js = blocks.reduce((a, b) => (b.length > a.length ? b : a), '');
  try {
    new vm.Script(main_js, { filename: 'index.html-inline.js' });
    ok(true, 'inline script parses');
  } catch (e) {
    ok(false, 'inline script parses', e.message);
  }

  /* ── Step 1: clean load ────────────────────────────────────────────── */
  section('Step 1 — loads with zero errors');
  const vc = new VirtualConsole();
  const errs = [];
  vc.on('jsdomError', e => errs.push(e.message));
  const dom = new JSDOM(html, {
    runScripts: 'dangerously', url: 'http://localhost/',
    virtualConsole: vc, pretendToBeVisual: true,
  });
  const w = dom.window, d = w.document;
  await sleep(60);
  ok(errs.length === 0, 'no jsdomError during load', errs.join(' | '));

  /* ── Step 2: functions resolved ────────────────────────────────────── */
  section('Step 2 — functions resolved off window');
  ['renderDomainRecon', 'toggleDrFlareReveal', 'exportDrCard', '_drReconForExport',
   '_flareCredCell', 'buildDomainReconReport',
   'renderExposure', 'initExposure', 'fxSelectAnalysis', '_fxJoinRows',
   'buildExposureReport', 'exportExposureReport', 'exportExposureCard',
   '_fxAttachRecords', 'fxToggleRow', 'sortExposure'].forEach(fn =>
    ok(typeof w[fn] === 'function', `${fn} is defined`, typeof w[fn]));

  /* ── Step 3: seed a campaign + a masked domain recon, then render ───── */
  section('Step 3 — masked render');
  w.localStorage.setItem('s.activeCamp', JSON.stringify({
    id: 'c-1', name: 'EXAMPLE', objectives: { companyDomain: 'example.com' } }));
  const masked = Array.from({ length: 1200 }, (_, i) => maskedRow(i));
  const record = {
    id: 'dr-1', campaignId: 'c-1', domain: 'example.com',
    timestamp: new Date().toISOString(),
    flare_exposed_creds: 7300, flare_breach_summary: { combolists: 7300 },
    flare_domain_breaches: masked, flare_domain_truncated: false,
  };
  w.localStorage.setItem('s.domainRecon', JSON.stringify([record]));

  /* The three Flare blocks moved out of renderDomainRecon into the unified
     Credential & Breach Exposure section. Same markup, same reveal path, same
     export keys — only the container changed. */
  /* One table now. Records are attributed to identities; anything unclaimed sits
     behind the offsite bucket row, which starts collapsed because people come
     first. Open it — these 1,200 fixture rows are all unattributed. */
  w.renderExposure({ recon: record });
  const content = () => d.getElementById('fx-content').innerHTML;
  ok(/offsite addresses/.test(content()), 'the offsite bucket row renders');
  w.eval(`_fxOpen.add(FX_OFFSITE)`);
  w.renderExposure({ recon: record });
  ok(!content().includes(CLEARTEXT), 'no cleartext in the masked DOM');
  ok(content().includes('&bull;') || content().includes('•'),
     'masked rows show the stored-value dots');
  ok(/7,300 exposed/.test(content()), 'header shows the true total, not the page size');
  ok(/1,150 more not shown/.test(content()), 'the bucket is capped and says how much it dropped',
     (content().match(/[\d,]+ more not shown/) || [])[0]);
  const revealBtn = () => [...d.querySelectorAll('#fx-content button')]
    .find(b => /Reveal & export all|Reveal &amp; export all|Reveal/.test(b.textContent));
  ok(!!revealBtn(), 'a Reveal control is offered');

  /* ── Step 4: masked export carries no cleartext ────────────────────── */
  section('Step 4 — masked export');
  let captured = null;
  w._exportReport = (report /*, fmt */) => { captured = report; };
  w.exportDrCard('flare', 'csv');
  ok(captured, 'exportDrCard produced a report');
  let flareSec = captured && captured.sections.find(s => s.key === 'flare');
  ok(!!flareSec, 'the export has a flare section');
  ok(!JSON.stringify(captured).includes(CLEARTEXT), 'masked export holds no cleartext');
  ok(/masked —/.test(JSON.stringify(flareSec)), 'masked export marks each row masked');

  /* ── Step 5: reveal is an explicit, flare-only re-fetch ─────────────── */
  section('Step 5 — reveal opts in');
  const calls = [];
  w.fetchJson = async (url, opts) => {
    const body = JSON.parse(opts.body);
    calls.push({ url, body });
    return {
      flare_exposed_creds: 7300,
      flare_domain_breaches: Array.from({ length: 3 }, (_, i) => revealedRow(i)),
      flare_domain_truncated: true,
    };
  };
  await w.toggleDrFlareReveal(true);
  await sleep(20);
  ok(calls.length === 1, 'one reveal call', calls.length);
  ok(calls[0] && /\/webhook\/domain-recon$/.test(calls[0].url), 'hit the domain-recon webhook',
     calls[0] && calls[0].url);
  ok(calls[0] && Array.isArray(calls[0].body.sources) && calls[0].body.sources.length === 1
     && calls[0].body.sources[0] === 'flare', 'reveal is flare-only (does not re-run all recon)',
     calls[0] && JSON.stringify(calls[0].body.sources));
  ok(calls[0] && calls[0].body.full_credentials === true, 'asks for the full list',
     calls[0] && JSON.stringify(calls[0].body));
  ok(calls[0] && calls[0].body.include_credentials === true, 'opts in to cleartext',
     calls[0] && JSON.stringify(calls[0].body));
  ok(content().includes(CLEARTEXT), 'cleartext is now shown on screen');
  ok(/UNMASKED/.test(content()), 'the header flips to UNMASKED');

  /* ── Step 6: revealed export carries cleartext, storage does not ────── */
  section('Step 6 — export reveals, storage stays clean');
  captured = null;
  w.exportDrCard('flare', 'csv');
  ok(captured && JSON.stringify(captured).includes(CLEARTEXT),
     'revealed export carries the cleartext values');
  const stored = w.localStorage.getItem('s.domainRecon') || '';
  ok(!stored.includes(CLEARTEXT), 's.domainRecon holds NO credential value', stored.slice(0, 120));
  ok(!JSON.stringify(record).includes(CLEARTEXT), 'the in-memory stored record was not mutated');

  /* ── Step 7: hide re-masks ─────────────────────────────────────────── */
  section('Step 7 — hide re-masks');
  await w.toggleDrFlareReveal(false);
  await sleep(20);
  ok(!content().includes(CLEARTEXT), 'cleartext is out of the DOM again');
  captured = null;
  w.exportDrCard('flare', 'csv');
  ok(captured && !JSON.stringify(captured).includes(CLEARTEXT),
     'export is masked again after hide');

  /* The section now reads TWO stores, so the per-key check above is no longer
     the whole surface. Sweep everything the page persisted. */
  const allStorage = JSON.stringify(w.localStorage);
  ok(!allStorage.includes(CLEARTEXT),
     'no cleartext anywhere in localStorage, not just s.domainRecon');

  /* ── Step 8: the join — one person, one row ────────────────────────── */
  /* This is the whole point of merging the five surfaces. j.doe appears in ALL
     THREE inputs: WF13's credential_matches, WF10's breachIntel and WF10's
     credentialIntel. Before the merge that person rendered three times across
     two sections. The failure mode is silent — three plausible-looking rows
     read as three findings — so assert the count, not just the content. */
  section('Step 8 — recon and analysis rows join on the person');
  const ANALYSIS = {
    id: 'an-1', campaignId: 'c-1', timestamp: new Date().toISOString(),
    status: 'under-review',
    breachIntel: [{ name: 'j.doe', breach_count: 2, has_stealer: true,
                    stealer_malware: ['redline'], breach_events: { stealer_logs: 2 },
                    plaintext_exposed: true, breach_cred_match: true,
                    personal_emails: ['jd@gmail.com'] }],
    breachIntelTotal: 40,
    credentialIntel: [{ name: 'j.doe', cred_count: 3, validated_cred_count: 1,
                        confirmed_compromised: true, cred_severity: 'high',
                        cred_services: ['VPN', 'SMB'], has_reuse: true,
                        breach_cred_match: true, plaintext_exposed: true }],
    credentialIntelTotal: 12,
  };
  w.localStorage.setItem('s.analyses', JSON.stringify([ANALYSIS]));
  const joinRecord = Object.assign({}, record, {
    credential_matches: [{ graph_user: 'j.doe', email: 'j.doe@example.com',
                           is_admin: true, has_password: true, has_stealer: true,
                           breach_count: 2, breach_source: 'combolists' }],
  });
  w.renderExposure({ recon: joinRecord, analysis: ANALYSIS });

  const joined = w._fxJoinRows(joinRecord, ANALYSIS);
  ok(joined.length === 1, 'three inputs collapse to ONE row', 'rows=' + joined.length);
  ok(joined[0].person === 'j.doe', 'the row keeps the person name', joined[0].person);
  ok(joined[0].isAdmin === true, 'admin flag survives the join');
  ok(joined[0].credCount === 3 && joined[0].breaches === 2,
     'counts merge (max), not concatenate', `creds=${joined[0].credCount} breaches=${joined[0].breaches}`);
  ok(joined[0].corpEmails.join() === 'j.doe@example.com',
     'the corporate address stays its own field');
  ok(joined[0].personalEmails.join() === 'jd@gmail.com',
     'personal addresses are NOT merged into the corporate one');

  const fx = () => d.getElementById('fx-content').innerHTML;
  /* Scoped to the identity table: j.doe also appears in the admin alert strip
     above it, and that duplication is the point of the strip. What must not
     happen is two ROWS for one person, which is what the merge removes. */
  const idTableOf = (h) => h.slice(h.indexOf('>Identity<'));
  const rowCount = (idTableOf(fx()).match(/openDossierFromCred\(&quot;j\.doe&quot;\)/g) || []).length;
  ok(rowCount === 1, 'j.doe renders exactly one row in the identity table',
     'occurrences=' + rowCount);
  ok(/CONFIRMED/.test(fx()) && /STEALER/.test(fx()),
     'the single row carries both the credential and the breach indicators');
  /* Scoped to the identity table on purpose: the admin alert strip above it
     carries its own PLAINTEXT PW tag for the same person, and that duplication
     is deliberate — one is an alert, one is the joined row. What must NOT
     happen is the joined row showing it twice, once from has_password and once
     from plaintext_exposed. */
  const plainCount = (idTableOf(fx()).match(/PLAINTEXT PW/g) || []).length;
  ok(plainCount === 1, 'the joined row shows PLAINTEXT PW once, not once per source',
     'count=' + plainCount);
  ok(/Admin Credentials Exposed in Breach \(1\)/.test(fx()),
     'the admin alert strip still calls j.doe out separately');
  ok(/between 40 and 52 people/.test(fx()),
     'the slice line states the union BOUND, never a made-up total',
     (fx().match(/between[^<]*/) || [])[0]);

  /* ── Step 9: record attribution, and the super-enrich gate ─────────── */
  /* This is the merge's whole point AND its riskiest rule. Folding an off-corp
     address into a named employee on weak evidence produces a row that looks
     exactly like a correct one — there is no way to spot it by eye. So assert
     the gate in all three states: corporate (always), personal + confirmed
     (folds), personal + unconfirmed (must NOT fold). */
  section('Step 9 — records attribute to identities, gated by super-enrich');
  const REC = (email, i) => ({
    breach_id: 'b-' + email + '-' + i, email, source: 'combolists',
    event_type: 'leaked_credentials', hash_type: 'plaintext',
    has_credential: true, credential_length: CLEARTEXT.length,
  });
  const attrRecord = Object.assign({}, record, {
    flare_domain_breaches: [REC('j.doe@example.com', 1), REC('jd@gmail.com', 2), REC('nobody@example.net', 3)],
    flare_exposed_creds: 3,
    credential_matches: [{ graph_user: 'j.doe', email: 'j.doe@example.com', is_admin: true }],
  });

  // (a) not super-enriched: the corporate record folds, the gmail one does NOT
  const notEnriched = JSON.parse(JSON.stringify(ANALYSIS));
  notEnriched.breachIntel[0].super_enriched = false;
  let r1 = w._fxJoinRows(attrRecord, notEnriched);
  let a1 = w._fxAttachRecords(r1, attrRecord.flare_domain_breaches);
  ok(r1[0].records.length === 1 && r1[0].records[0].email === 'j.doe@example.com',
     'corporate address attributes without confirmation',
     JSON.stringify(r1[0].records.map(x => x.email)));
  ok(a1.offsite.length === 2, 'the unconfirmed gmail address stays in the bucket',
     JSON.stringify(a1.offsite.map(x => x.email)));
  ok(a1.weakCount === 1, 'and the bucket says one address is a Super-Enrich away',
     'weakCount=' + a1.weakCount);

  // (b) super-enriched: the gmail address is now confirmed theirs
  const enriched = JSON.parse(JSON.stringify(ANALYSIS));
  enriched.breachIntel[0].super_enriched = true;
  let r2 = w._fxJoinRows(attrRecord, enriched);
  let a2 = w._fxAttachRecords(r2, attrRecord.flare_domain_breaches);
  ok(r2[0].records.length === 2,
     'super-enriched: the personal address folds into the person too',
     JSON.stringify(r2[0].records.map(x => x.email)));
  ok(a2.offsite.length === 1 && a2.offsite[0].email === 'nobody@example.net',
     'only the genuinely unrelated address is left in the bucket');
  ok(a2.weakCount === 0, 'nothing is pending confirmation any more');

  // (c) the degradation path — a record written before WF10 shipped the flag.
  //     Absent must behave as false, never as true.
  const preDeploy = JSON.parse(JSON.stringify(ANALYSIS));
  delete preDeploy.breachIntel[0].super_enriched;
  let r3 = w._fxJoinRows(attrRecord, preDeploy);
  let a3 = w._fxAttachRecords(r3, attrRecord.flare_domain_breaches);
  ok(r3[0].records.length === 1 && a3.offsite.length === 2,
     'a pre-deploy analysis record folds nothing off-corp',
     `attached=${r3[0].records.length} offsite=${a3.offsite.length}`);

  /* ── Step 10: expansion survives a reveal ─────────────────────────── */
  /* Reveal re-renders the whole section. If open rows lived in the DOM instead
     of module state, unmasking would collapse everything the operator had just
     opened — silently, at the worst moment. */
  section('Step 10 — an expanded row survives the reveal re-render');
  w.localStorage.setItem('s.analyses', JSON.stringify([enriched]));
  w.localStorage.setItem('s.domainRecon', JSON.stringify([attrRecord]));
  w.eval('_fxOpen.clear()');
  w.fxToggleRow('j.doe');
  ok(/data-fx-row="j\.doe"/.test(fx()), 'the identity row offers an expander');
  // innerHTML gives back the DECODED glyph, not the &#9662; source form.
  const openMark = () => (fx().match(/data-fx-row="j\.doe"[\s\S]{0,400}?tag-drill-car">(.)/) || [])[1];
  ok(openMark() === '\u25BE', 'it renders expanded', openMark());
  calls.length = 0;
  w.fetchJson = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) });
    return {
      flare_exposed_creds: 3, flare_domain_truncated: false,
      flare_domain_breaches: [
        { ...REC('j.doe@example.com', 1), credential_value: CLEARTEXT },
        { ...REC('jd@gmail.com', 2),   credential_value: CLEARTEXT },
        { ...REC('nobody@example.net', 3), credential_value: CLEARTEXT },
      ],
    };
  };
  await w.toggleDrFlareReveal(true);
  await sleep(20);
  ok(openMark() === '\u25BE', 'still expanded after the reveal re-render', openMark());
  ok(fx().includes(CLEARTEXT), 'and the expanded records are now unmasked');
  ok(!JSON.stringify(w.localStorage).includes(CLEARTEXT),
     'reveal still writes no cleartext to any store');

  /* ── summary ───────────────────────────────────────────────────────── */
  console.log(`\n${failures ? '✗' : '✓'} ${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error('FATAL', e); process.exit(2); });
