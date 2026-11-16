#!/usr/bin/env node
/*
 * Headless smoke for retrieved-content translation in the dashboard.
 *
 * Pins _tr(), the TR toolbar toggle, Organization/Web rendering of
 * *_translated fields, export columns that keep the original, and the Web
 * modal OCR button (only when a screenshot exists).
 *
 *   node scripts/smoke_frontend_translate.js
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

setTimeout(() => {
  console.log('Retrieved-content translation — _tr, toggle, cards, OCR, export');

  section('_tr helper');
  ok(typeof w._tr === 'function', '_tr is a global helper');
  ok(typeof w.getTranslateOn === 'function' && w.getTranslateOn() === true,
     'translations are on by default');
  const shown = w._tr('ООО Пример', 'Example LLC', 'ru');
  ok(shown.includes('Example LLC'), 'default shows the translation', shown);
  ok(shown.includes('tr-chip') && shown.includes('ru'), 'source-lang chip is present', shown);
  ok(shown.includes('original') && shown.includes('ООО Пример'),
     'original is kept in a details block', shown);
  ok(w._tr('same', '', '') === 'same' || w._tr('same', '', '').includes('same'),
     'empty translation falls back to the original');

  section('toolbar toggle');
  ok(d.getElementById('tr-toggle'), 'TR chip is in the header');
  w.setTranslateOn(false);
  w.pinTranslateToggle();
  ok(w.getTranslateOn() === false, 'toggle persists off');
  const origOnly = w._tr('ООО Пример', 'Example LLC', 'ru');
  ok(origOnly.includes('ООО Пример') && !origOnly.includes('Example LLC'),
     'toggle off shows the original only', origOnly);
  w.setTranslateOn(true);
  w.pinTranslateToggle();
  ok(d.getElementById('tr-toggle').classList.contains('qa-on'),
     'TR button is marked on when translations are shown');

  section('Organization card');
  const camp = {
    id: 'camp-1', name: 'Smoke', sketchId: 'sk-1',
    objectives: { targetType: 'organization', targetName: 'Primer', socialRegions: ['ru'] },
  };
  w.localStorage.setItem('s.campaigns', JSON.stringify([camp]));
  w.localStorage.setItem('s.activeCamp', JSON.stringify(camp));
  const rec = {
    domain: 'primer.test', timestamp: '2026-09-20T10:00:00Z', errors: [],
    dns_a: [], dns_mx: [], dns_ns: [], dns_txt: [], dns_cname: [],
    org_source: 'hh.ru-scrape', org_seed: 'Primer',
    org_sources: [
      { provider: 'hh.ru', transport: 'scrape', status: 'ok', reliable: true },
      { provider: 'website', transport: 'crawl', status: 'ok', reliable: true },
    ],
    org_profile: {
      name: 'ООО Пример', description: 'Компания занимается авиаперевозками.',
      description_translated: 'The company is engaged in air transportation.',
      address: 'Москва, Примерная улица 1', address_translated: 'Moscow, Primernaya Street 1',
      source_lang: 'ru',
    },
    org_people: [
      { name: 'Иван Иванов', job_title: 'Технический директор',
        job_title_translated: 'Chief Technology Officer', source: 'website', source_lang: 'ru' },
    ],
    org_jobs: [
      { title: 'Инженер информационной безопасности',
        title_translated: 'Information Security Engineer',
        location: 'Москва', via: 'hh.ru', source_lang: 'ru' },
    ],
    org_site: { pages_crawled: 4, chunks_indexed: 12, chunks_translated: 9 },
    org_related: [], org_vendors: [], org_departments: [], org_roles: [],
    org_offices: [], org_contacts: [], org_skills: [], org_title_matches: [],
    org_units: [], org_mentions: [],
  };
  w.renderDomainRecon(rec);
  const html = d.getElementById('dr-content').innerHTML;
  ok(html.includes('The company is engaged in air transportation.'),
     'org description shows the translation');
  ok(html.includes('Компания занимается авиаперевозками.'),
     'org description keeps the original');
  ok(html.includes('Chief Technology Officer'),
     'person title shows the translation');
  ok(html.includes('Chunks translated'),
     'website intelligence reports chunks_translated');
  ok(html.includes('Information Security Engineer'),
     'open role shows the translation');
  ok(html.includes('Инженер информационной безопасности'),
     'open role keeps the original');

  section('export keeps the original');
  const report = w.buildDomainReconReport(rec);
  const org = (report.sections || []).find(s => s.key === 'organization');
  const notes = ((org && org.blocks) || []).filter(b => b.type === 'note').map(b => b.text).join('\n');
  ok(notes.includes('Компания занимается авиаперевозками.'),
     'export note has the original description', notes);
  ok(notes.includes('Translated:') && notes.includes('air transportation'),
     'export note has a translated sibling', notes);
  const ppl = (report.sections || []).find(s => s.key === 'org_people');
  const cols = (ppl && ppl.blocks && ppl.blocks[0] && ppl.blocks[0].columns) || [];
  ok(cols.includes('Title') && cols.includes('Title (translated)'),
     'people export has original and translated title columns', cols);

  section('Web OCR button');
  w.eval(`_webCache = { sites: [
    { id: 'e1', url: 'https://10.0.0.5/login', title: 'Вход', title_translated: 'Login',
      source_lang: 'ru', resolved: '10.0.0.5', category: '',
      screenshot_url: '/screenshots/sk-1/a.png', has_screenshot: true,
      protocol: 'https', port: '443', active: true, request_status: 'Successful',
      source: 'eyewitness', has_default_creds: false, is_high_value: false },
    { id: 'e2', url: 'http://10.0.0.9/', title: '', resolved: '10.0.0.9',
      screenshot_url: '', has_screenshot: false, protocol: 'http', port: '80',
      active: false, request_status: 'Timeout', source: 'eyewitness',
      has_default_creds: false, is_high_value: false }
  ], stats: { total: 2, with_screenshot: 1 }, ts: Date.now() };
  _webFilter = 'all'; _webSearch = '';`);
  w.renderWeb();
  const titles = [...d.querySelectorAll('.web-title')].map(el => el.textContent);
  ok(titles.some(t => t.includes('Login')), 'web card title shows the translation', titles);
  w.openWebDetail(0);
  ok(d.getElementById('web-ocr-btn'), 'OCR button present when a screenshot exists');
  ok(typeof w.ocrWebScreenshot === 'function', 'ocrWebScreenshot is wired');
  w.closeWebDetail();
  w.openWebDetail(1);
  ok(!d.getElementById('web-ocr-btn'), 'OCR button absent without a screenshot');
  w.closeWebDetail();

  console.log(`\n${checks - failures}/${checks} checks passed`);
  process.exit(failures ? 1 : 0);
}, 1200);
