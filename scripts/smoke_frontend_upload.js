#!/usr/bin/env node
/*
 * Headless smoke for the browser upload size plan.
 *
 * A file of 32 MB or less stays on one JSON POST. A larger file is chunked.
 * Above 4 GB the page refuses and names the host scripts. The old 90 MB hard
 * refuse must not come back: it is what made a 200 MB report impossible.
 *
 *   node scripts/smoke_frontend_upload.js
 *
 * Exit 0 = pass, 1 = a failed assertion, 2 = jsdom missing.
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

const vc = new VirtualConsole();
const jsdomErrors = [];
vc.on('jsdomError', (err) => { jsdomErrors.push(String(err)); });

let dom;
try {
  dom = new JSDOM(fs.readFileSync(INDEX, 'utf8'), {
    runScripts: 'dangerously', pretendToBeVisual: true,
    url: 'http://localhost:8080/', virtualConsole: vc,
  });
} catch (e) {
  console.error('FATAL: frontend/index.html did not parse: ' + e.message);
  process.exit(1);
}

const w = dom.window;
ok(typeof w.planUpload === 'function', 'planUpload is a page global');
ok(typeof w.stageFile === 'function', 'stageFile is a page global');
ok(jsdomErrors.length === 0, 'the page loaded without a script error', jsdomErrors[0]);

const GiB = 1024 * 1024 * 1024;
const small = w.planUpload({ size: 32 * 1024 * 1024 });
const mid = w.planUpload({ size: 32 * 1024 * 1024 + 1 });
const report = w.planUpload({ size: 200 * 1024 * 1024 });
const huge = w.planUpload({ size: 4 * GiB + 1 });

ok(small.mode === 'json', 'a file of 32 MB stays on one JSON POST', small.mode);
ok(mid.mode === 'chunk', 'a file just over 32 MB is chunked', mid.mode);
ok(report.mode === 'chunk', 'a 200 MB report is chunked, not refused', report.mode);
ok(huge.mode === 'refuse', 'a file over 4 GB is refused', huge.mode);
ok(w.UPLOAD_MAX_BYTES === undefined, 'the old 90 MB constant is gone');
ok(typeof w.uploadWarning === 'function', 'uploadWarning is a page global');

const twoGb = w.uploadWarning({ size: 2 * GiB }, null);
const fiveGb = w.uploadWarning({ size: 4 * GiB + 1 }, null);
const reportWarn = w.uploadWarning({ size: 200 * 1024 * 1024 }, null);
const fitsRaisedCap = w.uploadWarning({ size: Math.floor(1.5 * GiB) }, { runner_cap: 2 * GiB, file_cap: 4 * GiB, disk_remaining: 20 * GiB });
const noRoom = w.uploadWarning({ size: 200 * 1024 * 1024 }, { runner_cap: GiB, file_cap: 4 * GiB, disk_remaining: 100 });
ok(twoGb.action === 'warn' && twoGb.reason === 'runner_cap', 'a 2 GB file is warned before upload', twoGb.action);
ok(fiveGb.action === 'refuse' && fiveGb.reason === 'file_cap', 'a file over 4 GB is a hard refuse', fiveGb.reason);
ok(reportWarn.action === 'ok', 'a 200 MB report is not warned', reportWarn.action);
ok(fitsRaisedCap.action === 'ok', 'a raised runner cap is honoured', fitsRaisedCap.action);
ok(noRoom.action === 'refuse' && noRoom.reason === 'disk', 'a file staging cannot hold is refused before upload', noRoom.reason);

const src = fs.readFileSync(INDEX, 'utf8');
ok(src.includes('function planUpload'), 'planUpload is defined in the page');
ok(!src.includes('}ody:'), 'the chunk branch was not left half-applied');
ok(src.includes('Do not raise N8N_PAYLOAD_SIZE_MAX'), 'the 413 copy does not tell the operator to raise the body cap');
ok(src.includes('uploadWarning(pendingFile'), 'Process checks the warning before the first chunk');

console.log();
if (failures) {
  console.error(`${failures} FAILURE(S) of ${checks}`);
  process.exit(1);
}
console.log(`smoke_frontend_upload: all ${checks} checks passed`);
// jsdom leaves timers running; without this the process never exits.
process.exit(0);
