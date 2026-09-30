'use strict';
/* Shared rig for the smoke_frontend_*.js suite.
 *
 * Every one of these tests used to open with the same copy-pasted head: an
 * absolute '/root/SPOTTER/frontend/index.html' and a jsdom candidate list that
 * named one nvm-installed node version. Both are host assumptions, and the
 * second is worse than it looks — it pins a node VERSION, so the tests break on
 * this very host after an `nvm install`, not only on someone else's machine.
 *
 * This mirrors the convention the Python side already uses
 * (REPO_ROOT = Path(__file__).resolve().parents[1]) and resolves jsdom from
 * whichever interpreter is actually running.
 *
 * Deliberately NOT here: the per-file ok()/section()/failures scaffolding. It
 * differs subtly between tests (some count checks, some also collect
 * jsdomErrors) and consolidating it would change assertion semantics in 18
 * files at once for no portability gain.
 */

const path = require('path');
const { execFileSync } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');

/* SPOTTER_FRONTEND_INDEX lets the same suite run against a candidate build
   without editing 18 files. */
const INDEX = process.env.SPOTTER_FRONTEND_INDEX ||
              path.join(REPO_ROOT, 'frontend', 'index.html');

function jsdomCandidates() {
  const out = [];
  // 1. Normal resolution: NODE_PATH, or a repo-local node_modules if one ever
  //    appears. This is the answer on a host that ran `npm i -g jsdom`.
  out.push('jsdom');
  // 2. An explicit override, for a host where jsdom lives somewhere unusual.
  if (process.env.SPOTTER_JSDOM) out.push(process.env.SPOTTER_JSDOM);
  // 3. Derived from the interpreter actually executing this file. jsdom ships
  //    inside the n8n install on a SPOTTER host, and deriving the prefix from
  //    process.execPath finds it for WHICHEVER node is running — which is what
  //    survives an nvm upgrade that a hardcoded version string does not.
  const prefix = path.resolve(path.dirname(process.execPath), '..');
  for (const base of [prefix, '/usr/local', '/usr']) {
    out.push(path.join(base, 'lib', 'node_modules', 'n8n', 'node_modules', 'jsdom'));
    out.push(path.join(base, 'lib', 'node_modules', 'jsdom'));
  }
  // 4. Ask npm where its global root is. Cheap, and correct on layouts the
  //    guesses above miss. Wrapped because npm may not be installed at all.
  try {
    const root = execFileSync('npm', ['root', '-g'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10000,
    }).trim();
    if (root) {
      out.push(path.join(root, 'n8n', 'node_modules', 'jsdom'));
      out.push(path.join(root, 'jsdom'));
    }
  } catch { /* npm absent or slow; the guesses above stand */ }
  return [...new Set(out)];
}

/* Returns the jsdom module. Exits 2 — "cannot run" — rather than 1, which the
   suite reserves for "an assertion failed"; a CI job must be able to tell a
   missing dependency from a real regression. */
function loadJsdom() {
  const candidates = jsdomCandidates();
  for (const c of candidates) {
    try { return require(c); } catch { /* try the next */ }
  }
  console.error('FATAL: jsdom not found. Tried:\n  ' + candidates.join('\n  '));
  console.error('\nInstall it with:  npm i -g jsdom');
  console.error('or point SPOTTER_JSDOM at an existing copy.');
  process.exit(2);
}

module.exports = { REPO_ROOT, INDEX, loadJsdom, jsdomCandidates };
