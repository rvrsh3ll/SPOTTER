#!/usr/bin/env node
/*
 * Headless smoke test for the Prompt tab's context budget.
 *
 * Why this exists
 * ---------------
 * On 2026-09-04 an operator asked the Prompt tab a normal multi-tool question
 * ("what vulnerabilities lead to the most lucrative compromise") and lost the
 * whole turn to:
 *
 *   You passed 32769 input tokens and requested 0 output tokens. However, the
 *   model's context length is only 32768 tokens ...
 *
 * The agent loop in sendChat() appends every tool result to `messages` and
 * removes nothing. Fixed overhead is ~5.6k tokens (system prompt + the twelve
 * tool schemas) and MAX_TOOL_ROUNDS allows twelve more results of up to
 * TOOL_RESULT_MAX_CHARS each, so the loop could build a ~78k-token request
 * against a 32,768-token vLLM window — four rounds succeeded and the fifth was
 * refused, discarding four rounds of paid-for graph queries.
 *
 * The Ollama path is worse and quieter: `n_ctx_seq` was measured at 8192, and
 * Ollama TRUNCATES rather than refusing, so the model answers from a transcript
 * it never received and the operator sees a confident answer built on nothing.
 *
 * What this asserts is the invariant that keeps both from happening:
 *
 *   1. a transcript that would overflow is trimmed BELOW the budget before the
 *      request is built, not after the backend complains
 *   2. trimming NEVER breaks tool_call_id pairing — every role:'tool' message
 *      still answers a tool_call issued by an assistant message before it.
 *      This is the trap: splicing out an old tool result to save tokens makes
 *      the backend reject the ENTIRE request, turning a partial answer into no
 *      answer at all
 *   3. the question being asked is never trimmed away
 *   4. an elided result leaves a stub naming the tool and how to re-fetch it,
 *      so the model reads a gap rather than concluding the store is empty
 *   5. the real vLLM refusal is recognised as a context overflow (and not as a
 *      tool-parse failure, which shares HTTP 400) and its limit is parsed out,
 *      so the true window is learned from the backend
 *   6. _capToolResult honours a per-round budget smaller than the constant
 *
 * Test 1 replays the actual failing turn: the REAL system prompt length, the
 * REAL tool schemas, and twelve max-size tool results against 32768.
 *
 *   node scripts/smoke_frontend_context_budget.js
 *
 * Exit 0 = pass. Exit 1 = at least one assertion failed (all are reported).
 *
 * What it CANNOT tell you: whether _estTokens matches the model's real
 * tokenizer. It is deliberately pessimistic (3 chars/token); the loop's
 * _isContextOverflow retry is what covers an estimate that is still too kind.
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

/* Top-level `const` is not a window property, so the constants have to be read
   through eval in the page's own scope. Function declarations are on window. */
const K = w.eval('({ TOOL_RESULT_MAX_CHARS, TOOL_RESULT_MIN_CHARS,'
  + ' LLM_ANSWER_RESERVE_TOKENS, LLM_CONTEXT_FALLBACK, MAX_CTX_RETRIES,'
  + ' toolsJson: JSON.stringify(SPOTTER_TOOLS) })');

/* Build a transcript shaped exactly like the one the loop produces: a system
   prompt, the operator's question, then N rounds of (assistant tool_calls,
   tool result). Sizes come from the real constants, not from guesses. */
function makeTranscript(rounds, sysChars, resultChars) {
  const msgs = [
    { role: 'system',  content: 'S'.repeat(sysChars) },
    { role: 'user',    content: 'What vulnerabilities in this network would lead me to the most lucrative compromise?' },
  ];
  const histEnd = msgs.length;
  for (let i = 0; i < rounds; i++) {
    const id = `call_${i}`;
    msgs.push({ role: 'assistant', content: null, tool_calls: [
      { id, type: 'function', function: { name: 'get_attack_paths', arguments: '{"limit":50}' } } ]});
    msgs.push({ role: 'tool', tool_call_id: id, name: 'get_attack_paths',
                content: JSON.stringify({ rows: 'R'.repeat(resultChars) }) });
  }
  return { msgs, histEnd };
}

/* The invariant a naive trim breaks. Every role:'tool' message must answer a
   tool_call_id issued by an assistant message EARLIER in the array. */
function pairingIntact(msgs) {
  const issued = new Set();
  for (const m of msgs) {
    if (m.role === 'assistant' && m.tool_calls) m.tool_calls.forEach(tc => issued.add(tc.id));
    if (m.role === 'tool') {
      if (!issued.has(m.tool_call_id)) return `orphaned tool reply ${m.tool_call_id}`;
      issued.delete(m.tool_call_id);
    }
  }
  return issued.size ? `unanswered tool_call(s): ${[...issued].join(', ')}` : null;
}

/* ── 1. the turn that actually failed ─────────────────────────────────────── */
section('the 2026-09-04 failure, replayed against a 32768-token window');
{
  /* The real numbers off this build: the tool schemas are measured, and the
     system prompt is sized from the source template that produced ~13k chars. */
  const SYS_CHARS = 13000;
  const CTX = 32768;
  const budget = CTX - K.LLM_ANSWER_RESERVE_TOKENS - w._estTokens(K.toolsJson);

  const { msgs, histEnd } = makeTranscript(12, SYS_CHARS, K.TOOL_RESULT_MAX_CHARS);
  const before = w._tokensOf(msgs);
  ok(before > CTX, 'the untrimmed transcript really does overflow the window',
     `${before} tokens vs ${CTX}`);

  const fit = w._fitMessages(msgs, budget, histEnd);
  const after = w._tokensOf(msgs);
  ok(after <= budget, 'trimmed to fit the budget before the request is built',
     `${after} tokens vs budget ${budget}`);
  ok(fit.elided > 0, 'it reports what it elided', JSON.stringify(fit));

  const orphan = pairingIntact(msgs);
  ok(orphan === null, 'tool_call_id pairing survives the trim', orphan);

  const last = msgs[msgs.length - 1];
  ok(msgs[0].role === 'system', 'the system prompt is still first', msgs[0].role);
  ok(msgs.some(m => m.role === 'user' && /most lucrative compromise/.test(m.content || '')),
     'the question being asked is never trimmed away');
  ok(last.role === 'tool', 'the most recent tool result is still the last message', last.role);

  const stub = msgs.find(m => m._elided);
  const parsed = stub ? JSON.parse(stub.content) : {};
  ok(/get_attack_paths/.test(parsed._dropped || ''),
     'an elided result names the tool it came from', parsed._dropped);
  ok(/re-call/i.test(parsed._recover || ''),
     'and tells the model how to fetch it again', parsed._recover);

  /* The two most recent results are what the model is reasoning about; a trim
     that fits without touching them must leave them readable. */
  const tools = msgs.filter(m => m.role === 'tool');
  ok(!tools[tools.length - 1]._elided,
     'the newest result is kept intact when the budget allows');
}

/* ── 2. the Ollama-sized window, where the backend would truncate silently ── */
section('an 8192-token window (this host\'s measured Ollama n_ctx_seq)');
{
  const CTX = 8192;
  /* Use the reserve sendChat() actually applies, not the flat constant. The
     ceiling became a FRACTION of the window (LLM_ANSWER_RESERVE_FRACTION) exactly
     because a flat 3072 eats 37% of an 8k window; this line kept the pre-fraction
     arithmetic and so tested a budget production never asks _fitMessages for —
     ~1,200 tokens tighter here. It only passed while the tool schemas were small
     enough to leave slack. */
  const budget = CTX - w._answerReserve(CTX) - w._estTokens(K.toolsJson);
  const { msgs, histEnd } = makeTranscript(6, 13000, K.TOOL_RESULT_MAX_CHARS);

  const fit = w._fitMessages(msgs, budget, histEnd);
  const after = w._tokensOf(msgs);
  ok(after <= budget, 'a window too small even for the system prompt still fits',
     `${after} tokens vs budget ${budget}`);
  ok(fit.truncatedSystem === true,
     'and it says the system prompt itself had to be cut', JSON.stringify(fit));
  ok(pairingIntact(msgs) === null, 'pairing survives even the worst case',
     pairingIntact(msgs));
  ok(msgs.some(m => m.role === 'user'), 'the operator question survives');
}

/* ── 3. a transcript that already fits is left alone ───────────────────────── */
section('no trimming when it is not needed');
{
  const { msgs, histEnd } = makeTranscript(1, 2000, 500);
  const snapshot = JSON.stringify(msgs);
  const fit = w._fitMessages(msgs, 32768, histEnd);
  ok(JSON.stringify(msgs) === snapshot, 'messages are untouched');
  ok(fit.elided === 0 && fit.dropped === 0 && !fit.truncatedSystem,
     'and nothing is reported to the operator', JSON.stringify(fit));
}

/* ── 4. recognising the backend's own refusal ──────────────────────────────── */
section('reading the backend refusal');
{
  const VLLM = 'You passed 32769 input tokens and requested 0 output tokens. However, '
    + "the model's context length is only 32768 tokens, resulting in a maximum input "
    + 'length of 32768 tokens. Please reduce the length of the input prompt. '
    + '(parameter=input_tokens, value=32769)';

  ok(w._isContextOverflow(400, VLLM) === true,
     'the real vLLM 400 is recognised as a context overflow');
  ok(w._ctxLimitFromError(VLLM) === 32768,
     'and the true window is parsed out of it', w._ctxLimitFromError(VLLM));

  /* Both failure modes answer HTTP 400 through Open WebUI, and the loop checks
     the parse-failure branch FIRST — so they must not overlap, or a context
     overflow would be retried as a malformed tool call and never trimmed. */
  ok(w._isToolParseFailure(400, VLLM) === false,
     'and it is NOT mistaken for a malformed tool call');
  ok(w._isContextOverflow(400, 'XML syntax error on line 7: unexpected EOF') === false,
     'while a real parse failure is not mistaken for an overflow');
  ok(w._isContextOverflow(401, 'Not authenticated') === false,
     'an auth failure is neither');

  ok(w._ctxLimitFromError("This model's maximum context length is 8192 tokens") === 8192,
     'the OpenAI/older-vLLM wording is understood too');
}

/* ── 5. the per-round result budget ────────────────────────────────────────── */
section('_capToolResult honours a live per-round budget');
{
  /* Rows are wide enough that even the first shrink step (15 items) is well
     over the floor — otherwise every budget produces the same output and the
     test proves nothing. */
  const big = { items: Array.from({ length: 400 }, (_, i) => ({
    name: `HOST-${i}.corp.local`, note: 'X'.repeat(600) })) };
  const raw = JSON.stringify(big).length;
  ok(raw > K.TOOL_RESULT_MAX_CHARS, 'the fixture is genuinely oversized', raw);

  const wide = JSON.stringify(w._capToolResult(big)).length;
  ok(wide <= K.TOOL_RESULT_MAX_CHARS,
     'with no budget it falls back to the constant', wide);

  const tight = JSON.stringify(w._capToolResult(big, 6000)).length;
  ok(tight <= 6000 && tight < wide,
     'a smaller per-round budget produces a smaller result', `${tight} vs ${wide}`);

  /* A late round can compute a tiny or negative allowance. The floor keeps the
     result worth reading rather than shrinking it to nothing, and the result
     still has to say it was trimmed so the model can ask for the rest. */
  const floored = w._capToolResult(big, -500);
  const flen = JSON.stringify(floored).length;
  ok(flen > 0 && flen <= K.TOOL_RESULT_MIN_CHARS,
     'a negative allowance is floored, not obeyed literally', flen);
  ok(/re-call/i.test(floored._truncated || ''),
     'and a trimmed result tells the model how to get the rest', floored._truncated);
}

/* ── 6. learning and remembering a model's window ──────────────────────────── */
section('context limits learned from the model list');
{
  w.localStorage.removeItem('s.llmCtxMap');
  /* The shape Open WebUI actually returns: vLLM entries carry max_model_len,
     Ollama entries carry nothing. */
  w._harvestContextLimits([
    { id: 'Qwen/Qwen3.8-27B-FP8', owned_by: 'openai', max_model_len: 32768 },
    { id: 'qwen3.8:27b-spotter-ui', owned_by: 'ollama' },
  ]);
  const map = JSON.parse(w.localStorage.getItem('s.llmCtxMap') || '{}');
  ok(map['Qwen/Qwen3.8-27B-FP8'] === 32768,
     'the vLLM window is harvested off /api/models', JSON.stringify(map));
  ok(map['qwen3.8:27b-spotter-ui'] === undefined,
     'an Ollama entry advertises nothing and is left to the fallback');
  ok(K.LLM_CONTEXT_FALLBACK > 0 && K.LLM_CONTEXT_FALLBACK <= 8192,
     'and the fallback is not larger than what Ollama actually loads',
     K.LLM_CONTEXT_FALLBACK);

  w._rememberContextLimit('some-model', 16384);
  ok(JSON.parse(w.localStorage.getItem('s.llmCtxMap'))['some-model'] === 16384,
     'a limit learned from an error is remembered');
}

/* ── 6b. repeated tool results, measured, then compacted if they are a large
   share of a window the turn still fits in. A summarizer is not the fix:
   the digest copies identifier, sid, path, score and count out of the JSON. */
section('repeated tool results against a 49152-token window');
{
  const CTX = 49152;
  const budget = CTX - w._answerReserve(CTX) - w._estTokens(K.toolsJson);
  const SID = 'S-1-5-21-1001';
  const PATH = 'alice@CORP.LOCAL -> DC01$';
  const SCORE = 87;
  function richTranscript(rounds, resultChars) {
    const msgs = [
      { role: 'system', content: 'S'.repeat(13000) },
      { role: 'user', content: 'What vulnerabilities in this network would lead me to the most lucrative compromise?' },
    ];
    for (let i = 0; i < rounds; i++) {
      const id = `call_r${i}`;
      const body = {
        identifier: 'alice@CORP.LOCAL',
        sid: SID,
        path: PATH,
        score: SCORE,
        count: 3,
        rows: 'R'.repeat(resultChars),
      };
      msgs.push({ role: 'assistant', content: null, tool_calls: [
        { id, type: 'function', function: { name: 'get_attack_paths', arguments: '{"limit":50}' } } ]});
      msgs.push({ role: 'tool', tool_call_id: id, name: 'get_attack_paths',
                  content: JSON.stringify(body) });
    }
    return msgs;
  }
  const msgs = richTranscript(6, 14000);
  const before = w._repeatedToolTokens(msgs);
  const share = before.repeated / budget;
  console.log(`        measured: ${before.total} tokens, ${before.repeated} repeated `
    + `across ${before.rounds} rounds, share ${share.toFixed(3)} of budget ${budget}`);
  ok(before.total < budget, 'a 6-round capped trace still fits a 49152 window',
     `${before.total} vs ${budget}`);
  ok(share >= 0.25, 'older rounds are a large share of that budget, which is the cost',
     share.toFixed(3));
  ok(pairingIntact(msgs) === null, 'pairing is intact before compaction', pairingIntact(msgs));
  ok(msgs.some(m => m.role === 'user' && /most lucrative compromise/.test(m.content || '')),
     'the operator question is in the trace');

  const n = w._compactConsumedTools(msgs, budget);
  ok(n === 4, 'only the rounds older than the two newest are compacted', n);
  const tools = msgs.filter(m => m.role === 'tool');
  ok(tools.slice(-2).every(m => !m._compacted && /R{20}/.test(m.content)),
     'the two newest rounds stay intact');
  ok(tools.slice(0, 4).every(m => m._compacted && m.tool_call_id),
     'compacted results keep tool_call_id');
  const digest = JSON.parse(tools[0].content);
  ok(digest._facts && digest._facts.sid === SID && digest._facts.path === PATH
     && digest._facts.score === SCORE && digest._facts.count === 3,
     'the digest copies sid, path, score and count, it does not rewrite them',
     JSON.stringify(digest._facts));
  ok(pairingIntact(msgs) === null, 'pairing survives compaction', pairingIntact(msgs));

  const one = richTranscript(1, 14000);
  const two = richTranscript(2, 14000);
  ok(w._compactConsumedTools(one, budget) === 0, 'one round is not compacted');
  ok(w._compactConsumedTools(two, budget) === 0, 'two rounds are not compacted');
}

/* ── 7. the whole loop, driven against a backend that refuses round 5 ─────────
   The unit checks above prove _fitMessages is correct. This proves the LOOP
   uses it: a real sendChat() turn, a real tool trace, and a backend that
   answers the fifth request exactly the way vLLM answered on 2026-09-04. The
   operator must end the turn with an ANSWER — the whole point of the
   degrade-never-to-zero rule is that four rounds of paid-for graph queries are
   not thrown away by one refusal. */
section('sendChat() survives the refusal and still answers');
(async () => {
  const rounds = [];
  let n = 0;
  w.fetch = async (url, opt) => {
    const u = String(url);
    if (/\/api\/models/.test(u))
      return { ok: true, status: 200, json: async () => ({ data: [
        { id: 'Qwen/Qwen3.8-27B-FP8', max_model_len: 32768 } ] }) };
    if (/llm-query/.test(u))
      return { ok: true, status: 200, json: async () => ({ row_count: 900,
        rows: Array.from({ length: 900 }, (_, i) => ({ name: `HOST-${i}.corp.local`, path: 'X'.repeat(400) })) }) };
    if (/chat\/completions/.test(u)) {
      const body = JSON.parse(opt.body);
      n++;
      rounds.push({ n, tokens: w._tokensOf(body.messages) + (body.tools ? w._estTokens(JSON.stringify(body.tools)) : 0) });
      if (n <= 4) return { ok: true, status: 200, json: async () => ({ choices: [ { message: {
        content: null, tool_calls: [ { id: 'c' + n, type: 'function',
          function: { name: 'get_attack_paths', arguments: '{"limit":50}' } } ] } } ] }) };
      if (n === 5) return { ok: false, status: 400, json: async () => ({ detail:
        'You passed 32769 input tokens and requested 0 output tokens. However, the model\'s context '
        + 'length is only 32768 tokens, resulting in a maximum input length of 32768 tokens. Please '
        + 'reduce the length of the input prompt. (parameter=input_tokens, value=32769)' }) };
      return { ok: true, status: 200, json: async () => ({ choices: [ { message: {
        content: 'DC01 and the SQL cluster are the lucrative pivot.' } } ] }) };
    }
    return { ok: false, status: 404, json: async () => ({ detail: 'not mocked' }) };
  };

  w.eval("_activeCampId='c1'");
  w.document.getElementById('llmModel').value = 'Qwen/Qwen3.8-27B-FP8';
  w.document.getElementById('chatInput').value =
    'What vulnerabilities in this network would lead me to the most lucrative compromise?';
  await w.sendChat();

  const bubbles = [...w.document.querySelectorAll('#chat-msgs .cmsg')];
  const answer  = bubbles.filter(e => e.className.includes('cmsg-asst'));
  const errors  = bubbles.filter(e => e.className.includes('cmsg-err'));
  const traces  = bubbles.filter(e => /▸/.test(e.textContent));

  ok(errors.length === 0, 'the refusal never reaches the operator as an error',
     errors.map(e => e.textContent.trim().slice(0, 120)).join(' | '));
  ok(answer.length === 1 && /lucrative pivot/.test(answer[0].textContent),
     'the turn ends with a real answer',
     answer.map(e => e.textContent.trim().slice(0, 80)).join(' | '));
  ok(traces.length === 4, 'and all four rounds of tool results were kept, not discarded',
     traces.length);
  ok(n === 6, 'the refused round was re-run rather than abandoned', `${n} requests`);

  /* Every request the loop built must have been inside the window it knew about
     — that is the invariant the operator lost the turn to. */
  const over = rounds.filter(r => r.tokens > 32768);
  ok(over.length === 0, 'no request was ever built larger than the model window',
     JSON.stringify(rounds));

  console.log(`\n${failures ? 'FAILED' : 'PASSED'} — ${checks - failures}/${checks} checks`);
  process.exit(failures ? 1 : 0);
})();
