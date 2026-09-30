#!/usr/bin/env node
/*
 * smoke_frontend_chat_stream.js — the Prompt tab's streaming transport and its
 * token accounting.
 *
 * WHY THIS EXISTS
 * ---------------
 * sendChat() used to post `stream: false` and wait for the whole completion, so
 * the operator watched "Thinking…" for the entire turn. Decode is the slow half
 * of a turn by a wide margin (measured 2026-09-08: 1.9s prefill against 26.8s of
 * generation on a typical turn), so that meant a blank screen for essentially the
 * whole wait — 28.2s to first paint, against 1.7s streaming.
 *
 * _chatCompletion() now speaks SSE and rebuilds the same response shape the loop
 * always consumed, which makes it the one piece of the chat path where a silent
 * regression is invisible in the UI: a mis-assembled tool call just looks like the
 * model "not calling tools", and a dropped `usage` object just looks like zero.
 * Both are checked here.
 *
 * The awkward parts it pins:
 *   - SSE frames split ACROSS chunk boundaries (a partial trailing line must be
 *     buffered, not parsed and lost)
 *   - tool calls arriving as indexed fragments whose `arguments` accumulate one
 *     string piece at a time
 *   - a mid-stream failure delivered as a data frame, because the HTTP status was
 *     already sent as 200
 *   - a backend that ignores `stream` and answers with a JSON body anyway
 *   - `usage` summed across every round of a multi-round turn, not just the last
 *
 * Runs offline against the real frontend/index.html in jsdom. No stack needed.
 */
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

/* Build a streaming Response-like object. `chunk` is deliberately small and
   co-prime-ish with the frame length so nearly every read lands mid-line — that
   is the case the buffering exists for. */
function sse(frames, { chunk = 29, ctype = 'text/event-stream' } = {}) {
  const payload = frames.map(f =>
    (typeof f === 'string' ? `data: ${f}\n\n` : `data: ${JSON.stringify(f)}\n\n`)).join('')
    + 'data: [DONE]\n\n';
  const bytes = Buffer.from(payload, 'utf8');
  let off = 0;
  return {
    ok: true, status: 200,
    headers: { get: (k) => (/^content-type$/i.test(k) ? ctype : null) },
    body: {
      getReader: () => ({
        read: async () => {
          if (off >= bytes.length) return { done: true, value: undefined };
          const end = Math.min(off + chunk, bytes.length);
          const value = new Uint8Array(bytes.subarray(off, end));
          off = end;
          return { done: false, value };
        },
      }),
    },
  };
}

const textFrame = (s) => ({ choices: [{ delta: { content: s } }] });
const HDRS = { 'Content-Type': 'application/json' };
const URL_ = 'http://x/api/chat/completions';

(async () => {

  /* ── 1. plain text stream ───────────────────────────────────────────── */
  section('a text answer is reassembled across chunk boundaries');
  {
    const seen = [];
    w.fetch = async () => sse([
      textFrame('DC01 '), textFrame('and the SQL '), textFrame('cluster.'),
      { choices: [{ delta: {}, finish_reason: 'stop' }],
        usage: { prompt_tokens: 5399, completion_tokens: 452 } },
    ]);
    const res = await w._chatCompletion(URL_, HDRS, { model: 'm', messages: [] },
      { onText: (t) => seen.push(t) });

    ok(res.ok, 'the stream completes ok', res.errMsg);
    ok(res.data.choices[0].message.content === 'DC01 and the SQL cluster.',
       'every fragment survives the chunk splitting',
       JSON.stringify(res.data.choices[0].message.content));
    ok(res.stats.streamed === true, 'and it went down the streaming path, not the fallback');
    ok(seen.length === 3 && seen[0] === 'DC01 ',
       'onText fired progressively rather than once at the end', JSON.stringify(seen));
    ok(res.data.usage?.prompt_tokens === 5399 && res.data.usage?.completion_tokens === 452,
       'usage from the final frame is captured', JSON.stringify(res.data.usage));
    ok(typeof res.stats.ttft === 'number' && res.stats.ttft >= 0,
       'time-to-first-token is measured', res.stats.ttft);
  }

  /* ── 2. tool-call fragment reassembly ───────────────────────────────── */
  section('tool calls arrive as indexed fragments and must be rejoined');
  {
    w.fetch = async () => sse([
      { choices: [{ delta: { tool_calls: [
        { index: 0, id: 'call_a', type: 'function', function: { name: 'get_attack_paths', arguments: '' } }] } }] },
      { choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: '{"lim' } }] } }] },
      /* a second call interleaved with the first — index, not arrival order, is identity */
      { choices: [{ delta: { tool_calls: [
        { index: 1, id: 'call_b', type: 'function', function: { name: 'list_targets', arguments: '{"n":' } }] } }] },
      { choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: 'it":50}' } }] } }] },
      { choices: [{ delta: { tool_calls: [{ index: 1, function: { arguments: '3}' } }] } }] },
      { choices: [{ delta: {}, finish_reason: 'tool_calls' }] },
    ]);
    const res = await w._chatCompletion(URL_, HDRS, { model: 'm', messages: [] });
    const tc = res.data.choices[0].message.tool_calls || [];

    ok(tc.length === 2, 'both interleaved calls are recovered', tc.length);
    ok(tc[0]?.id === 'call_a' && tc[0]?.function.name === 'get_attack_paths',
       'the first call keeps its id and name', JSON.stringify(tc[0]));
    ok(tc[0]?.function.arguments === '{"limit":50}',
       'its arguments are concatenated in order, not overwritten',
       JSON.stringify(tc[0]?.function.arguments));
    ok(tc[1]?.function.arguments === '{"n":3}',
       'and the interleaved second call is assembled independently',
       JSON.stringify(tc[1]?.function.arguments));
    ok(JSON.parse(tc[0].function.arguments).limit === 50,
       'the reassembled arguments are valid JSON the loop can parse');
  }

  /* ── 3. mid-stream error ────────────────────────────────────────────── */
  section('a failure after the 200 arrives as a data frame, not a status');
  {
    w.fetch = async () => sse([
      textFrame('partial answer'),
      { error: { message: 'engine died mid-generation' } },
    ]);
    const res = await w._chatCompletion(URL_, HDRS, { model: 'm', messages: [] });
    ok(res.ok === false, 'the round is reported as failed despite the HTTP 200', res.ok);
    ok(/engine died/.test(res.errMsg), 'the engine message reaches the caller', res.errMsg);
  }

  /* ── 4. non-streaming fallback ──────────────────────────────────────── */
  section('a backend that ignores `stream` still works');
  {
    w.fetch = async () => ({
      ok: true, status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ choices: [{ message: { content: 'whole thing at once' } }],
                           usage: { prompt_tokens: 10, completion_tokens: 4 } }),
    });
    const res = await w._chatCompletion(URL_, HDRS, { model: 'm', messages: [] });
    ok(res.ok && res.data.choices[0].message.content === 'whole thing at once',
       'a JSON body is parsed as a normal completion');
    ok(res.stats.streamed === false, 'and it is not reported as streamed');

    /* No headers, no body, no text() — the shape older mocks and odd proxies use. */
    w.fetch = async () => ({ ok: true, status: 200,
      json: async () => ({ choices: [{ message: { content: 'bare object' } }] }) });
    const res2 = await w._chatCompletion(URL_, HDRS, { model: 'm', messages: [] });
    ok(res2.ok && res2.data.choices[0].message.content === 'bare object',
       'a response object with neither a readable body nor text() falls back cleanly');
  }

  /* ── 5. the request actually asks for a stream ──────────────────────── */
  section('the outgoing request opts into streaming and usage');
  {
    let sent = null;
    w.fetch = async (_u, opt) => { sent = JSON.parse(opt.body); return sse([textFrame('hi')]); };
    await w._chatCompletion(URL_, HDRS, { model: 'm', messages: [{ role: 'user', content: 'q' }] });
    ok(sent.stream === true, 'stream: true is sent', JSON.stringify(sent.stream));
    ok(sent.stream_options?.include_usage === true,
       'include_usage is requested — without it there is no usage frame at all',
       JSON.stringify(sent.stream_options));
  }

  /* ── 6. usage accounting across a real multi-round turn ─────────────── */
  section('token accounting sums every round of a turn, not just the last');
  {
    w.localStorage.removeItem('spotter_llm_usage_v1');
    w.eval('_llmUsageHist = null; _llmUsageSession = { turns:0, rounds:0, prompt:0, completion:0, ms:0 };');

    let n = 0;
    w.fetch = async (url) => {
      const u = String(url);
      if (/\/api\/models/.test(u))
        return { ok: true, status: 200, headers: { get: () => 'application/json' },
                 json: async () => ({ data: [{ id: 'Qwen/Qwen3.8-27B-FP8', max_model_len: 49152 }] }) };
      if (/llm-query/.test(u))
        return { ok: true, status: 200, headers: { get: () => 'application/json' },
                 json: async () => ({ row_count: 2, rows: [{ name: 'DC01' }, { name: 'SQL01' }] }) };
      if (/chat\/completions/.test(u)) {
        n++;
        if (n === 1) return sse([
          { choices: [{ delta: { tool_calls: [
            { index: 0, id: 'c1', type: 'function',
              function: { name: 'get_attack_paths', arguments: '{"limit":5}' } }] } }] },
          { choices: [{ delta: {}, finish_reason: 'tool_calls' }],
            usage: { prompt_tokens: 4900, completion_tokens: 40 } },
        ]);
        return sse([
          textFrame('DC01 is the pivot.'),
          { choices: [{ delta: {}, finish_reason: 'stop' }],
            usage: { prompt_tokens: 6100, completion_tokens: 210 } },
        ]);
      }
      return { ok: false, status: 404, headers: { get: () => 'application/json' },
               json: async () => ({ detail: 'not mocked' }) };
    };

    w.eval("_activeCampId='c1'");
    w.document.getElementById('llmModel').value = 'Qwen/Qwen3.8-27B-FP8';
    w.document.getElementById('chatInput').value = 'Where is the shortest path to DA?';
    await w.sendChat();

    const s = w.eval('JSON.stringify(_llmUsageSession)');
    const sess = JSON.parse(s);
    ok(sess.turns === 1, 'one operator question counts as one turn', sess.turns);
    ok(sess.rounds === 2, 'both backend round-trips are counted as rounds', sess.rounds);
    ok(sess.prompt === 11000,
       'prompt tokens are summed across rounds (4900 + 6100) — the re-prefill cost',
       sess.prompt);
    ok(sess.completion === 250, 'completion tokens are summed too (40 + 210)', sess.completion);

    const note = w.document.querySelector('#chat-msgs .cmsg-usage');
    ok(!!note, 'a per-answer usage line is rendered under the reply');
    ok(note && /11(\.0)?k|11,000/.test(note.textContent),
       'and it reports the turn total, not the last round', note && note.textContent);
    ok(note && /2 rounds/.test(note.textContent),
       'and names the round count', note && note.textContent);

    const bar = w.document.getElementById('llm-usage-bar');
    ok(bar && bar.className === 'on', 'the session usage bar becomes visible',
       bar && JSON.stringify(bar.className));
    ok(bar && /44:1 in\/out|prompt-heavy/.test(bar.textContent),
       'and flags a prompt-heavy ratio, which is where a slow turn actually goes',
       bar && bar.textContent);

    const hist = JSON.parse(w.localStorage.getItem('spotter_llm_usage_v1') || '[]');
    ok(hist.length === 1 && hist[0].prompt === 11000,
       'the turn is persisted for export and later analysis', JSON.stringify(hist));
    ok(Array.isArray(hist[0].tools) && hist[0].tools[0] === 'get_attack_paths',
       'with the tools the turn actually called', JSON.stringify(hist[0].tools));
  }

  /* ── 7. no usage frame at all ───────────────────────────────────────── */
  section('a backend that sends no usage frame still gets accounted for');
  {
    w.localStorage.removeItem('spotter_llm_usage_v1');
    w.eval('_llmUsageHist = null; _llmUsageSession = { turns:0, rounds:0, prompt:0, completion:0, ms:0 };');

    w.fetch = async (url) => {
      const u = String(url);
      if (/\/api\/models/.test(u))
        return { ok: true, status: 200, headers: { get: () => 'application/json' },
                 json: async () => ({ data: [{ id: 'Qwen/Qwen3.8-27B-FP8', max_model_len: 49152 }] }) };
      if (/chat\/completions/.test(u))
        /* No usage frame — the shape a proxy that filters stream_options produces. */
        return sse([ textFrame('SQL01 is exposed.'),
                     { choices: [{ delta: {}, finish_reason: 'stop' }] } ]);
      return { ok: false, status: 404, headers: { get: () => 'application/json' },
               json: async () => ({ detail: 'not mocked' }) };
    };

    w.eval("_activeCampId='c1'");
    w.document.getElementById('llmModel').value = 'Qwen/Qwen3.8-27B-FP8';
    w.document.getElementById('chatInput').value = 'Which host is exposed?';
    await w.sendChat();

    const sess = JSON.parse(w.eval('JSON.stringify(_llmUsageSession)'));
    ok(sess.turns === 1, 'the turn is still recorded', sess.turns);
    ok(sess.prompt > 0, 'prompt tokens fall back to the local estimator', sess.prompt);
    ok(sess.completion > 0, 'completion tokens are estimated from the streamed text',
       sess.completion);
    ok(sess.estimated === true, 'and the session is flagged as estimated', sess.estimated);

    const notes = [...w.document.querySelectorAll('#chat-msgs .cmsg-usage')];
    const last = notes[notes.length - 1];
    ok(last && /~/.test(last.textContent),
       'the operator sees a ~ rather than a guess dressed as a measurement',
       last && last.textContent);
  }

  /* ── 8. the reasoning toggle ────────────────────────────────────────── */
  section('reasoning is on by default and only sent when turned off');
  {
    const bodies = [];
    w.fetch = async (url, opt) => {
      const u = String(url);
      if (/\/api\/models/.test(u))
        return { ok: true, status: 200, headers: { get: () => 'application/json' },
                 json: async () => ({ data: [{ id: 'Qwen/Qwen3.8-27B-FP8', max_model_len: 49152 }] }) };
      if (/chat\/completions/.test(u)) {
        bodies.push(JSON.parse(opt.body));
        return sse([ textFrame('done.'), { choices: [{ delta: {}, finish_reason: 'stop' }] } ]);
      }
      return { ok: false, status: 404, headers: { get: () => 'application/json' },
               json: async () => ({ detail: 'not mocked' }) };
    };
    w.eval("_activeCampId='c1'");
    w.document.getElementById('llmModel').value = 'Qwen/Qwen3.8-27B-FP8';

    ok(w.document.getElementById('llmThink').checked === true,
       'the control ships checked, so no existing turn changes behaviour');

    w.document.getElementById('chatInput').value = 'q1';
    await w.sendChat();
    ok(bodies.at(-1) && !('chat_template_kwargs' in bodies.at(-1)),
       'with reasoning ON no chat_template_kwargs key is sent at all',
       JSON.stringify(bodies.at(-1)?.chat_template_kwargs));

    w.document.getElementById('llmThink').checked = false;
    w.saveLlmCfg();
    w.document.getElementById('chatInput').value = 'q2';
    await w.sendChat();
    ok(bodies.at(-1)?.chat_template_kwargs?.enable_thinking === false,
       'with reasoning OFF enable_thinking:false is sent — the same flag WF10/WF12 use',
       JSON.stringify(bodies.at(-1)?.chat_template_kwargs));
    ok(w.localStorage.getItem('s.llmThink') === '0', 'and the choice is persisted',
       w.localStorage.getItem('s.llmThink'));

    /* Restore, so the default is what a fresh operator gets. */
    w.document.getElementById('llmThink').checked = true;
    w.saveLlmCfg();
  }

  console.log(`\n${failures ? 'FAILED' : 'PASSED'} — ${checks - failures}/${checks} checks`);
  process.exit(failures ? 1 : 0);
})();
