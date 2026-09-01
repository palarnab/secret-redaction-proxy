'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { Vault } = require('../src/vault');
const { redactString, redactJson } = require('../src/redact');
const { restoreString } = require('../src/restore');
const { createOpenAiRestore } = require('../src/intercept/stream/sse-openai');
const { createAnthropicRestore } = require('../src/intercept/stream/sse-anthropic');
const corpus = require('./corpus/secrets');

test('redact then restore is identity when model echoes placeholders', () => {
  for (const { type, text } of corpus.positives) {
    const vault = new Vault();
    const { value: redacted, hits } = redactString(text, vault);
    assert.ok(hits.length > 0, `no redaction for ${type}`);
    assert.notStrictEqual(redacted, text, `value unchanged for ${type}`);

    // Model echoes the redacted text verbatim.
    const { value: restored } = restoreString(redacted, vault);
    assert.strictEqual(restored, text, `restore mismatch for ${type}`);
  }
});

test('fakes are format-preserving (same length, structure) for prefix keys', () => {
  const vault = new Vault();
  const text = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
  const { value, hits } = redactString(text, vault);
  assert.strictEqual(value.length, text.length, 'length must be preserved');
  assert.ok(value.startsWith('ghp_'), 'prefix must be preserved');
  assert.notStrictEqual(value, text, 'fake must differ from real');
  assert.strictEqual(hits[0].type, 'github-pat');
});

test('redactJson preserves object structure and keys', () => {
  const obj = {
    model: 'gpt-4',
    messages: [
      { role: 'user', content: 'Use key sk_live_abcdefghijklmnop12345678 please' },
      { role: 'assistant', content: 'ok' },
    ],
    nested: { deep: { uri: 'mongodb+srv://admin:S3cr3tPass@c0.ab12.mongodb.net/db' } },
  };
  const original = JSON.parse(JSON.stringify(obj));
  const vault = new Vault();
  const { value, hits } = redactJson(obj, vault);

  assert.ok(hits.length >= 2, 'expected multiple redactions');
  assert.deepStrictEqual(Object.keys(value), Object.keys(original));
  assert.strictEqual(value.messages.length, original.messages.length);
  assert.strictEqual(value.model, original.model);
  // Secret values changed, non-secret text preserved.
  assert.notStrictEqual(value.messages[0].content, original.messages[0].content);
  assert.strictEqual(value.messages[1].content, original.messages[1].content);

  // Round-trip restore over a concatenation of the redacted values.
  const blob = JSON.stringify(value);
  const { value: restoredBlob } = restoreString(blob, vault);
  assert.ok(restoredBlob.includes('sk_live_abcdefghijklmnop12345678'));
  assert.ok(restoredBlob.includes('S3cr3tPass'));
});

test('same real value maps to the same fake (idempotent tokenization)', () => {
  const vault = new Vault();
  const key = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
  const text = `${key} and again ${key}`;
  const { value } = redactString(text, vault);
  const fakes = vault.fakes();
  assert.strictEqual(fakes.length, 1, 'one unique fake for one unique secret');
  const occurrences = value.split(fakes[0]).length - 1;
  assert.strictEqual(occurrences, 2, 'both occurrences replaced with same fake');
});

test('OpenAI SSE restore reassembles a placeholder split across deltas', () => {
  const vault = new Vault();
  const secret = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
  const { value: redacted } = redactString(secret, vault);
  const fake = vault.fakes()[0];
  assert.strictEqual(redacted, fake);

  // Split the fake across two content deltas.
  const half = Math.floor(fake.length / 2);
  const part1 = fake.slice(0, half);
  const part2 = fake.slice(half);

  const restorer = createOpenAiRestore(vault, {});
  let out = '';
  out += restorer.push(sseData({ choices: [{ delta: { content: 'Your key ' } }] }));
  out += restorer.push(sseData({ choices: [{ delta: { content: part1 } }] }));
  out += restorer.push(sseData({ choices: [{ delta: { content: part2 } }] }));
  out += restorer.push(
    sseData({ choices: [{ delta: {}, finish_reason: 'stop' }] })
  );
  out += restorer.push('data: [DONE]\n\n');
  out += restorer.end();

  const contents = extractOpenAiContents(out);
  assert.ok(
    contents.includes(secret),
    `expected restored secret in stream, got: ${JSON.stringify(contents)}`
  );
  assert.ok(!contents.includes(fake), 'fake must not leak to the harness');
});

test('Anthropic SSE restore reassembles a placeholder split across deltas', () => {
  const vault = new Vault();
  const secret = 'sk_live_abcdefghijklmnop12345678';
  const { value: fake } = redactString(secret, vault);
  const half = Math.floor(fake.length / 2);

  const restorer = createAnthropicRestore(vault, {});
  let out = '';
  out += restorer.push(anthropicDelta('Here: '));
  out += restorer.push(anthropicDelta(fake.slice(0, half)));
  out += restorer.push(anthropicDelta(fake.slice(half)));
  out += restorer.push('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  out += restorer.end();

  const text = extractAnthropicText(out);
  assert.ok(text.includes(secret), `expected restored secret, got: ${text}`);
  assert.ok(!text.includes(fake), 'fake must not leak');
});

test('restore is a safe no-op when the model mangles the placeholder', () => {
  const vault = new Vault();
  const secret = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
  const { value: fake } = redactString(secret, vault);
  const mangled = fake.slice(0, 10) + ' ...truncated... ' + fake.slice(-4);
  const { value: restored } = restoreString(mangled, vault);
  assert.strictEqual(restored, mangled, 'no exact match => unchanged');
  assert.ok(!restored.includes(secret), 'never emits the real secret on a miss');
});

// --- helpers ---
function sseData(obj) {
  return 'data: ' + JSON.stringify(obj) + '\n\n';
}
function anthropicDelta(textVal) {
  return (
    'event: content_block_delta\n' +
    'data: ' +
    JSON.stringify({
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'text_delta', text: textVal },
    }) +
    '\n\n'
  );
}
function extractOpenAiContents(stream) {
  let out = '';
  for (const line of stream.split('\n')) {
    if (!line.startsWith('data:')) continue;
    const payload = line.slice(5).trim();
    if (payload === '[DONE]') continue;
    try {
      const obj = JSON.parse(payload);
      const c = obj.choices && obj.choices[0] && obj.choices[0].delta;
      if (c && typeof c.content === 'string') out += c.content;
    } catch {
      /* ignore */
    }
  }
  return out;
}
function extractAnthropicText(stream) {
  let out = '';
  for (const line of stream.split('\n')) {
    if (!line.startsWith('data:')) continue;
    const payload = line.slice(5).trim();
    try {
      const obj = JSON.parse(payload);
      if (obj.type === 'content_block_delta' && obj.delta && obj.delta.text) {
        out += obj.delta.text;
      }
    } catch {
      /* ignore */
    }
  }
  return out;
}
