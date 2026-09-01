'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { Vault } = require('../src/vault');
const { redactJson } = require('../src/redact');
const { Stats } = require('../src/stats');

test('redacted JSON re-serializes to valid JSON', () => {
  const obj = {
    messages: [{ role: 'user', content: 'key AKIAIOSFODNN7EXAMPLE and more' }],
  };
  const vault = new Vault();
  const { value } = redactJson(obj, vault);
  const serialized = JSON.stringify(value);
  assert.doesNotThrow(() => JSON.parse(serialized));
});

test('non-secret leaves are byte-for-byte unchanged', () => {
  const obj = {
    a: 'plain text with no secrets',
    b: 12345,
    c: true,
    d: null,
    e: ['list', 'of', 'strings'],
  };
  const vault = new Vault();
  const { value, hits } = redactJson(obj, vault);
  assert.strictEqual(hits.length, 0);
  assert.deepStrictEqual(value, obj);
});

test('fail-closed block leaves body untouched and reports type', () => {
  // Force tokenization failure by exhausting the vault with a stubbed generator
  // is complex; instead verify the policy path: a high-confidence fail-closed
  // type that cannot be faked returns blocked. We simulate by monkeypatching
  // the vault to refuse tokenization.
  const obj = { content: 'token ghp_1234567890abcdefghijklmnopqrstuvwxyz' };
  const vault = new Vault();
  vault.tokenize = () => null; // simulate inability to produce a fake
  const { value, blocked } = redactJson(obj, vault);
  assert.ok(blocked, 'expected a fail-closed block');
  assert.strictEqual(blocked.type, 'github-pat');
  assert.strictEqual(value.content, obj.content, 'body unchanged on block');
});

test('stats fingerprints are stable and contain no raw secret', () => {
  const stats = new Stats({ salt: 'fixed-salt' });
  const secret = 'AKIAIOSFODNN7EXAMPLE';
  const fp1 = stats.fingerprint(secret);
  const fp2 = stats.fingerprint(secret);
  assert.strictEqual(fp1, fp2, 'fingerprint must be deterministic per salt');
  assert.ok(!fp1.includes(secret), 'fingerprint must not contain the secret');
  assert.match(fp1, /^[a-f0-9]{16}$/);
});

test('stats summary counts redactions, restorations, and misses', () => {
  const stats = new Stats({ salt: 's' });
  stats.recordRequest();
  stats.recordRedaction({ type: 'github-pat', detector: 'regex', match: 'x', fake: 'FAKE1' });
  stats.recordRedaction({ type: 'jwt', detector: 'structural', match: 'y', fake: 'FAKE2' });
  stats.recordRestoration('FAKE1');
  const summary = stats.summary('/tmp/audit.jsonl');
  assert.match(summary, /Redactions performed:    2/);
  assert.match(summary, /Restorations performed:  1/);
  assert.match(summary, /Restore misses \(no-op\):  1/);
  assert.match(summary, /github-pat/);
  assert.match(summary, /jwt/);
});
