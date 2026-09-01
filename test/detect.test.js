'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { detect } = require('../src/detect');
const { shannonEntropy } = require('../src/detect/entropy');
const corpus = require('./corpus/secrets');

test('detects each positive secret type in the corpus', () => {
  for (const { type, text } of corpus.positives) {
    const matches = detect(text);
    assert.ok(matches.length > 0, `no match for ${type}: ${text}`);
    const types = matches.map((m) => m.type);
    assert.ok(
      types.includes(type),
      `expected type ${type} but got [${types.join(', ')}] for: ${text}`
    );
  }
});

test('does not raise fail-closed detectors on benign strings', () => {
  const { evaluate } = require('../src/policy');
  for (const text of corpus.negatives) {
    const matches = detect(text);
    const blocking = matches.filter((m) => evaluate(m).action === 'block');
    assert.strictEqual(
      blocking.length,
      0,
      `benign string triggered a block via [${blocking
        .map((m) => m.type)
        .join(', ')}]: ${text}`
    );
  }
});

test('resolves overlapping matches into non-overlapping spans', () => {
  const text = 'key sk-abcdef12345ABCDEF67890ghijklMNOPqrstUVWX here';
  const matches = detect(text);
  for (let i = 0; i < matches.length; i++) {
    for (let j = i + 1; j < matches.length; j++) {
      const a = matches[i];
      const b = matches[j];
      const overlap = a.start < b.end && b.start < a.end;
      assert.ok(!overlap, 'matches must not overlap');
    }
  }
});

test('entropy of random base64 is higher than english prose', () => {
  const random = 'Xk9pLm2QaZ7bR4tYw1sVn8cD3fG6hJ0';
  const prose = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  assert.ok(shannonEntropy(random) > shannonEntropy(prose));
});

test('detects a JWT and marks high confidence when segments decode', () => {
  const jwt = corpus.positives.find((p) => p.type === 'jwt').text;
  const matches = detect(jwt);
  const jwtMatch = matches.find((m) => m.type === 'jwt');
  assert.ok(jwtMatch, 'JWT not detected');
  assert.ok(jwtMatch.confidence >= 0.9, 'valid JWT should be high confidence');
});
