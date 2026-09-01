'use strict';

/**
 * Format-preserving fake generators. Given a secret `type` and the original
 * value, produce a same-shape replacement that:
 *   - preserves recognizable structure (prefixes, separators, length class),
 *   - keeps the payload syntactically valid where the model may reason on it
 *     (JWTs decode, connection strings still parse),
 *   - is random enough to be collision-free against real content.
 *
 * Fakes must never equal the original and must be reversible via exact string
 * replacement, so they avoid ambiguity with surrounding text.
 */

const crypto = require('crypto');

const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const HEX = '0123456789abcdef';
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function randInt(max) {
  return crypto.randomInt(max);
}

function randFrom(alphabet, n) {
  let out = '';
  for (let i = 0; i < n; i++) out += alphabet[randInt(alphabet.length)];
  return out;
}

/** Replace each char with a random char of the same class (letter/digit/other). */
function preserveShape(s) {
  let out = '';
  for (const ch of s) {
    if (ch >= 'a' && ch <= 'z') out += LOWER[randInt(26)];
    else if (ch >= 'A' && ch <= 'Z') out += UPPER[randInt(26)];
    else if (ch >= '0' && ch <= '9') out += DIGITS[randInt(10)];
    else out += ch;
  }
  return out;
}

function base64url(buf) {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function fakeJwt(original) {
  const header = base64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = base64url(
    Buffer.from(
      JSON.stringify({
        sub: randFrom(HEX, 16),
        iat: 1600000000,
        exp: 1700000000,
      })
    )
  );
  // Signature length mirrors HS256 (32 bytes -> 43 base64url chars).
  const sig = randFrom(B64URL, 43);
  const fake = `${header}.${payload}.${sig}`;
  return fake === original ? `${header}.${payload}.${randFrom(B64URL, 43)}` : fake;
}

function fakePem(original) {
  const m = original.match(/-----BEGIN ([^-]+)-----/);
  const label = m ? m[1] : 'PRIVATE KEY';
  const lines = [];
  const bodyLines = 25;
  for (let i = 0; i < bodyLines; i++) lines.push(randFrom(B64URL, 64));
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

/** Replace credentials/host in a URI (connection string or URL with creds). */
function fakeUri(original) {
  try {
    // URL() handles most schemes; connection strings like mongodb+srv:// too.
    const u = new URL(original);
    if (u.username) u.username = randFrom(LOWER, u.username.length || 6);
    if (u.password) u.password = randFrom(ALNUM, u.password.length || 12);
    if (u.hostname) {
      const parts = u.hostname.split('.');
      parts[0] = randFrom(LOWER + DIGITS, parts[0].length || 6);
      u.hostname = parts.join('.');
    }
    const fake = u.toString();
    return fake === original ? preserveShape(original) : fake;
  } catch {
    return preserveShape(original);
  }
}

const PREFIX_TYPES = {
  'aws-access-key-id': (o) => 'AKIA' + randFrom(UPPER + DIGITS, o.length - 4),
  'openai-key': (o) => keepPrefixRandom(o, /^sk-(proj-)?/, ALNUM),
  'anthropic-key': (o) => keepPrefixRandom(o, /^sk-ant-[a-z0-9]{0,8}-?/, ALNUM),
  'github-pat': (o) => keepPrefixRandom(o, /^gh[pousr]_/, ALNUM),
  'stripe-secret-key': (o) => keepPrefixRandom(o, /^sk_(live|test)_/, ALNUM),
  'google-api-key': (o) => keepPrefixRandom(o, /^AIza/, ALNUM + '-_'),
  'sendgrid-key': (o) => keepPrefixRandom(o, /^SG\./, ALNUM + '._-'),
  'twilio-key': (o) => keepPrefixRandom(o, /^SK/, HEX),
};

function keepPrefixRandom(original, prefixRe, alphabet) {
  const m = original.match(prefixRe);
  const prefix = m ? m[0] : '';
  const rest = original.slice(prefix.length);
  let fake = prefix + randFrom(alphabet, rest.length);
  if (fake === original) fake = prefix + randFrom(alphabet, rest.length);
  return fake;
}

/**
 * @param {string} type detector type
 * @param {string} original the real matched string
 * @returns {string} format-preserving fake
 */
function generateFake(type, original) {
  if (type === 'jwt') return fakeJwt(original);
  if (type === 'private-key-pem') return fakePem(original);
  if (
    type === 'connection-string' ||
    type === 'mongodb-uri' ||
    type === 'url-with-credentials'
  ) {
    return fakeUri(original);
  }
  if (PREFIX_TYPES[type]) return PREFIX_TYPES[type](original);

  // aws-secret-access-key, gcp keys, high-entropy blobs, generic: shape-preserve.
  const fake = preserveShape(original);
  return fake === original ? preserveShape(original) : fake;
}

module.exports = { generateFake, preserveShape, randFrom };
