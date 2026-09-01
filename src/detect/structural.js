'use strict';

/**
 * Structural detectors: things recognized by shape/grammar rather than a fixed
 * vendor prefix — JWTs, PEM private-key blocks, connection strings, and any URL
 * carrying embedded credentials.
 */

/** JWT: three base64url segments; header+payload must be JSON when decoded. */
const JWT_RE = /\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b/g;

/** PEM private key block (RSA/EC/OPENSSH/generic). */
const PEM_RE =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g;

/** Connection strings with credentials: scheme://user:pass@host... */
const CONN_RE =
  /\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|amqps|rediss):\/\/[^\s:/@]+:[^\s:/@]+@[^\s/]+[^\s]*)/g;

/** Any URL with user:pass@ credentials (http/https/ftp/etc.). */
const URL_CREDS_RE = /\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s:/@]+@[^\s/]+[^\s]*)/gi;

function decodesToJson(seg) {
  try {
    const b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64 + '==='.slice((b64.length + 3) % 4);
    const json = Buffer.from(pad, 'base64').toString('utf8');
    JSON.parse(json);
    return true;
  } catch {
    return false;
  }
}

function pushMatch(out, type, value, matched, start, confidence) {
  out.push({
    type,
    match: matched,
    start,
    end: start + matched.length,
    confidence,
    detector: 'structural',
  });
}

/**
 * @param {string} value
 * @returns {{type:string,match:string,start:number,end:number,confidence:number,detector:'structural'}[]}
 */
function runStructural(value) {
  const out = [];

  // JWT (validate header+payload decode to JSON to cut false positives).
  JWT_RE.lastIndex = 0;
  let m;
  while ((m = JWT_RE.exec(value)) !== null) {
    const tok = m[1];
    const [h, p] = tok.split('.');
    const confidence = decodesToJson(h) && decodesToJson(p) ? 0.95 : 0.6;
    pushMatch(out, 'jwt', value, tok, m.index + m[0].indexOf(tok), confidence);
  }

  // PEM private keys.
  PEM_RE.lastIndex = 0;
  while ((m = PEM_RE.exec(value)) !== null) {
    pushMatch(out, 'private-key-pem', value, m[0], m.index, 0.99);
  }

  // Connection strings with creds (mongodb/postgres/etc.).
  CONN_RE.lastIndex = 0;
  while ((m = CONN_RE.exec(value)) !== null) {
    const tok = m[1];
    const type = /^mongodb/i.test(tok) ? 'mongodb-uri' : 'connection-string';
    pushMatch(out, type, value, tok, m.index + m[0].indexOf(tok), 0.9);
  }

  // Generic URL with credentials (skip ones already caught as conn strings).
  URL_CREDS_RE.lastIndex = 0;
  while ((m = URL_CREDS_RE.exec(value)) !== null) {
    const tok = m[1];
    const start = m.index + m[0].indexOf(tok);
    const overlaps = out.some(
      (x) => start < x.end && start + tok.length > x.start
    );
    if (!overlaps) {
      pushMatch(out, 'url-with-credentials', value, tok, start, 0.85);
    }
  }

  return out;
}

module.exports = { runStructural, decodesToJson };
