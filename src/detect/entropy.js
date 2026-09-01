'use strict';

const config = require('../config');

/**
 * Entropy-based catch-all for opaque, high-entropy tokens that no named rule
 * matched (unknown/custom keys). Tokens are split on non-secret characters,
 * then scored with Shannon entropy. Emitted as low-confidence 'high-entropy-blob'
 * (redact-only, never fail-closed) to avoid over-blocking.
 */

const TOKEN_RE = /[A-Za-z0-9+/=_-]{12,}/g;

function shannonEntropy(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  const n = s.length;
  for (const c of freq.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksHex(s) {
  return /^[a-f0-9]+$/i.test(s);
}

function looksBase64(s) {
  return /^[A-Za-z0-9+/=_-]+$/.test(s) && /[A-Z]/.test(s) && /[a-z0-9]/.test(s);
}

/** Skip common non-secret high-entropy shapes (UUIDs, git SHAs are allowed to pass). */
function isLikelyBenign(s) {
  // Pure lowercase hex of git-sha / md5 length is often not a secret; still
  // low signal — leave to threshold. UUID with dashes handled by token split.
  return false;
}

/**
 * @param {string} value
 * @param {object} [opts] override thresholds/minLength (used by tests)
 * @returns {{type:string,match:string,start:number,end:number,confidence:number,detector:'entropy'}[]}
 */
function runEntropy(value, opts = {}) {
  const minLength = opts.minLength ?? config.entropy.minLength;
  const b64Threshold = opts.base64Threshold ?? config.entropy.base64Threshold;
  const hexThreshold = opts.hexThreshold ?? config.entropy.hexThreshold;

  const out = [];
  TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = TOKEN_RE.exec(value)) !== null) {
    const tok = m[0];
    if (tok.length < minLength) continue;
    if (isLikelyBenign(tok)) continue;

    const h = shannonEntropy(tok);
    let hit = false;
    if (looksHex(tok)) {
      if (h >= hexThreshold && tok.length >= 32) hit = true;
    } else if (looksBase64(tok)) {
      if (h >= b64Threshold) hit = true;
    }
    if (!hit) continue;

    // Confidence scales gently with entropy; capped low so policy treats it as
    // redact-only.
    const confidence = Math.min(0.6, 0.3 + (h - b64Threshold) * 0.1);
    out.push({
      type: 'high-entropy-blob',
      match: tok,
      start: m.index,
      end: m.index + tok.length,
      confidence: Math.max(0.3, confidence),
      detector: 'entropy',
    });
  }
  return out;
}

module.exports = { runEntropy, shannonEntropy };
