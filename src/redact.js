'use strict';

/**
 * Recursive JSON walk that redacts secret string values in place. The parsed
 * object's structure (keys, arrays, nesting) is never mutated — only leaf
 * string values that a detector flags are substituted with format-preserving
 * fakes drawn from the vault.
 */

const { detect } = require('./detect');
const { evaluate } = require('./policy');

/**
 * Redact a single string. Returns the (possibly) rewritten string plus the
 * hits that were applied and any policy block.
 *
 * @param {string} str
 * @param {import('./vault').Vault} vault
 * @param {object} ctx { stats }
 * @returns {{ value: string, hits: Array, blocked: null | {type, reason} }}
 */
function redactString(str, vault, ctx = {}) {
  const matches = detect(str);
  if (matches.length === 0) return { value: str, hits: [], blocked: null };

  const hits = [];
  // Apply substitutions right-to-left so earlier indices stay valid.
  const ordered = matches.slice().sort((a, b) => b.start - a.start);
  let result = str;

  for (const m of ordered) {
    const decision = evaluate(m);
    if (decision.action === 'ignore') continue;

    const fake = vault.tokenize(m.match, m.type);
    if (!fake) {
      // Could not tokenize. Fail-closed types block the whole request.
      if (decision.action === 'block') {
        return {
          value: str,
          hits,
          blocked: { type: m.type, reason: 'untokenizable-high-confidence' },
        };
      }
      continue; // redact-only type that couldn't be faked: skip safely.
    }

    result = result.slice(0, m.start) + fake + result.slice(m.end);
    const hit = { ...m, fake };
    hits.push(hit);
    if (ctx.stats) ctx.stats.recordRedaction(hit);
  }

  return { value: result, hits, blocked: null };
}

/**
 * Recursively redact all string leaves of a parsed JSON value.
 * @returns {{ value: any, hits: Array, blocked: null | object }}
 */
function redactJson(node, vault, ctx = {}) {
  const allHits = [];

  function walk(n) {
    if (typeof n === 'string') {
      const { value, hits, blocked } = redactString(n, vault, ctx);
      if (blocked) throw new BlockError(blocked);
      for (const h of hits) allHits.push(h);
      return value;
    }
    if (Array.isArray(n)) {
      for (let i = 0; i < n.length; i++) n[i] = walk(n[i]);
      return n;
    }
    if (n && typeof n === 'object') {
      for (const k of Object.keys(n)) n[k] = walk(n[k]);
      return n;
    }
    return n;
  }

  try {
    const value = walk(node);
    return { value, hits: allHits, blocked: null };
  } catch (e) {
    if (e instanceof BlockError) {
      return { value: node, hits: allHits, blocked: e.info };
    }
    throw e;
  }
}

class BlockError extends Error {
  constructor(info) {
    super('policy-block');
    this.info = info;
  }
}

module.exports = { redactString, redactJson };
