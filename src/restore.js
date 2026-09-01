'use strict';

/**
 * Reverse substitution: replace fake placeholders in model output with the real
 * values from the vault. Restoration is best-effort — if the model paraphrased
 * or mangled a placeholder, no exact match is found and it is safely left as-is
 * (the harness receives the fake, never a corrupted secret).
 *
 * Uses literal (non-regex) replacement so fakes containing URL/JSON punctuation
 * are handled correctly.
 */

/**
 * Restore a complete string. Returns rewritten text plus which fakes were hit.
 * @param {string} str
 * @param {import('./vault').Vault} vault
 * @param {object} [ctx] { stats }
 * @returns {{ value: string, restored: string[] }}
 */
function restoreString(str, vault, ctx = {}) {
  const fakes = vault.fakes();
  if (fakes.length === 0 || !str) return { value: str, restored: [] };

  // Replace longer fakes first to avoid partial-overlap issues.
  const ordered = fakes.slice().sort((a, b) => b.length - a.length);
  let result = str;
  const restored = [];

  for (const fake of ordered) {
    if (result.indexOf(fake) === -1) continue;
    const real = vault.realFor(fake);
    result = splitJoin(result, fake, real);
    restored.push(fake);
    if (ctx.stats) ctx.stats.recordRestoration(fake);
    if (ctx.stats && ctx.audit && ctx.host) {
      ctx.audit.restoration({ fingerprint: ctx.stats.fingerprint(real), host: ctx.host });
    }
  }

  return { value: result, restored };
}

function splitJoin(haystack, needle, replacement) {
  return haystack.split(needle).join(replacement);
}

/**
 * Streaming restorer for SSE / chunked responses. A placeholder may be split
 * across chunks, so text is buffered and the emit boundary is chosen so it
 * never cuts through a placeholder occurrence: any fake that straddles the
 * tentative cut is fully retained for the next chunk.
 */
class StreamRestorer {
  constructor(vault, ctx = {}) {
    this.vault = vault;
    this.ctx = ctx;
    this.buffer = '';
    const fakes = vault.fakes();
    this.maxFakeLen = fakes.reduce((max, f) => Math.max(max, f.length), 0);
    // Longest first so the cut check considers the widest placeholders.
    this._fakes = fakes.slice().sort((a, b) => b.length - a.length);
  }

  /**
   * Feed a chunk; returns the safe-to-emit portion (already restored).
   * @param {string} chunk
   * @returns {string}
   */
  push(chunk) {
    this.buffer += chunk;
    if (this.maxFakeLen === 0) {
      const out = this.buffer;
      this.buffer = '';
      return out;
    }
    const keep = this.maxFakeLen - 1;
    if (this.buffer.length <= keep) return '';

    const c0 = this.buffer.length - keep;
    let cut = c0;
    for (const fake of this._fakes) {
      let idx = 0;
      while ((idx = this.buffer.indexOf(fake, idx)) !== -1) {
        const end = idx + fake.length;
        if (idx < c0 && c0 < end) cut = Math.min(cut, idx);
        idx += 1;
      }
    }
    if (cut <= 0) return '';

    const commit = this.buffer.slice(0, cut);
    this.buffer = this.buffer.slice(cut);
    return this._restore(commit);
  }

  /** Flush remaining buffered text at stream end. */
  end() {
    const tail = this.buffer;
    this.buffer = '';
    return this._restore(tail);
  }

  _restore(text) {
    if (!text) return '';
    const { value } = restoreString(text, this.vault, this.ctx);
    return value;
  }
}

module.exports = { restoreString, StreamRestorer };
