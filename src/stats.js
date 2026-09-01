'use strict';

const crypto = require('crypto');
const config = require('./config');

/**
 * Session statistics. Tracks counts and per-type/per-detector hits. Never
 * stores raw secret values — only salted hash fingerprints so a type can be
 * correlated across occurrences without exposing the secret.
 */
class Stats {
  constructor(opts = {}) {
    this.salt =
      opts.salt ||
      config.fingerprintSalt ||
      crypto.randomBytes(16).toString('hex');
    this.requestsProcessed = 0;
    this.redactions = 0;
    this.restorations = 0;
    this.failClosedBlocks = 0;
    this.byType = new Map(); // type -> count
    this.byDetector = new Map(); // detector -> count
    this.fingerprints = new Map(); // fingerprint -> { type, count }
    this._pendingFakes = new Set(); // fakes redacted but not yet restored
  }

  fingerprint(value) {
    return crypto
      .createHmac('sha256', this.salt)
      .update(value)
      .digest('hex')
      .slice(0, 16);
  }

  recordRequest() {
    this.requestsProcessed++;
  }

  recordRedaction(hit) {
    this.redactions++;
    this.byType.set(hit.type, (this.byType.get(hit.type) || 0) + 1);
    this.byDetector.set(
      hit.detector,
      (this.byDetector.get(hit.detector) || 0) + 1
    );
    const fp = this.fingerprint(hit.match);
    const entry = this.fingerprints.get(fp) || { type: hit.type, count: 0 };
    entry.count++;
    this.fingerprints.set(fp, entry);
    if (hit.fake) this._pendingFakes.add(hit.fake);
  }

  recordRestoration(fake) {
    this.restorations++;
    this._pendingFakes.delete(fake);
  }

  recordBlock() {
    this.failClosedBlocks++;
  }

  /** Redactions that were never restored (model didn't echo verbatim). */
  get restoreMisses() {
    return this._pendingFakes.size;
  }

  /**
   * Render the end-of-session summary text.
   * @param {string} [auditPath]
   */
  summary(auditPath) {
    const lines = [];
    lines.push('=== Redaction session summary ===');
    lines.push(`Requests processed:      ${this.requestsProcessed}`);
    lines.push(`Redactions performed:    ${this.redactions}`);
    lines.push(`Restorations performed:  ${this.restorations}`);
    lines.push(
      `Restore misses (no-op):  ${this.restoreMisses}   (model did not echo placeholder verbatim)`
    );
    lines.push(`Fail-closed blocks:      ${this.failClosedBlocks}`);
    lines.push('Secret types protected:');
    const types = Array.from(this.byType.entries()).sort((a, b) => b[1] - a[1]);
    if (types.length === 0) {
      lines.push('  (none)');
    } else {
      const width = Math.max(...types.map(([t]) => t.length));
      for (const [type, count] of types) {
        lines.push(`  ${type.padEnd(width)}  x${count}`);
      }
    }
    const det = Array.from(this.byDetector.entries())
      .map(([d, c]) => `${d}=${c}`)
      .join(', ');
    lines.push(`Per-detector hits: ${det || '(none)'}`);
    if (auditPath) lines.push(`Audit log: ${auditPath}   (fingerprints only, no raw values)`);
    return lines.join('\n');
  }
}

module.exports = { Stats };
