'use strict';

const fs = require('fs');
const path = require('path');
const config = require('./config');

/**
 * Append-only JSONL audit log. Records outcomes (redaction, restoration, block)
 * with type + salted fingerprint only — never raw secret values.
 */
class AuditLog {
  constructor(opts = {}) {
    this.dir = opts.dir || config.auditDir;
    this.enabled = opts.enabled !== false;
    this._stream = null;
    this._path = null;
    if (this.enabled) this._open();
  }

  _open() {
    fs.mkdirSync(this.dir, { recursive: true });
    const day = new Date().toISOString().slice(0, 10);
    this._path = path.join(this.dir, `${day}.jsonl`);
    this._stream = fs.createWriteStream(this._path, { flags: 'a' });
  }

  get path() {
    return this._path;
  }

  _write(record) {
    if (!this.enabled || !this._stream) return;
    this._stream.write(JSON.stringify({ ts: new Date().toISOString(), ...record }) + '\n');
  }

  redaction({ type, detector, fingerprint, host }) {
    this._write({ event: 'redaction', type, detector, fingerprint, host });
  }

  restoration({ fingerprint, host }) {
    this._write({ event: 'restoration', fingerprint, host });
  }

  block({ type, reason, host }) {
    this._write({ event: 'block', type, reason, host });
  }

  sessionSummary(summaryObj) {
    this._write({ event: 'session-summary', ...summaryObj });
  }

  close() {
    if (this._stream) this._stream.end();
  }
}

module.exports = { AuditLog };
