'use strict';

const { StringDecoder } = require('string_decoder');
const { StreamRestorer } = require('../../restore');

/**
 * Generic SSE restore transform. Parses an event stream into frames, extracts
 * the model's text delta via a provider adapter, and restores placeholders
 * across delta boundaries using a rolling-buffer StreamRestorer. Framing bytes
 * (`event:`/`data:` lines, blank-line separators) are preserved; only the
 * decoded text content is rewritten.
 *
 * Restoration is best-effort: a placeholder split across the JSON escaping of
 * separate deltas may not reassemble, in which case the fake is passed through
 * unchanged (never a corrupted secret).
 *
 * Adapter contract:
 *   extract(obj)      -> string|null   text delta carried by this event
 *   inject(obj, text) -> obj           put restored text back into the event
 *   isFinal(obj)      -> boolean       event that terminates content
 *   flushEvent(text)  -> string        a full SSE event carrying leftover text
 */
class SseRestoreStream {
  constructor(vault, ctx, adapter) {
    this.restorer = new StreamRestorer(vault, ctx);
    this.adapter = adapter;
    this.frameBuf = '';
    this.decoder = new StringDecoder('utf8');
  }

  push(buf) {
    this.frameBuf += typeof buf === 'string' ? buf : this.decoder.write(buf);
    let out = '';
    let idx;
    while ((idx = this.frameBuf.indexOf('\n\n')) !== -1) {
      const raw = this.frameBuf.slice(0, idx);
      this.frameBuf = this.frameBuf.slice(idx + 2);
      out += this._handleEvent(raw) + '\n\n';
    }
    return out;
  }

  end() {
    let out = '';
    const raw = this.frameBuf + this.decoder.end();
    this.frameBuf = '';
    if (raw.trim()) out += this._handleEvent(raw) + '\n\n';
    out += this._flushPrefix();
    return out;
  }

  _flushPrefix() {
    const tail = this.restorer.end();
    if (!tail) return '';
    return this.adapter.flushEvent(tail);
  }

  _handleEvent(raw) {
    const lines = raw.split('\n');
    const dataLines = lines
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).replace(/^\s/, ''));

    if (dataLines.length === 0) return raw; // e.g. bare `event:` lines

    const dataStr = dataLines.join('\n');
    if (dataStr === '[DONE]') return this._flushPrefix() + raw;

    let obj;
    try {
      obj = JSON.parse(dataStr);
    } catch {
      return raw;
    }

    const text = this.adapter.extract(obj);
    const isFinal = this.adapter.isFinal(obj);

    if (text == null) {
      return isFinal ? this._flushPrefix() + raw : raw;
    }

    const restored = this.restorer.push(text);
    const newObj = this.adapter.inject(obj, restored);
    const rebuilt = lines
      .filter((l) => !l.startsWith('data:'))
      .concat('data: ' + JSON.stringify(newObj))
      .join('\n');

    return isFinal ? this._flushPrefix() + rebuilt : rebuilt;
  }
}

module.exports = { SseRestoreStream };
