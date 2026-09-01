'use strict';

const { SseRestoreStream } = require('./sse');

/**
 * Anthropic Messages SSE adapter. Text lives in content_block_delta events at
 * delta.text; message_stop terminates the stream.
 */
const adapter = {
  extract(obj) {
    if (
      obj &&
      obj.type === 'content_block_delta' &&
      obj.delta &&
      typeof obj.delta.text === 'string'
    ) {
      return obj.delta.text;
    }
    return null;
  },
  inject(obj, text) {
    obj.delta.text = text;
    return obj;
  },
  isFinal(obj) {
    return !!(obj && (obj.type === 'message_stop' || obj.type === 'message_delta'));
  },
  flushEvent(text) {
    const obj = {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'text_delta', text },
    };
    return 'event: content_block_delta\n' + 'data: ' + JSON.stringify(obj) + '\n\n';
  },
};

function createAnthropicRestore(vault, ctx) {
  return new SseRestoreStream(vault, ctx, adapter);
}

module.exports = { createAnthropicRestore, adapter };
