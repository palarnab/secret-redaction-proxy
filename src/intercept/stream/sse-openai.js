'use strict';

const { SseRestoreStream } = require('./sse');

/**
 * OpenAI Chat Completions SSE adapter. Text lives at
 * choices[0].delta.content; the stream ends with a finish_reason then
 * `data: [DONE]`.
 */
const adapter = {
  extract(obj) {
    const c = obj && obj.choices && obj.choices[0];
    if (!c || !c.delta || typeof c.delta.content !== 'string') return null;
    return c.delta.content;
  },
  inject(obj, text) {
    obj.choices[0].delta.content = text;
    return obj;
  },
  isFinal(obj) {
    const c = obj && obj.choices && obj.choices[0];
    return !!(c && c.finish_reason);
  },
  flushEvent(text) {
    const obj = { choices: [{ index: 0, delta: { content: text } }] };
    return 'data: ' + JSON.stringify(obj) + '\n\n';
  },
};

function createOpenAiRestore(vault, ctx) {
  return new SseRestoreStream(vault, ctx, adapter);
}

module.exports = { createOpenAiRestore, adapter };
