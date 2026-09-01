'use strict';

const config = require('./config');

/**
 * Policy engine. Decides, per detected match, whether to:
 *   - 'redact'  substitute with a fake (default),
 *   - 'block'   fail-closed if the fake cannot be produced (high-value types),
 *   - 'ignore'  low-confidence noise below the redaction floor.
 */

// Below this confidence a match is treated as noise and left untouched.
const REDACT_FLOOR = 0.3;

/**
 * @param {{type:string, confidence:number}} match
 * @returns {{ action: 'redact'|'block'|'ignore' }}
 */
function evaluate(match) {
  if (match.confidence < REDACT_FLOOR) return { action: 'ignore' };

  if (config.redactOnlyTypes.has(match.type)) {
    return { action: 'redact' };
  }

  if (config.failClosedTypes.has(match.type) && match.confidence >= 0.8) {
    // High-confidence dangerous secret: must be tokenized or blocked.
    return { action: 'block' };
  }

  return { action: 'redact' };
}

module.exports = { evaluate, REDACT_FLOOR };
