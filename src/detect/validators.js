'use strict';

/**
 * Optional, offline-only validators that refine detector confidence. These
 * never make network calls. A validator returns a multiplier applied to the
 * match confidence (1 = unchanged, >1 boost, <1 penalty) or null to drop.
 */

const { decodesToJson } = require('./structural');

/** AWS secret keys are 40 chars of base64 alphabet — reject obvious words. */
function validateAwsSecret(match) {
  const s = match.match;
  if (s.length !== 40) return 0.5;
  // Must contain a mix (not a single-case English word).
  const hasUpper = /[A-Z]/.test(s);
  const hasLowerOrDigit = /[a-z0-9]/.test(s);
  return hasUpper && hasLowerOrDigit ? 1.1 : 0.6;
}

function validateJwt(match) {
  const [h, p] = match.match.split('.');
  return h && p && decodesToJson(h) && decodesToJson(p) ? 1.1 : 0.7;
}

const VALIDATORS = {
  'aws-secret-access-key': validateAwsSecret,
  jwt: validateJwt,
};

/**
 * Apply validators to a list of matches, adjusting confidence in place.
 * @param {Array} matches
 * @returns {Array} matches (possibly with adjusted confidence, filtered)
 */
function applyValidators(matches) {
  const out = [];
  for (const match of matches) {
    const fn = VALIDATORS[match.type];
    if (!fn) {
      out.push(match);
      continue;
    }
    const mult = fn(match);
    if (mult == null) continue;
    out.push({ ...match, confidence: Math.min(1, match.confidence * mult) });
  }
  return out;
}

module.exports = { applyValidators };
