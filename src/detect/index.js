'use strict';

/**
 * Detector registry + orchestration. Runs regex, structural, and entropy
 * detectors over a string, applies validators, then resolves overlapping
 * matches into a non-overlapping, sorted set (highest confidence / longest
 * wins) so redaction never double-substitutes the same span.
 */

const { runRegexRules } = require('./regex-rules');
const { runStructural } = require('./structural');
const { runEntropy } = require('./entropy');
const { applyValidators } = require('./validators');

/**
 * Detect secrets in a single string.
 * @param {string} value
 * @param {object} [opts]
 * @returns {{type:string,match:string,start:number,end:number,confidence:number,detector:string}[]}
 */
function detect(value, opts = {}) {
  if (typeof value !== 'string' || value.length === 0) return [];

  let matches = [
    ...runRegexRules(value),
    ...runStructural(value),
    ...runEntropy(value, opts),
  ];

  matches = applyValidators(matches);
  return resolveOverlaps(matches);
}

/**
 * Keep the strongest, non-overlapping matches. Preference order:
 *   1. higher confidence
 *   2. longer span
 *   3. non-entropy detector over entropy (named rules trump catch-all)
 */
function resolveOverlaps(matches) {
  if (matches.length <= 1) return matches.slice().sort(byStart);

  const sorted = matches.slice().sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    const lenA = a.end - a.start;
    const lenB = b.end - b.start;
    if (lenB !== lenA) return lenB - lenA;
    const aEnt = a.detector === 'entropy' ? 1 : 0;
    const bEnt = b.detector === 'entropy' ? 1 : 0;
    return aEnt - bEnt;
  });

  const chosen = [];
  for (const m of sorted) {
    const overlaps = chosen.some((c) => m.start < c.end && m.end > c.start);
    if (!overlaps) chosen.push(m);
  }
  return chosen.sort(byStart);
}

function byStart(a, b) {
  return a.start - b.start;
}

module.exports = { detect, resolveOverlaps };
