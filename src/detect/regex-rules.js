'use strict';

/**
 * Named regex rules ported from common gitleaks/trufflehog patterns. Each rule
 * yields matches with a stable `type`, a `confidence` (0..1), and whether the
 * match itself is the secret (capture group 1 if present, else full match).
 *
 * Rules use the global flag so callers can iterate all occurrences.
 */

/** @typedef {{ type: string, regex: RegExp, confidence: number, group?: number }} Rule */

/** @type {Rule[]} */
const rules = [
  {
    type: 'aws-access-key-id',
    regex: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b/g,
    confidence: 0.95,
  },
  {
    // Contextual AWS secret (key-ish assignment) to reduce false positives.
    type: 'aws-secret-access-key',
    regex:
      /(?:aws.{0,20})?(?:secret|access).{0,20}?['"= :]+([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
    confidence: 0.75,
    group: 1,
  },
  {
    type: 'github-pat',
    regex: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g,
    confidence: 0.98,
  },
  {
    type: 'github-fine-grained-pat',
    regex: /\b(github_pat_[A-Za-z0-9_]{22,255})\b/g,
    confidence: 0.98,
  },
  {
    type: 'openai-key',
    regex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/g,
    confidence: 0.9,
  },
  {
    type: 'anthropic-key',
    regex: /\b(sk-ant-[A-Za-z0-9-]{20,})\b/g,
    confidence: 0.95,
  },
  {
    type: 'stripe-secret-key',
    regex: /\b(sk_(?:live|test)_[A-Za-z0-9]{16,})\b/g,
    confidence: 0.97,
  },
  {
    type: 'stripe-restricted-key',
    regex: /\b(rk_(?:live|test)_[A-Za-z0-9]{16,})\b/g,
    confidence: 0.97,
  },
  {
    type: 'google-api-key',
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    confidence: 0.9,
  },
  {
    type: 'gcp-service-account-key',
    // Private key id / client email combos are structural; catch the raw
    // service-account private_key_id here.
    regex: /"private_key_id"\s*:\s*"([a-f0-9]{40})"/g,
    confidence: 0.85,
    group: 1,
  },
  {
    type: 'sendgrid-key',
    regex: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    confidence: 0.95,
  },
  {
    type: 'twilio-key',
    regex: /\b(SK[a-f0-9]{32})\b/g,
    confidence: 0.8,
  },
  {
    type: 'npm-token',
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
    confidence: 0.95,
  },
  {
    type: 'square-token',
    regex: /\b(sq0[a-z]{3}-[A-Za-z0-9_-]{22,43})\b/g,
    confidence: 0.9,
  },
];

/**
 * Run all regex rules against a string and return raw matches.
 * @param {string} value
 * @returns {{type:string,match:string,start:number,end:number,confidence:number,detector:'regex'}[]}
 */
function runRegexRules(value) {
  const out = [];
  for (const rule of rules) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(value)) !== null) {
      const groupIdx = rule.group || (m[1] !== undefined ? 1 : 0);
      const matched = m[groupIdx];
      if (matched == null) continue;
      const start = m.index + m[0].indexOf(matched);
      out.push({
        type: rule.type,
        match: matched,
        start,
        end: start + matched.length,
        confidence: rule.confidence,
        detector: 'regex',
      });
      if (m.index === rule.regex.lastIndex) rule.regex.lastIndex++;
    }
  }
  return out;
}

module.exports = { rules, runRegexRules };
