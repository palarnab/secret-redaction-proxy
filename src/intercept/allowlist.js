'use strict';

const config = require('../config');

/**
 * Decide whether a host should be TLS-intercepted (decrypted for redaction) or
 * blind-tunnelled. Supports exact matches and leading-dot suffix wildcards.
 */
function shouldIntercept(hostname, allowlist = config.allowlist) {
  const host = String(hostname || '').trim().toLowerCase();
  if (!host) return false;
  for (const pattern of allowlist) {
    const p = String(pattern).trim().toLowerCase();
    if (!p) continue;
    if (p.startsWith('.')) {
      // ".example.com" matches example.com and any subdomain.
      if (host === p.slice(1) || host.endsWith(p)) return true;
    } else if (p.startsWith('*.')) {
      const suffix = p.slice(1); // ".example.com"
      if (host.endsWith(suffix)) return true;
    } else if (host === p) {
      return true;
    }
  }
  return false;
}

module.exports = { shouldIntercept };
