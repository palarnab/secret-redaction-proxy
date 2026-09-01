# Security & Limitations

Read this before relying on the proxy. It is a **prototype** that meaningfully reduces
accidental secret exposure to LLM providers — not a guarantee of zero leakage.

---

## Threat model

**Protects against:** secrets embedded in **conversation payloads** — pasted connection
strings, API keys in files the agent reads, env dumps, etc. — reaching the model provider in
cleartext.

**Assumes:** the local machine, the proxy process, and the local CA private key are trusted.
Anyone who can read `ca/ca.key.pem` can mint certificates your machine trusts — treat it like a
password (it is gitignored by default).

**Does not defend against:** a malicious harness, malware already on the host, or a network
attacker with your CA key.

---

## What is and isn't touched

| Item | Handling |
|---|---|
| Request body (JSON leaf strings) | Scanned; matches replaced with format-preserving fakes |
| JSON structure, method, path, query | Never modified |
| `Authorization` / `x-api-key` headers | Passed through — this is your upstream auth; the model never sees headers |
| Non-allowlisted hosts | Blind-tunnelled — never decrypted |
| Upstream TLS identity | Verified against the public CA store (no MITM upstream) |
| Response bodies | Placeholders restored (best-effort) before reaching the harness |

---

## Honest limitations

1. **Not 100% leak-proof — detector coverage is finite.** Novel or custom secret formats can be
   missed (false negatives). The layered detectors (regex + structural + entropy) maximize
   recall but cannot know every shape.
2. **Restoration is best-effort.** If the model paraphrases or splits a placeholder across the
   JSON escaping of separate streamed tokens, it may not reassemble. The result is a safe no-op
   (the harness sees the placeholder, never a corrupted secret) — counted as a *restore miss*.
3. **No response decompression yet.** The proxy forces `Accept-Encoding: identity` upstream so
   it can read/restore plaintext. A provider that ignores this and gzips anyway would yield a
   response the proxy can't restore (it would pass through compressed).
4. **Certificate pinning.** A client that pins a specific public certificate will refuse the
   proxy's leaf cert. Most Node-based harnesses don't pin today — verify per client version.
5. **Header/URL secrets are not redacted by design.** The provider API key lives in headers and
   is required for auth; the model never sees headers, so it is passed through.
6. **Prototype-grade performance/robustness.** Connection handling, edge cases, and load
   behavior are minimally hardened.

---

## Data-handling guarantees

- **The vault never persists.** It is in-memory, per-request, and zeroized after restore.
  → [../src/vault.js](../src/vault.js)
- **The audit log contains no raw secrets.** Only `type` + a salted HMAC-SHA256 **fingerprint**
  (16 hex chars), timestamps, host, and outcomes. → [../src/audit-log.js](../src/audit-log.js)
- **Stats print types + counts + fingerprints only** — never values.
  → [../src/stats.js](../src/stats.js)
- **Fail-closed:** a high-confidence, high-value secret that can't be tokenized **blocks** the
  request (HTTP 403) rather than risk a cleartext leak. → [../src/policy.js](../src/policy.js)

---

## Operational safety checklist

- [ ] `ca/ca.key.pem` is not committed or shared (it is gitignored).
- [ ] Only intended LLM hosts are on the `--allowlist`; everything else blind-tunnels.
- [ ] `SRP_FP_SALT` is set if you need audit fingerprints comparable across restarts — and kept
      out of source control.
- [ ] The `audit/` directory is treated as sensitive-metadata (fingerprints + hosts) and
      excluded from sharing.
- [ ] Demos and tests use **fake** credentials only (see
      [../test/corpus/secrets.js](../test/corpus/secrets.js)).
- [ ] When finished, remove `HTTPS_PROXY` / `NODE_EXTRA_CA_CERTS` and, if desired, delete the CA
      from `Cert:\CurrentUser\Root`.

---

## Verifying the guarantees

The guarantees above are enforced by tests
([../test/roundtrip.test.js](../test/roundtrip.test.js),
[../test/integrity.test.js](../test/integrity.test.js),
[../test/detect.test.js](../test/detect.test.js)):

```powershell
npm test
```

Covers: redact → restore identity, format-preserving fakes, idempotent tokenization, JSON
structure preservation, SSE reassembly of split placeholders, safe no-op on mangled echoes,
fail-closed blocking, and fingerprint privacy (no raw secret in the fingerprint).
