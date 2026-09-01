# Secret-Redaction Proxy

A local **forward proxy with TLS interception (MITM)** that sits between an AI coding
harness (GitHub Copilot / Claude / any LLM client) and the upstream model API. It detects
secrets in outbound traffic, replaces them with **format-preserving fakes**, forwards the
sanitized request, then **restores** the real values in the response so the harness keeps
working. At session end it reports how many redactions/restorations happened and which secret
*types* were protected — never the values.

See [plan.md](plan.md) for the full design rationale, goals, and honest limitations.
Task-focused guides live in [docs/](docs/README.md): [setup & usage](docs/setup-and-usage.md),
[demo guide](docs/demo.md), [architecture](docs/architecture.md),
[security & limitations](docs/security-and-limitations.md), and
[troubleshooting](docs/troubleshooting.md).

> **This is a prototype / proof-of-concept.** It is **not** 100% leak-proof — see
> [Limitations](#limitations).

---

## How it works

```
Harness  --HTTPS_PROXY-->  Redaction Proxy (localhost:8787)  --TLS-->  Real LLM API
                                  |
                    detect -> tokenize (vault) -> forward
                    restore <- reverse-substitute <- response
                                  |
                             stats + audit log
```

1. The client (with `HTTPS_PROXY` set) sends `CONNECT api.anthropic.com:443`.
2. If the host is on the **allowlist**, the proxy terminates TLS using a leaf cert minted by a
   local CA (which you trust once), reads the plaintext request, and **redacts** secrets.
3. The proxy opens its **own** TLS connection to the real upstream (validated against public
   CAs — no MITM upstream) and forwards the sanitized request.
4. The response is **restored** (fakes → real values) and written back to the client.
5. Non-allowlisted hosts are **blind-tunnelled** — never decrypted.

Outbound request validity is **guaranteed** (the proxy controls the exact bytes). Inbound
restoration is **best-effort**: if the model doesn't echo a placeholder verbatim, restore is a
safe no-op (the harness gets the placeholder, never a corrupted secret).

---

## Quick start

```powershell
# 1. Install dependencies
npm install

# 2. Generate the local CA
node src/tools/gen-ca.js
#    -> writes ca\ca.pem (certificate) and ca\ca.key.pem (private key)

# 3. Trust the CA (current user)
Import-Certificate -FilePath "$PWD\ca\ca.pem" -CertStoreLocation Cert:\CurrentUser\Root

# 4. Run the proxy
node src/server.js --port 8787 --allowlist api.openai.com,api.anthropic.com

# 5. Point a harness at it (new shell, before launching the client)
$env:HTTPS_PROXY        = "http://localhost:8787"
$env:NODE_EXTRA_CA_CERTS = "$PWD\ca\ca.pem"
$env:NO_PROXY           = "localhost,127.0.0.1"
code .    # or: claude
```

Press **Ctrl+C** on the proxy to stop and print the session summary.

> Node ignores the OS trust store, so `NODE_EXTRA_CA_CERTS` is required for Node-based
> harnesses (VS Code / Copilot, Claude Code) even after importing the CA into Windows.

### VS Code / GitHub Copilot `settings.json`

```jsonc
{
  "http.proxy": "http://localhost:8787",
  "http.proxyStrictSSL": true,
  "http.proxySupport": "on",
  "http.systemCertificates": true
}
```

---

## CLI

```
node src/server.js [options]

  --port <n>            Listen port (default 8787)
  --host <addr>         Listen address (default 127.0.0.1)
  --allowlist a,b,c     Comma-separated hosts to TLS-intercept (else blind-tunnel)
  --no-audit            Disable the JSONL audit log
  --verbose             Log intercept/tunnel decisions to stderr

node src/tools/gen-ca.js [--out <caDir>] [--force]
```

Environment overrides: `SRP_PORT`, `SRP_HOST`, `SRP_CA_DIR`, `SRP_AUDIT_DIR`,
`SRP_FP_SALT`, `SRP_VERBOSE`.

---

## What gets detected

Layered so a secret must slip past every layer to leak:

- **Named regex rules** — AWS (`AKIA…` + secret keys), GitHub PATs (`ghp_…`,
  `github_pat_…`), OpenAI (`sk-…`), Anthropic (`sk-ant-…`), Stripe (`sk_live_…`), Slack
  (`xox…`), Google (`AIza…`), SendGrid, Twilio, npm, Square, …
- **Structural** — JWTs (validated by decoding header/payload), PEM private-key blocks,
  connection strings (`mongodb+srv://`, `postgres://`, `mysql://`, `redis://`, …), and any
  URL carrying `user:pass@` credentials.
- **Entropy** — high Shannon-entropy tokens no named rule caught (unknown/opaque keys),
  redact-only so legitimate high-entropy text is not over-blocked.
- **Validators** — offline sanity checks that adjust confidence (never a network call).

### Policy

- **Fail-closed:** a high-confidence, high-value secret that cannot be tokenized **blocks the
  request** (HTTP 403) rather than risk a cleartext leak.
- **Redact-only:** entropy-only hits are redacted but never block on their own.

---

## Session summary & audit log

On shutdown the proxy prints, e.g.:

```
=== Redaction session summary ===
Requests processed:      142
Redactions performed:    37
Restorations performed:  35
Restore misses (no-op):   2   (model did not echo placeholder verbatim)
Fail-closed blocks:       1
Secret types protected:
  mongodb-uri     x12
  jwt             x 9
  ...
Per-detector hits: regex=22, structural=9, entropy=6
Audit log: ./audit/2026-09-01.jsonl   (fingerprints only, no raw values)
```

The audit log (`audit/<date>.jsonl`) records outcomes with **type + salted hash fingerprint
only** — never raw secret values.

---

## Project layout

```
src/
  server.js                 proxy entry: CONNECT, MITM termination, forwarding
  config.js                 ports, allowlist, thresholds, policy
  intercept/
    ca.js                   CA load + per-host leaf-cert minting
    allowlist.js            which hosts to intercept vs blind-tunnel
    stream/
      sse.js                generic SSE restore transform
      sse-openai.js         OpenAI chat-completions adapter
      sse-anthropic.js      Anthropic messages adapter
  detect/
    index.js                detector orchestration + overlap resolution
    regex-rules.js          named vendor patterns
    structural.js           JWT / PEM / connection strings / creds URLs
    entropy.js              Shannon-entropy catch-all
    validators.js           offline confidence refinement
  redact.js                 recursive JSON walk -> tokenize
  restore.js                reverse-substitution (+ streaming buffer)
  vault.js                  per-request real<->fake map, zeroized after use
  fakes.js                  format-preserving fake generators
  policy.js                 fail-closed / redact / ignore decisions
  stats.js                  counters + salted fingerprints
  audit-log.js              append-only JSONL (no raw secrets)
  tools/gen-ca.js           local CA generator
test/                       detect / roundtrip / integrity suites + corpus
```

---

## Development

```powershell
npm test    # runs node --test over test/*.test.js
```

---

## Limitations

- **Not 100% leak-proof.** Detector coverage is finite: novel/custom secret formats can be
  missed (false negatives).
- **Restoration is best-effort.** If the model paraphrases or splits a placeholder across the
  JSON escaping of separate streaming tokens, it may not reassemble — the fake passes through
  unchanged (never a corrupted secret).
- Does **not** redact the provider API key in `Authorization` / `x-api-key` headers — that is
  the upstream credential and the model never sees headers.
- Does not defend against a client that **pins** a specific public certificate. Verify per
  client version.
- Prototype-grade transport: forces `accept-encoding: identity` upstream so responses can be
  read/restored (no gzip handling yet).
