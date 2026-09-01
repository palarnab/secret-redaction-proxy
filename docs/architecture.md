# Architecture

A deeper look at how the proxy intercepts, redacts, restores, and reports — and the guarantees
it makes. For the original design rationale see [../plan.md](../plan.md).

---

## Request lifecycle

```
Harness  --HTTPS_PROXY-->  Redaction Proxy (localhost:8787)  --TLS-->  Real LLM API
                                  |
                    detect -> tokenize (vault) -> forward
                    restore <- reverse-substitute <- response
                                  |
                             stats + audit log
```

1. **CONNECT** — the client sends `CONNECT api.anthropic.com:443`. The proxy learns the target
   host from this line. → [../src/server.js](../src/server.js) `proxy.on('connect', …)`
2. **Allowlist decision** — [../src/intercept/allowlist.js](../src/intercept/allowlist.js):
   - **Intercept** (host on allowlist): reply `200 Connection Established`, then terminate the
     client's TLS using a leaf cert minted for that exact host.
   - **Blind-tunnel** (everything else): open a raw TCP pipe to the host; bytes flow through
     untouched, never decrypted.
3. **Leaf cert minting** — [../src/intercept/ca.js](../src/intercept/ca.js) signs a per-host
   leaf with the local CA, cached per hostname via an SNI callback.
4. **Redact** — the decrypted request is parsed and walked; secret string values are replaced
   with format-preserving fakes recorded in a per-request vault.
5. **Forward** — the proxy opens its **own** TLS connection to the real upstream, validated
   against the public CA store (no MITM upstream), and sends the sanitized request.
6. **Restore** — placeholders in the response are swapped back to real values (buffered for
   streaming) before being written to the client TLS socket.
7. **Report** — counts + salted fingerprints accumulate in stats; outcomes append to the audit
   log. On shutdown a session summary prints.

---

## Two TLS legs, on purpose

```
[ client ] === client-side TLS (our leaf cert, local CA) ===> [ PROXY ] === upstream TLS (real public CA) ===> [ LLM API ]
```

- **Client leg** is intentionally MITM'd so the proxy can read plaintext.
- **Upstream leg** uses normal certificate validation — the proxy is a genuine TLS client, so
  the real provider's identity is verified. `rejectUnauthorized` is never disabled.

---

## Provider-agnostic core, thin per-format streaming

- The **redaction core treats the body as opaque JSON** and recurses over every string leaf —
  no provider schema knowledge. → [../src/redact.js](../src/redact.js)
- The **only** provider-specific code is **SSE reassembly**, because a placeholder can be split
  across streamed tokens. Thin adapters configure a generic transform:
  - [../src/intercept/stream/sse.js](../src/intercept/stream/sse.js) — generic engine
  - [../src/intercept/stream/sse-openai.js](../src/intercept/stream/sse-openai.js)
  - [../src/intercept/stream/sse-anthropic.js](../src/intercept/stream/sse-anthropic.js)
  - unknown formats fall back to a raw rolling-buffer restorer.

---

## Detection pipeline

Layered so a secret must slip past **every** layer to leak.
→ [../src/detect/index.js](../src/detect/index.js)

1. **Named regex rules** — [../src/detect/regex-rules.js](../src/detect/regex-rules.js): AWS,
   GitHub, OpenAI, Anthropic, Stripe, Google, SendGrid, Twilio, npm, Square, …
2. **Structural** — [../src/detect/structural.js](../src/detect/structural.js): JWTs (validated
   by decoding header/payload), PEM private keys, connection strings, `user:pass@` URLs.
3. **Entropy** — [../src/detect/entropy.js](../src/detect/entropy.js): high-Shannon-entropy
   catch-all for unknown keys; low confidence, redact-only.
4. **Validators** — [../src/detect/validators.js](../src/detect/validators.js): offline
   confidence adjustment (never a network call).

Each detector returns `{ type, match, start, end, confidence, detector }`. Overlapping matches
are resolved into a **non-overlapping** set (higher confidence → longer span → named rule over
entropy) so no span is substituted twice.

---

## Redact / restore mechanics

- **Vault** ([../src/vault.js](../src/vault.js)) — a per-request bijective `real ↔ fake` map.
  The same real value always maps to the same fake within a request; the vault is **zeroized**
  after the response is restored and never persisted.
- **Fakes** ([../src/fakes.js](../src/fakes.js)) — format-preserving per type: prefixes kept
  (`ghp_`, `sk-`, `AKIA…`), JWTs still decode, connection strings still parse, generic values
  keep length and character class. Fakes are random enough to be collision-free.
- **Restore** ([../src/restore.js](../src/restore.js)) — literal (non-regex) reverse
  substitution. For streaming, a rolling buffer retains a tail so a fake split across chunks
  reassembles; the emit boundary is chosen so it **never cuts through a placeholder**. If the
  model didn't echo a fake verbatim, restore is a safe no-op.

---

## Integrity contract

| Part of the request | Action | Why |
|---|---|---|
| Method, path, query | untouched | routing identical |
| `Authorization` / `x-api-key` | passthrough | provider auth; the model never sees headers |
| `Content-Type` | untouched | stays `application/json` |
| `Content-Length` | recomputed | body length changed by substitution |
| JSON structure (keys/arrays/nesting) | untouched | parsed object mutated in place → always valid JSON |
| Leaf string values matching a detector | substituted (format-preserving fake) | body content is free-form |
| `Accept-Encoding` (outbound) | forced to `identity` | so responses can be read/restored (no gzip yet) |

**Outbound validity is guaranteed** (the proxy controls the exact bytes). **Inbound restoration
is best-effort.**

---

## Policy: fail-closed

→ [../src/policy.js](../src/policy.js), [../src/config.js](../src/config.js)

- Matches below a confidence floor are ignored (noise).
- High-value types (`failClosedTypes`) at high confidence that **cannot be tokenized** cause
  the whole request to be **blocked** with HTTP 403 — never forwarded with the real value.
- Entropy-only hits (`redactOnlyTypes`) are redacted but never block on their own, to avoid
  over-blocking legitimate high-entropy text.

---

## Observability

- **Stats** ([../src/stats.js](../src/stats.js)) — requests, redactions, restorations, restore
  misses, fail-closed blocks, per-type and per-detector counts, and salted fingerprints. Prints
  the end-of-session summary.
- **Audit log** ([../src/audit-log.js](../src/audit-log.js)) — append-only
  `audit/<date>.jsonl`. Records `redaction` / `restoration` / `block` / `session-summary` with
  **type + salted HMAC-SHA256 fingerprint only** — never raw secret values.

---

## Module map

```
src/
  server.js                 CONNECT, MITM termination, forwarding, wiring
  config.js                 ports, allowlist, thresholds, policy sets
  intercept/
    ca.js                   CA load + per-host leaf-cert minting (SNI)
    allowlist.js            intercept vs blind-tunnel decision
    stream/{sse,sse-openai,sse-anthropic}.js   streaming restore
  detect/{index,regex-rules,structural,entropy,validators}.js
  redact.js  restore.js  vault.js  fakes.js
  policy.js  stats.js  audit-log.js
  tools/gen-ca.js           local CA generator
```
