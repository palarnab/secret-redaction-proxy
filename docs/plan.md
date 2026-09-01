# Secret-Redaction Proxy — Implementation Plan

> A local **forward proxy with TLS interception (MITM)** that sits between an AI coding
> harness (GitHub Copilot / Claude / any LLM client) and the upstream model API. It detects
> secrets/credentials in outbound traffic, replaces them with **format-preserving fakes**, forwards
> the sanitized request, then **restores** the real values in the response so the harness keeps
> working. At the end of a session it reports how many redactions/restorations happened, which
> secret *types* were protected (never the values), and related statistics.

This document is self-contained. A future session can execute it without any prior chat context.

---

## 1. Goals & non-goals

### Goals
- Prevent secrets embedded in **conversation payloads** (pasted connection strings, keys in files
  the agent reads, env dumps, etc.) from reaching the LLM.
- Be **provider-agnostic**: OpenAI, Anthropic, Gemini, and future providers with zero per-provider
  code — the proxy tunnels whatever host the client asks for.
- Preserve request/response **validity** so the harness behaves normally.
- Emit **session statistics** and an audit log (redaction/restore counts, per-detector hits,
  hashed fingerprints, fail-closed blocks).

### Non-goals / honest limitations (do not over-promise)
- **Not 100% leak-proof.** Two inherent weak points:
  1. **Detector coverage** — novel/custom secret formats can be missed (false negatives).
  2. **Restoration is best-effort** — if the model paraphrases/mangles the placeholder instead of
     echoing it verbatim, restore is a safe no-op (harness gets the placeholder, never a corrupted
     secret).
- Does **not** redact the provider API key in the `Authorization`/`x-api-key` header — that is the
  credential used to authenticate upstream and the model never sees headers anyway.
- Does not defend against a client that **pins** a specific public certificate (rare for
  Node-based harnesses today, but verify per version).

---

## 2. Architecture overview

```
Harness (Copilot/Claude)  --HTTPS_PROXY-->  Redaction Proxy (localhost:8787)  --TLS-->  Real LLM API
                                                  |
                                    detect -> tokenize (vault) -> forward
                                    restore <- reverse-substitute <- response
                                                  |
                                             stats + audit log
```

- **Interception**: forward proxy driven by `HTTPS_PROXY`; TLS terminated with a **local CA** so the
  proxy can read plaintext. The upstream host is learned dynamically from the `CONNECT host:port`
  line (and confirmed by TLS SNI + `Host` header).
- **Redaction core is provider-agnostic**: it treats the request body as opaque JSON and walks it
  recursively, running detectors on every string value — no provider schema knowledge required.
- **Only provider-specific piece**: streaming (SSE) reassembly, because a placeholder can be split
  across chunks. Thin adapter per streaming format (~30 lines each).

### Language / stack
- **JavaScript (Node.js)** — plain JS, no TypeScript. Minimal dependencies.
- **Recommended interception engine: `mitmproxy`** with a redaction addon, OR a pure-Node proxy
  using the `http`/`tls` modules. `mitmproxy` already handles `CONNECT`, dynamic per-host leaf-cert
  minting, and upstream dialing — but the addon script is Python. Decision point in §9.
  - **Option A (pure Node)**: everything in JS, more code (must implement CONNECT + cert minting).
  - **Option B (mitmproxy + Node sidecar)**: mitmproxy does transport; it calls a local Node HTTP
    service for the detect/redact/restore/stats logic so all business logic stays in JS.
  - **Default recommendation: Option B** for the prototype (less transport plumbing, battle-tested
    TLS interception), migrate to Option A later if a single-binary JS tool is desired.

---

## 3. How interception connects (client configuration)

Two requirements: **(1) route traffic to the proxy**, **(2) trust the local CA** (Node ignores the
OS trust store, so `NODE_EXTRA_CA_CERTS` is almost always needed).

### VS Code / GitHub Copilot
`settings.json`:
```jsonc
{
  "http.proxy": "http://localhost:8787",
  "http.proxyStrictSSL": true,
  "http.proxySupport": "on",
  "http.systemCertificates": true
}
```
Launch env (before starting VS Code):
```powershell
$env:NODE_EXTRA_CA_CERTS = "C:\proxy\ca.pem"
$env:HTTPS_PROXY = "http://localhost:8787"
$env:NO_PROXY = "localhost,127.0.0.1"
code .
```

### Claude Code (CLI, Node-based)
```powershell
$env:HTTPS_PROXY = "http://localhost:8787"
$env:NODE_EXTRA_CA_CERTS = "C:\proxy\ca.pem"
$env:NO_PROXY = "localhost,127.0.0.1"
claude
```

### Claude Desktop (Electron)
- Set Windows system proxy → manual → `localhost:8787`.
- Install CA into **Trusted Root Certification Authorities**.
- Still set `NODE_EXTRA_CA_CERTS` in the launch environment (Electron's Node).

### Install the CA (once)
```powershell
Import-Certificate -FilePath C:\proxy\ca.pem -CertStoreLocation Cert:\CurrentUser\Root
```

---

## 4. How the proxy forwards to the correct upstream

1. Client (with `HTTPS_PROXY` set) sends `CONNECT api.anthropic.com:443` → proxy **learns target**.
2. Proxy replies `200 Connection Established`, then **terminates TLS toward the client** by serving a
   leaf cert for that exact host signed by the local CA (client trusts it).
3. Proxy reads the now-plaintext request → **redacts**.
4. Proxy opens its **own** TLS connection to the learned host, validated against **real public CAs**
   (no MITM upstream), and sends the redacted request.
5. Proxy **restores** placeholders in the response and writes it back over the client TLS socket.

Non-LLM hosts should be **blind-tunneled** (no interception) so only intended endpoints are
decrypted. Maintain an allowlist of LLM host patterns to intercept; everything else passes through.

---

## 5. Redaction round-trip (worked example)

**Outbound — harness → proxy → LLM** (only the URI value swapped; structure + auth identical):
```jsonc
// before
{ "role": "user", "content": "Fix prod. URI: mongodb+srv://admin:S3cr3tP@ss@cluster0.ab12.mongodb.net/prod" }
// after (forwarded to LLM)
{ "role": "user", "content": "Fix prod. URI: mongodb+srv://admin:Xk9pLm2Q@cluster0.zz00.mongodb.net/prod" }
```
Vault (in-memory, request-scoped, never sent): fake → real.

**Inbound — LLM → proxy → harness** (model echoes the placeholder; proxy restores real value):
```jsonc
// from LLM
{ "content": "Your URI mongodb+srv://admin:Xk9pLm2Q@cluster0.zz00.mongodb.net/prod points to prod..." }
// restored to harness
{ "content": "Your URI mongodb+srv://admin:S3cr3tP@ss@cluster0.ab12.mongodb.net/prod points to prod..." }
```

Placeholders must be **format-preserving** (same shape/charset/length class) so the model's reasoning
is not derailed, and **collision-free** vs. real content.

---

## 6. What the proxy is allowed to touch (integrity contract)

| Part | Action | Rationale |
|---|---|---|
| Method, path, query | untouched | routing identical |
| `Authorization` / `x-api-key` | passthrough | provider auth; model never sees headers |
| `Content-Type` | untouched | stays `application/json` |
| `Content-Length` | recomputed | body length changed |
| JSON structure (keys/arrays/nesting) | untouched | mutate parsed object in place → always valid JSON |
| Leaf string values matching a detector | substituted (format-preserving fake) | content is free-form; provider does not validate it |

Guarantee: **outbound request validity is guaranteed** (proxy controls exact bytes). **Inbound
restoration is best-effort.**

---

## 7. Component design

```
secret-redaction-proxy/
  README.md
  plan.md                     # this file
  package.json
  ca/                         # generated local CA + leaf cert cache (gitignored)
  src/
    server.js                 # proxy entry: CONNECT handling / mitmproxy sidecar endpoint
    intercept/
      allowlist.js            # LLM host patterns to TLS-intercept; else blind-tunnel
      stream/
        sse-openai.js         # SSE reassembly + re-emit (buffered restore)
        sse-anthropic.js
    detect/
      index.js                # detector registry + orchestration
      regex-rules.js          # gitleaks/trufflehog-style patterns (AWS, GCP, GitHub, Stripe, ...)
      structural.js           # JWT, PEM/PRIVATE KEY, connection strings, mongodb+srv://, URLs w/ creds
      entropy.js              # Shannon-entropy scan for high-entropy blobs
      validators.js           # optional safe validation to cut false positives
    redact.js                 # recursive JSON walk -> tokenize via vault
    restore.js                # reverse-substitute (incl. streaming buffer)
    vault.js                  # per-request real<->fake map; zeroized after restore
    fakes.js                  # format-preserving fake generators per secret type
    policy.js                 # fail-closed rules, allow/deny, size limits
    stats.js                  # counters, per-detector hits, hashed fingerprints
    audit-log.js              # append-only JSONL log (no raw secret values)
    config.js                 # ports, upstream allowlist, thresholds, policy
  test/
    corpus/                   # true-positive secrets (fake but realistic) + false-negative probes
    detect.test.js
    roundtrip.test.js         # redact -> restore equivalence, incl. streaming
    integrity.test.js         # structure/headers/content-length preserved
```

### Key modules
- **detect/**: layered — regex rules + structural detectors + entropy + optional validators.
  Each detector returns `{ type, match, start, end, confidence }`.
- **fakes.js**: given a secret `type` + original, produce a same-shape fake (e.g. `sk-` + 48 chars,
  a valid-looking JWT, a mongodb URI with fake user/host/pass).
- **vault.js**: bijective map for one request; supports multi-occurrence; zeroize on completion.
- **restore.js**: exact reverse-substitution; streaming version keeps a rolling buffer the width of
  the longest active placeholder so split placeholders across SSE frames are reassembled.
- **policy.js**: **fail-closed** — if a *known high-confidence* secret pattern is detected but cannot
  be safely tokenized, **block** the request rather than risk a cleartext leak.
- **stats.js / audit-log.js**: never store raw secret values — only `type` + a salted **hash
  fingerprint**, counts, timestamps, and outcomes.

---

## 8. Detector coverage strategy (maximize recall)

Layered so a secret must slip past *all* layers to leak:
1. **Named regex rules** — port a curated subset of gitleaks/trufflehog rules (AWS AKIA/ASIA + secret,
   GCP, GitHub PAT `ghp_`/`gho_`, Stripe `sk_live_`, Slack, OpenAI `sk-`, Twilio, SendGrid, etc.).
2. **Structural detectors** — JWT (`eyJ...` 3-part), PEM blocks (`-----BEGIN ... PRIVATE KEY-----`),
   connection strings (`mongodb+srv://`, `postgres://`, `mysql://`, `redis://`) incl. embedded creds,
   any URL with `user:pass@`.
3. **Entropy scan** — flag high Shannon-entropy tokens above a length threshold that no other rule
   caught (catches unknown/opaque keys).
4. **Optional validators** — where safe/offline, sanity-check structure to reduce false positives
   (e.g. JWT base64 segments decode; AWS key checksum shape). Never make a network call to validate.

Tuning: prefer **recall over precision** for known-dangerous types (fail-closed); allow
entropy-only hits to be **redact-but-not-block** to avoid over-blocking legitimate text.

---

## 9. Milestones

- [ ] **M0 — Decide transport**: Option A (pure Node) vs Option B (mitmproxy + Node sidecar).
      Default: B for prototype.
- [ ] **M1 — CA + interception skeleton**: generate local CA, mint leaf certs, `CONNECT` handling,
      blind-tunnel non-allowlisted hosts, plaintext read for allowlisted hosts. Verify Copilot and
      Claude can complete a normal (un-redacted) request through the proxy.
- [ ] **M2 — Redact/restore core (non-streaming)**: recursive JSON walk, vault, format-preserving
      fakes, reverse-substitute. `roundtrip.test.js` green.
- [ ] **M3 — Detectors**: regex + structural + entropy + optional validators; build test corpus.
- [ ] **M4 — Streaming**: SSE reassembly for OpenAI + Anthropic; buffered restore.
- [ ] **M5 — Policy**: fail-closed rules, size limits, allow/deny config.
- [ ] **M6 — Stats & audit**: counters, per-detector hits, hashed fingerprints, end-of-session
      summary report; append-only JSONL audit log.
- [ ] **M7 — Hardening**: cert-pinning check, `NODE_EXTRA_CA_CERTS` docs, memory zeroization,
      failure/edge handling, load/perf sanity.

Each milestone must ship with tests. Do not advance until the previous milestone's tests pass.

---

## 10. End-of-session reporting (required output)

At loop end, emit a summary such as:
```
=== Redaction session summary ===
Requests processed:      142
Redactions performed:    37
Restorations performed:  35
Restore misses (no-op):   2   (model did not echo placeholder verbatim)
Fail-closed blocks:       1
Secret types protected:
  mongodb-uri        x12
  aws-secret-key     x 6
  github-pat         x 4
  jwt                x 9
  high-entropy-blob  x 6
Per-detector hits: regex=22, structural=9, entropy=6
Audit log: ./audit/2026-09-01.jsonl   (fingerprints only, no raw values)
```
- Report **types + counts + hashed fingerprints only**. Never log or print raw secret values.

---

## 11. Security & correctness requirements

- **Never persist** the vault beyond a request; zeroize buffers after restore; encrypt at rest if
  anything must be buffered.
- **Audit log contains no raw secrets** — salted hash fingerprints only.
- **Fail-closed** on known high-confidence secret types that can't be tokenized.
- **Blind-tunnel** everything not on the LLM allowlist (minimize what is decrypted).
- Validate that outbound request **structure/headers/Content-Length** are preserved (integrity test).
- Handle model **non-verbatim echo** gracefully (restore no-op, count as miss, never emit corrupted
  value).
- Watch for **certificate pinning** in target clients; document per-version behavior.
- Keep dependencies minimal and audited.

---

## 12. Open questions to resolve before/while building

1. Transport engine: pure Node vs mitmproxy sidecar (M0).
2. Placeholder sentinel design that survives tokenization/reformatting by the model with highest
   fidelity (affects restore hit-rate).
3. Which gitleaks/trufflehog rule subset to port first (highest-value secret types).
4. Policy defaults: which types are **redact-and-block** vs **redact-only**.
5. Multi-request session correlation for stats (per-connection vs per-process aggregation).

---

## 13. Quick start (once built)

```powershell
# 1. Generate + trust CA
node src/tools/gen-ca.js --out C:\proxy\ca.pem
Import-Certificate -FilePath C:\proxy\ca.pem -CertStoreLocation Cert:\CurrentUser\Root

# 2. Run the proxy
node src/server.js --port 8787 --allowlist api.openai.com,api.anthropic.com

# 3. Point a harness at it
$env:HTTPS_PROXY = "http://localhost:8787"
$env:NODE_EXTRA_CA_CERTS = "C:\proxy\ca.pem"
$env:NO_PROXY = "localhost,127.0.0.1"
# then launch Copilot (code .) or Claude (claude)
```
```

## References to gather during implementation
- gitleaks / trufflehog rule sets (regex patterns) for detector porting.
- mitmproxy addon API (if Option B) — request/response hook points.
- Node `tls`/`http` CONNECT handling and SNI callback (if Option A).
```
