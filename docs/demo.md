# Demo Guide

Repeatable ways to show the Secret-Redaction Proxy in action — from a 60-second scripted
round-trip to a live harness walkthrough.

> **Recording a promo/demo video?** Open with a speaker-intro slide and narration first:
> **Arnab Pal — Software Architect, Hyland Software (Enterprise Imaging)** — *then* start the
> product story. Keep every secret shown **fake but realistic**; never use a real credential.

---

## Demo 0 — No network, no API key (30 seconds)

Prove the redact → restore pipeline end-to-end with the test suite:

```powershell
cd C:\git\poc\secret-redaction-proxy
npm test
```
Point out: `redact then restore is identity`, the two **SSE streaming** reassembly tests, and
`fail-closed block`. 18 tests, all green — the core guarantees are enforced by tests.

---

## Demo 1 — Scripted live round-trip (2 minutes, needs internet)

Uses `httpbin.org/post`, which echoes back whatever body it receives — perfect for showing the
full round-trip without an LLM API key.

### Terminal A — start the proxy (allowlist httpbin, verbose)
```powershell
cd C:\git\poc\secret-redaction-proxy
node src/server.js --port 8787 --allowlist httpbin.org --verbose
```

### Terminal B — send a request carrying a fake secret
```powershell
$env:NODE_EXTRA_CA_CERTS = "C:\git\poc\secret-redaction-proxy\ca\ca.pem"

$body = '{"messages":[{"role":"user","content":"deploy with token ghp_1234567890abcdefghijklmnopqrstuvwxyz"}]}'

curl.exe -x http://localhost:8787 https://httpbin.org/post `
  -H "content-type: application/json" `
  --data $body -sS
```

### What to point out
1. **Terminal A** prints `INTERCEPT httpbin.org:443` — the request was decrypted and scanned.
2. **The audit log** shows both halves of the round-trip:
   ```powershell
   Get-Content .\audit\$((Get-Date).ToString('yyyy-MM-dd')).jsonl -Tail 5
   ```
   ```json
   {"event":"redaction","type":"github-pat","detector":"regex","fingerprint":"…","host":"httpbin.org"}
   {"event":"restoration","fingerprint":"…","host":"httpbin.org"}
   ```
   - `redaction` = the real token was swapped for a **fake before leaving your machine**, so
     httpbin (standing in for the model) only ever saw the fake.
   - `restoration` = the fake in the response was swapped **back** to the real token before
     curl saw it. Same fingerprint on both lines = same secret, full round-trip.
3. **curl output**: the echoed `json.messages[0].content` shows the **real** token again —
   because the proxy restored it on the way back. The harness is none the wiser; the upstream
   never saw the real value.
4. **Ctrl+C in Terminal A** prints the session summary with `github-pat x1`.

> Want to *see* the fake the upstream received? Temporarily comment out the restore step is not
> needed — just trust the two audit lines: a `redaction` with no matching `restoration` would
> mean the upstream saw the fake and the model didn't echo it (a restore "miss").

---

## Demo 2 — Fail-closed block (1 minute)

Show that a high-confidence secret that can't be tokenized is **blocked**, not leaked. The
easiest way to force this is to send a body over the redaction size limit is *not* it — instead
demonstrate the policy via the test that already proves it:

```powershell
node --test test/integrity.test.js
```
Call out `fail-closed block leaves body untouched and reports type`: a `github-pat` that the
vault refuses to tokenize causes the whole request to be blocked with HTTP 403 and the original
body is never forwarded.

In a live setting, a blocked request returns:
```json
{"error":{"type":"secret_redaction_proxy_block","message":"Request blocked: a high-confidence secret was detected but could not be safely tokenized (fail-closed).","secret_type":"github-pat"}}
```

---

## Demo 3 — Real harness (GitHub Copilot / Claude)

The headline demo: a real coding assistant, protected transparently.

### Setup (once)
Follow [setup-and-usage.md](setup-and-usage.md) §2–§4: generate + trust the CA, run the proxy,
and launch the harness with `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` set.

### Script
1. Start the proxy with `--verbose` in a visible terminal.
2. In VS Code with Copilot Chat (or `claude`), paste a prompt containing fake-but-realistic
   secrets, e.g.:
   > "Here's my config, help me debug the connection:
   > `mongodb+srv://admin:S3cr3tPass@cluster0.ab12.mongodb.net/prod`
   > and my CI token `ghp_1234567890abcdefghijklmnopqrstuvwxyz`."
3. As the request goes out, show the terminal `INTERCEPT` line and the new `redaction` audit
   entries.
4. The assistant still answers coherently (it reasoned over **format-preserving fakes** — a
   valid-looking mongodb URI and PAT), and if it echoes the placeholder, the reply you read has
   the **real** values restored.
5. Stop the proxy → show the **session summary**: types protected, per-detector hits, restore
   misses.

### Talking points
- **Provider-agnostic**: no per-provider code — the proxy tunnels whatever host the client
  asks for and treats the body as opaque JSON.
- **Integrity contract**: method, path, auth headers, and JSON structure are untouched; only
  matched leaf string values change; `Content-Length` is recomputed.
- **Honest limits**: not 100% leak-proof (finite detectors; best-effort restore). Say this out
  loud — it builds trust.

---

## Suggested 3-minute video flow

| Time | Beat |
|---|---|
| 0:00 | **Speaker intro slide** — Arnab Pal, Software Architect, Hyland Software (Enterprise Imaging). |
| 0:20 | The problem: secrets pasted into AI chats leave your machine in cleartext. |
| 0:45 | Architecture diagram (from [../README.md](../README.md)) — proxy sits between harness and API. |
| 1:15 | Demo 1: scripted round-trip; show the two audit lines and the restored response. |
| 2:00 | Demo 3: live Copilot/Claude with a mongodb URI + PAT; show INTERCEPT + summary. |
| 2:40 | Honest limitations + fail-closed guarantee. |
| 3:00 | Close. |

---

## Safe demo data

Use only fake credentials shaped like the real thing (see
[../test/corpus/secrets.js](../test/corpus/secrets.js)). Examples:

| Type | Sample (fake) |
|---|---|
| GitHub PAT | `ghp_1234567890abcdefghijklmnopqrstuvwxyz` |
| OpenAI key | `sk-abcdef12345ABCDEF67890ghijklMNOPqrstUVWX` |
| Stripe key | `sk_live_abcdefghijklmnop12345678` |
| MongoDB URI | `mongodb+srv://admin:S3cr3tPass@cluster0.ab12.mongodb.net/prod` |
| AWS access key | `AKIAIOSFODNN7EXAMPLE` |

Never paste a real secret into a demo, even through the proxy.
