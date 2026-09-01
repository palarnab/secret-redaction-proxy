# Troubleshooting

Common issues and fixes. Run the proxy with `--verbose` to see `INTERCEPT` / `TUNNEL` decisions
while you debug.

---

## CA / TLS errors

### `Error: CA not found in …ca. Run: node src/tools/gen-ca.js`
The CA hasn't been generated. Run:
```powershell
node src/tools/gen-ca.js
```

### Harness/curl reports `self-signed certificate` / `unable to verify the first certificate`
Node isn't trusting the local CA. Node ignores the OS trust store — set `NODE_EXTRA_CA_CERTS`
in the **harness's** environment (not just the proxy's):
```powershell
$env:NODE_EXTRA_CA_CERTS = "C:\git\poc\secret-redaction-proxy\ca\ca.pem"
```
Then relaunch the harness from that same shell. For non-Node clients, also import the CA:
```powershell
Import-Certificate -FilePath "$PWD\ca\ca.pem" -CertStoreLocation Cert:\CurrentUser\Root
```

### `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` on the **upstream** side
This is the proxy validating the real provider. It means the machine's public CA store can't
verify the provider — unusual. Ensure system root certificates are up to date; do **not**
disable upstream validation.

### `ERR_TLS_CERT_ALTNAME_INVALID`
The minted leaf's SAN didn't match the requested host. Regenerate the CA and restart:
```powershell
node src/tools/gen-ca.js --force
```

---

## Proxy isn't being used

### Requests seem to bypass the proxy
- Confirm the harness environment actually has `HTTPS_PROXY` set:
  ```powershell
  $env:HTTPS_PROXY   # should be http://localhost:8787
  ```
- `NO_PROXY` should include `localhost,127.0.0.1` but **not** the LLM hosts.
- For VS Code, also set `http.proxy` in `settings.json` (see
  [setup-and-usage.md](setup-and-usage.md) §4).
- Env vars only apply to processes launched **after** they were set. Relaunch the harness.

### `--verbose` shows only `TUNNEL`, never `INTERCEPT`
The target host isn't on the allowlist, so it's blind-tunnelled (not scanned). Add it:
```powershell
node src/server.js --allowlist api.openai.com,api.anthropic.com,the.host.you.need
```
Check the exact host the harness dials (the `CONNECT host:port` in verbose logs).

---

## Connectivity

### `EADDRINUSE` on startup
Another process owns the port. Pick another:
```powershell
node src/server.js --port 8799
```
Find the occupant: `Get-NetTCPConnection -LocalPort 8787 | Select-Object OwningProcess`.

### `502` / `Upstream connection failed`
The proxy couldn't reach the real host (DNS, network, or firewall). Test directly:
```powershell
Test-NetConnection -ComputerName api.anthropic.com -Port 443
```

### Port shows not listening
```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 8787 -InformationLevel Quiet
```
If `False`, check the proxy terminal for a startup error (missing CA, bad flag, etc.).

---

## Redaction behavior

### A secret wasn't redacted
- **Was the host intercepted?** Only allowlisted hosts are scanned (`INTERCEPT` in verbose).
- **Was the body JSON or text?** Binary/oversized bodies (> `maxRedactBytes`, default 8 MB) are
  passed through unscanned by design.
- **Coverage gap.** The format may not be covered — detection is finite (see
  [security-and-limitations.md](security-and-limitations.md)). Consider adding a rule in
  [../src/detect/regex-rules.js](../src/detect/regex-rules.js).
- Confirm via a targeted check:
  ```powershell
  node -e "console.log(require('./src/detect').detect('YOUR_SAMPLE_HERE'))"
  ```

### Legitimate text got redacted (false positive)
High-entropy hashes/IDs can trip the entropy catch-all (redact-only, never blocks). Tune
`entropy.minLength` / thresholds in [../src/config.js](../src/config.js).

### The model's reply still shows a placeholder (restore miss)
The model didn't echo the fake verbatim (paraphrased or split across streamed tokens). This is
the documented best-effort limit — the proxy never emits a corrupted secret. It's counted as a
*restore miss* in the session summary.

### A request was blocked with HTTP 403
A high-confidence, high-value secret couldn't be tokenized, so the request was fail-closed. The
response body names the `secret_type`. This is intended protection, not a bug.

---

## Responses look garbled / compressed
If a provider ignores `Accept-Encoding: identity` and gzips anyway, the proxy can't restore the
plaintext (no decompression yet). The body passes through compressed. This is a known
prototype limitation — see [security-and-limitations.md](security-and-limitations.md).

---

## Still stuck?

1. Run `npm test` — if these fail, the environment/build is the issue, not your setup.
2. Re-run the proxy with `--verbose` and watch the decision log during a single request.
3. Tail the audit log to see exactly what was detected:
   ```powershell
   Get-Content .\audit\$((Get-Date).ToString('yyyy-MM-dd')).jsonl -Tail 20
   ```
