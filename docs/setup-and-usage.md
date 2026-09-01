# Setup & Usage

How to install, run, keep the Secret-Redaction Proxy running continuously, and verify it is
actually redacting traffic.

---

## 1. Prerequisites

- **Node.js 18+** (`node --version`).
- Windows PowerShell (examples below) — the tool itself is cross-platform.
- A Node-based AI harness to protect: VS Code / GitHub Copilot, or Claude Code.

---

## 2. One-time setup

```powershell
# From the repo root
cd C:\git\poc\secret-redaction-proxy

# Install dependencies (only node-forge)
npm install

# Generate the local Certificate Authority
node src/tools/gen-ca.js
# -> ca\ca.pem      (certificate — safe to distribute/trust)
# -> ca\ca.key.pem  (private key — keep secret, already gitignored)

# Trust the CA for the current user
Import-Certificate -FilePath "$PWD\ca\ca.pem" -CertStoreLocation Cert:\CurrentUser\Root
```

> **Why trust a CA?** The proxy terminates TLS so it can read (and sanitize) the plaintext
> request body. It serves each intercepted host a leaf certificate signed by this local CA.
> Only traffic to **allowlisted** hosts is decrypted; everything else is blind-tunnelled.

> **Node ignores the OS trust store.** Even after importing the CA into Windows, Node-based
> harnesses need `NODE_EXTRA_CA_CERTS` pointing at `ca\ca.pem` (see below).

---

## 3. Run the proxy

```powershell
node src/server.js --port 8787 --allowlist api.openai.com,api.anthropic.com
```

You should see:

```
Secret-Redaction Proxy listening on http://127.0.0.1:8787
Intercepting: api.openai.com, api.anthropic.com
Point a harness at it:
  $env:HTTPS_PROXY = "http://127.0.0.1:8787"
Press Ctrl+C to stop and print the session summary.
```

Press **Ctrl+C** to stop and print the end-of-session summary.

### CLI options

| Flag | Default | Purpose |
|---|---|---|
| `--port <n>` | `8787` | Listen port |
| `--host <addr>` | `127.0.0.1` | Listen address |
| `--allowlist a,b,c` | built-in LLM hosts | Hosts to TLS-intercept (all others blind-tunnelled) |
| `--no-audit` | audit on | Disable the JSONL audit log |
| `--verbose` | off | Log each `INTERCEPT` / `TUNNEL` decision to stderr |

### Environment overrides

`SRP_PORT`, `SRP_HOST`, `SRP_CA_DIR`, `SRP_AUDIT_DIR`, `SRP_FP_SALT`, `SRP_VERBOSE`.

> Pin `SRP_FP_SALT` to a fixed value if you want audit-log fingerprints to stay comparable
> across restarts; otherwise a fresh random salt is used per process.

---

## 4. Point a harness at the proxy

Open a **new** shell (so the env vars apply to the harness you launch), then:

```powershell
$env:HTTPS_PROXY         = "http://localhost:8787"
$env:NODE_EXTRA_CA_CERTS = "C:\git\poc\secret-redaction-proxy\ca\ca.pem"
$env:NO_PROXY            = "localhost,127.0.0.1"

code .     # launch VS Code / Copilot
# or
claude     # launch Claude Code
```

### VS Code / GitHub Copilot `settings.json`

```jsonc
{
  "http.proxy": "http://localhost:8787",
  "http.proxyStrictSSL": true,
  "http.proxySupport": "on",
  "http.systemCertificates": true
}
```

### Claude Desktop (Electron)

- Set the Windows system proxy → manual → `localhost:8787`.
- Import the CA into **Trusted Root Certification Authorities**.
- Still set `NODE_EXTRA_CA_CERTS` in the launch environment.

---

## 5. Keep it running all the time

The proxy is a long-lived local service. Pick whichever fits your workflow.

### Option A — dedicated terminal (simplest)
Run `node src/server.js …` in a terminal you leave open. Stopping it (Ctrl+C) prints the
session summary. Good for demos and short sessions.

### Option B — background job for the current login session
```powershell
$job = Start-Job -Name srp -ScriptBlock {
  Set-Location 'C:\git\poc\secret-redaction-proxy'
  node src/server.js --port 8787
}
Receive-Job -Name srp -Keep      # view recent output
Stop-Job  -Name srp; Remove-Job -Name srp   # stop it
```
Note: `Start-Job` output is captured, not streamed live; use `Receive-Job` to inspect it.

### Option C — auto-start at login (Task Scheduler)
Create a hidden task that starts the proxy when you log in:
```powershell
$action  = New-ScheduledTaskAction -Execute "node.exe" `
  -Argument "src\server.js --port 8787" `
  -WorkingDirectory "C:\git\poc\secret-redaction-proxy"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "SecretRedactionProxy" `
  -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited
```
Manage it:
```powershell
Start-ScheduledTask   -TaskName SecretRedactionProxy
Stop-ScheduledTask    -TaskName SecretRedactionProxy
Unregister-ScheduledTask -TaskName SecretRedactionProxy -Confirm:$false
```
> A background/scheduled proxy never receives Ctrl+C, so it won't print the interactive
> session summary. Rely on the **audit log** (below) for a running record instead.

### Option D — run as a Windows service
For always-on use across logins, wrap `node src/server.js` with a service manager such as
[NSSM](https://nssm.cc/) or `node-windows`. Point the service's working directory at the repo
and pass the same CLI flags. This keeps the proxy alive across reboots and user switches.

> Whatever you choose, the harness only benefits while `HTTPS_PROXY` and
> `NODE_EXTRA_CA_CERTS` are set in **its** environment. If you launch the harness from a
> shortcut, set those variables system-wide (or in the shortcut) so they always apply.

---

## 6. Verify it's working

### 6.1 Is it listening?
```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 8787 -InformationLevel Quiet   # -> True
```

### 6.2 Does CONNECT tunneling work? (blind-tunnel path)
`example.com` is **not** on the allowlist, so it should tunnel through untouched:
```powershell
curl.exe -x http://localhost:8787 https://example.com -sS -o NUL -w "%{http_code}`n"
# -> 200
```

### 6.3 Is an allowlisted host intercepted? (watch the decisions)
Run the proxy with `--verbose` and watch stderr while the harness makes a request:
```
INTERCEPT api.anthropic.com:443
TUNNEL    telemetry.example.net:443
```
`INTERCEPT` = decrypted + scanned. `TUNNEL` = passed through untouched.

### 6.4 Are secrets actually being redacted? (audit log)
Every redaction/restoration/block is appended to `audit\<YYYY-MM-DD>.jsonl` with **type +
salted fingerprint only** (never the raw secret):
```powershell
Get-Content .\audit\$((Get-Date).ToString('yyyy-MM-dd')).jsonl -Tail 20
```
Example lines:
```json
{"ts":"2026-09-01T12:00:00.000Z","event":"redaction","type":"github-pat","detector":"regex","fingerprint":"9f3a…","host":"api.anthropic.com"}
{"ts":"2026-09-01T12:00:01.000Z","event":"restoration","fingerprint":"9f3a…","host":"api.anthropic.com"}
```
To generate a real hit, paste a **fake-but-realistic** secret into a chat (see
[demo.md](demo.md)) and confirm a `redaction` line appears.

### 6.5 End-of-session summary
Stop a foreground proxy with **Ctrl+C**:
```
=== Redaction session summary ===
Requests processed:      12
Redactions performed:     4
Restorations performed:   3
Restore misses (no-op):   1
Fail-closed blocks:       0
Secret types protected:
  github-pat  x2
  jwt         x2
Per-detector hits: regex=2, structural=2, entropy=0
Audit log: .\audit\2026-09-01.jsonl   (fingerprints only, no raw values)
```

### 6.6 Confirm the pipeline logic without any harness
```powershell
npm test     # 18 tests: detection, redact->restore, streaming, integrity
```

---

## 7. Turn it off cleanly

- Foreground: **Ctrl+C** (prints the summary).
- Background job: `Stop-Job -Name srp; Remove-Job -Name srp`.
- Scheduled task/service: stop via the commands in §5.
- Optional: remove the env vars so the harness talks directly again:
  ```powershell
  Remove-Item Env:HTTPS_PROXY, Env:NODE_EXTRA_CA_CERTS, Env:NO_PROXY
  ```
- To fully undo trust: delete the CA from `Cert:\CurrentUser\Root` (match by subject
  “Secret Redaction Proxy Local CA”).

See [troubleshooting.md](troubleshooting.md) if something doesn't connect.
