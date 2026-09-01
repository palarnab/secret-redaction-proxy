# Documentation

Guides for the Secret-Redaction Proxy. Start with setup, then pick what you need.

| Doc | What it covers |
|---|---|
| [setup-and-usage.md](setup-and-usage.md) | Install, generate + trust the CA, run the proxy, point a harness at it, **keep it running always**, and **verify it's working**. |
| [demo.md](demo.md) | Repeatable demos: 30-second no-network proof, scripted live round-trip, fail-closed block, and a real Copilot/Claude walkthrough (+ video flow). |
| [architecture.md](architecture.md) | How interception, redaction, restoration, streaming, and stats fit together; the integrity contract; module map. |
| [security-and-limitations.md](security-and-limitations.md) | Threat model, what is and isn't protected, honest limitations, and safe-handling rules. |
| [troubleshooting.md](troubleshooting.md) | Fixes for TLS/cert errors, proxy-not-used, blank responses, and other common issues. |

Project overview and quick start also live in the top-level [../README.md](../README.md).
The original design rationale is in [../plan.md](../plan.md).
