# HEROS-Firewall

Inline MCP security proxy for the OWASP Agentic Top 10 (ASI01–ASI10), with
cryptographic human-approval challenges and Merkle-tree audit receipts.

An agent talks to the firewall over stdio. The firewall evaluates every
`tools/call` against a deterministic policy, forwards allowed calls to the
downstream MCP server, and records a hash-chained receipt. Destructive or
high-cost calls require an HMAC-signed, expiring, single-use human approval.

## Layers

1. **OWASP ASI policy engine** — goal hijacking, tool misuse, identity/scope
   abuse, untrusted tools, code execution, memory poisoning, inter-agent
   exfiltration, resource exhaustion, human-trust gates, and rogue chains.
2. **Human approval challenge** — 128-bit token, HMAC-SHA256 signature, 5-minute
   TTL, single use, bound to the exact tool + arguments + principal hash.
3. **Merkle audit receipts** — input/output SHA-256, principal, tool, decision,
   approval signature, idempotency key, previous hash, and a per-prefix Merkle
   root with inclusion proofs.
4. **Red-team harness** — 1,000 adversarial payloads across all 10 categories
   plus 200 benign operations, measuring FNR, FPR, and p99 policy latency.

## Quick start

```bash
npm test
npm run redteam

# Proxy stdio:
HEROS_APPROVAL_SECRET="$(openssl rand -hex 32)" \
HEROS_DOWNSTREAM_BIN=node \
HEROS_DOWNSTREAM_ARGS="path/to/upstream-mcp.mjs" \
node bin/heros-firewall.mjs

# Human signing helper (run where the approval secret lives):
HEROS_APPROVAL_SECRET=... node bin/heros-firewall.mjs --sign-approval <token>
```

The human submits the signature through the MCP method `firewall/approve` with
`{ token, signature }`. Inspect `firewall/receipts` and `firewall/health` for
the Merkle root and latency percentiles.

## Policy examples

| Attack | Decision | Category |
|---|---|---|
| `ignore previous instructions...` in email body | deny | ASI01 |
| `shell_exec` with `rm -rf` / `curl` | deny | ASI05 |
| `delete_record` with `read` scope | deny | ASI03 |
| unknown tool | deny | ASI04 |
| `read_secret` then `http_post` | deny | ASI10 |
| `delete_record` with `write` scope | challenge | ASI09 |
| `write_memory` with untrusted content | deny | ASI06 |

Allowed domains and agents are explicit allowlists. Payload size and call rate
are bounded.

## Measured red-team results

`npm run redteam` (Node 26, Apple Silicon):

| Adversarial | Benign | FNR | FPR | p99 policy latency |
|---:|---:|---:|---:|---:|
| 1,000 | 200 | 0.0000 | 0.0000 | 0.103 ms |

This is policy-engine latency; downstream MCP/network time is not included. The
sub-5ms target is met for the policy layer, not proven end-to-end.

## Tests

`npm test` — 16 tests covering all ASI categories, benign allow paths, approval
signing/expiry/replay, Merkle verification and tampering, idempotency, the proxy
allow/deny/challenge/retry flow, receipts, and the red-team thresholds.

## Status and limitations

- The React/Next.js SSE drill-through dashboard is **not built**: the Mobbin MCP
  is unavailable in this environment. JSON receipts and health metrics are
  exposed over MCP instead.
- No OCI k3s/Prometheus/Grafana deployment; no cloud credentials.
- The proxy is an in-process policy library plus a stdio runner; the red-team
  suite exercises the policy engine directly.
- Approval signatures are HMAC-based. A production deployment should use an
  asymmetric human-approval key or WebAuthn.

## License

MIT. Copyright (c) 2024-2026 Soumya Debnath.
