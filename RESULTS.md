# HEROS-Firewall Results

## Environment

| Item | Value |
|---|---|
| Date | 2026-10-31 |
| OS | macOS (Apple Silicon) |
| Node | 26.3.0 |
| Tests | 16/16 passing |
| Red-team payloads | 1,000 adversarial + 200 benign |

## Red-team

Command: `npm run redteam`

| Metric | Value |
|---|---:|
| Adversarial cases | 1,000 |
| Benign cases | 200 |
| Missed adversarial (FNR) | 0 / 1,000 |
| False positives (FPR) | 0 / 200 |
| p99 policy latency | 0.296 ms |
| Whole suite wall time | ~24 ms |

The p99 is the policy-engine evaluation time. It does not include process
spawning, downstream MCP handling, or network latency, so the "<5 ms proxy"
target is only proven for the policy layer.

## Tests

`npm test` covers:

- every ASI01–ASI10 category produces a deny or challenge,
- benign read/search/query/memory/inter-agent operations are allowed,
- approval tokens are signed, single-use, action-bound, and expire,
- Merkle receipts verify; tampering is detected; inclusion proofs verify,
- idempotency returns the cached downstream response,
- the proxy allows, denies without forwarding, challenges, then forwards after
  approval and records the approval signature,
- red-team thresholds: FNR < 1%, FPR < 1%, p99 < 5 ms.

## Not executed

- **React/Next.js SSE dashboard** — Mobbin MCP unavailable, so the UI surface was
  not built. Receipts/health are MCP methods.
- **OCI k3s + Prometheus/Grafana + Loki** — no cloud access; no deployment
  claimed.
- **End-to-end p99 through a real downstream MCP server** — the policy layer is
  measured; process/network latency is not.

## Reproduce

```bash
cd repos/HEROS-Firewall
npm test
npm run redteam
```
