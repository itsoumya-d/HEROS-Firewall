// SPDX-License-Identifier: MIT
// Inline MCP policy proxy.

import { sha256, MerkleLedger } from "./receipts.js";
import { ApprovalGate } from "./approvals.js";

function toolError(payload) {
  return {
    content: [{ type: "text", text: JSON.stringify(payload) }],
    structuredContent: payload,
    isError: true,
  };
}

function stripControlArgs(args) {
  const copy = { ...args };
  delete copy.approval_token;
  delete copy.idempotency_key;
  return copy;
}

export function createProxy({ engine, gate, ledger = new MerkleLedger(), downstream, principal = "agent", scopes = ["read"] }) {
  if (!engine || !gate || typeof downstream !== "function") {
    throw new Error("proxy requires engine, gate, and downstream");
  }
  const session = { principal, scopes, priorCalls: [], startedAt: Date.now() };
  const metrics = { total: 0, allowed: 0, denied: 0, challenged: 0, latencies: [] };

  async function handleToolCall(message) {
    const started = performance.now();
    const name = message.params?.name;
    const rawArgs = message.params?.arguments ?? {};
    if (typeof name !== "string" || !name) {
      return { jsonrpc: "2.0", id: message.id ?? null, error: { code: -32602, message: "missing tool name" } };
    }

    const idempotencyKey = rawArgs.idempotency_key ?? null;
    if (idempotencyKey) {
      const cached = ledger.findIdempotent(idempotencyKey);
      if (cached) return { jsonrpc: "2.0", id: message.id ?? null, result: cached.response };
    }

    const cleanArgs = stripControlArgs(rawArgs);
    const actionHash = sha256({ tool: name, args: cleanArgs, principal: session.principal });
    let approvalSignature = null;

    if (rawArgs.approval_token) {
      const consumed = gate.consume(rawArgs.approval_token, actionHash);
      if (!consumed.ok) {
        const response = toolError({ error_code: "INVALID_APPROVAL", error: consumed.reason, retryable: false });
        ledger.append({ principal: session.principal, tool: name, input: { name, args: cleanArgs }, output: response, decision: "deny" });
        metrics.denied++;
        metrics.total++;
        metrics.latencies.push(performance.now() - started);
        return { jsonrpc: "2.0", id: message.id ?? null, result: response };
      }
      approvalSignature = consumed.signature;
    }

    const policy = engine.evaluate({
      tool: name,
      args: cleanArgs,
      principal: session.principal,
      scopes: session.scopes,
      priorCalls: session.priorCalls,
      untrusted: Boolean(rawArgs.untrusted),
      callsThisMinute: session.priorCalls.length,
    });

    const effectiveDecision =
      approvalSignature && policy.decision === "challenge" ? "allow" : policy.decision;

    if (effectiveDecision === "deny" || effectiveDecision === "challenge") {
      const payload = {
        error_code: effectiveDecision === "challenge" ? "HUMAN_APPROVAL_REQUIRED" : policy.code,
        error: policy.reason,
        categories: policy.categories,
        retryable: effectiveDecision === "challenge",
      };
      if (effectiveDecision === "challenge") {
        payload.approval_token = gate.challenge({ actionHash, principal: session.principal });
        payload.action_hash = actionHash;
        payload.approval_hint = "Sign the token with the human approval secret, then retry with approval_token.";
      }
      const response = toolError(payload);
      ledger.append({
        principal: session.principal,
        tool: name,
        input: { name, args: cleanArgs },
        output: response,
        decision: policy.decision,
      });
      metrics[effectiveDecision === "challenge" ? "challenged" : "denied"]++;
      metrics.total++;
      metrics.latencies.push(performance.now() - started);
      return { jsonrpc: "2.0", id: message.id ?? null, result: response };
    }

    const forwarded = { ...message, params: { ...message.params, arguments: cleanArgs } };
    const response = await downstream(forwarded);
    const output = response.result ?? response.error ?? null;
    ledger.append({
      principal: session.principal,
      tool: name,
      input: { name, args: cleanArgs },
      output,
      decision: "allow",
      approvalSignature,
      idempotencyKey,
    });
    session.priorCalls.push(name);
    metrics.allowed++;
    metrics.total++;
    metrics.latencies.push(performance.now() - started);
    return response;
  }

  async function handle(message) {
    if (!message || typeof message !== "object") {
      return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "invalid request" } };
    }
    if (message.method === "tools/call") return handleToolCall(message);
    if (message.method === "firewall/approve") {
      const { token, signature } = message.params ?? {};
      const result = gate.approve(token, signature);
      return {
        jsonrpc: "2.0",
        id: message.id ?? null,
        result: { content: [{ type: "text", text: JSON.stringify(result) }], isError: !result.ok },
      };
    }
    if (message.method === "firewall/receipts") {
      return {
        jsonrpc: "2.0",
        id: message.id ?? null,
        result: { content: [{ type: "text", text: JSON.stringify({ root: ledger.root, receipts: ledger.receipts, valid: ledger.verify() }) }], isError: false },
      };
    }
    if (message.method === "firewall/health") {
      return { jsonrpc: "2.0", id: message.id ?? null, result: { content: [{ type: "text", text: JSON.stringify(metricsSummary()) }], isError: false } };
    }
    if (message.method === "initialize") {
      return {
        jsonrpc: "2.0",
        id: message.id ?? null,
        result: {
          protocolVersion: "2025-11-25",
          capabilities: { tools: {} },
          serverInfo: { name: "heros-firewall", version: "0.2.0" },
        },
      };
    }
    return downstream(message);
  }

  function metricsSummary() {
    const sorted = [...metrics.latencies].sort((a, b) => a - b);
    const pct = (p) => sorted.length ? sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)] : 0;
    return {
      total: metrics.total,
      allowed: metrics.allowed,
      denied: metrics.denied,
      challenged: metrics.challenged,
      p50_ms: Number(pct(0.5).toFixed(3)),
      p95_ms: Number(pct(0.95).toFixed(3)),
      p99_ms: Number(pct(0.99).toFixed(3)),
      receipts: ledger.receipts.length,
      merkle_root: ledger.root,
    };
  }

  return { handle, session, metrics: metricsSummary, ledger };
}
