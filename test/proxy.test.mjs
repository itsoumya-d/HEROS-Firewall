// SPDX-License-Identifier: MIT
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine } from '../src/policies.js';
import { ApprovalGate } from '../src/approvals.js';
import { MerkleLedger } from '../src/receipts.js';
import { createProxy } from '../src/proxy.js';

const SECRET = 'p'.repeat(40);

function fixture() {
  const calls = [];
  const downstream = async (message) => {
    calls.push(message);
    return {
      jsonrpc: '2.0',
      id: message.id,
      result: { content: [{ type: 'text', text: JSON.stringify({ ok: true, tool: message.params.name }) }], isError: false },
    };
  };
  const gate = new ApprovalGate({ secret: SECRET });
  const proxy = createProxy({
    engine: new PolicyEngine(),
    gate,
    ledger: new MerkleLedger(),
    downstream,
    scopes: ['write'],
  });
  return { proxy, calls, gate };
}

describe('policy proxy', () => {
  test('allows a safe call and records a receipt', async () => {
    const { proxy, calls } = fixture();
    const response = await proxy.handle({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'read_file', arguments: { path: 'docs/readme.md' } },
    });
    assert.equal(response.result.isError, false);
    assert.equal(calls.length, 1);
    assert.equal(proxy.ledger.receipts.length, 1);
    assert.equal(proxy.ledger.verify(), true);
  });

  test('denies unknown tools without calling downstream', async () => {
    const { proxy, calls } = fixture();
    const response = await proxy.handle({
      jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'shadow_tool', arguments: {} },
    });
    assert.equal(response.result.isError, true);
    assert.equal(calls.length, 0);
    assert.equal(JSON.parse(response.result.content[0].text).error_code, 'TOOL_NOT_ALLOWED');
  });

  test('challenge, human approval, retry, and receipt signature', async () => {
    const { proxy, calls, gate } = fixture();
    const params = { name: 'delete_record', arguments: { id: '42' } };
    const first = await proxy.handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params });
    const payload = JSON.parse(first.result.content[0].text);
    assert.equal(payload.error_code, 'HUMAN_APPROVAL_REQUIRED');
    assert.match(payload.approval_token, /^[0-9a-f]{32}$/);

    const approval = await proxy.handle({
      jsonrpc: '2.0', id: 4, method: 'firewall/approve',
      params: { token: payload.approval_token, signature: gate.sign(payload.approval_token) },
    });
    assert.equal(JSON.parse(approval.result.content[0].text).ok, true);

    const second = await proxy.handle({
      jsonrpc: '2.0', id: 5, method: 'tools/call',
      params: { name: 'delete_record', arguments: { id: '42', approval_token: payload.approval_token } },
    });
    assert.equal(second.result.isError, false);
    assert.equal(calls.length, 1);
    const last = proxy.ledger.receipts.at(-1);
    assert.equal(last.decision, 'allow');
    assert.ok(last.approval_signature);
    assert.equal(proxy.ledger.verify(), true);
  });

  test('idempotency returns cached downstream output', async () => {
    const { proxy, calls } = fixture();
    const call = {
      jsonrpc: '2.0', id: 6, method: 'tools/call',
      params: { name: 'read_file', arguments: { path: 'a', idempotency_key: 'same' } },
    };
    await proxy.handle(call);
    await proxy.handle({ ...call, id: 7 });
    assert.equal(calls.length, 1);
  });

  test('health and receipts endpoints', async () => {
    const { proxy } = fixture();
    const health = await proxy.handle({ jsonrpc: '2.0', id: 8, method: 'firewall/health' });
    const metrics = JSON.parse(health.result.content[0].text);
    assert.equal(typeof metrics.p99_ms, 'number');
    const receipts = await proxy.handle({ jsonrpc: '2.0', id: 9, method: 'firewall/receipts' });
    const body = JSON.parse(receipts.result.content[0].text);
    assert.equal(body.valid, true);
  });
});
