// SPDX-License-Identifier: MIT
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ApprovalGate } from '../src/approvals.js';

const SECRET = 's'.repeat(40);

describe('approval gates', () => {
  test('signed, single-use approval', () => {
    const gate = new ApprovalGate({ secret: SECRET });
    const token = gate.challenge({ actionHash: 'abc', principal: 'human' });
    assert.equal(gate.approve(token, 'bad').ok, false);
    assert.equal(gate.approve(token, gate.sign(token)).ok, true);
    assert.deepEqual(gate.consume(token, 'abc'), { ok: true, signature: gate.sign(token) });
    assert.equal(gate.consume(token, 'abc').ok, false);
  });

  test('action hash binding', () => {
    const gate = new ApprovalGate({ secret: SECRET });
    const token = gate.challenge({ actionHash: 'one', principal: 'human' });
    gate.approve(token, gate.sign(token));
    assert.equal(gate.consume(token, 'two').ok, false);
  });

  test('expiry', () => {
    let now = 1000;
    const gate = new ApprovalGate({ secret: SECRET, ttlMs: 10, now: () => now });
    const token = gate.challenge({ actionHash: 'x', principal: 'human' });
    gate.approve(token, gate.sign(token));
    now += 11;
    assert.equal(gate.consume(token, 'x').ok, false);
  });

  test('rejects short secrets', () => {
    assert.throws(() => new ApprovalGate({ secret: 'short' }));
  });
});
