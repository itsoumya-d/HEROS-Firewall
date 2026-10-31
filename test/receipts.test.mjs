// SPDX-License-Identifier: MIT
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { MerkleLedger, canonical, sha256, verifyProof } from '../src/receipts.js';

describe('Merkle receipts', () => {
  test('chain and Merkle root verify', () => {
    const ledger = new MerkleLedger();
    ledger.append({ principal: 'a', tool: 'read', input: { x: 1 }, output: { ok: true }, decision: 'allow' });
    ledger.append({ principal: 'a', tool: 'write', input: { x: 2 }, output: { ok: true }, decision: 'allow' });
    ledger.append({ principal: 'b', tool: 'delete', input: { x: 3 }, output: { ok: false }, decision: 'deny' });
    assert.equal(ledger.verify(), true);
    const proof = ledger.proof(1);
    assert.equal(verifyProof(proof.leaf, proof.path, proof.root), true);
    assert.equal(ledger.root, proof.root);
  });

  test('tampering breaks verification', () => {
    const ledger = new MerkleLedger();
    ledger.append({ principal: 'a', tool: 'read', input: { x: 1 }, output: { ok: true }, decision: 'allow' });
    ledger.receipts[0].decision = 'deny';
    assert.equal(ledger.verify(), false);
  });

  test('canonical hashing and idempotency cache', () => {
    assert.equal(canonical({ b: 1, a: 2 }), '{"a":2,"b":1}');
    assert.equal(sha256({ a: 1 }), sha256({ a: 1 }));
    const ledger = new MerkleLedger();
    const receipt = ledger.append({
      principal: 'a', tool: 'read', input: { x: 1 }, output: { ok: true },
      decision: 'allow', idempotencyKey: 'idem-1',
    });
    const cached = ledger.findIdempotent('idem-1');
    assert.equal(cached.receipt.receipt_id, receipt.receipt_id);
  });
});
