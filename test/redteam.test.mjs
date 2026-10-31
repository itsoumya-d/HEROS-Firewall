// SPDX-License-Identifier: MIT
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine } from '../src/policies.js';
import { runRedteam } from '../src/redteam.js';

test('red-team detects 1000 adversarial payloads with low false positives and low p99', () => {
  const result = runRedteam(new PolicyEngine());
  assert.equal(result.adversarial, 1000);
  assert.equal(result.benign, 200);
  assert.ok(result.fnr < 0.01, `FNR ${result.fnr}`);
  assert.ok(result.fpr < 0.01, `FPR ${result.fpr}`);
  assert.ok(result.p99_ms < 5, `p99 ${result.p99_ms}`);
});
