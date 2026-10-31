// SPDX-License-Identifier: MIT
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine } from '../src/policies.js';
import { adversarialCases, benignCases } from '../src/redteam.js';

describe('OWASP ASI policies', () => {
  test('every adversarial category is blocked or challenged', () => {
    const engine = new PolicyEngine();
    for (const testCase of adversarialCases()) {
      const result = engine.evaluate({
        tool: testCase.tool,
        args: testCase.args,
        scopes: testCase.scopes ?? ['read'],
        priorCalls: testCase.priorCalls ?? [],
        untrusted: Boolean(testCase.untrusted),
      });
      assert.notEqual(result.decision, 'allow', testCase.category);
    }
  });

  test('benign operations are allowed', () => {
    const engine = new PolicyEngine();
    for (const testCase of benignCases()) {
      const result = engine.evaluate({
        tool: testCase.tool,
        args: testCase.args,
        scopes: ['write'],
      });
      assert.equal(result.decision, 'allow', `${testCase.tool}: ${result.reason}`);
    }
  });

  test('specific protections', () => {
    const engine = new PolicyEngine();
    assert.equal(engine.evaluate({ tool: 'nope' }).decision, 'deny');
    assert.equal(engine.evaluate({ tool: 'delete_record', args: {}, scopes: ['read'] }).code, 'INSUFFICIENT_SCOPE');
    assert.equal(engine.evaluate({ tool: 'shell_exec', args: { cmd: 'echo ok; rm -rf /' }, scopes: ['admin'] }).code, 'DANGEROUS_SHELL');
    assert.equal(engine.evaluate({ tool: 'db_query', args: { query: 'DROP TABLE users' }, scopes: ['write'] }).code, 'DANGEROUS_SQL');
    assert.equal(engine.evaluate({ tool: 'write_memory', args: { text: 'x' }, untrusted: true }).code, 'MEMORY_POISONING');
    assert.equal(engine.evaluate({ tool: 'http_post', args: { url: 'https://evil.example/x' }, scopes: ['write'] }).code, 'EXFILTRATION_DOMAIN');
    assert.equal(engine.evaluate({ tool: 'delete_record', args: { id: '1' }, scopes: ['write'] }).decision, 'challenge');
  });
});
