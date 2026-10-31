// SPDX-License-Identifier: MIT
// stdio transport for an MCP client <-> firewall <-> downstream server.
import { spawn } from "node:child_process";
import readline from "node:readline";
import { PolicyEngine } from "./policies.js";
import { ApprovalGate } from "./approvals.js";
import { MerkleLedger } from "./receipts.js";
import { createProxy } from "./proxy.js";

async function startDownstream(bin, args) {
  const child = spawn(bin, args, { stdio: ["pipe", "pipe", "inherit"] });
  const pending = new Map();
  readline.createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", (line) => {
    if (!line.trim()) return;
    let message;
    try { message = JSON.parse(line); } catch { return; }
    const resolver = pending.get(message.id);
    if (resolver) { pending.delete(message.id); resolver(message); }
  });
  function call(message) {
    if (!Object.prototype.hasOwnProperty.call(message, "id")) {
      child.stdin.write(JSON.stringify(message) + "\n");
      return null;
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(message.id); reject(new Error("downstream timeout")); }, 30000);
      pending.set(message.id, (response) => { clearTimeout(timer); resolve(response); });
      child.stdin.write(JSON.stringify(message) + "\n");
    });
  }
  return { child, call };
}

export async function runStdioProxy({ downstreamBin, downstreamArgs = [], approvalSecret }) {
  if (!downstreamBin) throw new Error("downstreamBin is required");
  if (!approvalSecret || approvalSecret.length < 32) throw new Error("HEROS_APPROVAL_SECRET must be >= 32 chars");
  const downstream = await startDownstream(downstreamBin, downstreamArgs);
  const proxy = createProxy({
    engine: new PolicyEngine(),
    gate: new ApprovalGate({ secret: approvalSecret }),
    ledger: new MerkleLedger(),
    downstream: (message) => downstream.call(message),
  });
  const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  let queue = Promise.resolve();
  input.on("line", (line) => {
    if (!line.trim()) return;
    queue = queue.then(async () => {
      let message;
      try { message = JSON.parse(line); } catch {
        process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }) + "\n");
        return;
      }
      const response = await proxy.handle(message);
      if (response) process.stdout.write(JSON.stringify(response) + "\n");
    }).catch((error) => {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32603, message: error.message } }) + "\n");
    });
  });
}
