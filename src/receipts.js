// SPDX-License-Identifier: MIT
// Hash-chained receipts with Merkle roots and inclusion proofs.

import { createHash, randomBytes } from "node:crypto";

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return createHash("sha256").update(typeof value === "string" ? value : canonical(value)).digest("hex");
}

function pairHash(left, right) {
  return sha256(left + right);
}

export class MerkleLedger {
  constructor() {
    this.receipts = [];
    this.responses = new Map();
  }

  append({ principal, tool, input, output, decision, approvalSignature = null, idempotencyKey = null }) {
    const inputHash = sha256(input);
    const outputHash = sha256(output);
    const previous = this.receipts.at(-1)?.receipt_hash ?? "0".repeat(64);
    const receipt = {
      receipt_id: randomBytes(8).toString("hex"),
      created_at: new Date().toISOString(),
      principal,
      tool,
      input_hash: inputHash,
      output_hash: outputHash,
      decision,
      approval_signature: approvalSignature,
      idempotency_key: idempotencyKey,
      previous_hash: previous,
    };
    receipt.receipt_hash = sha256(receipt);
    this.receipts.push(receipt);
    receipt.merkle_root = this.rootFor(this.receipts.length);
    if (idempotencyKey) this.responses.set(idempotencyKey, { receipt, response: output });
    return receipt;
  }

  leaves(count = this.receipts.length) {
    return this.receipts.slice(0, count).map((receipt) => receipt.receipt_hash);
  }

  rootFor(count) {
    let level = this.leaves(count);
    if (level.length === 0) return "0".repeat(64);
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(pairHash(level[i], level[i + 1] ?? level[i]));
      }
      level = next;
    }
    return level[0];
  }

  findIdempotent(key) {
    return this.responses.get(key) ?? null;
  }

  proof(index) {
    if (index < 0 || index >= this.receipts.length) return null;
    let level = this.leaves();
    let position = index;
    const path = [];
    while (level.length > 1) {
      const sibling = position ^ 1;
      path.push({ hash: level[sibling] ?? level[position], side: sibling > position ? "right" : "left" });
      const next = [];
      for (let i = 0; i < level.length; i += 2) next.push(pairHash(level[i], level[i + 1] ?? level[i]));
      level = next;
      position = Math.floor(position / 2);
    }
    return { leaf: this.receipts[index].receipt_hash, path, root: level[0] };
  }

  verify() {
    let previous = "0".repeat(64);
    for (let i = 0; i < this.receipts.length; i++) {
      const receipt = this.receipts[i];
      const { merkle_root, receipt_hash, ...unsigned } = receipt;
      if (receipt.previous_hash !== previous) return false;
      if (sha256(unsigned) !== receipt_hash) return false;
      if (this.rootFor(i + 1) !== merkle_root) return false;
      previous = receipt.receipt_hash;
    }
    return true;
  }

  get root() {
    return this.rootFor(this.receipts.length);
  }
}

export function verifyProof(leaf, path, root) {
  let hash = leaf;
  for (const step of path) {
    hash = step.side === "right" ? pairHash(hash, step.hash) : pairHash(step.hash, hash);
  }
  return hash === root;
}
