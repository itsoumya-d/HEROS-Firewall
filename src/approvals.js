// SPDX-License-Identifier: MIT
// HMAC-signed, expiring, single-use approval challenges.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export class ApprovalGate {
  constructor({ secret, ttlMs = 300_000, now = () => Date.now() } = {}) {
    if (!secret || Buffer.byteLength(secret) < 32) {
      throw new Error("approval secret must be at least 32 bytes");
    }
    this.secret = Buffer.from(secret);
    this.ttlMs = ttlMs;
    this.now = now;
    this.pending = new Map();
  }

  challenge({ actionHash, principal }) {
    const token = randomBytes(16).toString("hex");
    this.pending.set(token, {
      actionHash,
      principal,
      expiresAt: this.now() + this.ttlMs,
      approved: false,
      used: false,
    });
    return token;
  }

  /** Human-side helper: sign the token with the approval secret. */
  sign(token) {
    return createHmac("sha256", this.secret).update(token).digest("hex");
  }

  approve(token, signature) {
    const record = this.pending.get(token);
    if (!record) return { ok: false, reason: "unknown token" };
    if (record.used) return { ok: false, reason: "token already used" };
    if (record.expiresAt < this.now()) {
      this.pending.delete(token);
      return { ok: false, reason: "token expired" };
    }
    const expected = Buffer.from(this.sign(token), "hex");
    const supplied = Buffer.from(String(signature ?? ""), "hex");
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) {
      return { ok: false, reason: "invalid signature" };
    }
    record.approved = true;
    return { ok: true, actionHash: record.actionHash };
  }

  consume(token, actionHash) {
    const record = this.pending.get(token);
    if (!record || !record.approved || record.used) return { ok: false, reason: "not approved" };
    if (record.expiresAt < this.now()) {
      this.pending.delete(token);
      return { ok: false, reason: "token expired" };
    }
    if (record.actionHash !== actionHash) return { ok: false, reason: "action mismatch" };
    record.used = true;
    this.pending.delete(token);
    return { ok: true, signature: this.sign(token) };
  }
}
