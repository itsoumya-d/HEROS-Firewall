#!/usr/bin/env node
// SPDX-License-Identifier: MIT
import { createHmac } from "node:crypto";
import { runStdioProxy } from "../src/stdio.js";

const args = process.argv.slice(2);
if (args[0] === "--version") { process.stdout.write("0.2.0\n"); process.exit(0); }
if (args[0] === "--sign-approval") {
  const secret = process.env.HEROS_APPROVAL_SECRET ?? "";
  if (secret.length < 32) { process.stderr.write("HEROS_APPROVAL_SECRET must be >= 32 chars\n"); process.exit(1); }
  process.stdout.write(createHmac("sha256", secret).update(args[1] ?? "").digest("hex") + "\n");
  process.exit(0);
}
if (args.includes("--help")) {
  process.stderr.write(`HEROS Firewall 0.2.0

  heros-firewall --stdio --downstream-bin <bin> --downstream-arg <arg>...
  heros-firewall --sign-approval <token>

Env: HEROS_APPROVAL_SECRET (>=32 bytes), HEROS_DOWNSTREAM_BIN, HEROS_DOWNSTREAM_ARGS
`);
  process.exit(0);
}
const bin = process.env.HEROS_DOWNSTREAM_BIN;
const downstreamArgs = (process.env.HEROS_DOWNSTREAM_ARGS ?? "").split(" ").filter(Boolean);
runStdioProxy({
  downstreamBin: bin,
  downstreamArgs,
  approvalSecret: process.env.HEROS_APPROVAL_SECRET,
}).catch((error) => { process.stderr.write(`[heros-firewall] ${error.message}\n`); process.exit(1); });
