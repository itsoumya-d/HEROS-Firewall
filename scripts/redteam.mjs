#!/usr/bin/env node
// SPDX-License-Identifier: MIT
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PolicyEngine } from "../src/policies.js";
import { runRedteam } from "../src/redteam.js";

const here = dirname(fileURLToPath(import.meta.url));
const result = runRedteam(new PolicyEngine());
mkdirSync(join(here, "..", "results"), { recursive: true });
writeFileSync(join(here, "..", "results", "redteam.json"), JSON.stringify(result, null, 2) + "\n");
console.log("| Adversarial | Benign | FNR | FPR | p99 policy latency |");
console.log("|---:|---:|---:|---:|---:|");
console.log(`| ${result.adversarial} | ${result.benign} | ${result.fnr.toFixed(4)} | ${result.fpr.toFixed(4)} | ${result.p99_ms.toFixed(3)} ms |`);
console.log(`wrote results/redteam.json`);
