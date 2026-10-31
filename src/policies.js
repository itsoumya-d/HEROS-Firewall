// SPDX-License-Identifier: MIT
// Deterministic OWASP Agentic (ASI01-ASI10) policy engine.

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /reveal\s+(the\s+)?system\s+prompt/i,
  /you\s+are\s+now\s+(an?\s+)?(admin|root|developer)/i,
  /exfiltrate|send\s+.*(secret|token|password)/i,
  /disregard\s+.*(safety|policy|rules)/i,
];

const SHELL_PATTERNS = /[;&|`$()<>]|\b(rm|curl|wget|nc|bash|sh)\s+-/i;
const SQL_PATTERNS = /\b(drop\s+table|delete\s+from|truncate|union\s+select|or\s+1=1)\b/i;
const PATH_PATTERNS = /(\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd)/i;

export const CATEGORIES = [
  "ASI01_GOAL_HIJACK",
  "ASI02_TOOL_MISUSE",
  "ASI03_IDENTITY_PRIVILEGE",
  "ASI04_SUPPLY_CHAIN",
  "ASI05_CODE_EXECUTION",
  "ASI06_MEMORY_POISONING",
  "ASI07_INTER_AGENT",
  "ASI08_CASCADING_FAILURE",
  "ASI09_HUMAN_TRUST",
  "ASI10_ROGUE_AGENT",
];

export const DEFAULT_POLICY = Object.freeze({
  allowedTools: [
    "read_file", "search", "http_get", "db_query", "write_file",
    "send_email", "delete_record", "read_secret", "http_post",
    "write_memory", "send_agent_message", "shell_exec", "eval_code",
  ],
  approvalTools: ["delete_record", "send_email", "write_file", "http_post", "shell_exec"],
  exfiltrationTools: ["http_post", "send_email", "send_agent_message"],
  sensitiveTools: ["read_secret"],
  toolScopes: { delete_record: "write", send_email: "write", write_file: "write", http_post: "write", shell_exec: "admin" },
  allowedDomains: ["api.internal.example"],
  allowedAgents: ["agent://planner", "agent://worker"],
  maxArgumentBytes: 65536,
  maxCallsPerMinute: 120,
  registry: null,
});

function strings(value, output = []) {
  if (typeof value === "string") output.push(value);
  else if (Array.isArray(value)) for (const item of value) strings(item, output);
  else if (value && typeof value === "object") for (const item of Object.values(value)) strings(item, output);
  return output;
}

export class PolicyEngine {
  constructor(policy = {}) {
    this.policy = { ...DEFAULT_POLICY, ...policy };
  }

  evaluate({ tool, args = {}, principal = "agent", scopes = ["read"], priorCalls = [], untrusted = false, callsThisMinute = 0 }) {
    const categories = [];
    const deny = (code, reason, category) => this.result("deny", code, reason, category, categories);
    const challenge = (code, reason, category) => this.result("challenge", code, reason, category, categories);
    const text = strings(args).join("\n");

    if (!this.policy.allowedTools.includes(tool)) {
      return deny("TOOL_NOT_ALLOWED", `tool ${tool} is not allowlisted`, "ASI04_SUPPLY_CHAIN");
    }
    if (this.policy.registry && !this.policy.registry.has(tool)) {
      return deny("UNTRUSTED_TOOL", `tool ${tool} is not in the signed registry`, "ASI04_SUPPLY_CHAIN");
    }
    if (Buffer.byteLength(JSON.stringify(args), "utf8") > this.policy.maxArgumentBytes) {
      return deny("ARGUMENT_TOO_LARGE", "tool arguments exceed the size limit", "ASI08_CASCADING_FAILURE");
    }
    if (callsThisMinute > this.policy.maxCallsPerMinute) {
      return deny("RATE_LIMITED", "per-minute call limit exceeded", "ASI08_CASCADING_FAILURE");
    }
    if (INJECTION_PATTERNS.some((pattern) => pattern.test(text))) {
      return deny("PROMPT_INJECTION", "untrusted text contains an instruction-hijack pattern", "ASI01_GOAL_HIJACK");
    }
    if (PATH_PATTERNS.test(text)) {
      return deny("PATH_TRAVERSAL", "argument contains a path traversal pattern", "ASI02_TOOL_MISUSE");
    }
    if (tool === "shell_exec" && SHELL_PATTERNS.test(text)) {
      return deny("DANGEROUS_SHELL", "shell_exec argument contains a dangerous command pattern", "ASI05_CODE_EXECUTION");
    }
    if (tool === "eval_code" && /import\s+os|subprocess|require\(|eval\(/i.test(text)) {
      return deny("DYNAMIC_CODE", "eval_code argument contains a forbidden construct", "ASI05_CODE_EXECUTION");
    }
    if (tool === "db_query" && SQL_PATTERNS.test(text)) {
      return deny("DANGEROUS_SQL", "db_query contains a destructive or injected SQL pattern", "ASI02_TOOL_MISUSE");
    }
    const required = this.policy.toolScopes[tool];
    if (required && !scopes.includes(required) && !(required === "write" && scopes.includes("admin"))) {
      return deny("INSUFFICIENT_SCOPE", `tool ${tool} requires ${required} scope`, "ASI03_IDENTITY_PRIVILEGE");
    }
    if (tool === "send_agent_message" && !this.policy.allowedAgents.includes(args.to)) {
      return deny("UNTRUSTED_AGENT", "inter-agent target is not allowlisted", "ASI07_INTER_AGENT");
    }
    if (untrusted && tool === "write_memory") {
      return deny("MEMORY_POISONING", "untrusted content cannot be written to memory", "ASI06_MEMORY_POISONING");
    }
    if (this.policy.exfiltrationTools.includes(tool)) {
      const url = args.url ?? args.to ?? "";
      if (typeof url === "string" && /^https?:\/\//i.test(url)) {
        const domain = url.replace(/^https?:\/\//i, "").split("/")[0];
        if (!this.policy.allowedDomains.includes(domain)) {
          return deny("EXFILTRATION_DOMAIN", `domain ${domain} is not allowlisted`, "ASI07_INTER_AGENT");
        }
      }
      if (priorCalls.includes("read_secret")) {
        return deny("EXFILTRATION_CHAIN", "sensitive read followed by an outbound action", "ASI10_ROGUE_AGENT");
      }
    }
    if (this.policy.approvalTools.includes(tool)) {
      return challenge("HUMAN_APPROVAL_REQUIRED", `tool ${tool} needs human approval`, "ASI09_HUMAN_TRUST");
    }
    return this.result("allow", "ALLOW", "policy checks passed", null, categories);
  }

  result(decision, code, reason, category, categories) {
    const list = category ? [...categories, category] : categories;
    return { decision, code, reason, categories: list, risk: decision === "deny" ? 1 : decision === "challenge" ? 0.6 : 0 };
  }
}
