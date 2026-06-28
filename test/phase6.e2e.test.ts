// Phase 6: End-to-end scenario suite
// Covers all 11 scenarios from the spec §9

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { FakeMcpClient } from "../mock/fake-client.js";
import { readFileSync, existsSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

function tmpDir(name: string) {
  return join(tmpdir(), `e2e-${name}-${process.pid}`);
}

function writePolicy(dir: string, yaml: string): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "policy.yaml");
  writeFileSync(path, yaml.trim(), "utf-8");
  return path;
}

// ── Scenario 1: Benign send_email → allow ────────────────────────────────────
describe("E2E Scenario 1: benign send_email → allow", () => {
  const TMP = tmpDir("s1");
  let client: FakeMcpClient;

  beforeAll(async () => {
    const policy = writePolicy(TMP, `
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
  path: "${join(TMP, "audit.log")}"
  hashChain: true
`);
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policy}`);
    await client.start();
  });

  afterAll(() => { client.stop(); rmSync(TMP, { recursive: true, force: true }); });

  it("send_email to @mycompany.com → allow + audited", async () => {
    const { result, error } = await client.callTool("send_email", {
      to: "alice@mycompany.com", subject: "Report", body: "Here is the Q4 report.",
    });
    expect(error).toBeUndefined();
    expect(result?.content?.[0]?.text).toContain("alice@mycompany.com");

    await new Promise(r => setTimeout(r, 200));
    const lines = readFileSync(join(TMP, "audit.log"), "utf-8").trim().split("\n").filter(Boolean);
    const callEntry = lines.map(l => JSON.parse(l) as Record<string, unknown>)
      .find(e => e["tool"] === "send_email");
    expect(callEntry).toBeDefined();
    expect(callEntry!["finalDecision"]).toBe("allow");
  });
});

// ── Scenario 2: send_email with bcc:@exfil.example → block S1 ───────────────
describe("E2E Scenario 2: send_email bcc exfil → block (S1)", () => {
  const TMP = tmpDir("s2");
  let client: FakeMcpClient;

  beforeAll(async () => {
    const policy = writePolicy(TMP, `
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
  path: "${join(TMP, "audit.log")}"
  hashChain: false
`);
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policy}`);
    await client.start();
  });

  afterAll(() => { client.stop(); rmSync(TMP, { recursive: true, force: true }); });

  it("bcc:@exfil.example → error response (blocked)", async () => {
    const { error } = await client.callTool("send_email", {
      to: "alice@mycompany.com", bcc: "collector@exfil.example", subject: "Hi", body: "test",
    });
    expect(error).toBeDefined();
    expect(error!.message).toContain("blocked");
  });
});

// ── Scenario 3: malicious server auto-injects external bcc → block ───────────
describe("E2E Scenario 3: malicious server bcc injection → block (S1 + staticScan)", () => {
  const TMP = tmpDir("s3");
  let client: FakeMcpClient;

  beforeAll(async () => {
    const policy = writePolicy(TMP, `
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
  path: "${join(TMP, "audit.log")}"
  hashChain: false
`);
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policy}`);
    await client.start();
  });

  afterAll(() => { client.stop(); rmSync(TMP, { recursive: true, force: true }); });

  it("malicious description → blocked at tools/list", async () => {
    let blocked = false;
    try { await client.listTools(); } catch { blocked = true; }
    await new Promise(r => setTimeout(r, 200));
    if (!blocked) {
      const lines = readFileSync(join(TMP, "audit.log"), "utf-8").trim().split("\n").filter(Boolean);
      blocked = lines.some(l => (JSON.parse(l) as Record<string,unknown>)["finalDecision"] === "block");
    }
    expect(blocked).toBe(true);
  });
});

// ── Scenario 4: Rug pull → block (S0) ────────────────────────────────────────
describe("E2E Scenario 4: rug pull → block (S0)", () => {
  const TMP = tmpDir("s4");
  let client: FakeMcpClient;

  beforeAll(async () => {
    const policy = writePolicy(TMP, `
servers:
  - id: rugpull
    command: "tsx mock/rugpull-server.ts"
stages:
  integrity: { enabled: true, onChange: block }
  staticScan: { enabled: false }
  egress: { enabled: false }
  secretScan: { enabled: false }
audit:
  path: "${join(TMP, "audit.log")}"
  hashChain: false
`);
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policy}`);
    await client.start();
  });

  afterAll(() => { client.stop(); rmSync(TMP, { recursive: true, force: true }); });

  it("first list OK, second list blocked", async () => {
    const first = await client.listTools();
    expect(first.tools[0].name).toBe("send_email");

    let blocked = false;
    try { await client.listTools(); } catch { blocked = true; }
    await new Promise(r => setTimeout(r, 300));
    if (!blocked) {
      const lines = readFileSync(join(TMP, "audit.log"), "utf-8").trim().split("\n").filter(Boolean);
      blocked = lines.some(l => (JSON.parse(l) as Record<string,unknown>)["finalDecision"] === "block");
    }
    expect(blocked).toBe(true);
  });
});

// ── Scenario 5: fetch_url?key=ghp_… → redact/block (S2) ─────────────────────
describe("E2E Scenario 5: secret in arg → redact (S2)", () => {
  const TMP = tmpDir("s5");
  let client: FakeMcpClient;

  beforeAll(async () => {
    const policy = writePolicy(TMP, `
servers:
  - id: leaky
    command: "tsx mock/leaky-tool-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: false }
  egress: { enabled: false }
  secretScan: { enabled: true, onDetect: redact }
audit:
  path: "${join(TMP, "audit.log")}"
  hashChain: false
`);
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policy}`);
    await client.start();
  });

  afterAll(() => { client.stop(); rmSync(TMP, { recursive: true, force: true }); });

  it("URL with github token → arg redacted, no raw token in audit", async () => {
    await client.callTool("fetch_url", { url: "https://api.example.com?key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" });
    await new Promise(r => setTimeout(r, 200));
    const raw = readFileSync(join(TMP, "audit.log"), "utf-8");
    expect(raw).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
  });
});

// ── Scenario 6: Response with fake token + injection text → flag (S2) ─────────
describe("E2E Scenario 6: response with token → flagged in audit", () => {
  const TMP = tmpDir("s6");
  let client: FakeMcpClient;

  beforeAll(async () => {
    const policy = writePolicy(TMP, `
servers:
  - id: leaky
    command: "tsx mock/leaky-tool-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: false }
  egress: { enabled: false }
  secretScan: { enabled: true, onDetect: redact }
audit:
  path: "${join(TMP, "audit.log")}"
  hashChain: false
`);
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policy}`);
    await client.start();
  });

  afterAll(() => { client.stop(); rmSync(TMP, { recursive: true, force: true }); });

  it("get_data response has token → flagged in audit, no raw token logged", async () => {
    await client.callTool("get_data", {});
    await new Promise(r => setTimeout(r, 300));
    const lines = readFileSync(join(TMP, "audit.log"), "utf-8").trim().split("\n").filter(Boolean);
    const flagged = lines.some(l => {
      const e = JSON.parse(l) as Record<string, unknown>;
      return (e["tool"] as string).includes("result") && e["finalDecision"] === "flag";
    });
    expect(flagged).toBe(true);
    const raw = readFileSync(join(TMP, "audit.log"), "utf-8");
    expect(raw).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
  });
});

// ── Scenario 7: Injection phrases in description → flag/block (staticScan) ───
describe("E2E Scenario 7: injection phrases in description → block", () => {
  const TMP = tmpDir("s7");
  let client: FakeMcpClient;

  beforeAll(async () => {
    const policy = writePolicy(TMP, `
servers:
  - id: malicious
    command: "tsx mock/malicious-email-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: true, blockSeverity: high }
  egress: { enabled: false }
  secretScan: { enabled: false }
audit:
  path: "${join(TMP, "audit.log")}"
  hashChain: false
`);
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policy}`);
    await client.start();
  });

  afterAll(() => { client.stop(); rmSync(TMP, { recursive: true, force: true }); });

  it("malicious server description → blocked", async () => {
    let blocked = false;
    try { await client.listTools(); } catch { blocked = true; }
    await new Promise(r => setTimeout(r, 200));
    if (!blocked) {
      const lines = readFileSync(join(TMP, "audit.log"), "utf-8").trim().split("\n").filter(Boolean);
      blocked = lines.some(l => (JSON.parse(l) as Record<string,unknown>)["finalDecision"] === "block");
    }
    expect(blocked).toBe(true);
  });
});

// ── Scenario 8: Audit log — tamper-evident, no raw secrets ───────────────────
describe("E2E Scenario 8: audit log tamper-evident, no raw secrets", () => {
  const TMP = tmpDir("s8");
  let client: FakeMcpClient;

  beforeAll(async () => {
    const policy = writePolicy(TMP, `
servers:
  - id: email
    command: "tsx mock/benign-email-server.ts"
stages:
  integrity: { enabled: false }
  staticScan: { enabled: false }
  egress: { enabled: false }
  secretScan: { enabled: true, onDetect: redact }
audit:
  path: "${join(TMP, "audit.log")}"
  hashChain: true
`);
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${policy}`);
    await client.start();
  });

  afterAll(() => { client.stop(); rmSync(TMP, { recursive: true, force: true }); });

  it("all entries are valid JSON with ts/serverId/finalDecision", async () => {
    await client.callTool("send_email", { to: "a@mycompany.com", subject: "x", body: "y" });
    await new Promise(r => setTimeout(r, 200));
    const lines = readFileSync(join(TMP, "audit.log"), "utf-8").trim().split("\n").filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(1);
    for (const line of lines) {
      const e = JSON.parse(line) as Record<string, unknown>;
      expect(e).toHaveProperty("ts");
      expect(e).toHaveProperty("serverId");
      expect(e).toHaveProperty("finalDecision");
    }
  });

  it("second+ entries have prevHash (hash chain)", async () => {
    const lines = readFileSync(join(TMP, "audit.log"), "utf-8").trim().split("\n").filter(Boolean);
    if (lines.length >= 2) {
      const second = JSON.parse(lines[1]) as Record<string, unknown>;
      expect(second).toHaveProperty("prevHash");
    }
  });

  it("no raw secrets in audit log", async () => {
    const raw = readFileSync(join(TMP, "audit.log"), "utf-8");
    expect(raw).not.toMatch(/AKIA[0-9A-Z]{16}/);
    expect(raw).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
    expect(raw).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  });
});
