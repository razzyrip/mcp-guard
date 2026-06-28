// Phase 1 acceptance tests:
// - fake-client reaches benign-email-server through the proxy
// - send_email succeeds
// - audit log has one entry per request

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { FakeMcpClient } from "../mock/fake-client.js";
import { readFileSync, existsSync, rmSync, mkdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

// We run the proxy as a subprocess using tsx (no build required for tests)
// proxy command: tsx src/cli.ts run --policy <tmp_policy>

const TMP = join(tmpdir(), `mcp-guard-test-${process.pid}`);
const AUDIT_PATH = join(TMP, "audit.log");
const PINS_PATH = join(TMP, "pins.json");
const POLICY_PATH = join(TMP, "policy.yaml");

function writePolicy(extra = ""): void {
  mkdirSync(TMP, { recursive: true });
  const yaml = `
servers:
  - id: email
    command: "tsx mock/benign-email-server.ts"

stages: {}

audit:
  path: "${AUDIT_PATH}"
  hashChain: true
${extra}
`.trim();
  writeFileSync(POLICY_PATH, yaml, "utf-8");
}

import { writeFileSync } from "fs";

describe("Phase 1 — pass-through proxy + audit", () => {
  let client: FakeMcpClient;

  beforeAll(async () => {
    writePolicy();
    client = new FakeMcpClient(
      `tsx src/cli.ts run --policy ${POLICY_PATH}`,
    );
    await client.start();
  });

  afterAll(() => {
    client.stop();
    if (existsSync(TMP)) rmSync(TMP, { recursive: true });
  });

  it("lists tools through the proxy", async () => {
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe("send_email");
  });

  it("send_email succeeds through the proxy", async () => {
    const { result, error } = await client.callTool("send_email", {
      to: "alice@mycompany.com",
      subject: "Hello",
      body: "Test email",
    });
    expect(error).toBeUndefined();
    expect(result).toBeDefined();
    const text = result?.content?.[0]?.text ?? "";
    expect(text).toContain("alice@mycompany.com");
  });

  it("audit log has entries after calls", async () => {
    // Give audit a moment to flush
    await new Promise((r) => setTimeout(r, 200));
    expect(existsSync(AUDIT_PATH)).toBe(true);
    const lines = readFileSync(AUDIT_PATH, "utf-8")
      .trim()
      .split("\n")
      .filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(1);

    // Each line must be valid JSON
    for (const line of lines) {
      const entry = JSON.parse(line) as Record<string, unknown>;
      expect(entry).toHaveProperty("ts");
      expect(entry).toHaveProperty("serverId");
      expect(entry).toHaveProperty("finalDecision");
    }
  });

  it("audit log entries have hash chain fields", async () => {
    const lines = readFileSync(AUDIT_PATH, "utf-8")
      .trim()
      .split("\n")
      .filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(2);
    // Second+ entries should have prevHash
    const second = JSON.parse(lines[1]) as Record<string, unknown>;
    expect(second).toHaveProperty("prevHash");
    expect(typeof second["prevHash"]).toBe("string");
  });

  it("no raw secrets appear in audit log", async () => {
    const raw = readFileSync(AUDIT_PATH, "utf-8");
    // No API key patterns, no BEGIN PRIVATE KEY
    expect(raw).not.toMatch(/AKIA[0-9A-Z]{16}/);
    expect(raw).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
    expect(raw).not.toMatch(/BEGIN [A-Z ]*PRIVATE KEY/);
  });
});

describe("Phase 1 — PipelineRunner unit tests", () => {
  it("allow passes through unchanged", async () => {
    const { PipelineRunner } = await import("../src/pipeline/runner.js");
    const runner = new PipelineRunner([]);
    const result = await runner.runCall(
      { server: "test", tool: "foo", args: { x: 1 } },
      {
        serverId: "test",
        policy: {
          servers: [],
          stages: {},
          audit: { path: "/tmp/audit.log", hashChain: false },
        },
        audit: { append: async () => {} },
      },
    );
    expect(result.finalDecision).toBe("allow");
    expect(result.mutatedArgs).toEqual({ x: 1 });
  });

  it("block stage short-circuits pipeline", async () => {
    const { PipelineRunner } = await import("../src/pipeline/runner.js");
    const called: string[] = [];
    const runner = new PipelineRunner([
      {
        name: "blocker",
        async onCall() {
          called.push("blocker");
          return { stage: "blocker", decision: "block", severity: "high", reason: "test block" };
        },
      },
      {
        name: "never",
        async onCall() {
          called.push("never");
          return { stage: "never", decision: "allow", severity: "none" };
        },
      },
    ]);
    const result = await runner.runCall(
      { server: "test", tool: "foo", args: {} },
      {
        serverId: "test",
        policy: { servers: [], stages: {}, audit: { path: "/tmp/audit.log", hashChain: false } },
        audit: { append: async () => {} },
      },
    );
    expect(result.finalDecision).toBe("block");
    expect(called).toEqual(["blocker"]); // "never" was not called
  });

  it("redact stage mutates args and continues", async () => {
    const { PipelineRunner } = await import("../src/pipeline/runner.js");
    const runner = new PipelineRunner([
      {
        name: "redactor",
        async onCall(call) {
          return {
            stage: "redactor",
            decision: "redact",
            severity: "medium",
            mutatedArgs: { ...call.args, secret: "***REDACTED***" },
            evidence: ["secret"],
          };
        },
      },
      {
        name: "checker",
        async onCall(call) {
          // Should see redacted args
          expect(call.args["secret"]).toBe("***REDACTED***");
          return { stage: "checker", decision: "allow", severity: "none" };
        },
      },
    ]);
    const result = await runner.runCall(
      { server: "test", tool: "foo", args: { secret: "real-secret", other: "value" } },
      {
        serverId: "test",
        policy: { servers: [], stages: {}, audit: { path: "/tmp/audit.log", hashChain: false } },
        audit: { append: async () => {} },
      },
    );
    expect(result.finalDecision).toBe("redact");
    expect(result.mutatedArgs["secret"]).toBe("***REDACTED***");
    expect(result.mutatedArgs["other"]).toBe("value");
    expect(result.redactions).toContain("secret");
  });
});
