// Phase 3: S2 Secret Scan tests
// - fetch_url with ?key=ghp_... is redacted/blocked
// - response with fake token is flagged
// - no raw secret in audit log

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { SecretScanStage } from "../src/pipeline/secretScan.js";
import { FakeMcpClient } from "../mock/fake-client.js";
import { readFileSync, existsSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

const baseCtx = {
  serverId: "test",
  policy: {
    servers: [],
    stages: {
      secretScan: { enabled: true, onDetect: "redact" as const, extraSecrets: [] },
    },
    audit: { path: "/tmp/audit.log", hashChain: false },
  },
  audit: { append: async () => {} },
};

// ── Unit tests ────────────────────────────────────────────────────────────────

describe("Phase 3 — SecretScanStage unit tests", () => {
  const stage = new SecretScanStage();

  it("clean args → allow", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "f", args: { url: "https://example.com/api" } },
      baseCtx,
    );
    expect(result.decision).toBe("allow");
  });

  it("GitHub token in arg → redact", async () => {
    const result = await stage.onCall(
      {
        server: "t",
        tool: "fetch_url",
        args: { url: "https://api.example.com?key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" },
      },
      baseCtx,
    );
    expect(result.decision).toBe("redact");
    expect(result.mutatedArgs?.["url"]).toBe("***REDACTED***");
    // Evidence must not contain the raw token value
    const evidenceStr = JSON.stringify(result.evidence ?? []);
    expect(evidenceStr).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  });

  it("AWS key in arg → redact", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "f", args: { key: "AKIAIOSFODNN7EXAMPLE" } },
      baseCtx,
    );
    expect(result.decision).toBe("redact");
    expect(result.mutatedArgs?.["key"]).toBe("***REDACTED***");
  });

  it("onDetect=block blocks instead of redacting", async () => {
    const ctx = {
      ...baseCtx,
      policy: {
        ...baseCtx.policy,
        stages: { secretScan: { enabled: true, onDetect: "block" as const, extraSecrets: [] } },
      },
    };
    const result = await stage.onCall(
      { server: "t", tool: "f", args: { token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" } },
      ctx,
    );
    expect(result.decision).toBe("block");
  });

  it("JWT in arg → redact", async () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const result = await stage.onCall(
      { server: "t", tool: "f", args: { auth: jwt } },
      baseCtx,
    );
    expect(result.decision).toBe("redact");
    expect(result.mutatedArgs?.["auth"]).toBe("***REDACTED***");
  });

  it("private key in arg → redact", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "f", args: { pem: "-----BEGIN RSA PRIVATE KEY-----\nMIIE..." } },
      baseCtx,
    );
    expect(result.decision).toBe("redact");
  });

  it("extraSecrets literal match → redact", async () => {
    const ctx = {
      ...baseCtx,
      policy: {
        ...baseCtx.policy,
        stages: { secretScan: { enabled: true, onDetect: "redact" as const, extraSecrets: ["supersecretpassword123"] } },
      },
    };
    const result = await stage.onCall(
      { server: "t", tool: "f", args: { pass: "supersecretpassword123" } },
      ctx,
    );
    expect(result.decision).toBe("redact");
  });

  it("response with fake token → flag", async () => {
    const fakeResult = {
      content: [{ type: "text", text: "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" }],
    };
    const result = await stage.onResult(
      { server: "t", tool: "get_data", args: {} },
      fakeResult,
      baseCtx,
    );
    expect(result.decision).toBe("flag");
    expect(result.severity).toBe("high");
    // Evidence must NOT contain raw token
    const evidenceStr = JSON.stringify(result.evidence ?? []);
    expect(evidenceStr).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  });

  it("disabled secretScan → allow", async () => {
    const ctx = {
      ...baseCtx,
      policy: { ...baseCtx.policy, stages: { secretScan: { enabled: false, onDetect: "redact" as const, extraSecrets: [] } } },
    };
    const result = await stage.onCall(
      { server: "t", tool: "f", args: { key: "AKIAIOSFODNN7EXAMPLE" } },
      ctx,
    );
    expect(result.decision).toBe("allow");
  });

  it("multiple secrets: all fields redacted", async () => {
    const result = await stage.onCall(
      {
        server: "t",
        tool: "f",
        args: {
          github: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
          aws: "AKIAIOSFODNN7EXAMPLE",
        },
      },
      baseCtx,
    );
    expect(result.decision).toBe("redact");
    expect(result.mutatedArgs?.["github"]).toBe("***REDACTED***");
    expect(result.mutatedArgs?.["aws"]).toBe("***REDACTED***");
  });
});

// ── Integration test: leaky-tool-server ──────────────────────────────────────

describe("Phase 3 — leaky-tool-server integration", () => {
  const TMP = join(tmpdir(), `leaky-test-${process.pid}`);
  const AUDIT_PATH = join(TMP, "audit.log");
  const POLICY_PATH = join(TMP, "policy.yaml");
  let client: FakeMcpClient;

  beforeAll(async () => {
    mkdirSync(TMP, { recursive: true });
    writeFileSync(
      POLICY_PATH,
      `
servers:
  - id: leaky
    command: "tsx mock/leaky-tool-server.ts"
stages:
  integrity:
    enabled: false
  staticScan:
    enabled: false
  secretScan:
    enabled: true
    onDetect: redact
    extraSecrets: []
audit:
  path: "${AUDIT_PATH}"
  hashChain: true
`.trim(),
    );
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${POLICY_PATH}`);
    await client.start();
  });

  afterAll(() => {
    client.stop();
    if (existsSync(TMP)) rmSync(TMP, { recursive: true });
  });

  it("fetch_url with token in URL is redacted (call goes through with redacted url)", async () => {
    const { result, error } = await client.callTool("fetch_url", {
      url: "https://api.example.com?key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    });
    // Should succeed (redact, not block) — downstream gets ***REDACTED*** url
    expect(error).toBeUndefined();
    const text = result?.content?.[0]?.text ?? "";
    expect(text).toContain("REDACTED");
  });

  it("get_data response with fake token is flagged in audit", async () => {
    await client.callTool("get_data", {});
    await new Promise((r) => setTimeout(r, 200));

    const lines = readFileSync(AUDIT_PATH, "utf-8").trim().split("\n").filter(Boolean);
    const flagged = lines.some((l) => {
      const e = JSON.parse(l) as { finalDecision: string; tool: string };
      return e.tool.includes("result") && e.finalDecision === "flag";
    });
    expect(flagged).toBe(true);
  });

  it("no raw secrets appear in the audit log", async () => {
    const raw = readFileSync(AUDIT_PATH, "utf-8");
    expect(raw).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
    expect(raw).not.toMatch(/AKIA[0-9A-Z]{16}/);
    expect(raw).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  });
});
