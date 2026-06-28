#!/usr/bin/env node
// Benign MCP email server — clean descriptions, no injection.
// "Sends" email by logging to stderr (no real network calls).
// Used as the happy-path test fixture.

import { createInterface } from "readline";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

function send(msg: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function makeResult(id: number | string | null | undefined, result: unknown): Record<string, unknown> {
  return { jsonrpc: "2.0", id, result };
}

function makeError(id: number | string | null | undefined, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

const TOOLS = [
  {
    name: "send_email",
    description: "Send an email to one or more recipients.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string", description: "Recipient email address" },
        subject: { type: "string", description: "Email subject" },
        body: { type: "string", description: "Email body" },
        cc: { type: "string", description: "CC email address (optional)" },
        bcc: { type: "string", description: "BCC email address (optional)" },
      },
      required: ["to", "subject", "body"],
    },
  },
];

const rl = createInterface({ input: process.stdin });

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let req: JsonRpcRequest;
  try {
    req = JSON.parse(trimmed) as JsonRpcRequest;
  } catch {
    return;
  }

  if (req.method === "initialize") {
    send(
      makeResult(req.id, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "benign-email-server", version: "0.1.0" },
      }),
    );
    return;
  }

  if (req.method === "notifications/initialized") {
    // no response needed
    return;
  }

  if (req.method === "tools/list") {
    send(makeResult(req.id, { tools: TOOLS }));
    return;
  }

  if (req.method === "tools/call") {
    const params = req.params as { name?: string; arguments?: Record<string, unknown> };
    if (params.name === "send_email") {
      const args = params.arguments ?? {};
      process.stderr.write(
        `[benign-email-server] send_email to=${args["to"]} subject="${args["subject"]}" cc=${args["cc"] ?? "-"} bcc=${args["bcc"] ?? "-"}\n`,
      );
      send(
        makeResult(req.id, {
          content: [{ type: "text", text: `Email sent to ${args["to"]}` }],
        }),
      );
      return;
    }
    send(makeError(req.id, -32601, `Unknown tool: ${params.name}`));
    return;
  }

  // Unknown method — return method not found
  send(makeError(req.id, -32601, `Method not found: ${req.method}`));
});

rl.on("close", () => process.exit(0));
