#!/usr/bin/env node
// Fake MCP client — connects through the proxy to a mock server.
// Used by tests and the demo script to drive scenarios.

import { spawn, type ChildProcess } from "child_process";
import { createInterface } from "readline";

export interface ClientOptions {
  /** Command to launch (the proxy or a server directly). */
  command: string;
}

export interface ToolResult {
  content?: Array<{ type: string; text?: string }>;
  isError?: boolean;
}

export class FakeMcpClient {
  private child: ChildProcess | null = null;
  private nextId = 1;
  private pending = new Map<string, (resp: Record<string, unknown>) => void>();

  constructor(private readonly command: string) {}

  async start(): Promise<void> {
    const [cmd, ...args] = this.command.split(/\s+/);
    this.child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });

    const rl = createInterface({ input: this.child.stdout! });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const msg = JSON.parse(trimmed) as Record<string, unknown>;
        const id = msg["id"];
        if (id !== undefined && id !== null) {
          const handler = this.pending.get(String(id));
          if (handler) {
            this.pending.delete(String(id));
            handler(msg);
          }
        }
      } catch {
        // ignore
      }
    });

    this.child.stderr?.on("data", (data: Buffer) => {
      process.stderr.write(`[fake-client/server] ${data.toString()}`);
    });

    // Initialize handshake
    await this.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "fake-client", version: "0.1.0" },
    });
    this.notify("notifications/initialized", {});
  }

  private request(method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      if (!this.child?.stdin?.writable) {
        reject(new Error("Client not started"));
        return;
      }
      const id = this.nextId++;
      this.pending.set(String(id), resolve);
      const msg = { jsonrpc: "2.0", id, method, params };
      this.child.stdin.write(JSON.stringify(msg) + "\n");

      // Timeout after 10s
      setTimeout(() => {
        if (this.pending.has(String(id))) {
          this.pending.delete(String(id));
          reject(new Error(`Timeout waiting for response to ${method} (id=${id})`));
        }
      }, 10_000);
    });
  }

  private notify(method: string, params: Record<string, unknown>): void {
    if (!this.child?.stdin?.writable) return;
    const msg = { jsonrpc: "2.0", method, params };
    this.child.stdin.write(JSON.stringify(msg) + "\n");
  }

  async listTools(): Promise<{ tools: Array<{ name: string; description?: string; inputSchema: unknown }> }> {
    const resp = await this.request("tools/list", {});
    const result = resp["result"] as { tools: Array<{ name: string; description?: string; inputSchema: unknown }> };
    return result;
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<{ result?: ToolResult; error?: { code: number; message: string } }> {
    const resp = await this.request("tools/call", { name, arguments: args });
    if (resp["error"]) {
      return { error: resp["error"] as { code: number; message: string } };
    }
    return { result: resp["result"] as ToolResult };
  }

  stop(): void {
    this.child?.kill();
    this.child = null;
  }
}
