import { createHash } from "crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { dirname } from "path";
import type { ToolDef } from "../pipeline/types.js";
import { canonicalize } from "../util/canonical.js";

// Persistent tool-definition hash store (.mcp-guard/pins.json).
// Pins are keyed by `${serverId}/${toolName}`.

export interface PinStore {
  [key: string]: string; // key -> sha256 hex
}

export class PinDB {
  private readonly path: string;
  private store: PinStore;

  constructor(path: string) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      const raw = readFileSync(path, "utf-8");
      this.store = JSON.parse(raw) as PinStore;
    } else {
      this.store = {};
    }
  }

  private key(serverId: string, toolName: string): string {
    return `${serverId}/${toolName}`;
  }

  /** Hash a ToolDef deterministically. */
  static hashTool(tool: ToolDef): string {
    const canonical = canonicalize({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema });
    return createHash("sha256").update(canonical).digest("hex");
  }

  /** Returns "new" (first time), "match" (same hash), or "changed" (rug pull). */
  check(serverId: string, tool: ToolDef): "new" | "match" | "changed" {
    const k = this.key(serverId, tool.name);
    const hash = PinDB.hashTool(tool);
    if (!(k in this.store)) return "new";
    return this.store[k] === hash ? "match" : "changed";
  }

  /** Pin (or re-pin) a tool definition. */
  pin(serverId: string, tool: ToolDef): void {
    const k = this.key(serverId, tool.name);
    this.store[k] = PinDB.hashTool(tool);
    this.flush();
  }

  /** Re-pin by explicit approval (mcp-guard pins --approve). */
  approve(serverId: string, toolName: string, tool: ToolDef): void {
    this.pin(serverId, tool);
  }

  getHash(serverId: string, toolName: string): string | undefined {
    return this.store[this.key(serverId, toolName)];
  }

  private flush(): void {
    writeFileSync(this.path, JSON.stringify(this.store, null, 2), "utf-8");
  }
}
