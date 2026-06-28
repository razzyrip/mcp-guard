import { createHash } from "crypto";
import { appendFileSync, mkdirSync } from "fs";
import { dirname } from "path";
import type { Audit, AuditEntry } from "../pipeline/types.js";

// Append-only JSONL audit log with optional hash chain for tamper-evidence.
// Raw secret values must never be written here — only pattern names + field paths.

export class AuditLog implements Audit {
  private prevHash: string | undefined;
  private readonly path: string;
  private readonly hashChain: boolean;

  constructor(path: string, hashChain: boolean) {
    this.path = path;
    this.hashChain = hashChain;
    // Ensure directory exists
    mkdirSync(dirname(path), { recursive: true });
  }

  async append(entry: AuditEntry): Promise<void> {
    const record: Record<string, unknown> = { ...entry };
    if (this.hashChain) {
      record["prevHash"] = this.prevHash ?? "genesis";
    }
    const line = JSON.stringify(record);
    this.prevHash = createHash("sha256").update(line).digest("hex");
    appendFileSync(this.path, line + "\n", "utf-8");
  }

  getLastHash(): string | undefined {
    return this.prevHash;
  }
}

// Hash tool call arguments for the audit log (one-way; never log raw args).
export function hashArgs(args: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(args)).digest("hex").slice(0, 16);
}
