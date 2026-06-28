import { PinDB } from "../audit/pins.js";
import { join } from "path";
import type { Stage, StageResult, ToolDef, Ctx } from "./types.js";

// S0 — Integrity stage.
// On tools/list: hash each ToolDef, compare to stored pin.
//   New tool  → pin it, allow.
//   Unchanged → allow.
//   Changed   → block or flag per policy onChange.

export class IntegrityStage implements Stage {
  readonly name = "integrity";
  private readonly db: PinDB;

  constructor(pinsPath: string) {
    this.db = new PinDB(pinsPath);
  }

  async onToolList(tools: ToolDef[], ctx: Ctx): Promise<StageResult[]> {
    const cfg = ctx.policy.stages.integrity;
    if (!cfg?.enabled) {
      return [{ stage: this.name, decision: "allow", severity: "none", reason: "integrity disabled" }];
    }

    const results: StageResult[] = [];
    for (const tool of tools) {
      const status = this.db.check(ctx.serverId, tool);
      if (status === "new") {
        this.db.pin(ctx.serverId, tool);
        results.push({
          stage: this.name,
          decision: "allow",
          severity: "none",
          reason: `new tool pinned: ${tool.name}`,
          evidence: [tool.name],
        });
      } else if (status === "match") {
        results.push({
          stage: this.name,
          decision: "allow",
          severity: "none",
          reason: `integrity ok: ${tool.name}`,
        });
      } else {
        // "changed" — rug pull detected
        const decision = cfg.onChange === "block" ? "block" : "flag";
        results.push({
          stage: this.name,
          decision,
          severity: "high",
          reason: `rug pull detected: tool definition changed for '${tool.name}'`,
          evidence: [tool.name],
        });
      }
    }

    if (results.length === 0) {
      results.push({ stage: this.name, decision: "allow", severity: "none", reason: "no tools" });
    }

    return results;
  }

  /** Re-pin a tool (called by `mcp-guard pins --approve`). */
  approve(serverId: string, tool: ToolDef): void {
    this.db.pin(serverId, tool);
  }

  getDb(): PinDB {
    return this.db;
  }
}
