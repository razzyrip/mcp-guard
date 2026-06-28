import type { Stage, StageResult, ToolDef, ToolCall, Ctx, Decision } from "./types.js";

// Runs pipeline stages in order.
// - First "block" short-circuits — call is NOT forwarded.
// - "redact" replaces args in the ToolCall and continues.
// - "flag" or irreversible tool is escalated (handled by caller).
// Every StageResult is collected for the audit entry.

export interface RunResult {
  finalDecision: Decision;
  stageResults: StageResult[];
  mutatedArgs: Record<string, unknown>;
  redactions: string[];
}

export class PipelineRunner {
  constructor(private readonly stages: Stage[]) {}

  async runCall(call: ToolCall, ctx: Ctx): Promise<RunResult> {
    const stageResults: StageResult[] = [];
    let currentArgs = { ...call.args };
    const redactions: string[] = [];
    let finalDecision: Decision = "allow";

    for (const stage of this.stages) {
      if (!stage.onCall) continue;

      const currentCall: ToolCall = { ...call, args: currentArgs };
      const result = await stage.onCall(currentCall, ctx);
      stageResults.push(result);

      if (result.decision === "block") {
        finalDecision = "block";
        break; // short-circuit
      }

      if (result.decision === "redact" && result.mutatedArgs) {
        currentArgs = result.mutatedArgs;
        if (result.evidence) redactions.push(...result.evidence);
        if (finalDecision === "allow") finalDecision = "redact";
      }

      if (result.decision === "flag") {
        if (finalDecision === "allow" || finalDecision === "redact") {
          finalDecision = "flag";
        }
      }
    }

    return { finalDecision, stageResults, mutatedArgs: currentArgs, redactions };
  }

  async runToolList(tools: ToolDef[], ctx: Ctx): Promise<StageResult[]> {
    const allResults: StageResult[] = [];
    for (const stage of this.stages) {
      if (!stage.onToolList) continue;
      const results = await stage.onToolList(tools, ctx);
      allResults.push(...results);
    }
    return allResults;
  }

  async runResult(call: ToolCall, result: unknown, ctx: Ctx): Promise<StageResult[]> {
    const allResults: StageResult[] = [];
    for (const stage of this.stages) {
      if (!stage.onResult) continue;
      const r = await stage.onResult(call, result, ctx);
      allResults.push(r);
    }
    return allResults;
  }
}
