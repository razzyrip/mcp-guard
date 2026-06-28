import type { ToolCall } from "./types.js";

// HITL — Human-in-the-loop approval providers.
// ApprovalProvider interface + two implementations:
//   autodeny — denies everything escalated (for CI / tests)
//   localweb  — spins a localhost page for human approval (interactive)

export interface ApprovalRequest {
  call: ToolCall;
  stageResults: Array<{ stage: string; decision: string; reason?: string }>;
  flaggedBy: string[];
}

export interface ApprovalResult {
  approved: boolean;
  reason?: string;
}

export interface ApprovalProvider {
  request(req: ApprovalRequest): Promise<ApprovalResult>;
}

// ── AutoDeny ─────────────────────────────────────────────────────────────────

export class AutoDenyProvider implements ApprovalProvider {
  async request(req: ApprovalRequest): Promise<ApprovalResult> {
    return {
      approved: false,
      reason: `autodeny: tool='${req.call.tool}' escalated by [${req.flaggedBy.join(", ")}] — auto-denied`,
    };
  }
}

// ── LocalWeb ──────────────────────────────────────────────────────────────────
// Opens a localhost HTTP server showing a human-readable approval page.
// Times out after 5 minutes if no response.

export class LocalWebProvider implements ApprovalProvider {
  private readonly port: number;
  private readonly timeoutMs: number;

  constructor(port = 8765, timeoutMs = 5 * 60 * 1000) {
    this.port = port;
    this.timeoutMs = timeoutMs;
  }

  async request(req: ApprovalRequest): Promise<ApprovalResult> {
    const { createServer } = await import("http");
    const { exec } = await import("child_process");

    return new Promise((resolve) => {
      let resolved = false;

      const server = createServer((httpReq, res) => {
        const url = httpReq.url ?? "/";
        if (url === "/") {
          const html = this.renderPage(req);
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(html);
          return;
        }
        if (url === "/approve") {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("Approved");
          server.close();
          if (!resolved) { resolved = true; resolve({ approved: true, reason: "human approved" }); }
          return;
        }
        if (url === "/deny") {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("Denied");
          server.close();
          if (!resolved) { resolved = true; resolve({ approved: false, reason: "human denied" }); }
          return;
        }
        res.writeHead(404);
        res.end();
      });

      server.listen(this.port, "127.0.0.1", () => {
        const url = `http://127.0.0.1:${this.port}/`;
        process.stderr.write(`[mcp-guard/hitl] Approval required: ${url}\n`);
        // Try to open browser
        exec(`open "${url}" 2>/dev/null || xdg-open "${url}" 2>/dev/null || true`);
      });

      // Timeout
      setTimeout(() => {
        if (!resolved) {
          resolved = true;
          server.close();
          resolve({ approved: false, reason: "HITL timeout — auto-denied" });
        }
      }, this.timeoutMs);
    });
  }

  private renderPage(req: ApprovalRequest): string {
    const stageRows = req.stageResults
      .map((r) => `<tr><td>${r.stage}</td><td>${r.decision}</td><td>${r.reason ?? ""}</td></tr>`)
      .join("");
    return `<!DOCTYPE html>
<html>
<head><title>mcp-guard — Approval Required</title>
<style>body{font-family:monospace;max-width:800px;margin:2em auto;padding:1em}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.5em}
.approve{background:#2a2;color:#fff;padding:.8em 2em;font-size:1.2em;margin-right:1em}
.deny{background:#a22;color:#fff;padding:.8em 2em;font-size:1.2em}
</style></head>
<body>
<h1>⚠️ Approval Required</h1>
<h2>Tool: <code>${req.call.tool}</code></h2>
<h3>Arguments:</h3>
<pre>${JSON.stringify(req.call.args, null, 2)}</pre>
<h3>Stage Verdicts:</h3>
<table><tr><th>Stage</th><th>Decision</th><th>Reason</th></tr>${stageRows}</table>
<h3>Flagged by: ${req.flaggedBy.join(", ")}</h3>
<br>
<a href="/approve" class="approve">✅ Approve</a>
<a href="/deny" class="deny">❌ Deny</a>
</body></html>`;
  }
}

// ── HITL Stage ────────────────────────────────────────────────────────────────
// Wraps an ApprovalProvider as a pipeline stage.
// Called after the rest of the pipeline when: decision is "flag" OR tool is irreversible.

import type { Stage as PipelineStage, StageResult, Ctx } from "./types.js";

export class HitlStage implements PipelineStage {
  readonly name = "hitl";

  constructor(private readonly provider: ApprovalProvider) {}

  /** Not called in the normal onCall flow — invoked explicitly by runner/relay for flag/irreversible. */
  async requestApproval(call: ToolCall, priorResults: StageResult[], ctx: Ctx): Promise<StageResult> {
    const cfg = ctx.policy.stages.hitl;
    if (!cfg?.enabled) {
      return { stage: this.name, decision: "allow", severity: "none", reason: "hitl disabled" };
    }

    const flaggedBy = priorResults
      .filter((r) => r.decision === "flag" || r.decision === "block")
      .map((r) => r.stage);

    const isIrreversible = cfg.irreversibleTools.includes(call.tool);
    if (flaggedBy.length === 0 && !isIrreversible) {
      return { stage: this.name, decision: "allow", severity: "none", reason: "no escalation needed" };
    }

    const approvalResult = await this.provider.request({
      call,
      stageResults: priorResults.map((r) => ({ stage: r.stage, decision: r.decision, reason: r.reason })),
      flaggedBy: [...flaggedBy, ...(isIrreversible ? ["irreversible-tool"] : [])],
    });

    if (approvalResult.approved) {
      return {
        stage: this.name,
        decision: "allow",
        severity: "none",
        reason: `HITL approved: ${approvalResult.reason ?? ""}`,
      };
    }

    return {
      stage: this.name,
      decision: "block",
      severity: "high",
      reason: `HITL denied: ${approvalResult.reason ?? "denied"}`,
    };
  }
}
