import { createInterface } from "readline";
import { StdioDownstreamTransport } from "./transport.js";
import { PipelineRunner } from "../pipeline/runner.js";
import { AuditLog, hashArgs } from "../audit/log.js";
import type { Ctx, ToolDef, ToolCall, Stage, Policy } from "../pipeline/types.js";
import type { CredentialBroker } from "../pipeline/broker.js";
import type { HitlStage } from "../pipeline/hitl.js";

export interface RelayOptions {
  serverId: string;
  command: string;
  policy: Policy;
  stages: Stage[];
  auditLog: AuditLog;
  userIntent?: string;
  broker?: CredentialBroker;
  hitl?: HitlStage;
}

// JSON-RPC message shapes
interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id?: number | string | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

function isRequest(msg: Record<string, unknown>): msg is JsonRpcRequest {
  return msg["method"] !== undefined;
}

function makeError(id: number | string | null | undefined, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

export class Relay {
  private readonly transport: StdioDownstreamTransport;
  private readonly runner: PipelineRunner;
  private readonly ctx: Ctx;
  // Map from request id -> original request (so we can correlate response)
  private readonly pendingCalls = new Map<
    string,
    { call: ToolCall; resolve: (r: JsonRpcResponse) => void }
  >();

  constructor(private readonly opts: RelayOptions) {
    this.transport = new StdioDownstreamTransport(opts.command);
    this.runner = new PipelineRunner(opts.stages);
    this.ctx = {
      serverId: opts.serverId,
      userIntent: opts.userIntent,
      policy: opts.policy,
      audit: opts.auditLog,
    };
  }

  /** Start the relay: read JSON-RPC from stdin, forward to downstream, relay responses. */
  start(): void {
    this.transport.start();

    // Downstream → upstream (client)
    this.transport.onMessage((msg) => {
      this.handleDownstreamMessage(msg).catch((err) => {
        process.stderr.write(`[relay] downstream message error: ${err}\n`);
      });
    });

    this.transport.onClose(() => {
      process.stderr.write("[relay] downstream server closed\n");
      process.exit(0);
    });

    // Upstream (client) → relay via stdin
    const rl = createInterface({ input: process.stdin });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const msg = JSON.parse(trimmed) as Record<string, unknown>;
        this.handleUpstreamMessage(msg).catch((err) => {
          process.stderr.write(`[relay] upstream message error: ${err}\n`);
        });
      } catch {
        // ignore non-JSON
      }
    });

    rl.on("close", () => {
      this.transport.stop();
    });
  }

  private sendToClient(msg: Record<string, unknown>): void {
    process.stdout.write(JSON.stringify(msg) + "\n");
  }

  private async handleUpstreamMessage(msg: Record<string, unknown>): Promise<void> {
    if (!isRequest(msg)) {
      // It's a response from client (rare) — forward as-is
      this.transport.send(msg);
      return;
    }

    const req = msg as JsonRpcRequest;

    // Hook: tools/call
    if (req.method === "tools/call" && req.params) {
      await this.handleToolsCall(req);
      return;
    }

    // Hook: tools/list — we'll intercept the response
    // For all other methods, forward transparently
    this.transport.send(msg);
  }

  private async handleToolsCall(req: JsonRpcRequest): Promise<void> {
    const params = req.params as { name?: string; arguments?: Record<string, unknown> };
    const toolName = params.name ?? "";
    const args = params.arguments ?? {};
    const call: ToolCall = { server: this.opts.serverId, tool: toolName, args };

    const runResult = await this.runner.runCall(call, this.ctx);

    // Write audit entry (call side)
    await this.opts.auditLog.append({
      ts: new Date().toISOString(),
      serverId: this.opts.serverId,
      tool: toolName,
      argsHash: hashArgs(args),
      stageResults: runResult.stageResults,
      finalDecision: runResult.finalDecision,
      redactions: runResult.redactions,
    });

    if (runResult.finalDecision === "block") {
      const blocked = makeError(
        req.id,
        -32000,
        `mcp-guard blocked: ${runResult.stageResults.find((r) => r.decision === "block")?.reason ?? "policy violation"}`,
      );
      this.sendToClient(blocked);
      return;
    }

    // HITL escalation — for flagged calls or irreversible tools
    const needsHitl =
      this.opts.hitl &&
      (runResult.finalDecision === "flag" ||
        (this.opts.policy.stages.hitl?.irreversibleTools ?? []).includes(toolName));

    if (needsHitl && this.opts.hitl) {
      const hitlResult = await this.opts.hitl.requestApproval(
        { ...call, args: runResult.mutatedArgs },
        runResult.stageResults,
        this.ctx,
      );
      await this.opts.auditLog.append({
        ts: new Date().toISOString(),
        serverId: this.opts.serverId,
        tool: toolName + "__hitl",
        argsHash: hashArgs(args),
        stageResults: [hitlResult],
        finalDecision: hitlResult.decision,
        redactions: [],
      });
      if (hitlResult.decision === "block") {
        this.sendToClient(makeError(req.id, -32000, `mcp-guard HITL: ${hitlResult.reason ?? "denied"}`));
        return;
      }
    }

    // Credential injection — AFTER pipeline approval, just before forwarding.
    // Broker substitutes real secret for handle; destination gating enforced inside broker.
    let finalArgs = runResult.mutatedArgs;
    if (this.opts.broker && this.opts.policy.credentials?.bindings?.some((b) => b.tool === toolName)) {
      // Collect declared domains from egress evidence (stage results)
      const egressResult = runResult.stageResults.find((r) => r.stage === "egress");
      const declaredDomains = egressResult?.evidence ?? [];
      try {
        const injected = await this.opts.broker.injectCredentials(
          { ...call, args: finalArgs },
          declaredDomains,
          this.ctx,
        );
        finalArgs = injected.args;
        // Audit injection event
        await this.opts.auditLog.append({
          ts: new Date().toISOString(),
          serverId: this.opts.serverId,
          tool: toolName + "__broker_inject",
          argsHash: hashArgs(args),
          stageResults: [{ stage: "credentialBroker", decision: "allow", severity: "none", evidence: injected.evidence }],
          finalDecision: "allow",
          redactions: [],
        });
      } catch (err) {
        const errResp = makeError(req.id, -32000, String(err));
        this.sendToClient(errResp);
        return;
      }
    }

    // Forward (potentially with redacted + credential-injected args)
    const forwardedReq: JsonRpcRequest = {
      ...req,
      params: {
        ...req.params,
        arguments: finalArgs,
      },
    };

    // Store pending so we can run onResult when the response arrives
    if (req.id !== undefined && req.id !== null) {
      await new Promise<void>((resolve) => {
        this.pendingCalls.set(String(req.id), {
          call: { ...call, args: finalArgs },
          resolve: (response) => {
            this.sendToClient(response);
            resolve();
          },
        });
        this.transport.send(forwardedReq);
      });
    } else {
      this.transport.send(forwardedReq);
    }
  }

  private async handleDownstreamMessage(msg: Record<string, unknown>): Promise<void> {
    const response = msg as JsonRpcResponse;

    // Check if this is a tools/list response — intercept for integrity + static scan
    // We detect it by checking if result contains a "tools" array
    if (
      response.result !== null &&
      response.result !== undefined &&
      typeof response.result === "object" &&
      "tools" in (response.result as object)
    ) {
      const tools = ((response.result as Record<string, unknown>)["tools"] ?? []) as ToolDef[];
      const listResults = await this.runner.runToolList(tools, this.ctx);

      const blocked = listResults.find((r) => r.decision === "block");
      const finalListDecision = blocked ? "block" : listResults.some((r) => r.decision === "flag") ? "flag" : "allow";

      // Always audit the tools/list event as one summary entry
      await this.opts.auditLog.append({
        ts: new Date().toISOString(),
        serverId: this.opts.serverId,
        tool: "__tools/list__",
        argsHash: "",
        stageResults: listResults,
        finalDecision: finalListDecision,
        redactions: [],
      });

      // If any stage blocked, send error to client
      if (blocked && response.id !== undefined) {
        const errResp = makeError(response.id, -32000, `mcp-guard blocked tools/list: ${blocked.reason ?? "policy violation"}`);
        this.sendToClient(errResp);
        return;
      }
    }

    // Check for pending call correlation
    if (response.id !== undefined && response.id !== null) {
      const idStr = String(response.id);
      const pending = this.pendingCalls.get(idStr);
      if (pending) {
        this.pendingCalls.delete(idStr);
        // Run onResult pipeline stage
        const resultStages = await this.runner.runResult(pending.call, response.result, this.ctx);
        // Audit result scan
        for (const r of resultStages) {
          await this.opts.auditLog.append({
            ts: new Date().toISOString(),
            serverId: this.opts.serverId,
            tool: pending.call.tool + "__result",
            argsHash: hashArgs(pending.call.args),
            stageResults: [r],
            finalDecision: r.decision,
            redactions: [],
          });
        }
        pending.resolve(response);
        return;
      }
    }

    // Pass through
    this.sendToClient(msg);
  }

  stop(): void {
    this.transport.stop();
  }
}
