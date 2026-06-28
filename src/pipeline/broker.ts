import { createHash } from "crypto";
import { createVault, hashSecret, type Vault } from "../secrets/vault.js";
import type {
  Stage,
  StageResult,
  ToolDef,
  ToolCall,
  Ctx,
  CredentialBinding,
  CredentialsConfig,
} from "./types.js";

// Credential Broker — keeps real secrets out of the AI context.
//
// onToolList: rewrite inputSchema to remove/replace credential fields with handle strings.
//   The agent plans calls using <<secret:name>> — the real value never enters its context.
//
// injectCredentials: called at the very end of forward (AFTER pipeline allow),
//   substitutes the real secret into the outbound JSON-RPC call args.
//   Only injects when the call's destination matches injectFor (intersects S1 allowlist).
//
// Audit log records: secret name + hash(value) + handle. Never the raw value.

const REDACTED_HANDLE_DESCRIPTION = "(credentials managed by mcp-guard — pass the handle value)";

export class CredentialBroker implements Stage {
  readonly name = "credentialBroker";
  private vault: Vault | null = null;

  constructor(private readonly config: CredentialsConfig) {}

  private getVault(): Vault {
    if (!this.vault) {
      this.vault = createVault({
        backend: this.config.vault,
        filePath: this.config.vault === "encrypted-file" ? ".mcp-guard/vault.enc" : undefined,
      });
    }
    return this.vault;
  }

  private bindingsForTool(toolName: string): CredentialBinding[] {
    return (this.config.bindings ?? []).filter((b) => b.tool === toolName);
  }

  /** Rewrite tool schema: remove/replace credential fields with handle description. */
  async onToolList(tools: ToolDef[], _ctx: Ctx): Promise<StageResult[]> {
    const bindings = this.config.bindings ?? [];
    if (bindings.length === 0) {
      return [{ stage: this.name, decision: "allow", severity: "none", reason: "no credential bindings" }];
    }

    for (const tool of tools) {
      const toolBindings = bindings.filter((b) => b.tool === tool.name);
      if (toolBindings.length === 0) continue;

      // Rewrite inputSchema to replace credential fields
      const schema = tool.inputSchema as Record<string, unknown>;
      if (schema && typeof schema === "object" && "properties" in schema) {
        const props = schema["properties"] as Record<string, unknown>;
        for (const binding of toolBindings) {
          if (binding.field && binding.field in props) {
            // Replace field with handle description — AI sees the handle, never real value
            props[binding.field] = {
              type: "string",
              description: `${REDACTED_HANDLE_DESCRIPTION} Use value: ${binding.handle}`,
              default: binding.handle,
            };
          }
        }
        // Remove from required if present
        if (Array.isArray(schema["required"])) {
          schema["required"] = (schema["required"] as string[]).filter(
            (f) => !toolBindings.some((b) => b.field === f),
          );
        }
      }
    }

    return [{ stage: this.name, decision: "allow", severity: "none", reason: "schema rewritten for credential fields" }];
  }

  /**
   * Called by the relay AFTER pipeline approval, just before forwarding.
   * Injects real secret into args if destination matches injectFor.
   * Returns mutated args and audit-safe evidence (handle + hash, never raw value).
   */
  async injectCredentials(
    call: ToolCall,
    declaredDomains: string[],
    ctx: Ctx,
  ): Promise<{ args: Record<string, unknown>; evidence: string[] }> {
    const toolBindings = this.bindingsForTool(call.tool);
    if (toolBindings.length === 0) {
      return { args: call.args, evidence: [] };
    }

    let args = { ...call.args };
    const evidence: string[] = [];

    for (const binding of toolBindings) {
      // Only inject if the destination matches injectFor
      const allowed = binding.injectFor.some((host) =>
        declaredDomains.some((d) => d === host || d.endsWith("." + host)),
      );
      if (!allowed) {
        // Destination not in injectFor — do NOT inject
        ctx.audit
          .append({
            ts: new Date().toISOString(),
            serverId: ctx.serverId,
            tool: call.tool,
            argsHash: "",
            stageResults: [
              {
                stage: this.name,
                decision: "block",
                severity: "high",
                reason: `credential injection refused: destination not in injectFor for secret '${binding.secret}'`,
                evidence: [`handle:${binding.handle}`, `injectFor:${binding.injectFor.join(",")}`],
              },
            ],
            finalDecision: "block",
            redactions: [],
          })
          .catch(() => {});
        throw new Error(`mcp-guard: credential '${binding.secret}' injection refused — destination not in injectFor`);
      }

      // Load secret from vault (held in memory only for this call)
      let secretValue: string;
      try {
        secretValue = await this.getVault().get(binding.secret);
      } catch (err) {
        throw new Error(`mcp-guard: vault error for secret '${binding.secret}': ${err}`);
      }

      // Inject
      if (binding.field) {
        args[binding.field] = secretValue;
      }

      // Record audit evidence: handle + hash, never raw value
      evidence.push(`injected:${binding.handle}:sha256:${hashSecret(secretValue)}`);

      // Zeroize from local scope — JS GC will handle the rest
      secretValue = "";
    }

    return { args, evidence };
  }

  /** onCall: check if caller passed the handle (allow) or tried to pass a real-looking value (flag). */
  async onCall(call: ToolCall, ctx: Ctx): Promise<StageResult> {
    const toolBindings = this.bindingsForTool(call.tool);
    if (toolBindings.length === 0) {
      return { stage: this.name, decision: "allow", severity: "none" };
    }

    // Check that credential fields contain the handle (not a raw secret)
    for (const binding of toolBindings) {
      if (!binding.field) continue;
      const value = call.args[binding.field];
      if (typeof value === "string" && value !== binding.handle && value !== "") {
        // Caller passed something other than the handle — suspicious
        return {
          stage: this.name,
          decision: "flag",
          severity: "medium",
          reason: `credential field '${binding.field}' for tool '${call.tool}' does not match expected handle; possible credential leak`,
          evidence: [binding.field],
        };
      }
    }

    return {
      stage: this.name,
      decision: "allow",
      severity: "none",
      reason: "credential handle verified",
    };
  }
}
