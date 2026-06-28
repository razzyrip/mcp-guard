import { isHighEntropy } from "../util/entropy.js";
import { deepClone } from "../util/redact.js";
import type { Stage, StageResult, ToolCall, Ctx } from "./types.js";

// S2 — Secret scan stage.
// On args: detect secrets → redact or block per policy.
// On responses: detect secrets → flag.
// Never writes raw secret values to evidence or audit — only pattern names + field paths.

interface SecretPattern {
  name: string;
  regex: RegExp;
}

// All patterns are for well-known token formats only.
const BUILT_IN_PATTERNS: SecretPattern[] = [
  { name: "aws-access-key", regex: /AKIA[0-9A-Z]{16}/ },
  { name: "github-token", regex: /gh[pousr]_[A-Za-z0-9]{36}/ },
  { name: "slack-token", regex: /xox[baprs]-[A-Za-z0-9\-]{10,}/ },
  { name: "google-api-key", regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: "private-key", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "jwt", regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ },
  {
    name: "generic-api-key",
    regex: /(api|secret|access|token)[_-]?key\s*[:=]\s*["']?[A-Za-z0-9\-_]{16,}/i,
  },
];

const REDACTED = "***REDACTED***";

/** Scan a single string value for known secret patterns. Returns matching pattern names. */
function scanString(value: string, extraSecrets: string[]): string[] {
  const matches: string[] = [];

  for (const pattern of BUILT_IN_PATTERNS) {
    if (pattern.regex.test(value)) {
      matches.push(pattern.name);
    }
  }

  // Extra literal secrets
  for (const secret of extraSecrets) {
    if (value.includes(secret)) {
      matches.push("extra-secret");
    }
  }

  // High-entropy check on long strings (> 20 chars, not already matched)
  if (matches.length === 0 && isHighEntropy(value, 20, 4.5)) {
    matches.push("high-entropy-string");
  }

  return matches;
}

/** Recursively scan an object's string values, return { path, patterns } hits. */
function scanObject(
  obj: Record<string, unknown>,
  extraSecrets: string[],
  prefix = "",
): Array<{ path: string; patterns: string[] }> {
  const hits: Array<{ path: string; patterns: string[] }> = [];

  for (const [key, value] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof value === "string") {
      const patterns = scanString(value, extraSecrets);
      if (patterns.length > 0) {
        hits.push({ path, patterns });
      }
    } else if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      hits.push(...scanObject(value as Record<string, unknown>, extraSecrets, path));
    } else if (Array.isArray(value)) {
      value.forEach((item, i) => {
        if (typeof item === "string") {
          const patterns = scanString(item, extraSecrets);
          if (patterns.length > 0) hits.push({ path: `${path}[${i}]`, patterns });
        }
      });
    }
  }

  return hits;
}

/** Redact secret values at the detected paths. */
function redactHits(
  args: Record<string, unknown>,
  hits: Array<{ path: string }>,
): Record<string, unknown> {
  const result = deepClone(args);
  for (const hit of hits) {
    const parts = hit.path.split(".");
    let cursor: Record<string, unknown> = result;
    for (let i = 0; i < parts.length - 1; i++) {
      if (typeof cursor[parts[i]] === "object" && cursor[parts[i]] !== null) {
        cursor = cursor[parts[i]] as Record<string, unknown>;
      }
    }
    const last = parts[parts.length - 1];
    if (last in cursor) cursor[last] = REDACTED;
  }
  return result;
}

export class SecretScanStage implements Stage {
  readonly name = "secretScan";

  async onCall(call: ToolCall, ctx: Ctx): Promise<StageResult> {
    const cfg = ctx.policy.stages.secretScan;
    if (!cfg?.enabled) {
      return { stage: this.name, decision: "allow", severity: "none", reason: "secretScan disabled" };
    }

    const extraSecrets = cfg.extraSecrets ?? [];
    const hits = scanObject(call.args, extraSecrets);

    if (hits.length === 0) {
      return { stage: this.name, decision: "allow", severity: "none" };
    }

    // Evidence: field paths + pattern names (never raw values)
    const evidence = hits.map((h) => `${h.path}:[${h.patterns.join(",")}]`);

    if (cfg.onDetect === "block") {
      return {
        stage: this.name,
        decision: "block",
        severity: "high",
        reason: `secrets detected in args: ${evidence.join("; ")}`,
        evidence,
      };
    }

    // redact
    const mutatedArgs = redactHits(call.args, hits);
    return {
      stage: this.name,
      decision: "redact",
      severity: "medium",
      reason: `secrets redacted in args: ${evidence.join("; ")}`,
      mutatedArgs,
      evidence,
    };
  }

  async onResult(call: ToolCall, result: unknown, ctx: Ctx): Promise<StageResult> {
    const cfg = ctx.policy.stages.secretScan;
    if (!cfg?.enabled) {
      return { stage: this.name, decision: "allow", severity: "none", reason: "secretScan disabled" };
    }

    // Scan result (responses) — flag only, never redact the response inline
    // (the caller can add a redaction pass later if needed)
    const extraSecrets = cfg.extraSecrets ?? [];
    let resultStr = "";
    try {
      resultStr = JSON.stringify(result);
    } catch {
      return { stage: this.name, decision: "allow", severity: "none" };
    }

    const patterns = scanString(resultStr, extraSecrets);
    if (patterns.length === 0) {
      return { stage: this.name, decision: "allow", severity: "none" };
    }

    return {
      stage: this.name,
      decision: "flag",
      severity: "high",
      reason: `secrets detected in response for '${call.tool}': ${patterns.join(", ")}`,
      evidence: patterns,
    };
  }
}
