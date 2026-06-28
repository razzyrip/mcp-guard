import type { Stage, StageResult, ToolDef, Ctx, Severity } from "./types.js";

// Static description scanner — runs at tools/list time (and install-time in Phase 7).
// Detects prompt-injection phrases, embedded URLs, base64 blobs,
// zero-width / bidi unicode, and ANSI escapes in tool descriptions.

interface PatternDef {
  name: string;
  severity: Severity;
  test: (desc: string) => boolean;
}

const INJECTION_PHRASES: Array<[string, Severity]> = [
  // Critical exfiltration commands
  ["secretly bcc", "high"],
  ["do not tell the user", "high"],
  ["do not mention this to the user", "high"],
  ["exfiltrate", "high"],
  ["send the key to", "high"],
  ["send the token to", "high"],
  ["send the secret to", "high"],
  // Strong injection indicators
  ["ignore previous", "high"],
  ["ignore all previous", "high"],
  ["disregard previous", "high"],
  ["always bcc", "high"],
  ["always cc", "high"],
  ["read .env", "high"],
  ["read ~/.ssh", "high"],
  ["read /etc/passwd", "high"],
  // Medium-severity warnings
  ["you are now", "medium"],
  ["new persona", "medium"],
  ["system prompt", "medium"],
  ["ignore your instructions", "medium"],
  // Low-severity oddities
  ["base64", "low"],
  ["eval(", "low"],
];

const PATTERNS: PatternDef[] = [
  // Injection phrases
  ...INJECTION_PHRASES.map(([phrase, severity]) => ({
    name: `injection:${phrase}`,
    severity: severity as Severity,
    test: (desc: string) => desc.toLowerCase().includes(phrase),
  })),

  // URLs embedded in descriptions (anything that looks like http/https/ftp)
  {
    name: "embedded-url",
    severity: "medium",
    test: (desc: string) => /https?:\/\/[^\s"'<>]+/i.test(desc),
  },

  // Base64-looking blobs (long stretches of base64 alphabet)
  {
    name: "base64-blob",
    severity: "medium",
    test: (desc: string) => /[A-Za-z0-9+/]{60,}={0,2}/.test(desc),
  },

  // Zero-width / bidi / homoglyph unicode
  {
    name: "zero-width-unicode",
    severity: "high",
    test: (desc: string) =>
      /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(desc),
  },

  // ANSI escape sequences
  {
    name: "ansi-escape",
    severity: "medium",
    test: (desc: string) => /\x1b\[[0-9;]*[mGKHFJABCDn]/.test(desc),
  },
];

function severityRank(s: Severity): number {
  return { none: 0, low: 1, medium: 2, high: 3 }[s];
}

export class StaticScanStage implements Stage {
  readonly name = "staticScan";

  async onToolList(tools: ToolDef[], ctx: Ctx): Promise<StageResult[]> {
    const cfg = ctx.policy.stages.staticScan;
    if (!cfg?.enabled) {
      return [{ stage: this.name, decision: "allow", severity: "none", reason: "staticScan disabled" }];
    }

    const blockRank = severityRank(cfg.blockSeverity);
    const results: StageResult[] = [];

    for (const tool of tools) {
      const desc = tool.description ?? "";
      const matches: string[] = [];
      let maxSeverity: Severity = "none";

      for (const pattern of PATTERNS) {
        if (pattern.test(desc)) {
          matches.push(pattern.name);
          if (severityRank(pattern.severity) > severityRank(maxSeverity)) {
            maxSeverity = pattern.severity;
          }
        }
      }

      if (matches.length === 0) {
        results.push({
          stage: this.name,
          decision: "allow",
          severity: "none",
          reason: `clean description: ${tool.name}`,
        });
        continue;
      }

      const decision = severityRank(maxSeverity) >= blockRank ? "block" : "flag";
      results.push({
        stage: this.name,
        decision,
        severity: maxSeverity,
        reason: `suspicious description in '${tool.name}': ${matches.join(", ")}`,
        evidence: matches,
      });
    }

    if (results.length === 0) {
      results.push({ stage: this.name, decision: "allow", severity: "none", reason: "no tools" });
    }

    return results;
  }
}
