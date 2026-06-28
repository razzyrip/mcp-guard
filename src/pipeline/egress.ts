import type { Stage, StageResult, ToolCall, Ctx } from "./types.js";

// S1 — Egress allowlist stage.
// Extracts declared destinations from tool call arguments (emails, URLs, hosts).
// Any destination not in allowedDomains → block or flag per onViolation.
// This catches email-exfiltration: bcc to external domain blocked even if send_email is allowed.

/** Extract the domain from an email address. */
function emailDomain(email: string): string | null {
  const match = email.match(/@([^@\s,;>]+)$/);
  return match ? match[1].toLowerCase() : null;
}

/** Extract the hostname from a URL. */
function urlHost(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Extract the domain/host from a value that could be an email, URL, or bare hostname. */
function extractDomain(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.includes("@")) return emailDomain(trimmed);
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://") || trimmed.startsWith("ftp://")) {
    return urlHost(trimmed);
  }
  // Bare hostname / domain
  if (/^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/.test(trimmed)) return trimmed.toLowerCase();
  return null;
}

/** Get all destination values from args for a given tool, per destinationFields config. */
function getDestinations(tool: string, args: Record<string, unknown>, destinationFields: Record<string, string[]>): string[] {
  const fields = destinationFields[tool] ?? [];
  const destinations: string[] = [];
  for (const field of fields) {
    const value = args[field];
    if (typeof value === "string" && value.trim()) {
      // Handle comma-separated values (e.g. "a@x.com, b@y.com")
      for (const part of value.split(/[,;]/)) {
        const trimmed = part.trim();
        if (trimmed) destinations.push(trimmed);
      }
    }
  }
  return destinations;
}

/** Check if a domain is allowed (exact match or subdomain of an allowedDomain). */
function isDomainAllowed(domain: string, allowedDomains: string[]): boolean {
  const d = domain.toLowerCase();
  return allowedDomains.some((allowed) => {
    const a = allowed.toLowerCase();
    return d === a || d.endsWith("." + a);
  });
}

export class EgressStage implements Stage {
  readonly name = "egress";

  async onCall(call: ToolCall, ctx: Ctx): Promise<StageResult> {
    const cfg = ctx.policy.stages.egress;
    if (!cfg?.enabled) {
      return { stage: this.name, decision: "allow", severity: "none", reason: "egress disabled" };
    }

    const { allowedDomains, destinationFields, onViolation } = cfg;

    const destinations = getDestinations(call.tool, call.args, destinationFields);
    if (destinations.length === 0) {
      return { stage: this.name, decision: "allow", severity: "none", reason: "no declared destinations" };
    }

    const violations: string[] = [];
    const declaredDomains: string[] = [];

    for (const dest of destinations) {
      const domain = extractDomain(dest);
      if (!domain) continue;
      declaredDomains.push(domain);
      if (!isDomainAllowed(domain, allowedDomains)) {
        violations.push(domain);
      }
    }

    if (violations.length === 0) {
      return {
        stage: this.name,
        decision: "allow",
        severity: "none",
        reason: `all destinations allowed: ${declaredDomains.join(", ")}`,
        evidence: declaredDomains,
      };
    }

    const decision = onViolation === "block" ? "block" : "flag";
    return {
      stage: this.name,
      decision,
      severity: "high",
      reason: `egress violation — non-allowlisted destination(s): ${violations.join(", ")}`,
      evidence: violations,
    };
  }
}
