import { z } from "zod";
import { readFileSync } from "fs";
import yaml from "js-yaml";
import type { Policy } from "../pipeline/types.js";

// ── Zod schemas ────────────────────────────────────────────────────────────────

const ServerConfigSchema = z.object({
  id: z.string(),
  command: z.string(),
});

const IntegrityConfigSchema = z.object({
  enabled: z.boolean().default(true),
  onChange: z.enum(["block", "flag"]).default("block"),
});

const StaticScanConfigSchema = z.object({
  enabled: z.boolean().default(true),
  blockSeverity: z.enum(["none", "low", "medium", "high"]).default("high"),
});

const EgressConfigSchema = z.object({
  enabled: z.boolean().default(true),
  allowedDomains: z.array(z.string()).default([]),
  destinationFields: z.record(z.array(z.string())).default({}),
  onViolation: z.enum(["block", "flag"]).default("block"),
});

const SecretScanConfigSchema = z.object({
  enabled: z.boolean().default(true),
  onDetect: z.enum(["redact", "block"]).default("redact"),
  extraSecrets: z.array(z.string()).default([]),
});

const JudgeConfigSchema = z.object({
  enabled: z.boolean().default(false),
  model: z.string().default("claude-haiku-4-5"),
  onError: z.enum(["flag", "block"]).default("flag"),
});

const HitlConfigSchema = z.object({
  enabled: z.boolean().default(true),
  irreversibleTools: z.array(z.string()).default([]),
  provider: z.enum(["autodeny", "localweb"]).default("autodeny"),
});

const CredentialBindingSchema = z.object({
  tool: z.string(),
  field: z.string().optional(),
  header: z.string().optional(),
  secret: z.string(),
  handle: z.string(),
  injectFor: z.array(z.string()),
});

const OAuthConfigSchema = z.object({
  server: z.string(),
  mode: z.literal("oauth"),
  scopes: z.array(z.string()),
});

const CredentialsConfigSchema = z.object({
  vault: z.enum(["keychain", "encrypted-file", "env", "external"]).default("env"),
  bindings: z.array(CredentialBindingSchema).optional(),
  oauth: z.array(OAuthConfigSchema).optional(),
});

const AuditConfigSchema = z.object({
  path: z.string().default(".mcp-guard/audit.log"),
  hashChain: z.boolean().default(true),
});

const StagesConfigSchema = z.object({
  integrity: IntegrityConfigSchema.optional(),
  staticScan: StaticScanConfigSchema.optional(),
  egress: EgressConfigSchema.optional(),
  secretScan: SecretScanConfigSchema.optional(),
  judge: JudgeConfigSchema.optional(),
  hitl: HitlConfigSchema.optional(),
});

const PolicySchema = z.object({
  servers: z.array(ServerConfigSchema),
  stages: StagesConfigSchema.default({}),
  credentials: CredentialsConfigSchema.optional(),
  audit: AuditConfigSchema.default({ path: ".mcp-guard/audit.log", hashChain: true }),
});

// ── Loader ─────────────────────────────────────────────────────────────────────

export function loadPolicy(filePath: string): Policy {
  const raw = readFileSync(filePath, "utf-8");
  const parsed = yaml.load(raw);
  const result = PolicySchema.safeParse(parsed);
  if (!result.success) {
    throw new Error(`Invalid policy file ${filePath}:\n${result.error.message}`);
  }
  return result.data as Policy;
}

export function defaultPolicy(): Policy {
  return PolicySchema.parse({
    servers: [],
    stages: {},
    audit: { path: ".mcp-guard/audit.log", hashChain: true },
  }) as Policy;
}

export { PolicySchema };
