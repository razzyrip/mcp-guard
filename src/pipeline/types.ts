// Core pipeline interfaces for mcp-guard
// All stages must implement Stage; none may depend on another's internals.

export type Decision = "allow" | "redact" | "block" | "flag";
export type Severity = "none" | "low" | "medium" | "high";

export interface ToolDef {
  name: string;
  description?: string;
  inputSchema: unknown;
}

export interface ToolCall {
  server: string;
  tool: string;
  args: Record<string, unknown>;
}

export interface Ctx {
  serverId: string;
  userIntent?: string;
  policy: Policy;
  audit: Audit;
}

export interface StageResult {
  stage: string;
  decision: Decision;
  severity: Severity;
  reason?: string;
  mutatedArgs?: Record<string, unknown>; // present when decision === "redact"
  evidence?: string[]; // matched patterns / changed fields (no raw secrets)
}

export interface Stage {
  name: string;
  onToolList?(tools: ToolDef[], ctx: Ctx): Promise<StageResult[]>;
  onCall?(call: ToolCall, ctx: Ctx): Promise<StageResult>;
  onResult?(call: ToolCall, result: unknown, ctx: Ctx): Promise<StageResult>;
}

// Forward references — concrete types defined in policy.ts and audit/log.ts
// Using 'unknown' here and casting with zod at the boundary keeps this file independent.
export interface Policy {
  servers: ServerConfig[];
  stages: StagesConfig;
  credentials?: CredentialsConfig;
  audit: AuditConfig;
}

export interface ServerConfig {
  id: string;
  command: string;
}

export interface StagesConfig {
  integrity?: IntegrityConfig;
  staticScan?: StaticScanConfig;
  egress?: EgressConfig;
  secretScan?: SecretScanConfig;
  judge?: JudgeConfig;
  hitl?: HitlConfig;
}

export interface IntegrityConfig {
  enabled: boolean;
  onChange: "block" | "flag";
}

export interface StaticScanConfig {
  enabled: boolean;
  blockSeverity: Severity;
}

export interface EgressConfig {
  enabled: boolean;
  allowedDomains: string[];
  destinationFields: Record<string, string[]>;
  onViolation: "block" | "flag";
}

export interface SecretScanConfig {
  enabled: boolean;
  onDetect: "redact" | "block";
  extraSecrets?: string[];
}

export interface JudgeConfig {
  enabled: boolean;
  model: string;
  onError: "flag" | "block";
}

export interface HitlConfig {
  enabled: boolean;
  irreversibleTools: string[];
  provider: "autodeny" | "localweb";
}

export interface CredentialBinding {
  tool: string;
  field?: string;
  header?: string;
  secret: string;
  handle: string;
  injectFor: string[];
}

export interface OAuthConfig {
  server: string;
  mode: "oauth";
  scopes: string[];
}

export interface CredentialsConfig {
  vault: "keychain" | "encrypted-file" | "env" | "external";
  bindings?: CredentialBinding[];
  oauth?: OAuthConfig[];
}

export interface AuditConfig {
  path: string;
  hashChain: boolean;
}

// Audit interface — implemented in audit/log.ts
export interface Audit {
  append(entry: AuditEntry): Promise<void>;
}

export interface AuditEntry {
  ts: string;
  serverId: string;
  tool: string;
  argsHash: string;
  stageResults: StageResult[];
  finalDecision: Decision;
  redactions: string[];
  prevHash?: string;
}
