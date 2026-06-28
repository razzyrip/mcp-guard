import { IntegrityStage } from "../pipeline/integrity.js";
import { StaticScanStage } from "../pipeline/staticScan.js";
import { EgressStage } from "../pipeline/egress.js";
import { SecretScanStage } from "../pipeline/secretScan.js";
import { CredentialBroker } from "../pipeline/broker.js";
import { JudgeStage } from "../pipeline/judge.js";
import { HitlStage, AutoDenyProvider, LocalWebProvider } from "../pipeline/hitl.js";
import Anthropic from "@anthropic-ai/sdk";
import { join } from "path";
import { mkdirSync } from "fs";
import type { Stage, Policy } from "../pipeline/types.js";

// Builds the ordered list of pipeline stages from policy config.
// Stages are independent; this factory is the only place they are composed.

export interface StageFactoryOptions {
  policy: Policy;
  /** Base directory for state files (pins, etc.). Default: .mcp-guard/ */
  stateDir?: string;
}

export interface StageFactoryResult {
  stages: Stage[];
  broker?: CredentialBroker;
  hitl?: HitlStage;
}

export function buildStages(opts: StageFactoryOptions): StageFactoryResult {
  const { policy } = opts;
  const stateDir = opts.stateDir ?? ".mcp-guard";
  mkdirSync(stateDir, { recursive: true });

  const stages: Stage[] = [];
  let broker: CredentialBroker | undefined;
  let hitl: HitlStage | undefined;

  // S0 — Integrity
  if (policy.stages.integrity?.enabled !== false) {
    const pinsPath = join(stateDir, "pins.json");
    stages.push(new IntegrityStage(pinsPath));
  }

  // Static scan (runs at tools/list)
  if (policy.stages.staticScan?.enabled !== false) {
    stages.push(new StaticScanStage());
  }

  // S1 — Egress allowlist
  if (policy.stages.egress?.enabled !== false) {
    stages.push(new EgressStage());
  }

  // S2 — Secret scan
  if (policy.stages.secretScan?.enabled !== false) {
    stages.push(new SecretScanStage());
  }

  // Credential broker — schema rewrite on onToolList, handle validation on onCall
  if (policy.credentials?.bindings?.length) {
    broker = new CredentialBroker(policy.credentials);
    stages.push(broker);
  }

  // S3 — AI judge (out-of-band, mocked in tests)
  if (policy.stages.judge?.enabled) {
    const judgeStage = new JudgeStage(() => new Anthropic());
    stages.push(judgeStage);
  }

  // HITL — approval provider
  if (policy.stages.hitl?.enabled) {
    const provider =
      policy.stages.hitl.provider === "localweb"
        ? new LocalWebProvider()
        : new AutoDenyProvider();
    hitl = new HitlStage(provider);
    // HitlStage is NOT added to the pipeline stages array — it's called explicitly
    // by the relay after a flag/irreversible decision (not as a normal onCall stage).
  }

  return { stages, broker, hitl };
}
