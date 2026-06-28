#!/usr/bin/env node
import { Command } from "commander";
import { loadPolicy } from "./config/policy.js";
import { AuditLog } from "./audit/log.js";
import { Relay } from "./proxy/relay.js";
import { buildStages } from "./proxy/stageFactory.js";
import { dirname } from "path";

const program = new Command();

program
  .name("mcp-guard")
  .description("MCP Security Proxy — transparent guardrail layer for AI agents")
  .version("0.1.0");

program
  .command("run")
  .description("Start the MCP guard proxy")
  .requiredOption("--policy <path>", "Path to policy YAML file")
  .option("--server <id>", "Server ID to proxy (uses first server in policy if omitted)")
  .option("--intent <text>", "User intent hint passed to the AI judge")
  .action(async (opts: { policy: string; server?: string; intent?: string }) => {
    const policy = loadPolicy(opts.policy);

    if (policy.servers.length === 0) {
      console.error("No servers defined in policy");
      process.exit(1);
    }

    const serverConfig = opts.server
      ? policy.servers.find((s) => s.id === opts.server)
      : policy.servers[0];

    if (!serverConfig) {
      console.error(`Server '${opts.server}' not found in policy`);
      process.exit(1);
    }

    const auditLog = new AuditLog(policy.audit.path, policy.audit.hashChain);
    const stateDir = dirname(policy.audit.path);
    const { stages, broker, hitl } = buildStages({ policy, stateDir });

    const relay = new Relay({
      serverId: serverConfig.id,
      command: serverConfig.command,
      policy,
      stages,
      auditLog,
      userIntent: opts.intent,
      broker,
      hitl,
    });

    process.stderr.write(`[mcp-guard] proxying ${serverConfig.id}: ${serverConfig.command}\n`);
    relay.start();
  });

program
  .command("pins")
  .description("Manage tool definition pins")
  .option("--approve <server/tool>", "Re-pin a changed tool definition")
  .action((opts: { approve?: string }) => {
    if (opts.approve) {
      console.log(`Approving pin for ${opts.approve} (not yet implemented)`);
    } else {
      console.log("Use --approve <server/tool> to re-pin a changed tool definition");
    }
  });

program.parse();
