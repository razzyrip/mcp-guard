# mcp-guard

A transparent MCP proxy that sits between an AI coding agent and downstream MCP servers, catching risky or data-exfiltrating tool behaviour before it executes.

**Defensive security tool.** The mock servers in `mock/` are red-team test fixtures only — they contain benign placeholder payloads and `*.example` destinations.

---

## Table of Contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Integrating with your AI agent](#integrating-with-your-ai-agent)
  - [Claude Code](#claude-code)
  - [OpenCode](#opencode)
  - [GitHub Copilot (VS Code)](#github-copilot-vs-code)
  - [Cursor](#cursor)
  - [Windsurf](#windsurf)
  - [Any other MCP client](#any-other-mcp-client)
- [Configuration](#configuration)
- [CLI reference](#cli-reference)
- [Running tests](#running-tests)
- [Security model](#security-model)
- [Repository layout](#repository-layout)
- [Out of scope / production notes](#out-of-scope--production-notes)
- [Need help?](#need-help)

---

## What it does

```
AI client ──MCP──> mcp-guard (proxy) ──MCP──> downstream MCP server
                        │
   install-time ──> [S0 integrity pin + static description scan]
   per call ──────> [S0 → S1 egress → S2 secret-scan → S3 AI judge → HITL] → audit
```

| Stage | What it catches |
|-------|----------------|
| **S0 integrity** | Tool definition changes ("rug pulls") — hashes and pins each `ToolDef`, blocks if hash changes |
| **staticScan** | Injection phrases, embedded URLs, base64 blobs, zero-width/bidi unicode in descriptions |
| **S1 egress** | Declared destinations (emails, URLs) not in the allowlist — catches exfil BCC even if `send_email` is allowed |
| **S2 secretScan** | AWS keys, GitHub tokens, JWTs, private keys, high-entropy strings in args and responses |
| **S3 judge** | Out-of-band Anthropic call — checks whether the action matches user intent |
| **HITL** | Human approval for flagged or irreversible tool calls |
| **broker** | Credential injection — agent sees only a handle (`<<secret:figma>>`), real token injected at boundary after S1 approval |

Every decision is written to an append-only, hash-chained JSONL audit log. Raw secret values never appear in the log.

---

## How it works

Instead of connecting your AI agent directly to an MCP server, you connect it to `mcp-guard`. mcp-guard then spawns the real MCP server as a child process and relays all JSON-RPC traffic through its security pipeline.

```
Before:  AI agent ─────────────────────────> MCP server

After:   AI agent ──> mcp-guard (proxy) ──> MCP server
                           │
                      security pipeline
                      + audit log
```

No changes to the MCP server are required. No changes to the AI agent are required. You only change the command the agent uses to start the MCP server.

---

## Installation

### Requirements

- **Node.js >= 20** — check with `node --version`
- **npm** (comes with Node.js)

### Install Node.js (if needed)

```bash
# macOS — via Homebrew
brew install node

# Linux (Debian/Ubuntu)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Windows — download installer from https://nodejs.org
# or via winget:
winget install OpenJS.NodeJS.LTS
```

### Install mcp-guard

#### Option A — from npm (recommended for users)

```bash
npm install -g mcp-guard
```

Verify:
```bash
mcp-guard --version
# 0.1.0
```

#### Option B — from source (for development or contribution)

```bash
git clone https://github.com/razzyrip/mcp-guard.git
cd mcp-guard
npm install
npm run build
npm link          # makes `mcp-guard` available globally from source
```

---

## Quick start

1. **Copy the example policy and adapt it:**

```bash
cp policy.example.yaml my-policy.yaml
```

2. **Edit `my-policy.yaml`** — set the downstream server command, allowed domains, and which stages you want enabled (see [Configuration](#configuration)).

3. **Run the proxy:**

```bash
mcp-guard run --policy my-policy.yaml
```

4. **Run the demo** (optional — shows a verdict table for 8 built-in security scenarios):

```bash
npm run demo
```

5. **Run tests:**

```bash
npm test
```

---

## Integrating with your AI agent

The integration pattern is always the same: wherever the agent is configured to run an MCP server command, you prepend `mcp-guard run --policy /path/to/policy.yaml --` (or replace the command entirely). mcp-guard becomes the process the agent connects to; it then spawns the real server.

### Claude Code

Claude Code reads its MCP server list from `~/.claude/mcp_servers.json` (or a project-local `.claude/mcp_servers.json`).

**Step 1 — Create a policy file** (e.g. `~/.config/mcp-guard/policy.yaml`):

```yaml
servers:
  - id: github
    command: "npx @github/github-mcp-server stdio"

stages:
  integrity:   { enabled: true, onChange: block }
  staticScan:  { enabled: true, blockSeverity: high }
  egress:
    enabled: true
    allowedDomains: ["github.com", "api.github.com"]
    destinationFields:
      create_pull_request: ["base_repo"]
    onViolation: block
  secretScan:  { enabled: true, onDetect: redact }
  judge:       { enabled: false }
  hitl:        { enabled: false }

audit:
  path: "~/.config/mcp-guard/audit.log"
  hashChain: true
```

**Step 2 — Configure Claude Code.**

Open or create `~/.claude/mcp_servers.json`:

```json
{
  "mcpServers": {
    "github-guarded": {
      "command": "mcp-guard",
      "args": ["run", "--policy", "/Users/yourname/.config/mcp-guard/policy.yaml"],
      "env": {}
    }
  }
}
```

> **Note:** The `servers[].command` inside your policy YAML points to the *real* MCP server. The `command` in `mcp_servers.json` points to `mcp-guard`.

**Step 3 — Restart Claude Code.** The agent will now connect through mcp-guard.

---

### OpenCode

OpenCode stores MCP configuration in `opencode.json` (project root) or `~/.config/opencode/opencode.json` (global).

**Step 1 — Create a policy file** (e.g. `~/.config/mcp-guard/policy.yaml`) — same as shown in the Claude Code section above.

**Step 2 — Edit your `opencode.json`:**

```json
{
  "mcp": {
    "github-guarded": {
      "type": "local",
      "command": "mcp-guard",
      "args": ["run", "--policy", "/Users/yourname/.config/mcp-guard/policy.yaml"],
      "environment": {}
    }
  }
}
```

**Step 3 — Restart OpenCode.** Run your usual workflow — mcp-guard is now silently in the middle.

**Passing user intent to the judge (optional):**

If you have S3 judge enabled, you can pass a hint about what you're doing so the judge has context:

```json
{
  "mcp": {
    "github-guarded": {
      "type": "local",
      "command": "mcp-guard",
      "args": [
        "run",
        "--policy", "/Users/yourname/.config/mcp-guard/policy.yaml",
        "--intent", "Reviewing PRs and merging approved ones"
      ]
    }
  }
}
```

---

### GitHub Copilot (VS Code)

GitHub Copilot in VS Code supports MCP servers via the VS Code settings.

**Step 1 — Create a policy file.**

**Step 2 — Open VS Code settings** (`Cmd+,` / `Ctrl+,`), search for `mcp`, and click **Edit in settings.json**. Add:

```json
{
  "github.copilot.chat.mcp.servers": {
    "github-guarded": {
      "command": "mcp-guard",
      "args": ["run", "--policy", "/Users/yourname/.config/mcp-guard/policy.yaml"],
      "env": {}
    }
  }
}
```

Alternatively, use a workspace-level `.vscode/mcp.json`:

```json
{
  "servers": {
    "github-guarded": {
      "command": "mcp-guard",
      "args": ["run", "--policy", "${workspaceFolder}/.mcp-guard/policy.yaml"]
    }
  }
}
```

**Step 3 — Reload the window** (`Cmd+Shift+P` → "Developer: Reload Window"). The MCP server list in Copilot Chat will now show `github-guarded` and all calls will go through mcp-guard.

---

### Cursor

Cursor stores MCP server configuration in `~/.cursor/mcp.json`.

**Step 1 — Create a policy file.**

**Step 2 — Edit `~/.cursor/mcp.json`:**

```json
{
  "mcpServers": {
    "github-guarded": {
      "command": "mcp-guard",
      "args": ["run", "--policy", "/Users/yourname/.config/mcp-guard/policy.yaml"],
      "env": {}
    }
  }
}
```

For a project-scoped config, create `.cursor/mcp.json` in the project root:

```json
{
  "mcpServers": {
    "my-api-server-guarded": {
      "command": "mcp-guard",
      "args": ["run", "--policy", ".mcp-guard/policy.yaml"]
    }
  }
}
```

**Step 3 — Restart Cursor.** Open Settings → MCP to confirm the server appears and shows a green status indicator.

---

### Windsurf

Windsurf uses `~/.codeium/windsurf/mcp_config.json` for MCP configuration.

**Step 1 — Create a policy file.**

**Step 2 — Edit `~/.codeium/windsurf/mcp_config.json`:**

```json
{
  "mcpServers": {
    "github-guarded": {
      "command": "mcp-guard",
      "args": ["run", "--policy", "/Users/yourname/.config/mcp-guard/policy.yaml"],
      "env": {}
    }
  }
}
```

**Step 3 — Restart Windsurf.** The guarded server will appear in the Cascade panel.

---

### Any other MCP client

The general pattern for any MCP client that supports stdio servers:

**Before (direct connection):**
```json
{
  "command": "npx my-mcp-server",
  "args": ["stdio"]
}
```

**After (through mcp-guard):**
```json
{
  "command": "mcp-guard",
  "args": ["run", "--policy", "/path/to/policy.yaml"]
}
```

And in your `policy.yaml`:
```yaml
servers:
  - id: my-server
    command: "npx my-mcp-server stdio"
```

The key insight: **the real server command moves into `policy.yaml`**. The client only sees `mcp-guard`.

---

## Configuration

Copy `policy.example.yaml` as your starting point:

```bash
cp policy.example.yaml my-policy.yaml
```

### Full annotated schema

```yaml
servers:
  # The downstream MCP server mcp-guard will spawn and proxy.
  - id: github
    command: "npx @github/github-mcp-server stdio"
    # env:               # optional extra env vars for the child process
    #   GITHUB_TOKEN: "..."

stages:
  integrity:               # S0 — hash pin every ToolDef, block on any change (rug-pull defense)
    enabled: true
    onChange: block        # block | flag

  staticScan:              # Scan tool descriptions for injection patterns at list-time
    enabled: true
    blockSeverity: high    # block at this severity; flag below it

  egress:                  # S1 — allowlist of permitted outbound destinations
    enabled: true
    allowedDomains:
      - "github.com"
      - "api.github.com"
    destinationFields:     # which argument fields of which tools carry destinations
      send_email: ["to", "cc", "bcc"]
      fetch_url:  ["url"]
    onViolation: block     # block | flag

  secretScan:              # S2 — DLP: AWS keys, GH tokens, JWTs, high-entropy strings
    enabled: true
    onDetect: redact       # redact | block
    extraSecrets: []       # additional literal values to redact (never logged in clear)

  judge:                   # S3 — Anthropic out-of-band judge (requires ANTHROPIC_API_KEY)
    enabled: false
    model: "claude-haiku-4-5"
    onError: flag          # flag | block on API error

  hitl:                    # Human-in-the-loop approval via browser popup
    enabled: false
    irreversibleTools:     # always require HITL for these tools
      - "send_email"
      - "delete_file"
      - "push_to_branch"
    provider: autodeny     # autodeny (CI/tests) | localweb (browser UI, 5 min timeout)

credentials:               # Credential broker — keeps real tokens out of AI context
  vault: env               # env | encrypted-file | keychain | external
  bindings:
    - tool: get_file
      field: accessToken
      secret: figma        # set env var MCP_SECRET_FIGMA=<real token>
      handle: "<<secret:figma>>"   # what the model sees and plans with
      injectFor:
        - "api.figma.com" # only inject when egress destination matches

audit:
  path: ".mcp-guard/audit.log"
  hashChain: true          # SHA-256 chain for tamper-evidence
```

### Vault backends

| Backend | Description | Setup |
|---------|-------------|-------|
| `env` | `MCP_SECRET_<NAME>` env vars | Set `MCP_SECRET_FIGMA=token` before running |
| `encrypted-file` | AES-256-GCM encrypted JSON file | Set `MCP_GUARD_VAULT_PASS` and create vault with `mcp-guard vault init` |
| `keychain` | macOS Keychain (stub — falls back to env) | Use `env` for now |
| `external` | Placeholder for Vault/1Password | Not yet implemented |

### Recommended configurations by use case

**Minimal — just block obvious attacks:**
```yaml
stages:
  integrity:  { enabled: true, onChange: block }
  staticScan: { enabled: true, blockSeverity: high }
  secretScan: { enabled: true, onDetect: redact }
  egress:     { enabled: false }
  judge:      { enabled: false }
  hitl:       { enabled: false }
```

**Team/shared environment — add egress control:**
```yaml
stages:
  integrity:  { enabled: true, onChange: block }
  staticScan: { enabled: true, blockSeverity: high }
  egress:
    enabled: true
    allowedDomains: ["yourdomain.com"]
    onViolation: block
  secretScan: { enabled: true, onDetect: redact }
  judge:      { enabled: false }
  hitl:
    enabled: true
    irreversibleTools: ["send_email", "delete_file"]
    provider: localweb
```

**Maximum protection — all stages on:**
```yaml
stages:
  integrity:  { enabled: true, onChange: block }
  staticScan: { enabled: true, blockSeverity: medium }
  egress:
    enabled: true
    allowedDomains: ["yourdomain.com"]
    onViolation: block
  secretScan: { enabled: true, onDetect: block }
  judge:      { enabled: true, model: "claude-haiku-4-5", onError: block }
  hitl:
    enabled: true
    irreversibleTools: ["send_email", "delete_file", "push_to_branch"]
    provider: localweb
```

---

## CLI reference

```
mcp-guard run --policy <path>
  Start the proxy. Reads the first server from policy unless --server is given.

  --policy <path>     Path to policy YAML file (required)
  --server <id>       Server ID to proxy (default: first in policy)
  --intent <text>     User intent hint passed to the AI judge

mcp-guard pins
  Manage tool definition pins.

  --approve <server/tool>   Re-pin a changed tool definition after review
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required when `judge.enabled: true` |
| `MCP_SECRET_<NAME>` | Vault secret when `credentials.vault: env` (e.g. `MCP_SECRET_FIGMA`) |
| `MCP_GUARD_VAULT_PASS` | Passphrase for `encrypted-file` vault |

---

## Running tests

```bash
npm test          # all phases (fully offline — Anthropic SDK is mocked)
npm run demo      # interactive 8-scenario verdict table
```

No Anthropic API key is required for tests.

---

## Security model

- **AI is a detection layer, not the security boundary.** All deterministic controls (S0–S2, audit, broker) work fully with S3 disabled. Disabling the AI judge must not weaken S0–S2.
- **Credentials never travel through AI context.** Real tokens live only on the path `vault → broker → downstream server`. The audit log records only `sha256(value)`.
- **Append-only audit log** with SHA-256 hash chain for tamper-evidence. Tampering with an entry breaks every subsequent hash.
- **Every stage is independently tested** and composed only by the factory — stages cannot call each other.

---

## Repository layout

```
src/
  cli.ts                  # mcp-guard CLI entrypoint
  proxy/
    relay.ts              # JSON-RPC relay (hooks tools/list, tools/call, responses)
    transport.ts          # stdio downstream transport (extensible)
    stageFactory.ts       # builds and composes pipeline stages from policy
  pipeline/
    types.ts              # Stage, StageResult, Decision, Ctx interfaces
    integrity.ts          # S0 — hash pinning
    staticScan.ts         # description injection scanner
    egress.ts             # S1 — destination allowlist
    secretScan.ts         # S2 — DLP secret scanner
    judge.ts              # S3 — out-of-band AI judge
    hitl.ts               # HITL approval providers
    broker.ts             # credential broker
    runner.ts             # stage runner (short-circuit on block)
  config/policy.ts        # zod schema + YAML loader
  secrets/vault.ts        # pluggable vault backends
  audit/
    log.ts                # append-only JSONL + hash chain
    pins.ts               # tool definition hash store
  util/
    canonical.ts          # stable JSON serialization for hashing
    entropy.ts            # Shannon entropy for high-entropy string detection
    redact.ts             # object/string redaction utilities
mock/
  benign-email-server.ts     # clean MCP email server
  malicious-email-server.ts  # injection + server-side bcc exfil fixture
  rugpull-server.ts          # returns tampered tools on 2nd list
  leaky-tool-server.ts       # secrets in args + toxic response
  figma-server.ts            # exercises credential broker
  fake-client.ts             # MCP client for tests and demo
test/                        # vitest specs per phase
scripts/demo.ts              # npm run demo — verdict table
policy.example.yaml
```

---

## Out of scope / production notes

1. **True egress enforcement requires OS-level sandboxing** (network namespace, container, or seccomp). The current MVP enforces egress on *declared* destinations in tool arguments. A server making a raw outbound socket is only fully contained by a sandbox.

2. **Cryptographic tool signing (ETDI-style JWT tool definitions)** is a future hardening over local hash pins.

3. **Remote MCP transport (SSE/HTTP)** — `transport.ts` is designed to be extended. The current implementation uses stdio only, which is what all agents listed here use locally.

4. **Credential broker hardening:** prefer OAuth 2.1 (short-lived, scoped tokens) over long-lived PATs. Run the broker in a separate security context. Short-lived scoped tokens keep the blast radius small and time-bounded.

5. **The AI judge is assistive only.** Never rely on it as the security boundary.

---

## Need help?

Questions, ideas, or want a hand getting mcp-guard running? Reach out — I'm glad to help.

Open an [issue](https://github.com/razzyrip/mcp-guard/issues) or contact me email: razzyripper@gmail.com
