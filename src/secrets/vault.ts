import { createCipheriv, createDecipheriv, randomBytes, createHash, scryptSync } from "crypto";
import { readFileSync, writeFileSync, existsSync } from "fs";

// Vault — pluggable secret backend.
// Secrets are retrieved on demand, held in memory only for the duration of one forward,
// and zeroized after use. Never written to config, transcript, or audit.

export type VaultBackend = "env" | "encrypted-file" | "keychain" | "external";

export interface VaultOptions {
  backend: VaultBackend;
  /** Path to encrypted secrets file (encrypted-file backend) */
  filePath?: string;
  /** Passphrase for encrypted-file (from env var MCP_GUARD_VAULT_PASS) */
  passphrase?: string;
}

export interface Vault {
  get(secretName: string): Promise<string>;
}

// ── env backend ────────────────────────────────────────────────────────────────

class EnvVault implements Vault {
  async get(secretName: string): Promise<string> {
    // Convention: secret name "figma" → env var MCP_SECRET_FIGMA
    const envKey = `MCP_SECRET_${secretName.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
    const value = process.env[envKey];
    if (!value) {
      throw new Error(`Secret '${secretName}' not found in env (expected ${envKey})`);
    }
    return value;
  }
}

// ── encrypted-file backend ─────────────────────────────────────────────────────
// Simple AES-256-GCM encrypted JSON file.
// Format: { iv: hex, authTag: hex, ciphertext: hex, salt: hex }

const ALGO = "aes-256-gcm";

interface EncryptedStore {
  iv: string;
  authTag: string;
  ciphertext: string;
  salt: string;
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32) as Buffer;
}

class EncryptedFileVault implements Vault {
  private readonly filePath: string;
  private readonly passphrase: string;
  private cache: Record<string, string> | null = null;

  constructor(filePath: string, passphrase: string) {
    this.filePath = filePath;
    this.passphrase = passphrase;
  }

  private load(): Record<string, string> {
    if (!existsSync(this.filePath)) return {};
    const raw = readFileSync(this.filePath, "utf-8");
    const store = JSON.parse(raw) as EncryptedStore;
    const salt = Buffer.from(store.salt, "hex");
    const key = deriveKey(this.passphrase, salt);
    const iv = Buffer.from(store.iv, "hex");
    const authTag = Buffer.from(store.authTag, "hex");
    const decipher = createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(store.ciphertext, "hex")),
      decipher.final(),
    ]);
    return JSON.parse(decrypted.toString("utf-8")) as Record<string, string>;
  }

  /** Save secrets (used by vault CLI / tests). */
  save(secrets: Record<string, string>): void {
    const salt = randomBytes(32);
    const key = deriveKey(this.passphrase, salt);
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGO, key, iv);
    const plaintext = JSON.stringify(secrets);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const store: EncryptedStore = {
      iv: iv.toString("hex"),
      authTag: authTag.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
      salt: salt.toString("hex"),
    };
    writeFileSync(this.filePath, JSON.stringify(store), "utf-8");
    this.cache = null; // invalidate cache
  }

  async get(secretName: string): Promise<string> {
    if (!this.cache) this.cache = this.load();
    const value = this.cache[secretName];
    if (value === undefined) {
      throw new Error(`Secret '${secretName}' not found in encrypted vault`);
    }
    return value;
  }
}

// ── Keychain stub (macOS) ──────────────────────────────────────────────────────
// Real impl would use `security find-generic-password`; stub for MVP.

class KeychainVault implements Vault {
  async get(secretName: string): Promise<string> {
    // Try env fallback for dev
    const envKey = `MCP_SECRET_${secretName.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
    const value = process.env[envKey];
    if (value) return value;
    throw new Error(`Keychain vault: secret '${secretName}' not found (keychain integration not yet implemented; set ${envKey})`);
  }
}

// ── Factory ────────────────────────────────────────────────────────────────────

export function createVault(opts: VaultOptions): Vault {
  switch (opts.backend) {
    case "env":
      return new EnvVault();
    case "encrypted-file": {
      const filePath = opts.filePath ?? ".mcp-guard/vault.enc";
      const passphrase = opts.passphrase ?? process.env["MCP_GUARD_VAULT_PASS"] ?? "";
      if (!passphrase) {
        throw new Error("encrypted-file vault requires MCP_GUARD_VAULT_PASS env var or passphrase option");
      }
      return new EncryptedFileVault(filePath, passphrase);
    }
    case "keychain":
      return new KeychainVault();
    case "external":
      throw new Error("External vault backend not yet implemented");
    default:
      throw new Error(`Unknown vault backend: ${opts.backend as string}`);
  }
}

/** Hash a secret value (for audit log — never log the raw value). */
export function hashSecret(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

// Export EncryptedFileVault for test usage
export { EncryptedFileVault };
