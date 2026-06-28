import { spawn, type ChildProcess } from "child_process";
import { createInterface } from "readline";

// Downstream server transport — spawns the server as a child process and
// exposes a simple send/onMessage interface over its stdio.
// Design is transport-agnostic: SSE/HTTP can be added as a separate impl.

export type MessageHandler = (message: Record<string, unknown>) => void;

export class StdioDownstreamTransport {
  private child: ChildProcess | null = null;
  private handlers: MessageHandler[] = [];
  private errorHandlers: ((err: Error) => void)[] = [];
  private closeHandlers: (() => void)[] = [];
  private buffer = "";

  constructor(private readonly command: string) {}

  start(): void {
    const [cmd, ...args] = this.command.split(/\s+/);
    this.child = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const rl = createInterface({ input: this.child.stdout! });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const msg = JSON.parse(trimmed) as Record<string, unknown>;
        for (const handler of this.handlers) {
          handler(msg);
        }
      } catch {
        // non-JSON output from downstream server — ignore
      }
    });

    this.child.stderr?.on("data", (data: Buffer) => {
      process.stderr.write(`[downstream] ${data.toString()}`);
    });

    this.child.on("error", (err) => {
      for (const h of this.errorHandlers) h(err);
    });

    this.child.on("close", () => {
      for (const h of this.closeHandlers) h();
    });
  }

  send(message: Record<string, unknown>): void {
    if (!this.child?.stdin?.writable) {
      throw new Error("Downstream transport not started or stdin closed");
    }
    this.child.stdin.write(JSON.stringify(message) + "\n");
  }

  onMessage(handler: MessageHandler): void {
    this.handlers.push(handler);
  }

  onError(handler: (err: Error) => void): void {
    this.errorHandlers.push(handler);
  }

  onClose(handler: () => void): void {
    this.closeHandlers.push(handler);
  }

  stop(): void {
    this.child?.kill();
    this.child = null;
  }

  isRunning(): boolean {
    return this.child !== null && !this.child.killed;
  }
}
