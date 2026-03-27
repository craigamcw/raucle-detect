/**
 * Manages the lifecycle of the raucle-detect Python REST server.
 *
 * Starts the server as a child process when the plugin loads,
 * monitors health, and restarts on failure.
 */

import { spawn, type ChildProcess } from "node:child_process";

export interface ServerManagerOptions {
  port: number;
  mode: string;
  rulesDir?: string;
  pythonPath?: string;
  logger: { info: (msg: string) => void; warn: (msg: string) => void; error: (msg: string) => void };
}

export class ServerManager {
  private process: ChildProcess | null = null;
  private port: number;
  private mode: string;
  private rulesDir?: string;
  private pythonPath: string;
  private logger: ServerManagerOptions["logger"];
  private restarting = false;
  private stopped = false;

  constructor(opts: ServerManagerOptions) {
    this.port = opts.port;
    this.mode = opts.mode;
    this.rulesDir = opts.rulesDir;
    this.pythonPath = opts.pythonPath || "raucle-detect";
    this.logger = opts.logger;
  }

  async start(): Promise<void> {
    if (this.process) return;

    // Check if server is already running (from a prior start)
    try {
      const resp = await fetch(`http://127.0.0.1:${this.port}/health`, {
        signal: AbortSignal.timeout(1000),
      });
      if (resp.ok) {
        this.logger.info(`raucle-detect server already running on port ${this.port}`);
        return;
      }
    } catch {
      // Not running — proceed to start
    }

    const isCliCommand = !this.pythonPath.includes("python");
    const args = isCliCommand
      ? [
          "serve",
          "--host", "127.0.0.1",
          "--port", String(this.port),
          "--mode", this.mode,
        ]
      : [
          "-m", "raucle_detect",
          "serve",
          "--host", "127.0.0.1",
          "--port", String(this.port),
          "--mode", this.mode,
        ];

    if (this.rulesDir) {
      args.push("--rules-dir", this.rulesDir);
    }

    this.logger.info(`Starting raucle-detect server on port ${this.port} (mode: ${this.mode})`);

    this.process = spawn(this.pythonPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
      detached: false,
    });

    this.process.stdout?.on("data", (data: Buffer) => {
      const line = data?.toString?.()?.trim?.();
      if (line) this.logger.info(`[raucle-detect] ${line}`);
    });

    this.process.stderr?.on("data", (data: Buffer) => {
      const line = data?.toString?.()?.trim?.();
      if (line) this.logger.warn(`[raucle-detect] ${line}`);
    });

    this.process.on("exit", (code) => {
      this.logger.warn(`raucle-detect server exited with code ${code}`);
      this.process = null;
      if (!this.stopped && !this.restarting) {
        this.restarting = true;
        setTimeout(() => {
          this.restarting = false;
          if (!this.stopped) {
            this.logger.info("Restarting raucle-detect server...");
            this.start().catch((e) =>
              this.logger.error(`Failed to restart raucle-detect: ${e}`)
            );
          }
        }, 10000);
      }
    });

    // Wait for server to be ready
    await this.waitForReady();
  }

  private async waitForReady(maxWaitMs = 15000): Promise<void> {
    const startTime = Date.now();
    while (Date.now() - startTime < maxWaitMs) {
      try {
        const resp = await fetch(`http://127.0.0.1:${this.port}/health`, {
          signal: AbortSignal.timeout(2000),
        });
        if (resp.ok) {
          this.logger.info(`raucle-detect server ready on port ${this.port}`);
          return;
        }
      } catch {
        // Not ready yet
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    this.logger.warn("raucle-detect server did not become ready in time — will retry on first scan");
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.process) {
      this.logger.info("Stopping raucle-detect server");
      this.process.kill("SIGTERM");
      this.process = null;
    }
  }

  get isRunning(): boolean {
    return this.process !== null && !this.process.killed;
  }
}
