/**
 * HTTP client for the raucle-detect REST API.
 *
 * Communicates with a locally-running raucle-detect server
 * (started as a background service by the plugin).
 */

export interface ScanRequest {
  prompt: string;
  mode?: string;
}

export interface ScanResult {
  verdict: string;
  confidence: number;
  injection_detected: boolean;
  categories: string[];
  attack_technique: string;
  matched_rules: string[];
  action: string;
  notes: string[];
  scan_time_ms?: number;
}

export interface HealthResponse {
  status: string;
  version: string;
  mode: string;
  rules_loaded: number;
}

export class ScannerClient {
  private baseUrl: string;
  private timeout: number;

  constructor(port: number = 8900, timeout: number = 5000) {
    this.baseUrl = `http://127.0.0.1:${port}`;
    this.timeout = timeout;
  }

  async scan(prompt: string, mode?: string): Promise<ScanResult> {
    const body: ScanRequest = { prompt };
    if (mode) body.mode = mode;
    return this._post("/scan", body);
  }

  async scanOutput(output: string, originalPrompt?: string, mode?: string): Promise<ScanResult> {
    const body: Record<string, string> = { output };
    if (originalPrompt) body.original_prompt = originalPrompt;
    if (mode) body.mode = mode;
    return this._post("/scan/output", body);
  }

  async scanToolCall(toolName: string, args: Record<string, unknown>, mode?: string): Promise<ScanResult> {
    const body: Record<string, unknown> = { tool_name: toolName, arguments: args };
    if (mode) body.mode = mode;
    return this._post("/scan/tool", body);
  }

  private async _post(path: string, body: unknown): Promise<ScanResult> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!resp.ok) {
      throw new Error(`raucle-detect ${path} failed: ${resp.status} ${resp.statusText}`);
    }

    return (await resp.json()) as ScanResult;
  }

  async health(): Promise<HealthResponse> {
    const resp = await fetch(`${this.baseUrl}/health`, {
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!resp.ok) {
      throw new Error(`raucle-detect health check failed: ${resp.status}`);
    }

    return (await resp.json()) as HealthResponse;
  }

  async isReady(): Promise<boolean> {
    try {
      const h = await this.health();
      return h.status === "ok";
    } catch {
      return false;
    }
  }
}
