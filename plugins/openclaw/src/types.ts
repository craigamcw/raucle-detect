/**
 * Plugin configuration types.
 */

export interface RaucleClawConfig {
  enabled?: boolean;
  mode?: "strict" | "standard" | "permissive";
  serverPort?: number;
  rulesDir?: string;
  alertChannel?: string;
  blockOnMalicious?: boolean;
  scanInbound?: boolean;
  scanOutbound?: boolean;
  scanToolCalls?: boolean;
  pythonPath?: string;
  agentOverrides?: Record<string, AgentOverride>;
}

export interface AgentOverride {
  mode?: "strict" | "standard" | "permissive";
  scanInbound?: boolean;
  scanOutbound?: boolean;
  scanToolCalls?: boolean;
}

export function resolveConfig(raw: Record<string, unknown>): RaucleClawConfig {
  return {
    enabled: (raw.enabled as boolean) ?? true,
    mode: (raw.mode as RaucleClawConfig["mode"]) ?? "standard",
    serverPort: (raw.serverPort as number) ?? 8900,
    rulesDir: raw.rulesDir as string | undefined,
    alertChannel: raw.alertChannel as string | undefined,
    blockOnMalicious: (raw.blockOnMalicious as boolean) ?? true,
    scanInbound: (raw.scanInbound as boolean) ?? true,
    scanOutbound: (raw.scanOutbound as boolean) ?? true,
    scanToolCalls: (raw.scanToolCalls as boolean) ?? true,
    pythonPath: raw.pythonPath as string | undefined,
    agentOverrides: raw.agentOverrides as Record<string, AgentOverride> | undefined,
  };
}

export function getAgentMode(
  config: RaucleClawConfig,
  agentId?: string,
): string {
  if (agentId && config.agentOverrides?.[agentId]?.mode) {
    return config.agentOverrides[agentId].mode!;
  }
  return config.mode ?? "standard";
}

export function shouldScanInbound(
  config: RaucleClawConfig,
  agentId?: string,
): boolean {
  if (agentId && config.agentOverrides?.[agentId]?.scanInbound !== undefined) {
    return config.agentOverrides[agentId].scanInbound!;
  }
  return config.scanInbound ?? true;
}

export function shouldScanOutbound(
  config: RaucleClawConfig,
  agentId?: string,
): boolean {
  if (agentId && config.agentOverrides?.[agentId]?.scanOutbound !== undefined) {
    return config.agentOverrides[agentId].scanOutbound!;
  }
  return config.scanOutbound ?? true;
}

export function shouldScanToolCalls(
  config: RaucleClawConfig,
  agentId?: string,
): boolean {
  if (agentId && config.agentOverrides?.[agentId]?.scanToolCalls !== undefined) {
    return config.agentOverrides[agentId].scanToolCalls!;
  }
  return config.scanToolCalls ?? true;
}
