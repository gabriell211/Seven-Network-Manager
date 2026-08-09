import { getServerConfig } from "./config";

export interface SystemStatus {
  name: string;
  version: string;
  deploymentMode: string;
}

export async function getSystemStatus(): Promise<SystemStatus | null> {
  const { apiBaseUrl } = getServerConfig();
  try {
    const response = await fetch(`${apiBaseUrl}/api/v1/system`, {
      cache: "no-store",
      signal: AbortSignal.timeout(2_000),
    });
    if (!response.ok) return null;
    // Temporary handwritten type until the OpenAPI generator from #8 lands.
    return (await response.json()) as SystemStatus;
  } catch {
    return null;
  }
}
