import { cache } from "react";
import { number, object, safeParse, string } from "valibot";

import { getServerConfig } from "./config";

const systemStatusSchema = object({
  name: string(),
  version: string(),
  deploymentMode: string(),
});

const readinessStatusSchema = object({
  status: string(),
  database: string(),
  redis: string(),
  runtime: string(),
  appliedMigrations: number(),
});

export interface SystemStatus {
  name: string;
  version: string;
  deploymentMode: string;
}

export interface ReadinessStatus {
  status: string;
  database: string;
  redis: string;
  runtime: string;
  appliedMigrations: number;
}

export interface PlatformSnapshot {
  system: SystemStatus | null;
  readiness: ReadinessStatus | null;
  capturedAt: string;
}

async function fetchJson(path: string): Promise<unknown | null> {
  const { apiBaseUrl } = getServerConfig();

  try {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      cache: "no-store",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(2_500),
    });

    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) return null;

    return (await response.json()) as unknown;
  } catch {
    return null;
  }
}

export async function getSystemStatus(): Promise<SystemStatus | null> {
  const result = safeParse(systemStatusSchema, await fetchJson("/api/v1/system"));
  return result.success ? result.output : null;
}

export async function getReadinessStatus(): Promise<ReadinessStatus | null> {
  const result = safeParse(readinessStatusSchema, await fetchJson("/ready"));
  return result.success ? result.output : null;
}

export const getPlatformSnapshot = cache(async (): Promise<PlatformSnapshot> => {
  const [system, readiness] = await Promise.all([getSystemStatus(), getReadinessStatus()]);

  return {
    system,
    readiness,
    capturedAt: new Date().toISOString(),
  };
});
