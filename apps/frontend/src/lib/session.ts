import { cache } from "react";
import { cookies } from "next/headers";

import type {
  Device,
  DeviceLifecycle,
  DeviceType,
  ErrorEnvelope,
  LifecycleRequest,
  NewDevice,
  OperationalContext,
  UpdateDeviceRequest,
} from "@/src/generated/api-contract";

import { getServerConfig } from "./config";

const ACCESS_COOKIE = "snm_access";

export type ApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; error: ErrorEnvelope };

export interface DeviceListFilters {
  search?: string;
  lifecycle?: DeviceLifecycle;
  deviceType?: DeviceType;
  limit?: number;
  offset?: number;
}

async function accessToken(): Promise<string | null> {
  return (await cookies()).get(ACCESS_COOKIE)?.value ?? null;
}

export async function authenticatedRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<ApiResult<T>> {
  const token = await accessToken();
  if (!token) {
    return {
      ok: false,
      status: 401,
      error: { code: "missing_session", message: "authentication is required" },
    };
  }

  const { apiBaseUrl } = getServerConfig();
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  headers.set("authorization", `Bearer ${token}`);
  if (init.body !== undefined && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  try {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      ...init,
      cache: "no-store",
      headers,
      signal: init.signal ?? AbortSignal.timeout(10_000),
    });
    const requestId = response.headers.get("x-request-id");
    const contentType = response.headers.get("content-type") ?? "";
    const payload = contentType.includes("application/json")
      ? ((await response.json()) as unknown)
      : null;

    if (!response.ok) {
      const envelope = isErrorEnvelope(payload)
        ? payload
        : {
            code: "unexpected_backend_response",
            message: `control plane returned HTTP ${response.status}`,
            requestId,
          };
      return { ok: false, status: response.status, error: envelope };
    }

    return { ok: true, status: response.status, data: payload as T };
  } catch {
    return {
      ok: false,
      status: 503,
      error: {
        code: "control_plane_unavailable",
        message: "control plane is temporarily unavailable",
      },
    };
  }
}

export const getOperationalContext = cache(async () =>
  authenticatedRequest<OperationalContext>("/api/v1/context"),
);

export async function listDevices(
  siteId: string,
  filters: DeviceListFilters,
): Promise<ApiResult<Device[]>> {
  const query = new URLSearchParams();
  if (filters.search) query.set("search", filters.search);
  if (filters.lifecycle) query.set("lifecycle", filters.lifecycle);
  if (filters.deviceType) query.set("deviceType", filters.deviceType);
  query.set("limit", String(filters.limit ?? 50));
  query.set("offset", String(filters.offset ?? 0));
  return authenticatedRequest<Device[]>(
    `/api/v1/sites/${encodeURIComponent(siteId)}/devices?${query.toString()}`,
  );
}

export async function getDevice(siteId: string, deviceId: string): Promise<ApiResult<Device>> {
  return authenticatedRequest<Device>(
    `/api/v1/sites/${encodeURIComponent(siteId)}/devices/${encodeURIComponent(deviceId)}`,
  );
}

export async function createDevice(siteId: string, input: NewDevice): Promise<ApiResult<Device>> {
  return authenticatedRequest<Device>(`/api/v1/sites/${encodeURIComponent(siteId)}/devices`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function updateDevice(
  siteId: string,
  deviceId: string,
  input: UpdateDeviceRequest,
): Promise<ApiResult<Device>> {
  return authenticatedRequest<Device>(
    `/api/v1/sites/${encodeURIComponent(siteId)}/devices/${encodeURIComponent(deviceId)}`,
    { method: "PATCH", body: JSON.stringify(input) },
  );
}

export async function transitionDeviceLifecycle(
  siteId: string,
  deviceId: string,
  input: LifecycleRequest,
): Promise<ApiResult<Device>> {
  return authenticatedRequest<Device>(
    `/api/v1/sites/${encodeURIComponent(siteId)}/devices/${encodeURIComponent(deviceId)}/lifecycle`,
    { method: "POST", body: JSON.stringify(input) },
  );
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record.code === "string" && typeof record.message === "string";
}
