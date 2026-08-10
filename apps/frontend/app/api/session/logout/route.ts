import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import type { ErrorEnvelope } from "@/src/generated/api-contract";
import { getServerConfig } from "@/src/lib/config";

export async function POST() {
  const store = await cookies();
  const refresh = store.get("__Host-snm_refresh") ?? store.get("snm_refresh");
  const csrf = store.get("__Host-snm_csrf") ?? store.get("snm_csrf");
  const response = new NextResponse(null, { status: 204 });
  response.cookies.set("snm_access", "", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 0,
  });

  if (!refresh || !csrf) return response;

  const { apiBaseUrl } = getServerConfig();
  try {
    const backend = await fetch(`${apiBaseUrl}/api/v1/auth/logout`, {
      method: "POST",
      headers: {
        cookie: `${refresh.name}=${refresh.value}; ${csrf.name}=${csrf.value}`,
        "x-snm-csrf": csrf.value,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    for (const value of backend.headers.getSetCookie()) {
      response.headers.append("set-cookie", value);
    }
    if (!backend.ok) {
      const payload = (await backend.json()) as ErrorEnvelope;
      return NextResponse.json(payload, { status: backend.status });
    }
  } catch {
    return NextResponse.json<ErrorEnvelope>(
      { code: "control_plane_unavailable", message: "control plane is temporarily unavailable" },
      { status: 503 },
    );
  }

  return response;
}
