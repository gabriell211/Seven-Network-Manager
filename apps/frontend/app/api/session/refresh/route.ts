import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import type { AccessResponse, ErrorEnvelope } from "@/src/generated/api-contract";
import { getServerConfig } from "@/src/lib/config";

export async function POST() {
  const store = await cookies();
  const refresh = store.get("__Host-snm_refresh") ?? store.get("snm_refresh");
  const csrf = store.get("__Host-snm_csrf") ?? store.get("snm_csrf");
  if (!refresh || !csrf) {
    return NextResponse.json<ErrorEnvelope>(
      { code: "invalid_session", message: "refresh session is unavailable" },
      { status: 401 },
    );
  }

  const { apiBaseUrl } = getServerConfig();
  let backend: Response;
  try {
    backend = await fetch(`${apiBaseUrl}/api/v1/auth/refresh`, {
      method: "POST",
      headers: {
        accept: "application/json",
        cookie: `${refresh.name}=${refresh.value}; ${csrf.name}=${csrf.value}`,
        "x-snm-csrf": csrf.value,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return NextResponse.json<ErrorEnvelope>(
      { code: "control_plane_unavailable", message: "control plane is temporarily unavailable" },
      { status: 503 },
    );
  }

  const body = (await backend.json()) as AccessResponse | ErrorEnvelope;
  if (!backend.ok || !("accessToken" in body)) {
    return NextResponse.json(body as ErrorEnvelope, { status: backend.status });
  }

  const response = NextResponse.json({ authenticated: true }, { status: 200 });
  response.cookies.set("snm_access", body.accessToken, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: body.expiresInSeconds,
  });
  for (const value of backend.headers.getSetCookie()) {
    response.headers.append("set-cookie", value);
  }
  return response;
}
