import { NextResponse } from "next/server";
import * as v from "valibot";

import type { AccessResponse, ErrorEnvelope, LoginRequest } from "@/src/generated/api-contract";
import { getServerConfig } from "@/src/lib/config";

const LoginSchema = v.object({
  organizationSlug: v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(128)),
  email: v.pipe(v.string(), v.trim(), v.email(), v.maxLength(320)),
  password: v.pipe(v.string(), v.minLength(1), v.maxLength(1024)),
});

export async function POST(request: Request) {
  let input: unknown;
  try {
    input = await request.json();
  } catch {
    return NextResponse.json<ErrorEnvelope>(
      { code: "invalid_json", message: "request body must be valid JSON" },
      { status: 400 },
    );
  }

  const parsed = v.safeParse(LoginSchema, input);
  if (!parsed.success) {
    return NextResponse.json<ErrorEnvelope>(
      { code: "invalid_login_request", message: "organization, e-mail or password is invalid" },
      { status: 422 },
    );
  }

  const payload: LoginRequest = parsed.output;
  const { apiBaseUrl } = getServerConfig();
  let backend: Response;
  try {
    backend = await fetch(`${apiBaseUrl}/api/v1/auth/login`, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/json" },
      body: JSON.stringify(payload),
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
