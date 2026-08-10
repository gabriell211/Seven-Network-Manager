"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import * as v from "valibot";

import { OperationalIcon } from "./operational-icon";

const LoginSchema = v.object({
  organizationSlug: v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(128)),
  email: v.pipe(v.string(), v.trim(), v.email(), v.maxLength(320)),
  password: v.pipe(v.string(), v.minLength(1), v.maxLength(1024)),
});

interface ErrorResponse {
  code?: string;
  message?: string;
}

export function LoginForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const form = new FormData(event.currentTarget);
    const parsed = v.safeParse(LoginSchema, {
      organizationSlug: form.get("organizationSlug"),
      email: form.get("email"),
      password: form.get("password"),
    });
    if (!parsed.success) {
      setError("Revise organização, e-mail e senha antes de continuar.");
      return;
    }

    setPending(true);
    try {
      const response = await fetch("/api/session/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(parsed.output),
      });
      if (!response.ok) {
        const payload = (await response.json()) as ErrorResponse;
        setError(payload.message ?? "Não foi possível autenticar.");
        return;
      }
      router.replace("/inventory");
      router.refresh();
    } catch {
      setError("O control plane está indisponível. Verifique o deployment e tente novamente.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="login-form" onSubmit={submit}>
      <label className="field">
        <span className="field__label">Organização</span>
        <span className="field__control">
          <OperationalIcon name="monitor" size={18} />
          <input autoComplete="organization" name="organizationSlug" placeholder="slug da organização" required />
        </span>
      </label>

      <label className="field">
        <span className="field__label">E-mail</span>
        <span className="field__control">
          <OperationalIcon name="user" size={18} />
          <input autoComplete="username" inputMode="email" name="email" placeholder="voce@empresa.com" required type="email" />
        </span>
      </label>

      <label className="field">
        <span className="field__label">Senha</span>
        <span className="field__control">
          <OperationalIcon name="lock" size={18} />
          <input autoComplete="current-password" name="password" required type="password" />
        </span>
      </label>

      {error ? <div className="form-error" role="alert">{error}</div> : null}

      <button className="button button--primary button--full" disabled={pending} type="submit">
        <OperationalIcon name="signIn" size={18} />
        {pending ? "Autenticando…" : "Entrar no control plane"}
      </button>
    </form>
  );
}
