"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import type { OperationalContext } from "@/src/generated/api-contract";
import type { PlatformSnapshot } from "@/src/lib/api";

import { Brand } from "./brand";
import { Icon } from "./icon";
import { LogoutButton } from "./logout-button";
import { NetworkState } from "./network-state";
import { PrimaryNavigation } from "./primary-navigation";

interface ProductShellProps {
  children: ReactNode;
  context: OperationalContext | null;
  snapshot: PlatformSnapshot;
}

export function ProductShell({ children, context, snapshot }: ProductShellProps) {
  const pathname = usePathname();
  const readiness = snapshot.readiness?.status ?? "offline";
  const version = snapshot.system?.version ?? "indisponível";
  const deploymentMode = snapshot.system?.deploymentMode ?? "control plane offline";

  if (pathname.startsWith("/login")) {
    return <main className="auth-surface">{children}</main>;
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Ir para o conteúdo</a>

      <aside className="sidebar">
        <div className="sidebar__brand">
          <Brand />
        </div>
        <PrimaryNavigation context={context} />
        <div className="sidebar__security">
          <span className="sidebar__security-icon"><Icon name="shield" size={18} /></span>
          <div>
            <strong>Execução isolada</strong>
            <span>LAN somente via site-runtime</span>
          </div>
        </div>
      </aside>

      <div className="app-shell__body">
        <header className="topbar">
          <div className="topbar__mobile-brand"><Brand compact /></div>
          <div className="topbar__context">
            <span className="eyebrow">{context ? "Organização autenticada" : "Control plane"}</span>
            <strong>{context ? context.organization.name : deploymentMode}</strong>
            {context ? <span>{context.sites.length} site(s) acessível(is)</span> : null}
          </div>
          <div className="topbar__actions">
            <NetworkState />
            <span className="platform-chip" data-status={readiness}>
              <span className="platform-chip__dot" />
              {formatReadiness(readiness)}
            </span>
            {context ? <LogoutButton /> : <Link className="icon-action" href="/login">Entrar</Link>}
          </div>
        </header>

        <main className="app-main" id="main-content">{children}</main>

        <footer className="app-footer">
          <div className="app-footer__brand">
            <Brand compact />
            <div>
              <strong>Seven Network Manager</strong>
              <span>Infraestrutura administrada com contexto e isolamento</span>
            </div>
          </div>
          <div className="app-footer__meta">
            <span>v{version}</span>
            <span aria-hidden="true">•</span>
            <span>{new Date(snapshot.capturedAt).getFullYear()} Seven</span>
            <span aria-hidden="true">•</span>
            <span>PostgreSQL autoritativo · Redis efêmero</span>
          </div>
        </footer>
      </div>
    </div>
  );
}

function formatReadiness(value: string) {
  switch (value) {
    case "ready":
      return "Operacional";
    case "degraded":
      return "Degradado";
    case "not_ready":
      return "Não pronto";
    default:
      return "Offline";
  }
}
