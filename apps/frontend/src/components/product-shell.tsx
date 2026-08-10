import type { ReactNode } from "react";

import type { PlatformSnapshot } from "@/src/lib/api";

import { Brand } from "./brand";
import { Icon } from "./icon";
import { NetworkState } from "./network-state";
import { PrimaryNavigation } from "./primary-navigation";

interface ProductShellProps {
  children: ReactNode;
  snapshot: PlatformSnapshot;
}

export function ProductShell({ children, snapshot }: ProductShellProps) {
  const readiness = snapshot.readiness?.status ?? "offline";
  const version = snapshot.system?.version ?? "indisponível";
  const deploymentMode = snapshot.system?.deploymentMode ?? "control plane offline";

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Ir para o conteúdo</a>

      <aside className="sidebar">
        <div className="sidebar__brand">
          <Brand />
        </div>
        <PrimaryNavigation />
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
            <span className="eyebrow">Control plane</span>
            <strong>{deploymentMode}</strong>
          </div>
          <div className="topbar__actions">
            <NetworkState />
            <span className="platform-chip" data-status={readiness}>
              <span className="platform-chip__dot" />
              {formatReadiness(readiness)}
            </span>
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
