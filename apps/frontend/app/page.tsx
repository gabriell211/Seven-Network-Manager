import Link from "next/link";
import { redirect } from "next/navigation";

import { Icon } from "@/src/components/icon";
import { OperationalIcon } from "@/src/components/operational-icon";
import { StatusCard } from "@/src/components/status-card";
import { getPlatformSnapshot } from "@/src/lib/api";
import { getOperationalContext } from "@/src/lib/session";

export default async function Home() {
  const [snapshot, context] = await Promise.all([
    getPlatformSnapshot(),
    getOperationalContext(),
  ]);
  if (!context.ok && context.status === 401) redirect("/login");

  const { readiness, system } = snapshot;
  const backendStatus = system ? "ready" : "offline";
  const runtimeStatus = toCardStatus(readiness?.runtime);
  const databaseStatus = toCardStatus(readiness?.database);
  const redisStatus = toCardStatus(readiness?.redis);
  const canViewInventory = context.ok
    ? context.data.sites.some((site) => site.permissions.includes("devices.view"))
    : false;

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <span className="eyebrow">Visão operacional</span>
          <h1>Infraestrutura sob controle.</h1>
          <p>
            Estado real do control plane e das dependências que sustentam a execução segura no ambiente gerenciado.
          </p>
        </div>
        <Link className="button button--secondary" href="/">
          <Icon name="refresh" size={17} />
          Atualizar status
        </Link>
      </section>

      <section aria-labelledby="platform-status-title" className="section-block">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Plataforma</span>
            <h2 id="platform-status-title">Saúde dos componentes</h2>
          </div>
          <span className="timestamp">Leitura: {formatTimestamp(snapshot.capturedAt)}</span>
        </div>

        <div className="status-grid">
          <StatusCard
            detail={system ? system.deploymentMode : "API não respondeu dentro do limite"}
            icon="activity"
            label="Control plane"
            status={backendStatus}
            value={system ? `v${system.version}` : "Offline"}
          />
          <StatusCard
            detail={readiness ? `${readiness.appliedMigrations} migrations aplicadas` : "Readiness indisponível"}
            icon="database"
            label="PostgreSQL"
            status={databaseStatus}
            value={formatComponentStatus(readiness?.database)}
          />
          <StatusCard
            detail="Coordenação e cache efêmero"
            icon="redis"
            label="Redis"
            status={redisStatus}
            value={formatComponentStatus(readiness?.redis)}
          />
          <StatusCard
            detail="Boundary obrigatório para operações na LAN"
            icon="runtime"
            label="Site runtime"
            status={runtimeStatus}
            value={formatComponentStatus(readiness?.runtime)}
          />
        </div>
      </section>

      <section aria-labelledby="modules-title" className="section-block">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Operação</span>
            <h2 id="modules-title">Capabilities disponíveis nesta sessão</h2>
          </div>
          <span className="section-heading__note">Somente recursos com contrato real e autorização efetiva</span>
        </div>

        <div className="module-grid">
          {canViewInventory ? (
            <Link className="module-card" href="/inventory">
              <span className="module-card__icon"><Icon name="inventory" size={22} /></span>
              <div>
                <strong>Inventário</strong>
                <p>Ativos, identidade técnica, lifecycle e contexto de site persistidos no PostgreSQL.</p>
              </div>
              <span aria-hidden="true" className="module-card__arrow">→</span>
            </Link>
          ) : null}
          <Link className="module-card" href="/api-docs">
            <span className="module-card__icon"><Icon name="settings" size={22} /></span>
            <div>
              <strong>Contrato REST</strong>
              <p>Operações e schemas publicados pela especificação OpenAPI versionada.</p>
            </div>
            <span aria-hidden="true" className="module-card__arrow">→</span>
          </Link>
        </div>

        {!canViewInventory ? (
          <div className="operational-state">
            <span className="operational-state__icon"><OperationalIcon name="lock" size={22} /></span>
            <div>
              <span className="eyebrow">Least privilege</span>
              <h2>Nenhuma capability operacional autorizada</h2>
              <p>A sessão não possui <code>devices.view</code> em nenhum site. O painel não exibe módulos aos quais o backend não concede acesso.</p>
            </div>
          </div>
        ) : null}
      </section>

      <section aria-labelledby="boundary-title" className="boundary-card">
        <div className="boundary-card__icon"><Icon name="shield" size={24} /></div>
        <div>
          <span className="eyebrow">Boundary de segurança</span>
          <h2 id="boundary-title">Control plane → site-runtime → LAN gerenciada</h2>
          <p>
            O navegador não executa operações de rede e o backend não abre SNMP, ICMP, WinRM ou SSH como fallback quando o runtime está indisponível.
          </p>
        </div>
      </section>
    </div>
  );
}

function toCardStatus(value: string | undefined): "ready" | "degraded" | "offline" | "neutral" {
  if (value === "ready") return "ready";
  if (value === "unavailable" || value === undefined) return "offline";
  return "degraded";
}

function formatComponentStatus(value: string | undefined) {
  if (value === "ready") return "Operacional";
  if (value === "unavailable") return "Indisponível";
  return value ?? "Sem resposta";
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "medium",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}
