import Link from "next/link";

import { Icon, type IconName } from "@/src/components/icon";
import { StatusCard } from "@/src/components/status-card";
import { getPlatformSnapshot } from "@/src/lib/api";

const modules: ReadonlyArray<{
  href: string;
  icon: IconName;
  title: string;
  description: string;
}> = [
  {
    href: "/inventory",
    icon: "inventory",
    title: "Inventário",
    description: "Ativos, identidade técnica, lifecycle e contexto de site.",
  },
  {
    href: "/ipam",
    icon: "ipam",
    title: "IPAM",
    description: "IPv4, IPv6 e routing domains com isolamento explícito.",
  },
  {
    href: "/discovery",
    icon: "discovery",
    title: "Discovery",
    description: "Descoberta controlada pela execução headless no site-runtime.",
  },
  {
    href: "/telemetry",
    icon: "telemetry",
    title: "Telemetria",
    description: "Saúde, observabilidade, checks e sinais operacionais.",
  },
];

export default async function Home() {
  const snapshot = await getPlatformSnapshot();
  const { readiness, system } = snapshot;
  const backendStatus = system ? "ready" : "offline";
  const runtimeStatus = toCardStatus(readiness?.runtime);
  const databaseStatus = toCardStatus(readiness?.database);
  const redisStatus = toCardStatus(readiness?.redis);

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
            <h2 id="modules-title">Módulos do sistema</h2>
          </div>
          <span className="section-heading__note">Rotas reais, sem atalhos decorativos</span>
        </div>

        <div className="module-grid">
          {modules.map((module) => (
            <Link className="module-card" href={module.href} key={module.href}>
              <span className="module-card__icon"><Icon name={module.icon} size={22} /></span>
              <div>
                <strong>{module.title}</strong>
                <p>{module.description}</p>
              </div>
              <span aria-hidden="true" className="module-card__arrow">→</span>
            </Link>
          ))}
        </div>
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
